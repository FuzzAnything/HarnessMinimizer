/*
 * Fuzzing harness for SQLite database metadata introspection and status operations
 * Targets: 
 * - sqlite3_table_column_metadata (866 undiscovered branches)
 * - sqlite3_stmt_explain (844 undiscovered branches) 
 * - sqlite3_prepare (838 undiscovered branches)
 * - sqlite3_db_cacheflush (536 undiscovered branches)
 * - sqlite3_db_status (137 undiscovered branches)
 * - sqlite3_db_status64 (135 undiscovered branches)
 * 
 * Required Helper APIs:
 * - sqlite3_open_v2, sqlite3_prepare_v2, sqlite3_step, sqlite3_finalize, sqlite3_close
 * 
 * Semantic diversity from existing harnesses (000-009):
 * - harness_000: Basic open/exec/close operations
 * - harness_001: Prepared statement lifecycle with basic binding  
 * - harness_002: BLOB I/O operations
 * - harness_003: Parameter binding and reset APIs
 * - harness_004: Backup APIs
 * - harness_005: Serialize/deserialize APIs
 * - harness_006: Virtual table APIs
 * - harness_007: get_table APIs
 * - harness_008: WAL checkpoint APIs
 * - harness_009: UTF-16 APIs
 * 
 * This harness focuses specifically on:
 * 1. Database metadata introspection via sqlite3_table_column_metadata()
 * 2. Statement execution plan explanation with sqlite3_stmt_explain()
 * 3. Legacy prepare interface sqlite3_prepare()
 * 4. Database performance metrics via sqlite3_db_status/sqlite3_db_status64()
 * 5. Cache management with sqlite3_db_cacheflush()
 * 6. Complete lifecycle: create test tables → query metadata → explain statements → check status → cleanup
 */

#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>
#include <array>

#include "sqlite3.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum input size check - metadata operations need substantial input
    if (size < 128) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Consume operation type to determine test scenario
    uint8_t operation_type = fdp.ConsumeIntegral<uint8_t>() % 8;
    
    // Consume database opening flags
    int open_flags = fdp.ConsumeIntegral<int>();
    
    // Consume SQL statement types for testing
    uint8_t sql_type = fdp.ConsumeIntegral<uint8_t>() % 4;
    
    // Consume parameters for column metadata queries
    uint8_t db_index = fdp.ConsumeIntegral<uint8_t>() % 3; // 0=main, 1=temp, 2=attached
    std::string db_name;
    switch (db_index) {
        case 0: db_name = "main"; break;
        case 1: db_name = "temp"; break;
        case 2: db_name = "attached"; break;
        default: db_name = "main"; break;
    }
    
    // Consume table and column names for metadata queries
    std::string table_name = fdp.ConsumeRandomLengthString(64);
    std::string column_name = fdp.ConsumeRandomLengthString(64);
    
    // Consume explain modes for sqlite3_stmt_explain
    int explain_mode = fdp.ConsumeIntegral<int>() % 3; // 0=normal, 1=explain, 2=explain query plan
    
    // Consume db status operation codes
    int status_op = fdp.ConsumeIntegral<int>() % 20; // SQLite has ~20 status ops
    
    // Consume reset flag for db_status
    int reset_flag = fdp.ConsumeBool() ? 1 : 0;
    
    // Consume SQL statements from remaining input
    std::string sql_statement = fdp.ConsumeRandomLengthString(2048);
    
    // Consume remaining data for additional testing scenarios
    std::vector<uint8_t> remaining_data = fdp.ConsumeRemainingBytes<uint8_t>();
    
    sqlite3* db = nullptr;
    sqlite3_stmt* stmt = nullptr;
    sqlite3_stmt* stmt_legacy = nullptr;
    int rc;
    
    // Initialize SQLite library
    rc = sqlite3_initialize();
    if (rc != SQLITE_OK) {
        return 0;
    }
    
    // Open an in-memory database for safety
    rc = sqlite3_open_v2(":memory:", &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
    if (rc != SQLITE_OK || db == nullptr) {
        sqlite3_shutdown();
        return 0;
    }
    
    // Set some safety limits on the database
    sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 50000);
    sqlite3_limit(db, SQLITE_LIMIT_SQL_LENGTH, 10000);
    sqlite3_limit(db, SQLITE_LIMIT_COLUMN, 100);
    sqlite3_limit(db, SQLITE_LIMIT_EXPR_DEPTH, 50);
    sqlite3_limit(db, SQLITE_LIMIT_VARIABLE_NUMBER, 50);
    
    // Create test tables with various column types for metadata testing
    const char* create_tables_sql = 
        "CREATE TABLE IF NOT EXISTS test_metadata ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "int_col INTEGER NOT NULL, "
        "real_col REAL, "
        "text_col TEXT COLLATE NOCASE, "
        "blob_col BLOB, "
        "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP"
        ");"
        "CREATE TABLE IF NOT EXISTS test_metadata2 ("
        "col1 INTEGER PRIMARY KEY, "
        "col2 VARCHAR(255), "
        "col3 DECIMAL(10,2), "
        "col4 BOOLEAN"
        ");"
        "CREATE VIEW IF NOT EXISTS test_view AS SELECT id, text_col FROM test_metadata WHERE int_col > 0;";
    
    rc = sqlite3_exec(db, create_tables_sql, nullptr, nullptr, nullptr);
    if (rc != SQLITE_OK) {
        // Continue anyway, some operations might still work
    }
    
    // Insert some test data for more realistic metadata
    const char* insert_data_sql = 
        "INSERT OR IGNORE INTO test_metadata (int_col, real_col, text_col, blob_col) VALUES "
        "(1, 3.14, 'test string', x'010203'), "
        "(2, 2.718, 'another string', x'040506'), "
        "(3, 1.618, 'unicode: café', x'070809');";
    
    rc = sqlite3_exec(db, insert_data_sql, nullptr, nullptr, nullptr);
    // Don't check rc - insertion might fail but metadata APIs should still work
    
    // TARGET API 1: sqlite3_prepare (legacy interface)
    // Test the legacy prepare interface alongside the modern one
    const char* test_sql = "SELECT * FROM test_metadata WHERE int_col > ?";
    rc = sqlite3_prepare(db, test_sql, -1, &stmt_legacy, nullptr);
    
    // Also prepare a statement using the modern interface for comparison
    rc = sqlite3_prepare_v2(db, sql_statement.c_str(), -1, &stmt, nullptr);
    
    if (stmt != nullptr) {
        // TARGET API 2: sqlite3_stmt_explain
        // Test changing explain mode on prepared statement
        rc = sqlite3_stmt_explain(stmt, explain_mode);
        
        // Execute the statement to generate some activity
        if (rc == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                // Consume some rows (limited to prevent infinite loops)
                static int max_rows = 10;
                if (--max_rows <= 0) break;
            }
            sqlite3_reset(stmt);
        }
        
        // TARGET API 3: sqlite3_table_column_metadata
        // Test metadata retrieval for various tables and columns
        const char* data_type = nullptr;
        const char* coll_seq = nullptr;
        int not_null = 0;
        int primary_key = 0;
        int autoinc = 0;
        
        // Test metadata on system tables
        rc = sqlite3_table_column_metadata(
            db, "main", "sqlite_master", "type", 
            &data_type, &coll_seq, &not_null, &primary_key, &autoinc
        );
        
        // Test metadata on our test tables
        rc = sqlite3_table_column_metadata(
            db, db_name.c_str(), table_name.c_str(), column_name.c_str(),
            &data_type, &coll_seq, &not_null, &primary_key, &autoinc
        );
        
        // Test with NULL parameters (special case behavior)
        rc = sqlite3_table_column_metadata(
            db, nullptr, "test_metadata", "id",
            nullptr, nullptr, nullptr, nullptr, nullptr
        );
        
        // Test metadata on all columns of test_metadata table
        const char* test_columns[] = {"id", "int_col", "real_col", "text_col", "blob_col", "timestamp"};
        for (size_t i = 0; i < sizeof(test_columns)/sizeof(test_columns[0]); i++) {
            rc = sqlite3_table_column_metadata(
                db, "main", "test_metadata", test_columns[i],
                &data_type, &coll_seq, &not_null, &primary_key, &autoinc
            );
        }
        
        // TARGET API 4 & 5: sqlite3_db_status and sqlite3_db_status64
        // Test various database status operations
        int current_val = 0;
        int highwater_val = 0;
        sqlite3_int64 current_val64 = 0;
        sqlite3_int64 highwater_val64 = 0;
        
        // Test all available status operations
        for (int op = 0; op < 20; op++) {
            // Try both 32-bit and 64-bit versions
            rc = sqlite3_db_status(db, op, &current_val, &highwater_val, reset_flag);
            rc = sqlite3_db_status64(db, op, &current_val64, &highwater_val64, reset_flag);
        }
        
        // Test specific important status operations
        int status_ops_to_test[] = {
            SQLITE_DBSTATUS_LOOKASIDE_USED,
            SQLITE_DBSTATUS_CACHE_USED,
            SQLITE_DBSTATUS_SCHEMA_USED,
            SQLITE_DBSTATUS_STMT_USED,
            SQLITE_DBSTATUS_CACHE_HIT,
            SQLITE_DBSTATUS_CACHE_MISS,
            SQLITE_DBSTATUS_CACHE_WRITE
        };
        
        for (size_t i = 0; i < sizeof(status_ops_to_test)/sizeof(status_ops_to_test[0]); i++) {
            rc = sqlite3_db_status(db, status_ops_to_test[i], &current_val, &highwater_val, reset_flag);
            rc = sqlite3_db_status64(db, status_ops_to_test[i], &current_val64, &highwater_val64, reset_flag);
        }
        
        // TARGET API 6: sqlite3_db_cacheflush
        // Test cache flushing operation
        rc = sqlite3_db_cacheflush(db);
        
        // Test cache flush after some database activity
        if (rc == SQLITE_OK) {
            // Do some additional operations that might dirty cache
            const char* extra_sql = "INSERT INTO test_metadata (int_col) VALUES (999); DELETE FROM test_metadata WHERE int_col = 999;";
            sqlite3_exec(db, extra_sql, nullptr, nullptr, nullptr);
            
            // Flush cache again
            rc = sqlite3_db_cacheflush(db);
        }
        
        // Clean up statements
        sqlite3_finalize(stmt);
    }
    
    if (stmt_legacy != nullptr) {
        sqlite3_finalize(stmt_legacy);
    }
    
    // Additional metadata testing based on operation type
    switch (operation_type) {
        case 0:
            // Test metadata on non-existent table
            rc = sqlite3_table_column_metadata(
                db, "main", "non_existent_table", "non_existent_column",
                nullptr, nullptr, nullptr, nullptr, nullptr
            );
            break;
            
        case 1:
            // Test metadata with invalid database name
            rc = sqlite3_table_column_metadata(
                db, "invalid_db", "test_metadata", "id",
                nullptr, nullptr, nullptr, nullptr, nullptr
            );
            break;
            
        case 2:
            // Test explain with different modes
            if (stmt != nullptr) {
                sqlite3_stmt_explain(stmt, 0); // Normal
                sqlite3_stmt_explain(stmt, 1); // Explain
                sqlite3_stmt_explain(stmt, 2); // Explain query plan
            }
            break;
            
        case 3:
            // Test db_status with reset
            for (int op = 0; op < 5; op++) {
                int cur = 0, hi = 0;
                sqlite3_db_status(db, op, &cur, &hi, 1); // With reset
                sqlite3_db_status(db, op, &cur, &hi, 0); // Without reset
            }
            break;
            
        case 4:
            // Test prepare with various SQL fragments
            {
                sqlite3_stmt* temp_stmt = nullptr;
                std::string partial_sql = fdp.ConsumeRandomLengthString(512);
                rc = sqlite3_prepare(db, partial_sql.c_str(), -1, &temp_stmt, nullptr);
                if (temp_stmt != nullptr) {
                    sqlite3_finalize(temp_stmt);
                }
            }
            break;
            
        case 5:
            // Test metadata on views
            rc = sqlite3_table_column_metadata(
                db, "main", "test_view", "text_col",
                nullptr, nullptr, nullptr, nullptr, nullptr
            );
            break;
            
        case 6:
            // Multiple cache flushes
            for (int i = 0; i < 3; i++) {
                sqlite3_db_cacheflush(db);
            }
            break;
            
        case 7:
            // Comprehensive status testing
            {
                int cur_vals[20];
                int hi_vals[20];
                sqlite3_int64 cur_vals64[20];
                sqlite3_int64 hi_vals64[20];
                
                for (int op = 0; op < 20; op++) {
                    sqlite3_db_status(db, op, &cur_vals[op], &hi_vals[op], 0);
                    sqlite3_db_status64(db, op, &cur_vals64[op], &hi_vals64[op], 0);
                }
            }
            break;
    }
    
    // Clean up database connection
    if (db != nullptr) {
        sqlite3_close(db);
    }
    
    sqlite3_shutdown();
    return 0;
}
