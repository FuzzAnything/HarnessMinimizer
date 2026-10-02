/*
** SQLite metadata and statement explanation APIs fuzzing harness
**
** This harness specifically targets SQLite metadata and explanation APIs 
** identified as high-priority coverage gaps:
** - sqlite3_table_column_metadata: Retrieve column metadata information (853 undiscovered branches)
** - sqlite3_stmt_explain: Change EXPLAIN mode for prepared statements (831 undiscovered branches)
** - sqlite3_stmt_isexplain: Check if statement is in EXPLAIN mode
** - Related metadata and diagnostic functions
**
** Differentiation from existing harnesses:
** - harness_000: Basic database operations (open, exec, prepare, step)
** - harness_001: Advanced operations with progress handlers and authorizers
** - harness_002: BLOB-specific incremental I/O operations
** - harness_003: Virtual table creation, configuration, and operations
** - harness_004: Database backup operations between source and destination databases
** - harness_005: Database serialization/deserialization with WAL checkpoints
** - harness_006: UTF-16 specific APIs and Unicode handling
** - harness_007: Metadata retrieval and statement explanation APIs (this harness)
**
** Operation lifecycle: 
**   Database setup → Table creation with varied schemas → 
**   Column metadata retrieval → Statement preparation → 
**   Explain mode manipulation → Query execution → Result analysis
**
** Key design considerations:
** 1. Create tables with diverse column types, constraints, and collations
** 2. Test metadata retrieval for various column scenarios
** 3. Exercise all explain modes (0=normal, 1=EXPLAIN, 2=EXPLAIN QUERY PLAN)
** 4. Test edge cases: NULL column names, rowid columns, WITHOUT ROWID tables
** 5. Ensure proper error handling for invalid metadata queries
*/

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>

#include <fuzzer/FuzzedDataProvider.h>
#include "sqlite3.h"

// Simple callback for sqlite3_exec (minimal implementation)
static int exec_callback(void* NotUsed, int argc, char** argv, char** azColName) {
    (void)NotUsed;
    (void)argc;
    (void)argv;
    (void)azColName;
    return 0;
}

// Available database schemas for metadata queries
static const char* const db_schemas[] = {
    "main",
    "temp",
    // NULL schema (defaults to "main")
};

// Column types for table creation
static const char* const column_types[] = {
    "INTEGER",
    "REAL", 
    "TEXT",
    "BLOB",
    "INTEGER PRIMARY KEY",
    "INTEGER PRIMARY KEY AUTOINCREMENT",
    "TEXT NOT NULL",
    "REAL DEFAULT 0.0",
    "BLOB CHECK(length(data) < 1000)",
    "TEXT COLLATE NOCASE",
    "TEXT COLLATE RTRIM",
    "INTEGER UNIQUE",
    "REAL CHECK(value > 0)",
};

// Explain modes for sqlite3_stmt_explain
static const int explain_modes[] = {
    0,  // Normal mode
    1,  // EXPLAIN mode
    2,  // EXPLAIN QUERY PLAN mode
};

// Operation types for the metadata/explain harness
enum MetadataOperation {
    META_OP_BASIC = 0,
    META_OP_WITH_EXPLAIN = 1,
    META_OP_ROWID_TESTS = 2,
    META_OP_ERROR_CASES = 3,
    META_OP_FULL_CYCLE = 4
};

// Helper function to generate random table name from fuzzer input
static std::string generate_table_name(FuzzedDataProvider& fdp) {
    std::string name = "tbl_";
    name += std::to_string(fdp.ConsumeIntegralInRange<uint32_t>(1, 1000));
    return name;
}

// Helper function to generate random column name from fuzzer input
static std::string generate_column_name(FuzzedDataProvider& fdp) {
    const char* prefixes[] = {"col", "field", "data", "value", "attr"};
    std::string name = fdp.PickValueInArray(prefixes);
    name += "_";
    name += std::to_string(fdp.ConsumeIntegralInRange<uint32_t>(1, 100));
    return name;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum input size check: need enough for configuration and basic operations
    // sizeof(int) for config + multiple strings for table/column names + explain modes
    const size_t MIN_SIZE = sizeof(int) * 8 + 128;  // Basic config + room for strings
    if (size < MIN_SIZE) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Initialize SQLite library
    if (sqlite3_initialize() != SQLITE_OK) {
        return 0;
    }
    
    sqlite3* db = nullptr;
    char* err_msg = nullptr;
    
    // Consume database configuration from fuzzer input
    int open_flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_MEMORY;
    
    // Add optional flags based on fuzzer input
    if (fdp.ConsumeBool()) {
        open_flags |= SQLITE_OPEN_NOMUTEX;
    }
    if (fdp.ConsumeBool()) {
        open_flags |= SQLITE_OPEN_FULLMUTEX;
    }
    
    // Open in-memory database
    int rc = sqlite3_open_v2(":memory:", &db, open_flags, nullptr);
    if (rc != SQLITE_OK || db == nullptr) {
        sqlite3_shutdown();
        return 0;
    }
    
    // Set limits to prevent excessive resource usage
    sqlite3_limit(db, SQLITE_LIMIT_VDBE_OP, fdp.ConsumeIntegralInRange<int>(1000, 50000));
    sqlite3_limit(db, SQLITE_LIMIT_LENGTH, fdp.ConsumeIntegralInRange<int>(1000, 100000));
    
    // Determine operation type based on fuzzer input
    MetadataOperation op_type = static_cast<MetadataOperation>(
        fdp.ConsumeIntegralInRange<int>(0, 4));
    
    // Generate table and column names from fuzzer input
    std::string table_name = generate_table_name(fdp);
    std::vector<std::string> column_names;
    std::vector<std::string> column_defs;
    
    // Generate 1-8 columns for our test table
    int num_columns = fdp.ConsumeIntegralInRange<int>(1, 8);
    for (int i = 0; i < num_columns; i++) {
        column_names.push_back(generate_column_name(fdp));
        column_defs.push_back(fdp.PickValueInArray(column_types));
    }
    
    // Create the test table with generated schema
    std::string create_table_sql = "CREATE TABLE " + table_name + " (";
    for (size_t i = 0; i < column_defs.size(); i++) {
        if (i > 0) create_table_sql += ", ";
        create_table_sql += column_names[i] + " " + column_defs[i];
    }
    
    // Possibly create WITHOUT ROWID table based on fuzzer input
    if (fdp.ConsumeBool()) {
        create_table_sql += ", PRIMARY KEY(" + column_names[0] + ")";
        create_table_sql += ") WITHOUT ROWID";
    } else {
        create_table_sql += ")";
    }
    
    rc = sqlite3_exec(db, create_table_sql.c_str(), nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        if (err_msg) {
            sqlite3_free(err_msg);
            err_msg = nullptr;
        }
        // Try simpler table creation
        std::string fallback_sql = "CREATE TABLE " + table_name + 
                                   " (id INTEGER PRIMARY KEY, data TEXT)";
        rc = sqlite3_exec(db, fallback_sql.c_str(), nullptr, nullptr, &err_msg);
        if (rc != SQLITE_OK) {
            if (err_msg) {
                sqlite3_free(err_msg);
                err_msg = nullptr;
            }
            sqlite3_close(db);
            sqlite3_shutdown();
            return 0;
        }
        // Update column names for fallback table
        column_names = {"id", "data"};
    }
    
    // Insert some test data into the table
    std::string insert_sql = "INSERT INTO " + table_name + " VALUES ";
    for (int i = 0; i < 3; i++) {
        if (i > 0) insert_sql += ", ";
        if (column_names.size() == 2 && column_names[0] == "id" && column_names[1] == "data") {
            insert_sql += "(" + std::to_string(i) + ", 'test" + std::to_string(i) + "')";
        } else {
            // Generic insert with NULL values for all columns except first
            insert_sql += "(" + std::to_string(i);
            for (size_t j = 1; j < column_names.size(); j++) {
                insert_sql += ", NULL";
            }
            insert_sql += ")";
        }
    }
    
    rc = sqlite3_exec(db, insert_sql.c_str(), nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK && err_msg) {
        sqlite3_free(err_msg);
        err_msg = nullptr;
    }
    
    // Test 1: sqlite3_table_column_metadata for various columns
    for (size_t i = 0; i < column_names.size() && fdp.remaining_bytes() > 0; i++) {
        const char* zDataType = nullptr;
        const char* zCollSeq = nullptr;
        int notnull = 0;
        int primarykey = 0;
        int autoinc = 0;
        
        // Select database schema (main, temp, or NULL)
        const char* zDbName = fdp.ConsumeBool() ? 
                              (fdp.ConsumeBool() ? "temp" : "main") : 
                              nullptr;
        
        rc = sqlite3_table_column_metadata(
            db,
            zDbName,
            table_name.c_str(),
            column_names[i].c_str(),
            &zDataType,
            &zCollSeq,
            &notnull,
            &primarykey,
            &autoinc
        );
        
        // Metadata retrieval should succeed for existing columns
        // (We don't check rc here as it might fail for some edge cases)
    }
    
    // Test 2: sqlite3_table_column_metadata for rowid column (if table has rowid)
    if (fdp.ConsumeBool()) {
        const char* zDataType = nullptr;
        const char* zCollSeq = nullptr;
        int notnull = 0;
        int primarykey = 0;
        int autoinc = 0;
        
        // Test rowid, oid, and _rowid_ column names
        const char* rowid_names[] = {"rowid", "oid", "_rowid_"};
        const char* rowid_name = fdp.PickValueInArray(rowid_names);
        
        rc = sqlite3_table_column_metadata(
            db,
            "main",
            table_name.c_str(),
            rowid_name,
            &zDataType,
            &zCollSeq,
            &notnull,
            &primarykey,
            &autoinc
        );
        
        // This may succeed or fail depending on table structure
    }
    
    // Test 3: sqlite3_table_column_metadata with NULL column name (table existence check)
    if (fdp.ConsumeBool()) {
        const char* zDataType = nullptr;
        const char* zCollSeq = nullptr;
        int notnull = 0;
        int primarykey = 0;
        int autoinc = 0;
        
        rc = sqlite3_table_column_metadata(
            db,
            "main",
            table_name.c_str(),
            nullptr,  // NULL column name for table existence check
            &zDataType,
            &zCollSeq,
            &notnull,
            &primarykey,
            &autoinc
        );
        
        // Should return SQLITE_OK for existing table
    }
    
    // Test 4: sqlite3_table_column_metadata for non-existent column (error case)
    if (fdp.ConsumeBool()) {
        const char* zDataType = nullptr;
        const char* zCollSeq = nullptr;
        int notnull = 0;
        int primarykey = 0;
        int autoinc = 0;
        
        std::string bad_column = "non_existent_column_" + 
                                 std::to_string(fdp.ConsumeIntegral<uint32_t>());
        
        rc = sqlite3_table_column_metadata(
            db,
            "main",
            table_name.c_str(),
            bad_column.c_str(),
            &zDataType,
            &zCollSeq,
            &notnull,
            &primarykey,
            &autoinc
        );
        
        // Should return error for non-existent column
    }
    
    // Test 5: Prepare statements and test sqlite3_stmt_explain
    sqlite3_stmt* stmt = nullptr;
    std::string query = "SELECT * FROM " + table_name + " WHERE " + 
                       column_names[0] + " > ?";
    
    rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
    if (rc == SQLITE_OK && stmt != nullptr) {
        // Bind a parameter value from fuzzer input
        int param_value = fdp.ConsumeIntegral<int>();
        sqlite3_bind_int(stmt, 1, param_value);
        
        // Test sqlite3_stmt_isexplain before changing mode
        int is_explain = sqlite3_stmt_isexplain(stmt);
        
        // Change explain mode based on fuzzer input
        int explain_mode = fdp.PickValueInArray(explain_modes);
        rc = sqlite3_stmt_explain(stmt, explain_mode);
        
        if (rc == SQLITE_OK) {
            // Execute the statement in the new explain mode
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                // Process row data if needed
                int col_count = sqlite3_column_count(stmt);
                for (int i = 0; i < col_count; i++) {
                    // Just touch the data to ensure it's processed
                    sqlite3_column_type(stmt, i);
                }
            }
            
            // Reset statement for potential reuse
            sqlite3_reset(stmt);
            
            // Test switching to a different explain mode
            if (fdp.ConsumeBool()) {
                int new_explain_mode = fdp.PickValueInArray(explain_modes);
                if (new_explain_mode != explain_mode) {
                    sqlite3_stmt_explain(stmt, new_explain_mode);
                    
                    // Execute again in new mode
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        int col_count = sqlite3_column_count(stmt);
                        for (int i = 0; i < col_count; i++) {
                            sqlite3_column_type(stmt, i);
                        }
                    }
                }
            }
        }
        
        // Finalize the statement
        sqlite3_finalize(stmt);
        stmt = nullptr;
    }
    
    // Test 6: Prepare EXPLAIN/EXPLAIN QUERY PLAN statements directly
    if (fdp.ConsumeBool()) {
        const char* explain_prefixes[] = {"", "EXPLAIN ", "EXPLAIN QUERY PLAN "};
        const char* prefix = fdp.PickValueInArray(explain_prefixes);
        
        std::string explain_query = std::string(prefix) + 
                                   "SELECT count(*) FROM " + table_name;
        
        rc = sqlite3_prepare_v2(db, explain_query.c_str(), -1, &stmt, nullptr);
        if (rc == SQLITE_OK && stmt != nullptr) {
            // Check initial explain mode
            int initial_explain = sqlite3_stmt_isexplain(stmt);
            
            // Try to change explain mode (may succeed or fail)
            if (fdp.ConsumeBool()) {
                int target_mode = fdp.PickValueInArray(explain_modes);
                sqlite3_stmt_explain(stmt, target_mode);
            }
            
            // Execute the explain statement
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                int col_count = sqlite3_column_count(stmt);
                for (int i = 0; i < col_count; i++) {
                    sqlite3_column_type(stmt, i);
                }
            }
            
            sqlite3_finalize(stmt);
            stmt = nullptr;
        }
    }
    
    // Test 7: Multiple statements with different explain modes
    if (fdp.ConsumeBool() && fdp.remaining_bytes() > 100) {
        std::vector<sqlite3_stmt*> statements;
        
        for (int i = 0; i < 3 && fdp.remaining_bytes() > 50; i++) {
            std::string multi_query = "SELECT " + column_names[0] + 
                                     " FROM " + table_name + 
                                     " LIMIT " + std::to_string(i + 1);
            
            rc = sqlite3_prepare_v2(db, multi_query.c_str(), -1, &stmt, nullptr);
            if (rc == SQLITE_OK && stmt != nullptr) {
                // Set random explain mode
                int mode = fdp.PickValueInArray(explain_modes);
                sqlite3_stmt_explain(stmt, mode);
                
                // Execute
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    // Process row
                }
                
                statements.push_back(stmt);
            }
        }
        
        // Cleanup all statements
        for (sqlite3_stmt* s : statements) {
            sqlite3_finalize(s);
        }
    }
    
    // Cleanup
    if (stmt != nullptr) {
        sqlite3_finalize(stmt);
    }
    
    if (err_msg != nullptr) {
        sqlite3_free(err_msg);
    }
    
    sqlite3_close(db);
    sqlite3_shutdown();
    
    return 0;
}
