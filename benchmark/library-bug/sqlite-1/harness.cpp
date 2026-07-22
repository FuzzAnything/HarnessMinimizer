#include <fuzzer/FuzzedDataProvider.h>
#include <sqlite3.h>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <cstring>
#include <cctype>

// Fuzzing harness for SQLite FTS5 (Full Text Search) virtual table operations
// Target: FTS5 module - largest uncovered complexity cluster with 2000+ branch points
// Coverage focus: FTS5 virtual table creation, querying, maintenance operations
// Key APIs: sqlite3_create_module_v2 (0% covered), fts5FilterMethod, fts5UpdateMethod, fts5NextMethod

// Custom FTS5-like virtual table module for testing sqlite3_create_module_v2
static int fts5_like_create(sqlite3* db, void* pAux,
                           int argc, const char* const* argv,
                           sqlite3_vtab** ppVTab, char** pzErr) {
    // Allocate the virtual table structure
    sqlite3_vtab* pVTab = (sqlite3_vtab*)sqlite3_malloc(sizeof(sqlite3_vtab));
    if (!pVTab) {
        if (pzErr) {
            *pzErr = sqlite3_mprintf("out of memory");
        }
        return SQLITE_ERROR;
    }
    // Zero the structure
    memset(pVTab, 0, sizeof(sqlite3_vtab));
    
    // Declare the virtual table schema similar to FTS5
    int rc = sqlite3_declare_vtab(db, 
        "CREATE TABLE x("
        "title TEXT, "
        "body TEXT, "
        "author TEXT, "
        "content TEXT HIDDEN, "
        "rank FLOAT HIDDEN"
        ")");
    
    if (rc != SQLITE_OK) {
        sqlite3_free(pVTab);
        if (pzErr) {
            *pzErr = sqlite3_mprintf("declare vtab failed");
        }
        return rc;
    }
    
    *ppVTab = pVTab;
    return SQLITE_OK;
}

static int fts5_like_connect(sqlite3* db, void* pAux,
                            int argc, const char* const* argv,
                            sqlite3_vtab** ppVTab, char** pzErr) {
    return fts5_like_create(db, pAux, argc, argv, ppVTab, pzErr);
}

static int fts5_like_bestindex(sqlite3_vtab* pVTab, sqlite3_index_info* pIdxInfo) {
    // Simple best index implementation
    return SQLITE_OK;
}

static int fts5_like_disconnect(sqlite3_vtab* pVTab) {
    if (pVTab) {
        sqlite3_free(pVTab);
    }
    return SQLITE_OK;
}

static int fts5_like_destroy(sqlite3_vtab* pVTab) {
    return fts5_like_disconnect(pVTab);
}

static int fts5_like_open(sqlite3_vtab* pVTab, sqlite3_vtab_cursor** ppCursor) {
    // Allocate a cursor structure
    sqlite3_vtab_cursor* pCursor = (sqlite3_vtab_cursor*)sqlite3_malloc(sizeof(sqlite3_vtab_cursor));
    if (!pCursor) {
        return SQLITE_ERROR;
    }
    memset(pCursor, 0, sizeof(sqlite3_vtab_cursor));
    *ppCursor = pCursor;
    return SQLITE_OK;
}

static int fts5_like_close(sqlite3_vtab_cursor* pCursor) {
    if (pCursor) {
        sqlite3_free(pCursor);
    }
    return SQLITE_OK;
}

// FTS5-like filter method (simulating fts5FilterMethod)
static int fts5_like_filter(sqlite3_vtab_cursor* pCursor,
                           int idxNum, const char* idxStr,
                           int argc, sqlite3_value** argv) {
    // Simulate FTS5 filter behavior
    return SQLITE_OK;
}

// FTS5-like next method (simulating fts5NextMethod)
static int fts5_like_next(sqlite3_vtab_cursor* pCursor) {
    // Simulate moving to next row
    return SQLITE_OK;
}

static int fts5_like_eof(sqlite3_vtab_cursor* pCursor) {
    return 1; // Always at EOF for this simple implementation
}

static int fts5_like_column(sqlite3_vtab_cursor* pCursor,
                           sqlite3_context* ctx, int col) {
    // Return some dummy data
    if (col == 0) {
        sqlite3_result_text(ctx, "Test Title", -1, SQLITE_TRANSIENT);
    } else if (col == 1) {
        sqlite3_result_text(ctx, "Test Body Content", -1, SQLITE_TRANSIENT);
    } else if (col == 2) {
        sqlite3_result_text(ctx, "Test Author", -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_result_null(ctx);
    }
    return SQLITE_OK;
}

static int fts5_like_rowid(sqlite3_vtab_cursor* pCursor, sqlite3_int64* pRowid) {
    *pRowid = 1;
    return SQLITE_OK;
}

// FTS5-like update method (simulating fts5UpdateMethod)
static int fts5_like_update(sqlite3_vtab* pVTab, int argc, sqlite3_value** argv, sqlite3_int64* pRowid) {
    // Simulate FTS5 update operation
    return SQLITE_OK;
}

static int fts5_like_begin(sqlite3_vtab* pVTab) {
    return SQLITE_OK;
}

static int fts5_like_sync(sqlite3_vtab* pVTab) {
    return SQLITE_OK;
}

static int fts5_like_commit(sqlite3_vtab* pVTab) {
    return SQLITE_OK;
}

static int fts5_like_rollback(sqlite3_vtab* pVTab) {
    return SQLITE_OK;
}

static int fts5_like_findfunction(sqlite3_vtab* pVTab, int nArg, const char* zName,
                                 void (**pxFunc)(sqlite3_context*, int, sqlite3_value**),
                                 void** ppArg) {
    // No custom functions for this simple module
    return 0;
}

static int fts5_like_rename(sqlite3_vtab* pVTab, const char* zNew) {
    return SQLITE_OK;
}

// Virtual table module structure mimicking FTS5
static sqlite3_module fts5_like_module = {
    3,                          // iVersion
    fts5_like_create,           // xCreate
    fts5_like_connect,          // xConnect
    fts5_like_bestindex,        // xBestIndex
    fts5_like_disconnect,       // xDisconnect
    fts5_like_destroy,          // xDestroy
    fts5_like_open,             // xOpen
    fts5_like_close,            // xClose
    fts5_like_filter,           // xFilter (targets fts5FilterMethod pattern)
    fts5_like_next,             // xNext (targets fts5NextMethod pattern)
    fts5_like_eof,              // xEof
    fts5_like_column,           // xColumn
    fts5_like_rowid,            // xRowid
    fts5_like_update,           // xUpdate (targets fts5UpdateMethod pattern)
    fts5_like_begin,            // xBegin
    fts5_like_sync,             // xSync
    fts5_like_commit,           // xCommit
    fts5_like_rollback,         // xRollback
    fts5_like_findfunction,     // xFindFunction
    fts5_like_rename,           // xRename
    nullptr,                    // xSavepoint
    nullptr,                    // xRelease
    nullptr,                    // xRollbackTo
    nullptr,                    // xShadowName
    nullptr,                    // xIntegrity
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum input size for meaningful testing
    if (size < 16) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Step 1: Open an in-memory database
    sqlite3* db = nullptr;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }
    
    // Step 2: Test sqlite3_create_module_v2 directly (0% covered API)
    // Consume module name from fuzzed input
    std::string module_name = fdp.ConsumeRandomLengthString(20);
    if (module_name.empty()) {
        module_name = "fts5_like";
    }
    
    // Sanitize module name
    std::string safe_module_name;
    for (char c : module_name) {
        if (isalnum(c)) safe_module_name.push_back(c);
    }
    if (safe_module_name.empty()) safe_module_name = "fts5_like";
    
    // Test sqlite3_create_module_v2 with custom module
    void* module_user_data = nullptr; // Could be used for FTS5 global state
    rc = sqlite3_create_module_v2(db, safe_module_name.c_str(), &fts5_like_module, 
                                  module_user_data, nullptr);
    // Note: rc may fail if module name is invalid; continue anyway
    
    // Step 3: Also test built-in FTS5 module with SQL operations
    // Consume configuration options from fuzzed input
    uint8_t config_options = fdp.ConsumeIntegral<uint8_t>();
    
    // Determine table name for built-in FTS5
    std::string table_name = fdp.ConsumeRandomLengthString(20);
    if (table_name.empty()) {
        table_name = "fts5_test";
    }
    
    // Sanitize table name
    std::string safe_table_name;
    for (char c : table_name) {
        if (isalnum(c) || c == '_') safe_table_name.push_back(c);
    }
    if (safe_table_name.empty()) safe_table_name = "fts5_test";
    
    // Step 4: Create built-in FTS5 virtual table with various configurations
    std::string create_stmt;
    
    // Consume table configuration options
    bool contentless = (config_options & 0x01) != 0;
    bool external_content = (config_options & 0x02) != 0;
    bool columnsize_disabled = (config_options & 0x04) != 0;
    uint8_t tokenizer_type = fdp.ConsumeIntegral<uint8_t>() % 4;
    
    // Build CREATE VIRTUAL TABLE statement for built-in FTS5
    create_stmt = "CREATE VIRTUAL TABLE " + safe_table_name + " USING fts5(";
    
    // Add columns
    create_stmt += "title, body, author";
    
    // Add tokenizer configuration
    if (tokenizer_type == 0) {
        create_stmt += ", tokenize='unicode61'";
    } else if (tokenizer_type == 1) {
        create_stmt += ", tokenize='porter unicode61'";
    } else if (tokenizer_type == 2) {
        create_stmt += ", tokenize='trigram'";
    }
    // else default tokenizer
    
    // Add contentless option
    if (contentless) {
        create_stmt += ", content=''";
    }
    
    // Add external content option
    if (external_content) {
        create_stmt += ", content=external_content";
        // Create external content table
        std::string external_table = "CREATE TABLE external_content(id INTEGER PRIMARY KEY, title TEXT, body TEXT, author TEXT);";
        sqlite3_exec(db, external_table.c_str(), nullptr, nullptr, nullptr);
    }
    
    // Add columnsize option
    if (columnsize_disabled) {
        create_stmt += ", columnsize=0";
    }
    
    create_stmt += ");";
    
    // Execute CREATE VIRTUAL TABLE statement
    rc = sqlite3_exec(db, create_stmt.c_str(), nullptr, nullptr, nullptr);
    // Errors are acceptable for fuzzing - continue with other operations
    
    // Step 5: Insert data into FTS5 table (triggers fts5UpdateMethod)
    if (rc == SQLITE_OK) {
        // Consume number of insert operations
        uint8_t num_inserts = fdp.ConsumeIntegral<uint8_t>() % 5;
        
        for (uint8_t i = 0; i < num_inserts && fdp.remaining_bytes() > 10; i++) {
            std::string title = fdp.ConsumeRandomLengthString(50);
            std::string body = fdp.ConsumeRandomLengthString(200);
            std::string author = fdp.ConsumeRandomLengthString(30);
            
            // Build INSERT statement
            std::string insert_stmt = "INSERT INTO " + safe_table_name + 
                                      "(title, body, author) VALUES (?, ?, ?);";
            
            sqlite3_stmt* stmt = nullptr;
            rc = sqlite3_prepare_v2(db, insert_stmt.c_str(), -1, &stmt, nullptr);
            
            if (rc == SQLITE_OK && stmt != nullptr) {
                sqlite3_bind_text(stmt, 1, title.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 2, body.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 3, author.c_str(), -1, SQLITE_TRANSIENT);
                
                rc = sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }
    }
    
    // Step 6: Execute FTS5 queries (triggers fts5FilterMethod -> fts5NextMethod sequence)
    if (fdp.remaining_bytes() > 5) {
        // Consume query type
        uint8_t query_type = fdp.ConsumeIntegral<uint8_t>() % 6;
        std::string query_stmt;
        
        // Generate search terms from fuzzed input
        std::string search_term1 = fdp.ConsumeRandomLengthString(20);
        std::string search_term2 = fdp.ConsumeRandomLengthString(20);
        
        switch (query_type) {
            case 0:
                // Simple MATCH query
                query_stmt = "SELECT * FROM " + safe_table_name + 
                            " WHERE " + safe_table_name + " MATCH '" + search_term1 + "';";
                break;
            case 1:
                // Phrase search
                query_stmt = "SELECT * FROM " + safe_table_name + 
                            " WHERE " + safe_table_name + " MATCH '\"" + search_term1 + " " + search_term2 + "\"';";
                break;
            case 2:
                // Column-specific search
                query_stmt = "SELECT * FROM " + safe_table_name + 
                            " WHERE title MATCH '" + search_term1 + "';";
                break;
            case 3:
                // Boolean operator search
                query_stmt = "SELECT * FROM " + safe_table_name + 
                            " WHERE " + safe_table_name + " MATCH '" + search_term1 + " OR " + search_term2 + "';";
                break;
            case 4:
                // Prefix search
                query_stmt = "SELECT * FROM " + safe_table_name + 
                            " WHERE " + safe_table_name + " MATCH '" + search_term1 + "*';";
                break;
            case 5:
                // NEAR operator search
                query_stmt = "SELECT * FROM " + safe_table_name + 
                            " WHERE " + safe_table_name + " MATCH '" + search_term1 + " NEAR " + search_term2 + "';";
                break;
        }
        
        // Execute query using prepared statement to trigger full execution path
        sqlite3_stmt* query_stmt_ptr = nullptr;
        rc = sqlite3_prepare_v2(db, query_stmt.c_str(), -1, &query_stmt_ptr, nullptr);
        
        if (rc == SQLITE_OK && query_stmt_ptr != nullptr) {
            // Step through results (triggers fts5NextMethod)
            while (sqlite3_step(query_stmt_ptr) == SQLITE_ROW) {
                // Consume some columns to ensure full execution
                for (int col = 0; col < sqlite3_column_count(query_stmt_ptr); col++) {
                    // Just access the column - don't need to use the value
                    sqlite3_column_text(query_stmt_ptr, col);
                }
            }
            sqlite3_finalize(query_stmt_ptr);
        }
    }
    
    // Step 7: Test FTS5 auxiliary functions
    if (fdp.remaining_bytes() > 5) {
        // Test bm25() ranking function
        std::string bm25_query = "SELECT bm25(" + safe_table_name + ") FROM " + safe_table_name + 
                                " WHERE " + safe_table_name + " MATCH '" + 
                                fdp.ConsumeRandomLengthString(15) + "';";
        sqlite3_exec(db, bm25_query.c_str(), nullptr, nullptr, nullptr);
        
        // Test highlight() function
        std::string highlight_query = "SELECT highlight(" + safe_table_name + ", 0, '<b>', '</b>') FROM " + 
                                     safe_table_name + " WHERE " + safe_table_name + " MATCH '" + 
                                     fdp.ConsumeRandomLengthString(15) + "';";
        sqlite3_exec(db, highlight_query.c_str(), nullptr, nullptr, nullptr);
        
        // Test snippet() function
        std::string snippet_query = "SELECT snippet(" + safe_table_name + ", 0, '<b>', '</b>', '...', 10) FROM " + 
                                   safe_table_name + " WHERE " + safe_table_name + " MATCH '" + 
                                   fdp.ConsumeRandomLengthString(15) + "';";
        sqlite3_exec(db, snippet_query.c_str(), nullptr, nullptr, nullptr);
    }
    
    // Step 8: Test maintenance operations
    if (fdp.remaining_bytes() > 5) {
        // OPTIMIZE command
        std::string optimize_stmt = "INSERT INTO " + safe_table_name + 
                                   "(" + safe_table_name + ") VALUES('optimize');";
        sqlite3_exec(db, optimize_stmt.c_str(), nullptr, nullptr, nullptr);
        
        // REBUILD command (for contentless tables)
        if (contentless) {
            std::string rebuild_stmt = "INSERT INTO " + safe_table_name + 
                                      "(" + safe_table_name + ") VALUES('rebuild');";
            sqlite3_exec(db, rebuild_stmt.c_str(), nullptr, nullptr, nullptr);
        }
    }
    
    // Step 9: Test integrity check
    if (fdp.remaining_bytes() > 5) {
        std::string integrity_stmt = "SELECT integrity_check FROM " + safe_table_name + 
                                    " WHERE " + safe_table_name + " MATCH 'integrity-check';";
        sqlite3_exec(db, integrity_stmt.c_str(), nullptr, nullptr, nullptr);
    }
    
    // Step 10: Also test creating virtual table with our custom module
    if (fdp.remaining_bytes() > 10) {
        std::string custom_vtab_stmt = "CREATE VIRTUAL TABLE custom_fts USING " + 
                                      safe_module_name + " (title, body, author);";
        sqlite3_exec(db, custom_vtab_stmt.c_str(), nullptr, nullptr, nullptr);
    }
    
    // Step 11: Clean up
    if (!contentless && !external_content) {
        // Can't DROP contentless tables
        std::string drop_stmt = "DROP TABLE " + safe_table_name + ";";
        sqlite3_exec(db, drop_stmt.c_str(), nullptr, nullptr, nullptr);
    }
    
    // Drop external content table if created
    if (external_content) {
        sqlite3_exec(db, "DROP TABLE external_content;", nullptr, nullptr, nullptr);
    }
    
    // Close database connection
    sqlite3_close(db);
    
    return 0;
}
