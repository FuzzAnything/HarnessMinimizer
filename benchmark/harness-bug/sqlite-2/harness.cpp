#include <fuzzer/FuzzedDataProvider.h>
#include <sqlite3.h>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <cstring>

/*
 * SQLite Extension Loading Comprehensive Harness (harness_021.cpp)
 * 
 * Target: Extension loading APIs with 0% coverage and high complexity
 * Specifically targeting: 
 * - sqlite3_load_extension (0% coverage, 0 branches discovered)
 * - sqlite3_cancel_auto_extension (0% coverage, 4 branches undiscovered)
 * - sqlite3_drop_modules (0% coverage, 10 branches undiscovered)
 * 
 * Coverage focus: 
 * - Dynamic library loading infrastructure
 * - Extension registration and management
 * - Auto-extension lifecycle (register/cancel/reset)
 * - Virtual table module management (create/drop)
 * - Path validation and security checks for extension loading
 * 
 * Key APIs to target:
 * PRIMARY TARGETS:
 * 1. sqlite3_load_extension - Core API for loading external shared libraries
 * 2. sqlite3_cancel_auto_extension - Removes auto-loaded extensions
 * 3. sqlite3_drop_modules - Unregisters virtual table modules
 * 
 * SUPPORTING APIS:
 * 1. sqlite3_auto_extension - Registers extensions for automatic loading
 * 2. sqlite3_reset_auto_extension - Removes all auto-extension registrations
 * 3. sqlite3_enable_load_extension - Required to enable extension support
 * 4. sqlite3_create_module / sqlite3_create_module_v2 - Register virtual tables
 * 5. sqlite3_initialize / sqlite3_shutdown - Global initialization/cleanup
 * 
 * Semantic Differentiation from Existing Harnesses:
 * - harness_015: Tests auto_extension APIs minimally (NULL call only)
 * - harness_004: Basic virtual table creation (minimal implementation)
 * - harness_020: FTS5 operations (different semantic domain)
 * - This harness: Comprehensive extension loading lifecycle, including:
 *   * Dynamic library loading attempts (with fuzzed paths)
 *   * Complete auto-extension registration/cancellation cycle
 *   * Virtual table module creation and dropping
 *   * Error handling for invalid extension paths
 * 
 * Expected Coverage Gains:
 * - Target 100+ previously uncovered branches in extension loading infrastructure
 * - Exercise cross-platform dynamic linking code (dlopen/LoadLibrary paths)
 * - Test security validation for external code loading
 * - Reach complex module registration/deregistration logic
 */

// Minimal virtual table module implementation for testing create_module and drop_modules
static int test_vt_create(sqlite3* db, void* pAux,
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
    
    // Declare a simple virtual table schema
    int rc = sqlite3_declare_vtab(db, "CREATE TABLE test_vtab(id INTEGER, data TEXT)");
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

static int test_vt_connect(sqlite3* db, void* pAux,
                          int argc, const char* const* argv,
                          sqlite3_vtab** ppVTab, char** pzErr) {
    return test_vt_create(db, pAux, argc, argv, ppVTab, pzErr);
}

static int test_vt_bestindex(sqlite3_vtab* pVTab, sqlite3_index_info* pIdxInfo) {
    return SQLITE_OK;
}

static int test_vt_disconnect(sqlite3_vtab* pVTab) {
    if (pVTab) {
        sqlite3_free(pVTab);
    }
    return SQLITE_OK;
}

static int test_vt_destroy(sqlite3_vtab* pVTab) {
    return test_vt_disconnect(pVTab);
}

static int test_vt_open(sqlite3_vtab* pVTab, sqlite3_vtab_cursor** ppCursor) {
    // Allocate a minimal cursor structure
    sqlite3_vtab_cursor* pCursor = (sqlite3_vtab_cursor*)sqlite3_malloc(sizeof(sqlite3_vtab_cursor));
    if (!pCursor) {
        return SQLITE_ERROR;
    }
    memset(pCursor, 0, sizeof(sqlite3_vtab_cursor));
    *ppCursor = pCursor;
    return SQLITE_OK;
}

static int test_vt_close(sqlite3_vtab_cursor* pCursor) {
    if (pCursor) {
        sqlite3_free(pCursor);
    }
    return SQLITE_OK;
}

static int test_vt_filter(sqlite3_vtab_cursor* pCursor,
                         int idxNum, const char* idxStr,
                         int argc, sqlite3_value** argv) {
    return SQLITE_OK;
}

static int test_vt_next(sqlite3_vtab_cursor* pCursor) {
    return SQLITE_OK;
}

static int test_vt_eof(sqlite3_vtab_cursor* pCursor) {
    return 1; // Always at EOF for this simple implementation
}

static int test_vt_column(sqlite3_vtab_cursor* pCursor,
                         sqlite3_context* ctx, int col) {
    sqlite3_result_null(ctx);
    return SQLITE_OK;
}

static int test_vt_rowid(sqlite3_vtab_cursor* pCursor, sqlite3_int64* pRowid) {
    *pRowid = 0;
    return SQLITE_OK;
}

// Define the virtual table module structure
static sqlite3_module test_module = {
    0,                         // iVersion
    test_vt_create,            // xCreate
    test_vt_connect,           // xConnect
    test_vt_bestindex,         // xBestIndex
    test_vt_disconnect,        // xDisconnect
    test_vt_destroy,           // xDestroy
    test_vt_open,              // xOpen
    test_vt_close,             // xClose
    test_vt_filter,            // xFilter
    test_vt_next,              // xNext
    test_vt_eof,               // xEof
    test_vt_column,            // xColumn
    test_vt_rowid,             // xRowid
    nullptr,                   // xUpdate
    nullptr,                   // xBegin
    nullptr,                   // xSync
    nullptr,                   // xCommit
    nullptr,                   // xRollback
    nullptr,                   // xFindFunction
    nullptr,                   // xRename
    nullptr,                   // xSavepoint
    nullptr,                   // xRelease
    nullptr,                   // xRollbackTo
    nullptr                    // xShadowName
};

// Simple extension entry point function (mimics real extension initialization)
static void dummy_extension_init() {
    // Empty function - just for testing auto_extension registration
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum input size: need at least some bytes for configuration
    if (size < 8) return 0;
    
    FuzzedDataProvider fdp(data, size);
    
    // Step 1: Global initialization
    sqlite3_initialize();
    
    // Step 2: Create database connection
    sqlite3* db = nullptr;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK || !db) {
        sqlite3_shutdown();
        return 0;
    }
    
    // Step 3: Enable extension loading (required for load_extension to work)
    sqlite3_enable_load_extension(db, 1);
    
    // Consume configuration from fuzzer input
    uint8_t config = fdp.ConsumeIntegral<uint8_t>();
    
    // Step 4: Test auto-extension APIs based on configuration
    if (config & 0x01) {
        // Register auto-extension
        sqlite3_auto_extension((void(*)(void))dummy_extension_init);
        
        // Test cancel_auto_extension (PRIMARY TARGET)
        if (config & 0x02) {
            sqlite3_cancel_auto_extension((void(*)(void))dummy_extension_init);
        }
        
        // Test reset_auto_extension
        if (config & 0x04) {
            sqlite3_reset_auto_extension();
        }
    }
    
    // Step 5: Test load_extension API (PRIMARY TARGET)
    if (config & 0x08) {
        // Consume extension path from fuzzer input
        std::string extension_path = fdp.ConsumeRandomLengthString(256);
        
        // Consume entry point name (or use default)
        std::string entry_point;
        if (config & 0x10) {
            entry_point = fdp.ConsumeRandomLengthString(128);
        }
        
        char* err_msg = nullptr;
        
        // Attempt to load extension with fuzzed path
        // Note: This will likely fail with fuzzed paths, but will exercise
        // the path validation and error handling code paths
        rc = sqlite3_load_extension(
            db,
            extension_path.empty() ? nullptr : extension_path.c_str(),
            entry_point.empty() ? nullptr : entry_point.c_str(),
            &err_msg
        );
        
        // Clean up error message if any
        if (err_msg) {
            sqlite3_free(err_msg);
        }
        
        // Test with null parameters (edge cases)
        if (config & 0x20) {
            sqlite3_load_extension(db, nullptr, nullptr, nullptr);
        }
    }
    
    // Step 6: Test virtual table module APIs
    if (config & 0x40) {
        // Consume module name from fuzzer input
        std::string module_name = fdp.ConsumeRandomLengthString(64);
        if (module_name.empty()) {
            module_name = "fuzz_module";
        }
        
        // Create virtual table module
        rc = sqlite3_create_module_v2(
            db,
            module_name.c_str(),
            &test_module,
            nullptr,  // pAux
            nullptr   // xDestroy
        );
        
        // Also test the older create_module API
        if (config & 0x80) {
            sqlite3_create_module(
                db,
                module_name.c_str(),
                &test_module,
                nullptr
            );
        }
        
        // Test drop_modules API (PRIMARY TARGET)
        if ((config >> 8) & 0x01) {
            // Create array of module names to keep (or drop all)
            const char* keep_modules[2] = {nullptr, nullptr};
            
            if ((config >> 8) & 0x02) {
                // Keep specific module (test selective dropping)
                keep_modules[0] = module_name.c_str();
            }
            
            sqlite3_drop_modules(db, keep_modules);
        }
    }
    
    // Step 7: Test extension loading with various error conditions
    if ((config >> 8) & 0x04) {
        // Test with extremely long paths (buffer boundary tests)
        std::string long_path = fdp.ConsumeRandomLengthString(1024);
        char* err_msg = nullptr;
        sqlite3_load_extension(db, long_path.c_str(), nullptr, &err_msg);
        if (err_msg) sqlite3_free(err_msg);
        
        // Test with empty string paths
        sqlite3_load_extension(db, "", nullptr, nullptr);
        
        // Test with special characters in paths
        std::string special_path = fdp.ConsumeRandomLengthString(100);
        sqlite3_load_extension(db, special_path.c_str(), nullptr, nullptr);
    }
    
    // Step 8: Test concurrent operations
    if ((config >> 8) & 0x08) {
        // Multiple auto-extension registrations
        for (int i = 0; i < 3 && fdp.remaining_bytes() > 0; i++) {
            sqlite3_auto_extension((void(*)(void))dummy_extension_init);
        }
        
        // Multiple module creations with different names
        for (int i = 0; i < 2 && fdp.remaining_bytes() > 0; i++) {
            std::string mod_name = "mod_" + std::to_string(i);
            sqlite3_create_module(db, mod_name.c_str(), &test_module, nullptr);
        }
        
        // Reset all extensions
        sqlite3_reset_auto_extension();
    }
    
    // Step 9: Cleanup
    
    // Disable extension loading before closing
    sqlite3_enable_load_extension(db, 0);
    
    // Close database
    sqlite3_close_v2(db);
    
    // Global shutdown
    sqlite3_shutdown();
    
    return 0;
}
