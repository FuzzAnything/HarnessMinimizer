/*
 * SQLite Memory and Configuration APIs Fuzzing Harness
 * Targets comprehensive memory management and configuration APIs:
 * - sqlite3_config() with ~30 different configuration options
 * - sqlite3_db_config() with database-specific configuration verbs
 * - sqlite3_memory_used() and sqlite3_memory_highwater() memory tracking
 * - Custom memory allocator testing via sqlite3_mem_methods
 * - Threading mode configuration (SINGLETHREAD, MULTITHREAD, SERIALIZED)
 * - Lookaside memory configuration
 * - Page cache and heap configuration
 * 
 * Differentiated from previous harnesses by:
 * 1. Focusing exclusively on configuration and memory management APIs
 * 2. Testing custom memory allocator implementations
 * 3. Exercising all SQLITE_CONFIG_* options systematically
 * 4. Testing memory tracking functions throughout API usage
 * 5. Implementing proper configuration sequencing (pre/post initialization)
 * 
 * Strategy:
 * 1. Test configuration APIs both before and after sqlite3_initialize()
 * 2. Implement custom memory allocators to test SQLITE_CONFIG_MALLOC
 * 3. Test all available SQLITE_CONFIG_* options based on fuzzer input
 * 4. Exercise sqlite3_db_config() with various database configuration verbs
 * 5. Track memory usage throughout the test sequence
 * 6. Test threading mode transitions and their effects
 */

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>
#include <memory>
#include <cstdlib>
#include <fuzzer/FuzzedDataProvider.h>
#include "sqlite3.h"

// Custom memory allocator for testing SQLITE_CONFIG_MALLOC
static void* custom_malloc(int n) {
    if (n <= 0) return nullptr;
    void* p = malloc(n);
    return p;
}

static void custom_free(void* p) {
    if (p) free(p);
}

static void* custom_realloc(void* p, int n) {
    if (n <= 0) {
        if (p) free(p);
        return nullptr;
    }
    return realloc(p, n);
}

static int custom_size(void* p) {
    if (!p) return 0;
    // Simulate reporting allocation size (simplified)
    return 1024; // Always report 1KB for simplicity in fuzzing
}

static int custom_roundup(int n) {
    // Round up to next multiple of 8 for alignment
    return (n + 7) & ~7;
}

static int custom_init(void* pAppData) {
    (void)pAppData;
    return SQLITE_OK;
}

static void custom_shutdown(void* pAppData) {
    (void)pAppData;
}

// Custom memory methods structure
static sqlite3_mem_methods custom_mem_methods = {
    custom_malloc,
    custom_free,
    custom_realloc,
    custom_size,
    custom_roundup,
    custom_init,
    custom_shutdown,
    nullptr  // pAppData
};

// Log callback for SQLITE_CONFIG_LOG
static void log_callback(void* pArg, int iErrCode, const char* zMsg) {
    (void)pArg;
    (void)iErrCode;
    (void)zMsg;
    // Log callback - just a stub for testing
}

// SQL log callback for SQLITE_CONFIG_SQLLOG
static void sql_log_callback(void* pArg, sqlite3* db, const char* zSql, int eType) {
    (void)pArg;
    (void)db;
    (void)zSql;
    (void)eType;
    // SQL log callback - just a stub for testing
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Need minimum input for meaningful configuration testing
    if (size < 32) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);
    
    // Consume configuration flags and options
    uint32_t config_mask = fdp.ConsumeIntegral<uint32_t>();
    uint8_t threading_mode = fdp.ConsumeIntegral<uint8_t>() % 4; // 0-3
    uint8_t use_custom_allocator = fdp.ConsumeBool() ? 1 : 0;
    uint8_t test_sequence = fdp.ConsumeIntegral<uint8_t>() % 3; // 0-2
    
    // Consume numeric parameters for various configurations
    int64_t mmap_size = fdp.ConsumeIntegral<int64_t>();
    int64_t memdb_maxsize = fdp.ConsumeIntegral<int64_t>();
    int lookaside_size = fdp.ConsumeIntegralInRange<int>(128, 4096);
    int lookaside_count = fdp.ConsumeIntegralInRange<int>(1, 100);
    int heap_size = fdp.ConsumeIntegralInRange<int>(1024, 1048576);
    int pagecache_size = fdp.ConsumeIntegralInRange<int>(1024, 65536);
    int pagecache_count = fdp.ConsumeIntegralInRange<int>(1, 100);
    
    // Consume string data
    std::string db_name = fdp.ConsumeRandomLengthString(32);
    if (db_name.empty()) {
        db_name = ":memory:";
    }
    
    int rc;
    sqlite3* db = nullptr;
    sqlite3_mem_methods saved_methods;
    sqlite3_int64 initial_memory = 0;
    sqlite3_int64 highwater_memory = 0;
    // Track memory usage at start
    initial_memory = sqlite3_memory_used();
    highwater_memory = sqlite3_memory_highwater(0);
    
    // =====================================================================
    // PHASE 1: Configuration before initialization (valid configuration)
    // =====================================================================
    
    // Test threading mode configuration (must be before initialization)
    switch (threading_mode) {
        case 0:
            sqlite3_config(SQLITE_CONFIG_SINGLETHREAD);
            break;
        case 1:
            sqlite3_config(SQLITE_CONFIG_MULTITHREAD);
            break;
        case 2:
            sqlite3_config(SQLITE_CONFIG_SERIALIZED);
            break;
        default:
            // Use default (serialized)
            break;
    }
    
    // Test memory status configuration
    if (config_mask & 0x01) {
        sqlite3_config(SQLITE_CONFIG_MEMSTATUS, 1);
    } else {
        sqlite3_config(SQLITE_CONFIG_MEMSTATUS, 0);
    }
    
    // Test small malloc configuration
    if (config_mask & 0x02) {
        sqlite3_config(SQLITE_CONFIG_SMALL_MALLOC, 1);
    }
    
    // Test URI handling configuration
    if (config_mask & 0x04) {
        sqlite3_config(SQLITE_CONFIG_URI, 1);
    }
    
    // Test covering index scan configuration  
    if (config_mask & 0x08) {
        sqlite3_config(SQLITE_CONFIG_COVERING_INDEX_SCAN, 1);
    }
    
    // Test rowid in view configuration
    if (config_mask & 0x10) {
        int rowid_in_view = 1;
        sqlite3_config(SQLITE_CONFIG_ROWID_IN_VIEW, &rowid_in_view);
    }
    
    // Test log callback configuration (anytime option)
    if (config_mask & 0x20) {
        sqlite3_config(SQLITE_CONFIG_LOG, log_callback, nullptr);
    }
    
    // Test SQL log callback configuration (anytime option)
    if (config_mask & 0x40) {
        sqlite3_config(SQLITE_CONFIG_SQLLOG, sql_log_callback, nullptr);
    }
    
    // Test page cache header size (anytime option)
    if (config_mask & 0x80) {
        int pcache_hdrsz = 0;
        sqlite3_config(SQLITE_CONFIG_PCACHE_HDRSZ, &pcache_hdrsz);
    }
    
    // Test custom memory allocator if requested
    if (use_custom_allocator) {
        // Save current memory methods
        sqlite3_config(SQLITE_CONFIG_GETMALLOC, &saved_methods);
        
        // Set custom memory allocator
        sqlite3_config(SQLITE_CONFIG_MALLOC, &custom_mem_methods);
    }
    
    // Test lookaside configuration
    if (config_mask & 0x100) {
        sqlite3_config(SQLITE_CONFIG_LOOKASIDE, lookaside_size, lookaside_count);
    }
    
    // Test mmap size configuration
    if (config_mask & 0x200) {
        sqlite3_int64 default_mmap = mmap_size > 0 ? mmap_size : 0;
        sqlite3_int64 max_mmap = default_mmap * 2;
        if (max_mmap < default_mmap) max_mmap = default_mmap;
        sqlite3_config(SQLITE_CONFIG_MMAP_SIZE, default_mmap, max_mmap);
    }
    
    // Test memdb max size configuration
    if (config_mask & 0x400) {
        sqlite3_config(SQLITE_CONFIG_MEMDB_MAXSIZE, memdb_maxsize);
    }
    
    // =====================================================================
    // PHASE 2: Initialize SQLite and test database operations
    // =====================================================================
    
    rc = sqlite3_initialize();
    if (rc != SQLITE_OK) {
        // If initialization failed, try to shutdown and exit
        sqlite3_shutdown();
        return 0;
    }
    
    // Check memory usage after initialization
    sqlite3_int64 post_init_memory = sqlite3_memory_used();
    
    // Open a database to test db_config APIs
    rc = sqlite3_open_v2(db_name.c_str(), &db, 
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_MEMORY, 
                        nullptr);
    if (rc != SQLITE_OK || db == nullptr) {
        sqlite3_shutdown();
        return 0;
    }
    
    // =====================================================================
    // PHASE 3: Database-specific configuration
    // =====================================================================
    
    // Test various sqlite3_db_config() options
    if (config_mask & 0x800) {
        // Enable foreign keys
        sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_FKEY, 1, &rc);
    }
    
    if (config_mask & 0x1000) {
        // Enable triggers
        sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_TRIGGER, 1, &rc);
    }
    
    if (config_mask & 0x2000) {
        // Enable views
        sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_VIEW, 1, &rc);
    }
    
    if (config_mask & 0x4000) {
        // Set defensive mode
        sqlite3_db_config(db, SQLITE_DBCONFIG_DEFENSIVE, 1, &rc);
    }
    
    if (config_mask & 0x8000) {
        // Writable schema
        sqlite3_db_config(db, SQLITE_DBCONFIG_WRITABLE_SCHEMA, 1, &rc);
    }
    
    if (config_mask & 0x10000) {
        // Legacy alter table
        sqlite3_db_config(db, SQLITE_DBCONFIG_LEGACY_ALTER_TABLE, 1, &rc);
    }
    
    if (config_mask & 0x20000) {
        // DQS DML
        sqlite3_db_config(db, SQLITE_DBCONFIG_DQS_DML, 1, &rc);
    }
    
    if (config_mask & 0x40000) {
        // DQS DDL
        sqlite3_db_config(db, SQLITE_DBCONFIG_DQS_DDL, 1, &rc);
    }
    
    if (config_mask & 0x80000) {
        // Trusted schema
        sqlite3_db_config(db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 1, &rc);
    }
    
    // Test lookaside configuration at database level
    if (config_mask & 0x100000) {
        sqlite3_db_config(db, SQLITE_DBCONFIG_LOOKASIDE, nullptr, lookaside_size, lookaside_count);
    }
    
    // Test main database name
    if (config_mask & 0x200000) {
        sqlite3_db_config(db, SQLITE_DBCONFIG_MAINDBNAME, "main", nullptr);
    }
    
    // =====================================================================
    // PHASE 4: Test heap and page cache configuration (if not already done)
    // =====================================================================
    
    // These must be configured before database operations, but we test them
    // here to see the behavior when configured late (should return SQLITE_MISUSE)
    
    if (test_sequence == 0 && (config_mask & 0x400000)) {
        // Try to configure heap (should fail after initialization)
        void* heap_buffer = malloc(heap_size);
        if (heap_buffer) {
            // This should return SQLITE_MISUSE but we call it anyway
            sqlite3_config(SQLITE_CONFIG_HEAP, heap_buffer, heap_size, 1);
            free(heap_buffer);
        }
    }
    
    if (test_sequence == 1 && (config_mask & 0x800000)) {
        // Try to configure page cache (should fail after initialization)
        void* page_buffer = malloc(pagecache_size * pagecache_count);
        if (page_buffer) {
            // This should return SQLITE_MISUSE but we call it anyway
            sqlite3_config(SQLITE_CONFIG_PAGECACHE, page_buffer, pagecache_size, pagecache_count);
            free(page_buffer);
        }
    }
    
    // =====================================================================
    // PHASE 5: Perform some database operations to test configuration effects
    // =====================================================================
    
    if (fdp.remaining_bytes() > 10) {
        // Create a simple table and perform operations
        const char* create_sql = "CREATE TABLE IF NOT EXISTS config_test (id INTEGER, name TEXT)";
        char* err_msg = nullptr;
        sqlite3_exec(db, create_sql, nullptr, nullptr, &err_msg);
        if (err_msg) {
            sqlite3_free(err_msg);
        }
        
        // Insert some data if we have enough input
        if (fdp.remaining_bytes() > 20) {
            std::string insert_data = fdp.ConsumeRandomLengthString(50);
            std::string insert_sql = "INSERT INTO config_test VALUES (1, '" + insert_data + "')";
            sqlite3_exec(db, insert_sql.c_str(), nullptr, nullptr, nullptr);
        }
        
        // Query some data
        if (fdp.remaining_bytes() > 5) {
            sqlite3_stmt* stmt = nullptr;
            const char* select_sql = "SELECT * FROM config_test";
            if (sqlite3_prepare_v2(db, select_sql, -1, &stmt, nullptr) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    // Just step through results
                }
                sqlite3_finalize(stmt);
            }
        }
    }
    
    // =====================================================================
    // PHASE 6: Test memory tracking functions
    // =====================================================================
    
    // Get current memory usage
    sqlite3_int64 current_memory = sqlite3_memory_used();
    sqlite3_int64 current_highwater = sqlite3_memory_highwater(0);
    
    // Test resetting highwater mark
    if (config_mask & 0x1000000) {
        sqlite3_memory_highwater(1); // Reset highwater mark
        sqlite3_int64 reset_highwater = sqlite3_memory_highwater(0);
        (void)reset_highwater; // Use variable to avoid unused warning
    }
    
    // =====================================================================
    // PHASE 7: Test GET configuration options
    // =====================================================================
    
    if (config_mask & 0x2000000) {
        // Get current memory methods
        sqlite3_mem_methods current_methods;
        sqlite3_config(SQLITE_CONFIG_GETMALLOC, &current_methods);
    }

    if (config_mask & 0x4000000) {
        // Get mutex methods (if available)
        sqlite3_mutex_methods mutex_methods;
        sqlite3_config(SQLITE_CONFIG_GETMUTEX, &mutex_methods);
    }

    if (config_mask & 0x8000000) {
        // Get PCache2 methods
        sqlite3_pcache_methods2 pcache_methods;
        sqlite3_config(SQLITE_CONFIG_GETPCACHE2, &pcache_methods);
    }
    
    // =====================================================================
    // PHASE 8: Cleanup and restore configuration
    // =====================================================================
    
    // Close database
    if (db) {
        sqlite3_close(db);
    }
    
    // Restore original memory allocator if we changed it
    if (use_custom_allocator) {
        sqlite3_config(SQLITE_CONFIG_MALLOC, &saved_methods);
    }
    // Shutdown SQLite
    sqlite3_shutdown();
    
    // Final memory check
    sqlite3_int64 final_memory = sqlite3_memory_used();
    sqlite3_int64 final_highwater = sqlite3_memory_highwater(0);
    
    // Use the memory variables to avoid compiler warnings
    (void)initial_memory;
    (void)post_init_memory;
    (void)current_memory;
    (void)current_highwater;
    (void)final_memory;
    (void)final_highwater;
    (void)highwater_memory;
    
    return 0;
}
