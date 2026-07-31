// Eleventh fuzzing harness for liblouis library
// Target: Integration testing of bug-prone areas identified from previous crashes
// 1) Negative buffer length handling in translation/logging functions
// 2) Memory cleanup sequences and resource management around lou_free()
// 3) Table resolver memory allocation/deallocation patterns  
// 4) Order-of-validation issues in parameter checking
// Test these areas with varied sequences and edge cases to find related vulnerabilities

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <limits>
#include <unistd.h>

#include <fuzzer/FuzzedDataProvider.h>
#include "liblouis.h"

// Avoid log output during fuzzing
static void avoid_log(logLevels level, const char *msg) {
    (void)level;
    (void)msg;
}

// Global initialization flag
static int initialized = 0;

// Destructor to free resources
static void __attribute__((destructor)) free_resources(void) {
    lou_free();
}

// Helper function to convert bytes to widechar array for fuzzing
static int bytes_to_widechars(const uint8_t* data, size_t size, widechar* out, int max_out_len) {
    if (size == 0 || max_out_len <= 0) return 0;
    
    size_t chars_to_copy = size / sizeof(widechar);
    if (chars_to_copy > (size_t)max_out_len) {
        chars_to_copy = max_out_len;
    }
    
    for (size_t i = 0; i < chars_to_copy; i++) {
        out[i] = (widechar)data[i * sizeof(widechar) % size];
    }
    
    return (int)chars_to_copy;
}

// Custom table resolver for testing memory allocation/deallocation patterns
static char** test_table_resolver_memory_patterns(const char* table, const char* base) {
    if (!table || !base) return NULL;
    
    // Vary allocation patterns based on input
    size_t table_len = strlen(table);
    size_t base_len = strlen(base);
    
    // Create different allocation patterns
    int num_paths = 1 + (table_len % 5); // 1 to 5 paths
    char** result = (char**)malloc((num_paths + 1) * sizeof(char*));
    if (!result) return NULL;
    
    for (int i = 0; i < num_paths; i++) {
        // Vary allocation sizes
        size_t alloc_size = 10 + (table_len % 100) + (i * 20);
        result[i] = (char*)malloc(alloc_size);
        if (result[i]) {
            // Fill with pattern data
            snprintf(result[i], alloc_size, "%s-%s-%d", table, base, i);
        }
    }
    result[num_paths] = NULL;
    
    return result;
}

// Custom table resolver with edge cases
static char** test_table_resolver_edge_cases(const char* table, const char* base) {
    // Test various edge cases
    if (!table) {
        // Return empty array
        char** result = (char**)malloc(sizeof(char*));
        if (result) result[0] = NULL;
        return result;
    }
    
    if (strlen(table) == 0) {
        // Single empty string
        char** result = (char**)malloc(2 * sizeof(char*));
        if (!result) return NULL;
        result[0] = (char*)malloc(1);
        if (result[0]) result[0][0] = '\0';
        result[1] = NULL;
        return result;
    }
    
    // Normal case with multiple paths
    char** result = (char**)malloc(3 * sizeof(char*));
    if (!result) return NULL;
    
    result[0] = strdup(table);
    result[1] = (char*)malloc(256);
    if (result[1]) {
        snprintf(result[1], 256, "/usr/share/liblouis/tables/%s", table);
    }
    result[2] = NULL;
    
    return result;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Minimum size check
    if (size < 100) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Initialize library once
    if (!initialized) {
        lou_registerLogCallback(avoid_log);
        initialized = 1;
    }
    
    // ====== AREA 1: Negative buffer length handling in translation/logging functions ======
    
    // Create test buffers
    const int MAX_BUF_SIZE = 256;
    widechar inbuf[MAX_BUF_SIZE];
    widechar outbuf[MAX_BUF_SIZE];
    formtype typeform[MAX_BUF_SIZE];
    char spacing[MAX_BUF_SIZE];  // Changed from int to char
    
    // Initialize buffers
    for (int i = 0; i < MAX_BUF_SIZE; i++) {
        inbuf[i] = (widechar)(i % 256);
        outbuf[i] = 0;
        typeform[i] = plain_text;
        spacing[i] = 0;
    }
    
    // Generate various length test cases, including negatives
    std::vector<std::pair<int, int>> length_test_cases;
    // Consume test cases from fuzzer input
    int num_test_cases = fdp.ConsumeIntegralInRange<int>(1, 20);
    for (int i = 0; i < num_test_cases; i++) {
        int inlen = fdp.ConsumeIntegral<int>();
        int outlen = fdp.ConsumeIntegral<int>();
        length_test_cases.push_back({inlen, outlen});
    }
    
    // Add boundary values
    length_test_cases.push_back({0, 0});
    length_test_cases.push_back({-1, -1});
    length_test_cases.push_back({1, -1});
    length_test_cases.push_back({-1, 1});
    length_test_cases.push_back({std::numeric_limits<int>::max(), std::numeric_limits<int>::max()});
    length_test_cases.push_back({std::numeric_limits<int>::min(), std::numeric_limits<int>::min()});
    length_test_cases.push_back({std::numeric_limits<int>::max(), std::numeric_limits<int>::min()});
    
    // Create a temporary table file for testing
    static int counter = 0;
    char table_file[256];
    snprintf(table_file, sizeof(table_file), "/tmp/libfuzzer-harness10-%d.ctb", counter++);
    
    // Write table data
    std::vector<uint8_t> table_data = fdp.ConsumeBytes<uint8_t>(512);
    FILE *fp = fopen(table_file, "wb");
    if (!fp) {
        return 0;
    }
    fwrite(table_data.data(), 1, table_data.size(), fp);
    fclose(fp);
    
    // Test translation with various length parameters
    for (const auto& test_case : length_test_cases) {
        int inlen = test_case.first;
        int outlen = test_case.second;
        
        // Test lou_translateString with negative/edge case lengths
        lou_translateString(table_file, inbuf, &inlen, outbuf, &outlen, 
                           typeform, spacing, 0);
        
        // Test lou_backTranslateString  
        lou_backTranslateString(table_file, inbuf, &inlen, outbuf, &outlen,
                               typeform, spacing, 0);
        
        // Test with NULL pointers (order-of-validation issue)
        if (fdp.ConsumeBool()) {
            lou_translateString(NULL, inbuf, &inlen, outbuf, &outlen, NULL, NULL, 0);
        }
        
        if (fdp.ConsumeBool()) {
            lou_backTranslateString(NULL, inbuf, &inlen, outbuf, &outlen, NULL, NULL, 0);
        }
    }
    
    // ====== AREA 2: Memory cleanup sequences and resource management around lou_free() ======
    
    // Test various API sequences that allocate memory
    std::vector<const char*> test_operations;
    
    // Consume operations from fuzzer input
    int num_ops = fdp.ConsumeIntegralInRange<int>(1, 10);
    for (int i = 0; i < num_ops; i++) {
        int op = fdp.ConsumeIntegralInRange<int>(0, 7);
        switch (op) {
            case 0: test_operations.push_back("lou_getTable"); break;
            case 1: test_operations.push_back("lou_checkTable"); break;
            case 2: test_operations.push_back("lou_hyphenate"); break;
            case 3: test_operations.push_back("lou_translatePrehyphenated"); break;
            case 4: test_operations.push_back("lou_dotsToChar"); break;
            case 5: test_operations.push_back("lou_charToDots"); break;
            case 6: test_operations.push_back("lou_getEmphClasses"); break;
            case 7: test_operations.push_back("lou_getTableInfo"); break;
        }
    }
    
    // Execute operations in varied sequences
    for (const char* op_name : test_operations) {
        if (strcmp(op_name, "lou_getTable") == 0) {
            const void* table = lou_getTable(table_file);
            (void)table;
        } else if (strcmp(op_name, "lou_checkTable") == 0) {
            lou_checkTable(table_file);
        } else if (strcmp(op_name, "lou_hyphenate") == 0) {
            char hyphens[MAX_BUF_SIZE];
            int hyplen = MAX_BUF_SIZE;
            lou_hyphenate(table_file, inbuf, MAX_BUF_SIZE, hyphens, 0);
        } else if (strcmp(op_name, "lou_translatePrehyphenated") == 0) {
            int inlen = fdp.ConsumeIntegralInRange<int>(-10, 100);
            int outlen = fdp.ConsumeIntegralInRange<int>(-10, 100);
            int outputPos[MAX_BUF_SIZE];
            int inputPos[MAX_BUF_SIZE];
            int cursorPos = 0;
            char inputHyphens[MAX_BUF_SIZE];
            char outputHyphens[MAX_BUF_SIZE];
            lou_translatePrehyphenated(table_file, inbuf, &inlen, outbuf, &outlen,
                                      typeform, spacing, outputPos, inputPos, &cursorPos,
                                      inputHyphens, outputHyphens, 0);
        } else if (strcmp(op_name, "lou_dotsToChar") == 0) {
            widechar dots[MAX_BUF_SIZE];
            widechar chars[MAX_BUF_SIZE];
            for (int i = 0; i < MAX_BUF_SIZE; i++) {
                dots[i] = (widechar)(i % 256);
            }
            int length = fdp.ConsumeIntegralInRange<int>(1, MAX_BUF_SIZE);
            lou_dotsToChar(table_file, dots, chars, length, 0);
        } else if (strcmp(op_name, "lou_charToDots") == 0) {
            widechar chars[MAX_BUF_SIZE];
            widechar dots[MAX_BUF_SIZE];
            for (int i = 0; i < MAX_BUF_SIZE; i++) {
                chars[i] = (widechar)(i % 128);
            }
            int length = fdp.ConsumeIntegralInRange<int>(1, MAX_BUF_SIZE);
            lou_charToDots(table_file, chars, dots, length, 0);
        } else if (strcmp(op_name, "lou_getEmphClasses") == 0) {
            char const **classes = lou_getEmphClasses(table_file);
            if (classes) {
                lou_freeEmphClasses(classes);
            }
        } else if (strcmp(op_name, "lou_getTableInfo") == 0) {
            char* info = lou_getTableInfo(table_file, "locale");
            if (info) {
                lou_freeTableInfo(info);
            }
        }
        
        // Occasionally call lou_free() in the middle of sequences
        if (fdp.ConsumeProbability<double>() < 0.1) {
            lou_free();
            // Re-initialize
            lou_registerLogCallback(avoid_log);
        }
    }
    
    // ====== AREA 3: Table resolver memory allocation/deallocation patterns ======
    
    // Register different table resolvers
    if (fdp.ConsumeBool()) {
        lou_registerTableResolver(test_table_resolver_memory_patterns);
        
        // Use the custom resolver
        const void* table = lou_getTable("test-table");
        (void)table;
        
        // Register another resolver
        lou_registerTableResolver(test_table_resolver_edge_cases);
        
        // Use again
        table = lou_getTable("another-table");
        (void)table;
        
        // Restore default resolver
        lou_registerTableResolver(NULL);
    }
    
    // Test table finding APIs which use resolvers
    if (fdp.ConsumeBool()) {
        char* found = lou_findTable("en");
        if (found) {
            lou_freeTableFile(found);
        }
        
        char** tables = lou_findTables("en");
        if (tables) {
            lou_freeTableFiles(tables);
        }
        
        char** list = lou_listTables();
        if (list) {
            lou_freeTableFiles(list);
        }
    }
    
    // Test table indexing
    if (fdp.ConsumeBool()) {
        const char* table_list[] = {table_file, NULL};
        lou_indexTables(table_list);
    }
    
    // ====== AREA 4: Order-of-validation issues in parameter checking ======
    
    // Test parameter validation order with various invalid inputs
    std::vector<const char*> invalid_tables;
    invalid_tables.push_back(NULL);
    invalid_tables.push_back("");
    invalid_tables.push_back("/nonexistent/path/table.ctb");
    invalid_tables.push_back(table_file); // Valid for comparison
    
    // Test various APIs with invalid parameters in different orders
    for (const char* table : invalid_tables) {
        // Test with NULL buffers
        lou_translateString(table, NULL, NULL, NULL, NULL, NULL, NULL, 0);
        lou_backTranslateString(table, NULL, NULL, NULL, NULL, NULL, NULL, 0);
        
        // Test with invalid lengths
        int invalid_len = fdp.ConsumeIntegral<int>();
        lou_translateString(table, inbuf, &invalid_len, outbuf, &invalid_len, NULL, NULL, 0);
        // Test hyphenation with invalid params
        int hyplen = fdp.ConsumeIntegral<int>();
        lou_hyphenate(table, NULL, hyplen, NULL, 0);
        
        // Test compileString with invalid input
        if (table) {
            const char* invalid_string = fdp.ConsumeBool() ? NULL : "";
            lou_compileString(table, invalid_string);
        }
    }
    
    // Test logging functions directly
    if (fdp.ConsumeBool()) {
        // These might be internal but we can test through public APIs
        // that trigger logging
        
        // Set log level from environment
        lou_setLogLevel(LOU_LOG_ALL);
        
        // Test with various log levels
        std::vector<logLevels> levels = {
            LOU_LOG_ALL, LOU_LOG_DEBUG, LOU_LOG_INFO, 
            LOU_LOG_WARN, LOU_LOG_ERROR, LOU_LOG_FATAL
        };
        
        for (logLevels level : levels) {
            lou_setLogLevel(level);
            
            // Perform translation which triggers logging
            int test_inlen = fdp.ConsumeIntegralInRange<int>(-5, 20);
            int test_outlen = fdp.ConsumeIntegralInRange<int>(-5, 20);
            lou_translateString(table_file, inbuf, &test_inlen, outbuf, &test_outlen, NULL, NULL, 0);
        }
    }
    
    // Clean up
    unlink(table_file);
    
    return 0;
}
