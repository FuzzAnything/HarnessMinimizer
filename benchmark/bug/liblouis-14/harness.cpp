// liblouis fuzzing harness - maketable.c utility functions and gnulib memory allocation focus
// Targets: maketable.c utility functions (loadTable, hyphenationEnabled, isLetter, toLowercase, toDotPattern)
//          gnulib memory allocation (mmalloca, freea)
// Uses FuzzedDataProvider for structured input processing
// Focus on unexplored code paths orthogonal to existing translation-focused harnesses
// Based on coverage guidance report: maketable.c (5.15% region coverage) and gnulib/malloca.c (0% coverage)

#include <fuzzer/FuzzedDataProvider.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <vector>
#include <string>

// Include liblouis headers
#include <liblouis/liblouis.h>

// Forward declarations for maketable.c utility functions
// These are defined in maketable.c with extern linkage
extern "C" {
    void loadTable(const char *tableList);
    int hyphenationEnabled();
    int isLetter(widechar c);
    widechar toLowercase(widechar c);
    void toDotPattern(widechar *braille, char *pattern);
    // Note: printRule is complex and requires proper rule structure, skipping for now
}

// Forward declarations for gnulib memory allocation functions
// These are defined in gnulib/malloca.c
extern "C" {
    void *mmalloca(size_t n);
    void freea(void *p);
}



// Global initialization flag
static int initialized = 0;

// Log callback to suppress output during fuzzing
void avoid_log(logLevels level, const char *msg) {
    (void)level;
    (void)msg;
}

// Cleanup function
static void free_resources(void) {
    lou_free();
}

// Helper function to create a temporary table file from fuzzer data
static char* create_temp_table_file(const uint8_t* data, size_t size) {
    static int file_counter = 0;
    char filename[256];
    snprintf(filename, sizeof(filename), "/tmp/liblouis-utility-%d-%d.ctb", getpid(), file_counter++);
    
    // Determine how much data to write to the file (min 1 byte, max 1024 bytes)
    size_t file_size = (size > 0) ? (size % 1024) + 1 : 1;
    if (file_size > size) file_size = size;
    
    FILE* fp = fopen(filename, "wb");
    if (!fp) {
        return NULL;
    }
    
    fwrite(data, 1, file_size, fp);
    fclose(fp);
    
    // Duplicate filename for caller to free
    return strdup(filename);
}

// Helper to create widechar string from fuzzer input
static widechar* create_widechar_string(FuzzedDataProvider& fdp, size_t max_len = 256) {
    std::string str = fdp.ConsumeRandomLengthString(max_len);
    if (str.empty()) {
        return NULL;
    }
    
    widechar* wstr = (widechar*)malloc((str.length() + 1) * sizeof(widechar));
    if (!wstr) {
        return NULL;
    }
    
    for (size_t i = 0; i < str.length(); i++) {
        wstr[i] = (widechar)str[i];
    }
    wstr[str.length()] = 0;
    
    return wstr;
}

// Helper to test mmalloca with various sizes and patterns
static void test_mmalloca_patterns(FuzzedDataProvider& fdp) {
    // Test different allocation sizes
    size_t num_allocs = fdp.ConsumeIntegralInRange<size_t>(1, 10);
    
    void** allocations = (void**)malloc(num_allocs * sizeof(void*));
    if (!allocations) {
        return;
    }
    
    for (size_t i = 0; i < num_allocs; i++) {
        size_t alloc_size = fdp.ConsumeIntegralInRange<size_t>(1, 4096);
        allocations[i] = mmalloca(alloc_size);
        
        // If allocation succeeded, write some data to it
        if (allocations[i]) {
            // Write some pattern to the allocation
            uint8_t pattern = fdp.ConsumeIntegral<uint8_t>();
            memset(allocations[i], pattern, alloc_size);
        }
    }
    
    // Free allocations in reverse order
    for (size_t i = 0; i < num_allocs; i++) {
        if (allocations[i]) {
            freea(allocations[i]);
        }
    }
    
    free(allocations);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Minimum size check - need enough data for utility function testing
    if (size < 32) return 0;
    
    FuzzedDataProvider fdp(data, size);
    
    // Initialize liblouis once
    if (!initialized) {
        lou_registerLogCallback(avoid_log);
        initialized = 1;
        // Register cleanup
        atexit(free_resources);
    }
    
    // Consume operation type to decide which utility functions to test
    uint8_t operation = fdp.ConsumeIntegral<uint8_t>() % 8;
    
    // Create a temporary table file for loadTable testing
    std::vector<uint8_t> table_data = fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<size_t>(1, 512));
    char* temp_filename = create_temp_table_file(table_data.data(), table_data.size());
    
    // If we couldn't create a temp file, still proceed with other tests
    // (some operations don't need a file)
    
    // Test different utility functions based on operation
    switch (operation) {
        case 0: {
            // Test loadTable and hyphenationEnabled
            if (temp_filename) {
                loadTable(temp_filename);
                (void)hyphenationEnabled(); // Call but ignore result
            }
            break;
        }
        
        case 1: {
            // Test isLetter with various characters
            // First ensure table is loaded
            if (temp_filename) {
                loadTable(temp_filename);
            } else {
                // If no temp file, skip isLetter test to avoid NULL dereference
                break;
            }
            
            size_t num_chars = fdp.ConsumeIntegralInRange<size_t>(1, 50);
            for (size_t i = 0; i < num_chars; i++) {
                widechar c = fdp.ConsumeIntegral<widechar>();
                (void)isLetter(c); // Call but ignore result
            }
            break;
        }
        
        case 2: {
            // Test toLowercase with various characters
            // First ensure table is loaded
            if (temp_filename) {
                loadTable(temp_filename);
            } else {
                // If no temp file, skip toLowercase test to avoid NULL dereference
                break;
            }
            
            size_t num_chars = fdp.ConsumeIntegralInRange<size_t>(1, 50);
            for (size_t i = 0; i < num_chars; i++) {
                widechar c = fdp.ConsumeIntegral<widechar>();
                (void)toLowercase(c); // Call but ignore result
            }
            break;
        }
        
        case 3: {
            // Test toDotPattern - requires displayTable from loadTable
            if (temp_filename) {
                loadTable(temp_filename);
            } else {
                // If no temp file, skip toDotPattern test to avoid NULL dereference
                break;
            }
            
            widechar* braille_str = create_widechar_string(fdp, 50);
            if (braille_str) {
                char pattern[256];
                toDotPattern(braille_str, pattern);
                free(braille_str);
            }
            break;
        }
        
        case 4: {
            // Test mmalloca memory allocation patterns
            test_mmalloca_patterns(fdp);
            break;
        }
        
        case 5: {
            // Test combination of multiple utility functions
            if (temp_filename) {
                loadTable(temp_filename);
                (void)hyphenationEnabled();
                
                // Test character functions
                size_t num_chars = fdp.ConsumeIntegralInRange<size_t>(1, 20);
                for (size_t i = 0; i < num_chars; i++) {
                    widechar c = fdp.ConsumeIntegral<widechar>();
                    (void)isLetter(c);
                    (void)toLowercase(c);
                }
            }
            break;
        }
        
        
        case 6: {
            // Test memory allocation edge cases
            // Test mmalloca with zero size (if allowed)
            size_t zero_alloc_size = 0;
            void* zero_alloc = mmalloca(zero_alloc_size);
            if (zero_alloc) {
                freea(zero_alloc);
            }
            
            // Test with large allocation size
            size_t large_size = fdp.ConsumeIntegralInRange<size_t>(4097, 8192);
            void* large_alloc = mmalloca(large_size);
            if (large_alloc) {
                freea(large_alloc);
            }
            
            // Test with random size
            size_t random_size = fdp.ConsumeIntegralInRange<size_t>(1, 1024);
            void* random_alloc = mmalloca(random_size);
            if (random_alloc) {
                uint8_t fill = fdp.ConsumeIntegral<uint8_t>();
                memset(random_alloc, fill, random_size);
                freea(random_alloc);
            }
            break;
        }
        
        case 7: {
            // Edge case testing with minimal input consumption
            // Test with empty or near-empty inputs
            // Only test character functions if we have a table loaded
            if (temp_filename) {
                if (fdp.ConsumeBool()) {
                    loadTable(temp_filename);
                } else {
                    // If we don't load table, skip character functions
                    break;
                }
            } else {
                // No temp file, skip this test case
                break;
            }
            
            // Test with boundary values (table is now loaded)
            widechar boundary_chars[] = {0, 1, 127, 128, 255, 256, 65535};
            for (size_t i = 0; i < sizeof(boundary_chars)/sizeof(boundary_chars[0]); i++) {
                if (fdp.ConsumeBool()) {
                    (void)isLetter(boundary_chars[i]);
                    (void)toLowercase(boundary_chars[i]);
                }
            }
            break;
        }
    }
    
    // Clean up temp file
    if (temp_filename) {
        unlink(temp_filename);
        free(temp_filename);
    }
    
    return 0;
}
