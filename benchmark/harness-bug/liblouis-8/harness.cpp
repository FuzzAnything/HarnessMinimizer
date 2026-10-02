// liblouis fuzzing harness - Direct testing of maketable.c internal functions
// Targets: loadTable (primary - 0% coverage, 1188 undiscovered branches)
//          hyphenationEnabled, isLetter, toLowercase, toDotPattern
// Note: printRule is excluded because TranslationTableRule is an internal type
// Based on coverage guidance: /root/FuzzAgent/output/liblouis/coverage_guidance/harness_013_guidance.md
// Uses FuzzedDataProvider for structured input processing
// Follows pattern from tests/suggestChunks.c for extern declarations

#include <fuzzer/FuzzedDataProvider.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <liblouis/liblouis.h>
#include <assert.h>
#include <vector>
#include <string>
void avoid_log(logLevels level, const char *msg) {
    (void)level;
    (void)msg;
}

// Cleanup function
static void free_resources(void) {
    lou_free();
}

// External declarations matching maketable.c functions
// These functions are not part of the public API and must be declared as extern
extern "C" {
    extern void loadTable(const char *tableList);
    extern int hyphenationEnabled();
    extern int isLetter(widechar c);
    extern widechar toLowercase(widechar c);
    extern void toDotPattern(widechar *braille, char *pattern);
    // Note: printRule is excluded because TranslationTableRule is an internal type
    // extern int printRule(TranslationTableRule *rule, widechar *rule_string);
}
// Helper to convert std::string to widechar array
static std::vector<widechar> string_to_widechar(const std::string& str) {
    std::vector<widechar> wide_str;
    wide_str.reserve(str.length());
    
    for (size_t i = 0; i < str.length(); i++) {
        // Simple conversion - actual encoding handled by liblouis
        wide_str.push_back(static_cast<widechar>(str[i]));
    }
    
    return wide_str;
}

// Select a table from liblouis test data
static std::string select_test_table(FuzzedDataProvider& fdp) {
    // Tables from liblouis tests directory that should be available
    const char* test_tables[] = {
        "tests/tables/suggestChunks.ctb",  // Used in suggestChunks.c
        "tests/tables/empty.ctb",          // Empty table for edge cases
        "tests/tables/large.ctb",          // Large table for stress testing
        "tests/tables/bad.ctb",            // Invalid table for error handling
        "tests/tables/loop.ctb",           // Table with loop for special cases
        "tests/tables/attribute/attributeName_valid.utb",   // Valid attribute table
        "tests/tables/attribute/attributeName_invalid.utb", // Invalid attribute table
        "tests/tables/emphclass/emphclass_valid.utb",       // Valid emphasis class
        "tests/tables/emphclass/emphclass_invalid_1.utb",   // Invalid emphasis class 1
        "tests/tables/emphclass/emphclass_invalid_2.utb",   // Invalid emphasis class 2
        "tests/tables/context-ignored.utb",                 // Context ignored table
    };
    
    size_t table_index = fdp.ConsumeIntegralInRange<size_t>(0, 
        sizeof(test_tables)/sizeof(test_tables[0]) - 1);
    return std::string(test_tables[table_index]);
}

// Select a character for isLetter/toLowercase testing
static widechar select_test_character(FuzzedDataProvider& fdp) {
    uint8_t char_type = fdp.ConsumeIntegral<uint8_t>() % 8;
    
    switch (char_type) {
        case 0:
            // ASCII letter
            return static_cast<widechar>(fdp.ConsumeIntegralInRange<int>('A', 'Z'));
        case 1:
            // ASCII lowercase letter
            return static_cast<widechar>(fdp.ConsumeIntegralInRange<int>('a', 'z'));
        case 2:
            // ASCII digit
            return static_cast<widechar>(fdp.ConsumeIntegralInRange<int>('0', '9'));
        case 3:
            // ASCII punctuation
            return static_cast<widechar>(fdp.PickValueInArray({'.', ',', '!', '?', ';', ':'}));
        case 4:
            // Extended ASCII
            return static_cast<widechar>(fdp.ConsumeIntegralInRange<int>(128, 255));
        case 5:
            // Unicode-like value
            return static_cast<widechar>(fdp.ConsumeIntegralInRange<int>(256, 0xFFFF));
        case 6:
            // Zero/null character
            return 0;
        case 7:
            // Random value
            return static_cast<widechar>(fdp.ConsumeIntegral<uint16_t>());
        default:
            return static_cast<widechar>('A');
    }
}

// Generate braille string for toDotPattern testing
static std::vector<widechar> generate_braille_string(FuzzedDataProvider& fdp) {
    size_t length = fdp.ConsumeIntegralInRange<size_t>(0, 100);
    std::vector<widechar> braille;
    braille.reserve(length + 1);
    
    for (size_t i = 0; i < length; i++) {
        // Braille characters are typically in specific ranges
        // Generate random values that might be valid braille dots
        uint8_t braille_type = fdp.ConsumeIntegral<uint8_t>() % 4;
        switch (braille_type) {
            case 0:
                // ASCII letter (could be interpreted as braille)
                braille.push_back(static_cast<widechar>(fdp.ConsumeIntegralInRange<int>('A', 'Z')));
                break;
            case 1:
                // ASCII digit
                braille.push_back(static_cast<widechar>(fdp.ConsumeIntegralInRange<int>('0', '9')));
                break;
            case 2:
                // Braille dot patterns (0-255)
                braille.push_back(static_cast<widechar>(fdp.ConsumeIntegral<uint8_t>()));
                break;
            case 3:
                // Extended values
                braille.push_back(static_cast<widechar>(fdp.ConsumeIntegralInRange<int>(256, 0xFFFF)));
                break;
        }
    }
    
    // Null-terminate
    braille.push_back(0);
    return braille;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Minimum size check - need enough data for table loading and function testing
    if (size < 16) return 0;
    
    FuzzedDataProvider fdp(data, size);
    
    // Initialize liblouis once per process
    static int initialized = 0;
    if (!initialized) {
        // Set up logging to avoid console output during fuzzing
        lou_registerLogCallback(avoid_log);
        lou_setLogLevel(LOU_LOG_WARN); // Only show warnings and errors
        
        // Set data path to include test tables
        // Use both system tables and test tables directories
        lou_setDataPath("/usr/share/liblouis/tables:/root/src/liblouis/tables:/root/src/liblouis/tests/tables");
        
        initialized = 1;
        // Register cleanup
        atexit(free_resources);
    }
    
    // Consume operation type to decide testing strategy
    uint8_t operation = fdp.ConsumeIntegral<uint8_t>() % 5;
    
    // Select a test table
    std::string table_name = select_test_table(fdp);
    
    // Operation 0: Test loadTable with various table names
    if (operation == 0) {
        // Try to load the table
        loadTable(table_name.c_str());
        
        // After loading, test hyphenationEnabled
        // Note: This depends on the loaded table having hyphenation support
        hyphenationEnabled();
        
        return 0;
    }
    
    // Operation 1-4: First load a valid table, then test specific functions
    // Load a known valid table first to ensure functions have proper context
    loadTable("tests/tables/suggestChunks.ctb");
    
    switch (operation) {
        case 1: {
            // Test isLetter with various characters
            widechar test_char = select_test_character(fdp);
            int result = isLetter(test_char);
            (void)result; // Result ignored for fuzzing
            break;
        }
        
        case 2: {
            // Test toLowercase with various characters
            widechar test_char = select_test_character(fdp);
            widechar result = toLowercase(test_char);
            (void)result; // Result ignored for fuzzing
            break;
        }
        
        case 3: {
            // Test toDotPattern with generated braille string
            std::vector<widechar> braille = generate_braille_string(fdp);
            // Pattern buffer needs to be large enough for the output
            // toDotPattern generates ASCII dot patterns like "123-456"
            char pattern[1024];
            toDotPattern(braille.data(), pattern);
            break;
        }
        
        case 4: {
            // Combined test: load different tables and test multiple functions
            loadTable(table_name.c_str());
            
            // Test a few functions with the newly loaded table
            widechar test_char = select_test_character(fdp);
            isLetter(test_char);
            toLowercase(test_char);
            
            // Quick braille test if we have enough data
            if (fdp.remaining_bytes() > 10) {
                std::vector<widechar> braille = generate_braille_string(fdp);
                char pattern[1024];
                toDotPattern(braille.data(), pattern);
            }
            
            hyphenationEnabled();
            break;
        }
        
        default:
            // Should never reach here (operation 0 handled above)
            break;
    }
    
    return 0;
    
    return 0;
}
