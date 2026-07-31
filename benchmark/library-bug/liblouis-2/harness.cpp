/*
 * liblouis Deep Table Compilation and Hyphenation Fuzzing Harness
 *
 * Copyright (C) 2024 Fuzzing Harness Generator
 *
 * This harness specifically targets deep table compilation paths and hyphenation
 * subsystem based on coverage analysis guidance targeting the largest coverage gaps:
 * - compileRule (495 blocked branches) - largest single blocker
 * - lou_hyphenate (48 undiscovered branches) - highest among APIs
 * - compileHyphenation (173 blocked branches)
 *
 * Target APIs and coverage objectives:
 * 1. lou_compileString - with ISO/UTF-8 headers to trigger hyphenation compilation path
 * 2. lou_hyphenate - comprehensive testing with compiled tables
 * 3. lou_setDataPath - configure table search directory
 * 4. lou_getTable - retrieve compiled table for testing
 * 5. lou_free - memory cleanup
 *
 * Specific opcode coverage targets (currently 0 hits):
 * - CTO_Letter opcode (character class definition)
 * - CTO_Grouping opcode  
 * - CTO_UpLow opcode (case transformations)
 *
 * It follows the deep compilation workflow: setup (configure paths), compilation
 * (compile table strings with specific headers/opcodes), testing (hyphenation with
 * compiled tables), cleanup.
 * Uses FuzzedDataProvider to properly split fuzzer input for various parameters.
 * Semantic differentiation from previous harnesses: harness_000 (translation),
 * harness_001 (hyphenation), harness_002 (metadata), harness_003 (basic compilation),
 * harness_004 (logging) - this harness focuses exclusively on deep compilation
 * internals and specific uncovered opcodes.
 */

#include <fuzzer/FuzzedDataProvider.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <string>

#include <liblouis/liblouis.h>

// Common table names used in liblouis testing
static const char* COMMON_TABLES[] = {
    "en-us-g2.ctb",
    "en-ueb-g2.ctb", 
    "en-gb-g2.ctb",
    "de-de-g2.ctb",
    "fr-bfu-comp6.ctb",
    "es-g2.ctb",
    NULL
};

// Hyphenation modes for testing
static const int HYPHENATION_MODES[] = {
    0,  // Default mode
    1,  // Alternative modes if available
};

// Avoid logging during fuzzing
static void avoid_log(logLevels level, const char *msg) {
    (void)level;
    (void)msg;
}

// Global initialization flag
static int initialized = 0;

// Cleanup function
static void __attribute__((destructor)) free_resources(void) {
    lou_free();
}

// Generate a table string with specific opcodes for deep compilation testing
static std::string generate_table_string(FuzzedDataProvider& fdp) {
    std::string table_str;
    
    // Start with ISO or UTF-8 header (triggers hyphenation compilation in compileRule)
    bool use_iso = fdp.ConsumeBool();
    if (use_iso) {
        table_str += "ISO\n";
    } else {
        table_str += "UTF-8\n";
    }
    
    // Add CTO_Letter opcode definitions (character class)
    // Format: letter <character> <dots>
    table_str += "letter ";
    
    // Add a letter character (single character)
    char letter_char = 'a' + (fdp.ConsumeIntegral<uint8_t>() % 26);
    table_str += letter_char;
    table_str += ' ';
    
    // Add braille dots (1-8 in liblouis format)
    uint8_t dots = fdp.ConsumeIntegral<uint8_t>() % 255 + 1;
    // Convert to braille dot pattern (liblouis uses binary representation)
    for (int i = 0; i < 8; i++) {
        if (dots & (1 << i)) {
            table_str += '1' + i;
        }
    }
    table_str += '\n';
    
    // Add CTO_Grouping opcode
    // Format: grouping <characters> <dots>
    table_str += "grouping ";
    
    // Add grouping characters (2-4 characters)
    size_t group_len = fdp.ConsumeIntegralInRange<size_t>(2, 4);
    for (size_t i = 0; i < group_len; i++) {
        char group_char = 'a' + (fdp.ConsumeIntegral<uint8_t>() % 26);
        table_str += group_char;
    }
    table_str += ' ';
    
    // Add grouping dots
    uint8_t group_dots = fdp.ConsumeIntegral<uint8_t>() % 255 + 1;
    for (int i = 0; i < 8; i++) {
        if (group_dots & (1 << i)) {
            table_str += '1' + i;
        }
    }
    table_str += '\n';
    
    // Add CTO_UpLow opcode (case transformation)
    // Format: uplow <lowercase> <uppercase> <dots>
    table_str += "uplow ";
    
    // Lowercase character
    char lower_char = 'a' + (fdp.ConsumeIntegral<uint8_t>() % 26);
    table_str += lower_char;
    table_str += ' ';
    
    // Uppercase character  
    char upper_char = 'A' + (fdp.ConsumeIntegral<uint8_t>() % 26);
    table_str += upper_char;
    table_str += ' ';
    
    // Braille dots for the transformation
    uint8_t uplow_dots = fdp.ConsumeIntegral<uint8_t>() % 255 + 1;
    for (int i = 0; i < 8; i++) {
        if (uplow_dots & (1 << i)) {
            table_str += '1' + i;
        }
    }
    table_str += '\n';
    
    // Add some basic translation rules for testing hyphenation
    table_str += "always aa 1-1\n";
    table_str += "always bb 12-12\n";
    table_str += "always cc 14-14\n";
    
    return table_str;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Minimum size check for deep compilation testing
    // Need enough for path, table string generation, and hyphenation input
    if (size < 64) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Initialize library once
    if (!initialized) {
        lou_registerLogCallback(avoid_log);
        initialized = 1;
    }
    
    // PHASE 1: SETUP - Configure table search path
    
    // Consume and set data path
    if (fdp.remaining_bytes() > 20) {
        size_t path_len = fdp.ConsumeIntegralInRange<size_t>(1, 100);
        std::string path_str = fdp.ConsumeBytesAsString(path_len);
        if (!path_str.empty()) {
            lou_setDataPath(path_str.c_str());
        }
    }
    
    // Get current data path (for debugging/coverage)
    const char* current_path = lou_getDataPath();
    (void)current_path;
    
    // PHASE 2: DEEP TABLE COMPILATION
    
    // Select a table name for compilation context
    uint8_t table_choice = fdp.ConsumeIntegral<uint8_t>() % 6;
    const char* table_list = COMMON_TABLES[table_choice];
    
    // Generate table string with specific opcodes for deep compilation
    std::string table_string = generate_table_string(fdp);
    
    if (table_string.empty()) {
        return 0;
    }
    
    // Compile the table string - this should trigger compileHyphenation path
    // due to ISO/UTF-8 header and exercise compileRule with CTO_Letter,
    // CTO_Grouping, CTO_UpLow opcodes
    int compile_result = lou_compileString(table_list, table_string.c_str());
    
    // Result can be 0 (failure) or 1 (success) - both are valid test outcomes
    // Failures may be due to malformed table syntax, which exercises error paths
    (void)compile_result;
    
    // Get the compiled table for testing
    // Note: lou_getTable returns a pointer to the compiled translation table
    const void* compiled_table = lou_getTable(table_list);
    (void)compiled_table;
    
    // PHASE 3: HYPHENATION TESTING WITH COMPILED TABLE
    
    // Test hyphenation with various inputs and modes
    // Consume hyphenation mode
    uint8_t mode_choice = fdp.ConsumeIntegral<uint8_t>() % 2;
    int hyphen_mode = HYPHENATION_MODES[mode_choice];
    
    // Prepare input buffer for hyphenation
    // Consume input string length
    size_t input_len = 0;
    if (fdp.remaining_bytes() > 10) {
        input_len = fdp.ConsumeIntegralInRange<size_t>(1, 200);
    }
    
    if (input_len > 0 && fdp.remaining_bytes() >= input_len) {
        // Consume input string
        std::string input_str = fdp.ConsumeBytesAsString(input_len);
        
        // Convert to widechar format expected by lou_hyphenate
        std::vector<widechar> inbuf(input_str.size());
        for (size_t i = 0; i < input_str.size(); i++) {
            inbuf[i] = (widechar)input_str[i];
        }
        
        // Prepare hyphens output buffer (one char per input position)
        std::vector<char> hyphens(input_str.size());
        
        if (!inbuf.empty() && !hyphens.empty()) {
            // Call lou_hyphenate with the compiled table
            int hyphen_result = lou_hyphenate(
                table_list, 
                inbuf.data(), 
                (int)inbuf.size(), 
                hyphens.data(), 
                hyphen_mode
            );
            
            // Result can be 0 (failure) or 1 (success) - both valid
            (void)hyphen_result;
        }
    }
    
    // PHASE 4: ADDITIONAL HYPHENATION TEST SCENARIOS
    
    // Test with empty string (edge case)
    if (fdp.ConsumeBool() && fdp.remaining_bytes() > 0) {
        widechar empty_buf[1] = {0};
        char empty_hyphens[1] = {0};
        int empty_result = lou_hyphenate(table_list, empty_buf, 0, empty_hyphens, hyphen_mode);
        (void)empty_result;
    }
    
    // Test with special characters if we have remaining input
    if (fdp.remaining_bytes() > 20) {
        size_t special_len = fdp.ConsumeIntegralInRange<size_t>(1, 50);
        std::vector<widechar> special_buf(special_len);
        std::vector<char> special_hyphens(special_len);
        
        // Fill with various character types
        for (size_t i = 0; i < special_len; i++) {
            uint8_t char_type = fdp.ConsumeIntegral<uint8_t>() % 4;
            switch (char_type) {
                case 0: special_buf[i] = 'a' + (fdp.ConsumeIntegral<uint8_t>() % 26); break;
                case 1: special_buf[i] = 'A' + (fdp.ConsumeIntegral<uint8_t>() % 26); break;
                case 2: special_buf[i] = '0' + (fdp.ConsumeIntegral<uint8_t>() % 10); break;
                case 3: special_buf[i] = 32 + (fdp.ConsumeIntegral<uint8_t>() % 95); break; // printable ASCII
            }
        }
        
        if (!special_buf.empty()) {
            int special_result = lou_hyphenate(
                table_list,
                special_buf.data(),
                (int)special_buf.size(),
                special_hyphens.data(),
                hyphen_mode
            );
            (void)special_result;
        }
    }
    
    // PHASE 5: ERROR CONDITION TESTING
    
    // Test with invalid table names (exercises error paths)
    if (fdp.remaining_bytes() > 10 && fdp.ConsumeBool()) {
        size_t invalid_table_len = fdp.ConsumeIntegralInRange<size_t>(1, 50);
        std::string invalid_table = fdp.ConsumeBytesAsString(invalid_table_len);
        
        if (!invalid_table.empty()) {
            // Try compiling with invalid table name
            int invalid_compile = lou_compileString(invalid_table.c_str(), table_string.c_str());
            (void)invalid_compile;
            
            // Try hyphenation with invalid table name
            if (fdp.remaining_bytes() > 5) {
                size_t test_input_len = fdp.ConsumeIntegralInRange<size_t>(1, 20);
                std::string test_input = fdp.ConsumeBytesAsString(test_input_len);
                
                if (!test_input.empty()) {
                    std::vector<widechar> test_buf(test_input.size());
                    for (size_t i = 0; i < test_input.size(); i++) {
                        test_buf[i] = (widechar)test_input[i];
                    }
                    std::vector<char> test_hyphens(test_input.size());
                    
                    int invalid_hyphen = lou_hyphenate(
                        invalid_table.c_str(),
                        test_buf.data(),
                        (int)test_buf.size(),
                        test_hyphens.data(),
                        hyphen_mode
                    );
                    (void)invalid_hyphen;
                }
            }
        }
    }
    
    // Note: lou_free is called automatically via destructor
    return 0;
}
