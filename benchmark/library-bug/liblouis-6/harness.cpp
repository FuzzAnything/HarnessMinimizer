/*
 * Fuzzing harness for liblouis braille translation library - Internal Functions & Pattern Matching
 * Targets internal API functions from internal.h, table compilation, pattern matching,
 * error handling paths, and utility functions
 * Focus on semantic diversity from harness_000 (core translation) and harness_001 (table management)
 */

#include <fuzzer/FuzzedDataProvider.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <vector>
#include <string>

// Include liblouis headers - we need both public and internal headers
extern "C" {
#include "liblouis.h"
#include "internal.h"
}

// Note: internal.h declares all the _lou_* functions we need
// No need for forward declarations since we're including internal.h

// Common braille tables for testing - using same tables as previous harnesses for consistency
static const char* test_tables[] = {
    "en-us-g2.ctb",
    "en-gb-g2.ctb", 
    "fr-bfu-g2.ctb",
    "de-de-g2.ctb",
    "en-us-comp8.ctb",
    NULL  // NULL terminator
};
static const size_t num_tables = sizeof(test_tables) / sizeof(test_tables[0]) - 1;

// Opcode names for testing (from internal.h/compileTranslationTable.c)
static const char* test_opcode_names[] = {
    "include",
    "locale", 
    "undefined",
    "capsletter",
    "begcapsword",
    "endcapsword",
    "letter",
    "digit",
    "space",
    "punctuation"
};
static const size_t num_opcode_names = sizeof(test_opcode_names) / sizeof(test_opcode_names[0]);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size for meaningful fuzzing of internal functions
    // Fixed data: operation(1) + table_idx(size_t) + opcode_idx(size_t) + max_str_len(size_t) = ~25 bytes
    // Plus at least 1 byte for string data
    const size_t MIN_REQUIRED_SIZE = sizeof(uint8_t) + sizeof(size_t) + sizeof(size_t) + sizeof(size_t) + 1;
    if (size < MIN_REQUIRED_SIZE) return 0;
    
    FuzzedDataProvider fdp(data, size);
    
    // Check if we have enough data for fixed consumption
    if (fdp.remaining_bytes() < sizeof(uint8_t) + sizeof(size_t) + sizeof(size_t) + sizeof(size_t)) {
        return 0;
    }
    
    // Initialize logging to avoid output during fuzzing
    static bool initialized = false;
    if (!initialized) {
        lou_registerLogCallback(NULL);
        initialized = true;
    }
    
    // Consume operation type to decide which internal API to test
    // Targeting 12 different internal function groups
    uint8_t operation = fdp.ConsumeIntegral<uint8_t>() % 12;
    
    // Consume indices for tables and opcodes
    size_t table_idx = fdp.ConsumeIntegralInRange<size_t>(0, num_tables - 1);
    size_t opcode_idx = fdp.ConsumeIntegralInRange<size_t>(0, num_opcode_names - 1);
    
    const char* table = test_tables[table_idx];
    const char* opcode_name = test_opcode_names[opcode_idx];
    
    // Consume various string data for testing
    size_t max_str_len = fdp.ConsumeIntegralInRange<size_t>(1, 512);
    std::string input_str = fdp.ConsumeRandomLengthString(max_str_len);
    std::string rule_str = fdp.ConsumeRandomLengthString(256);
    std::string dots_str = fdp.ConsumeRandomLengthString(128);
    
    // Convert strings to widechar format where needed
    size_t wide_len = input_str.length();
    if (wide_len == 0) {
        return 0;  // Need at least some content
    }
    
    widechar* wide_input = (widechar*)malloc((wide_len + 1) * sizeof(widechar));
    if (!wide_input) return 0;
    
    // Simple ASCII to widechar conversion
    for (size_t i = 0; i < wide_len; i++) {
        wide_input[i] = (widechar)input_str[i];
    }
    wide_input[wide_len] = 0;
    
    // Test different internal API functions based on operation
    int result = 0;
    
    switch (operation) {
        case 0: {
            // Test _lou_extParseChars - string to widechar conversion
            widechar* parsed_chars = (widechar*)malloc((wide_len * 2 + 1) * sizeof(widechar));
            if (!parsed_chars) {
                free(wide_input);
                return 0;
            }
            result = _lou_extParseChars(input_str.c_str(), parsed_chars);
            free(parsed_chars);
            break;
        }
            
        case 1: {
            // Test _lou_extParseDots - dot pattern string to widechar conversion
            widechar* parsed_dots = (widechar*)malloc((dots_str.length() * 2 + 1) * sizeof(widechar));
            if (!parsed_dots) {
                free(wide_input);
                return 0;
            }
            result = _lou_extParseDots(dots_str.c_str(), parsed_dots);
            free(parsed_dots);
            break;
        }
            
        case 2: {
            // Test _lou_compileTranslationRule
            // Note: This may fail for invalid rules, which is OK for fuzzing
            result = _lou_compileTranslationRule(table, rule_str.c_str());
            break;
        }
            
        case 3: {
            // Test _lou_compileDisplayRule
            result = _lou_compileDisplayRule(table, rule_str.c_str());
            break;
        }
            
        case 4: {
            // Test _lou_findOpcodeNumber and _lou_findOpcodeName
            TranslationTableOpcode opcode = _lou_findOpcodeNumber(opcode_name);
            const char* found_name = _lou_findOpcodeName(opcode);
            // Just exercise the functions, don't check results
            (void)found_name;
            break;
        }
            
        case 5: {
            // Test _lou_charHash and _lou_stringHash
            if (wide_len > 0) {
                unsigned long int char_hash = _lou_charHash(wide_input[0]);
                unsigned long int str_hash = _lou_stringHash(wide_input, 0, NULL);
                (void)char_hash;
                (void)str_hash;
            }
            break;
        }
            
        case 6: {
            // Test pattern compilation with a small expression
            // Allocate buffers for pattern compilation
            const int expr_max = 256;
            widechar* expr_data = (widechar*)malloc(expr_max * sizeof(widechar));
            if (!expr_data) {
                free(wide_input);
                return 0;
            }
            
            // Try to compile a simple pattern
            // Note: table parameter can be NULL for some pattern functions
            int input_max = (int)(wide_len < 100 ? wide_len : 100);
            result = _lou_pattern_compile(wide_input, input_max, expr_data, expr_max, NULL, NULL);
            
            if (result > 0) {
                // If compilation succeeded, test pattern reversal
                _lou_pattern_reverse(expr_data);
                
                // Test pattern checking with the compiled expression
                int check_result = _lou_pattern_check(wide_input, 0, input_max, 1, expr_data, NULL);
                (void)check_result;
            }
            
            free(expr_data);
            break;
        }
            
        case 7: {
            // Test _lou_showString and _lou_showDots (output functions)
            // These functions produce output, but we've disabled logging
            if (wide_len > 0) {
                _lou_showString(wide_input, (int)(wide_len < 50 ? wide_len : 50), 0);
                
                // Create some dot patterns for testing
                widechar* dots = (widechar*)malloc(50 * sizeof(widechar));
                if (dots) {
                    for (int i = 0; i < 50 && i < (int)wide_len; i++) {
                        dots[i] = (widechar)(wide_input[i] % 256);
                    }
                    _lou_showDots(dots, (int)(wide_len < 50 ? wide_len : 50));
                    free(dots);
                }
            }
            break;
        }
            
        case 8: {
            // Test pass variable handling functions
            if (wide_len > 10) {
                int IC = 0;
                int itsTrue = 0;
                
                // Test pass variable test handling
                result = _lou_handlePassVariableTest(wide_input, &IC, &itsTrue);
                
                // Reset and test action handling
                IC = 0;
                result = _lou_handlePassVariableAction(wide_input, &IC);
                
                // Reset pass variables
                _lou_resetPassVariables();
            }
            break;
        }
            
        case 9: {
            // Test table loading functions (internal versions)
            // Note: These may cache tables, so we need to handle that
            const TranslationTableHeader* trans_table = _lou_getTranslationTable(table);
            const DisplayTableHeader* display_table = _lou_getDisplayTable(table);
            
            // Just exercise the functions - tables may be NULL if loading fails
            (void)trans_table;
            (void)display_table;
            break;
        }
            
        case 10: {
            // Test utility functions with edge cases
            
            // Test with empty string
            if (input_str.length() > 0) {
                widechar single_char[2] = {wide_input[0], 0};
                _lou_showString(single_char, 1, 1);  // Force hex output
            }
            
            // Test opcode lookup with random strings
            std::string random_opcode = fdp.ConsumeRandomLengthString(20);
            TranslationTableOpcode random_op = _lou_findOpcodeNumber(random_opcode.c_str());
            (void)random_op;
            
            break;
        }
            
        case 11: {
            // Test memory and error handling paths
            
            // Note: _lou_debugHook() is only available in DEBUG builds
            // So we skip it here to avoid compilation errors
            
            // Test with various string lengths for pattern compilation
            if (wide_len > 5) {
                const int small_expr_max = 32;
                widechar* small_expr = (widechar*)malloc(small_expr_max * sizeof(widechar));
                if (small_expr) {
                    // Try with very small buffer to test boundary conditions
                    int small_result = _lou_pattern_compile(wide_input, 5, small_expr, small_expr_max, NULL, NULL);
                    (void)small_result;
                    free(small_expr);
                }
            }
            
            // Test with invalid table names
            std::string invalid_table = fdp.ConsumeRandomLengthString(50);
            const TranslationTableHeader* invalid_trans = _lou_getTranslationTable(invalid_table.c_str());
            (void)invalid_trans;
            
            break;
        }
            
        default:
            // Should not reach here due to modulo operation
            break;
    }
    
    // Clean up
    free(wide_input);
    
    // Free any cached tables if needed (lou_free handles this)
    // Note: We don't call lou_free() here to avoid clearing caches between operations
    
    return 0;
}
