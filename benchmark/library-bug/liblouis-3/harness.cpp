// liblouis fuzzing harness - Translation table compilation focus
// Targets: lou_compileString and _lou_compileTranslationRule to exercise compileRule function
// Focus on translation table compilation with diverse, unexplored opcodes
// compileRule has 481 blocked branches (52.7% uncovered) - targeting this major coverage gap
// Uses FuzzedDataProvider for structured input processing
// Generates diverse opcode combinations for comprehensive coverage

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

// External declaration for internal function
extern "C" {
    extern int _lou_compileTranslationRule(const char *tableList, const char *inString);
}

// Opcode definitions from internal.h - focusing on diverse, unexplored opcodes
const char* opcodes[] = {
    // Character definition opcodes
    "space",
    "digit", 
    "litdigit",
    "punctuation",
    "math",
    "sign",
    "letter",
    "uppercase",
    "lowercase",
    
    // Control opcodes
    "noback",
    "nofor",
    "nocross",
    
    // Display opcodes
    "display",
    
    // Mode and emphasis opcodes
    "capsletter",
    "begcaps",
    "endcaps",
    "emphclass",
    "empletter",
    "begemph",
    "endemph",
    
    // Sign opcodes
    "lettersign",
    "number",
    "nonumber",
    
    // Sequence opcodes
    "seqdelimiter",
    "seqbefore",
    "seqafter",
    
    // Composition opcodes
    "begcomp",
    "endcomp",
    
    // Word/number position opcodes
    "begword",
    "midword",
    "endword",
    "begnum",
    "midnum",
    "endnum",
    
    // Special opcodes
    "replace",
    "correct",
    "context",
    "pass2",
    "pass3",
    "pass4",
    
    // Match opcodes
    "match",
    "backmatch",
    
    // Attribute/class opcodes
    "class",
    "attribute",
    "after",
    "before",
    
    // Base and hyphenation
    "base",
    "hyphen",
    "decpoint",
    
    // Deprecated but still valid for testing
    "uplow",
    "always",
    "large",
    "wholeword",
    "partword",
};

const size_t NUM_OPCODES = sizeof(opcodes) / sizeof(opcodes[0]);

// Helper to generate random character sequence for opcode parameters
static std::string generate_char_sequence(FuzzedDataProvider& fdp, bool for_dots = false) {
    // Generate 1-4 characters
    int length = fdp.ConsumeIntegralInRange<int>(1, 4);
    std::string result;
    
    for (int i = 0; i < length; i++) {
        if (for_dots) {
            // For braille dots (1-8, optionally with capital letters for multiple cells)
            int dot = fdp.ConsumeIntegralInRange<int>(1, 8);
            result += '0' + dot;
        } else {
            // For regular characters
            char c;
            uint8_t choice = fdp.ConsumeIntegral<uint8_t>() % 4;
            switch (choice) {
                case 0:
                    c = fdp.ConsumeIntegralInRange<char>('a', 'z');
                    break;
                case 1:
                    c = fdp.ConsumeIntegralInRange<char>('A', 'Z');
                    break;
                case 2:
                    c = fdp.ConsumeIntegralInRange<char>('0', '9');
                    break;
                case 3:
                    c = fdp.PickValueInArray({'.', ',', '!', '?', ';', ':', '-', '_', '=', '+'});
                    break;
                default:
                    c = 'x';
            }
            result += c;
        }
    }
    
    return result;
}

// Helper to generate a complete rule string with opcode and parameters
static std::string generate_rule(FuzzedDataProvider& fdp) {
    std::string rule;
    
    // Select an opcode
    size_t opcode_idx = fdp.ConsumeIntegralInRange<size_t>(0, NUM_OPCODES - 1);
    rule += opcodes[opcode_idx];
    rule += " ";
    
    const char* opcode = opcodes[opcode_idx];
    
    // Generate appropriate parameters based on opcode type
    if (strcmp(opcode, "space") == 0 || strcmp(opcode, "digit") == 0 || 
        strcmp(opcode, "litdigit") == 0 || strcmp(opcode, "punctuation") == 0 ||
        strcmp(opcode, "math") == 0 || strcmp(opcode, "sign") == 0 ||
        strcmp(opcode, "letter") == 0 || strcmp(opcode, "uppercase") == 0 ||
        strcmp(opcode, "lowercase") == 0) {
        // Character definition: char dots
        rule += generate_char_sequence(fdp, false);
        rule += " ";
        rule += generate_char_sequence(fdp, true);
    }
    else if (strcmp(opcode, "display") == 0) {
        // Display: char dots (both single)
        rule += generate_char_sequence(fdp, false);
        rule += " ";
        rule += generate_char_sequence(fdp, true);
    }
    else if (strcmp(opcode, "noback") == 0 || strcmp(opcode, "nofor") == 0 || 
             strcmp(opcode, "nocross") == 0) {
        // Control opcodes: no parameters needed
        // Just continue with character definition
        rule += "letter ";
        rule += generate_char_sequence(fdp, false);
        rule += " ";
        rule += generate_char_sequence(fdp, true);
    }
    else if (strcmp(opcode, "replace") == 0 || strcmp(opcode, "correct") == 0) {
        // Replace/correct: chars dots
        rule += generate_char_sequence(fdp, false);
        rule += " ";
        rule += generate_char_sequence(fdp, true);
    }
    else if (strcmp(opcode, "match") == 0 || strcmp(opcode, "backmatch") == 0) {
        // Match: pattern chars
        rule += generate_char_sequence(fdp, false);
        rule += " ";
        rule += generate_char_sequence(fdp, false);
    }
    else if (strcmp(opcode, "class") == 0) {
        // Class: name chars
        rule += generate_char_sequence(fdp, false);
    }
    else if (strcmp(opcode, "attribute") == 0) {
        // Attribute: name value
        rule += generate_char_sequence(fdp, false);
        rule += " ";
        rule += generate_char_sequence(fdp, false);
    }
    else if (strcmp(opcode, "after") == 0 || strcmp(opcode, "before") == 0) {
        // After/Before: class chars dots
        rule += generate_char_sequence(fdp, false);
        rule += " ";
        rule += generate_char_sequence(fdp, false);
        rule += " ";
        rule += generate_char_sequence(fdp, true);
    }
    else if (strcmp(opcode, "base") == 0) {
        // Base: char dots
        rule += generate_char_sequence(fdp, false);
        rule += " ";
        rule += generate_char_sequence(fdp, true);
    }
    else if (strcmp(opcode, "hyphen") == 0 || strcmp(opcode, "decpoint") == 0) {
        // Hyphen/decpoint: char dots
        rule += generate_char_sequence(fdp, false);
        rule += " ";
        rule += generate_char_sequence(fdp, true);
    }
    else if (strcmp(opcode, "begword") == 0 || strcmp(opcode, "midword") == 0 || 
             strcmp(opcode, "endword") == 0 || strcmp(opcode, "begnum") == 0 ||
             strcmp(opcode, "midnum") == 0 || strcmp(opcode, "endnum") == 0) {
        // Word/number position: chars dots
        rule += generate_char_sequence(fdp, false);
        rule += " ";
        rule += generate_char_sequence(fdp, true);
    }
    else {
        // Default: simple char dots for other opcodes
        rule += generate_char_sequence(fdp, false);
        rule += " ";
        rule += generate_char_sequence(fdp, true);
    }
    
    return rule;
}

// Select a test table
static std::string select_test_table(FuzzedDataProvider& fdp) {
    // Tables that should be available for compilation testing
    const char* test_tables[] = {
        "en-us-g1.ctb",  // Basic English grade 1
        "en-us-g2.ctb",  // English grade 2
        "tests/tables/empty.ctb",  // Empty table
        "tests/tables/large.ctb",  // Large table
    };
    
    size_t table_index = fdp.ConsumeIntegralInRange<size_t>(0, 
        sizeof(test_tables)/sizeof(test_tables[0]) - 1);
    return std::string(test_tables[table_index]);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Minimum size check - need enough data for rule generation
    if (size < 32) return 0;
    
    FuzzedDataProvider fdp(data, size);
    
    // Initialize liblouis once
    if (!initialized) {
        lou_registerLogCallback(avoid_log);
        initialized = 1;
        // Register cleanup
        atexit(free_resources);
    }
    
    // Consume operation type
    uint8_t operation = fdp.ConsumeIntegral<uint8_t>() % 3;
    
    // Select table for compilation
    std::string table_name = select_test_table(fdp);
    
    // Generate 1-5 rules to compile
    int num_rules = fdp.ConsumeIntegralInRange<int>(1, 5);
    std::string rule_string;
    
    for (int i = 0; i < num_rules; i++) {
        if (fdp.remaining_bytes() < 10) break;
        
        rule_string += generate_rule(fdp);
        if (i < num_rules - 1) {
            rule_string += "\n";
        }
    }
    
    if (rule_string.empty()) {
        return 0;
    }
    
    // Test different compilation functions
    int result = 0;
    
    switch (operation) {
        case 0: {
            // Test lou_compileString (public API)
            result = lou_compileString(table_name.c_str(), rule_string.c_str());
            (void)result; // Result ignored for fuzzing
            break;
        }
        
        case 1: {
            // Test _lou_compileTranslationRule (internal API)
            result = _lou_compileTranslationRule(table_name.c_str(), rule_string.c_str());
            (void)result;
            break;
        }
        
        case 2: {
            // Test multiple compilations with different opcode combinations
            // First with public API
            result = lou_compileString(table_name.c_str(), rule_string.c_str());
            (void)result;
            
            // Then with internal API if enough bytes remain
            if (fdp.remaining_bytes() > 20) {
                // Generate another rule for internal API
                std::string another_rule = generate_rule(fdp);
                result = _lou_compileTranslationRule(table_name.c_str(), another_rule.c_str());
                (void)result;
            }
            break;
        }
    }
    
    return 0;
}
