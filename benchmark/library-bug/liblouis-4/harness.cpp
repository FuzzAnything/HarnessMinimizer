/*
 * liblouis Final Catch-All Comprehensive Fuzzing Harness (harness_014.cpp)
 * 
 * This harness serves as the final comprehensive catch-all test for liblouis,
 * focusing on edge cases and scenarios not extensively covered in previous harnesses.
 * 
 * Seven targeted testing areas (as specified by Manager):
 * 1) Advanced table resolver scenarios with actual file resolution logic
 * 2) Testing with international tables and non-Latin scripts
 * 3) Complex Unicode normalization and encoding scenarios
 * 4) Testing library re-initialization and state persistence
 * 5) Testing with very specific braille table features (contractions, ligatures, etc.)
 * 6) Testing API parameter combinations that might have edge cases
 * 7) Simulating real-world application usage patterns with multiple translation sessions
 * 
 * APIs specifically targeted in this harness:
 * - Advanced table resolution with file system interaction
 * - International script handling (Arabic, Hebrew, Japanese, Korean, etc.)
 * - Complex Unicode sequences including normalization forms
 * - State persistence across lou_free() and reinitialization
 * - Braille-specific features like contractions, ligatures, and emphasis
 * - Edge-case parameter combinations for all main translation APIs
 * - Real-world application simulation with session management
 * 
 * Semantic differentiation from previous harnesses:
 * - harness_000-012: Functional testing, specific API groups, boundary conditions
 * - harness_013: Integration, real-world usage, complex scenarios, uncovered APIs
 * - This harness (014): FINAL CATCH-ALL focusing on edge cases, international scripts,
 *                      complex Unicode, and real-world persistence patterns
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>
#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <climits>
#include <codecvt>
#include <locale>

#include <fuzzer/FuzzedDataProvider.h>
extern "C" {
#include "liblouis/liblouis.h"
}

// ==================== ADVANCED TABLE RESOLVER WITH FILE SYSTEM LOGIC ====================

// Resolver that actually interacts with file system to find tables
static char** file_system_resolver(const char* table, const char* base) {
    // Base directory for tables
    const char* base_dir = base ? base : "/root/src/liblouis/tables/";
    std::vector<std::string> found_tables;
    
    // Try to find tables based on pattern matching
    if (table && table[0]) {
        std::string table_pattern = table;
        
        // Check for common table file extensions
        const char* extensions[] = {".ctb", ".utb", ".uti", ".tbl", NULL};
        
        for (int i = 0; extensions[i] != NULL; i++) {
            std::string full_pattern = std::string(base_dir) + "*" + table_pattern + "*" + extensions[i];
            
            // Simple glob-like matching (simplified for fuzzing)
            // In real implementation, would use opendir/readdir
            std::string potential_table = std::string(base_dir) + table_pattern + extensions[i];
            
            // Check if file exists (simplified)
            struct stat st;
            if (stat(potential_table.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
                found_tables.push_back(potential_table);
            }
        }
        
        // Also check without extension
        std::string no_ext_table = std::string(base_dir) + table_pattern;
        struct stat st;
        if (stat(no_ext_table.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
            found_tables.push_back(no_ext_table);
        }
    }
    
    // Fallback: return some known international tables
    if (found_tables.empty()) {
        const char* international_tables[] = {
            "/root/src/liblouis/tables/ar-ar-g2.ctb",      // Arabic Grade 2
            "/root/src/liblouis/tables/ar-ar-comp8.utb",   // Arabic computer braille
            "/root/src/liblouis/tables/he-IL.utb",         // Hebrew
            "/root/src/liblouis/tables/fa-ir-g1.utb",      // Persian/Farsi
            "/root/src/liblouis/tables/ja-kantenji.utb",   // Japanese
            "/root/src/liblouis/tables/ko-g2.ctb",         // Korean Grade 2
            "/root/src/liblouis/tables/hi-in-g1.utb",      // Hindi
            "/root/src/liblouis/tables/bn.ctb",           // Bengali
            "/root/src/liblouis/tables/ru-ru-g1.utb",      // Russian
            "/root/src/liblouis/tables/el.ctb",           // Greek
            NULL
        };
        
        for (int i = 0; international_tables[i] != NULL; i++) {
            struct stat st;
            if (stat(international_tables[i], &st) == 0 && S_ISREG(st.st_mode)) {
                found_tables.push_back(international_tables[i]);
            }
        }
    }
    
    // Allocate result array
    char** result = (char**)malloc((found_tables.size() + 1) * sizeof(char*));
    if (!result) return NULL;
    
    for (size_t i = 0; i < found_tables.size(); i++) {
        result[i] = strdup(found_tables[i].c_str());
        if (!result[i]) {
            for (size_t j = 0; j < i; j++) free(result[j]);
            free(result);
            return NULL;
        }
    }
    result[found_tables.size()] = NULL;
    
    return result;
}

// ==================== INTERNATIONAL/NON-LATIN SCRIPT TESTING ====================

// Generate text in various international scripts
static std::vector<uint8_t> generate_international_text(FuzzedDataProvider& fdp, size_t max_len) {
    std::vector<uint8_t> result;
    size_t target_len = fdp.ConsumeIntegralInRange<size_t>(1, max_len);
    
    uint8_t script_type = fdp.ConsumeIntegral<uint8_t>() % 10;
    
    for (size_t i = 0; i < target_len && fdp.remaining_bytes() > 0;) {
        switch (script_type) {
            case 0: // Arabic (UTF-8: U+0600-U+06FF)
                if (fdp.remaining_bytes() >= 2) {
                    result.push_back(0xD9);
                    result.push_back(fdp.ConsumeIntegralInRange<uint8_t>(0x80, 0xBF));
                    i += 2;
                }
                break;
                
            case 1: // Hebrew (UTF-8: U+0590-U+05FF)
                if (fdp.remaining_bytes() >= 2) {
                    result.push_back(0xD7);
                    result.push_back(fdp.ConsumeIntegralInRange<uint8_t>(0x90, 0xBF));
                    i += 2;
                }
                break;
                
            case 2: // Japanese Hiragana (UTF-8: U+3040-U+309F)
                if (fdp.remaining_bytes() >= 3) {
                    result.push_back(0xE3);
                    result.push_back(0x81);
                    result.push_back(fdp.ConsumeIntegralInRange<uint8_t>(0x80, 0xBF));
                    i += 3;
                }
                break;
                
            case 3: // Japanese Katakana (UTF-8: U+30A0-U+30FF)
                if (fdp.remaining_bytes() >= 3) {
                    result.push_back(0xE3);
                    result.push_back(0x82);
                    result.push_back(fdp.ConsumeIntegralInRange<uint8_t>(0x80, 0xBF));
                    i += 3;
                }
                break;
                
            case 4: // Korean Hangul (UTF-8: U+AC00-U+D7AF)
                if (fdp.remaining_bytes() >= 3) {
                    result.push_back(0xEA);
                    result.push_back(fdp.ConsumeIntegralInRange<uint8_t>(0xB0, 0xBF));
                    result.push_back(fdp.ConsumeIntegralInRange<uint8_t>(0x80, 0xBF));
                    i += 3;
                }
                break;
                
            case 5: // Devanagari (Hindi, Sanskrit - UTF-8: U+0900-U+097F)
                if (fdp.remaining_bytes() >= 3) {
                    result.push_back(0xE0);
                    result.push_back(0xA4);
                    result.push_back(fdp.ConsumeIntegralInRange<uint8_t>(0x80, 0xBF));
                    i += 3;
                }
                break;
                
            case 6: // Bengali (UTF-8: U+0980-U+09FF)
                if (fdp.remaining_bytes() >= 3) {
                    result.push_back(0xE0);
                    result.push_back(0xA6);
                    result.push_back(fdp.ConsumeIntegralInRange<uint8_t>(0x80, 0xBF));
                    i += 3;
                }
                break;
                
            case 7: // Cyrillic (Russian - UTF-8: U+0400-U+04FF)
                if (fdp.remaining_bytes() >= 2) {
                    result.push_back(0xD0);
                    result.push_back(fdp.ConsumeIntegralInRange<uint8_t>(0x80, 0xBF));
                    i += 2;
                }
                break;
                
            case 8: // Greek (UTF-8: U+0370-U+03FF)
                if (fdp.remaining_bytes() >= 2) {
                    result.push_back(0xCD);
                    result.push_back(fdp.ConsumeIntegralInRange<uint8_t>(0xB0, 0xBF));
                    i += 2;
                }
                break;
                
            case 9: // Mixed script text (combines different scripts)
                if (fdp.remaining_bytes() >= 1) {
                    uint8_t mixed_choice = fdp.ConsumeIntegral<uint8_t>() % 4;
                    if (mixed_choice == 0 && fdp.remaining_bytes() >= 2) {
                        // Latin-1 supplement
                        result.push_back(0xC3);
                        result.push_back(fdp.ConsumeIntegralInRange<uint8_t>(0x80, 0xBF));
                        i += 2;
                    } else {
                        // ASCII fallback
                        result.push_back(fdp.ConsumeIntegralInRange<uint8_t>(32, 126));
                        i += 1;
                    }
                }
                break;
        }
    }
    
    return result;
}

// ==================== COMPLEX UNICODE NORMALIZATION SCENARIOS ====================

// Generate text with Unicode combining characters (normalization forms)
static std::vector<uint8_t> generate_unicode_with_combining(FuzzedDataProvider& fdp, size_t max_len) {
    std::vector<uint8_t> result;
    size_t target_len = fdp.ConsumeIntegralInRange<size_t>(10, max_len);
    
    // Choose normalization complexity
    uint8_t norm_type = fdp.ConsumeIntegral<uint8_t>() % 4;
    
    for (size_t i = 0; i < target_len && fdp.remaining_bytes() > 0;) {
        switch (norm_type) {
            case 0: // Base character + combining mark
                if (fdp.remaining_bytes() >= 3) {
                    // Base character (ASCII)
                    result.push_back(fdp.ConsumeIntegralInRange<uint8_t>('a', 'z'));
                    i += 1;
                    
                    // Combining acute accent (U+0301)
                    result.push_back(0xCC);
                    result.push_back(0x81);
                    i += 2;
                }
                break;
                
            case 1: // Multiple combining marks on one base
                if (fdp.remaining_bytes() >= 5) {
                    // Base character
                    result.push_back(fdp.ConsumeIntegralInRange<uint8_t>('A', 'Z'));
                    i += 1;
                    
                    // Combining tilde (U+0303)
                    result.push_back(0xCC);
                    result.push_back(0x83);
                    i += 2;
                    
                    // Combining dot below (U+0323)
                    result.push_back(0xCC);
                    result.push_back(0xA3);
                    i += 2;
                }
                break;
                
            case 2: // Precomposed character (NFC form)
                if (fdp.remaining_bytes() >= 2) {
                    // Latin small letter a with acute (U+00E1)
                    result.push_back(0xC3);
                    result.push_back(0xA1);
                    i += 2;
                }
                break;
                
            case 3: // Surrogate pairs (outside BMP)
                if (fdp.remaining_bytes() >= 4) {
                    // Emoji: smiling face (U+1F600)
                    result.push_back(0xF0);
                    result.push_back(0x9F);
                    result.push_back(0x98);
                    result.push_back(0x80);
                    i += 4;
                }
                break;
        }
    }
    
    return result;
}

// ==================== SPECIFIC BRAILLE TABLE FEATURES TESTING ====================

// Test contractions and ligatures
static void test_contractions_and_ligatures(const char* table, const widechar* input, int input_len, 
                                           FuzzedDataProvider& fdp) {
    // Different tables have different contraction systems
    std::string table_str = table ? table : "";
    
    // Test various translation modes that affect contractions
    int mode = 0;
    if (fdp.ConsumeBool()) {
        mode |= no_contract;  // Test without contractions
    }
    
    if (fdp.ConsumeBool()) {
        mode |= computer_braille;  // Test computer braille mode
    }
    
    widechar output[1024];
    int out_len = sizeof(output) / sizeof(output[0]);
    
    // Forward translation with mode
    int result = lou_translateString(table, input, &input_len, output, &out_len, NULL, NULL, mode);
    
    if (result && out_len > 0) {
        // Back translation to see if contractions round-trip
        widechar back_output[1024];
        int back_out_len = sizeof(back_output) / sizeof(back_output[0]);
        int back_in_len = out_len;
        
        lou_backTranslateString(table, output, &back_in_len, back_output, &back_out_len, 
                               NULL, NULL, mode);
    }
}

// Test emphasis and typeforms
static void test_emphasis_features(const char* table, FuzzedDataProvider& fdp) {
    // Get emphasis classes for this table
    char const** emph_classes = lou_getEmphClasses(table);
    if (emph_classes) {
        // Test each emphasis class
        for (int i = 0; emph_classes[i] != NULL && fdp.remaining_bytes() > 5; i++) {
            // Get typeform for this emphasis class
            formtype tf = lou_getTypeformForEmphClass(table, emph_classes[i]);
            
            // Test with actual text using this typeform
            if (fdp.remaining_bytes() > 20) {
                std::string test_text = fdp.ConsumeRandomLengthString(50);
                widechar wide_input[128];
                int wide_len = test_text.size();
                
                // Simple conversion for fuzzing
                for (int j = 0; j < wide_len && j < 128; j++) {
                    wide_input[j] = (widechar)(unsigned char)test_text[j];
                }
                
                widechar output[256];
                int out_len = sizeof(output) / sizeof(output[0]);
                formtype typeforms[256];
                
                // Fill typeforms array with the emphasis
                for (int j = 0; j < wide_len && j < 256; j++) {
                    typeforms[j] = tf;
                }
                
                lou_translateString(table, wide_input, &wide_len, output, &out_len, 
                                   typeforms, NULL, 0);
            }
        }
        lou_freeEmphClasses(emph_classes);
    }
}

// ==================== REAL-WORLD APPLICATION SIMULATION ====================

// Simulate a real application session
static void simulate_application_session(FuzzedDataProvider& fdp) {
    // Initialize library with custom settings
    lou_setLogLevel(LOU_LOG_WARN);
    
    // Register advanced table resolver
    lou_registerTableResolver(file_system_resolver);
    
    // Choose tables for this session
    const char* session_tables[] = {
        "en-us-g2",    // English Grade 2 (common)
        "ar-ar-g2",    // Arabic Grade 2
        "ja-kantenji", // Japanese
        "ko-g2",       // Korean Grade 2
        "he-IL",       // Hebrew
        NULL
    };
    
    // Simulate multiple translation sessions
    int num_sessions = fdp.ConsumeIntegralInRange<int>(1, 5);
    
    for (int session = 0; session < num_sessions && fdp.remaining_bytes() > 50; session++) {
        // Choose table for this session
        int table_idx = fdp.ConsumeIntegralInRange<int>(0, 4);
        const char* table = session_tables[table_idx];
        
        // Generate text for this session
        size_t text_len = fdp.ConsumeIntegralInRange<size_t>(10, 200);
        std::vector<uint8_t> text_data = generate_international_text(fdp, text_len);
        
        if (text_data.empty()) continue;
        
        // Convert to widechar
        widechar wide_input[256];
        int wide_len = std::min(text_data.size(), (size_t)256);
        for (int i = 0; i < wide_len; i++) {
            wide_input[i] = (widechar)text_data[i];
        }
        
        // Perform translation with various parameters
        widechar output[512];
        int out_len = sizeof(output) / sizeof(output[0]);
        
        // Test different translation modes
        int mode = 0;
        if (fdp.ConsumeBool()) mode |= no_contract;
        if (fdp.ConsumeBool()) mode |= computer_braille;
        
        lou_translateString(table, wide_input, &wide_len, output, &out_len, NULL, NULL, mode);
        
        // If successful, try back translation
        if (out_len > 0 && fdp.remaining_bytes() > 20) {
            widechar back_output[256];
            int back_out_len = sizeof(back_output) / sizeof(back_output[0]);
            int back_in_len = out_len;
            
            lou_backTranslateString(table, output, &back_in_len, back_output, &back_out_len,
                                   NULL, NULL, mode);
        }
        
        // Test table metadata between sessions
        if (fdp.ConsumeBool() && fdp.remaining_bytes() > 10) {
            char* info = lou_getTableInfo(table, "language");
            if (info) {
                lou_freeTableInfo(info);
            }
        }
    }
    
    // Cleanup
    lou_registerTableResolver(NULL);
}

// ==================== EDGE CASE API PARAMETER COMBINATIONS ====================

// Test edge case parameter combinations
static void test_edge_case_parameters(FuzzedDataProvider& fdp, const char* table) {
    if (!table || fdp.remaining_bytes() < 20) return;
    
    // Generate test input
    std::string test_input = fdp.ConsumeRandomLengthString(100);
    widechar wide_input[128];
    int in_len = std::min((int)test_input.size(), 128);
    
    for (int i = 0; i < in_len; i++) {
        wide_input[i] = (widechar)(unsigned char)test_input[i];
    }
    
    // Test various edge cases
    
    // Case 1: Zero length input
    if (fdp.ConsumeBool()) {
        int zero_len = 0;
        widechar zero_output[10];
        int zero_out_len = 10;
        lou_translateString(table, wide_input, &zero_len, zero_output, &zero_out_len, 
                           NULL, NULL, 0);
    }
    
    // Case 2: Negative length (should be handled)
    if (fdp.ConsumeBool()) {
        int neg_len = -1;
        widechar neg_output[10];
        int neg_out_len = 10;
        lou_translateString(table, wide_input, &neg_len, neg_output, &neg_out_len, 
                           NULL, NULL, 0);
    }
    
    // Case 3: Output buffer too small
    if (fdp.ConsumeBool() && in_len > 5) {
        int small_out_len = 1;
        widechar small_output[1];
        lou_translateString(table, wide_input, &in_len, small_output, &small_out_len, 
                           NULL, NULL, 0);
    }
    
    // Case 4: NULL pointers for optional parameters
    if (fdp.ConsumeBool()) {
        int test_len = std::min(in_len, 10);
        widechar test_output[128];
        int test_out_len = 128;
        
        // Test with NULL for typeforms, spacing
        lou_translateString(table, wide_input, &test_len, test_output, &test_out_len, 
                           NULL, NULL, 0);
        
        // Test back translation with NULLs
        lou_backTranslateString(table, test_output, &test_out_len, wide_input, &test_len,
                               NULL, NULL, 0);
    }
    
    // Case 5: Extreme mode values
    if (fdp.ConsumeBool()) {
        int extreme_mode = fdp.ConsumeIntegral<int>();
        widechar extreme_output[128];
        int extreme_out_len = 128;
        int extreme_in_len = std::min(in_len, 20);
        
        lou_translateString(table, wide_input, &extreme_in_len, extreme_output, &extreme_out_len,
                           NULL, NULL, extreme_mode);
    }
}

// ==================== MAIN FUZZER ENTRY POINT ====================

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 16) return 0;  // Need minimum input
    
    FuzzedDataProvider fdp(data, size);
    
    // ========== TEST 1: ADVANCED TABLE RESOLVER SCENARIOS ==========
    
    // Register our file-system-aware resolver
    lou_registerTableResolver(file_system_resolver);
    
    // Test resolver with various queries
    if (fdp.remaining_bytes() > 10) {
        std::string table_query = fdp.ConsumeRandomLengthString(50);
        char** resolved_tables = file_system_resolver(table_query.c_str(), "/root/src/liblouis/tables/");
        
        if (resolved_tables) {
            // Try to use resolved tables
            for (int i = 0; resolved_tables[i] != NULL && fdp.remaining_bytes() > 20; i++) {
                // Quick table check
                lou_checkTable(resolved_tables[i]);
                
                // Free the string
                free(resolved_tables[i]);
            }
            free(resolved_tables);
        }
    }
    
    // ========== TEST 2: INTERNATIONAL TABLES AND NON-LATIN SCRIPTS ==========
    
    // List of international tables to test
    const char* international_tables[] = {
        "/root/src/liblouis/tables/ar-ar-g2.ctb",
        "/root/src/liblouis/tables/he-IL.utb",
        "/root/src/liblouis/tables/ja-kantenji.utb",
        "/root/src/liblouis/tables/ko-g2.ctb",
        "/root/src/liblouis/tables/hi-in-g1.utb",
        "/root/src/liblouis/tables/fa-ir-g1.utb",
        "/root/src/liblouis/tables/ru-ru-g1.utb",
        "/root/src/liblouis/tables/el.ctb",
        NULL
    };
    
    // Choose an international table
    int table_idx = fdp.ConsumeIntegralInRange<int>(0, 7);
    const char* international_table = international_tables[table_idx];
    
    // Generate international script text
    std::vector<uint8_t> intl_text = generate_international_text(fdp, 200);
    
    if (!intl_text.empty()) {
        // Convert to widechar
        widechar wide_intl[256];
        int wide_intl_len = std::min(intl_text.size(), (size_t)256);
        for (int i = 0; i < wide_intl_len; i++) {
            wide_intl[i] = (widechar)intl_text[i];
        }
        
        // Test translation with international text
        widechar intl_output[512];
        int intl_out_len = sizeof(intl_output) / sizeof(intl_output[0]);
        
        lou_translateString(international_table, wide_intl, &wide_intl_len, 
                           intl_output, &intl_out_len, NULL, NULL, 0);
    }
    
    // ========== TEST 3: COMPLEX UNICODE NORMALIZATION ==========
    
    std::vector<uint8_t> unicode_text = generate_unicode_with_combining(fdp, 200);
    
    if (!unicode_text.empty() && fdp.remaining_bytes() > 20) {
        // Choose a table that supports Unicode well
        const char* unicode_tables[] = {
            "/root/src/liblouis/tables/en-ueb-g2.ctb",  // Unicode-friendly
            "/root/src/liblouis/tables/boxes.ctb",      // Box drawing chars
            "/root/src/liblouis/tables/IPA.utb",        // IPA symbols
            NULL
        };
        
        int uni_table_idx = fdp.ConsumeIntegralInRange<int>(0, 2);
        const char* unicode_table = unicode_tables[uni_table_idx];
        
        widechar wide_unicode[256];
        int wide_unicode_len = std::min(unicode_text.size(), (size_t)256);
        for (int i = 0; i < wide_unicode_len; i++) {
            wide_unicode[i] = (widechar)unicode_text[i];
        }
        
        widechar unicode_output[512];
        int unicode_out_len = sizeof(unicode_output) / sizeof(unicode_output[0]);
        
        lou_translateString(unicode_table, wide_unicode, &wide_unicode_len,
                           unicode_output, &unicode_out_len, NULL, NULL, 0);
    }
    
    // ========== TEST 4: LIBRARY RE-INITIALIZATION AND STATE PERSISTENCE ==========
    
    // Test lou_free() and reinitialization multiple times
    int reinit_cycles = fdp.ConsumeIntegralInRange<int>(1, 3);
    
    for (int cycle = 0; cycle < reinit_cycles && fdp.remaining_bytes() > 30; cycle++) {
        // Free everything
        lou_free();
        
        // Reinitialize with different settings
        // Reinitialize with different settings - use valid logLevels enum values
        logLevels log_levels[] = {LOU_LOG_ALL, LOU_LOG_DEBUG, LOU_LOG_INFO, 
                                  LOU_LOG_WARN, LOU_LOG_ERROR, LOU_LOG_FATAL, LOU_LOG_OFF};
        int log_idx = fdp.ConsumeIntegralInRange<int>(0, 6);
        lou_setLogLevel(log_levels[log_idx]);
        
        // Register different resolver
        lou_registerTableResolver(file_system_resolver);
        
        // Quick test after reinitialization
        if (fdp.remaining_bytes() > 20) {
            const char* test_table = "/root/src/liblouis/tables/en-us-g2.ctb";
            std::string test_text = fdp.ConsumeRandomLengthString(50);
            widechar test_wide[128];
            int test_len = std::min((int)test_text.size(), 128);
            
            for (int i = 0; i < test_len; i++) {
                test_wide[i] = (widechar)(unsigned char)test_text[i];
            }
            
            widechar test_output[256];
            int test_out_len = sizeof(test_output) / sizeof(test_output[0]);
            
            lou_translateString(test_table, test_wide, &test_len, test_output, &test_out_len,
                               NULL, NULL, 0);
        }
    }
    
    // ========== TEST 5: SPECIFIC BRAILLE TABLE FEATURES ==========
    
    // Test with tables known to have specific features
    const char* feature_tables[] = {
        "/root/src/liblouis/tables/en-us-g2.ctb",  // Has contractions
        "/root/src/liblouis/tables/en-ueb-g2.ctb", // Unified English Braille
        "/root/src/liblouis/tables/da-dk-g26.ctb", // Danish with specific features
        "/root/src/liblouis/tables/ar-ar-g2.ctb",  // Arabic has right-to-left
        NULL
    };
    
    int feature_idx = fdp.ConsumeIntegralInRange<int>(0, 3);
    const char* feature_table = feature_tables[feature_idx];
    
    // Generate test text
    std::string feature_text = fdp.ConsumeRandomLengthString(100);
    widechar feature_wide[128];
    int feature_len = std::min((int)feature_text.size(), 128);
    
    for (int i = 0; i < feature_len; i++) {
        feature_wide[i] = (widechar)(unsigned char)feature_text[i];
    }
    
    // Test contractions and ligatures
    test_contractions_and_ligatures(feature_table, feature_wide, feature_len, fdp);
    
    // Test emphasis features if we have enough input
    if (fdp.remaining_bytes() > 30) {
        test_emphasis_features(feature_table, fdp);
    }
    
    // ========== TEST 6: EDGE CASE API PARAMETER COMBINATIONS ==========
    
    // Choose a table for edge case testing
    const char* edge_table = "/root/src/liblouis/tables/en-us-g2.ctb";
    test_edge_case_parameters(fdp, edge_table);
    
    // ========== TEST 7: REAL-WORLD APPLICATION SIMULATION ==========
    
    // Simulate a complete application session
    if (fdp.remaining_bytes() > 100) {
        simulate_application_session(fdp);
    }
    
    // Final cleanup
    lou_registerTableResolver(NULL);
    lou_setLogLevel(LOU_LOG_OFF);
    
    return 0;
}
