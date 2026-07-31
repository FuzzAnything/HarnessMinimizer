// Tenth fuzzing harness for liblouis library
// Specialized for complex table dependency resolution, cross-table translation scenarios,
// locale-specific translation modes, emphasis class handling with complex typeforms,
// and multi-pass translation operations. Targets semantic diversity to explore corner cases
// not tested by previous harnesses (000-008).

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>
#include <algorithm>
#include <memory>

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
    
    // For fuzzing, just convert bytes to widechars
    size_t chars_to_copy = size / sizeof(widechar);
    if (chars_to_copy > (size_t)max_out_len) {
        chars_to_copy = max_out_len;
    }
    
    // Copy bytes as widechars (simplified approach for fuzzing)
    for (size_t i = 0; i < chars_to_copy; i++) {
        // Simple byte to widechar conversion for fuzzing
        out[i] = (widechar)data[i * sizeof(widechar) % size];
    }
    
    return (int)chars_to_copy;
}

// Helper to create a test table file with potential dependencies
static char* create_test_table_with_deps(const std::vector<uint8_t>& table_data, int index, 
                                         bool create_dep_file) {
    char* table_file = (char*)malloc(256);
    if (!table_file) return nullptr;
    
    snprintf(table_file, 256, "/tmp/libfuzzer-harness9-%d.ctb", index);
    
    FILE *fp = fopen(table_file, "wb");
    if (fp) {
        // Write some basic table structure with potential include statements
        const char* header = "include test-dep.ctb\nlocale en-US\ndisplayname Test Table\n";
        fwrite(header, 1, strlen(header), fp);
        fwrite(table_data.data(), 1, table_data.size(), fp);
        fclose(fp);
        
        // Create dependency file if requested
        if (create_dep_file) {
            char dep_file[256];
            snprintf(dep_file, sizeof(dep_file), "/tmp/test-dep.ctb");
            FILE* dep_fp = fopen(dep_file, "wb");
            if (dep_fp) {
                const char* dep_content = "locale en-US\nemphclass italic bold underline\n";
                fwrite(dep_content, 1, strlen(dep_content), dep_fp);
                fclose(dep_fp);
            }
        }
    } else {
        free(table_file);
        return nullptr;
    }
    
    return table_file;
}

// Table resolver for testing dependency resolution
static char** test_table_resolver(const char* table, const char* base) {
    (void)base;
    
    // Simulate complex dependency resolution
    if (!table) return NULL;
    
    // Return multiple possible table paths for resolution
    char** result = (char**)malloc(4 * sizeof(char*));
    if (!result) return NULL;
    
    result[0] = (char*)malloc(strlen(table) + 1);
    if (result[0]) {
        strcpy(result[0], table);
    }
    
    // Alternative paths for the same table
    std::string alt1 = std::string("/tmp/") + table;
    result[1] = (char*)malloc(alt1.size() + 1);
    if (result[1]) {
        strcpy(result[1], alt1.c_str());
    }
    
    std::string alt2 = std::string("/usr/share/liblouis/tables/") + table;
    result[2] = (char*)malloc(alt2.size() + 1);
    if (result[2]) {
        strcpy(result[2], alt2.c_str());
    }
    
    result[3] = NULL;  // NULL termination
    
    return result;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Need enough data for complex scenarios
    if (size < 2048) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Initialize library once
    if (!initialized) {
        lou_registerLogCallback(avoid_log);
        initialized = 1;
    }
    
    // Test counter for unique file names
    static int test_counter = 0;
    int current_test = test_counter++;
    
    // ====== Test 1: Complex table dependency resolution ======
    {
        // Register custom table resolver
        lou_registerTableResolver(test_table_resolver);
        
        // Create multiple table files with dependencies
        size_t table1_size = fdp.ConsumeIntegralInRange<size_t>(100, 500);
        std::vector<uint8_t> table1_data = fdp.ConsumeBytes<uint8_t>(table1_size);
        
        char* table1_file = create_test_table_with_deps(table1_data, current_test * 2, true);
        if (table1_file) {
            // Test table loading with resolver
            const void* table1 = lou_getTable(table1_file);
            (void)table1;
            
            // Test table checking with dependencies
            int check_result = lou_checkTable(table1_file);
            (void)check_result;
            
            free(table1_file);
        }
        
        // Test with table list containing multiple tables
        if (fdp.remaining_bytes() > 100) {
            std::string table_list = fdp.ConsumeRandomLengthString(50) + "," + 
                                     fdp.ConsumeRandomLengthString(50);
            
            // Test translation with complex table list
            std::vector<widechar> test_input(10);
            std::vector<widechar> test_output(20);
            int inlen = 5;
            int outlen = 10;
            
            for (int i = 0; i < 5; i++) {
                test_input[i] = fdp.ConsumeIntegral<widechar>();
            }
            
            lou_translateString(table_list.c_str(), test_input.data(), &inlen, 
                               test_output.data(), &outlen, NULL, NULL, 0);
        }
    }
    
    // ====== Test 2: Emphasis class handling with complex typeforms ======
    {
        // Create a table file with emphasis class definitions
        size_t emph_table_size = fdp.ConsumeIntegralInRange<size_t>(200, 400);
        std::vector<uint8_t> emph_table_data = fdp.ConsumeBytes<uint8_t>(emph_table_size);
        
        char emph_filename[256];
        snprintf(emph_filename, sizeof(emph_filename), "/tmp/libfuzzer-emph-%d.ctb", current_test);
        
        FILE* emph_fp = fopen(emph_filename, "wb");
        if (emph_fp) {
            // Write table with emphasis classes
            const char* emph_header = "locale en-US\nemphclass italic bold underline custom1 custom2\n";
            fwrite(emph_header, 1, strlen(emph_header), emph_fp);
            fwrite(emph_table_data.data(), 1, emph_table_data.size(), emph_fp);
            fclose(emph_fp);
            
            // Test emphasis class APIs
            const char* emph_classes[] = {"italic", "bold", "underline", "custom1", "custom2", "nonexistent"};
            
            for (int i = 0; i < 6 && fdp.remaining_bytes() > 10; i++) {
                formtype typeform = lou_getTypeformForEmphClass(emph_filename, emph_classes[i]);
                (void)typeform;
            }
            
            // Get all emphasis classes
            char const** all_classes = lou_getEmphClasses(emph_filename);
            if (all_classes) {
                lou_freeEmphClasses(all_classes);
            }
            
            // Test translation with typeforms
            if (fdp.remaining_bytes() > 100) {
                std::vector<widechar> emph_input(20);
                std::vector<widechar> emph_output(40);
                std::vector<formtype> emph_typeforms(20);
                
                int inlen = 10;
                int outlen = 20;
                
                for (int i = 0; i < 10; i++) {
                    emph_input[i] = fdp.ConsumeIntegral<widechar>();
                    // Create complex typeform combinations
                    emph_typeforms[i] = static_cast<formtype>(
                        fdp.ConsumeIntegral<uint16_t>() & 
                        (emph_1 | emph_2 | emph_3 | emph_4 | emph_5)
                    );
                }
                
                // Test translation with typeforms
                lou_translateString(emph_filename, emph_input.data(), &inlen, 
                                   emph_output.data(), &outlen, 
                                   emph_typeforms.data(), NULL, 0);
                
                // Test back translation with typeforms
                lou_backTranslateString(emph_filename, emph_input.data(), &inlen,
                                       emph_output.data(), &outlen,
                                       emph_typeforms.data(), NULL, 0);
            }
            
            unlink(emph_filename);
        }
    }
    
    // ====== Test 3: Multi-pass translation operations ======
    {
        // Create input for multi-pass testing
        size_t text_size = fdp.ConsumeIntegralInRange<size_t>(50, 200);
        std::vector<uint8_t> text_data = fdp.ConsumeBytes<uint8_t>(text_size);
        
        if (text_data.size() > 10) {
            // Convert to widechar for translation
            std::vector<widechar> wide_text(text_data.size() / sizeof(widechar) + 1);
            for (size_t i = 0; i < wide_text.size() && i < text_data.size(); i++) {
                wide_text[i] = (widechar)text_data[i];
            }
            
            // Create a simple table for multi-pass testing
            char multi_filename[256];
            snprintf(multi_filename, sizeof(multi_filename), "/tmp/libfuzzer-multi-%d.ctb", current_test);
            
            FILE* multi_fp = fopen(multi_filename, "wb");
            if (multi_fp) {
                const char* multi_content = "locale en-US\n";
                fwrite(multi_content, 1, strlen(multi_content), multi_fp);
                fclose(multi_fp);
                
                // Perform multi-pass operations
                int pass_count = fdp.ConsumeIntegralInRange<int>(1, 5);
                
                for (int pass = 0; pass < pass_count && fdp.remaining_bytes() > 20; pass++) {
                    // Vary translation mode each pass
                    int mode = fdp.ConsumeIntegralInRange<int>(0, 3);
                    int translation_mode = 0;
                    
                    switch (mode) {
                        case 0: translation_mode = 0; break;  // Default
                        case 1: translation_mode = no_contract; break;
                        case 2: translation_mode = computer_braille; break;
                        case 3: translation_mode = no_translate; break;
                    }
                    
                    // Perform translation
                    std::vector<widechar> pass_output(wide_text.size() * 2);
                    int inlen = static_cast<int>(wide_text.size());
                    int outlen = static_cast<int>(pass_output.size());
                    
                    lou_translateString(multi_filename, wide_text.data(), &inlen,
                                       pass_output.data(), &outlen, NULL, NULL, translation_mode);
                    
                    // Use output as input for next pass (if any)
                    if (pass < pass_count - 1 && outlen > 0) {
                        wide_text.resize(outlen);
                        std::copy(pass_output.begin(), pass_output.begin() + outlen, wide_text.begin());
                    }
                }
                
                unlink(multi_filename);
            }
        }
    }
    
    // ====== Test 4: Cross-table translation scenarios ======
    {
        // Create multiple tables for cross-table testing
        char table_a[256], table_b[256];
        snprintf(table_a, sizeof(table_a), "/tmp/libfuzzer-cross-a-%d.ctb", current_test);
        snprintf(table_b, sizeof(table_b), "/tmp/libfuzzer-cross-b-%d.ctb", current_test);
        
        // Create table A
        FILE* fp_a = fopen(table_a, "wb");
        if (fp_a) {
            const char* content_a = "locale en-US\ninclude test-dep.ctb\n";
            fwrite(content_a, 1, strlen(content_a), fp_a);
            
            size_t a_data_size = fdp.ConsumeIntegralInRange<size_t>(50, 200);
            std::vector<uint8_t> a_data = fdp.ConsumeBytes<uint8_t>(a_data_size);
            fwrite(a_data.data(), 1, a_data.size(), fp_a);
            fclose(fp_a);
        }
        
        // Create table B  
        FILE* fp_b = fopen(table_b, "wb");
        if (fp_b) {
            const char* content_b = "locale fr-FR\nemphclass italic bold\n";
            fwrite(content_b, 1, strlen(content_b), fp_b);
            
            size_t b_data_size = fdp.ConsumeIntegralInRange<size_t>(50, 200);
            std::vector<uint8_t> b_data = fdp.ConsumeBytes<uint8_t>(b_data_size);
            fwrite(b_data.data(), 1, b_data.size(), fp_b);
            fclose(fp_b);
        }
        
        // Test cross-table operations
        if (fdp.remaining_bytes() > 100) {
            // Create combined table list
            std::string cross_table_list = std::string(table_a) + "," + std::string(table_b);
            
            // Test translation with cross-table list
            std::vector<widechar> cross_input(20);
            std::vector<widechar> cross_output(40);
            int inlen = 10;
            int outlen = 20;
            
            for (int i = 0; i < 10; i++) {
                cross_input[i] = fdp.ConsumeIntegral<widechar>();
            }
            
            // Test different translation modes
            int cross_mode = fdp.ConsumeIntegralInRange<int>(0, 2);
            int mode_flags = 0;
            if (cross_mode == 1) mode_flags = no_contract;
            if (cross_mode == 2) mode_flags = computer_braille;
            
            lou_translateString(cross_table_list.c_str(), cross_input.data(), &inlen,
                               cross_output.data(), &outlen, NULL, NULL, mode_flags);
            
            // Test back translation
            lou_backTranslateString(cross_table_list.c_str(), cross_input.data(), &inlen,
                                   cross_output.data(), &outlen, NULL, NULL, mode_flags);
        }
        
        // Clean up
        if (access(table_a, F_OK) == 0) unlink(table_a);
        if (access(table_b, F_OK) == 0) unlink(table_b);
    }
    
    // ====== Test 5: Locale-specific and advanced API testing ======
    {
        // Test locale-specific table finding
        if (fdp.remaining_bytes() > 50) {
            std::string locale_query = fdp.ConsumeRandomLengthString(20);
            
            // Index tables first
            const char* test_tables[] = {"en-us-g2.ctb", "fr-bfu-comp6.utb", nullptr};
            lou_indexTables(test_tables);
            
            // Try to find tables
            char* found_table = lou_findTable(locale_query.c_str());
            if (found_table) {
                lou_freeTableFile(found_table);
            }
            
            // List all tables
            char** all_tables = lou_listTables();
            if (all_tables) {
                lou_freeTableFiles(all_tables);
            }
        }
        
        // Test table compilation API
        if (fdp.remaining_bytes() > 100) {
            std::string table_to_compile = fdp.ConsumeRandomLengthString(30);
            std::string compile_string = fdp.ConsumeRandomLengthString(50);
            
            int compile_result = lou_compileString(table_to_compile.c_str(), compile_string.c_str());
            (void)compile_result;
        }
        
        // Test data path configuration (deprecated but should still work)
        if (fdp.remaining_bytes() > 50) {
            std::string test_path = fdp.ConsumeRandomLengthString(50);
            char* old_path = lou_setDataPath(test_path.c_str());
            if (old_path) {
                // Get current path
                char* current_path = lou_getDataPath();
                (void)current_path;
            }
        }
        
        // Test hyphenation with various modes
        if (fdp.remaining_bytes() > 150) {
            std::string hyphen_table = fdp.ConsumeRandomLengthString(30);
            
            std::vector<widechar> hyphen_input(20);
            std::vector<char> hyphen_output(20);
            int hyphen_len = 10;
            
            for (int i = 0; i < 10; i++) {
                hyphen_input[i] = fdp.ConsumeIntegral<widechar>();
            }
            
            lou_hyphenate(hyphen_table.c_str(), hyphen_input.data(), hyphen_len,
                         hyphen_output.data(), 0);
        }
    }
    
    // ====== Test 6: Character conversion with complex scenarios ======
    {
        if (fdp.remaining_bytes() > 200) {
            std::string conv_table = fdp.ConsumeRandomLengthString(30);
            
            // Test dots to char conversion
            std::vector<widechar> dots_input(20);
            std::vector<widechar> chars_output(20);
            
            for (size_t i = 0; i < dots_input.size(); i++) {
                dots_input[i] = fdp.ConsumeIntegral<widechar>();
            }
            
            lou_dotsToChar(conv_table.c_str(), dots_input.data(), chars_output.data(),
                          static_cast<int>(dots_input.size()), 0);
            
            // Test char to dots conversion
            lou_charToDots(conv_table.c_str(), dots_input.data(), chars_output.data(),
                          static_cast<int>(dots_input.size()), 0);
            
            // Test pre-hyphenated translation
            std::vector<widechar> prehyphen_input(20);
            std::vector<widechar> prehyphen_output(40);
            int pre_inlen = 10;
            int pre_outlen = 20;
            
            for (int i = 0; i < 10; i++) {
                prehyphen_input[i] = fdp.ConsumeIntegral<widechar>();
            }
            
            lou_translatePrehyphenated(conv_table.c_str(), prehyphen_input.data(), &pre_inlen,
                                      prehyphen_output.data(), &pre_outlen, NULL, NULL, 
                                      NULL, NULL, NULL, NULL, NULL, 0);
        }
    }
    
    // Clean up any remaining test files
    char dep_file[256];
    snprintf(dep_file, sizeof(dep_file), "/tmp/test-dep.ctb");
    if (access(dep_file, F_OK) == 0) {
        unlink(dep_file);
    }
    
    return 0;
}
