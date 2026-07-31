/*
 * Fuzzing harness for liblouis braille translation library
 * Targets: Hyphenation and table metadata functions
 * 
 * This harness exercises hyphenation, character conversion, and table metadata
 * functions that are currently uncovered. Based on CoverageAnalyzer guidance.
 * Sequence: table discovery -> table loading -> metadata examination -> 
 * hyphenation -> character conversion -> proper cleanup.
 * Ensures semantic diversity from harness_000 which focuses on translation.
 */

#include <fuzzer/FuzzedDataProvider.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <cassert>

#include "liblouis/liblouis.h"

// Avoid logging callback
static void avoid_log(logLevels level, const char *msg) {
    (void)level;
    (void)msg;
}

// Global initialization flag
static int initialized = 0;

// Destructor for cleanup
static void __attribute__((destructor)) free_resources(void) {
    lou_free();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Minimum size check: need at least some bytes for meaningful testing
    if (size < 32) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Initialize liblouis on first call
    if (!initialized) {
        lou_registerLogCallback(avoid_log);
        initialized = 1;
    }
    
    // Step 1: Table discovery - consume query strings
    // First query for lou_findTables
    size_t query1_len = fdp.ConsumeIntegralInRange<size_t>(1, 64);
    std::string query1 = fdp.ConsumeBytesAsString(query1_len);
    if (query1.empty()) query1 = "en"; // default
    
    // Second query for lou_findTable
    size_t query2_len = fdp.ConsumeIntegralInRange<size_t>(1, 64);
    std::string query2 = fdp.ConsumeBytesAsString(query2_len);
    if (query2.empty()) query2 = "us"; // default
    
    // Step 2: Find tables
    char** found_tables = lou_findTables(query1.c_str());
    char* found_table = lou_findTable(query2.c_str());
    
    // Step 3: Load a table for processing
    // Choose which table to load: either from found_tables or found_table
    const char* table_to_load = nullptr;
    if (found_table != nullptr) {
        table_to_load = found_table;
    } else if (found_tables != nullptr && found_tables[0] != nullptr) {
        table_to_load = found_tables[0];
    } else {
        // Use a default table
        table_to_load = "en-us-g2.ctb";
    }
    
    // Actually load the table
    const void* loaded_table = lou_getTable(table_to_load);
    if (loaded_table == nullptr) {
        // Cleanup and return if table loading failed
        if (found_table) lou_freeTableFile(found_table);
        if (found_tables) lou_freeTableFiles(found_tables);
        return 0;
    }
    
    // Step 4: Examine table metadata
    // Consume metadata key to query
    size_t key_len = fdp.ConsumeIntegralInRange<size_t>(1, 32);
    std::string metadata_key = fdp.ConsumeBytesAsString(key_len);
    if (metadata_key.empty()) metadata_key = "language";
    
    char* table_info = lou_getTableInfo(table_to_load, metadata_key.c_str());
    
    // Step 5: Hyphenation operations
    // Consume input text for hyphenation
    size_t text_len = fdp.ConsumeIntegralInRange<size_t>(1, 256);
    std::string input_text = fdp.ConsumeBytesAsString(text_len);
    
    if (!input_text.empty()) {
        // Convert input string to widechar format
        std::vector<widechar> wide_input(input_text.size() + 1);
        for (size_t i = 0; i < input_text.size(); ++i) {
            wide_input[i] = static_cast<widechar>(input_text[i]);
        }
        wide_input[input_text.size()] = 0; // Null terminator
        
        // Prepare hyphens buffer
        std::vector<char> hyphens(input_text.size() + 1);
        
        // Consume mode for hyphenation
        int hyphen_mode = fdp.ConsumeIntegral<int>() % 4;
        
        // Call lou_hyphenate
        lou_hyphenate(table_to_load, wide_input.data(), 
                     static_cast<int>(input_text.size()), 
                     hyphens.data(), hyphen_mode);
        
        // Step 6: Pre-hyphenated translation (if we have hyphens)
        // Prepare buffers for translation
        int inlen = static_cast<int>(input_text.size());
        int outlen = inlen * 2; // Reasonable output buffer size
        std::vector<widechar> outbuf(outlen);
        std::vector<formtype> typeform(inlen);
        std::vector<char> spacing(inlen);
        std::vector<int> outputPos(inlen);
        std::vector<int> inputPos(inlen);
        std::vector<int> cursorPos(inlen);
        std::vector<char> outputHyphens(inlen);
        
        // Consume mode for pre-hyphenated translation
        int prehyphen_mode = fdp.ConsumeIntegral<int>() % 4;
        
        // Call lou_translatePrehyphenated
        lou_translatePrehyphenated(table_to_load, wide_input.data(), &inlen,
                                  outbuf.data(), &outlen, typeform.data(),
                                  spacing.data(), outputPos.data(),
                                  inputPos.data(), cursorPos.data(),
                                  hyphens.data(), outputHyphens.data(),
                                  prehyphen_mode);
        
        // Step 7: Character conversion operations
        // Prepare buffers for dotsToChar and charToDots
        std::vector<widechar> dots_buf(inlen);
        std::vector<widechar> chars_buf(inlen);
        
        // Fill dots buffer with some data
        for (int i = 0; i < inlen && i < static_cast<int>(dots_buf.size()); ++i) {
            dots_buf[i] = static_cast<widechar>(fdp.ConsumeIntegral<uint8_t>());
        }
        
        // Consume modes for conversion
        int dots_mode = fdp.ConsumeIntegral<int>() % 4;
        int char_mode = fdp.ConsumeIntegral<int>() % 4;
        
        // Call lou_dotsToChar
        lou_dotsToChar(table_to_load, dots_buf.data(), chars_buf.data(), 
                      inlen, dots_mode);
        
        // Call lou_charToDots
        lou_charToDots(table_to_load, wide_input.data(), dots_buf.data(),
                      inlen, char_mode);
    }
    
    // Step 8: Cleanup
    if (table_info) {
        lou_freeTableInfo(table_info);
    }
    
    if (found_table) {
        lou_freeTableFile(found_table);
    }
    
    if (found_tables) {
        lou_freeTableFiles(found_tables);
    }
    
    return 0;
}
