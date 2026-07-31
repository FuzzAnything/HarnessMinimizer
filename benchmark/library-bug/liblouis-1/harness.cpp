/*
 * liblouis Logging System Fuzzing Harness
 *
 * Copyright (C) 2024 Fuzzing Harness Generator
 *
 * This harness specifically tests liblouis logging functionality based on
 * coverage analysis guidance targeting the largest uncovered complexity cluster.
 * Target APIs:
 * - lou_logFile (0% coverage, 16 undiscovered branches)
 * - lou_logPrint (0% coverage, 6 undiscovered branches) 
 * - lou_logEnd (25% coverage, 3 undiscovered branches)
 * - lou_registerLogCallback (Required helper: 50% coverage, 1 undiscovered branch)
 * - lou_setLogLevel (Setup function)
 * - lou_translateString/lou_hyphenate (To generate log messages through internal logging)
 *
 * It follows the logging system lifecycle: setup (set log level, register callback),
 * logging operations (open log file, generate log messages via translation/hyphenation
 * calls, direct logging API), cleanup (close log file).
 * It uses FuzzedDataProvider to properly split fuzzer input for various parameters.
 * Semantic differentiation from previous harnesses (translation, hyphenation, metadata,
 * table compilation) by focusing exclusively on logging subsystem.
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

// Log level enumeration for testing different levels
static const logLevels LOG_LEVELS[] = {
    LOU_LOG_ALL,
    LOU_LOG_DEBUG,
    LOU_LOG_INFO,
    LOU_LOG_WARN,
    LOU_LOG_ERROR,
    LOU_LOG_FATAL,
    LOU_LOG_OFF
};

// Custom logging callback for testing lou_registerLogCallback
static void custom_log_callback(logLevels level, const char *message) {
    // Just consume the parameters to avoid unused warnings
    (void)level;
    (void)message;
    // In real usage, this would process the log message
    // For fuzzing, we just need to ensure the callback mechanism works
}

// Global initialization flag
static int initialized = 0;

// Cleanup function
static void __attribute__((destructor)) free_resources(void) {
    lou_free();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Minimum size check for logging testing (need enough for various parameters)
    if (size < 32) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Initialize library once
    if (!initialized) {
        // Don't register callback initially - we'll test registration later
        // This allows testing default callback behavior
        initialized = 1;
    }
    
    // PHASE 1: SETUP - Configure logging system
    
    // 1.1 Set log level from fuzzer input
    uint8_t level_choice = fdp.ConsumeIntegral<uint8_t>() % 7;
    lou_setLogLevel(LOG_LEVELS[level_choice]);
    
    // 1.2 Test callback registration (or not) based on fuzzer input
    bool register_callback = fdp.ConsumeBool();
    if (register_callback) {
        lou_registerLogCallback(custom_log_callback);
    } else {
        // Test with default callback (NULL registration resets to default)
        lou_registerLogCallback(NULL);
    }
    
    // PHASE 2: LOG FILE MANAGEMENT
    
    // 2.1 Create temporary log file name from fuzzer input
    size_t filename_len = fdp.ConsumeIntegralInRange<size_t>(1, 64);
    std::string log_filename = fdp.ConsumeBytesAsString(filename_len);
    
    // Clean the filename to make it valid for fopen
    for (char &c : log_filename) {
        if (c == 0 || c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || 
            c == '"' || c == '<' || c == '>' || c == '|') {
            c = '_';
        }
    }
    
    // 2.2 Open log file using lou_logFile
    // Test both with valid filename and with NULL/empty (which should use stderr)
    bool use_valid_file = fdp.ConsumeBool();
    if (use_valid_file && !log_filename.empty()) {
        // Prepend /tmp/ to ensure we write to temporary location
        std::string full_path = "/tmp/liblouis_fuzz_log_" + log_filename;
        lou_logFile(full_path.c_str());
    } else {
        // Test with NULL filename (should revert to stderr)
        lou_logFile(NULL);
    }
    
    // PHASE 3: GENERATE LOG MESSAGES THROUGH TRANSLATION/HYPHENATION
    
    // 3.1 Select a translation table
    uint8_t table_choice = fdp.ConsumeIntegral<uint8_t>() % 6;
    const char* table_list = COMMON_TABLES[table_choice];
    
    // 3.2 Prepare input text for translation (which will generate internal logs)
    size_t input_len = fdp.ConsumeIntegralInRange<size_t>(1, 128);
    if (fdp.remaining_bytes() < input_len) {
        return 0;
    }
    
    std::string input_str = fdp.ConsumeBytesAsString(input_len);
    
    if (!input_str.empty()) {
        // Convert to widechar for liblouis APIs
        size_t widechar_len = input_str.size();
        std::vector<widechar> input_text(widechar_len + 1);
        for (size_t i = 0; i < widechar_len; i++) {
            input_text[i] = (widechar)(input_str[i] & 0xFF);
        }
        input_text[widechar_len] = 0;
        
        // Prepare output buffers
        int inlen = (int)widechar_len;
        int outlen = inlen * 16;  // Reasonable expansion factor for braille
        
        std::vector<widechar> outbuf(outlen);
        std::vector<char> hyphens_buf(widechar_len);  // char* for hyphenate
        std::vector<formtype> typeform_buf(widechar_len);
        std::vector<char> spacing_buf(widechar_len);
        
        // 3.3 Call translation APIs to trigger internal logging
        // Choose which API to test based on fuzzer input
        uint8_t api_choice = fdp.ConsumeIntegral<uint8_t>() % 3;
        
        switch (api_choice) {
            case 0:
                // Test lou_translateString - this will generate internal logs
                lou_translateString(table_list, input_text.data(), &inlen, 
                                   outbuf.data(), &outlen, typeform_buf.data(), 
                                   spacing_buf.data(), 0);
                break;
                
            case 1:
                // Test lou_hyphenate - this will also generate internal logs
                lou_hyphenate(table_list, input_text.data(), inlen, 
                             hyphens_buf.data(), 0);
                break;
                
            case 2:
                // Test lou_backTranslateString for additional logging paths
                lou_backTranslateString(table_list, input_text.data(), &inlen,
                                       outbuf.data(), &outlen, typeform_buf.data(),
                                       spacing_buf.data(), 0);
                break;
        }
    }
    // 4.1 Test lou_logPrint with various format strings and parameters
    if (fdp.remaining_bytes() > 10) {
        // Generate log message from fuzzer input
        size_t msg_len = fdp.ConsumeIntegralInRange<size_t>(1, 128);
        std::string log_message = fdp.ConsumeBytesAsString(msg_len);
        
        if (!log_message.empty()) {
            // Clean the message to avoid format string vulnerabilities in test
            // by using a simple format string
            lou_logPrint("%s", log_message.c_str());
            
            // Test with additional parameters if we have enough input
            if (fdp.remaining_bytes() > 20) {
                int int_param = fdp.ConsumeIntegral<int>();
                lou_logPrint("Test log with int: %d, message: %s", int_param, log_message.c_str());
            }
        }
    }
    
    // PHASE 5: TEST LOG FILE REOPENING AND MULTIPLE FILES
    
    // 5.1 Test reopening with different filename
    if (fdp.remaining_bytes() > 20) {
        size_t second_filename_len = fdp.ConsumeIntegralInRange<size_t>(1, 64);
        std::string second_filename = fdp.ConsumeBytesAsString(second_filename_len);
        
        // Clean the filename
        for (char &c : second_filename) {
            if (c == 0 || c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || 
                c == '"' || c == '<' || c == '>' || c == '|') {
                c = '_';
            }
        }
        
        if (!second_filename.empty()) {
            std::string second_full_path = "/tmp/liblouis_fuzz_log2_" + second_filename;
            lou_logFile(second_full_path.c_str());
            
            // Generate another log message to the new file
            if (fdp.remaining_bytes() > 10) {
                size_t second_msg_len = fdp.ConsumeIntegralInRange<size_t>(1, 64);
                std::string second_msg = fdp.ConsumeBytesAsString(second_msg_len);
                if (!second_msg.empty()) {
                    lou_logPrint("Second file: %s", second_msg.c_str());
                }
            }
        }
    }
    
    // PHASE 6: CLEANUP
    
    // 6.1 Close log file using lou_logEnd
    lou_logEnd();
    
    // 6.2 Test that we can still log after lou_logEnd (should go to stderr)
    if (fdp.remaining_bytes() > 10) {
        size_t final_msg_len = fdp.ConsumeIntegralInRange<size_t>(1, 32);
        std::string final_msg = fdp.ConsumeBytesAsString(final_msg_len);
        if (!final_msg.empty()) {
            lou_logPrint("After logEnd: %s", final_msg.c_str());
        }
    }
    
    // 6.3 Test reopening log file after lou_logEnd
    if (fdp.remaining_bytes() > 20) {
        size_t final_filename_len = fdp.ConsumeIntegralInRange<size_t>(1, 32);
        std::string final_filename = fdp.ConsumeBytesAsString(final_filename_len);
        
        // Clean the filename
        for (char &c : final_filename) {
            if (c == 0 || c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' || 
                c == '"' || c == '<' || c == '>' || c == '|') {
                c = '_';
            }
        }
        
        if (!final_filename.empty()) {
            std::string final_full_path = "/tmp/liblouis_fuzz_log_final_" + final_filename;
            lou_logFile(final_full_path.c_str());
            
            // Final log message
            lou_logPrint("Final test completed");
            
            // Final cleanup
            lou_logEnd();
        }
    }
    
    return 0;
}
