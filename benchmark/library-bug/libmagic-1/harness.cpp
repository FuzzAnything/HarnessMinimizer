/*
 * Fuzzing harness for libmagic library - Core File/Buffer/Descriptor Detection APIs
 * Target: Comprehensive coverage of the three main detection APIs with 5,334+ undiscovered branches:
 * 1. magic_descriptor - 1,803 undiscovered branches (0% covered)
 * 2. magic_file - 1,801 undiscovered branches (0% covered)  
 * 3. magic_buffer - 1,643 undiscovered branches (0% covered)
 * 
 * Related uncovered internal functions: file_fsmagic, file_buffer, file_ascmagic, 
 * file_ascmagic_with_encoding, file_softmagic
 * 
 * Invocation sequence per coverage guidance:
 * magic_open(MAGIC_NONE) -> magic_load() -> magic_file() -> magic_descriptor() -> 
 * magic_buffer() -> magic_setparam()/magic_getparam() -> magic_close()
 * 
 * Focus: File diversity, descriptor handling, buffer manipulation, parameter variations, error paths
 */

#include <fuzzer/FuzzedDataProvider.h>
#include "magic.h"
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <memory>
#include <algorithm>

// Helper to create different types of test files
static std::vector<uint8_t> create_test_content(FuzzedDataProvider& fdp, uint8_t content_type) {
    std::vector<uint8_t> content;
    size_t size = fdp.ConsumeIntegralInRange<size_t>(1, 4096);
    
    switch (content_type % 10) {
        case 0: // ASCII/text content for file_ascmagic
            for (size_t i = 0; i < size; i++) {
                content.push_back(fdp.ConsumeIntegralInRange<uint8_t>(32, 126));
            }
            break;
            
        case 1: // Binary data with some structure
            content = fdp.ConsumeBytes<uint8_t>(size);
            // Add some recognizable patterns
            if (size > 10) {
                content[0] = 0x7F; // ELF-like
                content[1] = 'E';
                content[2] = 'L';
                content[3] = 'F';
            }
            break;
            
        case 2: // CDF/OLE2 document header
            if (size >= 8) {
                content.push_back(0xD0);
                content.push_back(0xCF);
                content.push_back(0x11);
                content.push_back(0xE0);
                content.push_back(0xA1);
                content.push_back(0xB1);
                content.push_back(0x1A);
                content.push_back(0xE1);
                // Fill rest with random
                for (size_t i = 8; i < size; i++) {
                    content.push_back(fdp.ConsumeIntegral<uint8_t>());
                }
            }
            break;
            
        case 3: // JSON-like structure for file_softmagic
            {
                std::string json = "{\"test\":\"";
                json += fdp.ConsumeRandomLengthString(50);
                json += "\",\"value\":";
                json += std::to_string(fdp.ConsumeIntegral<int>());
                json += "}";
                content.assign(json.begin(), json.end());
            }
            break;
            
        case 4: // CSV-like content
            {
                std::string csv = "col1,col2,col3\n";
                csv += fdp.ConsumeRandomLengthString(20);
                csv += ",";
                csv += fdp.ConsumeRandomLengthString(20);
                csv += ",";
                csv += fdp.ConsumeRandomLengthString(20);
                content.assign(csv.begin(), csv.end());
            }
            break;
            
        case 5: // Mostly null bytes
            content.resize(size, 0);
            // Add some non-null bytes
            for (size_t i = 0; i < std::min(size, size_t(10)); i++) {
                content[i] = fdp.ConsumeIntegral<uint8_t>();
            }
            break;
            
        case 6: // UTF-8 like with high bytes
            for (size_t i = 0; i < size; i++) {
                uint8_t byte = fdp.ConsumeIntegral<uint8_t>();
                // Generate UTF-8 like sequences
                if (byte >= 0xC0 && byte <= 0xDF && i + 1 < size) {
                    content.push_back(byte);
                    content.push_back(fdp.ConsumeIntegralInRange<uint8_t>(0x80, 0xBF));
                    i++;
                } else {
                    content.push_back(byte);
                }
            }
            break;
            
        case 7: // Tar-like structure
            content.resize(size, 0);
            if (size > 100) {
                // Tar header starts at offset 0
                std::string filename = fdp.ConsumeRandomLengthString(50);
                size_t copy_len = std::min(filename.length(), size_t(100));
                std::copy(filename.begin(), filename.begin() + copy_len, content.begin());
            }
            break;
            
        case 8: // ELF binary header
            if (size >= 52) {
                // ELF header
                content.push_back(0x7F);
                content.push_back('E');
                content.push_back('L');
                content.push_back('F');
                // Class (32/64 bit)
                content.push_back(fdp.ConsumeBool() ? 1 : 2);
                // Endianness
                content.push_back(fdp.ConsumeBool() ? 1 : 2);
                // Version
                content.push_back(1);
                // OS ABI
                content.push_back(fdp.ConsumeIntegral<uint8_t>());
                // Padding
                for (int i = 0; i < 8; i++) content.push_back(0);
                // Type
                content.push_back(fdp.ConsumeIntegral<uint8_t>());
                content.push_back(fdp.ConsumeIntegral<uint8_t>());
                // Machine
                content.push_back(fdp.ConsumeIntegral<uint8_t>());
                content.push_back(fdp.ConsumeIntegral<uint8_t>());
                // Version
                content.push_back(1);
                content.push_back(0);
                content.push_back(0);
                content.push_back(0);
                // Fill rest
                for (size_t i = 52; i < size; i++) {
                    content.push_back(fdp.ConsumeIntegral<uint8_t>());
                }
            }
            break;
            
        case 9: // Random mixed content
        default:
            content = fdp.ConsumeBytes<uint8_t>(size);
            break;
    }
    
    return content;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check - need enough for basic operations
    if (size < 32) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Phase 1: Initialization with comprehensive flag testing
    int flags = MAGIC_NONE;
    uint32_t flag_selector = fdp.ConsumeIntegral<uint32_t>();
    
    // Set flags based on fuzzer input to test different configurations
    if (flag_selector & 0x01) flags |= MAGIC_DEBUG;
    if (flag_selector & 0x02) flags |= MAGIC_SYMLINK;
    if (flag_selector & 0x04) flags |= MAGIC_COMPRESS;
    if (flag_selector & 0x08) flags |= MAGIC_DEVICES;
    if (flag_selector & 0x10) flags |= MAGIC_MIME_TYPE;
    if (flag_selector & 0x20) flags |= MAGIC_CONTINUE;
    if (flag_selector & 0x40) flags |= MAGIC_CHECK;
    if (flag_selector & 0x80) flags |= MAGIC_PRESERVE_ATIME;
    if (flag_selector & 0x100) flags |= MAGIC_RAW;
    if (flag_selector & 0x200) flags |= MAGIC_ERROR;
    if (flag_selector & 0x400) flags |= MAGIC_MIME_ENCODING;
    if (flag_selector & 0x800) flags |= MAGIC_APPLE;
    if (flag_selector & 0x1000) flags |= MAGIC_EXTENSION;
    
    // Exclusion flags for testing different detection paths
    if (flag_selector & 0x2000) flags |= MAGIC_NO_CHECK_COMPRESS;
    if (flag_selector & 0x4000) flags |= MAGIC_NO_CHECK_TAR;
    if (flag_selector & 0x8000) flags |= MAGIC_NO_CHECK_SOFT;
    if (flag_selector & 0x10000) flags |= MAGIC_NO_CHECK_APPTYPE;
    if (flag_selector & 0x20000) flags |= MAGIC_NO_CHECK_ELF;
    if (flag_selector & 0x40000) flags |= MAGIC_NO_CHECK_TEXT;
    if (flag_selector & 0x80000) flags |= MAGIC_NO_CHECK_CDF;
    if (flag_selector & 0x100000) flags |= MAGIC_NO_CHECK_CSV;
    if (flag_selector & 0x200000) flags |= MAGIC_NO_CHECK_TOKENS;
    if (flag_selector & 0x400000) flags |= MAGIC_NO_CHECK_ENCODING;
    if (flag_selector & 0x800000) flags |= MAGIC_NO_CHECK_JSON;
    if (flag_selector & 0x1000000) flags |= MAGIC_NO_CHECK_SIMH;
    
    // Step 1: magic_open()
    magic_t magic_cookie = magic_open(flags);
    if (magic_cookie == NULL) {
        return 0;  // Could not open magic context
    }
    
    // Step 2: magic_load() - try loading magic database
    int load_result = magic_load(magic_cookie, NULL);
    
    // If default load fails, try alternative paths
    if (load_result == -1 && fdp.remaining_bytes() > 0) {
        std::string custom_path = fdp.ConsumeRandomLengthString(256);
        load_result = magic_load(magic_cookie, custom_path.c_str());
        
        // If still fails, we may not have a database - but continue testing
        if (load_result == -1) {
            // Some APIs might still work or test error paths
        }
    }
    
    // Phase 2: Test magic_file() - target: 1,801 undiscovered branches
    if (fdp.remaining_bytes() > 100) {
        // Create multiple temporary files with different content types
        for (int file_idx = 0; file_idx < 3 && fdp.remaining_bytes() > 50; file_idx++) {
            char temp_filename[] = "/tmp/magic_fuzz_file_XXXXXX";
            int fd = mkstemp(temp_filename);
            if (fd >= 0) {
                // Generate different content types to trigger different detection paths
                uint8_t content_type = fdp.ConsumeIntegral<uint8_t>();
                std::vector<uint8_t> file_content = create_test_content(fdp, content_type);
                
                if (!file_content.empty()) {
                    // Write to file
                    if (write(fd, file_content.data(), file_content.size()) == (ssize_t)file_content.size()) {
                        close(fd);
                        
                        // Step 3: magic_file() - core API with 0% coverage
                        const char* file_result = magic_file(magic_cookie, temp_filename);
                        (void)file_result; // Use result to avoid unused warning
                        
                        // Test with different flags
                        if (fdp.remaining_bytes() > 0 && fdp.ConsumeBool()) {
                            int current_flags = magic_getflags(magic_cookie);
                            uint8_t extra_flags = fdp.ConsumeIntegral<uint8_t>();
                            int new_flags = current_flags;
                            
                            if (extra_flags & 0x01) new_flags ^= MAGIC_MIME_TYPE;
                            if (extra_flags & 0x02) new_flags ^= MAGIC_MIME_ENCODING;
                            if (extra_flags & 0x04) new_flags ^= MAGIC_CONTINUE;
                            
                            magic_setflags(magic_cookie, new_flags);
                            
                            // Test again with modified flags
                            const char* file_result2 = magic_file(magic_cookie, temp_filename);
                            (void)file_result2;
                            
                            // Restore flags
                            magic_setflags(magic_cookie, current_flags);
                        }
                    } else {
                        close(fd);
                    }
                } else {
                    close(fd);
                }
                
                // Clean up temp file
                unlink(temp_filename);
            }
        }
    }
    
    // Phase 3: Test magic_descriptor() - target: 1,803 undiscovered branches
    if (fdp.remaining_bytes() > 100) {
        // Create temporary file for descriptor testing
        char temp_filename[] = "/tmp/magic_fuzz_fd_XXXXXX";
        int fd = mkstemp(temp_filename);
        if (fd >= 0) {
            // Generate content for descriptor testing
            uint8_t content_type = fdp.ConsumeIntegral<uint8_t>();
            std::vector<uint8_t> fd_content = create_test_content(fdp, content_type);
            
            if (!fd_content.empty()) {
                // Write to file
                if (write(fd, fd_content.data(), fd_content.size()) == (ssize_t)fd_content.size()) {
                    // Rewind to beginning
                    lseek(fd, 0, SEEK_SET);
                    
                    // Step 4: magic_descriptor() - core API with 0% coverage
                    const char* fd_result = magic_descriptor(magic_cookie, fd);
                    (void)fd_result;
                    
                    // Test error paths with invalid descriptors
                    if (fdp.remaining_bytes() > 0) {
                        uint8_t error_test = fdp.ConsumeIntegral<uint8_t>() % 4;
                        
                        switch (error_test) {
                            case 0: {
                                // Test with negative file descriptor
                                const char* neg_result = magic_descriptor(magic_cookie, -1);
                                (void)neg_result;
                                break;
                            }
                            case 1: {
                                // Test with closed descriptor (after closing)
                                close(fd);
                                fd = -1;
                                const char* closed_result = magic_descriptor(magic_cookie, fd);
                                (void)closed_result;
                                break;
                            }
                            case 2: {
                                // Test with very large descriptor number
                                const char* large_result = magic_descriptor(magic_cookie, 999999);
                                (void)large_result;
                                break;
                            }
                            case 3: {
                                // Test with current descriptor but modified flags
                                int current_flags = magic_getflags(magic_cookie);
                                magic_setflags(magic_cookie, current_flags | MAGIC_DEBUG);
                                const char* debug_result = magic_descriptor(magic_cookie, fd);
                                (void)debug_result;
                                magic_setflags(magic_cookie, current_flags);
                                break;
                            }
                        }
                    }
                }
            }
            
            // Clean up
            if (fd >= 0) {
                close(fd);
            }
            unlink(temp_filename);
        }
    }
    
    // Phase 4: Test magic_buffer() - target: 1,643 undiscovered branches
    if (fdp.remaining_bytes() > 0) {
        // Consume buffer data with various sizes
        size_t buffer_size = fdp.ConsumeIntegralInRange<size_t>(
            1, std::min(fdp.remaining_bytes(), size_t(32768)));
        std::vector<uint8_t> buffer_data = fdp.ConsumeBytes<uint8_t>(buffer_size);
        
        if (!buffer_data.empty()) {
            // Step 5: magic_buffer() - core API with 0% coverage
            const char* buffer_result = magic_buffer(magic_cookie, 
                buffer_data.data(), buffer_data.size());
            (void)buffer_result;
            
            // Test edge cases and variations
            if (fdp.remaining_bytes() > 0) {
                uint8_t buffer_variation = fdp.ConsumeIntegral<uint8_t>() % 6;
                switch (buffer_variation) {
                    case 0: {
                        // Zero-length buffer
                        const char* zero_result = magic_buffer(magic_cookie, 
                            buffer_data.data(), 0);
                        (void)zero_result;
                        break;
                    }
                    case 1: {
                        // NULL buffer with size
                        const char* null_result = magic_buffer(magic_cookie, 
                            NULL, buffer_data.size());
                        (void)null_result;
                        break;
                    }
                    case 2: {
                        // Very small buffer (1 byte)
                        const char* tiny_result = magic_buffer(magic_cookie, 
                            buffer_data.data(), 1);
                        (void)tiny_result;
                        break;
                    }
                    case 3: {
                        // Buffer with modified flags
                        int current_flags = magic_getflags(magic_cookie);
                        magic_setflags(magic_cookie, current_flags | MAGIC_RAW);
                        const char* raw_result = magic_buffer(magic_cookie, 
                            buffer_data.data(), std::min(buffer_data.size(), size_t(100)));
                        (void)raw_result;
                        magic_setflags(magic_cookie, current_flags);
                        break;
                    }
                    case 4: {
                        // Buffer with MIME flags
                        magic_setflags(magic_cookie, MAGIC_MIME_TYPE | MAGIC_MIME_ENCODING);
                        const char* mime_result = magic_buffer(magic_cookie, 
                            buffer_data.data(), buffer_data.size());
                        (void)mime_result;
                        magic_setflags(magic_cookie, flags);
                        break;
                    }
                    case 5: {
                        // Multiple buffer calls with same data
                        for (int i = 0; i < 3 && i < (int)buffer_data.size(); i++) {
                            const char* multi_result = magic_buffer(magic_cookie, 
                                buffer_data.data(), buffer_data.size() - i);
                            (void)multi_result;
                        }
                        break;
                    }
                }
            }
        }
    }
    
    // Phase 5: Parameter manipulation - magic_setparam()/magic_getparam()
    if (fdp.remaining_bytes() > sizeof(size_t)) {
        uint8_t param_test = fdp.ConsumeIntegral<uint8_t>() % 4;
        
        switch (param_test) {
            case 0: {
                // MAGIC_PARAM_BYTES_MAX
                size_t bytes_max = 0;
                if (magic_getparam(magic_cookie, MAGIC_PARAM_BYTES_MAX, &bytes_max) == 0) {
                    size_t new_bytes_max = fdp.ConsumeIntegralInRange<size_t>(100, 1000000);
                    magic_setparam(magic_cookie, MAGIC_PARAM_BYTES_MAX, &new_bytes_max);
                    
                    // Get it back to verify
                    size_t verify_bytes_max = 0;
                    magic_getparam(magic_cookie, MAGIC_PARAM_BYTES_MAX, &verify_bytes_max);
                }
                break;
            }
            case 1: {
                // MAGIC_PARAM_REGEX_MAX
                size_t regex_max = 0;
                if (magic_getparam(magic_cookie, MAGIC_PARAM_REGEX_MAX, &regex_max) == 0) {
                    size_t new_regex_max = fdp.ConsumeIntegralInRange<size_t>(100, 10000);
                    magic_setparam(magic_cookie, MAGIC_PARAM_REGEX_MAX, &new_regex_max);
                }
                break;
            }
            case 2: {
                // MAGIC_PARAM_ENCODING_MAX
                size_t encoding_max = 0;
                if (magic_getparam(magic_cookie, MAGIC_PARAM_ENCODING_MAX, &encoding_max) == 0) {
                    size_t new_encoding_max = fdp.ConsumeIntegralInRange<size_t>(100, 10000);
                    magic_setparam(magic_cookie, MAGIC_PARAM_ENCODING_MAX, &new_encoding_max);
                }
                break;
            }
            case 3: {
                // Test invalid parameter
                int invalid_param = 999;
                size_t dummy_value = 100;
                magic_setparam(magic_cookie, invalid_param, &dummy_value);
                break;
            }

        }
    }
    
    // Phase 6: Error checking and final operations
    // Check for errors that may have occurred
    const char* error_msg = magic_error(magic_cookie);
    (void)error_msg;
    
    int err = magic_errno(magic_cookie);
    (void)err;
    
    // Test version API
    int version = magic_version();
    (void)version;
    
    // Step 7: magic_close() - cleanup
    magic_close(magic_cookie);
    
    return 0;
}
