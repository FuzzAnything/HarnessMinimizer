/*
 * Fuzzing harness for libmagic (file type detection library)
 * This harness tests multiple public APIs of libmagic with fuzzed input
 * Based on analysis of libmagic source code and existing fuzzer
 */

#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

// Include libmagic headers - only magic.h is available in build directory
#include "magic.h"
// Include necessary system headers for POSIX functions
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Need minimum input for meaningful fuzzing
    if (size < 4) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Test 1: magic_open with different flags
    int flags = 0;
    
    // Consume flags from fuzzed input
    // Use available flag definitions from magic.h
    if (fdp.ConsumeBool()) flags |= MAGIC_NONE;
    if (fdp.ConsumeBool()) flags |= MAGIC_SYMLINK;
    if (fdp.ConsumeBool()) flags |= MAGIC_COMPRESS;
    if (fdp.ConsumeBool()) flags |= MAGIC_DEVICES;
    if (fdp.ConsumeBool()) flags |= MAGIC_MIME_TYPE;
    if (fdp.ConsumeBool()) flags |= MAGIC_MIME_ENCODING;
    if (fdp.ConsumeBool()) flags |= MAGIC_CONTINUE;
    if (fdp.ConsumeBool()) flags |= MAGIC_RAW;
    if (fdp.ConsumeBool()) flags |= MAGIC_ERROR;
    
    magic_t magic = magic_open(flags);
    if (magic == nullptr) {
        // If magic_open fails with complex flags, try with simple flags
        magic = magic_open(MAGIC_NONE);
        if (magic == nullptr) {
            return 0; // Can't proceed without magic handle
        }
    }
    
    // Test 2: magic_version (should always work)
    int version = magic_version();
    (void)version; // Use to avoid unused variable warning
    
    // Test 3: Get and set flags
    int current_flags = magic_getflags(magic);
    (void)current_flags;
    
    // Try setting different flags from fuzzed input
    int new_flags = fdp.ConsumeIntegral<int>();
    magic_setflags(magic, new_flags);
    
    // Test 4: Load a simple built-in magic database
    // Create a minimal magic database in memory
    const char* simple_magic = 
        "0 string \\x89PNG\\r\\n\\x1a\\n PNG image data\n"
        "0 string GIF GIF image data\n"
        "0 string \\xff\\xd8\\xff JPEG image data\n"
        "0 string \\x7fELF ELF executable\n"
        "0 string #! script text\n";
    
    // Write magic database to a temporary file
    char magic_template[] = "/tmp/magic_fuzz_XXXXXX";
    int magic_fd = mkstemp(magic_template);
    if (magic_fd != -1) {
        write(magic_fd, simple_magic, strlen(simple_magic));
        fsync(magic_fd);
        close(magic_fd);
        
        // Try to load the magic database
        if (magic_load(magic, magic_template) == -1) {
            // If load fails, continue anyway - magic_buffer may still work
        }
        
        // Clean up temporary file
        unlink(magic_template);
    }
    
    // Test 5: magic_buffer with fuzzed data
    // Split remaining input into multiple test cases
    while (fdp.remaining_bytes() > 0) {
        // Determine how much data to use for this test
        size_t test_size = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes());
        if (test_size == 0) {
            break;
        }
        
        std::vector<uint8_t> test_data = fdp.ConsumeBytes<uint8_t>(test_size);
        
        // Call magic_buffer with the test data
        const char* result = magic_buffer(magic, test_data.data(), test_data.size());
        (void)result; // Use result to avoid unused variable warning
        
        // Check for errors
        const char* error = magic_error(magic);
        (void)error;
        
        // Test magic_errno
        int err = magic_errno(magic);
        (void)err;
    }
    
    // Test 6: magic_file if we have data left
    if (fdp.remaining_bytes() > 10) {
        size_t file_size = fdp.ConsumeIntegralInRange<size_t>(1, fdp.remaining_bytes());
        std::vector<uint8_t> file_data = fdp.ConsumeBytes<uint8_t>(file_size);
        
        // Create temporary file with fuzzed data
        char file_template[] = "/tmp/data_fuzz_XXXXXX";
        int data_fd = mkstemp(file_template);
        if (data_fd != -1) {
            write(data_fd, file_data.data(), file_data.size());
            fsync(data_fd);
            close(data_fd);
            
            // Test magic_file
            const char* file_result = magic_file(magic, file_template);
            (void)file_result;
            
            // Clean up
            unlink(file_template);
        }
    }
    
    // Test 7: Test flag toggling with remaining input
    if (fdp.remaining_bytes() > 0) {
        // Try different flag combinations
        for (int i = 0; i < 5 && fdp.remaining_bytes() > 0; i++) {
            int toggle_flags = fdp.ConsumeIntegral<int>();
            magic_setflags(magic, toggle_flags);
            
            // Test magic_buffer with a small piece of data
            if (fdp.remaining_bytes() > 0) {
                size_t small_size = fdp.ConsumeIntegralInRange<size_t>(0, 
                    fdp.remaining_bytes() > 100 ? 100 : fdp.remaining_bytes());
                if (small_size > 0) {
                    std::vector<uint8_t> small_data = fdp.ConsumeBytes<uint8_t>(small_size);
                    magic_buffer(magic, small_data.data(), small_size);
                }
            }
        }
    }
    
    // Clean up
    magic_close(magic);
    
    return 0;
}
