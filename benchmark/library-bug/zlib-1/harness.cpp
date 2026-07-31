/*
 * Third fuzzing harness for zlib library
 * Targets gzip file I/O lifecycle APIs with 0% coverage: gzopen, gzread, gzwrite, gzseek, gzclose, gzerror
 * Implements the complete gzip file lifecycle: Open -> Read/Write/Seek -> Close
 * Semantic differentiation from harness_001: Focus on structured lifecycle rather than random operations
 * Uses FuzzedDataProvider for structured input consumption
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <vector>
#include <string>

#include <fuzzer/FuzzedDataProvider.h>
#include "zlib.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check: need enough data for meaningful testing
    // We need data for: operation selection, buffer sizes, and actual data
    if (size < 32) return 0;
    
    FuzzedDataProvider fdp(data, size);
    
    // Create temporary files for gzip operations
    char temp_input_filename[] = "/tmp/zlib_gzip_input_XXXXXX";
    char temp_output_filename[] = "/tmp/zlib_gzip_output_XXXXXX";
    
    int fd_input = mkstemp(temp_input_filename);
    int fd_output = mkstemp(temp_output_filename);
    if (fd_input < 0 || fd_output < 0) {
        if (fd_input >= 0) {
            close(fd_input);
            unlink(temp_input_filename);
        }
        if (fd_output >= 0) {
            close(fd_output);
            unlink(temp_output_filename);
        }
        return 0;
    }
    
    // Close file descriptors so we can write test data
    close(fd_input);
    close(fd_output);
    
    // Write test data to input file from fuzzer input (simulating gzip data)
    FILE* tmp_input = fopen(temp_input_filename, "wb");
    if (!tmp_input) {
        unlink(temp_input_filename);
        unlink(temp_output_filename);
        return 0;
    }
    
    // Consume data for the input file from fuzzer input
    size_t input_file_size = fdp.ConsumeIntegralInRange<size_t>(1, 2048);
    std::vector<uint8_t> input_file_data = fdp.ConsumeBytes<uint8_t>(input_file_size);
    if (input_file_data.empty()) {
        fclose(tmp_input);
        unlink(temp_input_filename);
        unlink(temp_output_filename);
        return 0;
    }
    
    fwrite(input_file_data.data(), 1, input_file_data.size(), tmp_input);
    fclose(tmp_input);
    
    gzFile gz_input_file = nullptr;
    gzFile gz_output_file = nullptr;
    
    // 1. Open gzip file for reading (first file lifecycle)
    // Consume mode from fuzzer input
    std::string read_mode = "rb";
    if (fdp.ConsumeBool()) {
        read_mode = "r";  // transparent mode
    }
    
    gz_input_file = gzopen(temp_input_filename, read_mode.c_str());
    if (gz_input_file == nullptr) {
        // Clean up and return if opening fails
        unlink(temp_input_filename);
        unlink(temp_output_filename);
        return 0;
    }
    
    // 2. Read data from gzip file using gzread
    // Consume buffer size from fuzzer input
    size_t read_buffer_size = fdp.ConsumeIntegralInRange<size_t>(1, 4096);
    std::vector<char> read_buffer(read_buffer_size, 0);
    
    if (!read_buffer.empty()) {
        int bytes_read = gzread(gz_input_file, read_buffer.data(), read_buffer.size());
        // bytes_read could be 0 or negative - that's OK for fuzzing
        (void)bytes_read; // Avoid unused variable warning
    }
    
    // 3. Open gzip file for writing (second file lifecycle)
    std::string write_mode = "wb";
    // Consume compression level from fuzzer input
    int compression_level = fdp.ConsumeIntegralInRange<int>(0, 9);
    if (compression_level > 0) {
        write_mode = "wb" + std::to_string(compression_level);
    }
    
    // Optionally add strategy
    if (fdp.ConsumeBool() && compression_level > 0) {
        int strategy = fdp.ConsumeIntegralInRange<int>(0, 4);
        char strategy_char = 'f'; // default
        switch (strategy) {
            case 0: strategy_char = 'f'; break; // filtered
            case 1: strategy_char = 'h'; break; // huffman only
            case 2: strategy_char = 'R'; break; // RLE
            case 3: strategy_char = 'F'; break; // fixed
        }
        write_mode += strategy_char;
    }
    
    gz_output_file = gzopen(temp_output_filename, write_mode.c_str());
    if (gz_output_file == nullptr) {
        // Clean up and return if opening fails
        gzclose(gz_input_file);
        unlink(temp_input_filename);
        unlink(temp_output_filename);
        return 0;
    }
    
    // 4. Write data to gzip file using gzwrite
    // Consume write data from fuzzer input
    size_t write_data_size = fdp.ConsumeIntegralInRange<size_t>(1, 4096);
    std::vector<uint8_t> write_data = fdp.ConsumeBytes<uint8_t>(write_data_size);
    
    if (!write_data.empty()) {
        int bytes_written = gzwrite(gz_output_file, write_data.data(), write_data.size());
        // bytes_written could be 0 - that's OK for fuzzing
        (void)bytes_written; // Avoid unused variable warning
        
        // Flush to ensure data is written for subsequent operations
        if (fdp.ConsumeBool()) {
            gzflush(gz_output_file, Z_SYNC_FLUSH);
        }
    }
    
    // 5. Test seeking in gzip files using gzseek
    // For input file (reading) - test seeking
    if (fdp.ConsumeBool() && fdp.remaining_bytes() >= sizeof(long)) {
        long offset = fdp.ConsumeIntegral<long>();
        // Consume whence: SEEK_SET (0), SEEK_CUR (1)
        int whence = fdp.ConsumeBool() ? SEEK_SET : SEEK_CUR;
        
        z_off_t seek_result = gzseek(gz_input_file, offset, whence);
        (void)seek_result; // Avoid unused variable warning
    }
    
    // For output file (writing) - only forward seeks are supported
    if (fdp.ConsumeBool() && fdp.remaining_bytes() >= sizeof(long)) {
        // Only use reasonable offsets for write seeks
        long offset = fdp.ConsumeIntegralInRange<long>(0, 1024);
        z_off_t seek_result = gzseek(gz_output_file, offset, SEEK_CUR);
        (void)seek_result; // Avoid unused variable warning
    }
    
    // 6. Check for errors using gzerror
    const char* error_msg = nullptr;
    int errnum = 0;
    
    // Check input file errors
    error_msg = gzerror(gz_input_file, &errnum);
    (void)error_msg; // Avoid unused variable warnings
    (void)errnum;
    
    // Check output file errors  
    error_msg = gzerror(gz_output_file, &errnum);
    (void)error_msg;
    (void)errnum;
    
    // 7. Close all opened handles (complete the lifecycle) using gzclose
    int close_ret = 0;
    
    close_ret = gzclose(gz_input_file);
    (void)close_ret; // Avoid unused variable warning
    
    close_ret = gzclose(gz_output_file);
    (void)close_ret;
    
    // Clean up temporary files
    unlink(temp_input_filename);
    unlink(temp_output_filename);
    
    return 0;
}
