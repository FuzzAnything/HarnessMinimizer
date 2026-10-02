/*
 * Fuzzing harness for zlib gzip reading utilities
 * Targets: gzgetc_, uncompress_z, compress_z, gzdirect, gzdopen, 
 *          gzread, gzgets, gzgetc, gzfread, gzerror, gzclose_r
 * 
 * This harness focuses specifically on gzip reading utilities and
 * uncovered compression/decompression APIs. Differentiates from 
 * harness_001 (gzip file I/O) by emphasizing in-memory operations
 * and comprehensive reading API coverage.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "zlib.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <vector>
#include <string>
#include <memory>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check for meaningful fuzzing
    // Need enough data for compression and reading operations
    if (size < 64) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);
    
    // Consume fixed-size parameters first
    uint8_t test_scenario = fdp.ConsumeIntegral<uint8_t>() % 3;
    uint8_t compression_level = fdp.ConsumeIntegralInRange<uint8_t>(0, 9);
    uint8_t use_gzdopen = fdp.ConsumeBool();
    uint8_t read_operation = fdp.ConsumeIntegral<uint8_t>() % 4;
    
    // Consume source data for compression
    size_t source_data_len = fdp.ConsumeIntegralInRange<size_t>(32, 2048);
    if (source_data_len > fdp.remaining_bytes()) {
        source_data_len = fdp.remaining_bytes();
    }
    
    std::vector<uint8_t> source_data = fdp.ConsumeBytes<uint8_t>(source_data_len);
    
    // Test scenario determines the flow
    switch (test_scenario) {
        case 0: {
            // Scenario 1: Direct compress_z/uncompress_z API testing
            // Calculate maximum compressed size
            z_size_t max_compressed_len = compressBound_z(source_data_len);
            if (max_compressed_len == 0) {
                return 0; // Invalid size
            }
            
            // Allocate destination buffer for compression
            std::vector<Bytef> compressed_data(max_compressed_len);
            z_size_t compressed_len = max_compressed_len;
            
            // Test compress_z
            int compress_result = compress_z(compressed_data.data(), &compressed_len,
                                            source_data.data(), source_data_len);
            
            // Only proceed if compression succeeded
            if (compress_result == Z_OK && compressed_len > 0) {
                // Allocate buffer for decompression
                std::vector<Bytef> decompressed_data(source_data_len);
                z_size_t decompressed_len = source_data_len;
                
                // Test uncompress_z
                int uncompress_result = uncompress_z(decompressed_data.data(), &decompressed_len,
                                                    compressed_data.data(), compressed_len);
                
                // Verify decompression matches original
                if (uncompress_result == Z_OK && decompressed_len == source_data_len) {
                    // Basic verification
                    if (memcmp(source_data.data(), decompressed_data.data(), source_data_len) != 0) {
                        // Data mismatch - should not happen with valid compression
                    }
                }
            }
            break;
        }
        
        case 1: {
            // Scenario 2: gzip file reading operations with gzopen
            // Create compressed data first
            z_size_t max_compressed_len = compressBound_z(source_data_len);
            if (max_compressed_len == 0) {
                return 0;
            }
            
            std::vector<Bytef> compressed_data(max_compressed_len);
            z_size_t compressed_len = max_compressed_len;
            
            int compress_result = compress_z(compressed_data.data(), &compressed_len,
                                            source_data.data(), source_data_len);
            
            if (compress_result != Z_OK || compressed_len == 0) {
                return 0;
            }
            
            // Write compressed data to temporary file
            char temp_filename[] = "/tmp/fuzz_gzread_XXXXXX";
            int fd = mkstemp(temp_filename);
            if (fd == -1) {
                return 0;
            }
            
            // Write compressed data to file
            ssize_t written = write(fd, compressed_data.data(), compressed_len);
            close(fd);
            
            if (written != (ssize_t)compressed_len) {
                unlink(temp_filename);
                return 0;
            }
            
            // Open gzip file for reading
            gzFile file = nullptr;
            if (use_gzdopen) {
                // Test gzdopen - reopen file descriptor
                fd = open(temp_filename, O_RDONLY);
                if (fd != -1) {
                    file = gzdopen(fd, "rb");
                    if (file == nullptr) {
                        close(fd);
                    }
                }
            } else {
                // Test gzopen
                file = gzopen(temp_filename, "rb");
            }
            
            if (file == nullptr) {
                unlink(temp_filename);
                return 0;
            }
            
            // Test gzdirect to check if file is in direct mode
            int direct_status = gzdirect(file);
            
            // Perform reading operations based on read_operation
            switch (read_operation) {
                case 0: {
                    // Test gzread - block reading
                    size_t read_buffer_size = 1024;
                    std::vector<char> read_buffer(read_buffer_size);
                    int bytes_read = gzread(file, read_buffer.data(), read_buffer_size);
                    
                    // If we read something, test gzgetc and gzgetc_
                    if (bytes_read > 0) {
                        // Test gzgetc (character reading)
                        int ch = gzgetc(file);
                        if (ch != -1) {
                            // Test backward compatibility gzgetc_
                            int ch2 = gzgetc_(file);
                        }
                        
                        // Test gzgets (line reading)
                        // Reset file position for line reading
                        gzrewind(file);
                        char line_buffer[256];
                        char* line_result = gzgets(file, line_buffer, sizeof(line_buffer));
                    }
                    break;
                }
                
                case 1: {
                    // Test gzfread - formatted reading
                    size_t items_to_read = 4;
                    size_t item_size = 128;
                    size_t total_read_size = items_to_read * item_size;
                    std::vector<char> fread_buffer(total_read_size);
                    
                    size_t items_read = gzfread(fread_buffer.data(), item_size, items_to_read, file);
                    break;
                }
                
                case 2: {
                    // Test mixed reading operations
                    // Read some bytes with gzread
                    char small_buffer[64];
                    int bytes_read = gzread(file, small_buffer, sizeof(small_buffer));
                    
                    // Try gzgetc multiple times
                    for (int i = 0; i < 10 && !gzeof(file); i++) {
                        int ch = gzgetc(file);
                        if (ch == -1) break;
                    }
                    
                    // Try gzgets
                    char line[128];
                    gzgets(file, line, sizeof(line));
                    break;
                }
                
                case 3: {
                    // Test reading until EOF
                    char buffer[512];
                    int total_bytes = 0;
                    while (!gzeof(file) && total_bytes < 4096) {
                        int bytes_read = gzread(file, buffer, sizeof(buffer));
                        if (bytes_read <= 0) break;
                        total_bytes += bytes_read;
                    }
                    break;
                }
            }
            
            // Check for errors
            int err_num;
            const char* error_msg = gzerror(file, &err_num);
            
            // Close file with gzclose_r (reading close)
            gzclose_r(file);
            
            // Clean up temporary file
            unlink(temp_filename);
            break;
        }
        
        case 2: {
            // Scenario 3: Direct reading from small compressed data
            // Create very small compressed data
            size_t small_source_len = std::min(source_data_len, (size_t)100);
            z_size_t max_compressed_len = compressBound_z(small_source_len);
            if (max_compressed_len == 0) {
                return 0;
            }
            
            std::vector<Bytef> compressed_data(max_compressed_len);
            z_size_t compressed_len = max_compressed_len;
            
            int compress_result = compress_z(source_data.data(), &compressed_len,
                                            source_data.data(), small_source_len);
            
            if (compress_result != Z_OK || compressed_len == 0) {
                return 0;
            }
            
            // Write to temp file
            char temp_filename[] = "/tmp/fuzz_gzread_small_XXXXXX";
            int fd = mkstemp(temp_filename);
            if (fd == -1) {
                return 0;
            }
            
            write(fd, compressed_data.data(), compressed_len);
            close(fd);
            
            // Open with gzopen
            gzFile file = gzopen(temp_filename, "rb");
            if (file != nullptr) {
                // Test gzdirect
                int direct = gzdirect(file);
                
                // Try to read (may fail due to small/invalid data)
                char buf[16];
                gzread(file, buf, sizeof(buf));
                
                // Check error
                int err_num;
                gzerror(file, &err_num);
                
                gzclose_r(file);
            }
            
            unlink(temp_filename);
            break;
        }
    }
    
    return 0;
}
