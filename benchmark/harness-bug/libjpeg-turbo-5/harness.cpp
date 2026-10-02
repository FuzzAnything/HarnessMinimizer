/*
 * Fuzzing harness for libjpeg-turbo JPEG error recovery and marker handling APIs
 * This harness targets completely uncovered error recovery and multi-scan JPEG APIs:
 * - jpeg_resync_to_restart: Error recovery from corrupted streams (0% coverage, 24 undiscovered branches)
 * - jpeg_write_marker: Writing custom JPEG markers (0% coverage, 10 undiscovered branches)
 * - jpeg_finish_output: Multi-scan output completion (0% coverage, 14 undiscovered branches)
 * - jpeg_start_output: Multi-scan output initiation (0% coverage, 10 undiscovered branches)
 * - jpeg_has_multiple_scans: Multi-scan detection (0% coverage, 4 undiscovered branches)
 * - jpeg_input_complete: Input completion check (0% coverage, 4 undiscovered branches)
 * 
 * Required Helper APIs:
 * - jpeg_CreateCompress/jpeg_CreateDecompress: Object initialization
 * - jpeg_destroy_compress/jpeg_destroy_decompress: Cleanup
 * - jpeg_set_defaults: Default configuration
 * - jpeg_set_quality: Quality setting
 * - jpeg_mem_src/jpeg_mem_dest: Memory-based I/O
 * - jpeg_read_header: Header reading
 * - jpeg_start_compress/jpeg_start_decompress: Operation start
 * - jpeg_finish_compress/jpeg_finish_decompress: Operation completion
 * 
 * Differentiates from existing harnesses (000-010):
 * - harness_000.cpp: Modern tj3* TurboJPEG APIs
 * - harness_001.cpp: Traditional tj* TurboJPEG APIs  
 * - harness_002.cpp: Modern tj3* YUV APIs
 * - harness_003.cpp: 12/16-bit precision APIs
 * - harness_004.cpp: Traditional tj* YUV operations
 * - harness_005.cpp: High-bit-depth image I/O
 * - harness_006.cpp: Traditional YUV encoding
 * - harness_007.cpp: Traditional libjpeg memory I/O APIs (jpeg_mem_src/jpeg_mem_dest)
 * - harness_008.cpp: Traditional libjpeg 12-bit APIs
 * - harness_009.cpp: Old turbojpeg YUV decompression APIs
 * - harness_010.cpp: Traditional file-based I/O APIs
 * 
 * Strategy: Implement full error recovery lifecycle with corrupted JPEG data injection,
 * multi-scan progressive JPEG testing, and custom marker writing to exercise foundational
 * error recovery modules currently at 0% coverage.
 * 
 * Expected Coverage Gain: 70+ undiscovered branches across 6 critical error recovery APIs
 */

#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <algorithm>

// Include traditional libjpeg headers
extern "C" {
#include "jpeglib.h"
#include "jerror.h"
}

// Error manager with custom error handler to catch errors without exiting
static boolean error_occurred = FALSE;

static void error_exit(j_common_ptr cinfo) {
    error_occurred = TRUE;
}

static void output_message(j_common_ptr cinfo) {
    // Suppress output messages during fuzzing
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check - need enough data for JPEG operations and corruption
    if (size < 128) return 0;
    
    FuzzedDataProvider fdp(data, size);
    
    // ========== PHASE 1: CREATE BASIC JPEG DATA FOR TESTING ==========
    
    struct jpeg_compress_struct cinfo_compress;
    struct jpeg_error_mgr jerr_compress;
    
    // Initialize compression object with custom error handler
    cinfo_compress.err = jpeg_std_error(&jerr_compress);
    jerr_compress.error_exit = error_exit;
    jerr_compress.output_message = output_message;
    error_occurred = FALSE;
    
    jpeg_CreateCompress(&cinfo_compress, JPEG_LIB_VERSION, sizeof(struct jpeg_compress_struct));
    
    // Consume compression parameters from fuzzer input
    int width = fdp.ConsumeIntegralInRange<int>(8, 128);
    int height = fdp.ConsumeIntegralInRange<int>(8, 128);
    int quality = fdp.ConsumeIntegralInRange<int>(1, 100);
    boolean progressive = fdp.ConsumeBool();
    int num_scans = progressive ? fdp.ConsumeIntegralInRange<int>(2, 4) : 1;
    
    // Set basic parameters
    cinfo_compress.image_width = width;
    cinfo_compress.image_height = height;
    cinfo_compress.input_components = 3; // RGB
    cinfo_compress.in_color_space = JCS_RGB;
    
    jpeg_set_defaults(&cinfo_compress);
    jpeg_set_quality(&cinfo_compress, quality, TRUE);
    
    if (progressive) {
        // Set up progressive mode for multi-scan testing
        jpeg_simple_progression(&cinfo_compress);
    }
    
    // Setup memory destination
    unsigned char* jpeg_buffer = nullptr;
    unsigned long jpeg_size = 0;
    jpeg_mem_dest(&cinfo_compress, &jpeg_buffer, &jpeg_size);
    
    // Start compression
    jpeg_start_compress(&cinfo_compress, TRUE);
    
    // Write custom markers using jpeg_write_marker
    // Test various marker types (0xE0-0xEF are application markers)
    int marker_count = fdp.ConsumeIntegralInRange<int>(0, 5);
    for (int i = 0; i < marker_count; i++) {
        int marker_type = 0xE0 + (fdp.ConsumeIntegralInRange<int>(0, 15) % 16);
        size_t marker_data_size = fdp.ConsumeIntegralInRange<size_t>(1, 64);
        std::vector<JOCTET> marker_data = fdp.ConsumeBytes<JOCTET>(marker_data_size);
        
        if (!marker_data.empty()) {
            jpeg_write_marker(&cinfo_compress, marker_type, marker_data.data(), marker_data.size());
        }
    }
    
    // Write scanlines
    size_t scanline_size = (size_t)width * 3; // RGB
    if (scanline_size > 0) {
        std::vector<JSAMPLE> scanline(scanline_size);
        for (int row = 0; row < height; row++) {
            // Fill with fuzzer data
            auto row_data = fdp.ConsumeBytes<JSAMPLE>(std::min(scanline_size, (size_t)1024));
            if (row_data.size() >= scanline_size) {
                memcpy(scanline.data(), row_data.data(), scanline_size);
            } else {
                // Fill with pattern if not enough data
                for (size_t i = 0; i < scanline_size; i++) {
                    scanline[i] = (JSAMPLE)((row * 7 + i * 13) % 256);
                }
            }
            
            JSAMPROW row_pointer[1];
            row_pointer[0] = scanline.data();
            jpeg_write_scanlines(&cinfo_compress, row_pointer, 1);
        }
    }
    
    // Finish compression
    jpeg_finish_compress(&cinfo_compress);
    
    // Clean up compression object (but keep buffer)
    jpeg_destroy_compress(&cinfo_compress);
    
    // ========== PHASE 2: TEST ERROR RECOVERY WITH CORRUPTED DATA ==========
    
    if (jpeg_buffer && jpeg_size > 16) {
        // Create corrupted version of JPEG data
        std::vector<unsigned char> corrupted_data(jpeg_buffer, jpeg_buffer + jpeg_size);
        
        // Corrupt random bytes based on fuzzer input
        int corruption_count = fdp.ConsumeIntegralInRange<int>(1, 10);
        for (int i = 0; i < corruption_count && corrupted_data.size() > 0; i++) {
            size_t corrupt_pos = fdp.ConsumeIntegralInRange<size_t>(0, corrupted_data.size() - 1);
            uint8_t corrupt_value = fdp.ConsumeIntegral<uint8_t>();
            corrupted_data[corrupt_pos] = corrupt_value;
        }
        
        // Setup decompression for corrupted data
        struct jpeg_decompress_struct cinfo_corrupt;
        struct jpeg_error_mgr jerr_corrupt;
        
        cinfo_corrupt.err = jpeg_std_error(&jerr_corrupt);
        jerr_corrupt.error_exit = error_exit;
        jerr_corrupt.output_message = output_message;
        error_occurred = FALSE;
        jpeg_CreateDecompress(&cinfo_corrupt, JPEG_LIB_VERSION, sizeof(struct jpeg_decompress_struct));
        
        // Setup memory source with corrupted data
        jpeg_mem_src(&cinfo_corrupt, corrupted_data.data(), corrupted_data.size());
        int header_result = jpeg_read_header(&cinfo_corrupt, TRUE);

        if (header_result == JPEG_HEADER_OK) {
            // Test jpeg_has_multiple_scans API
            boolean has_multiple_scans = jpeg_has_multiple_scans(&cinfo_corrupt);
            
            // Test jpeg_input_complete API
            boolean input_complete = jpeg_input_complete(&cinfo_corrupt);
            
            // Enable buffered-image mode only for multi-scan testing
            cinfo_corrupt.buffered_image = has_multiple_scans;

            if (has_multiple_scans && cinfo_corrupt.input_scan_number > 0) {
                // For multi-scan images, we need to call jpeg_start_decompress first
                // to set up the buffered-image mode state
                if (jpeg_start_decompress(&cinfo_corrupt)) {
                    int scan_number = fdp.ConsumeIntegralInRange<int>(
                        1, cinfo_corrupt.input_scan_number);
                    
                    // Test jpeg_start_output for multi-scan images
                    boolean start_output_result =
                        jpeg_start_output(&cinfo_corrupt, scan_number);
                    
                    if (start_output_result) {
                        // Read some scanlines (may trigger error recovery)
                        if (cinfo_corrupt.output_width > 0 &&
                            cinfo_corrupt.output_components > 0) {
                            size_t output_scanline_size =
                                (size_t)cinfo_corrupt.output_width *
                                cinfo_corrupt.output_components;

                            std::vector<JSAMPLE> output_buffer(
                                output_scanline_size);
                            
                            int max_scanlines =
                                fdp.ConsumeIntegralInRange<int>(1, 10);

                            for (int i = 0;
                                 i < max_scanlines &&
                                 cinfo_corrupt.output_scanline <
                                     cinfo_corrupt.output_height;
                                 i++) {
                                JSAMPROW row_pointer[1];
                                row_pointer[0] = output_buffer.data();
                                jpeg_read_scanlines(
                                    &cinfo_corrupt, row_pointer, 1);
                            }
                        }
                        
                        // Test jpeg_finish_output for multi-scan images
                        boolean finish_output_result =
                            jpeg_finish_output(&cinfo_corrupt);
                    }
                    
                    // Clean up multi-scan state
                    jpeg_destroy_decompress(&cinfo_corrupt);
                } else {
                    // jpeg_start_decompress failed, still need to clean up
                    jpeg_destroy_decompress(&cinfo_corrupt);
                }
            } else {
                // Single-scan (baseline) JPEG handling
                jpeg_start_decompress(&cinfo_corrupt);
                
                // Read scanlines (may trigger error recovery internally)
                if (cinfo_corrupt.output_width > 0 &&
                    cinfo_corrupt.output_components > 0) {
                    size_t output_scanline_size =
                        (size_t)cinfo_corrupt.output_width *
                        cinfo_corrupt.output_components;

                    std::vector<JSAMPLE> output_buffer(
                        output_scanline_size);
                    
                    while (cinfo_corrupt.output_scanline <
                           cinfo_corrupt.output_height) {
                        JSAMPROW row_pointer[1];
                        row_pointer[0] = output_buffer.data();

                        jpeg_read_scanlines(
                            &cinfo_corrupt, row_pointer, 1);
                        
                        // Break early to avoid excessive processing
                        if (cinfo_corrupt.output_scanline > 10)
                            break;
                    }
                }
                
                jpeg_finish_decompress(&cinfo_corrupt);
                jpeg_destroy_decompress(&cinfo_corrupt);
            }
        } else {
            // Header reading failed due to corruption
            jpeg_destroy_decompress(&cinfo_corrupt);
        }
    }

    // ========== PHASE 3: TEST ERROR RECOVERY WITH EXPLICIT RESYNC ==========
    
    if (jpeg_buffer && jpeg_size > 16) {
        // Test jpeg_resync_to_restart explicitly by creating a scenario
        // where we need to resync to a restart marker
        
        // Create severely corrupted data by truncating
        size_t truncate_point =
            fdp.ConsumeIntegralInRange<size_t>(jpeg_size / 4, jpeg_size / 2);

        std::vector<unsigned char> truncated_data(
            jpeg_buffer, jpeg_buffer + truncate_point);
        
        // Add restart marker to trigger resync logic
        if (truncated_data.size() > 2) {
            // Insert a restart marker (0xFF, 0xD0-0xD7)
            uint8_t restart_marker =
                0xD0 + (fdp.ConsumeIntegral<uint8_t>() % 8);

            truncated_data.push_back(0xFF);
            truncated_data.push_back(restart_marker);
        }
        
        struct jpeg_decompress_struct cinfo_resync;
        struct jpeg_error_mgr jerr_resync;
        
        cinfo_resync.err = jpeg_std_error(&jerr_resync);
        jerr_resync.error_exit = error_exit;
        jerr_resync.output_message = output_message;
        error_occurred = FALSE;
        
        jpeg_CreateDecompress(
            &cinfo_resync,
            JPEG_LIB_VERSION,
            sizeof(struct jpeg_decompress_struct));
        
        // Enable restart markers for testing resync
        cinfo_resync.restart_interval =
            fdp.ConsumeIntegralInRange<int>(1, 100);
        
        jpeg_mem_src(
            &cinfo_resync,
            truncated_data.data(),
            truncated_data.size());
        
        // Try to process with potential need for resync
        if (jpeg_read_header(&cinfo_resync, TRUE) == JPEG_HEADER_OK) {
            jpeg_start_decompress(&cinfo_resync);
            
            // Attempt to read scanlines (may trigger internal resync calls)
            if (cinfo_resync.output_width > 0 &&
                cinfo_resync.output_components > 0) {
                size_t scanline_size_resync =
                    (size_t)cinfo_resync.output_width *
                    cinfo_resync.output_components;

                std::vector<JSAMPLE> buffer_resync(
                    scanline_size_resync);
                
                for (int i = 0;
                     i < 3 &&
                     cinfo_resync.output_scanline <
                         cinfo_resync.output_height;
                     i++) {
                    JSAMPROW row_pointer[1];
                    row_pointer[0] = buffer_resync.data();

                    jpeg_read_scanlines(
                        &cinfo_resync, row_pointer, 1);
                }
            }
            
            // Explicitly test jpeg_resync_to_restart API
            // This function is typically called internally during error recovery
            // We can call it directly to test its functionality
            int desired_restart =
                fdp.ConsumeIntegralInRange<int>(0, 7);

            boolean resync_result =
                jpeg_resync_to_restart(
                    &cinfo_resync, desired_restart);
            
            jpeg_finish_decompress(&cinfo_resync);
        }
        
        jpeg_destroy_decompress(&cinfo_resync);
    }
    
    // ========== PHASE 4: TEST PROGRESSIVE/MULTI-SCAN COMPRESSION ==========
    
    if (fdp.ConsumeBool() && fdp.remaining_bytes() > 100) {
        // Create progressive JPEG with multiple scans
        struct jpeg_compress_struct cinfo_progressive;
        struct jpeg_error_mgr jerr_progressive;
        
        cinfo_progressive.err = jpeg_std_error(&jerr_progressive);
        jerr_progressive.error_exit = error_exit;
        jerr_progressive.output_message = output_message;
        error_occurred = FALSE;
        
        jpeg_CreateCompress(
            &cinfo_progressive,
            JPEG_LIB_VERSION,
            sizeof(struct jpeg_compress_struct));
        
        int prog_width =
            fdp.ConsumeIntegralInRange<int>(16, 64);
        int prog_height =
            fdp.ConsumeIntegralInRange<int>(16, 64);
        int prog_quality =
            fdp.ConsumeIntegralInRange<int>(50, 95);
        
        cinfo_progressive.image_width = prog_width;
        cinfo_progressive.image_height = prog_height;
        cinfo_progressive.input_components = 3;
        cinfo_progressive.in_color_space = JCS_RGB;
        
        jpeg_set_defaults(&cinfo_progressive);
        jpeg_set_quality(
            &cinfo_progressive, prog_quality, TRUE);
        
        // Enable progressive mode
        jpeg_simple_progression(&cinfo_progressive);
        
        unsigned char* prog_buffer = nullptr;
        unsigned long prog_size = 0;

        jpeg_mem_dest(
            &cinfo_progressive,
            &prog_buffer,
            &prog_size);
        
        jpeg_start_compress(&cinfo_progressive, TRUE);
        
        // Write some scanlines
        size_t prog_scanline_size = (size_t)prog_width * 3;

        if (prog_scanline_size > 0) {
            std::vector<JSAMPLE> prog_scanline(
                prog_scanline_size);

            for (int row = 0; row < prog_height; row++) {
                for (size_t i = 0;
                     i < prog_scanline_size;
                     i++) {
                    prog_scanline[i] =
                        (JSAMPLE)((row * 17 + i * 23) % 256);
                }
                
                JSAMPROW row_pointer[1];
                row_pointer[0] = prog_scanline.data();

                jpeg_write_scanlines(
                    &cinfo_progressive,
                    row_pointer,
                    1);
            }
        }
        
        jpeg_finish_compress(&cinfo_progressive);
        jpeg_destroy_compress(&cinfo_progressive);
        
        // Free the progressive buffer if allocated
        if (prog_buffer) {
            free(prog_buffer);
        }
    }
    
    // ========== PHASE 5: CLEANUP ==========
    
    // Free the JPEG buffer created in phase 1
    if (jpeg_buffer) {
        free(jpeg_buffer);
    }
    
    return 0;
}