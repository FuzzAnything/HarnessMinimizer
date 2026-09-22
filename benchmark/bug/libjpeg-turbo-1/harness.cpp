/*
 * Fuzzing harness for libjpeg-turbo arithmetic coding APIs
 * Targets arithmetic entropy coding functions: jinit_arith_encoder, jinit_arith_decoder
 * Tests arithmetic coding with various configurations, table parameters, and scan modes
 * Uses FuzzedDataProvider to dynamically control arithmetic coding parameters and test data
 */

#include <fuzzer/FuzzedDataProvider.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

extern "C" {
#include "jpeglib.h"
#include "jerror.h"
}

/* Error manager structure for setjmp/longjmp error handling */
struct fuzzer_error_mgr {
    struct jpeg_error_mgr pub;
    jmp_buf setjmp_buffer;
};

/* Error exit handler */
static void fuzzer_error_exit(j_common_ptr cinfo) {
    struct fuzzer_error_mgr *fuzz_err = (struct fuzzer_error_mgr *)cinfo->err;
    longjmp(fuzz_err->setjmp_buffer, 1);
}

/* Suppress warning messages */
static void fuzzer_emit_message(j_common_ptr cinfo, int msg_level) {
    // Suppress all messages during fuzzing
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Minimum size check: need enough for basic parameters
    if (size < 32) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);
    
    // Consume arithmetic coding parameters from fuzzer input
    uint8_t param_selector = fdp.ConsumeIntegral<uint8_t>();
    uint8_t operation_type = fdp.ConsumeIntegral<uint8_t>();
    
    // Select arithmetic coding operation: 0=compression, 1=decompression, 2=both
    int op_type = operation_type % 3;
    
    // Select image dimensions (bounded to avoid memory exhaustion)
    int width = fdp.ConsumeIntegralInRange<int>(8, 128);
    int height = fdp.ConsumeIntegralInRange<int>(8, 128);
    
    // Select color space and component count
    J_COLOR_SPACE color_space;
    int num_components;
    switch ((param_selector >> 1) % 5) {
        case 0: color_space = JCS_GRAYSCALE; num_components = 1; break;
        case 1: color_space = JCS_RGB; num_components = 3; break;
        case 2: color_space = JCS_YCbCr; num_components = 3; break;
        case 3: color_space = JCS_CMYK; num_components = 4; break;
        case 4: color_space = JCS_YCCK; num_components = 4; break;
        default: color_space = JCS_RGB; num_components = 3; break;
    }
    
    // Select progressive mode
    boolean progressive_mode = (param_selector >> 3) & 0x1;
    
    // Calculate required pixel data size
    size_t pixel_data_size = (size_t)width * height * num_components;
    // Check if we have enough data for pixel data
    if (fdp.remaining_bytes() < pixel_data_size) {
        // Adjust dimensions to fit available data
        width = 16;
        height = 16;
        pixel_data_size = (size_t)width * height * num_components;
        
        if (fdp.remaining_bytes() < pixel_data_size) {
            return 0;  // Still not enough data
        }
    }
    
    // Consume pixel data
    std::vector<uint8_t> pixel_data = fdp.ConsumeBytes<uint8_t>(pixel_data_size);
    
    // Test arithmetic coding compression
    if (op_type == 0 || op_type == 2) {
        struct jpeg_compress_struct cinfo;
        struct fuzzer_error_mgr jerr;
        unsigned char *jpeg_buffer = NULL;
        unsigned long jpeg_size = 0;
        JSAMPROW row_pointer[1];
        int row_stride;
        
        // Set up error manager
        cinfo.err = jpeg_std_error(&jerr.pub);
        jerr.pub.error_exit = fuzzer_error_exit;
        jerr.pub.emit_message = fuzzer_emit_message;
        
        // Initialize compression object
        jpeg_create_compress(&cinfo);
        
        // Set up error recovery with setjmp
        if (setjmp(jerr.setjmp_buffer)) {
            // Error occurred during compression
            jpeg_destroy_compress(&cinfo);
            if (jpeg_buffer) free(jpeg_buffer);
            goto decompression_test;  // Try decompression if compression fails
        }
        
        // Set up memory destination
        jpeg_mem_dest(&cinfo, &jpeg_buffer, &jpeg_size);
        
        // Set image dimensions
        cinfo.image_width = width;
        cinfo.image_height = height;
        cinfo.input_components = num_components;
        cinfo.in_color_space = color_space;
        
        // Set default compression parameters
        jpeg_set_defaults(&cinfo);
        
        // Enable arithmetic coding (overrides Huffman coding)
        cinfo.arith_code = TRUE;
        
        // Configure arithmetic coding tables
        for (int i = 0; i < NUM_ARITH_TBLS; i++) {
            // Set L, U values for DC tables (0-255 valid range)
            cinfo.arith_dc_L[i] = fdp.ConsumeIntegralInRange<UINT8>(1, 255);
            cinfo.arith_dc_U[i] = fdp.ConsumeIntegralInRange<UINT8>(
                cinfo.arith_dc_L[i] + 1, 255);
            
            // Set Kx values for AC tables (0-255 valid range)
            cinfo.arith_ac_K[i] = fdp.ConsumeIntegral<UINT8>();
        }
        
        // Set other compression parameters
        cinfo.dct_method = JDCT_ISLOW;
        cinfo.optimize_coding = (param_selector >> 4) & 0x1;
        
        // Set progressive mode if requested
        if (progressive_mode) {
            jpeg_simple_progression(&cinfo);
        }
        
        // Set restart interval
        cinfo.restart_interval = fdp.ConsumeIntegralInRange<unsigned int>(0, 100);
        
        // Start compression
        jpeg_start_compress(&cinfo, TRUE);
        
        // Write scanlines
        row_stride = width * num_components;
        while (cinfo.next_scanline < cinfo.image_height) {
            row_pointer[0] = &pixel_data[cinfo.next_scanline * row_stride];
            jpeg_write_scanlines(&cinfo, row_pointer, 1);
        }
        
        // Finish compression
        jpeg_finish_compress(&cinfo);
        
        // Clean up compression resources
        jpeg_destroy_compress(&cinfo);
        
        // If we generated JPEG data, test decompression
        if (jpeg_buffer && jpeg_size > 0 && (op_type == 2 || op_type == 1)) {
            decompression_test:
            // Test arithmetic coding decompression
            struct jpeg_decompress_struct dinfo;
            struct fuzzer_error_mgr derr;
            JSAMPARRAY output_buffer = NULL;
            
            // Set up error manager for decompression
            dinfo.err = jpeg_std_error(&derr.pub);
            derr.pub.error_exit = fuzzer_error_exit;
            derr.pub.emit_message = fuzzer_emit_message;
            
            // Initialize decompression object
            jpeg_create_decompress(&dinfo);
            
            // Set up error recovery with setjmp
            if (setjmp(derr.setjmp_buffer)) {
                // Error occurred during decompression
                jpeg_destroy_decompress(&dinfo);
                if (output_buffer) {
                    for (int i = 0; i < height; i++) {
                        free(output_buffer[i]);
                    }
                    free(output_buffer);
                }
                if (jpeg_buffer) free(jpeg_buffer);
                return 0;
            }
            
            // Set up memory source
            jpeg_mem_src(&dinfo, jpeg_buffer, jpeg_size);
            
            // Read header
            jpeg_read_header(&dinfo, TRUE);
            
            // Verify arithmetic coding is enabled
            if (!dinfo.arith_code) {
                // Arithmetic coding not enabled in input, skip decompression test
                jpeg_destroy_decompress(&dinfo);
                if (jpeg_buffer) free(jpeg_buffer);
                return 0;
            }
            
            // Start decompression
            jpeg_start_decompress(&dinfo);
            
            // Allocate output buffer
            output_buffer = (JSAMPARRAY)malloc(sizeof(JSAMPROW) * height);
            for (int i = 0; i < height; i++) {
                output_buffer[i] = (JSAMPLE *)malloc(width * num_components);
            }
            
            // Read scanlines
            while (dinfo.output_scanline < dinfo.output_height) {
                jpeg_read_scanlines(&dinfo, &output_buffer[dinfo.output_scanline], 1);
            }
            
            // Finish decompression
            jpeg_finish_decompress(&dinfo);
            
            // Clean up decompression resources
            jpeg_destroy_decompress(&dinfo);
            if (output_buffer) {
                for (int i = 0; i < height; i++) {
                    free(output_buffer[i]);
                }
                free(output_buffer);
            }
        }
        
        if (jpeg_buffer) free(jpeg_buffer);
    }
    
    return 0;
}
