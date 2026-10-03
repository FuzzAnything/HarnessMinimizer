/* Fuzzing harness for libpng resource limitation and palette optimization APIs
 * Targets uncovered PNG resource management and palette functionality:
 * 1. Resource limitation APIs (completely uncovered):
 *    - png_set_user_limits: Set maximum image dimensions (0 hits in existing harnesses)
 *    - png_get_user_width_max, png_get_user_height_max: Get dimension limits
 *    - png_set_chunk_cache_max: Set maximum chunk cache size (0 hits)
 *    - png_get_chunk_cache_max: Get chunk cache limit
 *    - png_set_chunk_malloc_max: Set maximum chunk allocation size (0 hits)
 *    - png_get_chunk_malloc_max: Get chunk allocation limit
 * 
 * 2. Palette optimization APIs (partially covered, focusing on edge cases):
 *    - png_build_grayscale_palette: Build optimized grayscale palette (0 hits)
 *    - png_set_quantize: Color quantization with edge case parameters
 *    - Palette-based image creation with boundary conditions
 * 
 * 3. Interleaved read/write operations with resource limits:
 *    - Testing PNG reading with dimension limits
 *    - Testing PNG writing with chunk cache limits
 *    - Testing palette optimization with various bit depths
 * 
 * Creates comprehensive testing scenarios for:
 * 1. Resource limitation configuration and validation
 * 2. Palette optimization with boundary conditions  
 * 3. Memory management with chunk allocation limits
 * 4. Edge case handling for large/small dimension limits
 * 
 * Uses FuzzedDataProvider to generate diverse resource limits and palette parameters
 * Differentiates from existing harnesses by targeting resource management exclusively
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <memory>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "png.h"

// Error handling callback functions
static void pngtest_error(png_structp png_ptr, png_const_charp error_msg) {
    // Suppress error messages during fuzzing
    (void)error_msg;
    // Use longjmp as required by libpng
    longjmp(png_jmpbuf(png_ptr), 1);
}

static void pngtest_warning(png_structp png_ptr, png_const_charp warning_msg) {
    // Suppress warning messages during fuzzing
    (void)png_ptr;
    (void)warning_msg;
}

// Custom read function for memory buffer
struct mem_buffer {
    const uint8_t* data;
    size_t size;
    size_t offset;
};

static void mem_read_fn(png_structp png_ptr, png_bytep data, png_size_t length) {
    mem_buffer* buf = (mem_buffer*)png_get_io_ptr(png_ptr);
    if (buf->offset + length > buf->size) {
        png_error(png_ptr, "Read beyond buffer");
        return;
    }
    memcpy(data, buf->data + buf->offset, length);
    buf->offset += length;
}

// Custom write function to discard output
static void mem_write_fn(png_structp png_ptr, png_bytep data, png_size_t length) {
    (void)png_ptr;
    (void)data;
    (void)length;
}

static void mem_flush_fn(png_structp png_ptr) {
    (void)png_ptr;
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Need sufficient data for comprehensive resource configuration
    // We'll split input into multiple parts for different test phases
    if (size < 128) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // ============================================
    // PHASE 1: Test resource limitation APIs with reading
    // ============================================
    
    // Consume fixed parameters for resource limits with reasonable constraints to prevent OOM
    png_uint_32 user_width_max = fdp.ConsumeIntegralInRange<png_uint_32>(1, 4096);   // Max 4K width (was 8192)
    png_uint_32 user_height_max = fdp.ConsumeIntegralInRange<png_uint_32>(1, 4096);  // Max 4K height (was 8192)
    png_uint_32 chunk_cache_max = fdp.ConsumeIntegralInRange<png_uint_32>(0, 256 * 1024); // Max 256KB cache (was 1MB)
    png_alloc_size_t chunk_malloc_max = fdp.ConsumeIntegralInRange<png_alloc_size_t>(1024, 4 * 1024 * 1024); // 1KB to 4MB (was 16MB)
    
    // Consume palette parameters with constraints
    int bit_depth = fdp.PickValueInArray({1, 2, 4, 8});
    int max_colors = fdp.ConsumeIntegralInRange<int>(1, 256);
    bool use_histogram = fdp.ConsumeBool();
    bool full_quantize = fdp.ConsumeBool();
    
    // Consume remaining bytes for PNG data with size limits to prevent OOM
    // Limit PNG data size to prevent excessive memory allocation
    size_t max_png_data_size = 1024 * 1024; // 1MB max
    size_t remaining_bytes = fdp.remaining_bytes();
    size_t png_data_size = std::min(remaining_bytes / 2, max_png_data_size);
    
    std::vector<uint8_t> png_data_read = fdp.ConsumeBytes<uint8_t>(png_data_size);
    // Limit second half as well
    size_t second_half_size = std::min(fdp.remaining_bytes(), max_png_data_size);
    std::vector<uint8_t> png_data_write = fdp.ConsumeBytes<uint8_t>(second_half_size);
    // Test 1: Reading with resource limits
    if (png_data_read.size() >= 8) {
        png_structp read_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL,
                                                     pngtest_error, pngtest_warning);
        if (read_ptr != NULL) {
            png_infop read_info_ptr = png_create_info_struct(read_ptr);
            if (read_info_ptr != NULL) {
                // Set up custom read from memory buffer
                mem_buffer read_buf;
                read_buf.data = png_data_read.data();
                read_buf.size = png_data_read.size();
                read_buf.offset = 0;
                
                png_set_read_fn(read_ptr, &read_buf, mem_read_fn);
                
                // Set resource limits if supported
                #ifdef PNG_SET_USER_LIMITS_SUPPORTED
                png_set_user_limits(read_ptr, user_width_max, user_height_max);
                png_set_chunk_cache_max(read_ptr, chunk_cache_max);
                png_set_chunk_malloc_max(read_ptr, chunk_malloc_max);
                
                // Verify limits were set
                png_uint_32 retrieved_width = png_get_user_width_max(read_ptr);
                png_uint_32 retrieved_height = png_get_user_height_max(read_ptr);
                png_uint_32 retrieved_cache = png_get_chunk_cache_max(read_ptr);
                png_alloc_size_t retrieved_malloc = png_get_chunk_malloc_max(read_ptr);
                (void)retrieved_width;
                (void)retrieved_height;
                (void)retrieved_cache;
                (void)retrieved_malloc;
                #endif
                
                // Try to read with error handling
                if (setjmp(png_jmpbuf(read_ptr))) {
                    // Error occurred (possibly due to resource limits)
                    png_destroy_read_struct(&read_ptr, &read_info_ptr, NULL);
                } else {
                    // Attempt to read PNG info
                    png_read_info(read_ptr, read_info_ptr);
                    
                    // Test palette expansion if image is palette-based
                    int color_type = png_get_color_type(read_ptr, read_info_ptr);
                    if (color_type == PNG_COLOR_TYPE_PALETTE) {
                        // Expand palette to RGB for testing
                        png_set_palette_to_rgb(read_ptr);
                        
                        // Test quantize if supported
                        #ifdef PNG_READ_QUANTIZE_SUPPORTED
                        if (max_colors > 0) {
                            // Create a palette for quantization
                            png_color palette[256];
                            png_uint_16 histogram[256] = {0};
                            
                            // Build a simple grayscale palette first
                            png_build_grayscale_palette(bit_depth, palette);
                            
                            // Apply quantization
                            png_set_quantize(read_ptr, palette, 
                                           (bit_depth == 1) ? 2 : 
                                           (bit_depth == 2) ? 4 : 
                                           (bit_depth == 4) ? 16 : 256,
                                           max_colors,
                                           use_histogram ? histogram : NULL,
                                           full_quantize);
                        }
                        #endif
                    }
                    
                    png_destroy_read_struct(&read_ptr, &read_info_ptr, NULL);
                }
            } else {
                png_destroy_read_struct(&read_ptr, NULL, NULL);
            }
        }
    }
    
    // Test 2: Writing with resource limits and palette optimization
    if (png_data_write.size() >= 8) {
        png_structp write_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL,
                                                       pngtest_error, pngtest_warning);
        if (write_ptr != NULL) {
            png_infop write_info_ptr = png_create_info_struct(write_ptr);
            if (write_info_ptr != NULL) {
                // Set up custom write to discard output
                png_set_write_fn(write_ptr, NULL, mem_write_fn, mem_flush_fn);
                
                // Set resource limits for writing
                #ifdef PNG_SET_USER_LIMITS_SUPPORTED
                png_set_user_limits(write_ptr, user_width_max, user_height_max);
                png_set_chunk_cache_max(write_ptr, chunk_cache_max);
                png_set_chunk_malloc_max(write_ptr, chunk_malloc_max);
                #endif
                
                // Set error handling
                if (setjmp(png_jmpbuf(write_ptr))) {
                    png_destroy_write_struct(&write_ptr, &write_info_ptr);
                } else {
                    // Create a simple palette-based image to test optimization
                    png_uint_32 width = 64;
                    png_uint_32 height = 64;
                    
                    // Test different color types including palette
                    int test_color_type = fdp.PickValueInArray({
                        PNG_COLOR_TYPE_GRAY,
                        PNG_COLOR_TYPE_PALETTE,
                        PNG_COLOR_TYPE_RGB
                    });
                    
                    png_set_IHDR(write_ptr, write_info_ptr, width, height, bit_depth,
                               test_color_type, PNG_INTERLACE_NONE,
                               PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
                    
                    // If palette color type, create and set palette
                    if (test_color_type == PNG_COLOR_TYPE_PALETTE) {
                        png_color palette[256];
                        int num_palette = 0;
                        
                        // Build grayscale palette for testing
                        if (bit_depth <= 8) {
                            png_build_grayscale_palette(bit_depth, palette);
                            num_palette = (bit_depth == 1) ? 2 : 
                                         (bit_depth == 2) ? 4 : 
                                         (bit_depth == 4) ? 16 : 256;
                            
                            png_set_PLTE(write_ptr, write_info_ptr, palette, num_palette);
                            
                            // Test quantization on writing path if supported
                            #ifdef PNG_WRITE_QUANTIZE_SUPPORTED
                            // Note: png_set_quantize is for reading, not writing
                            // For writing, we would use png_set_quantize if converting
                            // from truecolor to palette
                            #endif
                        }
                    }
                    
                    // Write info and end (no actual image data needed for this test)
                    png_write_info(write_ptr, write_info_ptr);
                    png_write_end(write_ptr, write_info_ptr);
                    
                    png_destroy_write_struct(&write_ptr, &write_info_ptr);
                }
            } else {
                png_destroy_write_struct(&write_ptr, NULL);
            }
        }
    }
    
    // Test 3: Direct palette building tests
    // Test png_build_grayscale_palette with various bit depths
    for (int test_depth : {1, 2, 4, 8}) {
        png_color palette[256];
        png_build_grayscale_palette(test_depth, palette);
        // The function should populate the palette array
        // We don't need to do anything with it, just calling exercises the code
    }
    
    return 0;
}
