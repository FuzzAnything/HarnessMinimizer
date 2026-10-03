/* Fuzzing harness for libpng simplified PNG image write operations with comprehensive parameter testing
 * Targets high-level PNG image API functions (png_image_* family) with focus on parameter edge cases:
 * - png_image_write_to_file (Target: 79 undiscovered branches)
 * - png_image_write_to_stdio (Target: 59 undiscovered branches)  
 * - png_image_write_to_memory (Target: 51 undiscovered branches)
 * - png_image_begin_read_from_file (Target: 63 undiscovered branches)
 * - png_image_begin_read_from_stdio (Target: 61 undiscovered branches)
 * - png_image_begin_read_from_memory (Target: 58 undiscovered branches)
 * - png_image_finish_read (Target: 51 undiscovered branches)
 * - png_image_free (Required Helper: Cleanup, 36 undiscovered branches)
 *
 * Required initialization APIs:
 * - png_create_read_struct / png_create_read_struct_2 (for reading)
 * - png_create_write_struct / png_create_write_struct_2 (for writing)
 * - png_create_info_struct (for both)
 *
 * Differentiates from existing harnesses by:
 * - Systematic testing of write API parameters (convert_to_8bit, row_stride variations)
 * - Comprehensive image format coverage including edge cases
 * - Testing memory allocation edge cases for png_image_write_to_memory
 * - Focus on parameter combinations rather than complete lifecycle
 *
 * Strategy: Use FuzzedDataProvider to generate diverse parameter combinations
 * for image formats, write flags, buffer configurations, and memory sizes.
 * Test each write function with valid and edge-case parameter values.
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <memory>
#include <string>
#include <fstream>
#include <cstdio>
#include <unistd.h>
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

// Create a temporary file from fuzzer input for file-based testing
static std::string create_temp_file(const uint8_t* data, size_t size) {
    char temp_filename[] = "/tmp/libpng_fuzz_temp_XXXXXX";
    int fd = mkstemp(temp_filename);
    if (fd == -1) {
        return "";
    }
    
    ssize_t written = write(fd, data, size);
    close(fd);
    
    if (written != static_cast<ssize_t>(size)) {
        unlink(temp_filename);
        return "";
    }
    
    return std::string(temp_filename);
}

// Calculate buffer size needed for PNG image based on format and dimensions
static size_t calculate_image_buffer_size(const png_image& image) {
    png_uint_32 bytes_per_pixel = 0;
    
    // Determine bytes per pixel based on format
    if (image.format & PNG_FORMAT_FLAG_COLORMAP) {
        // Colormap formats use 1 byte per pixel (index into colormap)
        bytes_per_pixel = 1;
    } else if (image.format & PNG_FORMAT_FLAG_LINEAR) {
        // Linear formats use 2 bytes per component
        if (image.format & PNG_FORMAT_FLAG_COLOR) {
            bytes_per_pixel = (image.format & PNG_FORMAT_FLAG_ALPHA) ? 8 : 6; // RGBA or RGB
        } else {
            bytes_per_pixel = (image.format & PNG_FORMAT_FLAG_ALPHA) ? 4 : 2; // GA or GRAY
        }
    } else {
        // Standard formats use 1 byte per component
        if (image.format & PNG_FORMAT_FLAG_COLOR) {
            bytes_per_pixel = (image.format & PNG_FORMAT_FLAG_ALPHA) ? 4 : 3; // RGBA or RGB
        } else {
            bytes_per_pixel = (image.format & PNG_FORMAT_FLAG_ALPHA) ? 2 : 1; // GA or GRAY
        }
    }
    
    return static_cast<size_t>(image.width) * static_cast<size_t>(image.height) * bytes_per_pixel;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Need sufficient data for comprehensive testing
    if (size < 128) {
        return 0;  // Need minimum for configuration and PNG data
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Declare all resources that need cleanup
    png_image read_image;
    png_image write_image;
    png_byte* image_buffer = NULL;
    png_byte* output_buffer = NULL;
    png_alloc_size_t memory_size = 0;
    char temp_filename[] = "/tmp/libpng_fuzz_in_XXXXXX";
    char output_filename[] = "/tmp/libpng_fuzz_out_XXXXXX";
    int temp_fd = -1;
    int output_fd = -1;
    FILE* stdio_file = NULL;
    bool temp_file_created = false;
    bool output_file_created = false;
    
    memset(&read_image, 0, sizeof(read_image));
    memset(&write_image, 0, sizeof(write_image));
    read_image.version = PNG_IMAGE_VERSION;
    write_image.version = PNG_IMAGE_VERSION;
    
    // ============================================
    // PHASE 1: Create a temporary PNG file for reading
    // ============================================
    
    // Consume PNG data for input file (first portion)
    size_t png_data_size = fdp.ConsumeIntegralInRange<size_t>(64, size / 2);
    std::vector<uint8_t> png_data = fdp.ConsumeBytes<uint8_t>(png_data_size);
    
    if (png_data.size() < 8) {
        return 0;  // Need minimum PNG signature
    }
    // Create temporary input file
    temp_fd = mkstemp(temp_filename);
    if (temp_fd == -1) {
        return 0;
    }
    temp_file_created = true;
    
    ssize_t written = write(temp_fd, png_data.data(), png_data.size());
    close(temp_fd);
    
    if (written != static_cast<ssize_t>(png_data.size())) {
        // Clean up and return early
        if (temp_file_created) {
            unlink(temp_filename);
        }
        return 0;
    }
    
    // Initialize read_image structure
    read_image.version = PNG_IMAGE_VERSION;
    read_image.opaque = NULL;
    read_image.width = 0;
    read_image.height = 0;
    read_image.format = 0;
    read_image.flags = 0;
    read_image.colormap_entries = 0;
    
    // Try to begin reading from file
    int begin_result = png_image_begin_read_from_file(&read_image, temp_filename);
    
    if (begin_result == 0) {
        // Reading failed, try stdio interface instead
        FILE* input_file = fopen(temp_filename, "rb");
        if (input_file != NULL) {
            begin_result = png_image_begin_read_from_stdio(&read_image, input_file);
            fclose(input_file);
        }
    }
    
    if (begin_result == 0) {
        // Both file and stdio reading failed, try memory interface
        begin_result = png_image_begin_read_from_memory(&read_image, 
                                                       png_data.data(), 
                                                       png_data.size());
    }
    
    if (begin_result != 0 && read_image.width > 0 && read_image.height > 0) {
        // Reading succeeded, allocate buffer for image data
        size_t buffer_size = PNG_IMAGE_SIZE(read_image);
        if (buffer_size > 0 && buffer_size < 1024 * 1024 * 16) { // Limit to 16MB
            image_buffer = (png_byte*)malloc(buffer_size);
            if (image_buffer != NULL) {
                memset(image_buffer, 0, buffer_size);
                
                // Test png_image_finish_read
                int finish_result = png_image_finish_read(&read_image, NULL, 
                                                         image_buffer, 0, NULL);
                (void)finish_result; // Result not used, just testing API
            }
        }
    }
    
    // ============================================
    // PHASE 3: Configure write_image for parameter testing
    // ============================================
    
    // Consume image dimensions (keep reasonable to prevent excessive memory)
    write_image.width = fdp.ConsumeIntegralInRange<png_uint_32>(1, 256);
    write_image.height = fdp.ConsumeIntegralInRange<png_uint_32>(1, 256);
    
    // Consume image format from fuzzer input
    uint32_t format_selector = fdp.ConsumeIntegral<uint32_t>() % 10;
    switch (format_selector) {
        case 0:
            write_image.format = PNG_FORMAT_RGB;
            break;
        case 1:
            write_image.format = PNG_FORMAT_RGBA;
            break;
        case 2:
            write_image.format = PNG_FORMAT_GRAY;
            break;
        case 3:
            write_image.format = PNG_FORMAT_GA;
            break;
        case 4:
            write_image.format = PNG_FORMAT_LINEAR_RGB;
            break;
        case 5:
            write_image.format = PNG_FORMAT_LINEAR_RGB_ALPHA;
            break;
        case 6:
            write_image.format = PNG_FORMAT_LINEAR_Y;
            break;
        case 7:
            write_image.format = PNG_FORMAT_LINEAR_Y_ALPHA;
            break;
        case 8:
            // Test with colormap format
            write_image.format = PNG_FORMAT_RGB_COLORMAP;
            write_image.colormap_entries = fdp.ConsumeIntegralInRange<uint32_t>(1, 256);
            break;
        case 9:
            // Test with linear colormap format
            write_image.format = PNG_FORMAT_RGBA_COLORMAP;
            write_image.colormap_entries = fdp.ConsumeIntegralInRange<uint32_t>(1, 256);
            break;
    }
    
    // Consume write parameters
    int convert_to_8bit = fdp.ConsumeBool() ? 1 : 0;
    png_int_32 row_stride = 0;
    
    // Test different row_stride values
    uint32_t row_stride_selector = fdp.ConsumeIntegral<uint32_t>() % 4;
    switch (row_stride_selector) {
        case 0:
            row_stride = 0;  // Let libpng calculate
            break;
        case 1:
            // Positive stride (top-down)
            row_stride = fdp.ConsumeIntegralInRange<png_int_32>(1, 1024);
            break;
        case 2:
            // Negative stride (bottom-up)
            row_stride = fdp.ConsumeIntegralInRange<png_int_32>(-1024, -1);
            break;
        case 3:
            // Unaligned stride (edge case)
            row_stride = fdp.ConsumeIntegralInRange<png_int_32>(-512, 512);
            break;
    }
    
    // Consume flags
    write_image.flags = 0;
    if (fdp.ConsumeBool()) {
        write_image.flags |= PNG_IMAGE_FLAG_COLORSPACE_NOT_sRGB;
    }
    
    // ============================================
    // PHASE 4: Create image buffer for writing
    // ============================================
    
    size_t write_buffer_size = calculate_image_buffer_size(write_image);
    if (write_buffer_size > 0 && write_buffer_size < 1024 * 1024 * 8) { // Limit to 8MB
        std::vector<uint8_t> write_buffer(write_buffer_size);
        
        // Fill buffer with fuzzer data
        size_t fill_size = std::min(fdp.remaining_bytes(), write_buffer_size);
        if (fill_size > 0) {
            std::vector<uint8_t> fill_data = fdp.ConsumeBytes<uint8_t>(fill_size);
            memcpy(write_buffer.data(), fill_data.data(), fill_size);
            
            // Fill remaining with pattern if needed
            for (size_t i = fill_size; i < write_buffer_size; i++) {
                write_buffer[i] = static_cast<uint8_t>(i % 256);
            }
        }
        
        // Create colormap if needed
        std::vector<uint8_t> colormap;
        if (write_image.format & PNG_FORMAT_FLAG_COLORMAP && write_image.colormap_entries > 0) {
            size_t colormap_size = write_image.colormap_entries * 
                ((write_image.format & PNG_FORMAT_FLAG_ALPHA) ? 4 : 3);
            colormap.resize(colormap_size);
            
            size_t colormap_fill = std::min(fdp.remaining_bytes(), colormap_size);
            if (colormap_fill > 0) {
                std::vector<uint8_t> colormap_data = fdp.ConsumeBytes<uint8_t>(colormap_fill);
                memcpy(colormap.data(), colormap_data.data(), colormap_fill);
            }
        }
        
        // ============================================
        // PHASE 5: Test png_image_write_to_file
        // ============================================
        
        output_fd = mkstemp(output_filename);
        if (output_fd != -1) {
            output_file_created = true;
            close(output_fd); // Close so file can be opened by png_image_write_to_file
            
            int write_result = png_image_write_to_file(&write_image, output_filename,
                                                      convert_to_8bit, write_buffer.data(),
                                                      row_stride, 
                                                      colormap.empty() ? NULL : colormap.data());
            (void)write_result; // Result not used, just testing API
            
            // Clean up output file
            unlink(output_filename);
            output_file_created = false;
        }
        
        // ============================================
        // PHASE 6: Test png_image_write_to_stdio
        // ============================================
        
        stdio_file = fopen("/dev/null", "wb");
        if (stdio_file != NULL) {
            int stdio_result = png_image_write_to_stdio(&write_image, stdio_file,
                                                       convert_to_8bit, write_buffer.data(),
                                                       row_stride,
                                                       colormap.empty() ? NULL : colormap.data());
            (void)stdio_result; // Result not used, just testing API
            fclose(stdio_file);
            stdio_file = NULL;
        }
        
        // ============================================
        // PHASE 7: Test png_image_write_to_memory with various buffer sizes
        // ============================================
        
        // Test with NULL memory to get required size
        memory_size = 0;
        int size_result = png_image_write_to_memory(&write_image, NULL, &memory_size,
                                                   convert_to_8bit, write_buffer.data(),
                                                   row_stride,
                                                   colormap.empty() ? NULL : colormap.data());
        
        if (size_result != 0 && memory_size > 0 && memory_size < 1024 * 1024 * 32) { // Limit to 32MB
            // Test with exact buffer size
            output_buffer = (png_byte*)malloc(memory_size);
            if (output_buffer != NULL) {
                png_alloc_size_t exact_size = memory_size;
                int exact_result = png_image_write_to_memory(&write_image, output_buffer, &exact_size,
                                                            convert_to_8bit, write_buffer.data(),
                                                            row_stride,
                                                            colormap.empty() ? NULL : colormap.data());
                (void)exact_result; // Result not used, just testing API
                free(output_buffer);
                output_buffer = NULL;
            }
            
            // Test with insufficient buffer size (edge case)
            if (memory_size > 1) {
                png_alloc_size_t small_size = memory_size / 2;
                output_buffer = (png_byte*)malloc(small_size);
                if (output_buffer != NULL) {
                    png_alloc_size_t small_result_size = small_size;
                    int small_result = png_image_write_to_memory(&write_image, output_buffer, &small_result_size,
                                                                convert_to_8bit, write_buffer.data(),
                                                                row_stride,
                                                                colormap.empty() ? NULL : colormap.data());
                    (void)small_result; // Result not used, just testing API
                    free(output_buffer);
                    output_buffer = NULL;
                }
            }
            
            // Test with larger buffer size
            png_alloc_size_t large_size = memory_size * 2;
            if (large_size < 1024 * 1024 * 64) { // Limit to 64MB
                output_buffer = (png_byte*)malloc(large_size);
                if (output_buffer != NULL) {
                    png_alloc_size_t large_result_size = large_size;
                    int large_result = png_image_write_to_memory(&write_image, output_buffer, &large_result_size,
                                                                convert_to_8bit, write_buffer.data(),
                                                                row_stride,
                                                                colormap.empty() ? NULL : colormap.data());
                    (void)large_result; // Result not used, just testing API
                    free(output_buffer);
                    output_buffer = NULL;
                }
            }
        }
    }
    
    // Clean up all resources
    if (image_buffer != NULL) {
        free(image_buffer);
    }
    
    if (output_buffer != NULL) {
        free(output_buffer);
    }
    
    if (stdio_file != NULL) {
        fclose(stdio_file);
    }
    
    if (temp_file_created) {
        unlink(temp_filename);
    }
    
    if (output_file_created) {
        unlink(output_filename);
    }
    
    // Call png_image_free for cleanup
    png_image_free(&read_image);
    png_image_free(&write_image);
    
    return 0;
}
