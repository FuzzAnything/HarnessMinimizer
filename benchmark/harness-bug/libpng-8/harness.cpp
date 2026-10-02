/* Fuzzing harness for libpng complete file-based PNG image lifecycle operations
 * Targets png_image_* API cluster with 262+ undiscovered branches across file I/O operations:
 * - png_image_write_to_file (Target: 20 branches, 79 undiscovered)
 * - png_image_write_to_stdio (Target: 12 branches, 59 undiscovered)  
 * - png_image_begin_read_from_file (Target: 12 branches, 63 undiscovered)
 * - png_image_begin_read_from_stdio (Target: 10 branches, 61 undiscovered)
 * - png_image_finish_read (Required Helper: 36 branches, 51 undiscovered)
 * 
 * Required Helper APIs:
 * - png_image_free (Required Helper: Cleanup)
 * - png_create_read_struct (Required Helper: Initialization for reading)
 * - png_create_write_struct (Required Helper: Initialization for writing)
 * - png_create_info_struct (Required Helper: Info struct creation)
 * - png_destroy_read_struct (Required Helper: Cleanup)
 * - png_destroy_write_struct (Required Helper: Cleanup)
 * - png_destroy_info_struct (Required Helper: Cleanup)
 *
 * Differentiates from existing harnesses:
 * - harness_009.cpp: Focuses on traditional PNG reading APIs with file/stdio
 * - harness_011.cpp: Covers file/stdio interfaces but mixes traditional and simplified APIs  
 * - harness_012.cpp: Focuses on simplified PNG image writing with synthetic data
 *
 * This harness focuses EXCLUSIVELY on the complete file-based PNG lifecycle using
 * the simplified png_image_* API cluster: read from file → process → write to file.
 *
 * Invocation sequence:
 * 1. Create temporary PNG file from fuzzer input
 * 2. Initialize png_image structure for reading
 * 3. Call png_image_begin_read_from_file to start reading
 * 4. Call png_image_finish_read to complete reading into buffer
 * 5. Optionally modify image data or format
 * 6. Initialize png_image structure for writing
 * 7. Call png_image_write_to_file or png_image_write_to_stdio to write image
 * 8. Clean up all resources with png_image_free and destroy structs
 *
 * Uses FuzzedDataProvider to split input for:
 * - PNG image data for initial file
 * - Image format selection for reading/writing
 * - Operation selection (read-only, write-only, complete lifecycle)
 * - Write flags (convert_to_8bit, row_stride variations)
 * - Background color for alpha compositing
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "png.h"

// Error handling callback functions for traditional PNG APIs
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
static std::string create_temp_file(const uint8_t* data, size_t size, const char* template_str) {
    char temp_filename[64];
    strncpy(temp_filename, template_str, sizeof(temp_filename));
    temp_filename[sizeof(temp_filename)-1] = '\0';
    
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
        bytes_per_pixel = 1; // Color-mapped: 1 byte per pixel
    } else if (image.format & PNG_FORMAT_FLAG_LINEAR) {
        // Linear formats: 2 bytes per component
        if (image.format & PNG_FORMAT_FLAG_ALPHA) {
            bytes_per_pixel = (image.format & PNG_FORMAT_FLAG_COLOR) ? 8 : 4; // RGBA: 8, GA: 4
        } else {
            bytes_per_pixel = (image.format & PNG_FORMAT_FLAG_COLOR) ? 6 : 2; // RGB: 6, GRAY: 2
        }
    } else {
        // Standard 8-bit formats: 1 byte per component
        if (image.format & PNG_FORMAT_FLAG_ALPHA) {
            bytes_per_pixel = (image.format & PNG_FORMAT_FLAG_COLOR) ? 4 : 2; // RGBA: 4, GA: 2
        } else {
            bytes_per_pixel = (image.format & PNG_FORMAT_FLAG_COLOR) ? 3 : 1; // RGB: 3, GRAY: 1
        }
    }
    
    return static_cast<size_t>(image.width) * static_cast<size_t>(image.height) * bytes_per_pixel;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Need sufficient data for comprehensive file-based PNG lifecycle testing
    // Minimum: PNG header (8 bytes) + basic configuration
    if (size < 128) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Declare all resources that need cleanup
    png_structp read_ptr = NULL;
    png_infop read_info_ptr = NULL;
    png_structp write_ptr = NULL;
    png_infop write_info_ptr = NULL;
    png_image read_image;
    png_image write_image;
    void* image_buffer = NULL;
    void* colormap_buffer = NULL;
    std::string input_filename;
    std::string output_filename;
    std::string stdio_filename;
    FILE* stdio_file = NULL;
    bool input_file_created = false;
    bool output_file_created = false;
    bool stdio_file_created = false;
    uint8_t operation = 0;
    
    // Initialize png_image structures
    memset(&read_image, 0, sizeof(read_image));
    memset(&write_image, 0, sizeof(write_image));
    read_image.version = PNG_IMAGE_VERSION;
    write_image.version = PNG_IMAGE_VERSION;
    
    // ============================================
    // PHASE 1: Create temporary PNG input file
    // ============================================
    
    // Consume portion of input for PNG file data
    size_t png_data_size = fdp.ConsumeIntegralInRange<size_t>(8, fdp.remaining_bytes() / 2);
    std::vector<uint8_t> png_data = fdp.ConsumeBytes<uint8_t>(png_data_size);
    
    if (png_data.size() < 8) {
        return 0; // Need at least PNG signature
    }
    
    // Create temporary input file with PNG data
    input_filename = create_temp_file(png_data.data(), png_data.size(), "/tmp/libpng_in_XXXXXX");
    if (input_filename.empty()) {
        return 0;
    }
    input_file_created = true;
    
    // ============================================
    // PHASE 2: Initialize traditional PNG structs
    // ============================================
    
    // Initialize read structure (even for simplified API, guidance mentions these)
    read_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, pngtest_error, pngtest_warning);
    if (!read_ptr) {
        goto cleanup;
    }
    
    read_info_ptr = png_create_info_struct(read_ptr);
    if (!read_info_ptr) {
        goto cleanup;
    }
    
    // Initialize write structure
    write_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, pngtest_error, pngtest_warning);
    if (!write_ptr) {
        goto cleanup;
    }
    
    write_info_ptr = png_create_info_struct(write_ptr);
    if (!write_info_ptr) {
        goto cleanup;
    }
    
    // ============================================
    // PHASE 3: File-based PNG reading using simplified API
    // ============================================
    
    // Consume operation selector from fuzzer input
    operation = fdp.ConsumeIntegral<uint8_t>() % 4;
    
    if (operation == 0 || operation == 2) {
        // Operations involving reading: 0=read-only, 2=complete lifecycle
        
        // Consume format flags for reading
        uint8_t format_selector = fdp.ConsumeIntegral<uint8_t>() % 8;
        switch (format_selector) {
            case 0:
                read_image.format = PNG_FORMAT_RGB;
                break;
            case 1:
                read_image.format = PNG_FORMAT_RGBA;
                break;
            case 2:
                read_image.format = PNG_FORMAT_GRAY;
                break;
            case 3:
                read_image.format = PNG_FORMAT_GA;
                break;
            case 4:
                read_image.format = PNG_FORMAT_LINEAR_RGB;
                break;
            case 5:
                read_image.format = PNG_FORMAT_LINEAR_RGB_ALPHA;
                break;
            case 6:
                read_image.format = PNG_FORMAT_RGB_COLORMAP;
                read_image.colormap_entries = fdp.ConsumeIntegralInRange<uint32_t>(1, 256);
                break;
            case 7:
                read_image.format = PNG_FORMAT_LINEAR_Y;
                break;
        }
        
        // Test png_image_begin_read_from_file
        if (png_image_begin_read_from_file(&read_image, input_filename.c_str()) == 0) {
            // If begin_read fails, we can still test write operations with synthetic data
            // Reset image structure for synthetic data generation
            memset(&read_image, 0, sizeof(read_image));
            read_image.version = PNG_IMAGE_VERSION;
            read_image.width = fdp.ConsumeIntegralInRange<png_uint_32>(1, 512);
            read_image.height = fdp.ConsumeIntegralInRange<png_uint_32>(1, 512);
            read_image.format = PNG_FORMAT_RGB; // Default format for synthetic data
        }
        
        // If we successfully began reading, allocate buffer and finish read
        if (read_image.width > 0 && read_image.height > 0) {
            size_t buffer_size = calculate_image_buffer_size(read_image);
            if (buffer_size > 0 && buffer_size < 1024 * 1024 * 10) { // Limit to 10MB
                image_buffer = malloc(buffer_size);
                if (image_buffer) {
                    // Consume background color for alpha compositing
                    png_color background;
                    background.red = fdp.ConsumeIntegral<uint8_t>();
                    background.green = fdp.ConsumeIntegral<uint8_t>();
                    background.blue = fdp.ConsumeIntegral<uint8_t>();
                    
                    // Consume row stride (positive = top-down, negative = bottom-up, 0 = auto)
                    png_int_32 row_stride = 0;
                    uint8_t stride_selector = fdp.ConsumeIntegral<uint8_t>() % 3;
                    if (stride_selector == 1) {
                        row_stride = fdp.ConsumeIntegralInRange<png_int_32>(1, 1000);
                    } else if (stride_selector == 2) {
                        row_stride = fdp.ConsumeIntegralInRange<png_int_32>(-1000, -1);
                    }
                    
                    // Allocate colormap if needed
                    if (read_image.format & PNG_FORMAT_FLAG_COLORMAP && read_image.colormap_entries > 0) {
                        size_t colormap_size = PNG_IMAGE_COLORMAP_SIZE(read_image);
                        colormap_buffer = malloc(colormap_size);
                    }
                    
                    // Test png_image_finish_read
                    png_image_finish_read(&read_image, &background, image_buffer, row_stride, colormap_buffer);
                }
            }
        }
    }
    
    // ============================================
    // PHASE 4: File-based PNG writing using simplified API
    // ============================================
    
    if (operation == 1 || operation == 2 || operation == 3) {
        // Operations involving writing: 1=write-only, 2=complete lifecycle, 3=stdio-only
        
        // Configure write image
        if (operation == 2 && read_image.width > 0 && read_image.height > 0) {
            // Complete lifecycle: use read image dimensions and format
            write_image.width = read_image.width;
            write_image.height = read_image.height;
            write_image.format = read_image.format;
            write_image.colormap_entries = read_image.colormap_entries;
        } else {
            // Write-only or stdio-only: generate synthetic image
            write_image.width = fdp.ConsumeIntegralInRange<png_uint_32>(1, 512);
            write_image.height = fdp.ConsumeIntegralInRange<png_uint_32>(1, 512);
            
            uint8_t write_format = fdp.ConsumeIntegral<uint8_t>() % 8;
            switch (write_format) {
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
                    write_image.format = PNG_FORMAT_RGB_COLORMAP;
                    write_image.colormap_entries = fdp.ConsumeIntegralInRange<uint32_t>(1, 256);
                    break;
                case 7:
                    write_image.format = PNG_FORMAT_LINEAR_Y;
                    break;
            }
            
            // Allocate image buffer for synthetic data
            size_t write_buffer_size = calculate_image_buffer_size(write_image);
            if (write_buffer_size > 0 && write_buffer_size < 1024 * 1024 * 10) {
                if (image_buffer) {
                    free(image_buffer);
                }
                image_buffer = malloc(write_buffer_size);
                if (image_buffer) {
                    // Fill with random data from fuzzer
                    std::vector<uint8_t> synthetic_data = fdp.ConsumeBytes<uint8_t>(
                        std::min(write_buffer_size, fdp.remaining_bytes()));
                    memcpy(image_buffer, synthetic_data.data(), 
                           std::min(synthetic_data.size(), write_buffer_size));
                    
                    // Fill remaining with pattern if needed
                    if (synthetic_data.size() < write_buffer_size) {
                        memset(static_cast<uint8_t*>(image_buffer) + synthetic_data.size(), 
                               0xAA, write_buffer_size - synthetic_data.size());
                    }
                }
            }
        }
        
        // Consume write parameters
        int convert_to_8bit = fdp.ConsumeBool() ? 1 : 0;
        png_int_32 write_row_stride = 0;
        uint8_t write_stride_selector = fdp.ConsumeIntegral<uint8_t>() % 3;
        if (write_stride_selector == 1) {
            write_row_stride = fdp.ConsumeIntegralInRange<png_int_32>(1, 1000);
        } else if (write_stride_selector == 2) {
            write_row_stride = fdp.ConsumeIntegralInRange<png_int_32>(-1000, -1);
        }
        
        if (operation == 1 || operation == 2) {
            // Test png_image_write_to_file
            
            // Create temporary output file
            output_filename = create_temp_file(nullptr, 0, "/tmp/libpng_out_XXXXXX");
            if (!output_filename.empty()) {
                output_file_created = true;
                
                if (image_buffer && write_image.width > 0 && write_image.height > 0) {
                    // Allocate colormap if needed
                    void* write_colormap = NULL;
                    if (write_image.format & PNG_FORMAT_FLAG_COLORMAP && write_image.colormap_entries > 0) {
                        size_t colormap_size = PNG_IMAGE_COLORMAP_SIZE(write_image);
                        write_colormap = malloc(colormap_size);
                        if (write_colormap) {
                            // Fill colormap with random data
                            std::vector<uint8_t> colormap_data = fdp.ConsumeBytes<uint8_t>(
                                std::min(colormap_size, fdp.remaining_bytes()));
                            memcpy(write_colormap, colormap_data.data(),
                                   std::min(colormap_data.size(), colormap_size));
                        }
                    }
                    
                    png_image_write_to_file(&write_image, output_filename.c_str(), 
                                           convert_to_8bit, image_buffer, 
                                           write_row_stride, write_colormap);
                    
                    if (write_colormap) {
                        free(write_colormap);
                    }
                }
            }
        }
        
        if (operation == 3) {
            // Test png_image_write_to_stdio
            
            // Create temporary file for stdio
            stdio_filename = create_temp_file(nullptr, 0, "/tmp/libpng_stdio_XXXXXX");
            if (!stdio_filename.empty()) {
                stdio_file_created = true;
                stdio_file = fopen(stdio_filename.c_str(), "wb");
                
                if (stdio_file && image_buffer && write_image.width > 0 && write_image.height > 0) {
                    // Allocate colormap if needed
                    void* write_colormap = NULL;
                    if (write_image.format & PNG_FORMAT_FLAG_COLORMAP && write_image.colormap_entries > 0) {
                        size_t colormap_size = PNG_IMAGE_COLORMAP_SIZE(write_image);
                        write_colormap = malloc(colormap_size);
                        if (write_colormap) {
                            // Fill colormap with random data
                            std::vector<uint8_t> colormap_data = fdp.ConsumeBytes<uint8_t>(
                                std::min(colormap_size, fdp.remaining_bytes()));
                            memcpy(write_colormap, colormap_data.data(),
                                   std::min(colormap_data.size(), colormap_size));
                        }
                    }
                    
                    png_image_write_to_stdio(&write_image, stdio_file,
                                            convert_to_8bit, image_buffer,
                                            write_row_stride, write_colormap);
                    
                    if (write_colormap) {
                        free(write_colormap);
                    }
                }
            }
        }
    }
    
    // ============================================
    // PHASE 5: Test png_image_begin_read_from_stdio
    // ============================================
    
    // If we have a stdio file from write operation, try reading from it
    if (stdio_file && operation == 3) {
        // Reset file pointer to beginning
        fclose(stdio_file);
        stdio_file = fopen(stdio_filename.c_str(), "rb");
        
        if (stdio_file) {
            png_image stdio_read_image;
            memset(&stdio_read_image, 0, sizeof(stdio_read_image));
            stdio_read_image.version = PNG_IMAGE_VERSION;
            stdio_read_image.format = PNG_FORMAT_RGB;
            
            // Test png_image_begin_read_from_stdio
            png_image_begin_read_from_stdio(&stdio_read_image, stdio_file);
            
            // Clean up stdio read image
            png_image_free(&stdio_read_image);
            fclose(stdio_file);
            stdio_file = NULL;
        }
    }
    
cleanup:
    // ============================================
    // PHASE 6: Cleanup
    // ============================================
    
    // Free png_image resources
    png_image_free(&read_image);
    png_image_free(&write_image);
    
    // Free allocated buffers
    if (image_buffer) {
        free(image_buffer);
    }
    if (colormap_buffer) {
        free(colormap_buffer);
    }
    
    // Destroy traditional PNG structs
    if (write_info_ptr) {
        png_destroy_info_struct(write_ptr, &write_info_ptr);
    }
    if (write_ptr) {
        png_destroy_write_struct(&write_ptr, NULL);
    }
    if (read_info_ptr) {
        png_destroy_info_struct(read_ptr, &read_info_ptr);
    }
    if (read_ptr) {
        png_destroy_read_struct(&read_ptr, NULL, NULL);
    }
    
    // Close stdio file if still open
    if (stdio_file) {
        fclose(stdio_file);
    }
    
    // Clean up temporary files
    if (input_file_created && !input_filename.empty()) {
        unlink(input_filename.c_str());
    }
    if (output_file_created && !output_filename.empty()) {
        unlink(output_filename.c_str());
    }
    if (stdio_file_created && !stdio_filename.empty()) {
        unlink(stdio_filename.c_str());
    }
    
    return 0;
}
