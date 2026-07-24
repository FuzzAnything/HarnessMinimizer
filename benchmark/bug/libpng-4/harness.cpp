#include <fuzzer/FuzzedDataProvider.h>
#include <png.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <vector>
#include <algorithm>

// Check if simplified write API is supported at compile time
#ifndef PNG_SIMPLIFIED_WRITE_SUPPORTED
#error This harness requires PNG_SIMPLIFIED_WRITE_SUPPORTED
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Need sufficient input for image parameters and pixel data
    if (size < 100) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);

    // Step 1: Choose operation mode from fuzzer input
    // 0: Write to file (using temporary file)
    // 1: Write to memory buffer
    // 2: Write to stdio (using temporary file)
    // 3: Test memory size calculation
    uint8_t operation_mode = fdp.ConsumeIntegral<uint8_t>() % 4;

    // Step 2: Initialize png_image structure for writing
    png_image image;
    memset(&image, 0, sizeof(image));
    image.version = PNG_IMAGE_VERSION;
    image.opaque = NULL;

    // Step 3: Consume image dimensions (limit to reasonable size for fuzzing)
    image.width = fdp.ConsumeIntegralInRange<png_uint_32>(1, 256);
    image.height = fdp.ConsumeIntegralInRange<png_uint_32>(1, 256);

    // Step 4: Choose image format from fuzzer input
    uint8_t format_choice = fdp.ConsumeIntegral<uint8_t>() % 12;
    png_uint_32 format = PNG_FORMAT_GRAY;
    
    switch (format_choice) {
        case 0: format = PNG_FORMAT_GRAY; break;
        case 1: format = PNG_FORMAT_GA; break;
        case 2: format = PNG_FORMAT_RGB; break;
        case 3: format = PNG_FORMAT_RGBA; break;
        case 4: format = PNG_FORMAT_BGR; break;
        case 5: format = PNG_FORMAT_BGRA; break;
        case 6: format = PNG_FORMAT_ABGR; break;
        case 7: format = PNG_FORMAT_ARGB; break;
        case 8: format = PNG_FORMAT_LINEAR_RGB; break;
        case 9: format = PNG_FORMAT_LINEAR_RGB_ALPHA; break;
        case 10: format = PNG_FORMAT_LINEAR_Y; break;
        case 11: format = PNG_FORMAT_LINEAR_Y_ALPHA; break;
    }
    
    image.format = format;

    // Step 5: Set flags based on fuzzer input
    uint8_t flag_choice = fdp.ConsumeIntegral<uint8_t>() % 4;
    switch (flag_choice) {
        case 0:
            // No additional flags
            break;
        case 1:
            // Set fast flag
            image.flags |= PNG_IMAGE_FLAG_FAST;
            break;
        case 2:
            // Set 16-bit sRGB flag if format is linear
            if (format & PNG_FORMAT_FLAG_LINEAR) {
                image.flags |= PNG_IMAGE_FLAG_16BIT_sRGB;
            }
            break;
        case 3:
            // Set non-sRGB colorspace flag for color formats
            if (format & PNG_FORMAT_FLAG_COLOR) {
                image.flags |= PNG_IMAGE_FLAG_COLORSPACE_NOT_sRGB;
            }
            break;
    }

    // Step 6: Handle colormap for colormapped formats
    void* colormap = NULL;
    image.colormap_entries = 0;
    
    if (format & PNG_FORMAT_FLAG_COLORMAP) {
        // For colormapped format, set up a simple colormap
        image.colormap_entries = fdp.ConsumeIntegralInRange<png_uint_32>(1, 256);
        
        // Allocate colormap (size depends on format)
        png_uint_32 colormap_size = PNG_IMAGE_COLORMAP_SIZE(image);
        if (colormap_size > 0 && colormap_size < 1024 * 1024) {
            colormap = malloc(colormap_size);
            if (colormap) {
                // Fill colormap with random data from fuzzer input
                size_t bytes_to_fill = std::min((size_t)colormap_size, fdp.remaining_bytes());
                if (bytes_to_fill > 0) {
                    auto colormap_data = fdp.ConsumeBytes<uint8_t>(bytes_to_fill);
                    memcpy(colormap, colormap_data.data(), bytes_to_fill);
                }
            }
        }
    }

    // Step 7: Calculate buffer size for image data
    png_uint_32 buffer_size = PNG_IMAGE_SIZE(image);
    if (buffer_size == 0 || buffer_size > 10 * 1024 * 1024) {
        // Avoid excessive memory allocation
        if (colormap) free(colormap);
        png_image_free(&image);
        return 0;
    }

    // Step 8: Allocate and fill image buffer with test patterns
    void* buffer = malloc(buffer_size);
    if (buffer == NULL) {
        if (colormap) free(colormap);
        png_image_free(&image);
        return 0;
    }

    // Fill buffer with various test patterns based on fuzzer input
    // This creates diverse image data to exercise different code paths
    size_t bytes_to_fill = std::min((size_t)buffer_size, fdp.remaining_bytes());
    if (bytes_to_fill > 0) {
        auto buffer_data = fdp.ConsumeBytes<uint8_t>(bytes_to_fill);
        memcpy(buffer, buffer_data.data(), bytes_to_fill);
        
        // Fill remaining bytes with pattern if we didn't consume all
        if (bytes_to_fill < buffer_size) {
            uint8_t* buf_ptr = static_cast<uint8_t*>(buffer);
            for (size_t i = bytes_to_fill; i < buffer_size; i++) {
                buf_ptr[i] = static_cast<uint8_t>(i % 256);
            }
        }
    } else {
        // No fuzzer data left, fill with simple pattern
        uint8_t* buf_ptr = static_cast<uint8_t*>(buffer);
        for (size_t i = 0; i < buffer_size; i++) {
            buf_ptr[i] = static_cast<uint8_t>(i % 256);
        }
    }

    // Step 9: Determine row stride (can be 0, positive, or negative for bottom-up)
    png_int_32 row_stride = 0;
    uint8_t stride_choice = fdp.ConsumeIntegral<uint8_t>() % 3;
    
    if (stride_choice == 1) {
        // Calculate proper stride
        png_uint_32 pixel_channels = 0;
        if (format & PNG_FORMAT_FLAG_COLOR) {
            pixel_channels = 3; // RGB
            if (format & PNG_FORMAT_FLAG_ALPHA) {
                pixel_channels = 4; // RGBA
            }
        } else {
            pixel_channels = 1; // Grayscale
            if (format & PNG_FORMAT_FLAG_ALPHA) {
                pixel_channels = 2; // GA
            }
        }
        
        if (format & PNG_FORMAT_FLAG_LINEAR) {
            pixel_channels *= 2; // 16-bit per component
        }
        
        row_stride = image.width * pixel_channels;
    } else if (stride_choice == 2) {
        // Negative stride for bottom-up layout
        png_uint_32 pixel_channels = 0;
        if (format & PNG_FORMAT_FLAG_COLOR) {
            pixel_channels = 3; // RGB
            if (format & PNG_FORMAT_FLAG_ALPHA) {
                pixel_channels = 4; // RGBA
            }
        } else {
            pixel_channels = 1; // Grayscale
            if (format & PNG_FORMAT_FLAG_ALPHA) {
                pixel_channels = 2; // GA
            }
        }
        
        if (format & PNG_FORMAT_FLAG_LINEAR) {
            pixel_channels *= 2; // 16-bit per component
        }
        
        row_stride = -(static_cast<png_int_32>(image.width * pixel_channels));
    }

    // Step 10: Determine convert_to_8bit flag
    int convert_to_8bit = fdp.ConsumeBool() ? 1 : 0;

    // Step 11: Execute the chosen write operation
    int write_result = 0;
    
    switch (operation_mode) {
        case 0: {
            // Write to file using png_image_write_to_file
            // Create a temporary file for writing
            char temp_filename[] = "/tmp/libpng_fuzz_XXXXXX";
            int fd = mkstemp(temp_filename);
            if (fd >= 0) {
                close(fd);
                write_result = png_image_write_to_file(&image, temp_filename, 
                                                      convert_to_8bit, buffer,
                                                      row_stride, colormap);
                // Clean up temporary file
                unlink(temp_filename);
            }
            break;
        }
        
        case 1: {
            // Write to memory using png_image_write_to_memory
            // First get required memory size
            png_alloc_size_t memory_bytes = 0;
            int size_result = png_image_write_get_memory_size(image, memory_bytes,
                                                            convert_to_8bit, buffer,
                                                            row_stride, colormap);
            
            if (size_result && memory_bytes > 0 && memory_bytes < 10 * 1024 * 1024) {
                // Allocate memory buffer and write
                void* memory_buffer = malloc(memory_bytes);
                if (memory_buffer) {
                    write_result = png_image_write_to_memory(&image, memory_buffer,
                                                           &memory_bytes, convert_to_8bit,
                                                           buffer, row_stride, colormap);
                    free(memory_buffer);
                }
            }
            break;
        }
        
        case 2: {
            // Write to stdio using png_image_write_to_stdio
            // Create a temporary file for writing
            char temp_filename[] = "/tmp/libpng_fuzz_XXXXXX";
            FILE* temp_file = NULL;
            int fd = mkstemp(temp_filename);
            if (fd >= 0) {
                temp_file = fdopen(fd, "wb");
                if (temp_file) {
                    write_result = png_image_write_to_stdio(&image, temp_file,
                                                          convert_to_8bit, buffer,
                                                          row_stride, colormap);
                    fclose(temp_file);
                } else {
                    close(fd);
                }
                // Clean up temporary file
                unlink(temp_filename);
            }
            break;
        }
        
        case 3: {
            // Test memory size calculation without actual write
            png_alloc_size_t memory_bytes = 0;
            write_result = png_image_write_get_memory_size(image, memory_bytes,
                                                         convert_to_8bit, buffer,
                                                         row_stride, colormap);
            // Result indicates if calculation succeeded
            break;
        }
    }

    // Step 12: Clean up resources
    free(buffer);
    if (colormap) {
        free(colormap);
    }
    
    // Always call png_image_free to clean up any resources allocated by libpng
    png_image_free(&image);

    return 0;
}
