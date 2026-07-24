/* Fuzzing harness for libpng simplified PNG image writing operations
 * Targets simplified PNG image writing APIs with 193+ undiscovered branches:
 * - png_image_write_to_file (Primary Target - 79 undiscovered branches)
 * - png_image_write_to_stdio (Primary Target - 59 undiscovered branches)  
 * - png_image_write_to_memory (Secondary Target - 55 undiscovered branches)
 * - png_image_free (Required Helper - Cleanup)
 * 
 * Differentiates from harness_001.cpp (memory-based simplified API) and 
 * harness_011.cpp (file/stdio with traditional APIs) by focusing exclusively
 * on synthetic image data generation and simplified write API variations.
 * 
 * Invocation sequence:
 * 1. Initialize png_image structure with various image formats and dimensions
 * 2. Generate synthetic image buffer data matching the format
 * 3. Test png_image_write_to_file with temporary file
 * 4. Test png_image_write_to_stdio with FILE* stream  
 * 5. Test png_image_write_to_memory with allocated buffer
 * 6. Always call png_image_free for cleanup
 * 
 * Uses FuzzedDataProvider to split input for:
 * - Image format and dimension selection
 * - Write operation flags (convert_to_8bit)
 * - Synthetic image data generation
 * - Memory buffer sizing for write_to_memory
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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Need sufficient data for comprehensive image configuration and testing
    if (size < 128) {
        return 0;  // Need minimum for image configuration
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Declare all resources that need cleanup
    png_image image;
    png_byte* image_buffer = NULL;
    png_alloc_size_t memory_size = 0;
    png_byte* output_buffer = NULL;
    char temp_filename[] = "/tmp/libpng_write_XXXXXX";
    char stdio_filename[] = "/tmp/libpng_stdio_XXXXXX";
    int temp_fd = -1;
    int stdio_fd = -1;
    FILE* stdio_file = NULL;
    bool temp_file_created = false;
    bool stdio_file_created = false;
    
    memset(&image, 0, sizeof(image));
    image.version = PNG_IMAGE_VERSION;
    
    // ============================================
    // PHASE 1: Image Configuration
    // ============================================
    
    // Consume image dimensions (keep reasonable to prevent excessive memory)
    image.width = fdp.ConsumeIntegralInRange<png_uint_32>(1, 512);
    image.height = fdp.ConsumeIntegralInRange<png_uint_32>(1, 512);
    
    // Consume image format from fuzzer input
    uint32_t format_selector = fdp.ConsumeIntegral<uint32_t>() % 8;
    switch (format_selector) {
        case 0:
            image.format = PNG_FORMAT_RGB;
            break;
        case 1:
            image.format = PNG_FORMAT_RGBA;
            break;
        case 2:
            image.format = PNG_FORMAT_GRAY;
            break;
        case 3:
            image.format = PNG_FORMAT_GA;
            break;
        case 4:
            image.format = PNG_FORMAT_LINEAR_RGB;
            break;
        case 5:
            image.format = PNG_FORMAT_LINEAR_RGB_ALPHA;
            break;
        case 6:
            // Test with colormap format
            image.format = PNG_FORMAT_RGB_COLORMAP;
            image.colormap_entries = fdp.ConsumeIntegralInRange<uint32_t>(1, 256);
            break;
        case 7:
            // Test with linear grayscale
            image.format = PNG_FORMAT_LINEAR_Y;
            break;
    }
    
    // Consume flags
    image.flags = 0;
    if (fdp.ConsumeBool()) {
        image.flags |= PNG_IMAGE_FLAG_COLORSPACE_NOT_sRGB;
    }
    
    // ============================================
    // PHASE 2: Image Buffer Preparation
    // ============================================
    
    // Calculate required buffer size for the image
    png_uint_32 image_size = PNG_IMAGE_SIZE(image);
    
    // Prevent excessive memory allocation
    if (image_size == 0 || image_size > 10000000) {
        return 0;
    }
    
    // Allocate image buffer
    image_buffer = (png_byte*)malloc(image_size);
    if (image_buffer == NULL) {
        return 0;
    }
    
    // Fill buffer with synthetic data from fuzzer input
    // We'll use the remaining fuzzer input as image data
    size_t remaining_bytes = fdp.remaining_bytes();
    if (remaining_bytes < image_size) {
        // Not enough data, fill with pattern
        for (png_uint_32 i = 0; i < image_size; i++) {
            image_buffer[i] = (i % 256);
        }
    } else {
        // Use fuzzer data for image content
        std::vector<uint8_t> image_data = fdp.ConsumeBytes<uint8_t>(image_size);
        memcpy(image_buffer, image_data.data(), image_size);
    }
    
    // For colormap formats, we need to allocate and fill colormap
    png_color* colormap = NULL;
    if (image.format == PNG_FORMAT_RGB_COLORMAP || 
        image.format == PNG_FORMAT_RGBA_COLORMAP) {
        if (image.colormap_entries > 0 && image.colormap_entries <= 256) {
            size_t colormap_size = image.colormap_entries * sizeof(png_color);
            colormap = (png_color*)malloc(colormap_size);
            if (colormap != NULL) {
                // Fill colormap with synthetic data
                for (uint32_t i = 0; i < image.colormap_entries; i++) {
                    colormap[i].red = (i * 37) % 256;
                    colormap[i].green = (i * 73) % 256;
                    colormap[i].blue = (i * 109) % 256;
                }
            }
        }
    }
    
    // Consume operation flags
    int convert_to_8bit = fdp.ConsumeBool() ? 1 : 0;
    
    // ============================================
    // PHASE 3: File-based Writing (png_image_write_to_file)
    // ============================================
    
    // Create temporary file for writing
    temp_fd = mkstemp(temp_filename);
    if (temp_fd >= 0) {
        temp_file_created = true;
        close(temp_fd);
        temp_fd = -1;
        
        // Test png_image_write_to_file
        png_image_write_to_file(&image, temp_filename, convert_to_8bit, 
                               image_buffer, 0, colormap);
    }
    
    // ============================================
    // PHASE 4: Stdio-based Writing (png_image_write_to_stdio)
    // ============================================
    
    // Create another temporary file for stdio writing
    stdio_fd = mkstemp(stdio_filename);
    if (stdio_fd >= 0) {
        stdio_file_created = true;
        close(stdio_fd);
        stdio_fd = -1;
        
        // Open as FILE* for stdio writing
        stdio_file = fopen(stdio_filename, "wb");
        if (stdio_file != NULL) {
            // Test png_image_write_to_stdio
            png_image_write_to_stdio(&image, stdio_file, convert_to_8bit,
                                    image_buffer, 0, colormap);
            
            fclose(stdio_file);
            stdio_file = NULL;
        }
    }
    
    // ============================================
    // PHASE 5: Memory-based Writing (png_image_write_to_memory)
    // ============================================
    
    // First, get the required memory size
    memory_size = 0;
    int size_result = png_image_write_to_memory(&image, NULL, &memory_size,
                                               convert_to_8bit, image_buffer,
                                               0, colormap);
    
    if (size_result != 0 && memory_size > 0 && memory_size < 10000000) {
        // Allocate buffer for memory writing
        output_buffer = (png_byte*)malloc(memory_size);
        if (output_buffer != NULL) {
            // Test actual memory writing
            png_alloc_size_t actual_size = memory_size;
            png_image_write_to_memory(&image, output_buffer, &actual_size,
                                     convert_to_8bit, image_buffer,
                                     0, colormap);
            
            free(output_buffer);
            output_buffer = NULL;
        }
    }
    
    // Test with negative row stride (bottom-up layout)
    if (image.height > 1) {
        png_int_32 negative_stride = -((png_int_32)(PNG_IMAGE_ROW_STRIDE(image)));
        png_image_write_to_memory(&image, NULL, &memory_size,
                                 convert_to_8bit, image_buffer,
                                 negative_stride, colormap);
    }
    
    // ============================================
    // PHASE 6: Error Path Testing
    // ============================================
    
    // Test with invalid parameters to exercise error handling
    
    // Test with NULL image pointer
    if (fdp.ConsumeBool()) {
        png_image_write_to_memory(NULL, NULL, &memory_size,
                                 convert_to_8bit, image_buffer,
                                 0, colormap);
    }
    
    // Test with invalid image version
    if (fdp.ConsumeBool()) {
        png_image bad_image = image;
        bad_image.version = 0;  // Invalid version
        png_image_write_to_memory(&bad_image, NULL, &memory_size,
                                 convert_to_8bit, image_buffer,
                                 0, colormap);
    }
    
    // Test with zero dimensions
    if (fdp.ConsumeBool()) {
        png_image zero_image = image;
        zero_image.width = 0;
        png_image_write_to_memory(&zero_image, NULL, &memory_size,
                                 convert_to_8bit, image_buffer,
                                 0, colormap);
    }
    
    // ============================================
    // PHASE 7: Cleanup
    // ============================================
    
    // Clean up colormap if allocated
    if (colormap != NULL) {
        free(colormap);
        colormap = NULL;
    }
    
    // Clean up image structure
    if (image.version == PNG_IMAGE_VERSION) {
        png_image_free(&image);
    }
    
    // Free image buffer
    if (image_buffer != NULL) {
        free(image_buffer);
        image_buffer = NULL;
    }
    
    // Clean up temporary files
    if (temp_file_created) {
        unlink(temp_filename);
    }
    
    if (stdio_file_created) {
        unlink(stdio_filename);
    }
    
    return 0;
}
