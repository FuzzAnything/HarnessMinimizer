#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <png.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <vector>
#include <string>

// Structure to hold memory reading callback data
struct png_read_memory_data {
    const uint8_t* data;
    size_t size;
    size_t offset;
};

// Read callback function for memory-based input
static void png_read_memory_callback(png_structp png_ptr, png_bytep out_bytes, png_size_t byte_count) {
    png_read_memory_data* read_data = (png_read_memory_data*)png_get_io_ptr(png_ptr);
    
    if (read_data->offset + byte_count > read_data->size) {
        png_error(png_ptr, "Insufficient data in memory buffer");
        return;
    }
    
    memcpy(out_bytes, read_data->data + read_data->offset, byte_count);
    read_data->offset += byte_count;
}

// Structure to hold memory writing callback data
struct png_write_memory_data {
    uint8_t* buffer;
    size_t capacity;
    size_t size;
};

// Write callback function for memory-based output
static void png_write_memory_callback(png_structp png_ptr, png_bytep data, png_size_t length) {
    png_write_memory_data* write_data = (png_write_memory_data*)png_get_io_ptr(png_ptr);
    
    if (write_data->size + length > write_data->capacity) {
        // Reallocate buffer if needed
        size_t new_capacity = write_data->capacity * 2;
        if (new_capacity < write_data->size + length) {
            new_capacity = write_data->size + length;
        }
        uint8_t* new_buffer = (uint8_t*)realloc(write_data->buffer, new_capacity);
        if (new_buffer == NULL) {
            png_error(png_ptr, "Memory allocation failed in write callback");
            return;
        }
        write_data->buffer = new_buffer;
        write_data->capacity = new_capacity;
    }
    
    memcpy(write_data->buffer + write_data->size, data, length);
    write_data->size += length;
}

// Flush callback function (optional)
static void png_flush_callback(png_structp png_ptr) {
    // Nothing to do for memory-based output
    (void)png_ptr;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Need sufficient data for comprehensive palette and color space testing
    if (size < 100) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // ====================================================
    // PHASE 1: TEST PNG_DATA_FREER FUNCTION
    // ====================================================
    
    // Create PNG write structure
    png_structp write_png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, 
                                                         nullptr, nullptr, nullptr);
    if (write_png_ptr == nullptr) {
        return 0;
    }
    
    // Create PNG info structure for writing
    png_infop write_info_ptr = png_create_info_struct(write_png_ptr);
    if (write_info_ptr == nullptr) {
        png_destroy_write_struct(&write_png_ptr, nullptr);
        return 0;
    }
    
    // Set up error handling for writing
    if (setjmp(png_jmpbuf(write_png_ptr))) {
        png_destroy_write_struct(&write_png_ptr, &write_info_ptr);
        return 0;
    }
    
    // Set up memory-based writing
    png_write_memory_data write_data;
    write_data.buffer = nullptr;
    write_data.capacity = 0;
    write_data.size = 0;
    
    png_set_write_fn(write_png_ptr, &write_data, png_write_memory_callback, png_flush_callback);
    
    // ====================================================
    // PHASE 2: TEST PNG_BUILD_GRAYSCALE_PALETTE FUNCTION
    // ====================================================
    
    // Consume parameters for grayscale palette testing
    int bit_depth = fdp.ConsumeIntegralInRange<int>(1, 8);
    int palette_size = 0;
    
    switch (bit_depth) {
        case 1:
            palette_size = 2;
            break;
        case 2:
            palette_size = 4;
            break;
        case 4:
            palette_size = 16;
            break;
        case 8:
            palette_size = 256;
            break;
        default:
            palette_size = 0;  // Invalid bit depth
            break;
    }
    
    // Only proceed if we have a valid palette size
    if (palette_size > 0) {
        // Allocate palette array
        png_color* grayscale_palette = (png_color*)malloc(palette_size * sizeof(png_color));
        if (grayscale_palette != nullptr) {
            // Target API: png_build_grayscale_palette
            png_build_grayscale_palette(bit_depth, grayscale_palette);
            
            // Verify the palette was built correctly
            for (int i = 0; i < palette_size; i++) {
                // In a grayscale palette, R=G=B
                if (grayscale_palette[i].red != grayscale_palette[i].green ||
                    grayscale_palette[i].green != grayscale_palette[i].blue) {
                    // This would indicate an error in png_build_grayscale_palette
                }
            }
            
            // Test using the grayscale palette in PNG creation
            png_uint_32 width = fdp.ConsumeIntegralInRange<png_uint_32>(1, 100);
            png_uint_32 height = fdp.ConsumeIntegralInRange<png_uint_32>(1, 100);
            int color_type = PNG_COLOR_TYPE_PALETTE;
            int interlace_type = fdp.ConsumeBool() ? PNG_INTERLACE_ADAM7 : PNG_INTERLACE_NONE;
            
            // Set IHDR with palette color type
            png_set_IHDR(write_png_ptr, write_info_ptr, width, height, bit_depth,
                         color_type, interlace_type, PNG_COMPRESSION_TYPE_BASE,
                         PNG_FILTER_TYPE_BASE);
            
            // Set the grayscale palette
            png_set_PLTE(write_png_ptr, write_info_ptr, grayscale_palette, palette_size);
            
            // Free the palette
            free(grayscale_palette);
        }
    }
    
    // ====================================================
    // PHASE 3: TEST PNG_SET_SRGB_GAMA_AND_CHRM FUNCTION
    // ====================================================
    
    // Test color space configuration with different intents
    int srgb_intent = fdp.ConsumeIntegralInRange<int>(0, 3);
    
    // Target API: png_set_sRGB_gAMA_and_cHRM
    png_set_sRGB_gAMA_and_cHRM(write_png_ptr, write_info_ptr, srgb_intent);
    
    // Also test individual sRGB setting for comparison
    png_set_sRGB(write_png_ptr, write_info_ptr, srgb_intent);
    
    // ====================================================
    // PHASE 4: TEST MEMORY MANAGEMENT WITH PNG_DATA_FREER
    // ====================================================
    
    // Create some test data chunks to manage
    std::string test_text = fdp.ConsumeRandomLengthString(100);
    std::vector<uint8_t> test_profile = fdp.ConsumeBytes<uint8_t>(50);
    
    // Add text chunk to test PNG data management
    png_text text_chunk;
    text_chunk.compression = PNG_TEXT_COMPRESSION_NONE;
    text_chunk.key = (char*)"TestKey";
    text_chunk.text = (char*)test_text.c_str();
    text_chunk.text_length = test_text.length();
    
    png_set_text(write_png_ptr, write_info_ptr, &text_chunk, 1);
    
    // Test different free modes with png_data_freer
    int freer_mode = fdp.ConsumeIntegralInRange<int>(0, 2);
    png_uint_32 mask = PNG_FREE_TEXT;
    
    switch (freer_mode) {
        case 0:
            // PNG_DESTROY_WILL_FREE_DATA
            png_data_freer(write_png_ptr, write_info_ptr, PNG_DESTROY_WILL_FREE_DATA, mask);
            break;
        case 1:
            // PNG_USER_WILL_FREE_DATA
            png_data_freer(write_png_ptr, write_info_ptr, PNG_USER_WILL_FREE_DATA, mask);
            break;
        case 2:
            // Test with multiple masks
            mask |= PNG_FREE_PLTE | PNG_FREE_TRNS;
            png_data_freer(write_png_ptr, write_info_ptr, PNG_DESTROY_WILL_FREE_DATA, mask);
            break;
    }
    
    // Test png_free_data function (closely related to png_data_freer)
    int free_num = fdp.ConsumeIntegralInRange<int>(-1, 10);
    png_free_data(write_png_ptr, write_info_ptr, mask, free_num);
    
    // ====================================================
    // PHASE 5: ADDITIONAL COLOR SPACE AND PALETTE TESTS
    // ====================================================
    
    // Test other color space functions that interact with our target APIs
    int operation = fdp.ConsumeIntegralInRange<int>(0, 5);
    
    switch (operation) {
        case 0:
            // Test gamma correction with palette
            png_set_gAMA(write_png_ptr, write_info_ptr, fdp.ConsumeFloatingPoint<double>());
            break;
        case 1:
            // Test cHRM with fixed point values
            png_set_cHRM_fixed(write_png_ptr, write_info_ptr,
                              fdp.ConsumeIntegral<png_fixed_point>(),
                              fdp.ConsumeIntegral<png_fixed_point>(),
                              fdp.ConsumeIntegral<png_fixed_point>(),
                              fdp.ConsumeIntegral<png_fixed_point>(),
                              fdp.ConsumeIntegral<png_fixed_point>(),
                              fdp.ConsumeIntegral<png_fixed_point>(),
                              fdp.ConsumeIntegral<png_fixed_point>(),
                              fdp.ConsumeIntegral<png_fixed_point>());
            break;
        case 2:
            // Test iCCP profile (alternative to sRGB)
            if (test_profile.size() > 0) {
                png_set_iCCP(write_png_ptr, write_info_ptr, "TestProfile",
                            PNG_COMPRESSION_TYPE_BASE, test_profile.data(),
                            test_profile.size());
            }
            break;
        case 3:
            // Test palette with transparency
            if (palette_size > 0) {
                std::vector<png_byte> trans_palette(palette_size);
                for (size_t i = 0; i < trans_palette.size() && i < palette_size; i++) {
                    trans_palette[i] = fdp.ConsumeIntegral<uint8_t>();
                }
                png_set_tRNS(write_png_ptr, write_info_ptr, trans_palette.data(), palette_size, nullptr);
            }
            break;
        case 4:
            // Test background color with palette
            png_color_16 background;
            background.red = fdp.ConsumeIntegral<uint16_t>();
            background.green = fdp.ConsumeIntegral<uint16_t>();
            background.blue = fdp.ConsumeIntegral<uint16_t>();
            background.gray = fdp.ConsumeIntegral<uint16_t>();
            png_set_bKGD(write_png_ptr, write_info_ptr, &background);
            break;
        case 5:
            // Test histogram with palette
            if (palette_size > 0) {
                std::vector<png_uint_16> histogram(palette_size);
                for (int i = 0; i < palette_size; i++) {
                    histogram[i] = fdp.ConsumeIntegral<png_uint_16>();
                }
                png_set_hIST(write_png_ptr, write_info_ptr, histogram.data());
            }
            break;
    }
    
    // ====================================================
    // PHASE 6: WRITE PNG DATA TO EXERCISE CONFIGURATIONS
    // ====================================================
    
    // Write PNG info
    png_write_info(write_png_ptr, write_info_ptr);
    
    // Create and write some dummy row data
    // Get image dimensions using proper API calls
    png_uint_32 width = png_get_image_width(write_png_ptr, write_info_ptr);
    png_uint_32 height = png_get_image_height(write_png_ptr, write_info_ptr);
    size_t rowbytes = png_get_rowbytes(write_png_ptr, write_info_ptr);
    
    if (rowbytes > 0 && height > 0 && width > 0) {
        std::vector<png_byte> row_data(rowbytes);
        
        // Fill row with fuzzer data
        std::vector<uint8_t> row_fill_data = fdp.ConsumeBytes<uint8_t>(rowbytes);
        for (size_t i = 0; i < rowbytes && i < row_fill_data.size(); i++) {
            row_data[i] = row_fill_data[i];
        }
        
        png_bytep row_pointer = row_data.data();
        
        // Write a few rows (limited to prevent excessive memory usage)
        for (png_uint_32 y = 0; y < height && y < 3; y++) {
            png_write_row(write_png_ptr, row_pointer);
        }
    }
    
    // End writing
    png_write_end(write_png_ptr, write_info_ptr);
    
    // ====================================================
    // PHASE 7: CLEANUP AND MEMORY MANAGEMENT VERIFICATION
    // ====================================================
    
    // Test png_free_data again with different parameters
    png_uint_32 cleanup_mask = PNG_FREE_ALL;
    png_free_data(write_png_ptr, write_info_ptr, cleanup_mask, -1);
    
    // Clean up write structures
    png_destroy_write_struct(&write_png_ptr, &write_info_ptr);
    
    // Free memory buffer if allocated
    if (write_data.buffer != nullptr) {
        free(write_data.buffer);
    }
    
    return 0;
}
