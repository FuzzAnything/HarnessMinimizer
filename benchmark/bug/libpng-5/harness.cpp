/* Harness for fuzzing libpng basic PNG parsing operations
 * Targets core PNG reading APIs: png_create_read_struct, png_read_info,
 * png_read_end, png_destroy_read_struct
 */

#include <fuzzer/FuzzedDataProvider.h>
#include <png.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

// Custom I/O structure for reading from memory buffer
struct png_memory_reader {
    const uint8_t* data;
    size_t size;
    size_t offset;
};

// Read callback for libpng
static void pngtest_read_data(png_structp png_ptr, png_bytep data, png_size_t length) {
    png_memory_reader* reader = (png_memory_reader*)png_get_io_ptr(png_ptr);
    
    if (reader->offset + length > reader->size) {
        png_error(png_ptr, "Read beyond buffer");
        return;
    }
    
    memcpy(data, reader->data + reader->offset, length);
    reader->offset += length;
}

// Error callback for libpng
static void pngtest_error(png_structp png_ptr, png_const_charp error_msg) {
    // Error handling - do nothing for fuzzing
    (void)png_ptr;
    (void)error_msg;
}

// Warning callback for libpng  
static void pngtest_warning(png_structp png_ptr, png_const_charp warning_msg) {
    // Warning handling - do nothing for fuzzing
    (void)png_ptr;
    (void)warning_msg;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check - need at least some data for PNG header
    if (size < 8) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Create memory reader structure
    png_memory_reader reader;
    reader.data = data;
    reader.size = size;
    reader.offset = 0;
    
    // Initialize PNG structures
    png_structp png_ptr = NULL;
    png_infop info_ptr = NULL;
    png_infop end_info = NULL;
    
    // Create PNG read structure
    png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, pngtest_error, pngtest_warning);
    if (png_ptr == NULL) {
        return 0;
    }
    
    // Create info structures
    info_ptr = png_create_info_struct(png_ptr);
    if (info_ptr == NULL) {
        png_destroy_read_struct(&png_ptr, NULL, NULL);
        return 0;
    }
    
    end_info = png_create_info_struct(png_ptr);
    if (end_info == NULL) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return 0;
    }
    
    // Set up error handling with setjmp
    if (setjmp(png_jmpbuf(png_ptr))) {
        // Error occurred during PNG processing
        png_destroy_read_struct(&png_ptr, &info_ptr, &end_info);
        return 0;
    }
    
    // Set read function to read from memory buffer
    png_set_read_fn(png_ptr, &reader, pngtest_read_data);
    
    // Try to read PNG info - this will parse the PNG header and chunks
    png_read_info(png_ptr, info_ptr);
    
    // Try to get some PNG information using fuzzed data to choose which APIs to call
    if (fdp.ConsumeBool()) {
        png_uint_32 width = png_get_image_width(png_ptr, info_ptr);
        png_uint_32 height = png_get_image_height(png_ptr, info_ptr);
        (void)width;
        (void)height;
    }
    
    if (fdp.ConsumeBool()) {
        png_byte color_type = png_get_color_type(png_ptr, info_ptr);
        png_byte bit_depth = png_get_bit_depth(png_ptr, info_ptr);
        (void)color_type;
        (void)bit_depth;
    }
    
    if (fdp.ConsumeBool()) {
        png_uint_32 res_x = png_get_x_pixels_per_meter(png_ptr, info_ptr);
        png_uint_32 res_y = png_get_y_pixels_per_meter(png_ptr, info_ptr);
        (void)res_x;
        (void)res_y;
    }
    
    // Try to read the end of PNG
    png_read_end(png_ptr, end_info);
    
    // Clean up
    png_destroy_read_struct(&png_ptr, &info_ptr, &end_info);
    
    return 0;
}
