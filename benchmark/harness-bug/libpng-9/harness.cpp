#include <fuzzer/FuzzedDataProvider.h>
#include <png.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

// Write callback functions that discard output (for fuzzing)
void user_write_data(png_structp png_ptr, png_bytep data, png_size_t length) {
    // Do nothing, discard the data
    (void)png_ptr;
    (void)data;
    (void)length;
}

void user_flush_data(png_structp png_ptr) {
    // Do nothing
    (void)png_ptr;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Need enough data for basic parameters and some image data
    if (size < 100) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);

    // Step 1: Consume image dimensions from fuzzer input
    // Store height in volatile variable since it's used in error handler after longjmp
    volatile png_uint_32 width = fdp.ConsumeIntegralInRange<png_uint_32>(1, 100);
    volatile png_uint_32 height = fdp.ConsumeIntegralInRange<png_uint_32>(1, 100);
    // Step 2: Consume bit depth and color type
    // Bit depths: 1, 2, 4, 8, 16
    int bit_depth_choice = fdp.ConsumeIntegralInRange(0, 4);
    png_byte bit_depth;
    switch (bit_depth_choice) {
        case 0: bit_depth = 1; break;
        case 1: bit_depth = 2; break;
        case 2: bit_depth = 4; break;
        case 3: bit_depth = 8; break;
        default: bit_depth = 16; break;
    }
    
    // Color type: grayscale, RGB, palette, grayscale+alpha, RGBA
    int color_type_choice = fdp.ConsumeIntegralInRange(0, 5);
    png_byte color_type;
    switch (color_type_choice) {
        case 0: color_type = PNG_COLOR_TYPE_GRAY; break;
        case 1: color_type = PNG_COLOR_TYPE_RGB; break;
        case 2: color_type = PNG_COLOR_TYPE_PALETTE; break;
        case 3: color_type = PNG_COLOR_TYPE_GRAY_ALPHA; break;
        case 4: color_type = PNG_COLOR_TYPE_RGB_ALPHA; break;
        default: color_type = PNG_COLOR_TYPE_GRAY; break;
    }
    // Step 3: Consume transform flags for png_write_png
    // PNG_TRANSFORM flags can be combined - only use write-compatible transforms
    int transforms = 0;
    
    // Individual transform flags (write-compatible only)
    if (fdp.ConsumeBool()) transforms |= PNG_TRANSFORM_IDENTITY;        // read and write
    if (fdp.ConsumeBool()) transforms |= PNG_TRANSFORM_PACKING;         // read and write
    if (fdp.ConsumeBool()) transforms |= PNG_TRANSFORM_PACKSWAP;        // read and write
    if (fdp.ConsumeBool()) transforms |= PNG_TRANSFORM_INVERT_MONO;     // read and write
    if (fdp.ConsumeBool()) transforms |= PNG_TRANSFORM_SHIFT;           // read and write
    if (fdp.ConsumeBool()) transforms |= PNG_TRANSFORM_BGR;             // read and write
    if (fdp.ConsumeBool()) transforms |= PNG_TRANSFORM_SWAP_ALPHA;      // read and write
    if (fdp.ConsumeBool()) transforms |= PNG_TRANSFORM_SWAP_ENDIAN;     // read and write
    if (fdp.ConsumeBool()) transforms |= PNG_TRANSFORM_INVERT_ALPHA;    // read and write
    if (fdp.ConsumeBool()) transforms |= PNG_TRANSFORM_STRIP_FILLER;    // write only
    if (fdp.ConsumeBool()) transforms |= PNG_TRANSFORM_STRIP_FILLER_BEFORE; // write only (same as STRIP_FILLER)
    if (fdp.ConsumeBool()) transforms |= PNG_TRANSFORM_STRIP_FILLER_AFTER;  // write only (0x1000)
    // Step 4: Create write structure - png_create_write_struct
    png_structp png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
    if (!png_ptr) {
        return 0;
    }

    // Step 5: Create info structure - png_create_info_struct
    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_write_struct(&png_ptr, nullptr);
        return 0;
    }
    // Track row allocations - use volatile for variables modified between setjmp/longjmp
    volatile png_bytep* row_pointers = nullptr;
    volatile bool row_pointers_allocated = false;
    volatile bool individual_rows_allocated = false;
    
    // Set up error handling
    if (setjmp(png_jmpbuf(png_ptr))) {
        // Clean up rows if they were allocated
        // Note: After longjmp, volatile variables retain their values
        if (individual_rows_allocated && row_pointers) {
            for (png_uint_32 y = 0; y < height; ++y) {
                if (row_pointers[y]) {
                    free((void*)row_pointers[y]);
                }
            }
        }
        if (row_pointers_allocated && row_pointers) {
            free((void*)row_pointers);
        }
        png_destroy_write_struct(&png_ptr, &info_ptr);
        return 0;
    }

    // Step 6: Set write callbacks (discard output)
    png_set_write_fn(png_ptr, nullptr, user_write_data, user_flush_data);

    // Step 7: Set IHDR (image header)
    int interlace_type = fdp.ConsumeBool() ? PNG_INTERLACE_ADAM7 : PNG_INTERLACE_NONE;
    int compression_type = PNG_COMPRESSION_TYPE_DEFAULT;
    int filter_type = PNG_FILTER_TYPE_DEFAULT;
    png_set_IHDR(png_ptr, info_ptr, width, height, bit_depth, color_type,
                 interlace_type, compression_type, filter_type);

    // Step 8: Allocate and fill row pointers with fuzzer data
    // Calculate row bytes using png_get_rowbytes
    row_pointers = (png_bytep*)malloc(height * sizeof(png_bytep));
    if (!row_pointers) {
        png_destroy_write_struct(&png_ptr, &info_ptr);
        return 0;
    }
    row_pointers_allocated = true;
    // Initialize all row pointers to NULL for cleanup
    for (png_uint_32 y = 0; y < height; ++y) {
        row_pointers[y] = nullptr;
    }
    volatile bool allocation_failed = false;
    for (png_uint_32 y = 0; y < height; ++y) {
        // Get rowbytes from libpng
        png_size_t rowbytes = png_get_rowbytes(png_ptr, info_ptr);
        if (rowbytes == 0) {
            rowbytes = 1; // avoid zero allocation
        }
        
        // Ensure we have enough data left
        if (fdp.remaining_bytes() < rowbytes) {
            allocation_failed = true;
            break;
        }
        
        row_pointers[y] = (png_byte*)malloc(rowbytes);
        if (!row_pointers[y]) {
            allocation_failed = true;
            break;
        }
        
        // Consume bytes for this row
        auto row_data = fdp.ConsumeBytes<uint8_t>(rowbytes);
        memcpy((void*)row_pointers[y], row_data.data(), rowbytes);
    }
    
    if (allocation_failed) {
        // Clean up any allocated rows
        for (png_uint_32 y = 0; y < height; ++y) {
            if (row_pointers[y]) {
                free((void*)row_pointers[y]);
            }
        }
        free((void*)row_pointers);
        png_destroy_write_struct(&png_ptr, &info_ptr);
        return 0;
    }
    
    // Mark rows as allocated for error handler - MUST be before any PNG operations
    individual_rows_allocated = true;
    
    // Step 9: Set rows in info structure
    png_set_rows(png_ptr, info_ptr, (png_bytepp)row_pointers);

    // Step 10: Primary target - png_write_png with transform flags
    png_write_png(png_ptr, info_ptr, transforms, nullptr);

    // Step 11: Optionally test png_write_rows directly for additional coverage
    // Choose based on remaining fuzzer input
    if (fdp.ConsumeBool() && fdp.remaining_bytes() > 0) {
        // Write a few rows using png_write_rows
        png_uint_32 num_rows_to_write = fdp.ConsumeIntegralInRange<png_uint_32>(1, height);
        png_write_rows(png_ptr, (png_bytepp)row_pointers, num_rows_to_write);
        
        // Optionally flush
        if (fdp.ConsumeBool()) {
            png_write_flush(png_ptr);
        }
    }

    // Step 12: Clean up row pointers
    for (png_uint_32 y = 0; y < height; ++y) {
        if (row_pointers[y]) {
            free((void*)row_pointers[y]);
        }
    }
    free((void*)row_pointers);

    // Step 13: Destroy write struct
    png_destroy_write_struct(&png_ptr, &info_ptr);

    return 0;
}
