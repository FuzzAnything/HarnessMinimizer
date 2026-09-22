/*
 * Fuzzing harness for libtiff library - Scanline Reading Operations
 * Target: TIFF scanline reading APIs - TIFFReadScanline, TIFFReadFromUserBuffer,
 *         TIFFScanlineSize, TIFFRasterScanlineSize, TIFFScanlineSize64,
 *         TIFFRasterScanlineSize64, TIFFWriteScanline, TIFFIsTiled,
 *         TIFFReadRawTile, TIFFReadEncodedTile, TIFFReadRawStrip, TIFFReadEncodedStrip
 * 
 * This harness exercises TIFF scanline reading operations using fuzzer input
 * as TIFF data and generates scanline parameters for reading.
 * Focuses on scanline reading APIs that have 108+ undiscovered branches according to coverage analysis.
 * Follows the invocation sequence: open TIFF file, check if not tiled with TIFFIsTiled,
 * compute scanline size with TIFFScanlineSize/TIFFScanlineSize64,
 * compute raster scanline size with TIFFRasterScanlineSize/TIFFRasterScanlineSize64,
 * read scanlines with TIFFReadScanline, use buffer-based reading with TIFFReadFromUserBuffer,
 * read raw/encoded tiles with TIFFReadRawTile/TIFFReadEncodedTile,
 * read raw/encoded strips with TIFFReadRawStrip/TIFFReadEncodedStrip,
 * optionally write scanlines with TIFFWriteScanline, close with TIFFClose.
 * Differentiates from existing harnesses: harness_000 (basic reading),
 * harness_001 (writing), harness_002 (directory manipulation),
 * harness_003 (tile reading), harness_004 (raw writing),
 * harness_005 (file open/close), harness_006 (strip reading).
 * This harness specifically targets scanline operations as primary focus with comprehensive reading APIs.
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <sstream>
#include <fuzzer/FuzzedDataProvider.h>
#include <tiffio.h>
#include <tiffio.hxx>

// Error handler to suppress libtiff errors during fuzzing
extern "C" void tiff_error_handler(const char* unused, const char* unused2,
                                   va_list unused3) {
    // Suppress error messages during fuzzing
    (void)unused;
    (void)unused2;
    (void)unused3;
    return;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
    // Set error handlers to suppress output
    TIFFSetErrorHandler(tiff_error_handler);
    TIFFSetWarningHandler(tiff_error_handler);

    // Need minimum input for TIFF header and scanline parameters
    if (Size < 128) {
        return 0; // Too small for meaningful testing
    }

    FuzzedDataProvider fdp(Data, Size);

    // ----------------------
    // Phase 1: Process fuzzer input for scanline and tile parameters
    // ----------------------

    // Consume part of input for scanline parameters
    uint32_t target_row = fdp.ConsumeIntegral<uint32_t>();
    uint16_t target_sample = fdp.ConsumeIntegral<uint16_t>();
    uint32_t target_strile = fdp.ConsumeIntegral<uint32_t>(); // strip or tile number
    uint32_t tile_x = fdp.ConsumeIntegral<uint32_t>();
    uint32_t tile_y = fdp.ConsumeIntegral<uint32_t>();
    uint32_t tile_z = fdp.ConsumeIntegral<uint32_t>();
    
    // Determine which operations to use based on input
    bool test_read_scanline = fdp.ConsumeBool();
    bool test_read_from_user_buffer = fdp.ConsumeBool();
    bool test_write_scanline = fdp.ConsumeBool();
    bool test_size_calculations = fdp.ConsumeBool();
    bool test_raw_tile = fdp.ConsumeBool();
    bool test_encoded_tile = fdp.ConsumeBool();
    bool test_raw_strip = fdp.ConsumeBool();
    bool test_encoded_strip = fdp.ConsumeBool();

    // Consume remaining bytes as TIFF data
    std::vector<uint8_t> tiff_data = fdp.ConsumeRemainingBytes<uint8_t>();
    
    if (tiff_data.size() < 8) {
        return 0; // Too small for TIFF header
    }

    // ----------------------
    // Phase 2: Open TIFF file from memory
    // ----------------------

    TIFF* tif = nullptr;
    
    // Create string stream from the data
    std::istringstream s(std::string(tiff_data.begin(), tiff_data.end()));
    
    // Open TIFF from stream (memory-based approach)
    // Note: TIFFStreamOpen is in tiffio.hxx which we included
    tif = TIFFStreamOpen("MemTIFF", &s);
    
    if (!tif) {
        return 0;
    }

    // ----------------------
    // Phase 3: Check if file is not tiled and read directory
    // ----------------------

    // Try to read directory information first
    int dir_read = TIFFReadDirectory(tif);
    
    if (!dir_read) {
        // Cannot read directory, clean up and exit
        TIFFClose(tif);
        return 0;
    }

    // Check if file is tiled (scanline operations are for non-tiled images)
    int is_tiled = TIFFIsTiled(tif);
    
    // Get image dimensions
    uint32_t width = 0, height = 0;
    TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &width);
    TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &height);
    
    // Validate dimensions
    if (width == 0 || height == 0 || width > 4096 || height > 4096) {
        TIFFClose(tif);
        return 0;
    }

    // Ensure target_row is within bounds
    if (target_row >= height) {
        target_row = target_row % height;
    }

    // Get strip/tile information
    uint32_t strips_per_image = TIFFNumberOfStrips(tif);
    uint32_t tiles_per_image = TIFFNumberOfTiles(tif);
    
    // Adjust target_strile to be within bounds
    if (is_tiled && tiles_per_image > 0) {
        if (target_strile >= tiles_per_image) {
            target_strile = target_strile % tiles_per_image;
        }
    } else if (!is_tiled && strips_per_image > 0) {
        if (target_strile >= strips_per_image) {
            target_strile = target_strile % strips_per_image;
        }
    }

    // ----------------------
    // Phase 4: Scanline size calculations
    // ----------------------

    uint64_t scanline_size64 = 0;
    tmsize_t scanline_size = 0;
    uint64_t raster_scanline_size64 = 0;
    tmsize_t raster_scanline_size = 0;
    
    if (test_size_calculations) {
        // Test 64-bit size calculations
        scanline_size64 = TIFFScanlineSize64(tif);
        raster_scanline_size64 = TIFFRasterScanlineSize64(tif);
        
        // Test regular size calculations (may truncate on 32-bit)
        scanline_size = TIFFScanlineSize(tif);
        raster_scanline_size = TIFFRasterScanlineSize(tif);
        
        // Validate sizes are reasonable
        if (scanline_size64 > 1024 * 1024 * 1024 || 
            raster_scanline_size64 > 1024 * 1024 * 1024) {
            // Too large for safe testing, clean up
            TIFFClose(tif);
            return 0;
        }
    }

    // ----------------------
    // Phase 5: Scanline reading operations
    // ----------------------

    if (test_read_scanline) {
        // Allocate buffer for scanline data
        size_t buffer_size = 0;
        if (scanline_size > 0) {
            buffer_size = static_cast<size_t>(scanline_size);
        } else {
            // Estimate buffer size based on image dimensions
            uint16_t samples_per_pixel = 1;
            uint16_t bits_per_sample = 8;
            TIFFGetField(tif, TIFFTAG_SAMPLESPERPIXEL, &samples_per_pixel);
            TIFFGetField(tif, TIFFTAG_BITSPERSAMPLE, &bits_per_sample);
            buffer_size = ((width * samples_per_pixel * bits_per_sample) + 7) / 8;
        }
        
        // Cap buffer size to prevent excessive memory usage
        if (buffer_size > 1024 * 1024) {
            buffer_size = 1024 * 1024;
        }
        
        if (buffer_size > 0) {
            uint8_t* scanline_buffer = static_cast<uint8_t*>(_TIFFmalloc(buffer_size));
            if (scanline_buffer) {
                // Try to read scanline
                int result = TIFFReadScanline(tif, scanline_buffer, target_row, target_sample);
                
                // Also test with default sample (0)
                if (target_sample != 0) {
                    result = TIFFReadScanline(tif, scanline_buffer, target_row, 0);
                }
                
                _TIFFfree(scanline_buffer);
            }
        }
    }

    // ----------------------
    // Phase 6: User buffer reading operations
    // ----------------------

    if (test_read_from_user_buffer) {
        // Allocate input and output buffers
        size_t in_buffer_size = 1024;
        size_t out_buffer_size = 2048;
        uint8_t* in_buffer = static_cast<uint8_t*>(_TIFFmalloc(in_buffer_size));
        uint8_t* out_buffer = static_cast<uint8_t*>(_TIFFmalloc(out_buffer_size));
        
        if (in_buffer && out_buffer) {
            // Initialize input buffer with some data
            for (size_t i = 0; i < in_buffer_size; i++) {
                in_buffer[i] = static_cast<uint8_t>(i % 256);
            }
            
            // Initialize output buffer
            memset(out_buffer, 0, out_buffer_size);
            
            // Test TIFFReadFromUserBuffer
            // strile can be strip or tile number depending on image organization
            int result = TIFFReadFromUserBuffer(tif, target_strile, 
                                                in_buffer, in_buffer_size,
                                                out_buffer, out_buffer_size);
            
            _TIFFfree(in_buffer);
            _TIFFfree(out_buffer);
        } else {
            if (in_buffer) _TIFFfree(in_buffer);
            if (out_buffer) _TIFFfree(out_buffer);
        }
    }

    // ----------------------
    // Phase 7: Tile reading operations
    // ----------------------

    if (is_tiled) {
        // Test tile reading operations
        
        if (test_raw_tile) {
            // Allocate buffer for raw tile data
            size_t tile_buffer_size = 4096; // Conservative size
            uint8_t* tile_buffer = static_cast<uint8_t*>(_TIFFmalloc(tile_buffer_size));
            
            if (tile_buffer) {
                // Try to read raw tile
                tmsize_t result = TIFFReadRawTile(tif, target_strile, tile_buffer, tile_buffer_size);
                _TIFFfree(tile_buffer);
            }
        }
        
        if (test_encoded_tile) {
            // Allocate buffer for encoded tile data
            size_t tile_buffer_size = 4096; // Conservative size
            uint8_t* tile_buffer = static_cast<uint8_t*>(_TIFFmalloc(tile_buffer_size));
            
            if (tile_buffer) {
                // Try to read encoded tile
                tmsize_t result = TIFFReadEncodedTile(tif, target_strile, tile_buffer, tile_buffer_size);
                _TIFFfree(tile_buffer);
            }
        }
    } else {
        // Test strip reading operations for non-tiled images
        
        if (test_raw_strip) {
            // Allocate buffer for raw strip data
            size_t strip_buffer_size = 4096; // Conservative size
            uint8_t* strip_buffer = static_cast<uint8_t*>(_TIFFmalloc(strip_buffer_size));
            
            if (strip_buffer) {
                // Try to read raw strip
                tmsize_t result = TIFFReadRawStrip(tif, target_strile, strip_buffer, strip_buffer_size);
                _TIFFfree(strip_buffer);
            }
        }
        
        if (test_encoded_strip) {
            // Allocate buffer for encoded strip data
            size_t strip_buffer_size = 4096; // Conservative size
            uint8_t* strip_buffer = static_cast<uint8_t*>(_TIFFmalloc(strip_buffer_size));
            
            if (strip_buffer) {
                // Try to read encoded strip
                tmsize_t result = TIFFReadEncodedStrip(tif, target_strile, strip_buffer, strip_buffer_size);
                _TIFFfree(strip_buffer);
            }
        }
    }

    // ----------------------
    // Phase 8: Scanline writing operations (for completeness)
    // ----------------------

    if (test_write_scanline) {
        // Allocate small buffer for writing test
        size_t write_buffer_size = 128;
        uint8_t* write_buffer = static_cast<uint8_t*>(_TIFFmalloc(write_buffer_size));
        
        if (write_buffer) {
            // Initialize with some data
            for (size_t i = 0; i < write_buffer_size; i++) {
                write_buffer[i] = static_cast<uint8_t>((i + target_row) % 256);
            }
            
            // Try to write scanline (may fail since we opened for reading)
            // This tests error paths
            int result = TIFFWriteScanline(tif, write_buffer, target_row, target_sample);
            
            _TIFFfree(write_buffer);
        }
    }

    // ----------------------
    // Phase 9: Read multiple scanlines in sequence
    // ----------------------

    // Test reading multiple scanlines
    if (height > 1) {
        // Read a few scanlines sequentially
        uint32_t num_scanlines_to_read = 3;
        if (num_scanlines_to_read > height) {
            num_scanlines_to_read = height;
        }
        
        // Allocate buffer for one scanline
        size_t multi_buffer_size = 1024; // Conservative size
        uint8_t* multi_buffer = static_cast<uint8_t*>(_TIFFmalloc(multi_buffer_size));
        
        if (multi_buffer) {
            for (uint32_t row = 0; row < num_scanlines_to_read; row++) {
                uint32_t current_row = (target_row + row) % height;
                int result = TIFFReadScanline(tif, multi_buffer, current_row, 0);
                
                // Break early if we encounter an error
                if (result < 0) {
                    break;
                }
            }
            
            _TIFFfree(multi_buffer);
        }
    }

    // ----------------------
    // Phase 10: Test with different sample values
    // ----------------------

    // Get samples per pixel information
    uint16_t samples_per_pixel = 1;
    TIFFGetField(tif, TIFFTAG_SAMPLESPERPIXEL, &samples_per_pixel);
    
    if (samples_per_pixel > 1) {
        // Test reading with different sample indices
        size_t sample_buffer_size = 512;
        uint8_t* sample_buffer = static_cast<uint8_t*>(_TIFFmalloc(sample_buffer_size));
        
        if (sample_buffer) {
            for (uint16_t sample = 0; sample < samples_per_pixel && sample < 4; sample++) {
                int result = TIFFReadScanline(tif, sample_buffer, target_row, sample);
            }
            
            _TIFFfree(sample_buffer);
        }
    }

    // ----------------------
    // Phase 11: Cleanup
    // ----------------------

    TIFFClose(tif);
    return 0;
}
