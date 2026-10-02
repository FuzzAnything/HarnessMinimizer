/*
 * libtiff fuzzing harness for writing operations
 * Targets key TIFF writing APIs: TIFFWriteTile, TIFFWriteEncodedTile, 
 * TIFFWriteScanline, TIFFWriteEncodedStrip, TIFFWriteRawStrip, 
 * TIFFWriteRawTile, and TIFFWriteCheck
 * Semantic differentiation from harness_000 which focused on reading operations
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <unistd.h>  // For close(), unlink()
#include <fuzzer/FuzzedDataProvider.h>
#include <tiffio.h>
// Maximum file size for safety
const size_t MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

// Error handler that does nothing (silent)
extern "C" void silent_error_handler(const char *module, const char *fmt, va_list ap) {
    (void)module;
    (void)fmt;
    (void)ap;
    return;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Set silent error handlers to avoid output noise
    TIFFSetErrorHandler(silent_error_handler);
    TIFFSetWarningHandler(silent_error_handler);
    
    // Minimum input size check
    if (size < 32) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Create a temporary file for writing TIFF data
    std::string temp_filename = "/tmp/libtiff_fuzz_write_XXXXXX";
    int fd = mkstemp(&temp_filename[0]);
    if (fd < 0) {
        return 0;
    }
    close(fd);
    
    // Consume parameters for TIFF configuration
    uint8_t operation_type = fdp.ConsumeIntegral<uint8_t>() % 4;
    uint16_t image_width = fdp.ConsumeIntegralInRange<uint16_t>(1, 1024);
    uint16_t image_height = fdp.ConsumeIntegralInRange<uint16_t>(1, 1024);
    uint16_t bits_per_sample = fdp.ConsumeIntegralInRange<uint16_t>(1, 32); // Allow 1-32 bits per sample
    uint16_t samples_per_pixel = fdp.ConsumeBool() ? 1 : 3; // 1 for grayscale, 3 for RGB
    uint16_t photometric = fdp.ConsumeBool() ? PHOTOMETRIC_RGB : PHOTOMETRIC_MINISBLACK;
    uint16_t compression = fdp.ConsumeIntegral<uint8_t>() % 6; // Several compression types
    
    // Consume tile/strip configuration
    uint32_t tile_width = fdp.ConsumeIntegralInRange<uint32_t>(16, 256);
    uint32_t tile_height = fdp.ConsumeIntegralInRange<uint32_t>(16, 256);
    uint32_t rows_per_strip = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    
    // Consume buffer data for writing
    size_t buffer_size = fdp.ConsumeIntegralInRange<size_t>(1, 65536);
    std::vector<uint8_t> write_buffer = fdp.ConsumeBytes<uint8_t>(buffer_size);
    
    // Open TIFF file for writing
    TIFF* tif = TIFFOpen(temp_filename.c_str(), "w");
    if (!tif) {
        unlink(temp_filename.c_str());
        return 0;
    }
    
    // Set basic TIFF fields
    TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, image_width);
    TIFFSetField(tif, TIFFTAG_IMAGELENGTH, image_height);
    TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, bits_per_sample);
    TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, samples_per_pixel);
    TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, photometric);
    TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
    TIFFSetField(tif, TIFFTAG_COMPRESSION, compression);
    // Call TIFFWriteCheck to validate writing configuration
    TIFFWriteCheck(tif, 0, "fuzzer_test");
    
    // Calculate required buffer sizes based on image parameters
    // Bytes per sample = ceil(bits_per_sample / 8)
    size_t bytes_per_sample = (bits_per_sample + 7) / 8;
    size_t scanline_size = image_width * samples_per_pixel * bytes_per_sample;
    size_t tile_size = tile_width * tile_height * samples_per_pixel * bytes_per_sample;
    size_t strip_size = rows_per_strip * scanline_size;
    
    // Ensure write buffer is large enough for the largest required operation
    size_t required_buffer_size = std::max({scanline_size, tile_size, strip_size, (size_t)1});
    if (write_buffer.size() < required_buffer_size) {
        write_buffer.resize(required_buffer_size);
    }
    
    // Choose between tile-based or strip-based organization
    bool use_tiles = fdp.ConsumeBool();
    
    if (use_tiles) {
        // Configure as tiled image
        TIFFSetField(tif, TIFFTAG_TILEWIDTH, tile_width);
        TIFFSetField(tif, TIFFTAG_TILELENGTH, tile_height);
        
        // Calculate number of tiles
        uint32_t tiles_across = (image_width + tile_width - 1) / tile_width;
        uint32_t tiles_down = (image_height + tile_height - 1) / tile_height;
        
        if (tiles_across > 0 && tiles_down > 0 && write_buffer.size() > 0) {
            // Test TIFFWriteTile
            uint32_t tile_x = fdp.ConsumeIntegralInRange<uint32_t>(0, tiles_across - 1);
            uint32_t tile_y = fdp.ConsumeIntegralInRange<uint32_t>(0, tiles_down - 1);
            uint32_t tile_z = 0;
            uint16_t sample = 0;
            
            // Write a tile
            TIFFWriteTile(tif, write_buffer.data(), 
                         tile_x * tile_width, 
                         tile_y * tile_height, 
                         tile_z, sample);
            
            // Test TIFFWriteEncodedTile
            uint32_t tile_number = fdp.ConsumeIntegralInRange<uint32_t>(0, tiles_across * tiles_down - 1);
            tmsize_t bytes_to_write = fdp.ConsumeIntegralInRange<tmsize_t>(1, write_buffer.size());
            TIFFWriteEncodedTile(tif, tile_number, write_buffer.data(), bytes_to_write);
            
            // Test TIFFWriteRawTile
            if (write_buffer.size() >= 1024) {
                tmsize_t raw_bytes = fdp.ConsumeIntegralInRange<tmsize_t>(1, 1024);
                TIFFWriteRawTile(tif, tile_number, write_buffer.data(), raw_bytes);
            }
        }
    } else {
        // Configure as stripped image
        TIFFSetField(tif, TIFFTAG_ROWSPERSTRIP, rows_per_strip);
        
        if (image_height > 0 && write_buffer.size() > 0) {
            // Test TIFFWriteScanline
            uint32_t row = fdp.ConsumeIntegralInRange<uint32_t>(0, image_height - 1);
            TIFFWriteScanline(tif, write_buffer.data(), row, 0);
            
            // Test TIFFWriteEncodedStrip
            uint32_t strip = fdp.ConsumeIntegralInRange<uint32_t>(0, 
                (image_height + rows_per_strip - 1) / rows_per_strip - 1);
            tmsize_t strip_bytes = fdp.ConsumeIntegralInRange<tmsize_t>(1, write_buffer.size());
            TIFFWriteEncodedStrip(tif, strip, write_buffer.data(), strip_bytes);
            
            // Test TIFFWriteRawStrip
            if (write_buffer.size() >= 512) {
                tmsize_t raw_strip_bytes = fdp.ConsumeIntegralInRange<tmsize_t>(1, 512);
                TIFFWriteRawStrip(tif, strip, write_buffer.data(), raw_strip_bytes);
            }
        }
    }
    
    // Write directory (finalize image)
    TIFFWriteDirectory(tif);
    
    // Cleanup
    TIFFClose(tif);
    unlink(temp_filename.c_str());
    
    return 0;
}
