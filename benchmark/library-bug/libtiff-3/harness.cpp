#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <vector>
#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "tiffio.h"

// Error handler that does nothing (to suppress libtiff error messages during fuzzing)
extern "C" void handle_error(const char* module, const char* fmt, va_list ap) {
    // Do nothing - we want to continue fuzzing even on errors
    (void)module;
    (void)fmt;
    (void)ap;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 100) {
        // Need enough data for meaningful TIFF operations with RGBA reading
        return 0;
    }

    // Set error handlers to avoid printing to stderr during fuzzing
    TIFFSetErrorHandler(handle_error);
    TIFFSetWarningHandler(handle_error);

    FuzzedDataProvider fdp(data, size);
    
    // Consume fuzzer input for operation selection and parameters
    uint8_t operation_mode = fdp.ConsumeIntegral<uint8_t>();
    uint8_t image_type = fdp.ConsumeIntegral<uint8_t>() % 4; // 0-3: different image configurations
    
    // Consume parameters for tile/strip coordinates and orientations
    uint32_t tile_x = fdp.ConsumeIntegral<uint32_t>();
    uint32_t tile_y = fdp.ConsumeIntegral<uint32_t>();
    uint32_t strip_num = fdp.ConsumeIntegral<uint32_t>();
    uint16_t orientation = fdp.ConsumeIntegral<uint16_t>() % 8; // 0-7: different orientations
    
    // Use remaining bytes as TIFF data (minimum 50 bytes for basic TIFF)
    if (fdp.remaining_bytes() < 50) {
        return 0;
    }
    std::vector<uint8_t> tiff_data = fdp.ConsumeRemainingBytes<uint8_t>();
    
    if (tiff_data.empty()) {
        return 0;
    }

    // Create a temporary file with the TIFF data
    char temp_filename_buffer[] = "/tmp/temp_tiff_rgba_XXXXXX.tiff";
    int temp_fd = mkstemps(temp_filename_buffer, 5);
    if (temp_fd < 0) {
        return 0;
    }
    
    // Write TIFF data to temp file
    if (write(temp_fd, tiff_data.data(), tiff_data.size()) != (ssize_t)tiff_data.size()) {
        close(temp_fd);
        return 0;
    }
    close(temp_fd);
    const char* temp_filename = temp_filename_buffer;

    // Step 1: Open TIFF file (TIFFOpen/TIFFFdOpen)
    TIFF* tif = TIFFOpen(temp_filename, "r");
    if (!tif) {
        // Try with TIFFFdOpen as fallback
        temp_fd = open(temp_filename, O_RDONLY);
        if (temp_fd < 0) {
            unlink(temp_filename);
            return 0;
        }
        tif = TIFFFdOpen(temp_fd, temp_filename, "r");
        if (!tif) {
            close(temp_fd);
            unlink(temp_filename);
            return 0;
        }
    }

    // Step 2: Read directory information
    uint16_t dir_count = 0;
    do {
        dir_count++;
        
        // Get basic image parameters
        uint32_t width = 0, height = 0;
        uint16_t samples_per_pixel = 0, bits_per_sample = 0;
        uint16_t photometric = 0;
        uint16_t planar_config = 0;
        uint32_t rows_per_strip = 0;
        uint32_t tile_width = 0, tile_height = 0;
        
        TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &width);
        TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &height);
        TIFFGetField(tif, TIFFTAG_SAMPLESPERPIXEL, &samples_per_pixel);
        TIFFGetField(tif, TIFFTAG_BITSPERSAMPLE, &bits_per_sample);
        TIFFGetField(tif, TIFFTAG_PHOTOMETRIC, &photometric);
        TIFFGetField(tif, TIFFTAG_PLANARCONFIG, &planar_config);
        
        // Check if image is tiled
        int is_tiled = TIFFIsTiled(tif);
        
        if (is_tiled) {
            TIFFGetField(tif, TIFFTAG_TILEWIDTH, &tile_width);
            TIFFGetField(tif, TIFFTAG_TILELENGTH, &tile_height);
        } else {
            TIFFGetField(tif, TIFFTAG_ROWSPERSTRIP, &rows_per_strip);
        }
        
        // Allocate RGBA buffer for tile/strip operations (reasonable size limit)
        size_t max_rgba_pixels = 0;
        if (is_tiled && tile_width > 0 && tile_height > 0) {
            max_rgba_pixels = tile_width * tile_height;
        } else if (!is_tiled && rows_per_strip > 0 && width > 0) {
            max_rgba_pixels = width * rows_per_strip;
        } else if (width > 0 && height > 0) {
            max_rgba_pixels = width * height;
        }
        
        // Limit buffer size to prevent excessive memory usage
        if (max_rgba_pixels > 1000000) { // 1M pixels max
            max_rgba_pixels = 1000000;
        }
        
        // Step 3: TIFFReadRGBATile for tiled images (if applicable)
        if ((operation_mode & 0x01) && is_tiled && tile_width > 0 && tile_height > 0 && 
            width >= tile_width && height >= tile_height && max_rgba_pixels > 0) {
            
            uint32_t* rgba_buffer = (uint32_t*)_TIFFmalloc(max_rgba_pixels * sizeof(uint32_t));
            if (rgba_buffer) {
                // Calculate tile coordinates within bounds
                uint32_t max_tiles_x = (width + tile_width - 1) / tile_width;
                uint32_t max_tiles_y = (height + tile_height - 1) / tile_height;
                
                if (max_tiles_x > 0 && max_tiles_y > 0) {
                    uint32_t tile_col = tile_x % max_tiles_x;
                    uint32_t tile_row = tile_y % max_tiles_y;
                    
                    // Call TIFFReadRGBATile
                    TIFFReadRGBATile(tif, tile_col * tile_width, tile_row * tile_height, rgba_buffer);
                }
                _TIFFfree(rgba_buffer);
            }
        }
        
        // Step 4: TIFFReadRGBAStrip for stripped images (if applicable)
        if ((operation_mode & 0x02) && !is_tiled && rows_per_strip > 0 && width > 0 && height > 0 && max_rgba_pixels > 0) {
            
            uint32_t* rgba_buffer = (uint32_t*)_TIFFmalloc(max_rgba_pixels * sizeof(uint32_t));
            if (rgba_buffer) {
                uint32_t strip_count = TIFFNumberOfStrips(tif);
                if (strip_count > 0) {
                    uint32_t actual_strip = strip_num % strip_count;
                    
                    // Call TIFFReadRGBAStrip
                    TIFFReadRGBAStrip(tif, actual_strip, rgba_buffer);
                }
                _TIFFfree(rgba_buffer);
            }
        }
        
        // Step 5: TIFFReadRGBAImage for whole image reading
        if ((operation_mode & 0x04) && width > 0 && height > 0 && max_rgba_pixels > 0) {
            
            uint32_t* rgba_buffer = (uint32_t*)_TIFFmalloc(max_rgba_pixels * sizeof(uint32_t));
            if (rgba_buffer) {
                // Call TIFFReadRGBAImage
                TIFFReadRGBAImage(tif, width, height, rgba_buffer, 0);
                _TIFFfree(rgba_buffer);
            }
        }
        
        // Step 6: TIFFReadRGBAImageOriented with different orientations
        if ((operation_mode & 0x08) && width > 0 && height > 0 && max_rgba_pixels > 0) {
            
            uint32_t* rgba_buffer = (uint32_t*)_TIFFmalloc(max_rgba_pixels * sizeof(uint32_t));
            if (rgba_buffer) {
                // Call TIFFReadRGBAImageOriented with orientation from fuzzer input
                TIFFReadRGBAImageOriented(tif, width, height, rgba_buffer, orientation, 0);
                _TIFFfree(rgba_buffer);
            }
        }
        
        // Step 7: TIFFReadTile and TIFFReadRawTile for raw tile data (tiled images only)
        if ((operation_mode & 0x10) && is_tiled) {
            uint32_t tile_count = TIFFNumberOfTiles(tif);
            if (tile_count > 0) {
                uint32_t tile_to_read = tile_x % tile_count;
                tmsize_t tile_size = TIFFTileSize(tif);
                
                if (tile_size > 0 && tile_size < 10 * 1024 * 1024) { // Reasonable limit
                    void* tile_buffer = _TIFFmalloc(tile_size);
                    if (tile_buffer) {
                        // Call TIFFReadTile
                        TIFFReadTile(tif, tile_buffer, tile_x, tile_y, 0, 0);
                        
                        // Also try TIFFReadRawTile
                        TIFFReadRawTile(tif, tile_to_read, tile_buffer, tile_size);
                        
                        _TIFFfree(tile_buffer);
                    }
                }
            }
        }
        
        // Step 8: TIFFReadRawStrip for raw strip data (stripped images only)
        if ((operation_mode & 0x20) && !is_tiled) {
            uint32_t strip_count = TIFFNumberOfStrips(tif);
            if (strip_count > 0) {
                uint32_t strip_to_read = strip_num % strip_count;
                tmsize_t strip_size = TIFFRawStripSize(tif, strip_to_read);
                
                if (strip_size > 0 && strip_size < 10 * 1024 * 1024) { // Reasonable limit
                    void* strip_buffer = _TIFFmalloc(strip_size);
                    if (strip_buffer) {
                        // Call TIFFReadRawStrip
                        TIFFReadRawStrip(tif, strip_to_read, strip_buffer, strip_size);
                        _TIFFfree(strip_buffer);
                    }
                }
            }
        }
        
    } while (TIFFReadDirectory(tif));

    // Step 9: Close (cleanup)
    TIFFClose(tif);
    
    // Clean up temporary file
    unlink(temp_filename_buffer);

    return 0;
}
