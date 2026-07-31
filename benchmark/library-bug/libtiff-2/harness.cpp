/* Fuzzing harness for libtiff targeting comprehensive RGBA image reading lifecycle operations */
#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <tiffio.h>

/* Error handler to suppress libtiff error messages during fuzzing */
extern "C" void handle_error(const char* unused, const char* unused2, va_list unused3) {
    // Suppress error messages during fuzzing
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check - need enough data for TIFF file and configuration
    if (size < 64) {
        return 0;
    }

    // Set error handlers to suppress libtiff messages
    TIFFSetErrorHandler(handle_error);
    TIFFSetWarningHandler(handle_error);

    FuzzedDataProvider fdp(data, size);

    // Consume operation type to determine which RGBA reading path to test
    uint8_t operation_type = fdp.ConsumeIntegral<uint8_t>() % 4;
    
    // Consume parameters for RGBA image operations
    bool use_extended = fdp.ConsumeBool();
    int stop_on_error = fdp.ConsumeIntegral<int>() % 2;
    uint32_t tile_x = fdp.ConsumeIntegral<uint32_t>();
    uint32_t tile_y = fdp.ConsumeIntegral<uint32_t>();
    uint32_t strip_num = fdp.ConsumeIntegral<uint32_t>();
    uint32_t width = fdp.ConsumeIntegral<uint32_t>();
    uint32_t height = fdp.ConsumeIntegral<uint32_t>();
    uint16_t orientation = fdp.ConsumeIntegral<uint16_t>() % 8;
    
    // Use remaining data as TIFF file content
    std::string tiff_data = fdp.ConsumeRemainingBytesAsString();
    
    // Create a temporary file for TIFF operations
    char filename[] = "/tmp/tiff_fuzz_rgba_lifecycle_XXXXXX.tif";
    int fd = mkstemps(filename, 4);
    if (fd < 0) {
        return 0;
    }
    
    // Write TIFF data to the temporary file
    if (write(fd, tiff_data.c_str(), tiff_data.size()) != (ssize_t)tiff_data.size()) {
        close(fd);
        unlink(filename);
        return 0;
    }
    
    close(fd);
    
    // Open TIFF file for reading
    TIFF* tif = TIFFOpen(filename, "r");
    if (!tif) {
        unlink(filename);
        return 0;
    }
    
    // Read the first directory if available
    int dir_read = TIFFReadDirectory(tif);
    
    if (!dir_read) {
        TIFFClose(tif);
        unlink(filename);
        return 0;
    }
    
    // Initialize RGBA image context
    TIFFRGBAImage img;
    char emsg[1024];
    
    // Begin RGBA image processing
    int begin_result = TIFFRGBAImageBegin(&img, tif, stop_on_error, emsg);
    
    if (!begin_result) {
        TIFFClose(tif);
        unlink(filename);
        return 0;
    }
    
    // Check if image is suitable for RGBA reading
    int ok_result = TIFFRGBAImageOK(tif, emsg);
    
    // Test different RGBA reading operations based on operation_type
    switch (operation_type) {
        case 0: {
            // Test tile-based RGBA reading
            if (TIFFIsTiled(tif)) {
                uint32_t tile_width = 0, tile_length = 0;
                TIFFGetField(tif, TIFFTAG_TILEWIDTH, &tile_width);
                TIFFGetField(tif, TIFFTAG_TILELENGTH, &tile_length);
                
                if (tile_width > 0 && tile_length > 0) {
                    // Calculate tile coordinates within bounds
                    uint32_t image_width = 0, image_length = 0;
                    TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &image_width);
                    TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &image_length);
                    
                    if (image_width > 0 && image_length > 0) {
                        uint32_t actual_tile_x = tile_x % image_width;
                        uint32_t actual_tile_y = tile_y % image_length;
                        
                        // Allocate buffer for tile data (tile width * tile length * 4 bytes per pixel)
                        size_t tile_buffer_size = tile_width * tile_length * 4;
                        if (tile_buffer_size > 0 && tile_buffer_size < 16777216) { // Limit to 16MB
                            uint32_t* tile_buffer = (uint32_t*)_TIFFmalloc(tile_buffer_size);
                            if (tile_buffer) {
                                if (use_extended) {
                                    TIFFReadRGBATileExt(tif, actual_tile_x, actual_tile_y, tile_buffer, stop_on_error);
                                } else {
                                    TIFFReadRGBATile(tif, actual_tile_x, actual_tile_y, tile_buffer);
                                }
                                _TIFFfree(tile_buffer);
                            }
                        }
                    }
                }
            }
            break;
        }
        
        case 1: {
            // Test strip-based RGBA reading
            if (!TIFFIsTiled(tif)) {
                uint32_t strips_per_image = TIFFNumberOfStrips(tif);
                if (strips_per_image > 0) {
                    uint32_t actual_strip = strip_num % strips_per_image;
                    
                    // Calculate strip size (width * rows_per_strip * 4 bytes per pixel)
                    uint32_t rows_per_strip = 0;
                    TIFFGetField(tif, TIFFTAG_ROWSPERSTRIP, &rows_per_strip);
                    if (rows_per_strip == 0) rows_per_strip = 1;
                    
                    uint32_t image_width = 0;
                    TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &image_width);
                    
                    size_t strip_buffer_size = image_width * rows_per_strip * 4;
                    if (strip_buffer_size > 0 && strip_buffer_size < 16777216) { // Limit to 16MB
                        uint32_t* strip_buffer = (uint32_t*)_TIFFmalloc(strip_buffer_size);
                        if (strip_buffer) {
                            if (use_extended) {
                                TIFFReadRGBAStripExt(tif, actual_strip, strip_buffer, stop_on_error);
                            } else {
                                TIFFReadRGBAStrip(tif, actual_strip, strip_buffer);
                            }
                            _TIFFfree(strip_buffer);
                        }
                    }
                }
            }
            break;
        }
        
        case 2: {
            // Test full image RGBA reading
            uint32_t image_width = 0, image_length = 0;
            TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &image_width);
            TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &image_length);
            
            if (image_width > 0 && image_length > 0 && image_width < 4096 && image_length < 4096) {
                size_t rgba_buffer_size = image_width * image_length * 4;
                if (rgba_buffer_size > 0 && rgba_buffer_size < 16777216) { // Limit to 16MB
                    uint32_t* rgba_buffer = (uint32_t*)_TIFFmalloc(rgba_buffer_size);
                    if (rgba_buffer) {
                        TIFFReadRGBAImage(tif, image_width, image_length, rgba_buffer, 0);
                        _TIFFfree(rgba_buffer);
                    }
                }
            }
            break;
        }
        
        case 3: {
            // Test oriented image RGBA reading
            uint32_t image_width = 0, image_length = 0;
            TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &image_width);
            TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &image_length);
            
            if (image_width > 0 && image_length > 0 && image_width < 4096 && image_length < 4096) {
                size_t rgba_buffer_size = image_width * image_length * 4;
                if (rgba_buffer_size > 0 && rgba_buffer_size < 16777216) { // Limit to 16MB
                    uint32_t* rgba_buffer = (uint32_t*)_TIFFmalloc(rgba_buffer_size);
                    if (rgba_buffer) {
                        TIFFReadRGBAImageOriented(tif, image_width, image_length, rgba_buffer, orientation, 0);
                        _TIFFfree(rgba_buffer);
                    }
                }
            }
            break;
        }
    }
    
    // End RGBA image processing
    TIFFRGBAImageEnd(&img);
    
    // Clean up
    TIFFClose(tif);
    unlink(filename);
    
    return 0;
}
