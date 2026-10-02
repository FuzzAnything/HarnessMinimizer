/* Fuzzing harness for libtiff targeting RGBA image reading functions with comprehensive lifecycle management
 * Focus: RGBA image reading functions (TIFFReadRGBATile, TIFFReadRGBATileExt, TIFFReadRGBAImage, 
 *        TIFFReadRGBAStrip, TIFFReadRGBAStripExt) with proper lifecycle management
 * Target APIs: TIFFReadRGBATile, TIFFReadRGBATileExt, TIFFReadRGBAImage, TIFFReadRGBAStrip, TIFFReadRGBAStripExt
 * Supporting APIs: TIFFRGBAImageBegin, TIFFRGBAImageGet, TIFFRGBAImageEnd, TIFFRGBAImageOK
 * Strategy: Test complete RGBA image lifecycle with varied error handling, buffer management, 
 *           and edge case testing for 600+ undiscovered branches
 * Coverage Gap: These RGBA functions have complex state management and error handling paths
 *               that require systematic testing of different image configurations and failure modes
 */
#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <algorithm>

#include <tiffio.h>

/* Error handler to suppress libtiff error messages during fuzzing */
extern "C" void handle_error(const char* unused, const char* unused2, va_list unused3) {
    // Suppress error messages during fuzzing
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check - need enough data for TIFF file and configuration
    if (size < 256) {
        return 0;
    }

    // Set error handlers to suppress libtiff messages
    TIFFSetErrorHandler(handle_error);
    TIFFSetWarningHandler(handle_error);

    FuzzedDataProvider fdp(data, size);

    // Consume test configuration parameters
    uint8_t test_mode = fdp.ConsumeIntegral<uint8_t>() % 8;  // 8 different test scenarios
    bool use_extended_apis = fdp.ConsumeBool();
    int stop_on_error = fdp.ConsumeIntegral<int>() % 2;
    
    // Consume coordinates and dimensions for RGBA operations
    uint32_t tile_x = fdp.ConsumeIntegral<uint32_t>();
    uint32_t tile_y = fdp.ConsumeIntegral<uint32_t>();
    uint32_t strip_num = fdp.ConsumeIntegral<uint32_t>();
    uint32_t req_width = fdp.ConsumeIntegral<uint32_t>();
    uint32_t req_height = fdp.ConsumeIntegral<uint32_t>();
    
    // Limit dimensions to prevent excessive memory usage
    if (req_width > 2048) req_width = 2048;
    if (req_height > 2048) req_height = 2048;
    
    // Consume buffer management strategy
    uint8_t buffer_strategy = fdp.ConsumeIntegral<uint8_t>() % 3;  // 0: _TIFFmalloc, 1: new[], 2: vector
    
    // Consume remaining data as TIFF file content
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
    
    // Get actual image dimensions from TIFF
    uint32_t actual_width = 0, actual_height = 0;
    TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &actual_width);
    TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &actual_height);
    
    // Test 1: Validate image can be read as RGBA
    char emsg[1024];
    int ok_result = TIFFRGBAImageOK(tif, emsg);
    
    // If image is not suitable for RGBA reading, try basic cleanup and exit
    if (!ok_result) {
        // Still test some error paths before cleaning up
        if (test_mode == 0) {
            // Try to initialize RGBA image even if validation fails (error path testing)
            TIFFRGBAImage img;
            TIFFRGBAImageBegin(&img, tif, stop_on_error, emsg);
            TIFFRGBAImageEnd(&img);
        }
        TIFFClose(tif);
        unlink(filename);
        return 0;
    }
    
    // Test different RGBA reading scenarios based on test_mode
    switch (test_mode) {
        case 0: {
            // Complete RGBA image lifecycle with TIFFRGBAImage APIs
            TIFFRGBAImage img;
            int begin_result = TIFFRGBAImageBegin(&img, tif, stop_on_error, emsg);
            
            if (begin_result) {
                // Get reasonable dimensions for buffer allocation
                uint32_t get_width = std::min(actual_width, (uint32_t)512);
                uint32_t get_height = std::min(actual_height, (uint32_t)512);
                
                size_t buffer_size = get_width * get_height * 4;
                if (buffer_size > 0 && buffer_size < 16777216) {  // Limit to 16MB
                    uint32_t* buffer = nullptr;
                    
                    // Test different buffer allocation strategies
                    switch (buffer_strategy) {
                        case 0:
                            buffer = (uint32_t*)_TIFFmalloc(buffer_size);
                            break;
                        case 1:
                            buffer = new uint32_t[buffer_size / sizeof(uint32_t)];
                            break;
                        case 2: {
                            std::vector<uint32_t> vec_buffer(buffer_size / sizeof(uint32_t));
                            buffer = vec_buffer.data();
                            // Note: buffer will be invalid after scope ends, but we're testing
                            // the API call itself, not the buffer contents
                            TIFFRGBAImageGet(&img, buffer, get_width, get_height);
                            break;
                        }
                    }
                    
                    if (buffer && buffer_strategy != 2) {
                        TIFFRGBAImageGet(&img, buffer, get_width, get_height);
                        
                        // Clean up based on allocation strategy
                        if (buffer_strategy == 0) {
                            _TIFFfree(buffer);
                        } else if (buffer_strategy == 1) {
                            delete[] buffer;
                        }
                    }
                }
                
                TIFFRGBAImageEnd(&img);
            }
            break;
        }
        
        case 1: {
            // Tile-based RGBA reading (only for tiled images)
            if (TIFFIsTiled(tif)) {
                uint32_t tile_width = 0, tile_length = 0;
                TIFFGetFieldDefaulted(tif, TIFFTAG_TILEWIDTH, &tile_width);
                TIFFGetFieldDefaulted(tif, TIFFTAG_TILELENGTH, &tile_length);
                
                if (tile_width > 0 && tile_length > 0 && actual_width > 0 && actual_height > 0) {
                    // Calculate valid tile coordinates (must be tile boundaries)
                    uint32_t valid_tile_x = (tile_x / tile_width) * tile_width;
                    uint32_t valid_tile_y = (tile_y / tile_length) * tile_length;
                    
                    // Ensure coordinates are within image bounds
                    if (valid_tile_x < actual_width && valid_tile_y < actual_height) {
                        size_t tile_buffer_size = tile_width * tile_length * 4;
                        if (tile_buffer_size > 0 && tile_buffer_size < 16777216) {
                            uint32_t* tile_buffer = (uint32_t*)_TIFFmalloc(tile_buffer_size);
                            if (tile_buffer) {
                                if (use_extended_apis) {
                                    TIFFReadRGBATileExt(tif, valid_tile_x, valid_tile_y, tile_buffer, stop_on_error);
                                } else {
                                    TIFFReadRGBATile(tif, valid_tile_x, valid_tile_y, tile_buffer);
                                }
                                _TIFFfree(tile_buffer);
                            }
                        }
                    }
                }
            }
            break;
        }
        
        case 2: {
            // Strip-based RGBA reading (only for striped images)
            uint32_t strips_per_image = TIFFNumberOfStrips(tif);
            if (strips_per_image > 0 && !TIFFIsTiled(tif)) {
                uint32_t rows_per_strip = 0;
                TIFFGetFieldDefaulted(tif, TIFFTAG_ROWSPERSTRIP, &rows_per_strip);
                
                if (rows_per_strip > 0 && actual_width > 0) {
                    uint32_t valid_strip = strip_num % strips_per_image;
                    uint32_t strip_height = rows_per_strip;
                    
                    // Adjust for last strip which might be shorter
                    if (valid_strip == strips_per_image - 1 && actual_height % rows_per_strip != 0) {
                        strip_height = actual_height % rows_per_strip;
                    }
                    
                    size_t strip_buffer_size = actual_width * strip_height * 4;
                    if (strip_buffer_size > 0 && strip_buffer_size < 16777216) {
                        uint32_t* strip_buffer = (uint32_t*)_TIFFmalloc(strip_buffer_size);
                        if (strip_buffer) {
                            if (use_extended_apis) {
                                TIFFReadRGBAStripExt(tif, valid_strip, strip_buffer, stop_on_error);
                            } else {
                                TIFFReadRGBAStrip(tif, valid_strip, strip_buffer);
                            }
                            _TIFFfree(strip_buffer);
                        }
                    }
                }
            }
            break;
        }
        
        case 3: {
            // Full RGBA image reading with requested dimensions
            if (actual_width > 0 && actual_height > 0) {
                // Use minimum of actual and requested dimensions
                uint32_t read_width = std::min(actual_width, req_width);
                uint32_t read_height = std::min(actual_height, req_height);
                
                if (read_width > 0 && read_height > 0) {
                    size_t image_buffer_size = read_width * read_height * 4;
                    if (image_buffer_size > 0 && image_buffer_size < 16777216) {
                        uint32_t* image_buffer = (uint32_t*)_TIFFmalloc(image_buffer_size);
                        if (image_buffer) {
                            TIFFReadRGBAImage(tif, read_width, read_height, image_buffer, stop_on_error);
                            _TIFFfree(image_buffer);
                        }
                    }
                }
            }
            break;
        }
        
        case 4: {
            // Test error recovery by calling APIs with invalid parameters
            // This tests error handling paths in the RGBA functions
            uint32_t* null_buffer = nullptr;
            
            // Call with null buffer (should handle gracefully)
            if (TIFFIsTiled(tif)) {
                TIFFReadRGBATile(tif, 0, 0, null_buffer);
            } else {
                TIFFReadRGBAStrip(tif, 0, null_buffer);
            }
            
            // Call with out-of-bounds coordinates
            if (actual_width > 0 && actual_height > 0) {
                uint32_t* dummy_buffer = (uint32_t*)_TIFFmalloc(1024);
                if (dummy_buffer) {
                    if (TIFFIsTiled(tif)) {
                        TIFFReadRGBATile(tif, actual_width + 100, actual_height + 100, dummy_buffer);
                    } else {
                        TIFFReadRGBAStrip(tif, 99999, dummy_buffer);
                    }
                    _TIFFfree(dummy_buffer);
                }
            }
            break;
        }
        
        case 5: {
            // Test multiple sequential RGBA operations on the same image
            // This tests state management and resource cleanup between operations
            
            // First, try full image read
            if (actual_width > 0 && actual_height > 0) {
                uint32_t small_width = std::min(actual_width, (uint32_t)256);
                uint32_t small_height = std::min(actual_height, (uint32_t)256);
                
                size_t buffer_size = small_width * small_height * 4;
                if (buffer_size > 0 && buffer_size < 16777216) {
                    uint32_t* buffer = (uint32_t*)_TIFFmalloc(buffer_size);
                    if (buffer) {
                        TIFFReadRGBAImage(tif, small_width, small_height, buffer, stop_on_error);
                        
                        // Then try strip/tile operations if applicable
                        if (TIFFIsTiled(tif) && actual_width >= 256 && actual_height >= 256) {
                            TIFFReadRGBATile(tif, 0, 0, buffer);
                        } else if (!TIFFIsTiled(tif)) {
                            TIFFReadRGBAStrip(tif, 0, buffer);
                        }
                        
                        _TIFFfree(buffer);
                    }
                }
            }
            break;
        }
        
        case 6: {
            // Test with minimal buffer sizes (edge case testing)
            if (actual_width > 0 && actual_height > 0) {
                // Allocate buffer for just 1 pixel
                uint32_t* single_pixel = (uint32_t*)_TIFFmalloc(4);
                if (single_pixel) {
                    // Try to read with dimensions that don't match buffer size
                    // This should trigger error paths
                    TIFFReadRGBAImage(tif, 1, 1, single_pixel, stop_on_error);
                    _TIFFfree(single_pixel);
                }
            }
            break;
        }
        
        case 7: {
            // Test RGBA operations on multiple directories (multi-page TIFFs)
            int dir_count = 1;
            while (TIFFReadDirectory(tif) && dir_count < 3) {  // Limit to 3 directories
                dir_count++;
                
                // Get dimensions for current directory
                TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &actual_width);
                TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &actual_height);
                
                if (actual_width > 0 && actual_height > 0) {
                    uint32_t small_width = std::min(actual_width, (uint32_t)128);
                    uint32_t small_height = std::min(actual_height, (uint32_t)128);
                    
                    size_t buffer_size = small_width * small_height * 4;
                    if (buffer_size > 0 && buffer_size < 65536) {
                        uint32_t* buffer = (uint32_t*)_TIFFmalloc(buffer_size);
                        if (buffer) {
                            TIFFReadRGBAImage(tif, small_width, small_height, buffer, stop_on_error);
                            _TIFFfree(buffer);
                        }
                    }
                }
            }
            
            // Return to first directory for cleanup
            TIFFSetDirectory(tif, 0);
            break;
        }
    }
    
    // Final cleanup
    TIFFClose(tif);
    unlink(filename);
    
    return 0;
}
