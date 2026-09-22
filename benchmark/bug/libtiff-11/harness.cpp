/*
 * Fuzzing harness for libtiff library focusing on LogLuv compression and color conversion functions
 * Targets completely uncovered LogLuv APIs in tif_luv.c module: TIFFInitSGILog, LogLuv encoding/decoding,
 * LogLuv color conversions, and LogLuv-specific TIFF tags
 * Tests LogLuv compression (COMPRESSION_SGILOG, COMPRESSION_SGILOG24), LogL/Luv photometric interpretations,
 * SGILOGDATAFMT, SGILOGENCODE tags, and related color space conversion functions
 * Uses FuzzedDataProvider to process input dynamically
 * Semantically differentiated from:
 * - harness_000 (basic reading)
 * - harness_001 (writing) 
 * - harness_002 (RGBA reading)
 * - harness_003 (directory manipulation basics)
 * - harness_004 (advanced directory management)
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <tiffio.h>

// Error handler to suppress library error messages during fuzzing
extern "C" void handle_error(const char *module, const char *fmt, va_list ap) {
    (void)module;
    (void)fmt;
    (void)ap;
    return;
}

// LogLuv-specific constants
#define COMPRESSION_SGILOG 34676   /* SGI Log Luminance RLE */
#define COMPRESSION_SGILOG24 34677 /* SGI Log 24-bit packed */
#define PHOTOMETRIC_LOGL 32844     /* CIE Log2(L) */
#define PHOTOMETRIC_LOGLUV 32845   /* CIE Log2(L) (u',v') */

// SGILOGDATAFMT values
#define SGILOGDATAFMT_FLOAT   0  /* IEEE 32-bit float XYZ values */
#define SGILOGDATAFMT_16BIT   1  /* 16-bit integer encodings of logL, u and v */
#define SGILOGDATAFMT_RAW     2  /* 32-bit unsigned integer with encoded pixel */
#define SGILOGDATAFMT_8BIT    3  /* 8-bit default RGB gamma-corrected values */

// SGILOGENCODE values  
#define SGILOGENCODE_NODITHER  0  /* do not dither encoded values */
#define SGILOGENCODE_RANDITHER 1  /* apply random dithering during encoding */

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Minimum size check - need at least some data for meaningful testing
    if (size < 200) {
        return 0;
    }
    
    // Initialize FuzzedDataProvider for structured input processing
    FuzzedDataProvider fdp(data, size);
    
    // Set error handlers to suppress library messages
    TIFFSetErrorHandler(handle_error);
    TIFFSetWarningHandler(handle_error);
    
    // Create a temporary file for LogLuv testing
    const char* filename = "/tmp/fuzzed_logluv_tiff.tif";
    
    // Determine whether to test reading or writing LogLuv format
    bool test_writing = fdp.ConsumeBool();
    
    if (test_writing) {
        /**********************************************************************
         * TEST LOGLUV WRITING
         **********************************************************************/
        
        // Open TIFF file for writing
        TIFF* tif = TIFFOpen(filename, "w");
        if (!tif) {
            return 0;
        }
        
        // Consume basic image parameters from fuzzed input
        uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
        uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
        
        // Determine LogLuv compression type
        uint8_t compression_selector = fdp.ConsumeIntegral<uint8_t>() % 2;
        uint16_t compression = (compression_selector == 0) ? COMPRESSION_SGILOG : COMPRESSION_SGILOG24;
        
        // Determine photometric interpretation (LogL or LogLuv)
        uint8_t photometric_selector = fdp.ConsumeIntegral<uint8_t>() % 2;
        uint16_t photometric = (photometric_selector == 0) ? PHOTOMETRIC_LOGL : PHOTOMETRIC_LOGLUV;
        
        // Samples per pixel depends on photometric interpretation
        uint16_t samples_per_pixel = (photometric == PHOTOMETRIC_LOGL) ? 1 : 3;
        
        // Bits per sample for LogLuv (typically 8, 16, or 32)
        const uint16_t bits_per_sample_values[] = {8, 16, 32};
        uint16_t bits_per_sample_idx = fdp.ConsumeIntegral<uint16_t>() % 3;
        uint16_t bits_per_sample = bits_per_sample_values[bits_per_sample_idx];
        
        // Set basic TIFF directory fields for LogLuv
        TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, width);
        TIFFSetField(tif, TIFFTAG_IMAGELENGTH, height);
        TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, samples_per_pixel);
        TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, bits_per_sample);
        TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, photometric);
        TIFFSetField(tif, TIFFTAG_COMPRESSION, compression);
        
        // Set planar configuration (contiguous for LogLuv)
        TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
        
        // Set LogLuv-specific tags
        // SGILOGDATAFMT: data format for LogLuv
        const int sgidatafmt_values[] = {SGILOGDATAFMT_FLOAT, SGILOGDATAFMT_16BIT, SGILOGDATAFMT_RAW, SGILOGDATAFMT_8BIT};
        int sgidatafmt_idx = fdp.ConsumeIntegral<uint8_t>() % 4;
        int sgidatafmt = sgidatafmt_values[sgidatafmt_idx];
        TIFFSetField(tif, TIFFTAG_SGILOGDATAFMT, sgidatafmt);
        
        // SGILOGENCODE: encoding method (dithering)
        const int sgiencode_values[] = {SGILOGENCODE_NODITHER, SGILOGENCODE_RANDITHER};
        int sgiencode_idx = fdp.ConsumeIntegral<uint8_t>() % 2;
        int sgiencode = sgiencode_values[sgiencode_idx];
        TIFFSetField(tif, TIFFTAG_SGILOGENCODE, sgiencode);
        
        // Calculate image buffer size for pixel data
        size_t pixel_size = (size_t)width * height * samples_per_pixel * (bits_per_sample / 8);
        
        // Generate pixel data from fuzzed input if we have enough
        if (fdp.remaining_bytes() >= 100 && pixel_size > 0 && pixel_size < 65536) {
            // Limit pixel size to prevent OOM
            size_t actual_pixel_size = std::min(pixel_size, (size_t)65536);
            
            if (fdp.remaining_bytes() >= actual_pixel_size) {
                std::vector<uint8_t> pixel_data = fdp.ConsumeBytes<uint8_t>(actual_pixel_size);
                
                // Write pixel data based on image configuration
                if (TIFFIsTiled(tif)) {
                    // Write as tiles if tiled configuration
                    uint32_t tile_width = 0, tile_height = 0;
                    TIFFGetField(tif, TIFFTAG_TILEWIDTH, &tile_width);
                    TIFFGetField(tif, TIFFTAG_TILELENGTH, &tile_height);
                    
                    if (tile_width == 0 || tile_height == 0) {
                        // Set default tile size if not already set
                        tile_width = std::min(width, (uint32_t)256);
                        tile_height = std::min(height, (uint32_t)256);
                        TIFFSetField(tif, TIFFTAG_TILEWIDTH, tile_width);
                        TIFFSetField(tif, TIFFTAG_TILELENGTH, tile_height);
                    }
                    
                    // Write tile data
                    tmsize_t tile_size = TIFFTileSize(tif);
                    if (tile_size > 0 && tile_size <= actual_pixel_size) {
                        // Write first tile if we have data
                        TIFFWriteTile(tif, pixel_data.data(), 0, 0, 0, 0);
                    }
                } else {
                    // Write as scanlines
                    for (uint32_t row = 0; row < height; row++) {
                        if (row * width * samples_per_pixel * (bits_per_sample / 8) < pixel_data.size()) {
                            uint8_t* row_data = pixel_data.data() + (row * width * samples_per_pixel * (bits_per_sample / 8));
                            TIFFWriteScanline(tif, row_data, row, 0);
                        }
                    }
                }
            }
        }
        
        // Write directory
        TIFFWriteDirectory(tif);
        TIFFClose(tif);
        
    } else {
        /**********************************************************************
         * TEST LOGLUV READING
         **********************************************************************/
        
        // First create a LogLuv file with fuzzed data
        FILE* tmpfile = fopen(filename, "wb");
        if (!tmpfile) {
            return 0;
        }
        
        // Write fuzzed data to temporary file
        size_t write_size = fdp.ConsumeIntegralInRange<size_t>(200, std::min(size, (size_t)1048576));
        auto file_data = fdp.ConsumeBytes<uint8_t>(write_size);
        fwrite(file_data.data(), 1, file_data.size(), tmpfile);
        fclose(tmpfile);
        
        // Open the TIFF file for reading
        TIFF* tif = TIFFOpen(filename, "r");
        if (!tif) {
            remove(filename);
            return 0;
        }
        
        // Get basic image dimensions
        uint32_t width = 0, height = 0;
        TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &width);
        TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &height);
        
        // Get compression type to check if it's LogLuv
        uint16_t compression = 0;
        TIFFGetField(tif, TIFFTAG_COMPRESSION, &compression);
        
        // Get photometric interpretation
        uint16_t photometric = 0;
        TIFFGetField(tif, TIFFTAG_PHOTOMETRIC, &photometric);
        
        // Check if this is a LogLuv file
        bool is_logluv = (compression == COMPRESSION_SGILOG || compression == COMPRESSION_SGILOG24) ||
                        (photometric == PHOTOMETRIC_LOGL || photometric == PHOTOMETRIC_LOGLUV);
        
        if (is_logluv && width > 0 && height > 0 && width <= 4096 && height <= 4096) {
            // Try to get LogLuv-specific tags
            int sgidatafmt = 0;
            int sgiencode = 0;
            
            TIFFGetField(tif, TIFFTAG_SGILOGDATAFMT, &sgidatafmt);
            TIFFGetField(tif, TIFFTAG_SGILOGENCODE, &sgiencode);
            
            // Calculate buffer size for reading
            uint16_t samples_per_pixel = 0;
            uint16_t bits_per_sample = 0;
            TIFFGetField(tif, TIFFTAG_SAMPLESPERPIXEL, &samples_per_pixel);
            TIFFGetField(tif, TIFFTAG_BITSPERSAMPLE, &bits_per_sample);
            
            if (samples_per_pixel > 0 && bits_per_sample > 0) {
                size_t read_buffer_size = (size_t)width * height * samples_per_pixel * (bits_per_sample / 8);
                
                // Limit buffer size to prevent OOM
                if (read_buffer_size > 0 && read_buffer_size <= 16777216) { // 16MB max
                    uint8_t* buffer = (uint8_t*)_TIFFmalloc(read_buffer_size);
                    if (buffer) {
                        // Test different reading strategies based on fuzzed input
                        uint8_t read_strategy = fdp.ConsumeIntegral<uint8_t>() % 3;
                        
                        if (TIFFIsTiled(tif)) {
                            // Read tile by tile
                            uint32_t tile_width = 0, tile_height = 0;
                            TIFFGetField(tif, TIFFTAG_TILEWIDTH, &tile_width);
                            TIFFGetField(tif, TIFFTAG_TILELENGTH, &tile_height);
                            
                            if (tile_width > 0 && tile_height > 0) {
                                tmsize_t tile_size = TIFFTileSize(tif);
                                if (tile_size > 0 && tile_size <= read_buffer_size) {
                                    // Read first tile
                                    TIFFReadTile(tif, buffer, 0, 0, 0, 0);
                                }
                            }
                        } else {
                            // Read scanline by scanline
                            uint32_t rows_to_read = fdp.ConsumeIntegralInRange<uint32_t>(1, height);
                            rows_to_read = std::min(rows_to_read, height);
                            
                            for (uint32_t row = 0; row < rows_to_read; row++) {
                                TIFFReadScanline(tif, buffer + (row * width * samples_per_pixel * (bits_per_sample / 8)), row, 0);
                            }
                        }
                        
                        _TIFFfree(buffer);
                    }
                }
            }
            
            // Test reading entire strips if strip-based
            tmsize_t strip_size = TIFFStripSize(tif);
            uint32_t strips_per_image = TIFFNumberOfStrips(tif);
            
            if (strip_size > 0 && strip_size <= 65536 && strips_per_image > 0) {
                uint8_t* strip_buffer = (uint8_t*)_TIFFmalloc(strip_size);
                if (strip_buffer) {
                    // Read a few strips based on fuzzed input
                    uint32_t strips_to_read = fdp.ConsumeIntegralInRange<uint32_t>(1, std::min(strips_per_image, (uint32_t)10));
                    
                    for (uint32_t strip = 0; strip < strips_to_read; strip++) {
                        TIFFReadEncodedStrip(tif, strip, strip_buffer, strip_size);
                    }
                    
                    _TIFFfree(strip_buffer);
                }
            }
        }
        
        // Clean up
        TIFFClose(tif);
        remove(filename);
    }
    
    return 0;
}
