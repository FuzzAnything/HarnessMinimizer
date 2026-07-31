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
        // Need enough data for meaningful LogLuv operations
        return 0;
    }

    // Set error handlers to avoid printing to stderr during fuzzing
    TIFFSetErrorHandler(handle_error);
    TIFFSetWarningHandler(handle_error);

    FuzzedDataProvider fdp(data, size);
    
    // Consume fuzzer input for operation selection and parameters
    uint8_t operation_mode = fdp.ConsumeIntegral<uint8_t>();
    uint8_t compression_type = fdp.ConsumeIntegral<uint8_t>() % 2; // 0: SGILOG, 1: SGILOG24
    uint8_t data_format = fdp.ConsumeIntegral<uint8_t>() % 3; // 0: FLOAT, 1: 16BIT, 2: RAW
    bool create_new_file = fdp.ConsumeBool();
    bool test_color_conversions = fdp.ConsumeBool();
    
    // Consume parameters for image dimensions
    uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 512);
    uint16_t samples_per_pixel = fdp.ConsumeIntegralInRange<uint16_t>(1, 4);
    
    // Consume parameters for color conversion testing
    float xyz_values[3];
    for (int i = 0; i < 3; i++) {
        xyz_values[i] = fdp.ConsumeFloatingPoint<float>();
    }
    int encode_method = fdp.ConsumeIntegralInRange<int>(0, 2); // 0-2: different encoding methods
    
    // Use remaining bytes as TIFF data (minimum 50 bytes for basic TIFF)
    if (fdp.remaining_bytes() < 50) {
        return 0;
    }
    std::vector<uint8_t> tiff_data = fdp.ConsumeRemainingBytes<uint8_t>();
    
    if (tiff_data.empty()) {
        return 0;
    }

    // Create a temporary file with the TIFF data
    char temp_filename_buffer[] = "/tmp/temp_tiff_logluv_XXXXXX.tiff";
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
    TIFF* tif = nullptr;
    if (create_new_file) {
        // Open for writing to create LogLuv file
        tif = TIFFOpen(temp_filename, "w+");
    } else {
        // Open for reading existing LogLuv data
        tif = TIFFOpen(temp_filename, "r");
    }
    
    if (!tif) {
        // Try with TIFFFdOpen as fallback
        temp_fd = open(temp_filename, create_new_file ? O_RDWR : O_RDONLY);
        if (temp_fd < 0) {
            unlink(temp_filename);
            return 0;
        }
        tif = TIFFFdOpen(temp_fd, temp_filename, create_new_file ? "w+" : "r");
        if (!tif) {
            close(temp_fd);
            unlink(temp_filename);
            return 0;
        }
    }

    // Step 2: Configure LogLuv compression if creating new file
    if (create_new_file) {
        // Set basic image parameters
        TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, width);
        TIFFSetField(tif, TIFFTAG_IMAGELENGTH, height);
        TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, samples_per_pixel);
        TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 8); // LogLuv uses 8-bit samples
        
        // Set LogLuv compression
        uint16_t compression = (compression_type == 0) ? COMPRESSION_SGILOG : COMPRESSION_SGILOG24;
        TIFFSetField(tif, TIFFTAG_COMPRESSION, compression);
        
        // Set SGILOGDATAFMT for data format
        uint16_t sgilog_datafmt;
        switch (data_format) {
            case 0: sgilog_datafmt = SGILOGDATAFMT_FLOAT; break;
            case 1: sgilog_datafmt = SGILOGDATAFMT_16BIT; break;
            case 2: sgilog_datafmt = SGILOGDATAFMT_RAW; break;
            default: sgilog_datafmt = SGILOGDATAFMT_FLOAT;
        }
        TIFFSetField(tif, TIFFTAG_SGILOGDATAFMT, sgilog_datafmt);
        
        // Set photometric interpretation for LogLuv
        TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_LOGLUV);
        
        // Set planar configuration
        TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
        
        // Write a simple directory (even if no actual image data)
        TIFFWriteDirectory(tif);
    }

    // Step 3: Read directory information to access LogLuv data
    uint16_t dir_count = 0;
    do {
        dir_count++;
        
        // Get compression type to verify it's LogLuv
        uint16_t compression = 0;
        TIFFGetField(tif, TIFFTAG_COMPRESSION, &compression);
        
        // Only process LogLuv-compressed directories
        if (compression == COMPRESSION_SGILOG || compression == COMPRESSION_SGILOG24) {
            // Get SGILOGDATAFMT if available
            uint16_t sgilog_datafmt = 0;
            TIFFGetField(tif, TIFFTAG_SGILOGDATAFMT, &sgilog_datafmt);
            
            // Get image dimensions
            uint32_t img_width = 0, img_height = 0;
            TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &img_width);
            TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &img_height);
            
            // Try to read the image using TIFFReadRGBAImage (handles LogLuv decompression)
            if (img_width > 0 && img_height > 0 && img_width < 4096 && img_height < 4096) {
                uint32_t* raster = (uint32_t*)_TIFFmalloc(img_width * img_height * sizeof(uint32_t));
                if (raster) {
                    // This will trigger LogLuv decompression internally
                    TIFFReadRGBAImage(tif, img_width, img_height, raster, 0);
                    _TIFFfree(raster);
                }
            }
            
            // Test LogLuv color conversion functions if enabled
            if (test_color_conversions && LOGLUV_PUBLIC) {
                // Test LogLuv24fromXYZ
                uint32_t logluv24 = LogLuv24fromXYZ(xyz_values, encode_method);
                
                // Test LogLuv32fromXYZ (if 32-bit LogLuv is available)
                uint32_t logluv32 = LogLuv32fromXYZ(xyz_values, encode_method);
                
                // Test LogLuv24toXYZ
                float xyz_out24[3];
                LogLuv24toXYZ(logluv24, xyz_out24);
                
                // Test LogLuv32toXYZ
                float xyz_out32[3];
                LogLuv32toXYZ(logluv32, xyz_out32);
                
                // Test LogL16fromY and LogL16toY
                double y_value = xyz_values[1];
                int logl16_encoded = LogL16fromY(y_value, encode_method);
                double logl16_decoded = LogL16toY(logl16_encoded);
                
                // Test LogL10fromY and LogL10toY
                int logl10_encoded = LogL10fromY(y_value, encode_method);
                double logl10_decoded = LogL10toY(logl10_encoded);
                
                // Test uv_encode and uv_decode
                double u = 0.0, v = 0.0;
                double u_out = 0.0, v_out = 0.0;
                // Convert XYZ to UV for testing
                double s = xyz_values[0] + 15. * xyz_values[1] + 3. * xyz_values[2];
                if (s > 0.) {
                    u = 4. * xyz_values[0] / s;
                    v = 9. * xyz_values[1] / s;
                }
                int uv_encoded = uv_encode(u, v, encode_method);
                uv_decode(&u_out, &v_out, uv_encoded);
            }
            
            // Test color space conversion functions
            if (test_color_conversions) {
                // Test TIFFXYZToRGB
                TIFFCIELabToRGB cielab_to_rgb;
                TIFFDisplay display;
                float white_point[3] = {0.9505f, 1.0f, 1.0890f}; // D65 white point
                float matrix[9] = {0.4124f, 0.3576f, 0.1805f,
                                   0.2126f, 0.7152f, 0.0722f,
                                   0.0193f, 0.1192f, 0.9505f};
                
                // Initialize CIELab to RGB converter
                TIFFCIELabToRGBInit(&cielab_to_rgb, &display, white_point);
                
                // Convert XYZ to RGB
                uint32_t r, g, b;
                TIFFXYZToRGB(&cielab_to_rgb, xyz_values[0], xyz_values[1], xyz_values[2], &r, &g, &b);
                
                // Test TIFFYCbCrtoRGB
                TIFFYCbCrToRGB ycbcr_to_rgb;
                float luma_coefficients[3] = {0.299f, 0.587f, 0.114f};
                float reference_white[2] = {0.3127f, 0.3290f};
                
                // Initialize YCbCr to RGB converter
                TIFFYCbCrToRGBInit(&ycbcr_to_rgb, luma_coefficients, reference_white);
                
                // Convert YCbCr to RGB (using fuzzed values as YCbCr)
                uint32_t y = fdp.ConsumeIntegral<uint32_t>();
                int32_t cb = fdp.ConsumeIntegral<int32_t>();
                int32_t cr = fdp.ConsumeIntegral<int32_t>();
                uint32_t rgb_r, rgb_g, rgb_b;
                TIFFYCbCrtoRGB(&ycbcr_to_rgb, y, cb, cr, &rgb_r, &rgb_g, &rgb_b);
                
                // Test TIFFCIELabToXYZ
                float x_out, y_out, z_out;
                TIFFCIELabToXYZ(&cielab_to_rgb, y, cb, cr, &x_out, &y_out, &z_out);
            }
        }
        
    } while (TIFFReadDirectory(tif));

    // Step 4: Clean up
    TIFFClose(tif);
    
    // Clean up temporary file
    unlink(temp_filename);

    return 0;
}
