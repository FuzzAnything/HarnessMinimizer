/*
 * Libtiff fuzzing harness - LogLuv Color Space Conversion Functions
 * This harness specifically targets LogLuv color space conversion APIs as identified by
 * coverage analysis. Focuses on LogLuv color space operations, proper initialization,
 * cleanup sequence, and FuzzedDataProvider input processing.
 * 
 * Target functions from tif_luv.c:
 * 1. LogLuv24toXYZ: Convert 24-bit LogLuv to XYZ color space (4 branches, 16 undiscovered)
 * 2. LogLuv32toXYZ: Convert 32-bit LogLuv to XYZ color space (2 branches, 6 undiscovered)
 * 3. LogLuv24fromXYZ: Convert XYZ to 24-bit LogLuv (6 branches, 22 undiscovered)
 * 4. LogLuv32fromXYZ: Convert XYZ to 32-bit LogLuv (12 branches, 20 undiscovered)
 * 5. uv_encode: Encode (u',v') coordinates (12 branches, 12 undiscovered)
 * 6. uv_decode: Decode (u',v') index (10 branches, 10 undiscovered)
 * 7. LogL16fromY: Get 16-bit LogL from Y luminance (8 branches, 8 undiscovered)
 * 8. LogL10fromY: Get 10-bit LogL from Y luminance (4 branches, 4 undiscovered)
 * 9. LogL16toY: Compute luminance from 16-bit LogL (4 branches, 4 undiscovered)
 * 10. LogL10toY: Compute luminance from 10-bit LogL (2 branches, 2 undiscovered)
 * 
 * Required helper functions:
 * - TIFFInitSGILog: LogLuv codec initialization (6 branches, 14 undiscovered)
 * - TIFFOpen/TIFFFdOpen: File initialization
 * - TIFFClose: Cleanup
 * 
 * Semantic differentiation from existing harnesses:
 * - harness_000: Basic directory reading with TIFFReadDirectory
 * - harness_001: JPEG compression/decompression testing
 * - harness_023: Custom directory manipulation functions
 * - This harness (024): Specifically targets LOGLUV COLOR SPACE CONVERSION,
 *   testing direct color space conversion APIs and LogLuv codec initialization,
 *   focusing on specialized high dynamic range color space operations.
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <cmath>
#include <fuzzer/FuzzedDataProvider.h>
#include "tiffio.h"
extern "C" void handle_error(const char *module, const char *fmt, va_list ap) {
    return;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Minimum size needed for LogLuv color space testing
    // Need enough data for: XYZ coordinates, encoding method, operation type,
    // and LogLuv pixel data for conversion testing
    if (size < 128) return 0;
    
    FuzzedDataProvider fdp(data, size);
    
    // Set error handlers to suppress output
    TIFFSetErrorHandler(handle_error);
    TIFFSetWarningHandler(handle_error);
    
    // Create a temporary file name using fuzzer input
    std::string temp_filename = "/tmp/tiff_logluv_fuzz_" + 
                                fdp.ConsumeRandomLengthString(16) + ".tif";
    
    // Consume operation type from fuzzer input
    uint8_t operation = fdp.ConsumeIntegral<uint8_t>() % 4; // 0-3
    
    // Consume encoding method (dithering option)
    int encode_method = fdp.ConsumeBool() ? SGILOGENCODE_NODITHER : SGILOGENCODE_RANDITHER;
    
    // Consume compression type
    uint16_t compression = fdp.ConsumeBool() ? COMPRESSION_SGILOG : COMPRESSION_SGILOG24;
    
    // Consume photometric interpretation
    uint16_t photometric = fdp.ConsumeBool() ? PHOTOMETRIC_LOGL : PHOTOMETRIC_LOGLUV;
    
    // Consume basic image parameters
    uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 256);
    uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 256);
    uint16_t samples_per_pixel = fdp.ConsumeBool() ? 1 : 3; // 1 for grayscale, 3 for color
    
    // Open TIFF file for writing
    TIFF *tif = TIFFOpen(temp_filename.c_str(), "w+");
    if (!tif) {
        // Clean up and return if TIFF cannot be opened for writing
        return 0;
    }
    
    // Set basic TIFF tags for image
    TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, width);
    TIFFSetField(tif, TIFFTAG_IMAGELENGTH, height);
    TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, samples_per_pixel);
    TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, (compression == COMPRESSION_SGILOG) ? 16 : 8);
    TIFFSetField(tif, TIFFTAG_COMPRESSION, compression);
    TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, photometric);
    TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
    
    // Set LogLuv-specific tags
    TIFFSetField(tif, TIFFTAG_SGILOGDATAFMT, SGILOGDATAFMT_FLOAT);
    TIFFSetField(tif, TIFFTAG_SGILOGENCODE, encode_method);
    
    // Write the main image directory
    if (!TIFFWriteDirectory(tif)) {
        TIFFClose(tif);
        remove(temp_filename.c_str());
        return 0;
    }
    
    // Test direct color space conversion functions
    float xyz[3];
    uint32_t logluv_pixel;
    int result;
    
    switch (operation) {
        case 0: // Test LogLuv24 conversions
            {
                // Consume random XYZ values from fuzzer input
                xyz[0] = fdp.ConsumeFloatingPoint<float>();
                xyz[1] = fdp.ConsumeFloatingPoint<float>();
                xyz[2] = fdp.ConsumeFloatingPoint<float>();
                
                // Convert XYZ to 24-bit LogLuv
                logluv_pixel = LogLuv24fromXYZ(xyz, encode_method);
                
                // Convert back to XYZ
                float xyz_back[3];
                LogLuv24toXYZ(logluv_pixel, xyz_back);
                
                // Test uv_encode and uv_decode
                double u = fdp.ConsumeFloatingPoint<double>();
                double v = fdp.ConsumeFloatingPoint<double>();
                int chroma_index = uv_encode(u, v, encode_method);
                
                double u_back, v_back;
                result = uv_decode(&u_back, &v_back, chroma_index);
                
                // Test LogL10 functions
                double Y = fdp.ConsumeFloatingPoint<double>();
                int logl10 = LogL10fromY(Y, encode_method);
                double Y_back = LogL10toY(logl10);
            }
            break;
            
        case 1: // Test LogLuv32 conversions
            {
                // Consume random XYZ values from fuzzer input
                xyz[0] = fdp.ConsumeFloatingPoint<float>();
                xyz[1] = fdp.ConsumeFloatingPoint<float>();
                xyz[2] = fdp.ConsumeFloatingPoint<float>();
                
                // Convert XYZ to 32-bit LogLuv
                logluv_pixel = LogLuv32fromXYZ(xyz, encode_method);
                
                // Convert back to XYZ
                float xyz_back[3];
                LogLuv32toXYZ(logluv_pixel, xyz_back);
                
                // Test LogL16 functions
                double Y = fdp.ConsumeFloatingPoint<double>();
                int logl16 = LogL16fromY(Y, encode_method);
                double Y_back = LogL16toY(logl16);
                
                // Test with negative luminance
                double Y_neg = -fdp.ConsumeFloatingPointInRange<double>(0.1, 100.0);
                int logl16_neg = LogL16fromY(Y_neg, encode_method);
                double Y_neg_back = LogL16toY(logl16_neg);
            }
            break;
            
        case 2: // Test LogLuv codec with actual image data
            {
                // Write sample image data
                size_t pixel_count = width * height;
                std::vector<float> image_data;
                
                if (samples_per_pixel == 1) {
                    // Grayscale: Y values only
                    image_data.resize(pixel_count);
                    for (size_t i = 0; i < pixel_count && fdp.remaining_bytes() > 4; i++) {
                        image_data[i] = fdp.ConsumeFloatingPoint<float>();
                    }
                    
                    if (TIFFWriteEncodedStrip(tif, 0, image_data.data(), 
                                              pixel_count * sizeof(float)) == -1) {
                        // Write failed, continue with cleanup
                    }
                } else {
                    // Color: XYZ values
                    image_data.resize(pixel_count * 3);
                    for (size_t i = 0; i < pixel_count * 3 && fdp.remaining_bytes() > 4; i++) {
                        image_data[i] = fdp.ConsumeFloatingPoint<float>();
                    }
                    
                    if (TIFFWriteEncodedStrip(tif, 0, image_data.data(), 
                                              pixel_count * 3 * sizeof(float)) == -1) {
                        // Write failed, continue with cleanup
                    }
                }
                
                // Close and reopen for reading to test decoding
                TIFFClose(tif);
                tif = TIFFOpen(temp_filename.c_str(), "r");
                
                if (tif) {
                    // Read directory
                    TIFFReadDirectory(tif);
                    
                    // Read strip data (just metadata, not actual data)
                    tmsize_t strip_size = TIFFStripSize(tif);
                    uint32_t strip_count = TIFFNumberOfStrips(tif);
                    
                    // Allocate buffer for reading
                    std::vector<uint8_t> read_buffer(strip_size);
                    
                    // Try to read first strip
                    if (strip_count > 0 && strip_size > 0) {
                        TIFFReadEncodedStrip(tif, 0, read_buffer.data(), strip_size);
                    }
                }
            }
            break;
            
        case 3: // Test edge cases and boundary conditions
            {
                // Test with extreme XYZ values
                float extreme_xyz[3];
                extreme_xyz[0] = fdp.ConsumeFloatingPointInRange<float>(-1e20f, 1e20f);
                extreme_xyz[1] = fdp.ConsumeFloatingPointInRange<float>(-1e20f, 1e20f);
                extreme_xyz[2] = fdp.ConsumeFloatingPointInRange<float>(-1e20f, 1e20f);
                
                uint32_t logluv24_extreme = LogLuv24fromXYZ(extreme_xyz, encode_method);
                uint32_t logluv32_extreme = LogLuv32fromXYZ(extreme_xyz, encode_method);
                
                // Test with zero and near-zero values
                float zero_xyz[3] = {0.0f, 0.0f, 0.0f};
                uint32_t logluv24_zero = LogLuv24fromXYZ(zero_xyz, encode_method);
                uint32_t logluv32_zero = LogLuv32fromXYZ(zero_xyz, encode_method);
                
                // Test LogL16fromY with boundary values
                double Y_values[] = {
                    0.0,
                    1.8371976e19,  // Boundary from code
                    -1.8371976e19, // Boundary from code
                    5.4136769e-20, // Boundary from code
                    -5.4136769e-20 // Boundary from code
                };
                
                for (double Y_val : Y_values) {
                    int logl16_boundary = LogL16fromY(Y_val, encode_method);
                    double Y_back = LogL16toY(logl16_boundary);
                }
                
                // Test uv_encode with various (u,v) values
                for (int i = 0; i < 5 && fdp.remaining_bytes() > 16; i++) {
                    double u_test = fdp.ConsumeFloatingPointInRange<double>(-1.0, 2.0);
                    double v_test = fdp.ConsumeFloatingPointInRange<double>(-1.0, 2.0);
                    int chroma_idx = uv_encode(u_test, v_test, encode_method);
                    
                    double u_decoded, v_decoded;
                    uv_decode(&u_decoded, &v_decoded, chroma_idx);
                }
            }
            break;
    }
    
    // Clean up
    if (tif) {
        TIFFClose(tif);
    }
    remove(temp_filename.c_str());
    
    return 0;
}
