#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <vector>
#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <fuzzer/FuzzedDataProvider.h>

// Include libtiff headers - note: we need tiffio.h for public declarations
// and we may need to access LogLuv conversion functions directly
#include "tiffio.h"

// Error handler that does nothing (to suppress libtiff error messages during fuzzing)
extern "C" void handle_error(const char* module, const char* fmt, va_list ap) {
    // Do nothing - we want to continue fuzzing even on errors
    (void)module;
    (void)fmt;
    (void)ap;
}

// Forward declarations for LogLuv functions that might not be in public headers
// These are from tif_luv.c
extern "C" {
    // LogLuv color space conversion functions
    uint32_t LogLuv24fromXYZ(float *XYZ, int em);
    uint32_t LogLuv32fromXYZ(float *XYZ, int em);
    void LogLuv24toXYZ(uint32_t p, float *XYZ);
    void LogLuv32toXYZ(uint32_t p, float *XYZ);
    
    // Luminance conversion functions
    int LogL16fromY(double Y, int em);
    double LogL16toY(int p16);
    int LogL10fromY(double Y, int em);
    double LogL10toY(int p10);
    
    // UV coordinate encoding/decoding
    int uv_encode(double u, double v, int em);
    int uv_decode(double *u, double *v, int Ce);
    
    // XYZ to RGB24 conversion
    void XYZtoRGB24(float *xyz, uint8_t *rgb);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Set error handlers to avoid printing to stderr during fuzzing
    TIFFSetErrorHandler(handle_error);
    TIFFSetWarningHandler(handle_error);
    
    // Minimum size needed: we need at least enough for some XYZ values and parameters
    if (size < 100) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Consume parameters for TIFF file creation
    uint8_t operation_type = fdp.ConsumeIntegral<uint8_t>() % 2; // 0: TIFFOpen, 1: TIFFFdOpen
    uint8_t compression_type = fdp.ConsumeIntegral<uint8_t>() % 2; // 0: SGILOG, 1: SGILOG24
    int encode_method = fdp.ConsumeIntegralInRange<int>(0, 2);
    uint16_t sgilog_datafmt = fdp.ConsumeIntegral<uint16_t>() % 3; // 0: FLOAT, 1: 16BIT, 2: RAW
    
    // Consume image dimensions
    uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 256);
    uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 256);
    uint16_t samples_per_pixel = fdp.ConsumeIntegralInRange<uint16_t>(1, 4);
    
    // Consume XYZ coordinates for testing conversion functions
    float xyz[3];
    for (int i = 0; i < 3; i++) {
        xyz[i] = fdp.ConsumeFloatingPoint<float>();
    }
    
    // Consume additional test values
    double luminance_values[3];
    for (int i = 0; i < 3; i++) {
        luminance_values[i] = fdp.ConsumeFloatingPoint<double>();
    }
    
    // Consume UV coordinates for testing
    double u_values[2], v_values[2];
    for (int i = 0; i < 2; i++) {
        u_values[i] = fdp.ConsumeFloatingPoint<double>();
        v_values[i] = fdp.ConsumeFloatingPoint<double>();
    }
    
    // Create a temporary file for TIFF operations
    char temp_filename[] = "/tmp/temp_logluv_XXXXXX.tiff";
    int temp_fd = mkstemps(temp_filename, 5);
    if (temp_fd < 0) {
        return 0;
    }
    close(temp_fd);
    
    // Step 1: Initialize with TIFFOpen/TIFFFdOpen with LogLuv compression mode
    TIFF* tif = nullptr;
    const char* mode = "w";  // Write mode for creating LogLuv file
    
    if (operation_type == 0) {
        // Use TIFFOpen
        tif = TIFFOpen(temp_filename, mode);
    } else {
        // Use TIFFFdOpen
        temp_fd = open(temp_filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (temp_fd < 0) {
            unlink(temp_filename);
            return 0;
        }
        tif = TIFFFdOpen(temp_fd, temp_filename, mode);
    }
    
    if (!tif) {
        unlink(temp_filename);
        return 0;
    }
    
    // Step 2: Configure with TIFFSetField for LogLuv tags
    // Set basic image parameters
    TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, width);
    TIFFSetField(tif, TIFFTAG_IMAGELENGTH, height);
    TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, samples_per_pixel);
    TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 8); // LogLuv uses 8-bit samples
    
    // Set LogLuv compression
    uint16_t compression = (compression_type == 0) ? COMPRESSION_SGILOG : COMPRESSION_SGILOG24;
    TIFFSetField(tif, TIFFTAG_COMPRESSION, compression);
    
    // Set SGILOGDATAFMT for data format
    uint16_t data_format;
    switch (sgilog_datafmt) {
        case 0: data_format = SGILOGDATAFMT_FLOAT; break;
        case 1: data_format = SGILOGDATAFMT_16BIT; break;
        case 2: data_format = SGILOGDATAFMT_RAW; break;
        default: data_format = SGILOGDATAFMT_FLOAT;
    }
    TIFFSetField(tif, TIFFTAG_SGILOGDATAFMT, data_format);
    
    // Set photometric interpretation for LogLuv
    TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_LOGLUV);
    
    // Set planar configuration
    TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
    
    // Write a directory (even if no actual image data)
    TIFFWriteDirectory(tif);
    
    // Step 3: Exercise conversion functions directly
    // Test 1: XYZtoRGB24 - Convert XYZ to RGB24
    uint8_t rgb[3];
    XYZtoRGB24(xyz, rgb);
    
    // Test 2: LogLuv24fromXYZ - Encode XYZ to 24-bit LogLuv
    uint32_t logluv24_encoded = LogLuv24fromXYZ(xyz, encode_method);
    
    // Test 3: LogLuv32fromXYZ - Encode XYZ to 32-bit LogLuv
    uint32_t logluv32_encoded = LogLuv32fromXYZ(xyz, encode_method);
    
    // Test 4: LogLuv24toXYZ - Decode 24-bit LogLuv back to XYZ
    float xyz_decoded_24[3];
    LogLuv24toXYZ(logluv24_encoded, xyz_decoded_24);
    
    // Test 5: LogLuv32toXYZ - Decode 32-bit LogLuv back to XYZ
    float xyz_decoded_32[3];
    LogLuv32toXYZ(logluv32_encoded, xyz_decoded_32);
    
    // Test 6: uv_encode - Encode UV coordinates
    int uv_encoded1 = uv_encode(u_values[0], v_values[0], encode_method);
    int uv_encoded2 = uv_encode(u_values[1], v_values[1], encode_method);
    
    // Test 7: uv_decode - Decode UV coordinates
    double u_decoded1, v_decoded1;
    double u_decoded2, v_decoded2;
    uv_decode(&u_decoded1, &v_decoded1, uv_encoded1);
    uv_decode(&u_decoded2, &v_decoded2, uv_encoded2);
    
    // Test 8: LogL16fromY and LogL16toY - 16-bit luminance encoding/decoding
    int logl16_encoded1 = LogL16fromY(luminance_values[0], encode_method);
    int logl16_encoded2 = LogL16fromY(luminance_values[1], encode_method);
    
    double logl16_decoded1 = LogL16toY(logl16_encoded1);
    double logl16_decoded2 = LogL16toY(logl16_encoded2);
    
    // Test 9: LogL10fromY and LogL10toY - 10-bit luminance encoding/decoding
    int logl10_encoded1 = LogL10fromY(luminance_values[0], encode_method);
    int logl10_encoded2 = LogL10fromY(luminance_values[1], encode_method);
    int logl10_encoded3 = LogL10fromY(luminance_values[2], encode_method);
    
    double logl10_decoded1 = LogL10toY(logl10_encoded1);
    double logl10_decoded2 = LogL10toY(logl10_encoded2);
    double logl10_decoded3 = LogL10toY(logl10_encoded3);
    
    // Test 10: Test with edge case values using remaining fuzzer data
    if (fdp.remaining_bytes() > 20) {
        float edge_xyz[3];
        for (int i = 0; i < 3 && fdp.remaining_bytes() >= sizeof(float); i++) {
            edge_xyz[i] = fdp.ConsumeFloatingPoint<float>();
        }
        
        uint8_t edge_rgb[3];
        XYZtoRGB24(edge_xyz, edge_rgb);
        
        // Test round-trip with edge values
        uint32_t edge_logluv = LogLuv24fromXYZ(edge_xyz, encode_method);
        float decoded_edge_xyz[3];
        LogLuv24toXYZ(edge_logluv, decoded_edge_xyz);
    }
    
    // Step 4: Cleanup with TIFFClose
    TIFFClose(tif);
    
    // Clean up temporary file
    unlink(temp_filename);
    
    return 0;
}
