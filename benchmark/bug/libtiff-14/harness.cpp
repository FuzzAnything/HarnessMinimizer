/* Fuzzing harness for libtiff targeting color space conversion operations */
#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>

#include <tiffio.h>

/* Error handler to suppress libtiff error messages during fuzzing */
extern "C" void handle_error(const char* unused, const char* unused2, va_list unused3) {
    // Suppress error messages during fuzzing
}

// Simple roundup function to replace TIFFroundup_32 macro
static size_t roundup_32(size_t size, size_t alignment) {
    return ((size + alignment - 1) / alignment) * alignment;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check - need enough data for configuration and operations
    if (size < 128) {
        return 0;
    }

    // Set error handlers to suppress libtiff messages
    TIFFSetErrorHandler(handle_error);
    TIFFSetWarningHandler(handle_error);

    FuzzedDataProvider fdp(data, size);

    // Consume operation type to determine which color conversion path to test
    uint8_t operation_type = fdp.ConsumeIntegral<uint8_t>() % 3;

    // Consume parameters for color space conversions
    uint32_t l_value = fdp.ConsumeIntegral<uint32_t>();
    int32_t a_value = fdp.ConsumeIntegral<int32_t>();
    int32_t b_value = fdp.ConsumeIntegral<int32_t>();
    uint32_t Y_value = fdp.ConsumeIntegral<uint32_t>();
    int32_t Cb_value = fdp.ConsumeIntegral<int32_t>();
    int32_t Cr_value = fdp.ConsumeIntegral<int32_t>();
    float X_value = fdp.ConsumeFloatingPoint<float>();
    float Y_float = fdp.ConsumeFloatingPoint<float>();
    float Z_value = fdp.ConsumeFloatingPoint<float>();
    double u_value = fdp.ConsumeFloatingPoint<double>();
    double v_value = fdp.ConsumeFloatingPoint<double>();
    
    // Consume display configuration parameters
    float refWhite[3];
    refWhite[0] = fdp.ConsumeFloatingPoint<float>();
    refWhite[1] = fdp.ConsumeFloatingPoint<float>();
    refWhite[2] = fdp.ConsumeFloatingPoint<float>();
    
    // Consume RGB conversion parameters
    float luma[3];
    float chroma[3];
    luma[0] = fdp.ConsumeFloatingPoint<float>();
    luma[1] = fdp.ConsumeFloatingPoint<float>();
    luma[2] = fdp.ConsumeFloatingPoint<float>();
    chroma[0] = fdp.ConsumeFloatingPoint<float>();
    chroma[1] = fdp.ConsumeFloatingPoint<float>();
    chroma[2] = fdp.ConsumeFloatingPoint<float>();
    
    // Consume encode method
    int encode_method = fdp.ConsumeIntegralInRange<int>(0, 3);
    
    // Allocate memory for color conversion structures
    TIFFCIELabToRGB cielab;
    TIFFYCbCrToRGB* ycbcr = nullptr;
    
    // Test different color conversion operations
    switch (operation_type) {
        case 0: {
            // Test CIE Lab to RGB conversion
            
            // Initialize display structure with reasonable values
            TIFFDisplay display;
            memset(&display, 0, sizeof(TIFFDisplay));
            
            // Set up display matrix
            for (int i = 0; i < 3; i++) {
                for (int j = 0; j < 3; j++) {
                    display.d_mat[i][j] = 0.33f;
                }
            }
            
            display.d_YCR = 1.0f;
            display.d_YCG = 1.0f;
            display.d_YCB = 1.0f;
            display.d_Vrwr = 255;
            display.d_Vrwg = 255;
            display.d_Vrwb = 255;
            display.d_Y0R = 0.0f;
            display.d_Y0G = 0.0f;
            display.d_Y0B = 0.0f;
            display.d_gammaR = 2.2f;
            display.d_gammaG = 2.2f;
            display.d_gammaB = 2.2f;
            
            // Initialize CIE Lab to RGB conversion
            int init_result = TIFFCIELabToRGBInit(&cielab, &display, refWhite);
            if (init_result == 0) {
                // Convert CIE Lab to XYZ
                float X, Y, Z;
                TIFFCIELabToXYZ(&cielab, l_value, a_value, b_value, &X, &Y, &Z);
                
                // Convert XYZ to RGB
                uint32_t r, g, b;
                TIFFXYZToRGB(&cielab, X, Y, Z, &r, &g, &b);
            }
            break;
        }
        
        case 1: {
            // Test YCbCr to RGB conversion
            
            // Allocate memory for YCbCr conversion structure
            // According to tiffio.h, we need to allocate a large buffer
            size_t buffer_size = roundup_32(sizeof(TIFFYCbCrToRGB), sizeof(long)) +
                                 4 * 256 * sizeof(TIFFRGBValue) + 
                                 2 * 256 * sizeof(int) +
                                 3 * 256 * sizeof(int32_t);
            
            ycbcr = (TIFFYCbCrToRGB*)_TIFFmalloc(buffer_size);
            if (ycbcr) {
                // Initialize YCbCr to RGB conversion
                int init_result = TIFFYCbCrToRGBInit(ycbcr, luma, chroma);
                if (init_result == 0) {
                    // Convert YCbCr to RGB
                    uint32_t r, g, b;
                    TIFFYCbCrtoRGB(ycbcr, Y_value, Cb_value, Cr_value, &r, &g, &b);
                }
                _TIFFfree(ycbcr);
            }
            break;
        }
        
        case 2: {
            // Test LogLuv and UV conversions
            
            // Test uv_encode/uv_decode
            int uv_result = uv_encode(u_value, v_value, encode_method);
            
            // Decode back
            double decoded_u, decoded_v;
            if (uv_result >= 0) {
                uv_decode(&decoded_u, &decoded_v, uv_result);
            }
            
            // Test LogLuv conversions
            float xyz[3];
            xyz[0] = X_value;
            xyz[1] = Y_float;
            xyz[2] = Z_value;
            
            // Convert XYZ to LogLuv24
            uint32_t logluv24 = LogLuv24fromXYZ(xyz, encode_method);
            
            // Convert XYZ to LogLuv32
            uint32_t logluv32 = LogLuv32fromXYZ(xyz, encode_method);
            
            // Convert LogLuv back to XYZ
            if (logluv24 != 0) {
                float xyz_out[3];
                LogLuv24toXYZ(logluv24, xyz_out);
            }
            
            if (logluv32 != 0) {
                float xyz_out[3];
                LogLuv32toXYZ(logluv32, xyz_out);
            }
            
            // Test LogL to Y conversions
            double logl16_y = LogL16toY(fdp.ConsumeIntegral<int>());
            double logl10_y = LogL10toY(fdp.ConsumeIntegral<int>());
            
            // Test Y to LogL conversions
            int logl16_from_y = LogL16fromY(fdp.ConsumeFloatingPoint<double>(), encode_method);
            int logl10_from_y = LogL10fromY(fdp.ConsumeFloatingPoint<double>(), encode_method);
            
            break;
        }
    }

    return 0;
}
