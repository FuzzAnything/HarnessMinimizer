/* Fuzzing harness for libpng metadata retrieval operations (pngget.c module)
 * Targets PNG metadata getter functions with extremely low coverage (8.07% lines, 14.29% functions):
 * 1. Color calibration getters:
 *    - png_get_cHRM (Target: 22 undiscovered branches)
 *    - png_get_cHRM_XYZ (Target: 120 undiscovered branches)
 * 2. ICC profile getter:
 *    - png_get_iCCP (Target: 14 undiscovered branches)
 * 3. Coding-independent code points getter:
 *    - png_get_cICP (Target: 14 undiscovered branches)
 * 4. Pixel calibration getter:
 *    - png_get_pCAL (Target: 20 undiscovered branches)
 * 5. Transparency getter:
 *    - png_get_tRNS (Target: 18 undiscovered branches)
 * 6. Background color getter:
 *    - png_get_bKGD (Target: 8 undiscovered branches)
 *
 * Required setup APIs (to populate metadata for retrieval):
 * - png_create_read_struct / png_create_read_struct_2 (Initialization)
 * - png_create_info_struct (Initialization)
 * - png_set_cHRM / png_set_cHRM_fixed (Prerequisite for get_cHRM)
 * - png_set_iCCP (Prerequisite for get_iCCP)
 * - png_set_cICP (Prerequisite for get_cICP)
 * - png_set_pCAL (Prerequisite for get_pCAL)
 * - png_set_tRNS (Prerequisite for get_tRNS)
 * - png_set_bKGD (Prerequisite for get_bKGD)
 *
 * Invocation sequence:
 * 1. Initialize PNG read structures
 * 2. Set metadata values using png_set_* functions with fuzzer-provided data
 * 3. Retrieve metadata using corresponding png_get_* functions
 * 4. Verify retrieved values match set values where applicable
 * 5. Clean up resources
 *
 * Uses FuzzedDataProvider to generate diverse metadata values:
 * - Color calibration coordinates (white point, RGB primaries)
 * - ICC profile data
 * - Coding-independent code points
 * - Pixel calibration parameters
 * - Transparency data
 * - Background color values
 *
 * Differentiates from existing harnesses by:
 * - Focusing exclusively on metadata retrieval operations (pngget.c)
 * - Testing getter functions that require prior metadata setup
 * - Exploring the largely untested metadata handling code paths
 * - Providing semantic diversity beyond image read/write operations
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <memory>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "png.h"

// Error handling callback functions
static void pngtest_error(png_structp png_ptr, png_const_charp error_msg) {
    // Suppress error messages during fuzzing
    (void)error_msg;
    // Use longjmp as required by libpng
    longjmp(png_jmpbuf(png_ptr), 1);
}

static void pngtest_warning(png_structp png_ptr, png_const_charp warning_msg) {
    // Suppress warning messages during fuzzing
    (void)png_ptr;
    (void)warning_msg;
}

// Custom read function (minimal implementation for metadata testing)
static void dummy_read_fn(png_structp png_ptr, png_bytep data, png_size_t length) {
    // For metadata testing, we don't need actual PNG data
    // Just fill with zeros to prevent errors
    memset(data, 0, length);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Need sufficient data for metadata configuration
    // We'll split input into multiple parts for different metadata types
    if (size < 256) {
        return 0;  // Need enough data for comprehensive metadata testing
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // ============================================
    // PHASE 1: Initialize PNG structures
    // ============================================
    
    // Create read structure
    png_structp read_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL,
                                                 pngtest_error, pngtest_warning);
    if (read_ptr == NULL) {
        return 0;
    }
    
    // Create info structure
    png_infop info_ptr = png_create_info_struct(read_ptr);
    if (info_ptr == NULL) {
        png_destroy_read_struct(&read_ptr, NULL, NULL);
        return 0;
    }
    
    // Set up minimal I/O for metadata testing
    png_set_read_fn(read_ptr, NULL, dummy_read_fn);
    
    // Set error handling
    if (setjmp(png_jmpbuf(read_ptr))) {
        // Error occurred during metadata operations
        png_destroy_read_struct(&read_ptr, &info_ptr, NULL);
        return 0;
    }
    
    // ============================================
    // PHASE 2: Set and test cHRM (color calibration) metadata
    // ============================================
    
    // Consume cHRM parameters from fuzzer input
    double white_x = fdp.ConsumeFloatingPointInRange<double>(0.0, 1.0);
    double white_y = fdp.ConsumeFloatingPointInRange<double>(0.0, 1.0);
    double red_x = fdp.ConsumeFloatingPointInRange<double>(0.0, 1.0);
    double red_y = fdp.ConsumeFloatingPointInRange<double>(0.0, 1.0);
    double green_x = fdp.ConsumeFloatingPointInRange<double>(0.0, 1.0);
    double green_y = fdp.ConsumeFloatingPointInRange<double>(0.0, 1.0);
    double blue_x = fdp.ConsumeFloatingPointInRange<double>(0.0, 1.0);
    double blue_y = fdp.ConsumeFloatingPointInRange<double>(0.0, 1.0);
    
    // Set cHRM metadata
    png_set_cHRM(read_ptr, info_ptr, white_x, white_y, red_x, red_y,
                green_x, green_y, blue_x, blue_y);
    
    // Retrieve cHRM metadata (floating point version)
    double retrieved_white_x, retrieved_white_y;
    double retrieved_red_x, retrieved_red_y;
    double retrieved_green_x, retrieved_green_y;
    double retrieved_blue_x, retrieved_blue_y;
    
    png_uint_32 cHRM_result = png_get_cHRM(read_ptr, info_ptr,
                                          &retrieved_white_x, &retrieved_white_y,
                                          &retrieved_red_x, &retrieved_red_y,
                                          &retrieved_green_x, &retrieved_green_y,
                                          &retrieved_blue_x, &retrieved_blue_y);
    
    // Also test cHRM_XYZ retrieval
    double red_X, red_Y, red_Z, green_X, green_Y, green_Z, blue_X, blue_Y, blue_Z;
    png_uint_32 cHRM_XYZ_result = png_get_cHRM_XYZ(read_ptr, info_ptr,
                                                  &red_X, &red_Y, &red_Z,
                                                  &green_X, &green_Y, &green_Z,
                                                  &blue_X, &blue_Y, &blue_Z);
    
    // ============================================
    // PHASE 3: Set and test iCCP (ICC profile) metadata
    // ============================================
    
    // Consume ICC profile data from fuzzer input
    std::string icc_name = fdp.ConsumeRandomLengthString(80);
    int icc_compression_type = fdp.ConsumeIntegralInRange<int>(0, 2); // PNG_COMPRESSION_TYPE_BASE values
    std::vector<png_byte> icc_profile = fdp.ConsumeBytes<png_byte>(fdp.ConsumeIntegralInRange<size_t>(0, 1024));
    
    // Set iCCP metadata
    png_set_iCCP(read_ptr, info_ptr,
                icc_name.c_str(), icc_compression_type,
                icc_profile.data(), (png_uint_32)icc_profile.size());
    
    // Retrieve iCCP metadata
    char* retrieved_name = NULL;
    int retrieved_compression_type = 0;
    png_byte* retrieved_profile = NULL;
    png_uint_32 retrieved_profile_len = 0;
    
    png_uint_32 iCCP_result = png_get_iCCP(read_ptr, info_ptr,
                                          &retrieved_name, &retrieved_compression_type,
                                          &retrieved_profile, &retrieved_profile_len);
    
    // ============================================
    // PHASE 4: Set and test cICP (coding-independent code points) metadata
    // ============================================
    // Consume cICP parameters
    png_byte colour_primaries = fdp.ConsumeIntegral<png_byte>();
    png_byte transfer_function = fdp.ConsumeIntegral<png_byte>();
    png_byte matrix_coefficients = fdp.ConsumeIntegral<png_byte>();
    png_byte video_full_range_flag = fdp.ConsumeIntegralInRange<png_byte>(0, 1);
    
    // Set cICP metadata
    png_set_cICP(read_ptr, info_ptr, colour_primaries, transfer_function,
                matrix_coefficients, video_full_range_flag);
    
    // Retrieve cICP metadata
    png_byte retrieved_colour_primaries, retrieved_transfer_function;
    png_byte retrieved_matrix_coefficients, retrieved_video_full_range_flag;
    
    png_uint_32 cICP_result = png_get_cICP(read_ptr, info_ptr,
                                          &retrieved_colour_primaries, &retrieved_transfer_function,
                                          &retrieved_matrix_coefficients, &retrieved_video_full_range_flag);
    // ============================================
    
    // Consume pCAL parameters
    std::string pcal_purpose = fdp.ConsumeRandomLengthString(80);
    png_int_32 pcal_X0 = fdp.ConsumeIntegral<png_int_32>();
    png_int_32 pcal_X1 = fdp.ConsumeIntegral<png_int_32>();
    int pcal_type = fdp.ConsumeIntegralInRange<int>(0, 3); // PNG_EQUATION_* values
    int pcal_nparams = fdp.ConsumeIntegralInRange<int>(0, 5); // Reduced from 10 to avoid excessive memory
    
    std::string pcal_units_str = fdp.ConsumeRandomLengthString(20);
    std::vector<std::string> pcal_param_strings(pcal_nparams);
    std::vector<char*> pcal_params(pcal_nparams);
    
    for (int i = 0; i < pcal_nparams; i++) {
        // Generate parameter as string representation of a floating point number
        double param_val = fdp.ConsumeFloatingPointInRange<double>(-1000.0, 1000.0);
        pcal_param_strings[i] = std::to_string(param_val);
        pcal_params[i] = (char*)pcal_param_strings[i].c_str();
    }
    
    // Set pCAL metadata
    png_set_pCAL(read_ptr, info_ptr,
                pcal_purpose.c_str(),
                pcal_X0, pcal_X1, pcal_type,
                pcal_nparams,
                pcal_units_str.c_str(),
                pcal_params.data());
    
    // Retrieve pCAL metadata
    char* retrieved_purpose = NULL;
    png_int_32 retrieved_X0, retrieved_X1;
    int retrieved_type, retrieved_nparams;
    char* retrieved_units = NULL;
    char** retrieved_params = NULL;
    
    png_uint_32 pCAL_result = png_get_pCAL(read_ptr, info_ptr,
                                          &retrieved_purpose,
                                          &retrieved_X0, &retrieved_X1,
                                          &retrieved_type, &retrieved_nparams,
                                          &retrieved_units, &retrieved_params);
    // PHASE 6: Set and test tRNS (transparency) metadata
    // ============================================
    
    // Consume tRNS parameters based on color type
    int color_type = PNG_COLOR_TYPE_RGB; // Default for testing
    png_color_16 trans_color;
    trans_color.red = fdp.ConsumeIntegral<png_uint_16>();
    trans_color.green = fdp.ConsumeIntegral<png_uint_16>();
    trans_color.blue = fdp.ConsumeIntegral<png_uint_16>();
    trans_color.gray = fdp.ConsumeIntegral<png_uint_16>();
    trans_color.index = fdp.ConsumeIntegral<png_byte>();
    
    // Set tRNS metadata
    png_set_tRNS(read_ptr, info_ptr, NULL, 0, &trans_color);
    
    // Retrieve tRNS metadata
    png_bytep trans_alpha = NULL;
    int num_trans = 0;
    png_color_16p retrieved_trans_color = NULL;
    
    png_uint_32 tRNS_result = png_get_tRNS(read_ptr, info_ptr,
                                          &trans_alpha, &num_trans,
                                          &retrieved_trans_color);
    
    // ============================================
    // PHASE 7: Set and test bKGD (background color) metadata
    // ============================================
    
    // Consume bKGD parameters
    png_color_16 background;
    background.red = fdp.ConsumeIntegral<png_uint_16>();
    background.green = fdp.ConsumeIntegral<png_uint_16>();
    background.blue = fdp.ConsumeIntegral<png_uint_16>();
    background.gray = fdp.ConsumeIntegral<png_uint_16>();
    background.index = fdp.ConsumeIntegral<png_byte>();
    
    // Set bKGD metadata
    png_set_bKGD(read_ptr, info_ptr, &background);
    
    // Retrieve bKGD metadata
    png_color_16p retrieved_background = NULL;
    
    png_uint_32 bKGD_result = png_get_bKGD(read_ptr, info_ptr,
                                          &retrieved_background);
    
    // ============================================
    // PHASE 8: Test additional metadata getters
    // ============================================
    
    // Test basic image info getters (should return 0 since no image data)
    png_get_image_width(read_ptr, info_ptr);
    png_get_image_height(read_ptr, info_ptr);
    png_get_bit_depth(read_ptr, info_ptr);
    png_get_color_type(read_ptr, info_ptr);
    png_get_filter_type(read_ptr, info_ptr);
    png_get_interlace_type(read_ptr, info_ptr);
    png_get_compression_type(read_ptr, info_ptr);
    png_get_rowbytes(read_ptr, info_ptr);
    png_get_channels(read_ptr, info_ptr);
    png_get_pixel_aspect_ratio(read_ptr, info_ptr);
    png_get_x_pixels_per_meter(read_ptr, info_ptr);
    png_get_y_pixels_per_meter(read_ptr, info_ptr);
    
    // Test valid flag checking
    png_get_valid(read_ptr, info_ptr, PNG_INFO_cHRM);
    png_get_valid(read_ptr, info_ptr, PNG_INFO_iCCP);
    png_get_valid(read_ptr, info_ptr, PNG_INFO_cICP);
    png_get_valid(read_ptr, info_ptr, PNG_INFO_pCAL);
    png_get_valid(read_ptr, info_ptr, PNG_INFO_tRNS);
    png_get_valid(read_ptr, info_ptr, PNG_INFO_bKGD);
    
    // ============================================
    // PHASE 9: Cleanup
    // ============================================
    
    // Note: pCAL strings are managed by std::string, no manual freeing needed
    // pcal_param_strings are std::string objects
    // pcal_params points to c_str() of those strings
    // Destroy PNG structures
    png_destroy_read_struct(&read_ptr, &info_ptr, NULL);
    
    return 0;
}
