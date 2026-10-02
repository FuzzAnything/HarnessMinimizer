/*
 * Fuzzing harness for libaom AV1 film grain synthesis (grain_synthesis.c)
 * Targets completely uncovered film grain synthesis module (600 lines, 0% coverage)
 * 
 * Coverage guidance focus: grain_synthesis.c has 0% coverage across all metrics
 * Critical gap in AV1 decoder's film grain synthesis feature
 * 
 * Target API: av1_add_film_grain() - main film grain synthesis function
 * 
 * Film grain synthesis is an AV1 feature for adding synthetic film grain to decoded video
 * to mimic the look of analog film or hide compression artifacts
 * 
 * Key components to test:
 * 1. Film grain parameter structure (aom_film_grain_t) initialization
 * 2. Source image creation with various formats and bit depths
 * 3. Destination image allocation
 * 4. Film grain synthesis application with different configurations
 * 5. Edge cases in grain synthesis algorithm
 * 6. Memory management for grain tables and intermediate buffers
 * 
 * Different from existing harnesses (000-015):
 * 1. First harness to specifically target film grain synthesis API
 * 2. Tests av1_add_film_grain() directly rather than through decoder control
 * 3. Exercises all film grain parameters: scaling points, AR coefficients, chroma adjustments
 * 4. Tests various bit depths (8, 10, 12-bit) as film grain depends on bit depth
 * 5. Tests different image formats (I420, I422, I444) for comprehensive coverage
 * 6. Focuses on grain_synthesis.c which has 0% coverage in existing fuzzing
 * 7. Tests error conditions with invalid grain parameters
 */

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>
#include <algorithm>

#include "fuzzer/FuzzedDataProvider.h"
#include "aom/aom.h"
#include "aom/aom_image.h"
#include "aom/aom_codec.h"

// Define film grain structures locally since headers aren't installed in fuzzer build
// Based on /root/src/libaom/aom_dsp/grain_params.h

typedef struct {
  int apply_grain;
  int update_parameters;
  int scaling_points_y[14][2];
  int num_y_points;
  int scaling_points_cb[10][2];
  int num_cb_points;
  int scaling_points_cr[10][2];
  int num_cr_points;
  int scaling_shift;
  int ar_coeff_lag;
  int ar_coeffs_y[24];
  int ar_coeffs_cb[25];
  int ar_coeffs_cr[25];
  int ar_coeff_shift;
  int cb_mult;
  int cb_luma_mult;
  int cb_offset;
  int cr_mult;
  int cr_luma_mult;
  int cr_offset;
  int overlap_flag;
  int clip_to_restricted_range;
  unsigned int bit_depth;
  int chroma_scaling_from_luma;
  int grain_scale_shift;
  uint16_t random_seed;
} aom_film_grain_t;

// Declare av1_add_film_grain function prototype
extern "C" {
int av1_add_film_grain(const aom_film_grain_t *grain_params,
                       const aom_image_t *src, aom_image_t *dst);
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum input size: grain parameters + basic image info
    const size_t MIN_INPUT_SIZE = sizeof(uint8_t) * 20 + sizeof(int16_t) * 100 + 256;
    if (size < MIN_INPUT_SIZE) {
        return 0;  // Not enough data for meaningful film grain testing
    }

    FuzzedDataProvider fdp(data, size);

    // ========== Phase 1: Consume Film Grain Parameters ==========
    // Fixed-size parameters first
    bool apply_grain = fdp.ConsumeBool();
    bool update_parameters = fdp.ConsumeBool();
    
    // Scaling points for Y channel (0-14 points)
    int num_y_points = fdp.ConsumeIntegralInRange<int>(0, 14);
    int scaling_points_y[14][2];
    for (int i = 0; i < num_y_points; i++) {
        scaling_points_y[i][0] = fdp.ConsumeIntegralInRange<int>(0, 255);
        scaling_points_y[i][1] = fdp.ConsumeIntegralInRange<int>(0, 255);
    }
    
    // Scaling points for Cb channel (0-10 points)
    int num_cb_points = fdp.ConsumeIntegralInRange<int>(0, 10);
    int scaling_points_cb[10][2];
    for (int i = 0; i < num_cb_points; i++) {
        scaling_points_cb[i][0] = fdp.ConsumeIntegralInRange<int>(0, 255);
        scaling_points_cb[i][1] = fdp.ConsumeIntegralInRange<int>(0, 255);
    }
    
    // Scaling points for Cr channel (0-10 points)
    int num_cr_points = fdp.ConsumeIntegralInRange<int>(0, 10);
    int scaling_points_cr[10][2];
    for (int i = 0; i < num_cr_points; i++) {
        scaling_points_cr[i][0] = fdp.ConsumeIntegralInRange<int>(0, 255);
        scaling_points_cr[i][1] = fdp.ConsumeIntegralInRange<int>(0, 255);
    }
    
    // Scaling shift (8-11)
    int scaling_shift = fdp.ConsumeIntegralInRange<int>(8, 11);
    
    // AR coefficients lag (0-3)
    int ar_coeff_lag = fdp.ConsumeIntegralInRange<int>(0, 3);
    
    // AR coefficients for Y channel (up to 24 coefficients)
    int ar_coeffs_y[24];
    int max_y_coeffs = (ar_coeff_lag * 2 + 1) * (ar_coeff_lag * 2 + 1);
    int actual_y_coeffs = std::min(max_y_coeffs, 24);
    for (int i = 0; i < actual_y_coeffs; i++) {
        ar_coeffs_y[i] = fdp.ConsumeIntegralInRange<int>(-128, 127);
    }
    
    // AR coefficients for Cb channel (up to 25 coefficients)
    int ar_coeffs_cb[25];
    int max_cb_coeffs = (ar_coeff_lag * 2 + 1) * (ar_coeff_lag * 2 + 1) + 1;
    int actual_cb_coeffs = std::min(max_cb_coeffs, 25);
    for (int i = 0; i < actual_cb_coeffs; i++) {
        ar_coeffs_cb[i] = fdp.ConsumeIntegralInRange<int>(-128, 127);
    }
    
    // AR coefficients for Cr channel (up to 25 coefficients)
    int ar_coeffs_cr[25];
    int max_cr_coeffs = (ar_coeff_lag * 2 + 1) * (ar_coeff_lag * 2 + 1) + 1;
    int actual_cr_coeffs = std::min(max_cr_coeffs, 25);
    for (int i = 0; i < actual_cr_coeffs; i++) {
        ar_coeffs_cr[i] = fdp.ConsumeIntegralInRange<int>(-128, 127);
    }
    
    // AR coefficient shift (6-9)
    int ar_coeff_shift = fdp.ConsumeIntegralInRange<int>(6, 9);
    
    // Chroma multipliers and offsets (8-9 bit ranges)
    int cb_mult = fdp.ConsumeIntegralInRange<int>(0, 255);
    int cb_luma_mult = fdp.ConsumeIntegralInRange<int>(0, 255);
    int cb_offset = fdp.ConsumeIntegralInRange<int>(0, 511);
    
    int cr_mult = fdp.ConsumeIntegralInRange<int>(0, 255);
    int cr_luma_mult = fdp.ConsumeIntegralInRange<int>(0, 255);
    int cr_offset = fdp.ConsumeIntegralInRange<int>(0, 511);
    
    // Flags
    bool overlap_flag = fdp.ConsumeBool();
    bool clip_to_restricted_range = fdp.ConsumeBool();
    bool chroma_scaling_from_luma = fdp.ConsumeBool();
    
    // Grain scale shift and bit depth
    int grain_scale_shift = fdp.ConsumeIntegralInRange<int>(0, 3);
    unsigned int bit_depth = fdp.ConsumeIntegralInRange<unsigned int>(8, 12);
    
    // Random seed
    uint16_t random_seed = fdp.ConsumeIntegral<uint16_t>();

    // ========== Phase 2: Image Configuration ==========
    uint8_t img_format_choice = fdp.ConsumeIntegral<uint8_t>() % 4; // 0: I420, 1: I422, 2: I444, 3: I42016
    uint16_t width = fdp.ConsumeIntegralInRange<uint16_t>(16, 128);  // Small size for performance
    uint16_t height = fdp.ConsumeIntegralInRange<uint16_t>(16, 128);
    unsigned int align = 32;  // Standard alignment
    
    // Map format choice
    aom_img_fmt_t fmt;
    switch (img_format_choice) {
        case 0: fmt = AOM_IMG_FMT_I420; break;
        case 1: fmt = AOM_IMG_FMT_I422; break;
        case 2: fmt = AOM_IMG_FMT_I444; break;
        case 3: fmt = AOM_IMG_FMT_I42016; break;
        default: fmt = AOM_IMG_FMT_I420; break;
    }
    
    // Adjust bit depth based on format
    if (fmt & AOM_IMG_FMT_HIGHBITDEPTH) {
        bit_depth = fdp.ConsumeIntegralInRange<unsigned int>(10, 12);
    } else {
        bit_depth = 8;
    }

    // ========== Phase 3: Prepare Film Grain Parameters ==========
    aom_film_grain_t grain_params;
    memset(&grain_params, 0, sizeof(grain_params));
    
    grain_params.apply_grain = apply_grain ? 1 : 0;
    grain_params.update_parameters = update_parameters ? 1 : 0;
    
    // Copy scaling points
    memcpy(grain_params.scaling_points_y, scaling_points_y, sizeof(scaling_points_y));
    grain_params.num_y_points = num_y_points;
    
    memcpy(grain_params.scaling_points_cb, scaling_points_cb, sizeof(scaling_points_cb));
    grain_params.num_cb_points = num_cb_points;
    
    memcpy(grain_params.scaling_points_cr, scaling_points_cr, sizeof(scaling_points_cr));
    grain_params.num_cr_points = num_cr_points;
    
    grain_params.scaling_shift = scaling_shift;
    grain_params.ar_coeff_lag = ar_coeff_lag;
    
    // Copy AR coefficients
    memcpy(grain_params.ar_coeffs_y, ar_coeffs_y, sizeof(ar_coeffs_y));
    memcpy(grain_params.ar_coeffs_cb, ar_coeffs_cb, sizeof(ar_coeffs_cb));
    memcpy(grain_params.ar_coeffs_cr, ar_coeffs_cr, sizeof(ar_coeffs_cr));
    
    grain_params.ar_coeff_shift = ar_coeff_shift;
    grain_params.cb_mult = cb_mult;
    grain_params.cb_luma_mult = cb_luma_mult;
    grain_params.cb_offset = cb_offset;
    grain_params.cr_mult = cr_mult;
    grain_params.cr_luma_mult = cr_luma_mult;
    grain_params.cr_offset = cr_offset;
    grain_params.overlap_flag = overlap_flag ? 1 : 0;
    grain_params.clip_to_restricted_range = clip_to_restricted_range ? 1 : 0;
    grain_params.bit_depth = bit_depth;
    grain_params.chroma_scaling_from_luma = chroma_scaling_from_luma ? 1 : 0;
    grain_params.grain_scale_shift = grain_scale_shift;
    grain_params.random_seed = random_seed;

    // ========== Phase 4: Create Source and Destination Images ==========
    aom_image_t src_img, dst_img;
    aom_image_t* src = aom_img_alloc(&src_img, fmt, width, height, align);
    aom_image_t* dst = aom_img_alloc(&dst_img, fmt, width, height, align);
    
    if (!src || !dst) {
        if (src) aom_img_free(src);
        if (dst) aom_img_free(dst);
        return 0;
    }
    
    // Set bit depth for high bit depth formats
    if (fmt & AOM_IMG_FMT_HIGHBITDEPTH) {
        src->bit_depth = bit_depth;
        dst->bit_depth = bit_depth;
    }
    
    // Fill source image with some data from remaining fuzzer input
    size_t remaining_bytes = fdp.remaining_bytes();
    if (remaining_bytes > 0) {
        std::vector<uint8_t> image_data = fdp.ConsumeRemainingBytes<uint8_t>();
        
        // Fill image planes with data (simplified - real implementation would respect plane layout)
        // For fuzzing purposes, we just need some non-zero data
        for (int plane = 0; plane < 3; plane++) {
            uint8_t* plane_ptr = src->planes[plane];
            if (!plane_ptr) continue;
            
            int plane_width = aom_img_plane_width(src, plane);
            int plane_height = aom_img_plane_height(src, plane);
            size_t plane_stride = src->stride[plane];
            size_t bytes_per_sample = (fmt & AOM_IMG_FMT_HIGHBITDEPTH) ? 2 : 1;
            
            for (int y = 0; y < plane_height; y++) {
                for (int x = 0; x < plane_width; x++) {
                    // Simple pattern for testing
                    size_t idx = (y * plane_width + x) % image_data.size();
                    uint8_t value = image_data[idx];
                    
                    if (fmt & AOM_IMG_FMT_HIGHBITDEPTH) {
                        // For high bit depth, store 10-12 bit values
                        uint16_t* sample_ptr = reinterpret_cast<uint16_t*>(plane_ptr + y * plane_stride + x * 2);
                        *sample_ptr = (value << (bit_depth - 8)) | (value >> (16 - bit_depth));
                    } else {
                        // For 8-bit, just store the value
                        plane_ptr[y * plane_stride + x] = value;
                    }
                }
            }
        }
    }

    // ========== Phase 5: Apply Film Grain Synthesis ==========
    // This is the main target API - will exercise grain_synthesis.c
    int result = av1_add_film_grain(&grain_params, src, dst);
    
    // Result can be 0 for success or -1 for failure
    // Both are valid outcomes for fuzzing

    // ========== Phase 6: Cleanup ==========
    aom_img_free(src);
    aom_img_free(dst);

    return 0;
}
