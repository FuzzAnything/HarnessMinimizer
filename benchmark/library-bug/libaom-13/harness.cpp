/*
 *
 * Fuzzing harness for libaom AV1 encoder extreme configuration validation module.
 * This harness targets specific blocked branches in validate_config function:
 *   - Line 676: if (max_frame_area > (1 << 30)) - 0 hits
 *   - Lines 723-727: if (gf_min_pyr_height > gf_max_pyr_height) - 0 hits
 *   - Additional validation logic with boundary conditions
 *
 * Also targets uncovered public APIs:
 *   - aom_codec_iface_name: 0% coverage
 *   - aom_codec_get_caps: 0% coverage
 *   - aom_codec_enc_config_set: 6 undiscovered branches (50% function lines hit)
 *   - aom_codec_control: 4 undiscovered branches (71.4% function lines hit)
 *
 * Coverage gap: 202/372 branches blocked in validate_config function.
 * Semantic differentiation from existing harnesses:
 *   - Encoder configuration validation (012): Basic validation testing
 *   - This harness: Extreme boundary condition testing + uncovered API testing
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <vector>
#include <algorithm>
#include <cstring>

#include "fuzzer/FuzzedDataProvider.h"
#include "aom/aom.h"
#include "aom/aom_codec.h"
#include "aom/aom_encoder.h"
#include "aom/aom_image.h"
#include "aom/aomcx.h"

// Minimum input size required to start fuzzing
#define MIN_INPUT_SIZE 128

// Helper function to populate image with random data
static void populate_image_with_random_data(aom_image_t *img, FuzzedDataProvider &fdp) {
    for (int plane = 0; plane < 3; ++plane) {
        unsigned char *plane_buf = img->planes[plane];
        if (plane_buf == nullptr) continue;
        
        size_t plane_height = aom_img_plane_height(img, plane);
        size_t stride = img->stride[plane];
        size_t plane_width = aom_img_plane_width(img, plane);
        
        // Fill plane with random data
        for (size_t y = 0; y < plane_height; ++y) {
            unsigned char *row = plane_buf + y * stride;
            for (size_t x = 0; x < plane_width; ++x) {
                row[x] = fdp.ConsumeIntegral<unsigned char>();
            }
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Require minimum input size
    if (size < MIN_INPUT_SIZE) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);

    // Determine which extreme validation scenario to test
    uint8_t validation_scenario = fdp.ConsumeIntegral<uint8_t>() % 8;
    
    // Initialize encoder structures
    aom_codec_ctx_t codec;
    aom_codec_enc_cfg_t cfg;
    
    // Get AV1 encoder interface
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    if (!iface) {
        return 0;
    }
    
    // Test uncovered public APIs: aom_codec_iface_name and aom_codec_get_caps
    const char* iface_name = aom_codec_iface_name(iface);
    (void)iface_name; // Use result to avoid unused variable warning
    
    int caps = aom_codec_get_caps(iface);
    (void)caps; // Use result to avoid unused variable warning
    
    // Get default configuration
    aom_codec_err_t res = aom_codec_enc_config_default(iface, &cfg, 0);
    if (res != AOM_CODEC_OK) {
        return 0;
    }
    
    // Apply extreme validation scenarios based on the coverage guidance
    switch (validation_scenario) {
        case 0:  // Test max frame area > 2^30 (line 676)
            // Set dimensions that exceed 2^30 area (1,073,741,824 pixels)
            // Example: 65536 * 16384 = 1,073,725,440 > 2^30
            cfg.g_w = fdp.ConsumeIntegralInRange<unsigned int>(40000, 65536);
            cfg.g_h = fdp.ConsumeIntegralInRange<unsigned int>(16384, 32768);
            break;
            
        case 1:  // Test invalid pyramid height relationship (lines 723-727)
            // Set gf_min_pyr_height > gf_max_pyr_height to trigger validation error
            cfg.g_usage = AOM_USAGE_GOOD_QUALITY;
            break;
            
        case 2:  // Test DeltaQ variance boost with non-ALLINTRA usage
            // This should trigger validation error according to guidance
            cfg.g_usage = AOM_USAGE_GOOD_QUALITY;  // Not ALL_INTRA
            break;
            
        case 3:  // Test large scale tile with aq_mode (invalid combination)
            cfg.large_scale_tile = 1;
            break;
            
        case 4:  // Test very small frame dimensions (edge case)
            cfg.g_w = fdp.ConsumeIntegralInRange<unsigned int>(1, 16);
            cfg.g_h = fdp.ConsumeIntegralInRange<unsigned int>(1, 16);
            break;
            
        case 5:  // Test mixed extreme parameters
            // Random combination of extreme values
            cfg.g_w = fdp.ConsumeIntegralInRange<unsigned int>(1, 65536);
            cfg.g_h = fdp.ConsumeIntegralInRange<unsigned int>(1, 65536);
            cfg.g_usage = fdp.ConsumeIntegral<uint8_t>() % (AOM_USAGE_ALL_INTRA + 1);
            cfg.large_scale_tile = fdp.ConsumeBool();
            break;
            
        case 6:  // Test aom_codec_enc_config_set with extreme config
            // Initialize with valid config first, then try to set extreme config
            cfg.g_w = fdp.ConsumeIntegralInRange<unsigned int>(16, 4096);
            cfg.g_h = fdp.ConsumeIntegralInRange<unsigned int>(16, 4096);
            break;
            
        case 7:  // Test comprehensive control parameter coverage
            // Test various encoder control parameters
            cfg.g_w = fdp.ConsumeIntegralInRange<unsigned int>(16, 4096);
            cfg.g_h = fdp.ConsumeIntegralInRange<unsigned int>(16, 4096);
            break;
    }
    
    // Set common configuration parameters (except for cases 0, 4 which have their own dimensions)
    if (validation_scenario != 0 && validation_scenario != 4) {
        // For other cases, ensure reasonable dimensions if not already set
        if (validation_scenario == 6 || validation_scenario == 7) {
            // Cases 6 and 7 already set dimensions above
        } else {
            cfg.g_w = fdp.ConsumeIntegralInRange<unsigned int>(16, 4096);
            cfg.g_h = fdp.ConsumeIntegralInRange<unsigned int>(16, 4096);
        }
    }
    
    cfg.g_timebase.num = fdp.ConsumeIntegralInRange<unsigned int>(1, 1000);
    cfg.g_timebase.den = fdp.ConsumeIntegralInRange<unsigned int>(1, 1000);
    cfg.rc_target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(1, 2000000);
    cfg.rc_max_quantizer = fdp.ConsumeIntegralInRange<unsigned int>(1, 63);
    cfg.rc_min_quantizer = fdp.ConsumeIntegralInRange<unsigned int>(1, cfg.rc_max_quantizer);
    cfg.g_threads = fdp.ConsumeIntegralInRange<unsigned int>(1, 64);
    cfg.g_profile = fdp.ConsumeIntegral<uint8_t>() % 3;
    cfg.g_bit_depth = fdp.PickValueInArray({AOM_BITS_8, AOM_BITS_10, AOM_BITS_12});
    cfg.g_input_bit_depth = fdp.ConsumeIntegralInRange<unsigned int>(8, 12);
    
    // Create test image with configured dimensions
    aom_image_t *img = aom_img_alloc(NULL, AOM_IMG_FMT_I420, cfg.g_w, cfg.g_h, 1);
    if (!img) {
        return 0;
    }
    
    // Fill image with random data
    populate_image_with_random_data(img, fdp);
    
    // Initialize encoder with initial config (triggers validate_config)
    res = aom_codec_enc_init_ver(&codec, iface, &cfg, 0, AOM_ENCODER_ABI_VERSION);
    
    // Only proceed if initialization succeeded (or we want to test config_set even if init fails?)
    if (res == AOM_CODEC_OK) {
        // Apply specific control parameters based on validation scenario
        switch (validation_scenario) {
            case 1:  // Set invalid pyramid height relationship
                {
                    // Set min > max to trigger validation error
                    unsigned int gf_min_pyr_height = fdp.ConsumeIntegralInRange<unsigned int>(3, 5);
                    unsigned int gf_max_pyr_height = fdp.ConsumeIntegralInRange<unsigned int>(1, 2);
                    
                    // Set pyramid heights (min > max is invalid)
                    aom_codec_control(&codec, AV1E_SET_GF_MIN_PYRAMID_HEIGHT, gf_min_pyr_height);
                    aom_codec_control(&codec, AV1E_SET_GF_MAX_PYRAMID_HEIGHT, gf_max_pyr_height);
                    
                    // Also set min/max gf intervals
                    unsigned int min_gf_interval = fdp.ConsumeIntegralInRange<unsigned int>(1, 10);
                    unsigned int max_gf_interval = fdp.ConsumeIntegralInRange<unsigned int>(min_gf_interval, 20);
                    aom_codec_control(&codec, AV1E_SET_MIN_GF_INTERVAL, min_gf_interval);
                    aom_codec_control(&codec, AV1E_SET_MAX_GF_INTERVAL, max_gf_interval);
                }
                break;
                
            case 2:  // Set DeltaQ variance boost with non-ALLINTRA usage
                {
                    unsigned int deltaq_mode = fdp.ConsumeIntegralInRange<unsigned int>(5, 7); // Include DELTA_Q_VARIANCE_BOOST (6)
                    aom_codec_control(&codec, AV1E_SET_DELTAQ_MODE, deltaq_mode);
                }
                break;
                
            case 3:  // Set aq_mode with large scale tile
                {
                    unsigned int aq_mode = fdp.ConsumeIntegralInRange<unsigned int>(1, 3);
                    aom_codec_control(&codec, AV1E_SET_AQ_MODE, aq_mode);
                }
                break;
                
            case 5:  // Test various control parameters
            case 7:  // Test comprehensive control parameter coverage
                {
                    // Test encoder control API coverage
                    unsigned int tile_columns = fdp.ConsumeIntegralInRange<unsigned int>(0, 6);
                    unsigned int tile_rows = fdp.ConsumeIntegralInRange<unsigned int>(0, 6);
                    unsigned int enable_cdef = fdp.ConsumeBool();
                    unsigned int enable_restoration = fdp.ConsumeBool();
                    
                    aom_codec_control(&codec, AV1E_SET_TILE_COLUMNS, tile_columns);
                    aom_codec_control(&codec, AV1E_SET_TILE_ROWS, tile_rows);
                    aom_codec_control(&codec, AV1E_SET_ENABLE_CDEF, enable_cdef);
                    aom_codec_control(&codec, AV1E_SET_ENABLE_RESTORATION, enable_restoration);
                    
                    // Test pyramid heights (both valid and potentially invalid)
                    unsigned int gf_min_pyr_height = fdp.ConsumeIntegralInRange<unsigned int>(0, 5);
                    unsigned int gf_max_pyr_height = fdp.ConsumeIntegralInRange<unsigned int>(0, 5);
                    aom_codec_control(&codec, AV1E_SET_GF_MIN_PYRAMID_HEIGHT, gf_min_pyr_height);
                    aom_codec_control(&codec, AV1E_SET_GF_MAX_PYRAMID_HEIGHT, gf_max_pyr_height);
                    
                    // Test other control parameters
                    unsigned int enable_intra_edge_filter = fdp.ConsumeBool();
                    unsigned int enable_smooth_intra = fdp.ConsumeBool();
                    unsigned int enable_paeth_intra = fdp.ConsumeBool();
                    
                    aom_codec_control(&codec, AV1E_SET_ENABLE_INTRABC, fdp.ConsumeBool());
                    aom_codec_control(&codec, AV1E_SET_ENABLE_CFL_INTRA, fdp.ConsumeBool());
                    aom_codec_control(&codec, AV1E_SET_ENABLE_FILTER_INTRA, fdp.ConsumeBool());
                    aom_codec_control(&codec, AV1E_SET_ENABLE_SMOOTH_INTRA, enable_smooth_intra);
                    aom_codec_control(&codec, AV1E_SET_ENABLE_PAETH_INTRA, enable_paeth_intra);
                    aom_codec_control(&codec, AV1E_SET_ENABLE_INTERINTRA_WEDGE, fdp.ConsumeBool());
                }
                break;
                
            case 6:  // Test aom_codec_enc_config_set with extreme config
                {
                    // Create a new config with extreme values
                    aom_codec_enc_cfg_t extreme_cfg;
                    res = aom_codec_enc_config_default(iface, &extreme_cfg, 0);
                    if (res == AOM_CODEC_OK) {
                        // Set extreme dimensions that could trigger max_frame_area > 2^30
                        extreme_cfg.g_w = fdp.ConsumeIntegralInRange<unsigned int>(40000, 65536);
                        extreme_cfg.g_h = fdp.ConsumeIntegralInRange<unsigned int>(16384, 32768);
                        
                        // Try to set the extreme config (triggers validate_config via encoder_set_config)
                        aom_codec_enc_config_set(&codec, &extreme_cfg);
                    }
                }
                break;
        }
        
        // Try to encode the image (this will trigger validate_config)
        // Even if validation fails, we want to exercise the validation logic
        aom_codec_encode(&codec, img, 0, 1, 0);
        
        // Clean up encoder
        aom_codec_destroy(&codec);
    }
    
    // Free image
    aom_img_free(img);
    
    return 0;
}
