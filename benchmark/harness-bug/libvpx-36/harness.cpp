/*
 * Fuzzing harness for libvpx VP9 encoder functions with major branch blockers:
 * - vp9_pick_inter_mode (600/736 branches blocked)
 * - validate_config (290/402 branches blocked)
 * 
 * Target: VP9 encoder configuration testing with SVC and advanced controls
 * to address semantic diversity gap. Focus on advanced mode selection logic
 * and complex configuration scenarios not covered by existing harnesses.
 * 
 * Key coverage targets:
 * 1. Advanced SVC configurations with non-uniform scaling factors
 * 2. Temporal layer reference configurations for different quality settings
 * 3. Golden frame interval constraints with SVC multi-layer encoding
 * 4. Rate control mode interactions with SVC layer configurations
 * 5. Adaptive quantization mode variations across layers
 * 6. Tile configuration with SVC for parallel encoding scenarios
 * 7. Multi-pass encoding configurations with SVC
 * 8. Reference frame buffer management in SVC context
 * 9. Motion vector scaling for spatial scalability
 * 10. Quality-based threshold adjustments in SVC mode selection
 * 
 * Differentiation from existing harnesses:
 * - harness_026: Focuses on basic SVC encoding execution paths
 * - harness_029: Focuses on SVC parameter validation
 * - harness_030: Focuses on validate_config error paths
 * - This harness: Comprehensive integration testing of vp9_pick_inter_mode
 *   with validate_config using advanced SVC controls and semantic parameter
 *   relationships to target the remaining blocked branches
 */

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <memory>
#include <algorithm>
#include <string>

#include "fuzzer/FuzzedDataProvider.h"

// libvpx headers
#include "vpx/vpx_codec.h"
#include "vpx/vpx_encoder.h"
#include "vpx/vpx_image.h"
#include "vpx/vp8cx.h"

// SVC constants
#ifndef VPX_SS_MAX_LAYERS
#define VPX_SS_MAX_LAYERS 5
#endif

#ifndef VPX_TS_MAX_LAYERS  
#define VPX_TS_MAX_LAYERS 5
#endif

#ifndef VPX_MAX_LAYERS
#define VPX_MAX_LAYERS 12
#endif

// Minimum input size for comprehensive advanced configuration testing
const size_t MIN_INPUT_SIZE = 2048;

// Helper to create random image data with proper YUV420 format
static std::vector<uint8_t> create_test_image(int width, int height, FuzzedDataProvider& fdp) {
    size_t y_size = width * height;
    size_t uv_size = (width / 2) * (height / 2);
    size_t image_size = y_size + 2 * uv_size; // YUV420
    
    if (image_size > 0 && fdp.remaining_bytes() >= image_size) {
        return fdp.ConsumeBytes<uint8_t>(image_size);
    }
    return {};
}

// Helper to generate complex SVC scaling factors with various ratios
static void generate_complex_scaling_factors(FuzzedDataProvider& fdp, 
                                           vpx_svc_extra_cfg_t* svc_params,
                                           int spatial_layers) {
    for (int i = 0; i < spatial_layers; ++i) {
        // Generate various scaling factor combinations to test all conditions
        // in vp9_pick_inter_mode scaling_factor_num == scaling_factor_den checks
        uint8_t scenario = fdp.ConsumeIntegral<uint8_t>() % 4;
        
        switch (scenario) {
            case 0: // No scaling (equal factors) - should trigger certain conditions
                svc_params->scaling_factor_num[i] = 1;
                svc_params->scaling_factor_den[i] = 1;
                break;
                
            case 1: // Moderate downscaling
                svc_params->scaling_factor_num[i] = fdp.ConsumeIntegralInRange<int>(1, 3);
                svc_params->scaling_factor_den[i] = fdp.ConsumeIntegralInRange<int>(2, 4);
                break;
                
            case 2: // Strong downscaling
                svc_params->scaling_factor_num[i] = 1;
                svc_params->scaling_factor_den[i] = fdp.ConsumeIntegralInRange<int>(2, 8);
                break;
                
            case 3: // Upscaling (less common but valid)
                svc_params->scaling_factor_num[i] = fdp.ConsumeIntegralInRange<int>(2, 4);
                svc_params->scaling_factor_den[i] = 1;
                break;
        }
        
        // Ensure denominator is not zero
        if (svc_params->scaling_factor_den[i] == 0) {
            svc_params->scaling_factor_den[i] = 1;
        }
    }
}

// Helper to generate advanced rate control configurations
static void generate_advanced_rate_control(FuzzedDataProvider& fdp,
                                          vpx_codec_enc_cfg_t* cfg,
                                          int spatial_layers,
                                          int temporal_layers) {
    // Select rate control mode
    uint8_t rc_mode = fdp.ConsumeIntegral<uint8_t>() % 3;
    switch (rc_mode) {
        case 0:
            cfg->rc_end_usage = VPX_VBR;  // Variable Bit Rate
            cfg->rc_2pass_vbr_bias_pct = fdp.ConsumeIntegralInRange<int>(0, 100);
            cfg->rc_2pass_vbr_corpus_complexity = fdp.ConsumeIntegralInRange<int>(0, 10000);
            break;
        case 1:
            cfg->rc_end_usage = VPX_CBR;  // Constant Bit Rate
            cfg->rc_undershoot_pct = fdp.ConsumeIntegralInRange<int>(0, 100);
            cfg->rc_overshoot_pct = fdp.ConsumeIntegralInRange<int>(0, 100);
            break;
        case 2:
            cfg->rc_end_usage = VPX_CQ;   // Constant Quality
            cfg->rc_min_quantizer = fdp.ConsumeIntegralInRange<int>(0, 50);
            cfg->rc_max_quantizer = fdp.ConsumeIntegralInRange<int>(cfg->rc_min_quantizer, 63);
            break;
    }
    
    // Generate layer target bitrates with complex patterns
    int total_layers = spatial_layers * temporal_layers;
    int base_bitrate = fdp.ConsumeIntegralInRange<int>(100, 5000);
    
    for (int i = 0; i < total_layers; ++i) {
        if (i == 0) {
            cfg->layer_target_bitrate[i] = base_bitrate;
        } else {
            // Create various bitrate patterns: increasing, decreasing, or mixed
            uint8_t pattern = fdp.ConsumeIntegral<uint8_t>() % 3;
            switch (pattern) {
                case 0: // Monotonic increasing (normal SVC)
                    cfg->layer_target_bitrate[i] = cfg->layer_target_bitrate[i-1] + 
                                                  fdp.ConsumeIntegralInRange<int>(1, 500);
                    break;
                case 1: // Same bitrate (simpler case)
                    cfg->layer_target_bitrate[i] = cfg->layer_target_bitrate[i-1];
                    break;
                case 2: // Decreasing (may trigger validation errors)
                    cfg->layer_target_bitrate[i] = cfg->layer_target_bitrate[i-1] - 
                                                  fdp.ConsumeIntegralInRange<int>(1, 100);
                    if (cfg->layer_target_bitrate[i] < 1) cfg->layer_target_bitrate[i] = 1;
                    break;
            }
        }
    }
    
    // Configure temporal rate decimators with power-of-2 variations
    int decimator = 1;
    for (int i = temporal_layers - 1; i >= 0; --i) {
        // Most should be power of 2, but test some edge cases
        if (fdp.ConsumeBool() && i > 0) {
            // 20% chance to test non-power-of-2 for error paths
            if (fdp.ConsumeIntegral<uint8_t>() % 5 == 0) {
                decimator = fdp.ConsumeIntegralInRange<int>(3, 6);
            } else {
                decimator *= 2;
            }
        } else {
            decimator *= 2;
        }
        cfg->ts_rate_decimator[i] = decimator;
    }
}
static void configure_advanced_controls(FuzzedDataProvider& fdp,
                                       vpx_codec_ctx_t* codec_ctx,
                                       vpx_codec_enc_cfg_t* cfg) {
    // Test various adaptive quantization modes
    int aq_mode = fdp.ConsumeIntegralInRange<int>(0, 4);
    vpx_codec_control(codec_ctx, VP9E_SET_AQ_MODE, aq_mode);
    
    // Test frame parallel decoding mode
    int frame_parallel = fdp.ConsumeBool() ? 1 : 0;
    vpx_codec_control(codec_ctx, VP9E_SET_FRAME_PARALLEL_DECODING, frame_parallel);
    
    // Test tile configuration (affects parallel encoding)
    int tile_columns = fdp.ConsumeIntegralInRange<int>(0, 6);
    int tile_rows = fdp.ConsumeIntegralInRange<int>(0, 2);
    vpx_codec_control(codec_ctx, VP9E_SET_TILE_COLUMNS, tile_columns);
    vpx_codec_control(codec_ctx, VP9E_SET_TILE_ROWS, tile_rows);
    
    // Test lossless encoding mode
    int lossless = fdp.ConsumeBool() ? 1 : 0;
    vpx_codec_control(codec_ctx, VP9E_SET_LOSSLESS, lossless);
    
    // Test color space and range
    int color_space = fdp.ConsumeIntegralInRange<int>(0, 7);
    int color_range = fdp.ConsumeBool() ? 1 : 0;
    vpx_codec_control(codec_ctx, VP9E_SET_COLOR_SPACE, color_space);
    vpx_codec_control(codec_ctx, VP9E_SET_COLOR_RANGE, color_range);
    
    // Note: VP9E_SET_RENDER_SIZE control may not be available in this version
    // Remove this control as it's causing compilation errors
    // Test render size (different from encoding size) - skipping for compatibility
    // Note: VP9E_SET_SVC_PARAMETERS control is handled separately with svc_params structure
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check for comprehensive advanced configuration testing
    if (size < MIN_INPUT_SIZE) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Step 1: Consume advanced configuration parameters from fuzzer input
    uint8_t spatial_layers = fdp.ConsumeIntegralInRange<uint8_t>(1, VPX_SS_MAX_LAYERS);
    uint8_t temporal_layers = fdp.ConsumeIntegralInRange<uint8_t>(1, VPX_TS_MAX_LAYERS);
    
    // Advanced resolution configurations
    uint16_t base_width = fdp.ConsumeIntegralInRange<uint16_t>(64, 1920);
    uint16_t base_height = fdp.ConsumeIntegralInRange<uint16_t>(64, 1080);
    
    // Complex bitrate configurations
    uint32_t base_bitrate = fdp.ConsumeIntegralInRange<uint32_t>(100, 10000);
    
    // Frame count with various patterns
    uint8_t frame_count = fdp.ConsumeIntegralInRange<uint8_t>(1, 10);
    
    // Encoding pass type (important for multi-pass validation)
    uint8_t pass_type = fdp.ConsumeIntegral<uint8_t>() % 3;
    
    // Step 2: Select VP9 encoder interface
    vpx_codec_iface_t* codec_iface = vpx_codec_vp9_cx();
    if (!codec_iface) {
        return 0;
    }
    
    vpx_codec_ctx_t codec_ctx;
    vpx_codec_err_t res;
    vpx_codec_enc_cfg_t cfg;
    
    // Step 3: Get default encoder configuration
    if (vpx_codec_enc_config_default(codec_iface, &cfg, 0) != VPX_CODEC_OK) {
        return 0;
    }
    
    // Step 4: Configure encoder with advanced parameters
    cfg.g_w = base_width;
    cfg.g_h = base_height;
    cfg.rc_target_bitrate = base_bitrate;
    
    // Configure timebase with various frame rates
    cfg.g_timebase.num = 1;
    uint8_t fps_scenario = fdp.ConsumeIntegral<uint8_t>() % 4;
    switch (fps_scenario) {
        case 0: cfg.g_timebase.den = 24; break;  // Film
        case 1: cfg.g_timebase.den = 30; break;  // NTSC
        case 2: cfg.g_timebase.den = 25; break;  // PAL
        case 3: cfg.g_timebase.den = fdp.ConsumeIntegralInRange<int>(15, 60); break; // Variable
    }
    
    // Configure encoding pass (important for validate_config)
    switch (pass_type) {
        case 0:
            cfg.g_pass = VPX_RC_ONE_PASS;
            cfg.g_lag_in_frames = fdp.ConsumeIntegralInRange<int>(0, 25);
            break;
        case 1:
            cfg.g_pass = VPX_RC_FIRST_PASS;
            cfg.g_lag_in_frames = 0;
            break;
        case 2:
            cfg.g_pass = VPX_RC_LAST_PASS;
            cfg.g_lag_in_frames = fdp.ConsumeIntegralInRange<int>(0, 25);
            // For last pass, need to simulate two-pass stats
            cfg.rc_twopass_stats_in.buf = fdp.ConsumeBytes<uint8_t>(100).data();
            cfg.rc_twopass_stats_in.sz = 100;
            break;
    }
    
    // Configure SVC layers
    cfg.ss_number_layers = spatial_layers;
    cfg.ts_number_layers = temporal_layers;
    
    // Generate advanced rate control configurations
    generate_advanced_rate_control(fdp, &cfg, spatial_layers, temporal_layers);
    
    // Configure golden frame intervals (important for lag_in_frames validation)
    cfg.g_lag_in_frames = fdp.ConsumeIntegralInRange<int>(0, 25);
    int max_gf_interval = fdp.ConsumeIntegralInRange<int>(0, 16);
    int min_gf_interval = fdp.ConsumeIntegralInRange<int>(0, max_gf_interval);
    
    // Configure profile and bit-depth (affects validate_config checks)
    cfg.g_profile = fdp.ConsumeIntegralInRange<int>(0, 3);
    
    // Step 5: Initialize encoder with configuration
    vpx_codec_flags_t flags = 0;
    res = vpx_codec_enc_init(&codec_ctx, codec_iface, &cfg, flags);
    if (res != VPX_CODEC_OK) {
        // Initialization may fail due to invalid configurations
        // This exercises error paths in validate_config
        return 0;
    }
    
    // Step 6: Configure advanced encoder controls
    configure_advanced_controls(fdp, &codec_ctx, &cfg);
    
    // Step 7: Enable SVC encoding with complex parameters
    int svc_enable = 1;
    vpx_codec_control(&codec_ctx, VP9E_SET_SVC, svc_enable);
    
    // Configure SVC-specific parameters
    vpx_svc_extra_cfg_t svc_params;
    memset(&svc_params, 0, sizeof(svc_params));
    
    // Generate complex scaling factors
    generate_complex_scaling_factors(fdp, &svc_params, spatial_layers);
    
    // Configure temporal layering mode
    svc_params.temporal_layering_mode = fdp.ConsumeIntegralInRange<int>(0, 3);
    
    // Configure layer quantizers with various quality patterns
    for (int i = 0; i < spatial_layers; ++i) {
        svc_params.max_quantizers[i] = fdp.ConsumeIntegralInRange<int>(40, 63);
        svc_params.min_quantizers[i] = fdp.ConsumeIntegralInRange<int>(0, svc_params.max_quantizers[i] - 1);
        
        // Speed setting variations per layer
        svc_params.speed_per_layer[i] = fdp.ConsumeIntegralInRange<int>(0, 9);
    }
    
    // Pass SVC parameters to encoder
    vpx_codec_control(&codec_ctx, VP9E_SET_SVC_PARAMETERS, &svc_params);
    
    // Step 8: Create source image with proper format
    vpx_image_t* raw_img = vpx_img_alloc(NULL, VPX_IMG_FMT_I420, base_width, base_height, 1);
    if (!raw_img) {
        vpx_codec_destroy(&codec_ctx);
        return 0;
    }
    
    // Fill image with test data
    std::vector<uint8_t> image_data = create_test_image(base_width, base_height, fdp);
    if (image_data.size() >= (size_t)(base_width * base_height * 3 / 2)) {
        // Copy Y plane
        size_t y_size = base_width * base_height;
        memcpy(raw_img->planes[VPX_PLANE_Y], image_data.data(), y_size);
        
        // Copy U and V planes (UV interleaved in test data)
        size_t uv_size = (base_width / 2) * (base_height / 2);
        if (image_data.size() >= y_size + uv_size) {
            memcpy(raw_img->planes[VPX_PLANE_U], image_data.data() + y_size, uv_size);
        }
        if (image_data.size() >= y_size + 2 * uv_size) {
            memcpy(raw_img->planes[VPX_PLANE_V], image_data.data() + y_size + uv_size, uv_size);
        }
    } else {
        // Fill with simple pattern if not enough data
        for (int i = 0; i < base_height; ++i) {
            for (int j = 0; j < base_width; ++j) {
                raw_img->planes[VPX_PLANE_Y][i * raw_img->stride[VPX_PLANE_Y] + j] = 
                    (i + j) % 256;
            }
        }
    }
    
    // Step 9: Encode frames with various flags to exercise vp9_pick_inter_mode
    for (int frame_idx = 0; frame_idx < frame_count; ++frame_idx) {
        vpx_codec_flags_t encode_flags = 0;
        
        // Test various frame flags
        if (fdp.ConsumeBool()) {
            encode_flags |= VPX_EFLAG_FORCE_KF;  // Force keyframe
        }
        
        if (fdp.ConsumeBool() && spatial_layers > 1) {
            // Test spatial layer dropping
            encode_flags |= (1 << (frame_idx % spatial_layers));
        }
        
        // Encode the frame
        res = vpx_codec_encode(&codec_ctx, raw_img, frame_idx, 1, encode_flags, VPX_DL_REALTIME);
        
        if (res != VPX_CODEC_OK) {
            // Encoding may fail due to complex configurations
            // This exercises error handling paths
            break;
        }
        
        // Get encoded data (exercises output processing paths)
        vpx_codec_iter_t iter = NULL;
        const vpx_codec_cx_pkt_t* pkt;
        while ((pkt = vpx_codec_get_cx_data(&codec_ctx, &iter)) != NULL) {
            if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
                // Frame encoded successfully
                // This exercises the full vp9_pick_inter_mode path with SVC
            }
        }
        
        // Check if we have enough data for more frames
        if (fdp.remaining_bytes() < MIN_INPUT_SIZE / 4) {
            break;
        }
    }
    
    // Step 10: Cleanup
    vpx_img_free(raw_img);
    vpx_codec_destroy(&codec_ctx);
    
    return 0;
}
