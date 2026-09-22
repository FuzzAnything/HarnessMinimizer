/*
 * Fuzzing harness for libvpx VP9 SVC configuration validation and speed feature exploration
 * 
 * Target: HarnessAgent
 * Goal: Address 623+ blocked branches identified in coverage analysis:
 *       1. vp9_pick_inter_mode (333 blocked branches) - test speed feature flags like 
 *          default_interp_filter == BILINEAR and SVC conditions (use_svc && spatial_layer_id > 0)
 *       2. validate_config (236 blocked branches) - trigger SVC parameter validation error paths:
 *          g_lag_in_frames < max_gf_interval + 2, out-of-order layer_target_bitrate,
 *          invalid ts_rate_decimator patterns
 *       3. vp9_one_pass_svc_start_layer (54 blocked branches) - test internal SVC layer management
 * 
 * This harness specifically targets SVC configuration validation error paths and
 * speed feature combinations that remain uncovered in VP9 encoder:
 * - Invalid SVC parameter combinations that trigger validation errors
 * - Speed feature flags affecting interpolation filter selection
 * - Internal SVC layer management through parameter manipulation
 * 
 * Semantic differentiation from previous harnesses:
 * - harness_000: Basic VP8/VP9 mixed decode/encode cycles
 * - harness_001: Multi-stream encoder with vpx_img_wrap/flip  
 * - harness_002: Decoder callbacks & stream info
 * - harness_003: Encoder metadata and output buffer management
 * - harness_004: Advanced image manipulation with rectangles and formats
 * - harness_005: Codec capability queries and version information
 * - harness_006: Systematic error handling and edge case testing
 * - harness_007: Image manipulation and scaling-related operations
 * - harness_008: Comprehensive coverage of all remaining areas (mixed VP8/VP9)
 * - harness_009: EXCLUSIVELY VP9-focused with advanced features (includes SVC)
 * - harness_010: EXCLUSIVELY vpx_dsp signal processing via public APIs
 * - harness_011-016: VP9 encoder configuration validation error paths
 * - harness_017: EXCLUSIVELY VP9 encoder speed feature configurations
 * - harness_018: EXCLUSIVELY VP9 SVC with bilinear interpolation
 * - harness_019: EXCLUSIVELY VP9 SVC configuration validation and speed feature exploration (THIS HARNESS)
 * 
 * Strategy: Test specific invalid SVC configurations to trigger validation errors in
 * validate_config function, while also testing speed feature combinations that affect
 * vp9_pick_inter_mode decisions. Focus on exercising the 623 blocked branches through
 * targeted parameter manipulation.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
#include <memory>
#include <vector>
#include <string.h>

#include "fuzzer/FuzzedDataProvider.h"
#include "vpx/vpx_codec.h"
#include "vpx/vpx_image.h"
#include "vpx/vp8dx.h"
#include "vpx/vp8cx.h"
#include "vpx/vpx_decoder.h"
#include "vpx/vpx_encoder.h"

#define VPX_MAX_LAYERS 12
#define VPX_TS_MAX_LAYERS 5
#define VPX_SS_MAX_LAYERS 5

extern "C" void usage_exit(void) { exit(EXIT_FAILURE); }

// Helper to create test image with fuzzed data
static vpx_image_t* create_test_image(FuzzedDataProvider& fdp, 
                                      unsigned int width, 
                                      unsigned int height) {
    vpx_image_t* img = vpx_img_alloc(NULL, VPX_IMG_FMT_I420, width, height, 1);
    if (!img) return NULL;
    
    img->bit_depth = 8;
    
    // Fill Y plane (full resolution)
    size_t y_size = width * height;
    if (img->planes[0] && y_size > 0) {
        std::vector<uint8_t> y_data = fdp.ConsumeBytes<uint8_t>(y_size);
        if (y_data.size() >= y_size) {
            memcpy(img->planes[0], y_data.data(), y_size);
        }
    }
    
    // Fill U and V planes (half resolution)
    size_t uv_width = (width + 1) / 2;
    size_t uv_height = (height + 1) / 2;
    size_t uv_size = uv_width * uv_height;
    
    if (img->planes[1] && uv_size > 0) {
        std::vector<uint8_t> u_data = fdp.ConsumeBytes<uint8_t>(uv_size);
        if (u_data.size() >= uv_size) {
            memcpy(img->planes[1], u_data.data(), uv_size);
        }
    }
    
    if (img->planes[2] && uv_size > 0) {
        std::vector<uint8_t> v_data = fdp.ConsumeBytes<uint8_t>(uv_size);
        if (v_data.size() >= uv_size) {
            memcpy(img->planes[2], v_data.data(), uv_size);
        }
    }
    
    return img;
}

// Helper to set invalid SVC configuration targeting validation error paths
static void set_invalid_svc_config(vpx_codec_enc_cfg_t* cfg, FuzzedDataProvider& fdp) {
    // Choose which validation error to trigger
    uint8_t error_type = fdp.ConsumeIntegral<uint8_t>() % 6;
    
    switch (error_type) {
        case 0:
            // Trigger ERROR("Set lag in frames to 0 (low delay) or >= (max-gf-interval + 2)")
            // g_lag_in_frames < max_gf_interval + 2
            cfg->g_lag_in_frames = 1;  // Small value
            // max_gf_interval will be set via VP9E_SET_MAX_GF_INTERVAL control later
            // Need g_lag_in_frames < max_gf_interval + 2
            break;
            
        case 1:
            // Trigger ERROR("ts_target_bitrate entries are not increasing")
            // Out-of-order layer_target_bitrate
            cfg->ss_number_layers = 3;
            cfg->layer_target_bitrate[0] = 1000;
            cfg->layer_target_bitrate[1] = 500;  // Lower than previous - INVALID
            cfg->layer_target_bitrate[2] = 1500;
            break;
            
        case 2:
            // Trigger ERROR("ts_rate_decimator factors are not powers of 2")
            // Invalid ts_rate_decimator patterns
            cfg->ts_number_layers = 3;
            cfg->ts_rate_decimator[0] = 4;  // Bottom layer should be 1
            cfg->ts_rate_decimator[1] = 3;  // Not power of 2 relationship
            cfg->ts_rate_decimator[2] = 1;  // Should be 4 * 2 = 8, but we set 1
            break;
            
        case 3:
            // Exceed VPX_MAX_LAYERS with multiplication
            cfg->ss_number_layers = 4;
            cfg->ts_number_layers = 4;  // 4*4=16 > 12 (VPX_MAX_LAYERS)
            break;
            
        case 4:
            // Invalid temporal layer count
            cfg->ts_number_layers = 6;  // > VPX_TS_MAX_LAYERS (5)
            break;
            
        case 5:
            // Invalid spatial layer count
            cfg->ss_number_layers = 6;  // > VPX_SS_MAX_LAYERS (5)
            break;
    }
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum input size for meaningful testing
    if (size < 1024) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // 1. INITIALIZE ENCODER WITH BASE CONFIGURATION
    // ---------------------------------------------
    
    vpx_codec_ctx_t encoder;
    vpx_codec_enc_cfg_t cfg;
    vpx_codec_err_t res;
    
    // Get VP9 encoder interface
    vpx_codec_iface_t* iface = vpx_codec_vp9_cx();
    if (!iface) {
        return 0;
    }
    
    // Get default configuration
    res = vpx_codec_enc_config_default(iface, &cfg, 0);
    if (res != VPX_CODEC_OK) {
        return 0;
    }
    
    // Set basic parameters from fuzzed input
    unsigned int width = fdp.ConsumeIntegralInRange<unsigned int>(16, 1920);
    unsigned int height = fdp.ConsumeIntegralInRange<unsigned int>(16, 1080);
    
    cfg.g_w = width;
    cfg.g_h = height;
    cfg.g_timebase.num = 1;
    cfg.g_timebase.den = 30;
    cfg.rc_target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 10000);
    cfg.g_error_resilient = 0;
    
    // 2. SET UP SVC CONFIGURATION WITH POTENTIAL VALIDATION ERRORS
    // -------------------------------------------------------------
    
    // Enable SVC with multiple layers
    cfg.ss_number_layers = fdp.ConsumeIntegralInRange<unsigned int>(1, 3);
    cfg.ts_number_layers = fdp.ConsumeIntegralInRange<unsigned int>(1, 3);
    
    // Set layer target bitrates (could be invalid)
    for (unsigned int i = 0; i < cfg.ss_number_layers; i++) {
        cfg.layer_target_bitrate[i] = fdp.ConsumeIntegralInRange<unsigned int>(100, 5000);
    }
    
    // Set temporal rate decimators (could be invalid)
    for (unsigned int i = 0; i < cfg.ts_number_layers; i++) {
        cfg.ts_rate_decimator[i] = fdp.ConsumeIntegralInRange<unsigned int>(1, 8);
    }
    
    // Set lag frames (could trigger validation error when combined with max_gf_interval)
    cfg.g_lag_in_frames = fdp.ConsumeIntegralInRange<unsigned int>(0, 10);
    // Apply specific invalid configurations to target validation errors
    set_invalid_svc_config(&cfg, fdp);
    
    // 3. INITIALIZE ENCODER AND TEST VALIDATION PATHS
    // ------------------------------------------------
    
    res = vpx_codec_enc_init_ver(&encoder, iface, &cfg, 0, VPX_ENCODER_ABI_VERSION);
    
    // Handle initialization failures (expected for invalid configs)
    if (res != VPX_CODEC_OK) {
        // Try with different ABI version to test version mismatch
        res = vpx_codec_enc_init_ver(&encoder, iface, &cfg, 0, VPX_ENCODER_ABI_VERSION - 1);
        if (res != VPX_CODEC_OK) {
            return 0;  // Invalid config successfully rejected
        }
    }
    
    // 4. SET UP SPEED FEATURES AND SVC CONTROLS
    // -----------------------------------------
    
    // Enable SVC
    vpx_codec_control(&encoder, VP9E_SET_SVC, 1);
    
    // Configure SVC parameters (vpx_svc_extra_cfg_t)
    vpx_svc_extra_cfg_t svc_params = {0};
    
    // Set quantization parameters for each layer
    for (int i = 0; i < (int)cfg.ss_number_layers; i++) {
        svc_params.min_quantizers[i] = fdp.ConsumeIntegralInRange<int>(0, 20);
        svc_params.max_quantizers[i] = fdp.ConsumeIntegralInRange<int>(40, 63);
        
        // Scaling factors for spatial layers
        svc_params.scaling_factor_num[i] = fdp.ConsumeIntegralInRange<int>(1, 16);
        svc_params.scaling_factor_den[i] = fdp.ConsumeIntegralInRange<int>(1, 16);
        
        // Speed setting per layer (affects vp9_pick_inter_mode)
        svc_params.speed_per_layer[i] = fdp.ConsumeIntegralInRange<int>(0, 8);
        
        // Loopfilter control per layer
        svc_params.loopfilter_ctrl[i] = fdp.ConsumeIntegralInRange<int>(0, 1);
    }
    
    svc_params.temporal_layering_mode = 0;
    
    // Apply SVC parameters
    vpx_codec_control(&encoder, VP9E_SET_SVC_PARAMETERS, &svc_params);
    
    // Set speed/quality trade-off (affects vp9_pick_inter_mode)
    int cpuused = fdp.ConsumeIntegralInRange<int>(0, 8);
    vpx_codec_control(&encoder, VP8E_SET_CPUUSED, cpuused);
    
    // Set content type tuning (affects speed features)
    int tune_content = fdp.ConsumeIntegralInRange<int>(0, 2);
    vpx_codec_control(&encoder, VP9E_SET_TUNE_CONTENT, tune_content);
    
    // Set row-based multi-threading
    int row_mt = fdp.ConsumeBool() ? 1 : 0;
    vpx_codec_control(&encoder, VP9E_SET_ROW_MT, row_mt);

    // Set max GF interval to potentially trigger lag frame validation error
    // This is needed for case 0 in set_invalid_svc_config
    unsigned int max_gf_interval = fdp.ConsumeIntegralInRange<unsigned int>(4, 16);
    vpx_codec_control(&encoder, VP9E_SET_MAX_GF_INTERVAL, max_gf_interval);
    
    // Set SVC layer ID for encoding (targets spatial_layer_id > 0 condition)
    vpx_svc_layer_id_t layer_id = {0};
    layer_id.spatial_layer_id = 0; // Start with base layer
    layer_id.temporal_layer_id = 0;
    vpx_codec_control(&encoder, VP9E_SET_SVC_LAYER_ID, &layer_id);
    
    // Note: There's no public API to directly set default_interp_filter to BILINEAR
    // This is an internal speed feature that might be set through other controls
    // or affected by CPUUSED and TUNE_CONTENT settings
    
    // 5. CREATE TEST IMAGE AND PERFORM ENCODING
    // ------------------------------------------
    
    // Create test image using fuzzed data
    vpx_image_t* img = create_test_image(fdp, width, height);
    if (!img) {
        vpx_codec_destroy(&encoder);
        return 0;
    }
    
    // Encode multiple frames to exercise different paths
    // This is critical for testing vp9_pick_inter_mode with SVC
    const int num_frames_to_encode = 4;
    
    for (int frame_idx = 0; frame_idx < num_frames_to_encode; frame_idx++) {
        // Switch between spatial layers to test the uncovered condition:
        // if (cpi->use_svc && svc->spatial_layer_id > 0)
        int spatial_layer = frame_idx % cfg.ss_number_layers;
        
        // Update layer ID for this frame
        layer_id.spatial_layer_id = spatial_layer;
        layer_id.temporal_layer_id = frame_idx % cfg.ts_number_layers;
        
        vpx_codec_control(&encoder, VP9E_SET_SVC_LAYER_ID, &layer_id);
        
        // Set frame type: keyframe for first frame, inter-frames for others
        vpx_codec_frame_flags_t flags = 0;
        if (frame_idx == 0) {
            flags |= VPX_EFLAG_FORCE_KF;
        }
        
        // Encode the frame
        res = vpx_codec_encode(&encoder, img, frame_idx, 1, flags, VPX_DL_REALTIME);
        if (res != VPX_CODEC_OK) {
            // Continue with next frame even if one fails
            continue;
        }
        
        // Retrieve encoded data to exercise output paths
        vpx_codec_iter_t iter = NULL;
        const vpx_codec_cx_pkt_t* pkt;
        while ((pkt = vpx_codec_get_cx_data(&encoder, &iter)) != NULL) {
            // Process different packet types
            switch (pkt->kind) {
                case VPX_CODEC_CX_FRAME_PKT:
                    // Frame packet - contains encoded video data
                    break;
                case VPX_CODEC_STATS_PKT:
                    // Statistics packet
                    break;
                case VPX_CODEC_PSNR_PKT:
                    // PSNR packet
                    break;
                default:
                    // Other packet types
                    break;
            }
        }
    }
    
    // 6. CLEANUP
    // -----------
    
    vpx_img_free(img);
    vpx_codec_destroy(&encoder);
    
    return 0;
}
