/*
 * Fuzzing harness for libvpx - Advanced VP9 SVC with high-bitdepth and screen content encoding
 * 
 * Target: HarnessAgent
 * Goal: Address the 347 blocked branches in vp9_pick_inter_mode by combining:
 *       1. SVC with multiple spatial/temporal layers
 *       2. High-bitdepth encoding (VPX_BITS_10/12)
 *       3. Screen content encoding (VP9E_CONTENT_SCREEN)
 *       4. Advanced encoder configurations (max_gf_interval, min_gf_interval, enable_auto_alt_ref)
 *       5. Complex rate control modes
 * 
 * This harness specifically targets the largest coverage gap (347 blocked branches in vp9_pick_inter_mode)
 * by creating complex encoder configurations that affect internal mode selection decisions:
 * - High-bitdepth encoding paths (CONFIG_VP9_HIGHBITDEPTH)
 * - SVC-specific code (spatial_layer_id > 0 checks)
 * - Screen content optimization paths
 * - Advanced rate control and ARF configurations
 * - Complex temporal/spatial scalability combinations
 * 
 * Semantic differentiation from previous harnesses 000-019:
 * - harness_009: Basic VP9-focused with advanced features (includes some SVC)
 * - harness_018: SVC with bilinear interpolation
 * - harness_019: SVC configuration validation and speed feature exploration
 * - harness_020: ADVANCED SVC with high-bitdepth, screen content, and complex encoder configs (THIS HARNESS)
 * 
 * Strategy: Combine multiple advanced features simultaneously to exercise deeper code paths
 * in vp9_pick_inter_mode through varied encoder state and configuration combinations.
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

// Helper to create high-bitdepth test image
static vpx_image_t* create_highbd_test_image(FuzzedDataProvider& fdp, 
                                            unsigned int width, 
                                            unsigned int height,
                                            vpx_img_fmt_t fmt,
                                            int bit_depth) {
    vpx_image_t* img = vpx_img_alloc(NULL, fmt, width, height, 1);
    if (!img) return NULL;
    
    img->bit_depth = bit_depth;
    
    // Fill image planes with fuzzed data
    size_t plane_size = width * height * (bit_depth > 8 ? 2 : 1);
    
    if (fmt == VPX_IMG_FMT_I420 || fmt == VPX_IMG_FMT_I42016) {
        // Y plane (full resolution)
        if (img->planes[0] && plane_size > 0) {
            std::vector<uint8_t> y_data = fdp.ConsumeBytes<uint8_t>(plane_size);
            if (y_data.size() >= plane_size) {
                memcpy(img->planes[0], y_data.data(), plane_size);
            }
        }
        // U and V planes (half resolution)
        size_t uv_width = (width + 1) / 2;
        size_t uv_height = (height + 1) / 2;
        size_t uv_size = uv_width * uv_height * (bit_depth > 8 ? 2 : 1);
        
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
    }
    
    return img;
}

// Helper to configure SVC parameters with fuzzed data
static void configure_svc_layers(FuzzedDataProvider& fdp,
                                vpx_codec_enc_cfg_t* cfg,
                                vpx_svc_extra_cfg_t* svc_params) {
    // Configure spatial layers
    cfg->ss_number_layers = fdp.ConsumeIntegralInRange<unsigned int>(1, VPX_SS_MAX_LAYERS);
    cfg->ts_number_layers = fdp.ConsumeIntegralInRange<unsigned int>(1, VPX_TS_MAX_LAYERS);
    
    // Configure spatial scaling parameters
    for (unsigned int i = 0; i < cfg->ss_number_layers; ++i) {
        cfg->ss_enable_auto_alt_ref[i] = fdp.ConsumeBool();
        cfg->ss_target_bitrate[i] = fdp.ConsumeIntegralInRange<unsigned int>(100, 10000);
    }
    
    // Configure temporal layers
    for (unsigned int i = 0; i < cfg->ts_number_layers; ++i) {
        cfg->ts_rate_decimator[i] = fdp.ConsumeIntegralInRange<unsigned int>(1, 4);
        cfg->ts_target_bitrate[i] = fdp.ConsumeIntegralInRange<unsigned int>(100, 10000);
        cfg->ts_periodicity = fdp.ConsumeIntegralInRange<unsigned int>(1, VPX_TS_MAX_PERIODICITY);
    }
    
    // Configure layer target bitrates
    for (int i = 0; i < VPX_MAX_LAYERS; ++i) {
        cfg->layer_target_bitrate[i] = fdp.ConsumeIntegralInRange<unsigned int>(0, 10000);
    }
    
    // Configure SVC extra parameters
    if (svc_params) {
        for (int i = 0; i < VPX_MAX_LAYERS; ++i) {
            svc_params->scaling_factor_num[i] = fdp.ConsumeIntegralInRange<int>(1, 4);
            svc_params->scaling_factor_den[i] = fdp.ConsumeIntegralInRange<int>(1, 4);
            svc_params->max_quantizers[i] = fdp.ConsumeIntegralInRange<int>(0, 63);
            svc_params->min_quantizers[i] = fdp.ConsumeIntegralInRange<int>(0, 63);
        }
    }
}

// Helper to configure advanced encoder parameters
static void configure_advanced_encoder(FuzzedDataProvider& fdp,
                                      vpx_codec_enc_cfg_t* cfg) {
    // Advanced rate control parameters
    cfg->rc_max_quantizer = fdp.ConsumeIntegralInRange<unsigned int>(0, 63);
    cfg->rc_min_quantizer = fdp.ConsumeIntegralInRange<unsigned int>(0, 63);
    cfg->rc_end_usage = static_cast<vpx_rc_mode>(fdp.ConsumeIntegralInRange<int>(0, 3));
    
    // Advanced encoder parameters from guidance
    // Note: min_gf_interval and max_gf_interval are set via codec controls, not cfg
    // They are used in the guidance but need to be set through VP9E_SET_MIN_GF_INTERVAL/VP9E_SET_MAX_GF_INTERVAL
    // Note: g_auto_alt_ref doesn't exist in cfg structure - use codec control instead
    
    // Set lag in frames
    cfg->g_lag_in_frames = fdp.ConsumeIntegralInRange<unsigned int>(0, 25);
    
    // Multi-threading
    cfg->g_threads = fdp.ConsumeIntegralInRange<unsigned int>(1, 8);
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 128) {
        return 0; // Need minimum input for complex configuration
    }

    FuzzedDataProvider fdp(data, size);
    
    // Consume test configuration from fuzzer input
    uint8_t test_mode = fdp.ConsumeIntegral<uint8_t>() % 4;
    bool use_high_bitdepth = fdp.ConsumeBool();
    bool use_screen_content = fdp.ConsumeBool();
    bool use_complex_rate_ctrl = fdp.ConsumeBool();
    
    // Image dimensions
    unsigned int width = fdp.ConsumeIntegralInRange<unsigned int>(16, 256);
    unsigned int height = fdp.ConsumeIntegralInRange<unsigned int>(16, 256);
    
    // Determine bit depth and image format
    int bit_depth = 8;
    vpx_img_fmt_t img_fmt = VPX_IMG_FMT_I420;
    
    if (use_high_bitdepth) {
        // Choose between 10-bit and 12-bit
        bit_depth = fdp.ConsumeBool() ? VPX_BITS_10 : VPX_BITS_12;
        img_fmt = VPX_IMG_FMT_I42016;
    }
    
    // Create test image
    vpx_image_t* img = create_highbd_test_image(fdp, width, height, img_fmt, bit_depth);
    if (!img) {
        return 0;
    }
    
    vpx_codec_ctx_t encoder;
    vpx_codec_enc_cfg_t cfg;
    vpx_codec_err_t err = VPX_CODEC_OK;
    
    // Initialize encoder configuration
    vpx_codec_iface_t* iface = vpx_codec_vp9_cx();
    err = vpx_codec_enc_config_default(iface, &cfg, 0);
    if (err != VPX_CODEC_OK) {
        vpx_img_free(img);
        return 0;
    }
    
    // Set basic configuration
    cfg.g_w = width;
    cfg.g_h = height;
    cfg.g_bit_depth = (bit_depth == 10) ? VPX_BITS_10 : 
                     (bit_depth == 12) ? VPX_BITS_12 : VPX_BITS_8;
    cfg.g_input_bit_depth = bit_depth;
    cfg.g_profile = (bit_depth > 8) ? 2 : 0; // Profile for high-bitdepth
    
    // Configure advanced encoder parameters
    configure_advanced_encoder(fdp, &cfg);
    
    // Configure rate control
    if (use_complex_rate_ctrl) {
        cfg.rc_target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 5000);
        cfg.rc_max_quantizer = fdp.ConsumeIntegralInRange<unsigned int>(4, 63);
        cfg.rc_min_quantizer = fdp.ConsumeIntegralInRange<unsigned int>(0, cfg.rc_max_quantizer);
        cfg.rc_undershoot_pct = fdp.ConsumeIntegralInRange<unsigned int>(0, 100);
        cfg.rc_overshoot_pct = fdp.ConsumeIntegralInRange<unsigned int>(0, 100);
        cfg.rc_buf_initial_sz = fdp.ConsumeIntegralInRange<unsigned int>(500, 5000);
        cfg.rc_buf_optimal_sz = fdp.ConsumeIntegralInRange<unsigned int>(500, 5000);
        cfg.rc_buf_sz = fdp.ConsumeIntegralInRange<unsigned int>(1000, 10000);
    }
    
    // Initialize encoder with appropriate flags
    vpx_codec_flags_t flags = 0;
    if (bit_depth > 8) {
        flags |= VPX_CODEC_USE_HIGHBITDEPTH;
    }
    
    // Initialize encoder
    err = vpx_codec_enc_init_ver(&encoder, iface, &cfg, flags, VPX_ENCODER_ABI_VERSION);
    if (err != VPX_CODEC_OK) {
        vpx_img_free(img);
        return 0;
    }
    
    // Set content type (screen content vs natural video)
    if (use_screen_content) {
        vpx_codec_control(&encoder, VP9E_SET_TUNE_CONTENT, VP9E_CONTENT_SCREEN);
    } else {
        vpx_codec_control(&encoder, VP9E_SET_TUNE_CONTENT, VP9E_CONTENT_DEFAULT);
    }
    
    // Set SVC parameters if enabled
    if (test_mode == 0 || test_mode == 2) {
        vpx_svc_extra_cfg_t svc_params;
        memset(&svc_params, 0, sizeof(svc_params));
        
        // Configure SVC
        vpx_codec_control(&encoder, VP9E_SET_SVC, 1);
        configure_svc_layers(fdp, &cfg, &svc_params);
        vpx_codec_control(&encoder, VP9E_SET_SVC_PARAMETERS, &svc_params);
        
        // Set layer ID for SVC encoding
        vpx_svc_layer_id_t layer_id;
        layer_id.spatial_layer_id = fdp.ConsumeIntegralInRange<int>(0, cfg.ss_number_layers - 1);
        layer_id.temporal_layer_id = fdp.ConsumeIntegralInRange<int>(0, cfg.ts_number_layers - 1);
        vpx_codec_control(&encoder, VP9E_SET_SVC_LAYER_ID, &layer_id);
    }
    
    // Set advanced encoder controls
    vpx_codec_control(&encoder, VP9E_SET_ROW_MT, fdp.ConsumeBool() ? 1 : 0);
    int tile_columns = fdp.ConsumeIntegralInRange<int>(0, 6);
    int tile_rows = fdp.ConsumeIntegralInRange<int>(0, 2);
    vpx_codec_control(&encoder, VP9E_SET_TILE_COLUMNS, tile_columns);
    vpx_codec_control(&encoder, VP9E_SET_TILE_ROWS, tile_rows);
    vpx_codec_control(&encoder, VP9E_SET_AQ_MODE, fdp.ConsumeIntegralInRange<unsigned int>(0, 4));
    vpx_codec_control(&encoder, VP9E_SET_ALT_REF_AQ, fdp.ConsumeBool() ? 1 : 0);
    
    // Set min/max GF intervals (key for vp9_pick_inter_mode)
    int min_gf_interval = fdp.ConsumeIntegralInRange<int>(0, 16);
    int max_gf_interval = fdp.ConsumeIntegralInRange<int>(min_gf_interval, 16);
    vpx_codec_control(&encoder, VP9E_SET_MIN_GF_INTERVAL, min_gf_interval);
    vpx_codec_control(&encoder, VP9E_SET_MAX_GF_INTERVAL, max_gf_interval);
    
    // Set color space and range
    vpx_codec_control(&encoder, VP9E_SET_COLOR_SPACE, fdp.ConsumeIntegralInRange<int>(0, 7));
    vpx_codec_control(&encoder, VP9E_SET_COLOR_RANGE, fdp.ConsumeIntegralInRange<int>(0, 1));
    // Encode a few frames with varying properties
    for (int frame_num = 0; frame_num < 3 && fdp.remaining_bytes() > 0; ++frame_num) {
        vpx_codec_pts_t pts = frame_num;
        int64_t duration = 1;
        int deadline = 0; // Best quality
        
        // For SVC, update layer ID for each frame
        if (test_mode == 0 || test_mode == 2) {
            vpx_svc_layer_id_t layer_id;
            layer_id.spatial_layer_id = fdp.ConsumeIntegralInRange<int>(0, cfg.ss_number_layers - 1);
            layer_id.temporal_layer_id = fdp.ConsumeIntegralInRange<int>(0, cfg.ts_number_layers - 1);
            vpx_codec_control(&encoder, VP9E_SET_SVC_LAYER_ID, &layer_id);
        }
        
        // Encode frame
        err = vpx_codec_encode(&encoder, img, pts, duration, 0, deadline);
        if (err != VPX_CODEC_OK) {
            break;
        }
        
        // Retrieve encoded data
        const vpx_codec_cx_pkt_t *pkt = NULL;
        vpx_codec_iter_t iter = NULL;
        
        while ((pkt = vpx_codec_get_cx_data(&encoder, &iter)) != NULL) {
            if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
                // Frame encoded successfully
                break;
            }
        }
    }
    
    // Clean up
    vpx_codec_destroy(&encoder);
    vpx_img_free(img);
    
    return 0;
}
