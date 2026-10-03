/*
 * Fuzzing harness for libvpx - VP9 encoder configuration validation with 181 blocked branches
 * 
 * Target: HarnessAgent
 * Goal: Target validate_config function in VP9 encoder through specific configuration
 *       combinations using vpx_codec_enc_init_ver, vpx_codec_enc_config_set, and
 *       vpx_codec_encode APIs. Focus on exploring deep coverage of configuration
 *       validation error paths and edge cases.
 * 
 * This harness specifically targets the 181 blocked branches in the validate_config
 * function by systematically testing invalid configuration parameter combinations.
 * 
 * Strategy:
 * 1. Generate various invalid encoder configurations using fuzzed input
 * 2. Test vpx_codec_enc_init_ver with invalid configs to trigger validation errors
 * 3. Test vpx_codec_enc_config_set with invalid configs after successful initialization
 * 4. Test vpx_codec_encode with various image formats and invalid states
 * 5. Focus on hitting RANGE_CHECK validation paths in validate_config function
 * 
 * Semantic differentiation from previous harnesses:
 * - harness_000: Basic VP8/VP9 decode/encode cycles
 * - harness_001: Multi-stream encoder with vpx_img_wrap/flip  
 * - harness_002: Decoder callbacks & stream info
 * - harness_003: Encoder metadata and output buffer management
 * - harness_004: Advanced image manipulation with rectangles and formats
 * - harness_005: Codec capability queries and version information
 * - harness_006: Systematic error handling and edge case testing
 * - harness_007: Image manipulation and scaling-related operations
 * - harness_008: Comprehensive coverage of all remaining areas (mixed VP8/VP9)
 * - harness_009: EXCLUSIVELY VP9-focused with advanced features
 * - harness_010: EXCLUSIVELY vpx_dsp signal processing via public APIs
 * - harness_011: EXCLUSIVELY VP9 encoder configuration validation error paths (THIS HARNESS)
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

extern "C" void usage_exit(void) { exit(EXIT_FAILURE); }

// Helper to create test image with fuzzed data
static vpx_image_t* create_test_image(FuzzedDataProvider& fdp, 
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
    } else if (fmt == VPX_IMG_FMT_NV12) {
        // Y plane
        if (img->planes[0] && plane_size > 0) {
            std::vector<uint8_t> y_data = fdp.ConsumeBytes<uint8_t>(plane_size);
            if (y_data.size() >= plane_size) {
                memcpy(img->planes[0], y_data.data(), plane_size);
            }
        }
        // UV interleaved plane
        size_t uv_size = ((width + 1) / 2) * ((height + 1) / 2) * 2;
        if (img->planes[1] && uv_size > 0) {
            std::vector<uint8_t> uv_data = fdp.ConsumeBytes<uint8_t>(uv_size);
            if (uv_data.size() >= uv_size) {
                memcpy(img->planes[1], uv_data.data(), uv_size);
            }
        }
    } else if (fmt == VPX_IMG_FMT_I422 || fmt == VPX_IMG_FMT_I42216) {
        // Y plane
        if (img->planes[0] && plane_size > 0) {
            std::vector<uint8_t> y_data = fdp.ConsumeBytes<uint8_t>(plane_size);
            if (y_data.size() >= plane_size) {
                memcpy(img->planes[0], y_data.data(), plane_size);
            }
        }
        // U and V planes (half width, full height)
        size_t uv_width = (width + 1) / 2;
        size_t uv_size = uv_width * height * (bit_depth > 8 ? 2 : 1);
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

// Test specific validation paths in validate_config function
static void test_config_validation_paths(FuzzedDataProvider& fdp, 
                                         vpx_codec_enc_cfg_t& cfg,
                                         vpx_codec_ctx_t& encoder) {
    vpx_codec_err_t err;
    
    // Test 1: Invalid width/height ranges (should trigger RANGE_CHECK in validate_config)
    // Lines 187-188: RANGE_CHECK(cfg, g_w, 1, 65536); RANGE_CHECK(cfg, g_h, 1, 65536);
    uint8_t invalid_dim_test = fdp.ConsumeIntegral<uint8_t>() % 4;
    switch (invalid_dim_test) {
        case 0:
            cfg.g_w = 0;  // Below minimum
            break;
        case 1:
            cfg.g_h = 0;  // Below minimum  
            break;
        case 2:
            cfg.g_w = 65537;  // Above maximum
            break;
        case 3:
            cfg.g_h = 65537;  // Above maximum
            break;
    }
    
    // Test 2: Invalid timebase (Lines 189-190)
    uint8_t invalid_timebase_test = fdp.ConsumeIntegral<uint8_t>() % 3;
    switch (invalid_timebase_test) {
        case 0:
            cfg.g_timebase.den = 0;  // Below minimum
            break;
        case 1:
            cfg.g_timebase.num = 0;  // Below minimum
            break;
        case 2:
            cfg.g_timebase.den = 1000000001;  // Above maximum
            break;
    }
    
    // Test 3: Invalid profile (Line 191: RANGE_CHECK_HI(cfg, g_profile, 3))
    cfg.g_profile = 4 + fdp.ConsumeIntegral<uint8_t>() % 10;
    
    // Test 4: Invalid quantizer ranges (Lines 193-194)
    uint8_t invalid_quant_test = fdp.ConsumeIntegral<uint8_t>() % 3;
    switch (invalid_quant_test) {
        case 0:
            cfg.rc_max_quantizer = 64 + fdp.ConsumeIntegral<uint8_t>() % 10;
            break;
        case 1:
            cfg.rc_min_quantizer = cfg.rc_max_quantizer + 1 + fdp.ConsumeIntegral<uint8_t>() % 10;
            break;
        case 2:
            cfg.rc_min_quantizer = 64 + fdp.ConsumeIntegral<uint8_t>() % 10;
            cfg.rc_max_quantizer = cfg.rc_min_quantizer - 1;
            break;
    }
    
    // Test 5: Invalid thread count (Line 200: RANGE_CHECK_HI(cfg, g_threads, MAX_NUM_THREADS))
    cfg.g_threads = 65 + fdp.ConsumeIntegral<uint8_t>() % 100;
    
    // Test 6: Invalid lag_in_frames (Line 201: RANGE_CHECK_HI(cfg, g_lag_in_frames, MAX_LAG_BUFFERS))
    cfg.g_lag_in_frames = 256 + fdp.ConsumeIntegral<uint8_t>() % 100;
    
    // Test 7: Invalid rc_end_usage (Line 202: RANGE_CHECK(cfg, rc_end_usage, VPX_VBR, VPX_Q))
    cfg.rc_end_usage = static_cast<vpx_rc_mode>(VPX_Q + 1 + fdp.ConsumeIntegral<uint8_t>() % 10);
    
    // Test 8: Invalid percentage values (Lines 203-205)
    cfg.rc_undershoot_pct = 101 + fdp.ConsumeIntegral<uint8_t>() % 100;
    cfg.rc_overshoot_pct = 101 + fdp.ConsumeIntegral<uint8_t>() % 100;
    cfg.rc_2pass_vbr_bias_pct = 101 + fdp.ConsumeIntegral<uint8_t>() % 100;
    
    // Test 9: Invalid kf_mode (Line 207)
    cfg.kf_mode = static_cast<vpx_kf_mode>(VPX_KF_AUTO + 1 + fdp.ConsumeIntegral<uint8_t>() % 10);
    
    // Test 10: Invalid g_pass (Lines 213-216)
    #if CONFIG_REALTIME_ONLY
    cfg.g_pass = VPX_RC_LAST_PASS;
    #else
    cfg.g_pass = static_cast<vpx_enc_pass>(VPX_RC_LAST_PASS + 1 + fdp.ConsumeIntegral<uint8_t>() % 10);
    #endif
    
    // Test 11: Invalid layer configurations (Lines 239-240, 253-254)
    cfg.ss_number_layers = VPX_SS_MAX_LAYERS + 1 + fdp.ConsumeIntegral<uint8_t>() % 10;
    cfg.ts_number_layers = VPX_TS_MAX_LAYERS + 1 + fdp.ConsumeIntegral<uint8_t>() % 10;
    
    // Initialize with invalid config to trigger validation errors
    err = vpx_codec_enc_init_ver(&encoder, vpx_codec_vp9_cx(), &cfg, 0, VPX_ENCODER_ABI_VERSION);
    // We expect errors here - that's what we're testing
}

// Test vpx_codec_enc_config_set with invalid configurations
static void test_enc_config_set_validation(FuzzedDataProvider& fdp,
                                           vpx_codec_ctx_t& encoder,
                                           vpx_codec_enc_cfg_t& valid_cfg) {
    vpx_codec_err_t err;
    
    // First initialize with a valid config
    err = vpx_codec_enc_init_ver(&encoder, vpx_codec_vp9_cx(), &valid_cfg, 0, VPX_ENCODER_ABI_VERSION);
    if (err != VPX_CODEC_OK) {
        // If initialization fails, we can't test enc_config_set
        return;
    }
    
    // Now create an invalid config to test vpx_codec_enc_config_set
    vpx_codec_enc_cfg_t invalid_cfg = valid_cfg;
    
    // Modify config to trigger specific validation errors
    uint8_t test_type = fdp.ConsumeIntegral<uint8_t>() % 8;
    
    switch (test_type) {
        case 0:
            // Cannot increase lag_in_frames (Line 836 in vp9_cx_iface.c)
            invalid_cfg.g_lag_in_frames = valid_cfg.g_lag_in_frames + 1 + fdp.ConsumeIntegral<uint8_t>() % 10;
            break;
        case 1:
            // Invalid width/height for resize (Lines 234-237)
            invalid_cfg.rc_resize_allowed = 1;
            invalid_cfg.rc_scaled_width = valid_cfg.g_w + 1 + fdp.ConsumeIntegral<uint8_t>() % 100;
            invalid_cfg.rc_scaled_height = valid_cfg.g_h + 1 + fdp.ConsumeIntegral<uint8_t>() % 100;
            break;
        case 2:
            // Invalid layer target bitrate ordering (Lines 260-262)
            if (invalid_cfg.ss_number_layers > 1 && invalid_cfg.ts_number_layers > 1) {
                // Make layer target bitrates non-increasing
                for (int i = 0; i < VPX_MAX_LAYERS; i++) {
                    invalid_cfg.layer_target_bitrate[i] = fdp.ConsumeIntegral<uint32_t>() % 10000;
                }
            }
            break;
        case 3:
            // Invalid ARF group formation (Lines 229-232)
            invalid_cfg.g_lag_in_frames = 1;  // Too small for max_gf_interval
            break;
        case 4:
            // Profile-bit depth mismatch (Lines 351-365)
            invalid_cfg.g_profile = 0;  // Profile 0
            invalid_cfg.g_bit_depth = VPX_BITS_10;  // 10-bit depth
            break;
        case 5:
            // Invalid two-pass stats (Lines 302-345)
            invalid_cfg.g_pass = VPX_RC_LAST_PASS;
            invalid_cfg.rc_twopass_stats_in.sz = 1;  // Too small
            break;
        case 6:
            // Invalid spatial/temporal layer product (Line 253)
            invalid_cfg.ss_number_layers = 4;
            invalid_cfg.ts_number_layers = 4;  // 4*4=16 > VPX_MAX_LAYERS(12)
            break;
        case 7:
            // Various invalid percentage values
            invalid_cfg.rc_dropframe_thresh = 101 + fdp.ConsumeIntegral<uint8_t>() % 100;
            invalid_cfg.rc_resize_up_thresh = 101 + fdp.ConsumeIntegral<uint8_t>() % 100;
            invalid_cfg.rc_resize_down_thresh = 101 + fdp.ConsumeIntegral<uint8_t>() % 100;
            break;
    }
    
    // Try to set invalid config - should trigger validation errors
    err = vpx_codec_enc_config_set(&encoder, &invalid_cfg);
    // We expect errors here - that's what we're testing
    
    // Clean up
    vpx_codec_destroy(&encoder);
}

// Test vpx_codec_encode with various invalid states
static void test_encode_validation(FuzzedDataProvider& fdp,
                                   vpx_codec_ctx_t& encoder,
                                   vpx_codec_enc_cfg_t& cfg) {
    vpx_codec_err_t err;
    
    // Initialize with valid config first
    err = vpx_codec_enc_init_ver(&encoder, vpx_codec_vp9_cx(), &cfg, 0, VPX_ENCODER_ABI_VERSION);
    if (err != VPX_CODEC_OK) {
        return;
    }
    
    // Create test image
    vpx_img_fmt_t test_formats[] = {
        VPX_IMG_FMT_I420,
        VPX_IMG_FMT_I422,
        VPX_IMG_FMT_I444,
        VPX_IMG_FMT_I42016,
        VPX_IMG_FMT_I42216,
        VPX_IMG_FMT_I44416
    };
    
    uint8_t format_idx = fdp.ConsumeIntegral<uint8_t>() % 6;
    vpx_img_fmt_t fmt = test_formats[format_idx];
    int bit_depth = (fmt == VPX_IMG_FMT_I42016 || fmt == VPX_IMG_FMT_I42216 || fmt == VPX_IMG_FMT_I44416) ? 10 : 8;
    
    vpx_image_t* img = create_test_image(fdp, cfg.g_w, cfg.g_h, fmt, bit_depth);
    if (!img) {
        vpx_codec_destroy(&encoder);
        return;
    }
    
    // Test various invalid encode scenarios
    uint8_t test_scenario = fdp.ConsumeIntegral<uint8_t>() % 4;
    
    switch (test_scenario) {
        case 0:
            // Encode with NULL image pointer
            err = vpx_codec_encode(&encoder, NULL, 0, 1, 0, VPX_DL_REALTIME);
            break;
        case 1:
            // Encode with mismatched image size (should trigger validate_img error)
            img->d_w = cfg.g_w / 2;
            img->d_h = cfg.g_h / 2;
            err = vpx_codec_encode(&encoder, img, 0, 1, 0, VPX_DL_REALTIME);
            break;
        case 2:
            // Encode with invalid image format for profile
            if (cfg.g_profile == 0) {
                // Profile 0 doesn't support I422/I444
                img->fmt = VPX_IMG_FMT_I422;
                err = vpx_codec_encode(&encoder, img, 0, 1, 0, VPX_DL_REALTIME);
            }
            break;
        case 3:
            // Multiple encodes with invalid flags
            for (int i = 0; i < 3; i++) {
                uint32_t invalid_flags = fdp.ConsumeIntegral<uint32_t>();
                err = vpx_codec_encode(&encoder, img, i, 1, invalid_flags, VPX_DL_REALTIME);
            }
            break;
    }
    
    vpx_img_free(img);
    vpx_codec_destroy(&encoder);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Minimum input size for meaningful testing
    if (size < 256) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);
    
    // Consume configuration parameters
    uint8_t test_type = fdp.ConsumeIntegral<uint8_t>() % 3;
    uint32_t width = 64 + (fdp.ConsumeIntegral<uint8_t>() % 192);  // 64-256
    uint32_t height = 64 + (fdp.ConsumeIntegral<uint8_t>() % 192); // 64-256
    
    // Create a base configuration
    vpx_codec_enc_cfg_t cfg;
    vpx_codec_err_t err = vpx_codec_enc_config_default(vpx_codec_vp9_cx(), &cfg, 0);
    if (err != VPX_CODEC_OK) {
        return 0;
    }
    
    // Set reasonable base values
    cfg.g_w = width;
    cfg.g_h = height;
    cfg.g_timebase.num = 1;
    cfg.g_timebase.den = 30;
    cfg.rc_target_bitrate = 256;
    cfg.g_profile = 0;
    cfg.g_threads = 1;
    cfg.g_lag_in_frames = 0;
    
    vpx_codec_ctx_t encoder;
    
    switch (test_type) {
        case 0:
            // Test vpx_codec_enc_init_ver with invalid configurations
            test_config_validation_paths(fdp, cfg, encoder);
            break;
        case 1:
            // Test vpx_codec_enc_config_set with invalid configurations
            test_enc_config_set_validation(fdp, encoder, cfg);
            break;
        case 2:
            // Test vpx_codec_encode with various invalid states
            test_encode_validation(fdp, encoder, cfg);
            break;
    }
    
    return 0;
}
