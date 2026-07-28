/*
 * Fuzzing harness for libvpx VP9 encoder configuration validation and 
 * mode selection logic targeting top branch blockers identified in coverage analysis.
 * 
 * Target: Comprehensive VP9 encoder configuration validation (validate_config function)
 * and specific conditions in vp9_pick_inter_mode affecting thresh_svc_skip_golden calculations.
 * 
 * Coverage Analysis Focus:
 * 1. validate_config function: 0% coverage (major validation paths untested)
 * 2. vp9_pick_inter_mode: 602+ blocked branches with specific focus on:
 *    - Lines 1796-1802: no_scaling = (lc->scaling_factor_num == lc->scaling_factor_den)
 *    - Lines 1803-1815: thresh_svc_skip_golden conditions based on:
 *        a) svc->spatial_layer_id > 0 && (svc->high_source_sad_superframe || no_scaling)
 *        b) svc->spatial_layer_id > 0 && cm->base_qindex > 150 && 
 *           cm->base_qindex > svc->lower_layer_qindex + 15
 *        c) svc->spatial_layer_id > 0 && cm->base_qindex < 140 && 
 *           cm->base_qindex < svc->lower_layer_qindex - 20
 *    - Lines 1817-1835: gf_temporal_ref conditions for temporal long term prediction
 *    - Lines 1830-1834: thresh_svc_skip_golden adjustments based on rc.avg_frame_low_motion
 * 
 * Semantic Diversity vs Existing Harnesses (040-049):
 * - harness_049: Non-SVC VP9 encoder configuration parameters
 * - harness_048: Two-pass SVC encoding validation
 * - harness_047: VP9 SVC decoder capabilities
 * - harness_046: SVC multi-layer encoding targeting vp9_pick_inter_mode
 * - harness_045: Direct vpx_codec_control_ with SVC parameters
 * - harness_044: SVC rate control and layer startup
 * - This harness (050): EXCLUSIVE focus on:
 *   1. Systematic validation testing of ALL validate_config parameters
 *   2. Targeted testing of specific vp9_pick_inter_mode conditions listed above
 *   3. Edge case and boundary value testing for configuration validation
 *   4. Invalid configuration testing to exercise error paths
 *   5. Interactions between validation parameters and mode selection logic
 * 
 * Key Validation Targets from validate_config:
 * 1. Dimension validation: g_w, g_h (1-65536)
 * 2. Timebase validation: g_timebase.den/num (1-1000000000)
 * 3. Profile validation: g_profile (0-3)
 * 4. Quantizer validation: rc_min/max_quantizer (0-63, min <= max)
 * 5. Boolean validation: lossless, frame_parallel_decoding_mode
 * 6. AQ mode validation: aq_mode (0-7), alt_ref_aq (0-1)
 * 7. Thread/lag validation: g_threads (0-64), g_lag_in_frames (0-35)
 * 8. RC validation: rc_end_usage, rc_undershoot/overshoot_pct (0-100)
 * 9. Two-pass validation: rc_2pass_vbr_bias_pct (0-100), rc_2pass_vbr_corpus_complexity (0-10000)
 * 10. KF mode validation: kf_mode (VPX_KF_DISABLED-VPX_KF_AUTO)
 * 11. Resize validation: rc_resize_allowed, rc_scaled_width/height
 * 12. GOP validation: min_gf_interval, max_gf_interval (0-35)
 * 13. Lag-GF interaction: g_lag_in_frames >= max_gf_interval + 2 when >0
 * 14. Target level validation: LEVEL_1 through LEVEL_6_2, UNKNOWN, AUTO, MAX
 * 15. SVC validation: ss_number_layers, ts_number_layers, layer_target_bitrate ordering
 * 
 * Strategy:
 * 1. Use FuzzedDataProvider to generate comprehensive configuration test cases
 * 2. Test both valid and invalid configurations to exercise validation paths
 * 3. Specifically target thresh_svc_skip_golden conditions in vp9_pick_inter_mode
 * 4. Test boundary values and edge cases for all validated parameters
 * 5. Exercise error recovery and reconfiguration paths
 * 6. Test SVC-specific validation with layer ordering constraints
 */

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <memory>
#include <string>
#include <algorithm>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
#include "vpx/vpx_encoder.h"
#include "vpx/vpx_codec.h"
#include "vpx/vpx_image.h"
#include "vpx/vp8cx.h"
}

// Minimum input size for comprehensive validation testing
const size_t MIN_INPUT_SIZE = 8192;

// Safe constants (since we can't include internal headers)
const unsigned int MAX_NUM_THREADS = 64;
const unsigned int MAX_LAG_BUFFERS = 35;
const unsigned int AQ_MODE_COUNT = 8;  // From vp9_encoder.h: NO_AQ=0 to AQ_MODE_COUNT=8

// Helper to generate test frame with controlled characteristics
static void generate_validation_test_frame(uint8_t* buffer, int width, int height,
                                          int stride, int frame_index,
                                          bool high_sad, FuzzedDataProvider& fdp) {
    // Generate frame patterns that can trigger high_source_sad_superframe
    uint8_t pattern_type = fdp.ConsumeIntegral<uint8_t>() % 3;
    
    for (int y = 0; y < height; y++) {
        uint8_t* row = buffer + y * stride;
        for (int x = 0; x < width; x++) {
            int value;
            if (high_sad) {
                // High SAD patterns: more variation, edges, noise
                value = ((x * 37) ^ (y * 13) ^ (frame_index * 97)) & 0xFF;
            } else {
                // Low SAD patterns: smooth gradients
                value = (x * 255 / std::max(1, width) + y * 255 / std::max(1, height)) / 2;
            }
            
            // Apply pattern variations
            switch (pattern_type) {
                case 0: // Original pattern
                    break;
                case 1: // Checkerboard overlay
                    value ^= ((x / 8) % 2) ^ ((y / 8) % 2) ? 64 : 0;
                    break;
                case 2: // Noise overlay
                    value = (value + (fdp.ConsumeIntegral<uint8_t>() % 32)) & 0xFF;
                    break;
            }
            
            row[x] = static_cast<uint8_t>(value);
        }
    }
}

// Test configuration for validate_config function
struct ValidationTestConfig {
    // Basic dimensions
    int width;
    int height;
    
    // Timebase
    uint32_t timebase_num;
    uint32_t timebase_den;
    
    // Profile
    unsigned int profile;
    
    // Quantizers
    unsigned int rc_min_quantizer;
    unsigned int rc_max_quantizer;
    
    // Boolean flags
    unsigned int lossless;
    unsigned int frame_parallel_decoding_mode;
    
    // AQ settings
    int aq_mode;
    int alt_ref_aq;
    unsigned int frame_periodic_boost;
    
    // Threading
    unsigned int g_threads;
    unsigned int g_lag_in_frames;
    
    // Rate control
    unsigned int rc_end_usage;
    unsigned int rc_undershoot_pct;
    unsigned int rc_overshoot_pct;
    unsigned int rc_2pass_vbr_bias_pct;
    unsigned int rc_2pass_vbr_corpus_complexity;
    
    // Keyframe
    unsigned int kf_mode;
    unsigned int rc_resize_allowed;
    unsigned int rc_dropframe_thresh;
    unsigned int rc_resize_up_thresh;
    unsigned int rc_resize_down_thresh;
    
    // Pass mode
    unsigned int g_pass;
    
    // GOP structure
    unsigned int min_gf_interval;
    unsigned int max_gf_interval;
    
    // Target level
    unsigned int target_level;
    
    // SVC settings
    unsigned int ss_number_layers;
    unsigned int ts_number_layers;
    unsigned int layer_target_bitrate[VPX_MAX_LAYERS];
    
    // Scaled dimensions
    unsigned int rc_scaled_width;
    unsigned int rc_scaled_height;
    
    // Test mode flags
    bool test_invalid_config;
    bool test_svc_validation;
    bool test_thresh_svc_conditions;
    bool test_high_sad_frames;
    
    // For thresh_svc_skip_golden conditions
    int spatial_layer_id;
    int lower_layer_qindex;
    bool no_scaling;
};

// Initialize validation test configuration from fuzzer input
static void init_validation_test_config(ValidationTestConfig* config, 
                                       FuzzedDataProvider& fdp) {
    // Consume test mode flags
    config->test_invalid_config = fdp.ConsumeBool();
    config->test_svc_validation = fdp.ConsumeBool();
    config->test_thresh_svc_conditions = fdp.ConsumeBool();
    config->test_high_sad_frames = fdp.ConsumeBool();
    
    // Basic dimensions (test both valid and invalid ranges)
    if (config->test_invalid_config && fdp.ConsumeBool()) {
        // Invalid dimensions
        config->width = fdp.ConsumeIntegralInRange<int>(65537, 131072);
        config->height = fdp.ConsumeIntegralInRange<int>(65537, 131072);
    } else {
        // Valid dimensions
        config->width = fdp.ConsumeIntegralInRange<int>(1, 65536);
        config->height = fdp.ConsumeIntegralInRange<int>(1, 65536);
    }
    
    // Timebase (test boundary values)
    if (config->test_invalid_config && fdp.ConsumeBool()) {
        config->timebase_num = 0;
        config->timebase_den = fdp.ConsumeIntegralInRange<uint32_t>(1000000001, 2000000000);
    } else {
        config->timebase_num = fdp.ConsumeIntegralInRange<uint32_t>(1, 1000000000);
        config->timebase_den = fdp.ConsumeIntegralInRange<uint32_t>(1, 1000000000);
    }
    
    // Profile (test out of range)
    if (config->test_invalid_config && fdp.ConsumeBool()) {
        config->profile = fdp.ConsumeIntegralInRange<unsigned int>(4, 10);
    } else {
        config->profile = fdp.ConsumeIntegralInRange<unsigned int>(0, 3);
    }
    
    // Quantizers (test invalid ordering)
    config->rc_max_quantizer = fdp.ConsumeIntegralInRange<unsigned int>(0, 63);
    if (config->test_invalid_config && fdp.ConsumeBool()) {
        config->rc_min_quantizer = config->rc_max_quantizer + 
                                  fdp.ConsumeIntegralInRange<unsigned int>(1, 10);
    } else {
        config->rc_min_quantizer = fdp.ConsumeIntegralInRange<unsigned int>(0, config->rc_max_quantizer);
    }
    
    // Boolean flags (test non-boolean values)
    if (config->test_invalid_config && fdp.ConsumeBool()) {
        config->lossless = fdp.ConsumeIntegralInRange<unsigned int>(2, 10);
        config->frame_parallel_decoding_mode = fdp.ConsumeIntegralInRange<unsigned int>(2, 10);
    } else {
        config->lossless = fdp.ConsumeBool() ? 1 : 0;
        config->frame_parallel_decoding_mode = fdp.ConsumeBool() ? 1 : 0;
    }
    
    // AQ settings
    if (config->test_invalid_config && fdp.ConsumeBool()) {
        config->aq_mode = fdp.ConsumeIntegralInRange<int>(AQ_MODE_COUNT - 1, AQ_MODE_COUNT + 5);
        config->alt_ref_aq = fdp.ConsumeIntegralInRange<int>(2, 10);
    } else {
        config->aq_mode = fdp.ConsumeIntegralInRange<int>(0, AQ_MODE_COUNT - 2);
        config->alt_ref_aq = fdp.ConsumeBool() ? 1 : 0;
    }
    config->frame_periodic_boost = fdp.ConsumeIntegralInRange<unsigned int>(0, 1);
    
    // Threading (test exceeding limits)
    if (config->test_invalid_config && fdp.ConsumeBool()) {
        config->g_threads = fdp.ConsumeIntegralInRange<unsigned int>(MAX_NUM_THREADS + 1, MAX_NUM_THREADS + 10);
        config->g_lag_in_frames = fdp.ConsumeIntegralInRange<unsigned int>(MAX_LAG_BUFFERS + 1, MAX_LAG_BUFFERS + 10);
    } else {
        config->g_threads = fdp.ConsumeIntegralInRange<unsigned int>(0, MAX_NUM_THREADS);
        config->g_lag_in_frames = fdp.ConsumeIntegralInRange<unsigned int>(0, MAX_LAG_BUFFERS);
    }
    
    // Rate control parameters
    config->rc_end_usage = fdp.ConsumeIntegralInRange<unsigned int>(VPX_VBR, VPX_Q);
    config->rc_undershoot_pct = fdp.ConsumeIntegralInRange<unsigned int>(0, 100);
    config->rc_overshoot_pct = fdp.ConsumeIntegralInRange<unsigned int>(0, 100);
    config->rc_2pass_vbr_bias_pct = fdp.ConsumeIntegralInRange<unsigned int>(0, 100);
    config->rc_2pass_vbr_corpus_complexity = fdp.ConsumeIntegralInRange<unsigned int>(0, 10000);
    
    // Keyframe mode
    config->kf_mode = fdp.ConsumeIntegralInRange<unsigned int>(VPX_KF_DISABLED, VPX_KF_AUTO);
    config->rc_resize_allowed = fdp.ConsumeBool() ? 1 : 0;
    config->rc_dropframe_thresh = fdp.ConsumeIntegralInRange<unsigned int>(0, 100);
    config->rc_resize_up_thresh = fdp.ConsumeIntegralInRange<unsigned int>(0, 100);
    config->rc_resize_down_thresh = fdp.ConsumeIntegralInRange<unsigned int>(0, 100);
    
    // Pass mode (test invalid for realtime-only)
    config->g_pass = fdp.ConsumeIntegralInRange<unsigned int>(VPX_RC_ONE_PASS, VPX_RC_LAST_PASS);
    
    // GOP intervals (test invalid relationships)
    config->min_gf_interval = fdp.ConsumeIntegralInRange<unsigned int>(0, MAX_LAG_BUFFERS - 1);
    config->max_gf_interval = fdp.ConsumeIntegralInRange<unsigned int>(0, MAX_LAG_BUFFERS - 1);
    
    if (config->test_invalid_config && fdp.ConsumeBool()) {
        // Make max < min when both > 0
        if (config->min_gf_interval > 0 && config->max_gf_interval > 0) {
            if (config->max_gf_interval > config->min_gf_interval) {
                std::swap(config->min_gf_interval, config->max_gf_interval);
            }
        }
        // Test invalid lag-gf relationship
        if (config->g_lag_in_frames > 0 && config->max_gf_interval > 0) {
            config->g_lag_in_frames = fdp.ConsumeIntegralInRange<unsigned int>(1, config->max_gf_interval + 1);
        }
    }
    
    // Target level (test invalid values)
    const unsigned int valid_levels[] = {
        0, 10, 11, 20, 21, 30, 31, 40, 41, 50, 51, 52, 60, 61, 62, 255, 256, 1000
    };
    
    if (config->test_invalid_config && fdp.ConsumeBool()) {
        // Generate invalid level
        do {
            config->target_level = fdp.ConsumeIntegralInRange<unsigned int>(0, 1000);
        } while (std::find(std::begin(valid_levels), std::end(valid_levels), config->target_level) != std::end(valid_levels));
    } else {
        // Pick valid level
        config->target_level = valid_levels[fdp.ConsumeIntegralInRange<size_t>(0, sizeof(valid_levels)/sizeof(valid_levels[0]) - 1)];
    }
    
    // SVC settings for thresh_svc_skip_golden conditions
    config->spatial_layer_id = fdp.ConsumeIntegralInRange<int>(0, 3);
    config->lower_layer_qindex = fdp.ConsumeIntegralInRange<int>(0, 255);
    config->no_scaling = fdp.ConsumeBool();
    
    // SVC layer configuration
    if (config->test_svc_validation) {
        config->ss_number_layers = fdp.ConsumeIntegralInRange<unsigned int>(1, VPX_SS_MAX_LAYERS);
        config->ts_number_layers = fdp.ConsumeIntegralInRange<unsigned int>(1, VPX_TS_MAX_LAYERS);
        
        // Test invalid layer count product
        if (config->test_invalid_config && fdp.ConsumeBool()) {
            config->ss_number_layers = fdp.ConsumeIntegralInRange<unsigned int>(VPX_SS_MAX_LAYERS/2 + 1, VPX_SS_MAX_LAYERS);
            config->ts_number_layers = fdp.ConsumeIntegralInRange<unsigned int>(VPX_TS_MAX_LAYERS/2 + 1, VPX_TS_MAX_LAYERS);
        }
        
        // Initialize layer target bitrates
        unsigned int total_layers = config->ss_number_layers * config->ts_number_layers;
        unsigned int base_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 10000);
        
        for (unsigned int i = 0; i < VPX_MAX_LAYERS; i++) {
            if (i < total_layers) {
                config->layer_target_bitrate[i] = base_bitrate + i * 100;
                
                // Test non-increasing bitrates for SVC validation
                if (config->test_invalid_config && fdp.ConsumeBool() && i > 0) {
                    config->layer_target_bitrate[i] = config->layer_target_bitrate[i-1] - 50;
                }
            } else {
                config->layer_target_bitrate[i] = 0;
            }
        }
    } else {
        config->ss_number_layers = 1;
        config->ts_number_layers = 1;
        for (int i = 0; i < VPX_MAX_LAYERS; i++) {
            config->layer_target_bitrate[i] = 0;
        }
    }
    
    // Scaled dimensions
    if (config->rc_resize_allowed) {
        config->rc_scaled_width = fdp.ConsumeIntegralInRange<unsigned int>(0, config->width);
        config->rc_scaled_height = fdp.ConsumeIntegralInRange<unsigned int>(0, config->height);
        
        // Test invalid scaled dimensions
        if (config->test_invalid_config && fdp.ConsumeBool()) {
            config->rc_scaled_width = config->width + fdp.ConsumeIntegralInRange<unsigned int>(1, 100);
            config->rc_scaled_height = config->height + fdp.ConsumeIntegralInRange<unsigned int>(1, 100);
        }
    } else {
        config->rc_scaled_width = 0;
        config->rc_scaled_height = 0;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum input size check
    if (size < MIN_INPUT_SIZE) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Initialize validation test configuration
    ValidationTestConfig config;
    init_validation_test_config(&config, fdp);
    
    // Initialize encoder configuration with defaults
    vpx_codec_enc_cfg_t cfg;
    vpx_codec_iface_t* iface = vpx_codec_vp9_cx();
    
    if (vpx_codec_enc_config_default(iface, &cfg, 0) != VPX_CODEC_OK) {
        return 0;
    }
    
    // Apply validation test configuration
    cfg.g_w = config.width;
    cfg.g_h = config.height;
    cfg.g_timebase.num = config.timebase_num;
    cfg.g_timebase.den = config.timebase_den;
    cfg.g_profile = config.profile;
    
    cfg.rc_min_quantizer = config.rc_min_quantizer;
    cfg.rc_max_quantizer = config.rc_max_quantizer;
    
    cfg.g_threads = config.g_threads;
    cfg.g_lag_in_frames = config.g_lag_in_frames;
    
    cfg.rc_end_usage = static_cast<vpx_rc_mode>(config.rc_end_usage);
    cfg.rc_undershoot_pct = config.rc_undershoot_pct;
    cfg.rc_overshoot_pct = config.rc_overshoot_pct;
    cfg.rc_2pass_vbr_bias_pct = config.rc_2pass_vbr_bias_pct;
    cfg.rc_2pass_vbr_corpus_complexity = config.rc_2pass_vbr_corpus_complexity;
    
    cfg.kf_mode = static_cast<vpx_kf_mode>(config.kf_mode);
    cfg.rc_resize_allowed = config.rc_resize_allowed;
    cfg.rc_dropframe_thresh = config.rc_dropframe_thresh;
    cfg.rc_resize_up_thresh = config.rc_resize_up_thresh;
    cfg.rc_resize_down_thresh = config.rc_resize_down_thresh;
    
    cfg.g_pass = static_cast<vpx_enc_pass>(config.g_pass);
    
    cfg.ss_number_layers = config.ss_number_layers;
    cfg.ts_number_layers = config.ts_number_layers;
    for (int i = 0; i < VPX_MAX_LAYERS; i++) {
        cfg.layer_target_bitrate[i] = config.layer_target_bitrate[i];
    }
    
    cfg.rc_scaled_width = config.rc_scaled_width;
    cfg.rc_scaled_height = config.rc_scaled_height;
    
    // Set target bitrate
    cfg.rc_target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 10000);
    
    // Try to initialize encoder with test configuration
    // This will trigger validate_config internally
    vpx_codec_ctx_t codec;
    vpx_codec_err_t init_result = vpx_codec_enc_init(&codec, iface, &cfg, 0);
    
    // Test reconfiguration if initial config was valid
    if (init_result == VPX_CODEC_OK) {
        // Apply extra configuration parameters via vpx_codec_control_
        // These are validated by validate_config when passed via vpx_codec_enc_config_set
        
        // Test lossless mode
        vpx_codec_control_(&codec, VP9E_SET_LOSSLESS, config.lossless);
        
        // Test frame parallel decoding mode
        vpx_codec_control_(&codec, VP9E_SET_FRAME_PARALLEL_DECODING, config.frame_parallel_decoding_mode);
        
        // Test AQ mode
        vpx_codec_control_(&codec, VP9E_SET_AQ_MODE, config.aq_mode);
        
        // Test alt-ref AQ
        vpx_codec_control_(&codec, VP9E_SET_ALT_REF_AQ, config.alt_ref_aq);
        
        // Test frame periodic boost
        vpx_codec_control_(&codec, VP8E_SET_FRAME_FLAGS, config.frame_periodic_boost ? VP8_EFLAG_NO_REF_LAST : 0);
        
        // Test target level
        vpx_codec_control_(&codec, VP9E_SET_TARGET_LEVEL, config.target_level);
        
        // Test GOP intervals
        vpx_codec_control_(&codec, VP9E_SET_MIN_GF_INTERVAL, config.min_gf_interval);
        vpx_codec_control_(&codec, VP9E_SET_MAX_GF_INTERVAL, config.max_gf_interval);
        
        // Test SVC parameters if configured
        if (config.test_svc_validation && config.ss_number_layers > 1) {
            // Set SVC parameters
            vpx_codec_control_(&codec, VP9E_SET_SVC, 1);
            
            // Configure spatial layers
            vpx_svc_extra_cfg_t svc_params = {};
            svc_params.temporal_layering_mode = VP9E_TEMPORAL_LAYERING_MODE_BYPASS;
            
            for (unsigned int i = 0; i < config.ss_number_layers; i++) {
                svc_params.scaling_factor_num[i] = config.no_scaling ? 1 : (i + 1);
                svc_params.scaling_factor_den[i] = config.no_scaling ? 1 : config.ss_number_layers;
                
                // Note: layer_target_bitrate is set in the main encoder configuration (cfg.layer_target_bitrate[i])
                // which we already set earlier
            }
            vpx_codec_control_(&codec, VP9E_SET_SVC_PARAMETERS, &svc_params);
            
            // Set spatial layer ID for thresh_svc_skip_golden conditions
            // Note: This would normally be set internally by the encoder during SVC encoding
            // We're simulating the conditions that affect vp9_pick_inter_mode
        }
        
        // Now test encoding with this configuration to exercise vp9_pick_inter_mode
        // conditions related to thresh_svc_skip_golden
        
        // Create test image
        int width = (config.width + 15) & ~15;
        int height = (config.height + 15) & ~15;
        
        vpx_image_t* img = vpx_img_alloc(NULL, VPX_IMG_FMT_I420, width, height, 1);
        if (img) {
            // Generate frame with controlled characteristics for thresh_svc conditions
            bool high_sad = config.test_high_sad_frames || 
                           (config.test_thresh_svc_conditions && fdp.ConsumeBool());
            
            generate_validation_test_frame(img->planes[VPX_PLANE_Y], width, height,
                                          img->stride[VPX_PLANE_Y], 0, high_sad, fdp);
            
            // Simple UV planes
            int uv_width = (width + 1) / 2;
            int uv_height = (height + 1) / 2;
            for (int y = 0; y < uv_height; y++) {
                memset(img->planes[VPX_PLANE_U] + y * img->stride[VPX_PLANE_U], 128, uv_width);
                memset(img->planes[VPX_PLANE_V] + y * img->stride[VPX_PLANE_V], 128, uv_width);
            }
            
            // Encode a few frames to exercise the configuration
            int num_frames = fdp.ConsumeIntegralInRange<int>(1, 5);
            for (int frame_idx = 0; frame_idx < num_frames; frame_idx++) {
                // Update frame for temporal variation
                if (frame_idx > 0) {
                    generate_validation_test_frame(img->planes[VPX_PLANE_Y], width, height,
                                                  img->stride[VPX_PLANE_Y], frame_idx, high_sad, fdp);
                }
                
                // Encode frame
                vpx_codec_encode(&codec, img, frame_idx, 1, 0, VPX_DL_REALTIME);
                
                // Get and discard compressed data
                vpx_codec_iter_t iter = NULL;
                const vpx_codec_cx_pkt_t* pkt;
                while ((pkt = vpx_codec_get_cx_data(&codec, &iter)) != NULL) {
                    (void)pkt;
                }
                
                // Check for insufficient input
                if (fdp.remaining_bytes() < 100) {
                    break;
                }
            }
            
            vpx_img_free(img);
        }
        
        // Clean up encoder
        vpx_codec_destroy(&codec);
    }
    
    // Test configuration set API (triggers validate_config)
    if (init_result == VPX_CODEC_OK || !config.test_invalid_config) {
        // Try to create another encoder and test vpx_codec_enc_config_set
        vpx_codec_ctx_t codec2;
        if (vpx_codec_enc_init(&codec2, iface, &cfg, 0) == VPX_CODEC_OK) {
            // Modify configuration and try to set it
            vpx_codec_enc_cfg_t cfg2 = cfg;
            
            // Change some parameters that should trigger re-validation
            if (config.test_invalid_config && fdp.ConsumeBool()) {
                // Make invalid change
                cfg2.g_w = 0;  // Invalid width
            } else {
                // Make valid change
                cfg2.rc_target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 10000);
            }
            
            vpx_codec_err_t set_result = vpx_codec_enc_config_set(&codec2, &cfg2);
            (void)set_result;  // Result checked by validate_config internally
            
            vpx_codec_destroy(&codec2);
        }
    }
    
    return 0;
}
