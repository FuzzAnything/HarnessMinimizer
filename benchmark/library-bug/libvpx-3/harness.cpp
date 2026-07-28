#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <memory>
#include <algorithm>
#include <limits>

#include <fuzzer/FuzzedDataProvider.h>
#include "vpx/vpx_encoder.h"
#include "vpx/vp8cx.h"
#include "vpx/vpx_image.h"

// Helper to generate extreme dimension values (1x1 to 65536x65536)
static void generate_extreme_dimensions(FuzzedDataProvider &fdp, 
                                       unsigned int &width, 
                                       unsigned int &height) {
    uint8_t dimension_mode = fdp.ConsumeIntegral<uint8_t>() % 5;
    
    switch (dimension_mode) {
        case 0: // Minimum dimensions
            width = 1;
            height = 1;
            break;
        case 1: // Maximum dimensions (65K x 65K)
            width = 65536;
            height = 65536;
            break;
        case 2: // Extreme width, normal height
            width = fdp.ConsumeIntegralInRange<unsigned int>(1, 65536);
            height = fdp.ConsumeIntegralInRange<unsigned int>(1, 1024);
            break;
        case 3: // Normal width, extreme height
            width = fdp.ConsumeIntegralInRange<unsigned int>(1, 1024);
            height = fdp.ConsumeIntegralInRange<unsigned int>(1, 65536);
            break;
        case 4: // Random dimensions in full range
            width = fdp.ConsumeIntegralInRange<unsigned int>(1, 65536);
            height = fdp.ConsumeIntegralInRange<unsigned int>(1, 65536);
            break;
    }
}

// Helper to generate invalid timebase combinations
static void generate_timebase_edge_cases(FuzzedDataProvider &fdp,
                                        vpx_rational_t &timebase) {
    uint8_t timebase_mode = fdp.ConsumeIntegral<uint8_t>() % 6;
    
    switch (timebase_mode) {
        case 0: // Zero numerator
            timebase.num = 0;
            timebase.den = fdp.ConsumeIntegralInRange<int>(1, 1000);
            break;
        case 1: // Zero denominator (invalid)
            timebase.num = fdp.ConsumeIntegralInRange<int>(1, 1000);
            timebase.den = 0;
            break;
        case 2: // Both zero (invalid)
            timebase.num = 0;
            timebase.den = 0;
            break;
        case 3: // Very large values
            timebase.num = fdp.ConsumeIntegralInRange<int>(1, std::numeric_limits<int>::max() / 2);
            timebase.den = fdp.ConsumeIntegralInRange<int>(1, std::numeric_limits<int>::max() / 2);
            break;
        case 4: // Negative values (invalid for timebase)
            timebase.num = -fdp.ConsumeIntegralInRange<int>(1, 1000);
            timebase.den = fdp.ConsumeIntegralInRange<int>(1, 1000);
            break;
        case 5: // Valid but unusual
            timebase.num = fdp.ConsumeIntegralInRange<int>(1, 1001);
            timebase.den = fdp.ConsumeIntegralInRange<int>(24, 60000);
            break;
    }
}

// Helper to generate layer configuration edge cases
static void generate_layer_edge_cases(FuzzedDataProvider &fdp,
                                     vpx_codec_enc_cfg_t &cfg) {
    // Test VPX_TS_MAX_LAYERS edge cases (5 layers max for temporal scaling)
    uint8_t layer_mode = fdp.ConsumeIntegral<uint8_t>() % 4;
    
    switch (layer_mode) {
        case 0: // Maximum temporal layers
            cfg.ts_number_layers = VPX_TS_MAX_LAYERS;
            cfg.ss_number_layers = VPX_SS_MAX_LAYERS;
            break;
        case 1: // Exceed maximum (should trigger validation errors)
            cfg.ts_number_layers = VPX_TS_MAX_LAYERS + 1;
            cfg.ss_number_layers = VPX_SS_MAX_LAYERS + 1;
            break;
        case 2: // Zero layers (invalid)
            cfg.ts_number_layers = 0;
            cfg.ss_number_layers = 0;
            break;
        case 3: // Random valid layers
            cfg.ts_number_layers = fdp.ConsumeIntegralInRange<unsigned int>(1, VPX_TS_MAX_LAYERS);
            cfg.ss_number_layers = fdp.ConsumeIntegralInRange<unsigned int>(1, VPX_SS_MAX_LAYERS);
            break;
    }
    
    // Set periodicity (must be >= number of layers)
    if (cfg.ts_number_layers > 0) {
        cfg.ts_periodicity = fdp.ConsumeIntegralInRange<unsigned int>(
            cfg.ts_number_layers, 
            VPX_TS_MAX_PERIODICITY
        );
    } else {
        cfg.ts_periodicity = 0;
    }
    
    // Set rate decimators with power-of-2 constraints
    // Only iterate up to VPX_TS_MAX_LAYERS to avoid array bounds errors
    unsigned int layers_to_process = std::min(cfg.ts_number_layers, (unsigned int)VPX_TS_MAX_LAYERS);
    for (unsigned int i = 0; i < layers_to_process; ++i) {
        // ts_rate_decimator[i] must be power of 2
        uint8_t power = fdp.ConsumeIntegralInRange<uint8_t>(0, 8);
        cfg.ts_rate_decimator[i] = 1 << power;
        
        // Also test invalid non-power-of-2 values
        if (fdp.ConsumeBool() && i > 0) {
            cfg.ts_rate_decimator[i] = fdp.ConsumeIntegralInRange<unsigned int>(3, 100);
        }
    }
    
    // Set target bitrates for layers
    unsigned int total_bitrate = cfg.rc_target_bitrate;
    // Only iterate up to VPX_TS_MAX_LAYERS to avoid array bounds errors
    layers_to_process = std::min(cfg.ts_number_layers, (unsigned int)VPX_TS_MAX_LAYERS);
    
    // Handle edge case when total_bitrate is 0 or 1
    if (total_bitrate <= 1) {
        for (unsigned int i = 0; i < layers_to_process; ++i) {
            cfg.ts_target_bitrate[i] = total_bitrate;
        }
        return;
    }
    
    // Distribute bitrate across layers
    for (unsigned int i = 0; i < layers_to_process; ++i) {
        unsigned int remaining_layers = layers_to_process - i;
        
        if (remaining_layers == 1) {
            // Last layer gets all remaining bitrate
            cfg.ts_target_bitrate[i] = total_bitrate;
            break;
        }
        
        // If we have no bitrate left, set remaining layers to 0
        if (total_bitrate == 0) {
            cfg.ts_target_bitrate[i] = 0;
            continue;
        }
        
        // We need to leave at least 1 for each remaining layer if possible
        unsigned int min_for_remaining = remaining_layers - 1;
        
        // Check if we have enough bitrate to satisfy minimum requirements
        if (total_bitrate <= min_for_remaining) {
            // Not enough bitrate to give 1 to each remaining layer
            // Give either 0 or 1 to this layer
            if (total_bitrate > 0) {
                cfg.ts_target_bitrate[i] = 1;
                total_bitrate -= 1;
            } else {
                cfg.ts_target_bitrate[i] = 0;
            }
            continue;
        }
        
        // We have enough for requirements, calculate max allocation
        unsigned int max_alloc = total_bitrate - min_for_remaining;
        
        // Also limit to half of remaining bitrate to leave some for others
        if (max_alloc > total_bitrate / 2) {
            max_alloc = total_bitrate / 2;
        }
        
        // max_alloc should be at least 1 since total_bitrate > min_for_remaining
        // but ensure it's at least 1 for safety
        if (max_alloc < 1) {
            max_alloc = 1;
        }
        
        cfg.ts_target_bitrate[i] = fdp.ConsumeIntegralInRange<unsigned int>(1, max_alloc);
        total_bitrate -= cfg.ts_target_bitrate[i];
    }
}
// Helper to test lag-in-frames relationships with max_gf_interval constraints
static void generate_lag_in_frames_edge_cases(FuzzedDataProvider &fdp,
                                             vpx_codec_enc_cfg_t &cfg) {
    // g_lag_in_frames must be 0 when g_pass == VPX_RC_FIRST_PASS
    // and must be <= MAX_LAG_BUFFERS (25 for VP9)
    
    uint8_t lag_mode = fdp.ConsumeIntegral<uint8_t>() % 5;
    
    switch (lag_mode) {
        case 0: // Valid lag with first pass (should be 0)
            cfg.g_pass = VPX_RC_FIRST_PASS;
            cfg.g_lag_in_frames = 0;
            break;
        case 1: // Invalid lag with first pass (non-zero)
            cfg.g_pass = VPX_RC_FIRST_PASS;
            cfg.g_lag_in_frames = fdp.ConsumeIntegralInRange<unsigned int>(1, 25);
            break;
        case 2: // Maximum lag
            cfg.g_pass = VPX_RC_LAST_PASS;
            cfg.g_lag_in_frames = 25; // MAX_LAG_BUFFERS
            break;
        case 3: // Exceed maximum lag
            cfg.g_pass = VPX_RC_LAST_PASS;
            cfg.g_lag_in_frames = 26; // Exceeds MAX_LAG_BUFFERS
            break;
        case 4: // Random valid lag
            cfg.g_pass = VPX_RC_LAST_PASS;
            cfg.g_lag_in_frames = fdp.ConsumeIntegralInRange<unsigned int>(0, 25);
            break;
    }
    // Note: max_gf_interval is not a field in vpx_codec_enc_cfg_t
    // It appears to be an internal constraint, not exposed in public API
    // The relationship between lag_in_frames and golden frame interval
    // is validated internally in the encoder implementation
    
    // For lag-in-frames validation, we can test that g_lag_in_frames = 0 
    // when g_pass == VPX_RC_FIRST_PASS (as per API documentation)
    // and that g_lag_in_frames <= internal limit (25 for VP9)
}

// Helper to test rc_resize_allowed with scaled bounds
static void generate_resize_edge_cases(FuzzedDataProvider &fdp,
                                      vpx_codec_enc_cfg_t &cfg) {
    cfg.rc_resize_allowed = fdp.ConsumeBool() ? 1 : 0;
    
    if (cfg.rc_resize_allowed) {
        // When resize is allowed, scaled dimensions must be valid
        
        uint8_t resize_mode = fdp.ConsumeIntegral<uint8_t>() % 4;
        
        switch (resize_mode) {
            case 0: // Valid scaled dimensions (smaller than original)
                cfg.rc_scaled_width = fdp.ConsumeIntegralInRange<unsigned int>(
                    1, cfg.g_w
                );
                cfg.rc_scaled_height = fdp.ConsumeIntegralInRange<unsigned int>(
                    1, cfg.g_h
                );
                break;
            case 1: // Scaled width larger than original (invalid)
                cfg.rc_scaled_width = cfg.g_w + fdp.ConsumeIntegralInRange<unsigned int>(1, 100);
                cfg.rc_scaled_height = cfg.g_h;
                break;
            case 2: // Scaled height larger than original (invalid)
                cfg.rc_scaled_width = cfg.g_w;
                cfg.rc_scaled_height = cfg.g_h + fdp.ConsumeIntegralInRange<unsigned int>(1, 100);
                break;
            case 3: // Zero dimensions (invalid)
                cfg.rc_scaled_width = 0;
                cfg.rc_scaled_height = 0;
                break;
        }
        
        // Set resize thresholds
        cfg.rc_resize_up_thresh = fdp.ConsumeIntegralInRange<unsigned int>(0, 100);
        cfg.rc_resize_down_thresh = fdp.ConsumeIntegralInRange<unsigned int>(0, 100);
        
        // Test invalid threshold relationships
        if (fdp.ConsumeBool()) {
            cfg.rc_resize_up_thresh = 101; // Exceeds 100%
        }
        if (fdp.ConsumeBool()) {
            cfg.rc_resize_down_thresh = 101; // Exceeds 100%
        }
    } else {
        // When resize not allowed, scaled dimensions should be ignored
        // but we can still set them to test validation
        cfg.rc_scaled_width = fdp.ConsumeIntegralInRange<unsigned int>(0, cfg.g_w);
        cfg.rc_scaled_height = fdp.ConsumeIntegralInRange<unsigned int>(0, cfg.g_h);
    }
}

// Helper to test kf_mode with kf_min_dist/kf_max_dist combinations
static void generate_kf_edge_cases(FuzzedDataProvider &fdp,
                                  vpx_codec_enc_cfg_t &cfg) {
    // kf_mode values: VPX_KF_DISABLED (0), VPX_KF_AUTO, VPX_KF_FIXED (deprecated)
    
    uint8_t kf_mode_val = fdp.ConsumeIntegral<uint8_t>() % 4;
    
    switch (kf_mode_val) {
        case 0:
            cfg.kf_mode = VPX_KF_DISABLED;
            break;
        case 1:
            cfg.kf_mode = VPX_KF_AUTO;
            break;
        case 2:
            cfg.kf_mode = VPX_KF_FIXED; // Deprecated, implies VPX_KF_DISABLED
            break;
        case 3:
            // Invalid kf_mode value
            cfg.kf_mode = static_cast<enum vpx_kf_mode>(3);
            break;
    }
    
    // Set kf_min_dist and kf_max_dist
    // kf_min_dist must be <= kf_max_dist
    // kf_max_dist must be <= 65535
    
    cfg.kf_min_dist = fdp.ConsumeIntegralInRange<unsigned int>(0, 65535);
    cfg.kf_max_dist = fdp.ConsumeIntegralInRange<unsigned int>(0, 65535);
    
    // Test invalid relationships
    if (fdp.ConsumeBool()) {
        // min > max
        cfg.kf_min_dist = cfg.kf_max_dist + fdp.ConsumeIntegralInRange<unsigned int>(1, 100);
    }
    if (fdp.ConsumeBool()) {
        // max too large
        cfg.kf_max_dist = 65536; // Exceeds limit
    }
    
    // kf_max_dist of 0 means unlimited, but has special handling
    if (fdp.ConsumeBool()) {
        cfg.kf_max_dist = 0;
    }
}

// Main fuzzer entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Need sufficient data for complex configuration testing
    if (size < 256) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Use VP9 encoder for configuration validation testing
    vpx_codec_iface_t *iface = vpx_codec_vp9_cx();
    if (!iface) {
        return 0;
    }
    
    // Get default configuration
    vpx_codec_enc_cfg_t cfg;
    if (vpx_codec_enc_config_default(iface, &cfg, 0) != VPX_CODEC_OK) {
        return 0;
    }
    
    // Test extreme dimension values
    generate_extreme_dimensions(fdp, cfg.g_w, cfg.g_h);
    
    // Test invalid timebase combinations  
    generate_timebase_edge_cases(fdp, cfg.g_timebase);
    
    // Test bit depth edge cases
    uint8_t bit_depth_mode = fdp.ConsumeIntegral<uint8_t>() % 4;
    switch (bit_depth_mode) {
        case 0:
            cfg.g_bit_depth = VPX_BITS_8;
            cfg.g_input_bit_depth = 8;
            break;
        case 1:
            cfg.g_bit_depth = VPX_BITS_10;
            cfg.g_input_bit_depth = 10;
            break;
        case 2:
            // Mismatched bit depths (should trigger validation)
            cfg.g_bit_depth = VPX_BITS_8;
            cfg.g_input_bit_depth = 10;
            break;
        case 3:
            // Invalid bit depth values
            cfg.g_bit_depth = static_cast<vpx_bit_depth_t>(3);
            cfg.g_input_bit_depth = 12;
            break;
    }
    
    // Test error resilient flags
    cfg.g_error_resilient = fdp.ConsumeIntegral<vpx_codec_er_flags_t>();
    
    // Test target bitrate edge cases
    uint8_t bitrate_mode = fdp.ConsumeIntegral<uint8_t>() % 3;
    switch (bitrate_mode) {
        case 0: // Normal bitrate
            cfg.rc_target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(1, 100000);
            break;
        case 1: // Zero bitrate (invalid for some modes)
            cfg.rc_target_bitrate = 0;
            break;
        case 2: // Very large bitrate
            cfg.rc_target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(1000000, 2000000);
            break;
    }
    
    // Test rate control mode edge cases
    cfg.rc_end_usage = static_cast<enum vpx_rc_mode>(
        fdp.ConsumeIntegral<uint8_t>() % 4
    );
    
    // Test quantizer bounds
    cfg.rc_min_quantizer = fdp.ConsumeIntegralInRange<unsigned int>(0, 63);
    cfg.rc_max_quantizer = fdp.ConsumeIntegralInRange<unsigned int>(0, 63);
    
    // Test invalid quantizer relationships (min > max)
    if (fdp.ConsumeBool()) {
        cfg.rc_min_quantizer = cfg.rc_max_quantizer + 
                              fdp.ConsumeIntegralInRange<unsigned int>(1, 10);
        if (cfg.rc_min_quantizer > 63) cfg.rc_min_quantizer = 63;
    }
    
    // Test layer configuration edge cases
    generate_layer_edge_cases(fdp, cfg);
    
    // Test lag-in-frames relationships
    generate_lag_in_frames_edge_cases(fdp, cfg);
    
    // Test resize configuration edge cases
    generate_resize_edge_cases(fdp, cfg);
    
    // Test keyframe configuration edge cases
    generate_kf_edge_cases(fdp, cfg);
    
    // Test drop frame threshold edge cases
    cfg.rc_dropframe_thresh = fdp.ConsumeIntegralInRange<unsigned int>(0, 100);
    if (fdp.ConsumeBool()) {
        cfg.rc_dropframe_thresh = 101; // Exceeds 100%
    }
    
    // Test thread count edge cases
    cfg.g_threads = fdp.ConsumeIntegralInRange<unsigned int>(0, 64);
    
    // Initialize encoder with edge-case configuration
    vpx_codec_ctx_t codec;
    vpx_codec_flags_t flags = 0;
    
    vpx_codec_err_t init_result = vpx_codec_enc_init_ver(
        &codec, iface, &cfg, flags, VPX_ENCODER_ABI_VERSION
    );
    
    // Even if initialization fails (expected for invalid configs),
    // we still want to test vpx_codec_enc_config_set
    
    if (init_result == VPX_CODEC_OK) {
        // Test reconfiguring with different edge cases
        for (int i = 0; i < 3 && fdp.remaining_bytes() > 100; ++i) {
            // Create a modified config with different edge cases
            vpx_codec_enc_cfg_t modified_cfg = cfg;
            
            // Change some parameters
            modified_cfg.g_w = fdp.ConsumeIntegralInRange<unsigned int>(1, 65536);
            modified_cfg.g_h = fdp.ConsumeIntegralInRange<unsigned int>(1, 65536);
            modified_cfg.rc_target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(1, 100000);
            
            // Try to set the new configuration
            vpx_codec_err_t config_result = vpx_codec_enc_config_set(
                &codec, &modified_cfg
            );
            
            // If config set succeeds, try encoding
            if (config_result == VPX_CODEC_OK && fdp.remaining_bytes() > 50) {
                // Create minimal test frame
                vpx_image_t *img = vpx_img_alloc(
                    nullptr, VPX_IMG_FMT_I420, 
                    modified_cfg.g_w, modified_cfg.g_h, 1
                );
                
                if (img) {
                    // Fill with minimal data
                    size_t y_size = modified_cfg.g_w * modified_cfg.g_h;
                    if (fdp.remaining_bytes() >= y_size) {
                        std::vector<uint8_t> y_data = fdp.ConsumeBytes<uint8_t>(y_size);
                        memset(img->planes[0], 128, y_size);
                    }
                    
                    // Try encoding
                    vpx_codec_encode(&codec, img, 0, 1, 0, VPX_DL_REALTIME);
                    
                    vpx_img_free(img);
                }
            }
        }
        
        // Clean up
        vpx_codec_destroy(&codec);
    } else {
        // Initialization failed - check error details
        const char *error_detail = vpx_codec_error_detail(&codec);
        (void)error_detail;
    }
    
    return 0;
}
