/*
 * Fuzzing harness for libvpx advanced encoder control APIs focusing on SVC (Scalable Video Coding)
 * Target APIs: vpx_codec_enc_init, vpx_codec_encode, vpx_codec_get_cx_data, vpx_codec_destroy,
 *              vpx_codec_control with SVC-specific controls, vpx_codec_enc_config_default,
 *              vpx_img_alloc
 * Focus: SVC encoder control functions, layer configuration, spatial/temporal scalability
 *        Specifically targets VP9 SVC control APIs with potentially many undiscovered branches:
 *        - VP9E_SET_SVC: Enable/disable SVC mode
 *        - VP9E_SET_SVC_PARAMETERS: Configure SVC parameters
 *        - VP9E_SET_SVC_LAYER_ID: Set layer IDs for spatial/temporal layers
 *        - VP9E_SET_SVC_REF_FRAME_CONFIG: Configure reference frame structure
 *        - VP9E_SET_TEMPORAL_LAYERING_MODE: Set temporal layering
 *        - Other advanced SVC controls
 * Note: This harness is semantically unique from harness_005 by focusing exclusively on
 *       SVC-specific controls which are complex and have many configuration options.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <algorithm>
#include <vector>
#include <memory>
#include <string>

#include <fuzzer/FuzzedDataProvider.h>
#include "vpx/vpx_encoder.h"
#include "vpx/vp8cx.h"
#include "vpx/vpx_image.h"

// SVC configuration constants
#define MAX_SPATIAL_LAYERS 5
#define MAX_TEMPORAL_LAYERS 5

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Minimum size check: SVC configuration requires significant data
    const size_t MIN_SIZE = 256;
    if (size < MIN_SIZE) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Consume configuration parameters from fuzzer input
    
    // Image dimensions (limited to reasonable sizes for fuzzing)
    unsigned int width = fdp.ConsumeIntegralInRange<unsigned int>(64, 512);
    unsigned int height = fdp.ConsumeIntegralInRange<unsigned int>(64, 512);
    
    // Choose encoder type - SVC is VP9 only
    vpx_codec_iface_t* encoder_iface = vpx_codec_vp9_cx();
    if (!encoder_iface) {
        return 0;
    }
    
    // Get default encoder configuration
    vpx_codec_enc_cfg_t cfg;
    if (vpx_codec_enc_config_default(encoder_iface, &cfg, 0) != VPX_CODEC_OK) {
        return 0;
    }
    
    // Override configuration with fuzzed data
    cfg.g_w = width;
    cfg.g_h = height;
    cfg.g_timebase.num = 1;
    cfg.g_timebase.den = fdp.ConsumeIntegralInRange<unsigned int>(24, 60);
    cfg.rc_target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(500, 5000);
    
    // Initialize encoder context
    vpx_codec_ctx_t codec;
    vpx_codec_flags_t flags = 0;
    vpx_codec_err_t init_err = vpx_codec_enc_init(&codec, encoder_iface, &cfg, flags);
    
    if (init_err != VPX_CODEC_OK) {
        // Try initialization without advanced features if initial fails
        flags = 0;
        if (vpx_codec_enc_init(&codec, encoder_iface, &cfg, flags) != VPX_CODEC_OK) {
            return 0;
        }
    }
    
    // Test SVC-specific encoder control functions
    // We'll test a subset of SVC controls based on available input data
    
    // 1. Enable SVC mode
    int enable_svc = fdp.ConsumeBool() ? 1 : 0;
    vpx_codec_err_t svc_err = vpx_codec_control_(&codec, VP9E_SET_SVC, enable_svc);
    (void)svc_err; // Ignore error - SVC may not be supported in all builds
    
    // Only proceed with SVC configuration if SVC was enabled
    if (enable_svc) {
        // 2. Configure SVC parameters if enough data remains
        if (fdp.remaining_bytes() > 500) { // Need enough data for full structure
            // Create proper SVC parameters structure
            vpx_svc_extra_cfg_t svc_params;
            // Initialize all fields with fuzzed data
            for (int i = 0; i < VPX_MAX_LAYERS && fdp.remaining_bytes() > 0; i++) {
                svc_params.max_quantizers[i] = fdp.ConsumeIntegralInRange<int>(0, 63);
            }
            for (int i = 0; i < VPX_MAX_LAYERS && fdp.remaining_bytes() > 0; i++) {
                svc_params.min_quantizers[i] = fdp.ConsumeIntegralInRange<int>(0, 63);
            }
            for (int i = 0; i < VPX_MAX_LAYERS && fdp.remaining_bytes() > 0; i++) {
                svc_params.scaling_factor_num[i] = fdp.ConsumeIntegral<int>();
            }
            for (int i = 0; i < VPX_MAX_LAYERS && fdp.remaining_bytes() > 0; i++) {
                svc_params.scaling_factor_den[i] = fdp.ConsumeIntegral<int>();
            }
            for (int i = 0; i < VPX_MAX_LAYERS && fdp.remaining_bytes() > 0; i++) {
                svc_params.speed_per_layer[i] = fdp.ConsumeIntegral<int>();
            }
            svc_params.temporal_layering_mode = fdp.ConsumeIntegral<int>();
            for (int i = 0; i < VPX_MAX_LAYERS && fdp.remaining_bytes() > 0; i++) {
                svc_params.loopfilter_ctrl[i] = fdp.ConsumeIntegral<int>();
            }
            
            // VP9E_SET_SVC_PARAMETERS expects vpx_svc_extra_cfg_t*
            vpx_codec_control_(&codec, VP9E_SET_SVC_PARAMETERS, &svc_params);
        }
        
        // 3. Set SVC layer ID
        if (fdp.remaining_bytes() > 100) {
            // Use proper vpx_svc_layer_id_t structure
            vpx_svc_layer_id_t layer_id;
            layer_id.spatial_layer_id = fdp.ConsumeIntegralInRange<int>(0, MAX_SPATIAL_LAYERS - 1);
            layer_id.temporal_layer_id = fdp.ConsumeIntegralInRange<int>(0, MAX_TEMPORAL_LAYERS - 1);
            // Initialize temporal_layer_id_per_spatial array
            for (int i = 0; i < VPX_SS_MAX_LAYERS && fdp.remaining_bytes() > 0; i++) {
                layer_id.temporal_layer_id_per_spatial[i] = fdp.ConsumeIntegralInRange<int>(0, MAX_TEMPORAL_LAYERS - 1);
            }
            
            vpx_codec_control_(&codec, VP9E_SET_SVC_LAYER_ID, &layer_id);
        }
        
        // 4. Test temporal layer ID (works for both VP8 and VP9)
        if (fdp.remaining_bytes() > 20) {
            int temporal_layer_id = fdp.ConsumeIntegralInRange<int>(0, MAX_TEMPORAL_LAYERS - 1);
            vpx_codec_control_(&codec, VP8E_SET_TEMPORAL_LAYER_ID, temporal_layer_id);
        }
        
        // 5. Test SVC reference frame configuration
        if (fdp.remaining_bytes() > 300) {
            // Use proper vpx_svc_ref_frame_config_t structure
            vpx_svc_ref_frame_config_t ref_config;
            // Initialize all array fields
            for (int i = 0; i < VPX_SS_MAX_LAYERS && fdp.remaining_bytes() > 0; i++) {
                ref_config.lst_fb_idx[i] = fdp.ConsumeIntegral<int>();
            }
            for (int i = 0; i < VPX_SS_MAX_LAYERS && fdp.remaining_bytes() > 0; i++) {
                ref_config.gld_fb_idx[i] = fdp.ConsumeIntegral<int>();
            }
            for (int i = 0; i < VPX_SS_MAX_LAYERS && fdp.remaining_bytes() > 0; i++) {
                ref_config.alt_fb_idx[i] = fdp.ConsumeIntegral<int>();
            }
            for (int i = 0; i < VPX_SS_MAX_LAYERS && fdp.remaining_bytes() > 0; i++) {
                ref_config.update_buffer_slot[i] = fdp.ConsumeIntegral<int>();
            }
            for (int i = 0; i < VPX_SS_MAX_LAYERS && fdp.remaining_bytes() > 0; i++) {
                ref_config.update_last[i] = fdp.ConsumeIntegral<int>();
            }
            for (int i = 0; i < VPX_SS_MAX_LAYERS && fdp.remaining_bytes() > 0; i++) {
                ref_config.update_golden[i] = fdp.ConsumeIntegral<int>();
            }
            for (int i = 0; i < VPX_SS_MAX_LAYERS && fdp.remaining_bytes() > 0; i++) {
                ref_config.update_alt_ref[i] = fdp.ConsumeIntegral<int>();
            }
            for (int i = 0; i < VPX_SS_MAX_LAYERS && fdp.remaining_bytes() > 0; i++) {
                ref_config.reference_last[i] = fdp.ConsumeIntegral<int>();
            }
            for (int i = 0; i < VPX_SS_MAX_LAYERS && fdp.remaining_bytes() > 0; i++) {
                ref_config.reference_golden[i] = fdp.ConsumeIntegral<int>();
            }
            for (int i = 0; i < VPX_SS_MAX_LAYERS && fdp.remaining_bytes() > 0; i++) {
                ref_config.reference_alt_ref[i] = fdp.ConsumeIntegral<int>();
            }
            for (int i = 0; i < VPX_SS_MAX_LAYERS && fdp.remaining_bytes() > 0; i++) {
                ref_config.duration[i] = fdp.ConsumeIntegral<int64_t>();
            }
            
            vpx_codec_control_(&codec, VP9E_SET_SVC_REF_FRAME_CONFIG, &ref_config);
        }
        
        // 6. Test SVC inter-layer prediction
        if (fdp.remaining_bytes() > 10) {
            unsigned int inter_layer_pred = fdp.ConsumeBool() ? 1 : 0;
            vpx_codec_control_(&codec, VP9E_SET_SVC_INTER_LAYER_PRED, inter_layer_pred);
        }
        
        // 7. Test other SVC-related controls if data remains
        if (fdp.remaining_bytes() > 100) {
            // Test frame dropping configuration - use proper vpx_svc_frame_drop_t
            vpx_svc_frame_drop_t drop_config;
            for (int i = 0; i < VPX_SS_MAX_LAYERS && fdp.remaining_bytes() > 0; i++) {
                drop_config.framedrop_thresh[i] = fdp.ConsumeIntegral<int>();
            }
            drop_config.framedrop_mode = static_cast<SVC_LAYER_DROP_MODE>(
                fdp.ConsumeIntegralInRange<int>(0, 3));
            drop_config.max_consec_drop = fdp.ConsumeIntegral<int>();
            
            vpx_codec_control_(&codec, VP9E_SET_SVC_FRAME_DROP_LAYER, &drop_config);
        }
    }
    
    // Also test some non-SVC advanced encoder controls that might not be covered
    // in harness_005 to maximize coverage of the 26 undiscovered branches
    
    // Test tile configuration controls
    if (fdp.remaining_bytes() > 20) {
        int tile_columns = fdp.ConsumeIntegralInRange<int>(0, 6);
        vpx_codec_control_(&codec, VP9E_SET_TILE_COLUMNS, tile_columns);
        
        int tile_rows = fdp.ConsumeIntegralInRange<int>(0, 6);
        vpx_codec_control_(&codec, VP9E_SET_TILE_ROWS, tile_rows);
    }
    
    // Test adaptive quantization mode
    if (fdp.remaining_bytes() > 10) {
        unsigned int aq_mode = fdp.ConsumeIntegralInRange<unsigned int>(0, 4);
        vpx_codec_control_(&codec, VP9E_SET_AQ_MODE, aq_mode);
    }
    
    // Test row-based multi-threading
    if (fdp.remaining_bytes() > 5) {
        unsigned int row_mt = fdp.ConsumeBool() ? 1 : 0;
        vpx_codec_control_(&codec, VP9E_SET_ROW_MT, row_mt);
    }
    
    // Test frame parallel decoding
    if (fdp.remaining_bytes() > 5) {
        unsigned int frame_parallel = fdp.ConsumeBool() ? 1 : 0;
        vpx_codec_control_(&codec, VP9E_SET_FRAME_PARALLEL_DECODING, frame_parallel);
    }
    
    // Test target level control
    if (fdp.remaining_bytes() > 10) {
        unsigned int target_level = fdp.ConsumeIntegralInRange<unsigned int>(0, 31);
        vpx_codec_control_(&codec, VP9E_SET_TARGET_LEVEL, target_level);
    }
    
    // Test TPL (temporal dependency model) control
    if (fdp.remaining_bytes() > 5) {
        int tpl_enabled = fdp.ConsumeBool() ? 1 : 0;
        vpx_codec_control_(&codec, VP9E_SET_TPL, tpl_enabled);
    }
    
    // Test post-encode drop control
    if (fdp.remaining_bytes() > 5) {
        unsigned int postencode_drop = fdp.ConsumeBool() ? 1 : 0;
        vpx_codec_control_(&codec, VP9E_SET_POSTENCODE_DROP, postencode_drop);
    }
    
    // Test delta Q UV control
    if (fdp.remaining_bytes() > 5) {
        int delta_q_uv = fdp.ConsumeIntegralInRange<int>(-63, 63);
        vpx_codec_control_(&codec, VP9E_SET_DELTA_Q_UV, delta_q_uv);
    }
    
    // Now try to encode a simple frame to exercise the configured encoder
    if (fdp.remaining_bytes() > 100) {
        // Allocate image buffer
        vpx_image_t *img = vpx_img_alloc(nullptr, VPX_IMG_FMT_I420, width, height, 16);
        if (img) {
            // Fill image planes with fuzzed data (simplified)
            size_t y_plane_size = width * height;
            size_t uv_plane_size = y_plane_size / 4;
            
            if (fdp.remaining_bytes() >= y_plane_size + uv_plane_size * 2) {
                // Fill Y plane
                std::vector<uint8_t> y_data = fdp.ConsumeBytes<uint8_t>(y_plane_size);
                if (y_data.size() == y_plane_size) {
                    memcpy(img->planes[VPX_PLANE_Y], y_data.data(), y_plane_size);
                }
                
                // Fill U plane
                std::vector<uint8_t> u_data = fdp.ConsumeBytes<uint8_t>(uv_plane_size);
                if (u_data.size() == uv_plane_size) {
                    memcpy(img->planes[VPX_PLANE_U], u_data.data(), uv_plane_size);
                }
                
                // Fill V plane
                std::vector<uint8_t> v_data = fdp.ConsumeBytes<uint8_t>(uv_plane_size);
                if (v_data.size() == uv_plane_size) {
                    memcpy(img->planes[VPX_PLANE_V], v_data.data(), uv_plane_size);
                }
                
                // Encode the image
                vpx_codec_encode(&codec, img, 0, 1, 0, VPX_DL_REALTIME);
                
                // Get compressed data
                const vpx_codec_cx_pkt_t *pkt;
                vpx_codec_iter_t iter = nullptr;
                while ((pkt = vpx_codec_get_cx_data(&codec, &iter)) != nullptr) {
                    // Just iterate through packets to exercise the API
                    (void)pkt;
                }
            }
            
            vpx_img_free(img);
        }
    }
    
    // Clean up
    vpx_codec_destroy(&codec);
    
    return 0;
}
