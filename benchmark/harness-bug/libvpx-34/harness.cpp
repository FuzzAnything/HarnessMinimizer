/*
 * Fuzzing harness for libvpx targeting VP9 encoder deep optimization logic
 * Focus: Deep encoder functions vp9_pick_inter_mode (428 blocked branches), 
 *        vp9_rd_pick_inter_mode_sb (311 blocked branches), rd_pick_partition (264 blocked branches)
 * 
 * Goal: Generate harness_022.cpp based on coverage guidance targeting deep encoder optimization logic
 *       through specific vpx_codec_control_ configurations to exercise advanced mode selection and
 *       rate-distortion optimization paths.
 * 
 * APIs to target as specified in guidance:
 * - vpx_codec_enc_config_default (config initialization)
 * - vpx_img_alloc (image allocation)
 * - vpx_codec_enc_init_ver (encoder initialization)
 * - vpx_codec_control_ (encoder optimization controls - primary target)
 * - vpx_codec_encode (frame encoding to trigger optimization paths)
 * - vpx_codec_destroy (cleanup)
 * - vpx_img_free (image cleanup)
 * 
 * Specific blocked branches targeted:
 * - vp9_pick_inter_mode: 428 blocked branches (out of 764) - core inter-frame mode selection
 * - vp9_rd_pick_inter_mode_sb: 311 blocked branches (out of 462) - RD optimization for superblocks
 * - rd_pick_partition: 264 blocked branches (out of 342) - partition decision logic
 * 
 * Optimization control strategy (different from previous harnesses):
 * 1. VP9E_SET_ALT_REF_AQ - Enable alternate reference frame adaptive quantization
 * 2. VP9E_SET_ROW_MT - Enable row-based multi-threading
 * 3. VP9E_SET_TUNE_CONTENT - Set content type tuning (default/screen)
 * 4. VP9E_SET_TILE_COLUMNS - Enable tile-based parallel encoding
 * 5. VP8E_SET_CPUUSED - Set speed/quality tradeoff (lower values trigger more RDO)
 * 6. VP9E_SET_AQ_MODE - Adaptive quantization mode
 * 7. VP9E_SET_LOSSLESS - Enable/disable lossless encoding
 * 
 * Advanced scenarios to trigger deep optimization paths:
 * 1. Multi-pass encoding (VPX_RC_FIRST_PASS, VPX_RC_LAST_PASS)
 * 2. SVC encoding with multiple temporal layers
 * 3. Lossless encoding mode
 * 4. Screen content encoding (VP9E_CONTENT_SCREEN)
 * 5. Low CPU_USED values (0-3) for exhaustive RDO search
 * 6. High CPU_USED values (7-9) for fast encoding
 * 
 * Semantic differentiation from harness_021:
 * 1. Specifically focuses on deep encoder optimization logic rather than configuration validation
 * 2. Targets low CPU_USED values (0-3) to force exhaustive rate-distortion optimization
 * 3. Tests ALT_REF_AQ specifically for alternate reference frame optimization
 * 4. Tests ROW_MT for row-based multi-threading optimization paths
 * 5. Tests content-specific tuning (default vs screen) to trigger different mode selection
 * 6. Focuses on the exact coverage gap: deep mode selection and RD optimization logic
 * 
 * Invocation sequence from guidance:
 * 1. Initialize image buffers using vpx_img_alloc
 * 2. Get default configuration using vpx_codec_enc_config_default
 * 3. Modify configuration for optimization testing
 * 4. Initialize encoder with vpx_codec_enc_init_ver
 * 5. Apply optimization controls using vpx_codec_control_
 * 6. Encode frames using vpx_codec_encode to trigger optimization paths
 * 7. Test diverse scenarios: multi-pass, SVC, lossless, screen content
 * 8. Cleanup using vpx_codec_destroy and vpx_img_free
 * 
 * Key optimization parameters to fuzz:
 * - CPU_USED: 0-9 (0 = slowest/best quality, 9 = fastest)
 * - AQ_MODE: 0-3 (different adaptive quantization strategies)
 * - TUNE_CONTENT: VP9E_CONTENT_DEFAULT, VP9E_CONTENT_SCREEN
 * - LOSSLESS: 0 or 1 (enable lossless encoding)
 * - ALT_REF_AQ: 0 or 1 (enable alternate reference AQ)
 * - ROW_MT: 0 or 1 (row-based multi-threading)
 * - TILE_COLUMNS: 0-6 (tile-based parallelism)
 * 
 * Reasoning from guidance: The existing harnesses have tested basic configurations but 
 * haven't deeply exercised the encoder's optimization logic. By using specific control
 * parameters that affect mode selection and rate-distortion decisions, we can reach
 * the blocked branches in vp9_pick_inter_mode and related optimization functions.
 * This represents the largest remaining coverage gap in VP9 encoder optimization logic.
 *
 * BUG FIX APPLIED: Corrected stack-buffer-overflow in SVC parameter handling.
 * Original bug: Incorrectly passed unsigned int[VPX_MAX_LAYERS] instead of vpx_svc_extra_cfg_t* 
 * to VP9E_SET_SVC_PARAMETERS control API. Fixed by using proper vpx_svc_extra_cfg_t structure
 * with memset initialization and proper field population from fuzzer input.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
#include <memory>
#include <vector>
#include <cstring>

#include <fuzzer/FuzzedDataProvider.h>

#include "vpx/vp8cx.h"
#include "vpx/vpx_encoder.h"
#include "vpx/vpx_codec.h"
#include "vpx/vpx_image.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum input size: need enough for optimization parameters and image data
    const size_t MIN_SIZE = sizeof(uint8_t) * 1024 + sizeof(int) * 64 + sizeof(unsigned int) * 32;
    if (size < MIN_SIZE) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Initialize encoder interface for VP9
    vpx_codec_iface_t* iface = vpx_codec_vp9_cx();
    if (!iface) {
        return 0;
    }
    
    // Step 1: Create a test image for encoding
    const int width = 64;  // Fixed small size for fuzzing efficiency
    const int height = 64;
    const vpx_img_fmt_t img_fmt = VPX_IMG_FMT_I420;
    
    vpx_image_t* img = vpx_img_alloc(NULL, img_fmt, width, height, 1);
    if (!img) {
        return 0;
    }
    
    // Fill image planes with fuzzed data
    size_t img_size = width * height;  // Y plane
    img_size += (width / 2) * (height / 2) * 2;  // U and V planes
    
    if (fdp.remaining_bytes() < img_size) {
        vpx_img_free(img);
        return 0;
    }
    
    std::vector<uint8_t> img_data = fdp.ConsumeBytes<uint8_t>(img_size);
    if (img_data.size() < img_size) {
        vpx_img_free(img);
        return 0;
    }
    
    // Copy data to image planes
    memcpy(img->planes[0], img_data.data(), width * height);
    memcpy(img->planes[1], img_data.data() + width * height, (width / 2) * (height / 2));
    memcpy(img->planes[2], img_data.data() + width * height * 5 / 4, (width / 2) * (height / 2));
    
    // Step 2: Get default encoder configuration
    vpx_codec_enc_cfg_t cfg;
    if (vpx_codec_enc_config_default(iface, &cfg, 0) != VPX_CODEC_OK) {
        vpx_img_free(img);
        return 0;
    }
    
    // Step 3: Configure encoder for optimization testing
    cfg.g_w = width;
    cfg.g_h = height;
    cfg.g_timebase.num = 1;
    cfg.g_timebase.den = 30;
    cfg.rc_target_bitrate = 1000;  // Reasonable bitrate for testing
    
    // Select encoding pass mode to trigger different optimization paths
    int pass_mode = fdp.ConsumeIntegralInRange<int>(0, 2);
    switch (pass_mode) {
        case 0:
            cfg.g_pass = VPX_RC_ONE_PASS;
            break;
        case 1:
            cfg.g_pass = VPX_RC_FIRST_PASS;
            break;
        case 2:
            cfg.g_pass = VPX_RC_LAST_PASS;
            break;
    }
    
    // Select rate control mode
    int rc_mode = fdp.ConsumeIntegralInRange<int>(0, 3);
    switch (rc_mode) {
        case 0:
            cfg.rc_end_usage = VPX_VBR;
            break;
        case 1:
            cfg.rc_end_usage = VPX_CBR;
            break;
        case 2:
            cfg.rc_end_usage = VPX_CQ;
            break;
        case 3:
            cfg.rc_end_usage = VPX_Q;
            break;
    }
    
    // Step 4: Initialize encoder
    vpx_codec_ctx_t codec;
    vpx_codec_flags_t flags = 0;
    
    if (vpx_codec_enc_init_ver(&codec, iface, &cfg, flags, VPX_ENCODER_ABI_VERSION) != VPX_CODEC_OK) {
        vpx_img_free(img);
        return 0;
    }
    
    // Step 5: Apply optimization controls (PRIMARY TARGET)
    // This is critical for reaching the blocked optimization branches
    
    // Control 1: CPU_USED - speed/quality tradeoff (critical for RDO paths)
    // Lower values (0-3) trigger exhaustive rate-distortion optimization
    // Higher values (7-9) use fast heuristics
    int cpu_used = fdp.ConsumeIntegralInRange<int>(0, 9);
    vpx_codec_control(&codec, VP8E_SET_CPUUSED, cpu_used);
    
    // Control 2: ALT_REF_AQ - alternate reference frame adaptive quantization
    int alt_ref_aq = fdp.ConsumeBool() ? 1 : 0;
    vpx_codec_control(&codec, VP9E_SET_ALT_REF_AQ, alt_ref_aq);
    
    // Control 3: ROW_MT - row-based multi-threading
    int row_mt = fdp.ConsumeBool() ? 1 : 0;
    vpx_codec_control(&codec, VP9E_SET_ROW_MT, row_mt);
    
    // Control 4: TUNE_CONTENT - content type tuning
    int tune_content = fdp.ConsumeBool() ? VP9E_CONTENT_SCREEN : VP9E_CONTENT_DEFAULT;
    vpx_codec_control(&codec, VP9E_SET_TUNE_CONTENT, tune_content);
    
    // Control 5: TILE_COLUMNS - tile-based parallelism
    unsigned int tile_columns = fdp.ConsumeIntegralInRange<unsigned int>(0, 3);
    vpx_codec_control(&codec, VP9E_SET_TILE_COLUMNS, tile_columns);
    
    // Control 6: AQ_MODE - adaptive quantization mode
    unsigned int aq_mode = fdp.ConsumeIntegralInRange<unsigned int>(0, 3);
    vpx_codec_control(&codec, VP9E_SET_AQ_MODE, aq_mode);
    
    // Control 7: LOSSLESS - lossless encoding mode
    unsigned int lossless = fdp.ConsumeBool() ? 1 : 0;
    vpx_codec_control(&codec, VP9E_SET_LOSSLESS, lossless);
    
    // Control 8: Set quantizer values to affect mode selection
    if (fdp.ConsumeBool()) {
        int min_q = fdp.ConsumeIntegralInRange<int>(0, 63);
        int max_q = fdp.ConsumeIntegralInRange<int>(min_q, 63);
        vpx_codec_control(&codec, VP8E_SET_CQ_LEVEL, min_q);
        cfg.rc_min_quantizer = min_q;
        cfg.rc_max_quantizer = max_q;
    }
    
    // Control 9: Set golden frame boost for CBR mode
    if (cfg.rc_end_usage == VPX_CBR && fdp.ConsumeBool()) {
        unsigned int gf_boost = fdp.ConsumeIntegralInRange<unsigned int>(0, 100);
        vpx_codec_control(&codec, VP8E_SET_GF_CBR_BOOST_PCT, gf_boost);
    }
    
    // Step 6: Test SVC encoding for complex optimization scenarios
    if (fdp.ConsumeBool() && fdp.remaining_bytes() > 100) {
        // Enable SVC
        vpx_codec_control(&codec, VP9E_SET_SVC, 1);
        
        // Set SVC parameters - CORRECTED: Use vpx_svc_extra_cfg_t structure
        vpx_svc_extra_cfg_t svc_cfg;
        memset(&svc_cfg, 0, sizeof(svc_cfg));
        
        int svc_layers = fdp.ConsumeIntegralInRange<int>(1, 3);
        
        // Fill SVC configuration with fuzzed data
        for (int i = 0; i < svc_layers && i < VPX_MAX_LAYERS; i++) {
            // Set min/max quantizers (0-63 valid range)
            svc_cfg.min_quantizers[i] = fdp.ConsumeIntegralInRange<int>(0, 63);
            svc_cfg.max_quantizers[i] = fdp.ConsumeIntegralInRange<int>(svc_cfg.min_quantizers[i], 63);
            
            // Set scaling factors (avoid division by zero)
            svc_cfg.scaling_factor_num[i] = fdp.ConsumeIntegralInRange<int>(1, 100);
            svc_cfg.scaling_factor_den[i] = fdp.ConsumeIntegralInRange<int>(1, 100);
            
            // Set speed per layer (CPU_USED range 0-9)
            svc_cfg.speed_per_layer[i] = fdp.ConsumeIntegralInRange<int>(0, 9);
            
            // Set loopfilter control (0 or 1)
            svc_cfg.loopfilter_ctrl[i] = fdp.ConsumeBool() ? 1 : 0;
        }
        
        // Set temporal layering mode
        svc_cfg.temporal_layering_mode = fdp.ConsumeIntegralInRange<int>(0, 2);
        
        vpx_codec_control(&codec, VP9E_SET_SVC_PARAMETERS, &svc_cfg);
        
        // Set layer ID
        vpx_svc_layer_id_t layer_id;
        layer_id.spatial_layer_id = fdp.ConsumeIntegralInRange<int>(0, svc_layers - 1);
        layer_id.temporal_layer_id = fdp.ConsumeIntegralInRange<int>(0, 2);
        vpx_codec_control(&codec, VP9E_SET_SVC_LAYER_ID, &layer_id);
    }
    
    // Step 7: Encode frames to trigger optimization logic
    // The actual optimization happens during encoding
    
    // First frame (keyframe)
    vpx_codec_encode(&codec, img, 0, 1, 0, VPX_DL_REALTIME);
    
    // Encode additional frames if we have more data
    // This triggers inter-frame mode selection and optimization
    if (fdp.remaining_bytes() > img_size / 2) {
        std::vector<uint8_t> img_data2 = fdp.ConsumeBytes<uint8_t>(img_size / 2);
        if (img_data2.size() >= img_size / 2) {
            // Modify image data slightly for second frame
            memcpy(img->planes[0], img_data2.data(), std::min((size_t)(width * height), img_data2.size()));
            
            // Encode with different flags to test various optimization paths
            vpx_enc_frame_flags_t frame_flags = 0;
            if (fdp.ConsumeBool()) {
                frame_flags |= VP8_EFLAG_NO_REF_LAST;
            }
            if (fdp.ConsumeBool()) {
                frame_flags |= VP8_EFLAG_NO_REF_GF;
            }
            if (fdp.ConsumeBool()) {
                frame_flags |= VP8_EFLAG_NO_REF_ARF;
            }
            
            // This call triggers vp9_pick_inter_mode and related optimization functions
            vpx_codec_encode(&codec, img, 1, 1, frame_flags, VPX_DL_REALTIME);
        }
    }
    
    // Step 8: Cleanup
    vpx_codec_destroy(&codec);
    vpx_img_free(img);
    
    return 0;
}
