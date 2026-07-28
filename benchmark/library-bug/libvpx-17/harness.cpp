/*
 * Fuzzing harness for libvpx VP9 Scalable Video Coding (SVC) functionality targeting
 * the 500+ blocked branches in vp9_pick_inter_mode and other SVC functions at 0% coverage.
 * 
 * Target: SVC-specific code paths using vpx_codec_control_ with SVC parameters:
 * - VP9E_SET_SVC_PARAMETERS: Configure SVC layer parameters
 * - VP9E_SET_SVC_LAYER_ID: Set spatial and temporal layer IDs  
 * - VP9E_SET_TEMPORAL_LAYER_ID: Set temporal layer ID
 * - VP9E_SET_NOISE_SENSITIVITY: Configure temporal denoising for SVC
 * 
 * Coverage Analysis (from coverage guidance):
 * - vp9_pick_inter_mode: 548 blocked branches (74% blocked) with SVC paths at 0 hits
 * - scale_partitioning_svc: 0% coverage
 * - vp9_one_pass_svc_start_layer: 0% coverage  
 * - temporal_filter_iterate_tile_c: 0% coverage
 * 
 * Key SVC Configuration Approach:
 * 1. Use vpx_codec_enc_init for single encoder context (multi-encoder is VP8 specific)
 * 2. Configure vpx_svc_parameters structure for SVC layer settings
 * 3. Use vpx_codec_control_ with SVC-specific control codes
 * 4. Create image buffers for multiple spatial layers
 * 5. Exercise temporal layering with varying layer IDs
 * 
 * Semantic Diversity vs Existing Harnesses:
 * - harness_032: Uses SvcContext structure and vpx_svc_* API functions
 * - harness_034-041: Focus on SVC configurations and validation
 * - This harness (045): Directly uses vpx_codec_control_ with SVC control codes and
 *   vpx_svc_parameters structure, targeting the specific blocked branches in
 *   vp9_pick_inter_mode's SVC code paths
 * 
 * Differentiation Strategy:
 * 1. Direct use of vpx_codec_control_ with VP9E_SET_SVC_* controls
 * 2. Configuration through vpx_svc_parameters structure
 * 3. Exercise frame encoding with varying spatial/temporal layer IDs
 * 4. Test noise sensitivity for temporal denoising in SVC
 * 5. Focus on code paths in vp9_pick_inter_mode related to SVC condition checks
 * 
 * Strategy: Configure VP9 encoder with SVC settings using vpx_codec_control_
 * and vpx_svc_parameters to exercise the blocked SVC branches in mode selection logic.
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

// Helper to generate simple frame data
static void generate_frame_data(uint8_t* buffer, int width, int height, 
                               int stride, int frame_index, int layer_id) {
    for (int y = 0; y < height; y++) {
        uint8_t* row = buffer + y * stride;
        for (int x = 0; x < width; x++) {
            // Generate pattern based on frame and layer
            int pattern = (x ^ y ^ frame_index ^ layer_id) & 0xFF;
            row[x] = pattern;
        }
    }
}

// Initialize vpx_svc_extra_cfg_t structure with fuzzed data
static void init_svc_parameters(vpx_svc_extra_cfg_t* svc_params, 
                               FuzzedDataProvider& fdp, 
                               int num_spatial_layers, int num_temporal_layers) {
    for (int i = 0; i < VPX_MAX_LAYERS; i++) {
        if (i < num_spatial_layers) {
            svc_params->max_quantizers[i] = fdp.ConsumeIntegralInRange<int>(20, 63);
            svc_params->min_quantizers[i] = fdp.ConsumeIntegralInRange<int>(0, svc_params->max_quantizers[i]);
            svc_params->scaling_factor_num[i] = fdp.ConsumeIntegralInRange<int>(1, 16);
            svc_params->scaling_factor_den[i] = fdp.ConsumeIntegralInRange<int>(4, 16);
            svc_params->speed_per_layer[i] = fdp.ConsumeIntegralInRange<int>(0, 9);
            svc_params->loopfilter_ctrl[i] = fdp.ConsumeIntegralInRange<int>(0, 1);
        } else {
            svc_params->max_quantizers[i] = 63;
            svc_params->min_quantizers[i] = 0;
            svc_params->scaling_factor_num[i] = 1;
            svc_params->scaling_factor_den[i] = 1;
            svc_params->speed_per_layer[i] = 0;
            svc_params->loopfilter_ctrl[i] = 0;
        }
    }
    svc_params->temporal_layering_mode = fdp.ConsumeIntegralInRange<int>(0, 3);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum input size check
    if (size < 100) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Consume configuration parameters from fuzzer input
    int num_spatial_layers = fdp.ConsumeIntegralInRange<int>(1, 5);
    int num_temporal_layers = fdp.ConsumeIntegralInRange<int>(1, 5);
    int width = fdp.ConsumeIntegralInRange<int>(64, 1024);
    int height = fdp.ConsumeIntegralInRange<int>(64, 1024);
    int num_frames = fdp.ConsumeIntegralInRange<int>(1, 10);
    bool enable_noise_sensitivity = fdp.ConsumeBool();
    
    // Initialize encoder context
    vpx_codec_ctx_t codec;
    vpx_codec_enc_cfg_t cfg;
    vpx_codec_iface_t* iface = vpx_codec_vp9_cx();
    
    if (vpx_codec_enc_config_default(iface, &cfg, 0) != VPX_CODEC_OK) {
        return 0;
    }
    
    // Configure basic encoder settings
    cfg.g_w = width;
    cfg.g_h = height;
    cfg.g_timebase.num = 1;
    cfg.g_timebase.den = 30;
    cfg.rc_target_bitrate = fdp.ConsumeIntegralInRange<int>(100, 10000);
    cfg.g_pass = VPX_RC_ONE_PASS;
    
    // Configure SVC settings in encoder config
    cfg.ss_number_layers = num_spatial_layers;
    cfg.ts_number_layers = num_temporal_layers;
    
    // Set layer bitrate allocation (simple equal allocation for fuzzing)
    for (int i = 0; i < num_spatial_layers; i++) {
        cfg.layer_target_bitrate[i] = cfg.rc_target_bitrate / num_spatial_layers;
    }
    
    // Initialize encoder
    if (vpx_codec_enc_init_ver(&codec, iface, &cfg, 0, VPX_ENCODER_ABI_VERSION) != VPX_CODEC_OK) {
        return 0;
    }
    
    // Configure SVC parameters using vpx_codec_control_
    vpx_svc_extra_cfg_t svc_params = {};
    init_svc_parameters(&svc_params, fdp, num_spatial_layers, num_temporal_layers);
    
    // Enable SVC
    int svc_enable = 1;
    if (vpx_codec_control(&codec, VP9E_SET_SVC, svc_enable) != VPX_CODEC_OK) {
        vpx_codec_destroy(&codec);
        return 0;
    }
    if (vpx_codec_control(&codec, VP9E_SET_SVC_PARAMETERS, &svc_params) != VPX_CODEC_OK) {
        vpx_codec_destroy(&codec);
        return 0;
    }
    
    // Set noise sensitivity for temporal denoising
    int noise_sensitivity = enable_noise_sensitivity ? 
                           fdp.ConsumeIntegralInRange<int>(0, 2) : 0;
    if (vpx_codec_control(&codec, VP9E_SET_NOISE_SENSITIVITY, noise_sensitivity) != VPX_CODEC_OK) {
        // Continue even if this fails (older versions might not support it)
    }
    
    // Allocate image buffers for different spatial layers
    std::vector<vpx_image_t*> layer_images;
    for (int spatial_layer = 0; spatial_layer < num_spatial_layers; spatial_layer++) {
        // Calculate dimensions for this spatial layer
        int layer_width = width;
        int layer_height = height;
        
        if (spatial_layer > 0) {
            // Apply scaling for higher layers using svc_params scaling factors
            layer_width = (width * svc_params.scaling_factor_num[spatial_layer]) / 
                         svc_params.scaling_factor_den[spatial_layer];
            layer_height = (height * svc_params.scaling_factor_num[spatial_layer]) / 
                          svc_params.scaling_factor_den[spatial_layer];
            // Ensure minimum dimensions
            if (layer_width < 16) layer_width = 16;
            if (layer_height < 16) layer_height = 16;
        }
        
        vpx_image_t* img = vpx_img_alloc(NULL, VPX_IMG_FMT_I420, 
                                         layer_width, layer_height, 1);
        if (!img) {
            // Cleanup already allocated images
            for (auto* img_ptr : layer_images) {
                vpx_img_free(img_ptr);
            }
            vpx_codec_destroy(&codec);
            return 0;
        }
        layer_images.push_back(img);
    }
    
    // Encode frames with varying layer configurations
    for (int frame_idx = 0; frame_idx < num_frames; frame_idx++) {
        // Generate frame data for each spatial layer
        for (size_t layer_idx = 0; layer_idx < layer_images.size(); layer_idx++) {
            vpx_image_t* img = layer_images[layer_idx];
            generate_frame_data(img->planes[VPX_PLANE_Y], img->d_w, img->d_h,
                               img->stride[VPX_PLANE_Y], frame_idx, layer_idx);
            
            // Generate U and V planes (simplified for fuzzing)
            int uv_width = (img->d_w + 1) / 2;
            int uv_height = (img->d_h + 1) / 2;
            generate_frame_data(img->planes[VPX_PLANE_U], uv_width, uv_height,
                               img->stride[VPX_PLANE_U], frame_idx, layer_idx);
            generate_frame_data(img->planes[VPX_PLANE_V], uv_width, uv_height,
                               img->stride[VPX_PLANE_V], frame_idx, layer_idx);
        }
        
        // Set layer ID for this frame
        vpx_svc_layer_id_t layer_id;
        layer_id.spatial_layer_id = fdp.ConsumeIntegralInRange<int>(0, num_spatial_layers - 1);
        layer_id.temporal_layer_id = fdp.ConsumeIntegralInRange<int>(0, num_temporal_layers - 1);
        
        if (vpx_codec_control(&codec, VP9E_SET_SVC_LAYER_ID, &layer_id) != VPX_CODEC_OK) {
            // Continue encoding even if layer ID setting fails
        }
        
        // Also set temporal layer ID separately using VP8 control (for VP9 this might not work, but we try)
        int temp_layer_id = layer_id.temporal_layer_id;
        if (vpx_codec_control(&codec, VP8E_SET_TEMPORAL_LAYER_ID, temp_layer_id) != VPX_CODEC_OK) {
            // Continue encoding - this control might not be supported for VP9
        }
        
        // Encode the frame using the first spatial layer's image
        // In real SVC, you would encode all layers, but for fuzzing we use one
        vpx_codec_encode(&codec, layer_images[0], frame_idx, 1, 0, VPX_DL_REALTIME);
        // Retrieve encoded data
        const vpx_codec_cx_pkt_t* pkt;
        vpx_codec_iter_t iter = NULL;
        while ((pkt = vpx_codec_get_cx_data(&codec, &iter)) != NULL) {
            if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
                // Packet received - exercise the code path
                // In real fuzzing, we might want to save or process this data
            }
        }
    }
    
    // Flush the encoder
    vpx_codec_encode(&codec, NULL, -1, 1, 0, VPX_DL_REALTIME);
    
    // Retrieve any remaining packets
    const vpx_codec_cx_pkt_t* pkt;
    vpx_codec_iter_t iter = NULL;
    while ((pkt = vpx_codec_get_cx_data(&codec, &iter)) != NULL) {
        if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
            // Exercise the code path
        }
    }
    
    // Cleanup
    for (auto* img : layer_images) {
        vpx_img_free(img);
    }
    vpx_codec_destroy(&codec);
    
    return 0;
}
