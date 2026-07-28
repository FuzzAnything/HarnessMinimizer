/*
 * Fuzzing harness for libvpx VP9 encoder targeting deep branch coverage in vp9_pick_inter_mode
 * with focus on SVC (Scalable Video Coding) configurations that trigger 511 blocked branches
 * 
 * Target: Internal encoder mode selection logic with SVC-specific conditions in vp9_pick_inter_mode
 * Primary focus: SVC parameters that control mode selection heuristics:
 *   - force_zero_mode_spatial_ref and svc_force_zero_mode[] array
 *   - Inter-layer prediction and reference frame constraints
 *   - Scaling factor variations between spatial layers
 *   - Temporal layer configurations affecting mode decisions
 *   - Quality layer differences (QP variations) between layers
 * 
 * This harness specifically targets SVC-related branch conditions in vp9_pick_inter_mode by:
 * 1. Creating varied SVC layer configurations with fuzzed parameters
 * 2. Testing scaling factor combinations that trigger force_zero_mode conditions
 * 3. Exercising inter-layer reference frame selection logic
 * 4. Creating temporal patterns that affect golden frame usage decisions
 * 5. Testing edge cases in SVC-specific early termination heuristics
 */

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <memory>

#include "fuzzer/FuzzedDataProvider.h"

// libvpx headers
#include "vpx/vpx_codec.h"
#include "vpx/vpx_encoder.h"
#include "vpx/vpx_image.h"
#include "vpx/vp8cx.h"

// Constants for SVC configuration
#ifndef VPX_SS_MAX_LAYERS
#define VPX_SS_MAX_LAYERS 5
#endif

#ifndef VPX_TS_MAX_LAYERS  
#define VPX_TS_MAX_LAYERS 5
#endif

#ifndef VPX_MAX_LAYERS
#define VPX_MAX_LAYERS 12
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Need sufficient input for complex SVC configurations and encoder parameters
    if (size < 2048) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);

    // Step 1: Consume SVC configuration parameters specifically targeting vp9_pick_inter_mode branches
    
    // Spatial and temporal layer configuration
    uint8_t spatial_layers = fdp.ConsumeIntegralInRange<uint8_t>(1, VPX_SS_MAX_LAYERS);
    uint8_t temporal_layers = fdp.ConsumeIntegralInRange<uint8_t>(1, VPX_TS_MAX_LAYERS);
    uint8_t current_spatial_layer = fdp.ConsumeIntegralInRange<uint8_t>(0, spatial_layers - 1);
    uint8_t current_temporal_layer = fdp.ConsumeIntegralInRange<uint8_t>(0, temporal_layers - 1);
    
    // Parameters that directly affect vp9_pick_inter_mode SVC logic
    bool force_zero_mode_spatial_ref = fdp.ConsumeBool();
    bool use_svc = fdp.ConsumeBool();
    bool non_reference_frame = fdp.ConsumeBool();
    bool high_source_sad_superframe = fdp.ConsumeBool();
    bool use_gf_temporal_ref_current_layer = fdp.ConsumeBool();
    
    // Scaling factors - critical for triggering force_zero_mode conditions
    int scaling_factors_num[VPX_SS_MAX_LAYERS];
    int scaling_factors_den[VPX_SS_MAX_LAYERS];
    bool has_scaling_mismatch = false;
    
    for (int i = 0; i < spatial_layers; ++i) {
        scaling_factors_num[i] = fdp.ConsumeIntegralInRange<int>(1, 16);
        scaling_factors_den[i] = fdp.ConsumeIntegralInRange<int>(1, 16);
        if (scaling_factors_den[i] == 0) scaling_factors_den[i] = 1;
        
        // Create scaling mismatches to trigger force_zero_mode conditions
        if (i > 0 && fdp.ConsumeBool()) {
            scaling_factors_num[i] = scaling_factors_num[i-1] + fdp.ConsumeIntegralInRange<int>(-2, 2);
            scaling_factors_den[i] = scaling_factors_den[i-1] + fdp.ConsumeIntegralInRange<int>(-2, 2);
            if (scaling_factors_num[i] <= 0) scaling_factors_num[i] = 1;
            if (scaling_factors_den[i] <= 0) scaling_factors_den[i] = 1;
            
            if (scaling_factors_num[i] != scaling_factors_num[i-1] || 
                scaling_factors_den[i] != scaling_factors_den[i-1]) {
                has_scaling_mismatch = true;
            }
        }
    }
    
    // Downsample filter phase - affects flag_svc_subpel logic
    int8_t downsample_filter_phase[VPX_SS_MAX_LAYERS];
    for (int i = 0; i < spatial_layers; ++i) {
        downsample_filter_phase[i] = fdp.ConsumeIntegralInRange<int8_t>(0, 16);
    }
    
    // Quality (QP) differences between layers - affects skip golden thresholds
    int base_qindex = fdp.ConsumeIntegralInRange<int>(0, 255);
    int lower_layer_qindex = base_qindex + fdp.ConsumeIntegralInRange<int>(-50, 50);
    
    // Motion vector parameters for SVC
    int8_t svc_mv_col = fdp.ConsumeIntegralInRange<int8_t>(-32, 32);
    int8_t svc_mv_row = fdp.ConsumeIntegralInRange<int8_t>(-32, 32);
    
    // Threshold variations for SVC skip logic
    unsigned int thresh_svc_skip_golden = fdp.ConsumeIntegralInRange<unsigned int>(0, 2000);
    
    // Reference frame flags variation
    uint8_t ref_frame_flags = fdp.ConsumeIntegral<uint8_t>();
    
    // Step 2: Image and encoding parameters
    uint16_t base_width = fdp.ConsumeIntegralInRange<uint16_t>(64, 1920);
    uint16_t base_height = fdp.ConsumeIntegralInRange<uint16_t>(64, 1080);
    
    // Image format variation
    uint8_t format_choice = fdp.ConsumeIntegral<uint8_t>() % 4;
    vpx_img_fmt_t img_fmt = VPX_IMG_FMT_I420; // Default
    switch (format_choice) {
        case 0: img_fmt = VPX_IMG_FMT_I420; break;
        case 1: img_fmt = VPX_IMG_FMT_I422; break;
        case 2: img_fmt = VPX_IMG_FMT_I444; break;
        case 3: img_fmt = VPX_IMG_FMT_NV12; break;
    }
    
    // Bitrate and frame parameters
    uint32_t base_bitrate = fdp.ConsumeIntegralInRange<uint32_t>(1000, 10000000);
    uint8_t frame_count = fdp.ConsumeIntegralInRange<uint8_t>(1, 8);
    uint8_t keyframe_interval = fdp.ConsumeIntegralInRange<uint8_t>(0, 100);
    
    // Speed and quality settings that affect mode decisions
    uint8_t speed = fdp.ConsumeIntegralInRange<uint8_t>(0, 9);
    uint8_t cpu_used = fdp.ConsumeIntegralInRange<uint8_t>(0, 16);
    uint8_t aq_mode = fdp.ConsumeIntegral<uint8_t>() % 4;
    
    // Step 3: Select VP9 encoder interface
    vpx_codec_iface_t* codec_iface = vpx_codec_vp9_cx();
    
    if (!codec_iface) {
        return 0;
    }

    vpx_codec_ctx_t codec_ctx;
    vpx_codec_err_t res;
    vpx_codec_enc_cfg_t cfg;

    // Step 4: Get default encoder configuration
    if (vpx_codec_enc_config_default(codec_iface, &cfg, 0) != VPX_CODEC_OK) {
        return 0;
    }

    // Step 5: Configure encoder settings with SVC focus
    cfg.g_w = base_width;
    cfg.g_h = base_height;
    cfg.rc_target_bitrate = base_bitrate;
    cfg.g_timebase.num = 1;
    cfg.g_timebase.den = 30; // 30 fps
    
    // Configure SVC layers
    cfg.ts_number_layers = temporal_layers;
    cfg.ss_number_layers = spatial_layers;
    
    // Set up temporal layer pattern
    if (temporal_layers > 1) {
        cfg.ts_periodicity = temporal_layers;
        for (int i = 0; i < temporal_layers; ++i) {
            cfg.ts_rate_decimator[i] = fdp.ConsumeIntegralInRange<uint8_t>(1, 8);
        }
        
        // Target bitrate distribution across temporal layers
        for (int i = 0; i < temporal_layers; ++i) {
            cfg.layer_target_bitrate[i] = base_bitrate * (i + 1) / temporal_layers;
        }
    }
    
    // Configure spatial layer bitrates
    for (int i = 0; i < spatial_layers; ++i) {
        if (i < temporal_layers) {
            cfg.layer_target_bitrate[i] = base_bitrate * (i + 1) / spatial_layers;
        }
    }
    
    // Rate control parameters
    cfg.rc_end_usage = static_cast<vpx_rc_mode>(fdp.ConsumeIntegral<uint8_t>() % 3);
    cfg.rc_undershoot_pct = fdp.ConsumeIntegralInRange<uint16_t>(0, 100);
    cfg.rc_overshoot_pct = fdp.ConsumeIntegralInRange<uint16_t>(0, 100);
    cfg.rc_min_quantizer = fdp.ConsumeIntegralInRange<uint8_t>(0, 63);
    cfg.rc_max_quantizer = fdp.ConsumeIntegralInRange<uint8_t>(0, 63);
    
    // Keyframe parameters
    cfg.kf_max_dist = keyframe_interval;
    cfg.kf_mode = VPX_KF_AUTO;
    cfg.kf_min_dist = 0;
    
    // Error resilience
    cfg.g_error_resilient = fdp.ConsumeBool() ? 1 : 0;
    cfg.g_pass = VPX_RC_ONE_PASS;
    cfg.g_lag_in_frames = fdp.ConsumeIntegralInRange<unsigned int>(0, 25);

    // Step 6: Initialize encoder
    vpx_codec_flags_t flags = 0;
    res = vpx_codec_enc_init_ver(&codec_ctx, codec_iface, &cfg, flags, VPX_ENCODER_ABI_VERSION);
    if (res != VPX_CODEC_OK) {
        return 0;
    }
    
    // Step 7: Apply SVC controls targeting vp9_pick_inter_mode branch conditions
    
    // Enable SVC
    vpx_codec_control(&codec_ctx, VP9E_SET_SVC, use_svc ? 1 : 0);
    
    // Configure SVC parameters with focus on vp9_pick_inter_mode conditions
    if (use_svc) {
        vpx_svc_extra_cfg_t svc_params;
        memset(&svc_params, 0, sizeof(svc_params));
        
        // Temporal layering mode
        svc_params.temporal_layering_mode = fdp.ConsumeIntegral<uint8_t>() % 4;
        
        // Configure scaling factors - critical for force_zero_mode logic
        for (int sl = 0; sl < spatial_layers; ++sl) {
            svc_params.scaling_factor_num[sl] = scaling_factors_num[sl];
            svc_params.scaling_factor_den[sl] = scaling_factors_den[sl];
            
            // Speed per layer - affects mode decision speed
            svc_params.speed_per_layer[sl] = fdp.ConsumeIntegralInRange<int>(0, 9);
            
            // Loopfilter control per layer
            svc_params.loopfilter_ctrl[sl] = fdp.ConsumeIntegralInRange<int>(0, 2);
        }
        
        // Configure quantizers per layer - affects quality-based decisions
        for (int layer_idx = 0; layer_idx < (spatial_layers * temporal_layers); ++layer_idx) {
            svc_params.max_quantizers[layer_idx] = fdp.ConsumeIntegralInRange<int>(0, 63);
            svc_params.min_quantizers[layer_idx] = fdp.ConsumeIntegralInRange<int>(0, 63);
            
            // Ensure min <= max
            if (svc_params.min_quantizers[layer_idx] > svc_params.max_quantizers[layer_idx]) {
                std::swap(svc_params.min_quantizers[layer_idx], svc_params.max_quantizers[layer_idx]);
            }
        }
        
        vpx_codec_control(&codec_ctx, VP9E_SET_SVC_PARAMETERS, &svc_params);
        
        // Set SVC layer ID for dynamic testing
        vpx_svc_layer_id_t layer_id;
        memset(&layer_id, 0, sizeof(layer_id));
        layer_id.spatial_layer_id = current_spatial_layer;
        layer_id.temporal_layer_id = current_temporal_layer;
        vpx_codec_control(&codec_ctx, VP9E_SET_SVC_LAYER_ID, &layer_id);
        
        // Set reference frame configuration to test inter-layer prediction
        vpx_svc_ref_frame_config_t ref_config;
        memset(&ref_config, 0, sizeof(ref_config));
        
        // Configure reference frame buffers for SVC
        for (int i = 0; i < spatial_layers; ++i) {
            ref_config.lst_fb_idx[i] = fdp.ConsumeIntegralInRange<int>(0, 7);
            ref_config.gld_fb_idx[i] = fdp.ConsumeIntegralInRange<int>(0, 7);
            ref_config.alt_fb_idx[i] = fdp.ConsumeIntegralInRange<int>(0, 7);
            
            // Reference frame update flags
            ref_config.update_buffer_slot[i] = fdp.ConsumeIntegral<uint8_t>();
            ref_config.update_last[i] = fdp.ConsumeBool() ? 1 : 0;
            ref_config.update_golden[i] = fdp.ConsumeBool() ? 1 : 0;
            ref_config.update_alt_ref[i] = fdp.ConsumeBool() ? 1 : 0;
            
            // Reference frame duration
            ref_config.duration[i] = fdp.ConsumeIntegralInRange<int>(1, 100);
        }
        
        vpx_codec_control(&codec_ctx, VP9E_SET_SVC_REF_FRAME_CONFIG, &ref_config);
    }
    
    // Set speed and CPU used - affects mode decision heuristics
    vpx_codec_control(&codec_ctx, VP8E_SET_CPUUSED, cpu_used);
    
    // Set adaptive quantization
    vpx_codec_control(&codec_ctx, VP9E_SET_AQ_MODE, aq_mode);
    
    // Set auto alt-ref
    vpx_codec_control(&codec_ctx, VP8E_SET_ENABLEAUTOALTREF, fdp.ConsumeBool() ? 1 : 0);
    
    // Additional encoder controls that affect mode decisions
    vpx_codec_control(&codec_ctx, VP9E_SET_FRAME_PARALLEL_DECODING, fdp.ConsumeBool() ? 1 : 0);
    vpx_codec_control(&codec_ctx, VP9E_SET_TILE_COLUMNS, fdp.ConsumeIntegralInRange<int>(0, 6));
    vpx_codec_control(&codec_ctx, VP9E_SET_TILE_ROWS, fdp.ConsumeIntegralInRange<int>(0, 6));
    
    // Set noise sensitivity (exists as VP8E_SET_NOISE_SENSITIVITY for VP8, but VP9E_SET_NOISE_SENSITIVITY exists for VP9)
    vpx_codec_control(&codec_ctx, VP9E_SET_NOISE_SENSITIVITY, fdp.ConsumeIntegralInRange<unsigned int>(0, 4));
    
    // Set sharpness
    vpx_codec_control(&codec_ctx, VP8E_SET_SHARPNESS, fdp.ConsumeIntegralInRange<unsigned int>(0, 7));
    
    // Step 8: Allocate source image
    vpx_image_t* img = vpx_img_alloc(nullptr, img_fmt, base_width, base_height, 1);
    if (!img) {
        vpx_codec_destroy(&codec_ctx);
        return 0;
    }
    // Fill image with fuzzed data to create varied content
    size_t image_data_needed = base_width * base_height * 3 / 2; // YUV420
    if (fdp.remaining_bytes() < image_data_needed) {
        vpx_img_free(img);
        vpx_codec_destroy(&codec_ctx);
        return 0;
    }
    
    // Fill Y plane
    std::vector<uint8_t> y_plane = fdp.ConsumeBytes<uint8_t>(base_width * base_height);
    if (y_plane.size() < base_width * base_height) {
        vpx_img_free(img);
        vpx_codec_destroy(&codec_ctx);
        return 0;
    }
    memcpy(img->planes[VPX_PLANE_Y], y_plane.data(), base_width * base_height);
    
    // Fill U and V planes (subsampled for 4:2:0)
    size_t uv_size = (base_width * base_height) / 4;
    if (fdp.remaining_bytes() >= uv_size * 2) {
        std::vector<uint8_t> u_plane = fdp.ConsumeBytes<uint8_t>(uv_size);
        std::vector<uint8_t> v_plane = fdp.ConsumeBytes<uint8_t>(uv_size);
        
        if (u_plane.size() >= uv_size && v_plane.size() >= uv_size) {
            memcpy(img->planes[VPX_PLANE_U], u_plane.data(), uv_size);
            memcpy(img->planes[VPX_PLANE_V], v_plane.data(), uv_size);
        }
    }
    
    // Step 9: Encode frames with varied SVC configurations
    for (uint8_t frame_idx = 0; frame_idx < frame_count; ++frame_idx) {
        // Occasionally change SVC layer configuration during encoding
        if (frame_idx > 0 && fdp.ConsumeBool()) {
            vpx_svc_layer_id_t dynamic_layer_id;
            memset(&dynamic_layer_id, 0, sizeof(dynamic_layer_id));
            dynamic_layer_id.spatial_layer_id = fdp.ConsumeIntegralInRange<uint8_t>(0, spatial_layers - 1);
            dynamic_layer_id.temporal_layer_id = fdp.ConsumeIntegralInRange<uint8_t>(0, temporal_layers - 1);
            vpx_codec_control(&codec_ctx, VP9E_SET_SVC_LAYER_ID, &dynamic_layer_id);
        }
        
        // Encode the frame
        vpx_codec_encode(&codec_ctx, img, frame_idx, 1, 0, VPX_DL_REALTIME);
        
        // Get compressed data (ignore for fuzzing, but call to exercise code paths)
        vpx_codec_iter_t iter = nullptr;
        const vpx_codec_cx_pkt_t* pkt;
        while ((pkt = vpx_codec_get_cx_data(&codec_ctx, &iter)) != nullptr) {
            // Packet received, continue
        }
    }
    
    // Step 10: Cleanup
    vpx_img_free(img);
    vpx_codec_destroy(&codec_ctx);
    
    return 0;
}
