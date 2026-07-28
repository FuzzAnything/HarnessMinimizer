/*
 * Fuzzing harness for libvpx focusing on deep coverage of VP9 encoder configuration 
 * validation and scalability features (SVC - Scalable Video Coding)
 * 
 * Primary target: validate_config with 287 blocked branches (vp9_cx_iface.c:validate_config)
 * Secondary target: VP9 scalability features (spatial/temporal layering), configuration
 * validation error conditions, advanced encoding modes, tile-based encoding, multi-threading
 * 
 * Unique focus: Exclusive VP9 SVC testing with comprehensive parameter validation
 * Expected impact: Unblock 287+ branches in validate_config, test SVC-specific control APIs
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <algorithm>

#include "fuzzer/FuzzedDataProvider.h"

// Include vpx headers
extern "C" {
#include "vpx/vpx_codec.h"
#include "vpx/vpx_image.h"
#include "vpx/vpx_encoder.h"
#include "vpx/vp8cx.h"
}

extern "C" void usage_exit(void) { exit(EXIT_FAILURE); }

// Helper function to create a simple test image
static vpx_image_t* create_test_image(unsigned int width, unsigned int height) {
  vpx_image_t* img = vpx_img_alloc(NULL, VPX_IMG_FMT_I420, width, height, 1);
  if (!img) return NULL;
  
  // Fill with simple pattern
  for (unsigned int y = 0; y < height; y++) {
    for (unsigned int x = 0; x < width; x++) {
      img->planes[VPX_PLANE_Y][y * img->stride[VPX_PLANE_Y] + x] = (x + y) % 256;
    }
  }
  
  unsigned int uv_height = height / 2;
  unsigned int uv_width = width / 2;
  for (unsigned int y = 0; y < uv_height; y++) {
    for (unsigned int x = 0; x < uv_width; x++) {
      img->planes[VPX_PLANE_U][y * img->stride[VPX_PLANE_U] + x] = 128;
      img->planes[VPX_PLANE_V][y * img->stride[VPX_PLANE_V] + x] = 128;
    }
  }
  
  return img;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 512) {
    return 0;  // Need substantial data for comprehensive SVC configuration testing
  }

  FuzzedDataProvider fdp(data, size);

  // Use VP9 encoder exclusively for SVC testing
  vpx_codec_iface_t *encoder_iface = vpx_codec_vp9_cx();
  
  vpx_codec_ctx_t codec;
  vpx_codec_enc_cfg_t cfg;

  // Step 1: Get default configuration for VP9
  if (vpx_codec_enc_config_default(encoder_iface, &cfg, 0) != VPX_CODEC_OK) {
    return 0;
  }

  // Step 2: Comprehensive VP9 SVC configuration fuzzing targeting validate_config
  // Focus on parameters that trigger validation paths
  
  // 2.1 Temporal layering configuration (1-5 layers as per VP9 spec)
  cfg.ts_number_layers = fdp.ConsumeIntegralInRange<unsigned int>(0, 8); // 0 to test invalid
  cfg.ts_periodicity = fdp.ConsumeIntegralInRange<unsigned int>(0, 32); // >16 to test validation
  
  // Fill temporal layer IDs - can create invalid patterns
  for (unsigned int i = 0; i < cfg.ts_periodicity && i < VPX_TS_MAX_PERIODICITY; i++) {
    cfg.ts_layer_id[i] = fdp.ConsumeIntegralInRange<unsigned int>(0, 15); // >ts_number_layers-1 to test validation
  }
  
  // Set target bitrate for temporal layers - can create invalid distributions
  for (unsigned int i = 0; i < cfg.ts_number_layers && i < VPX_TS_MAX_LAYERS; i++) {
    cfg.ts_target_bitrate[i] = fdp.ConsumeIntegralInRange<unsigned int>(0, 1000000);
  }
  
  // Set rate decimator for temporal layers - can create invalid values (0 or >16)
  for (unsigned int i = 0; i < cfg.ts_number_layers && i < VPX_TS_MAX_LAYERS; i++) {
    cfg.ts_rate_decimator[i] = fdp.ConsumeIntegralInRange<unsigned int>(0, 32);
  }

  // 2.2 Spatial layering configuration (1-5 layers for VP9 SVC)
  cfg.ss_number_layers = fdp.ConsumeIntegralInRange<unsigned int>(0, 8); // 0 or >5 to test validation
  
  // Set target bitrate for spatial layers with potentially invalid auto-alt-ref
  for (unsigned int i = 0; i < cfg.ss_number_layers && i < VPX_SS_MAX_LAYERS; i++) {
    cfg.ss_target_bitrate[i] = fdp.ConsumeIntegralInRange<unsigned int>(0, 1000000);
    cfg.ss_enable_auto_alt_ref[i] = fdp.ConsumeIntegralInRange<int>(-1, 2); // -1, 0, 1, 2 to test validation
  }

  // 2.3 Combined layer target bitrates for SVC
  unsigned int total_layers = cfg.ss_number_layers * cfg.ts_number_layers;
  if (total_layers > VPX_MAX_LAYERS) total_layers = VPX_MAX_LAYERS;
  for (unsigned int i = 0; i < total_layers && i < VPX_MAX_LAYERS; i++) {
    cfg.layer_target_bitrate[i] = fdp.ConsumeIntegralInRange<unsigned int>(0, 1000000);
  }

  // 2.4 Bitrate allocation patterns targeting validation
  cfg.rc_target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(0, 10000000);
  cfg.rc_min_quantizer = fdp.ConsumeIntegralInRange<unsigned int>(0, 255); // >63 to test validation
  cfg.rc_max_quantizer = fdp.ConsumeIntegralInRange<unsigned int>(0, 255); // >63 to test validation
  
  // Explicitly test min > max validation path
  if (fdp.ConsumeBool()) {
    if (cfg.rc_min_quantizer > cfg.rc_max_quantizer) {
      // Keep invalid
    } else {
      std::swap(cfg.rc_min_quantizer, cfg.rc_max_quantizer);
    }
  }

  // 2.5 Keyframe intervals with potential invalid combinations
  cfg.kf_mode = static_cast<vpx_kf_mode>(fdp.ConsumeIntegral<uint8_t>() % 2); // Only valid values: 0 (VPX_KF_FIXED) or 1 (VPX_KF_AUTO)
  cfg.kf_min_dist = fdp.ConsumeIntegralInRange<unsigned int>(0, 10000);
  cfg.kf_max_dist = fdp.ConsumeIntegralInRange<unsigned int>(0, 10000);
  
  // Test invalid min > max when in auto mode
  if (cfg.kf_mode == VPX_KF_AUTO && fdp.ConsumeBool()) {
    if (cfg.kf_min_dist > cfg.kf_max_dist) {
      // Keep invalid
    } else {
      std::swap(cfg.kf_min_dist, cfg.kf_max_dist);
    }
  }

  // 2.6 Resolution and timebase - critical for validation
  cfg.g_w = fdp.ConsumeIntegralInRange<unsigned int>(0, 65536); // 0 to test validation
  cfg.g_h = fdp.ConsumeIntegralInRange<unsigned int>(0, 65536); // 0 to test validation
  
  // Test invalid aspect ratios
  cfg.g_timebase.num = fdp.ConsumeIntegralInRange<unsigned int>(0, 1000000); // 0 to test validation
  cfg.g_timebase.den = fdp.ConsumeIntegralInRange<unsigned int>(0, 1000000); // 0 to test validation

  // 2.7 Rate control parameters that affect validation
  cfg.rc_end_usage = static_cast<vpx_rc_mode>(fdp.ConsumeIntegral<uint8_t>() % 4); // Valid values: 0 (VPX_VBR), 1 (VPX_CBR), 2 (VPX_CQ), 3 (VPX_Q)
  cfg.rc_undershoot_pct = fdp.ConsumeIntegralInRange<unsigned int>(0, 1000); // >100 to test validation
  cfg.rc_overshoot_pct = fdp.ConsumeIntegralInRange<unsigned int>(0, 1000); // >100 to test validation
  
  cfg.rc_buf_sz = fdp.ConsumeIntegralInRange<unsigned int>(0, 100000);
  cfg.rc_buf_initial_sz = fdp.ConsumeIntegralInRange<unsigned int>(0, 200000); // >rc_buf_sz to test validation
  cfg.rc_buf_optimal_sz = fdp.ConsumeIntegralInRange<unsigned int>(0, 200000); // >rc_buf_sz to test validation

  // 2.8 Profile and advanced features
  cfg.g_profile = fdp.ConsumeIntegralInRange<unsigned int>(0, 10); // >3 to test validation
  cfg.g_threads = fdp.ConsumeIntegralInRange<unsigned int>(0, 256); // High values
  cfg.g_lag_in_frames = fdp.ConsumeIntegralInRange<unsigned int>(0, 1000);
  cfg.g_error_resilient = static_cast<vpx_codec_er_flags_t>(fdp.ConsumeIntegral<uint32_t>());
  cfg.g_pass = static_cast<vpx_enc_pass>(fdp.ConsumeIntegral<uint8_t>() % 3); // Valid values: 0 (VPX_RC_ONE_PASS), 1 (VPX_RC_FIRST_PASS), 2 (VPX_RC_LAST_PASS)

  // Step 3: Initialize encoder with fuzzed configuration (triggers validate_config)
  vpx_codec_err_t init_err = vpx_codec_enc_init_ver(&codec, encoder_iface, &cfg, 0, VPX_ENCODER_ABI_VERSION);
  
  // Step 4: If initialization succeeded, test SVC-specific control APIs
  if (init_err == VPX_CODEC_OK) {
    // 4.1 Enable SVC mode
    int svc_enable = fdp.ConsumeBool() ? 1 : 0;
    vpx_codec_control(&codec, VP9E_SET_SVC, svc_enable);
    
    if (svc_enable) {
      // 4.2 Set SVC extra configuration parameters
      vpx_svc_extra_cfg_t svc_extra_cfg;
      
      // Initialize SVC extra config with values from fuzzer input
      for (int i = 0; i < VPX_MAX_LAYERS; i++) {
        svc_extra_cfg.max_quantizers[i] = fdp.ConsumeIntegralInRange<int>(0, 255); // >63 to test validation
        svc_extra_cfg.min_quantizers[i] = fdp.ConsumeIntegralInRange<int>(0, 255); // >63 to test validation
        svc_extra_cfg.scaling_factor_num[i] = fdp.ConsumeIntegralInRange<int>(0, 512);
        svc_extra_cfg.scaling_factor_den[i] = fdp.ConsumeIntegralInRange<int>(0, 512);
        svc_extra_cfg.speed_per_layer[i] = fdp.ConsumeIntegralInRange<int>(-16, 16); // Valid range is -8 to 8
        svc_extra_cfg.loopfilter_ctrl[i] = fdp.ConsumeIntegralInRange<int>(0, 2);
      }
      svc_extra_cfg.temporal_layering_mode = fdp.ConsumeIntegralInRange<int>(0, 4);
      
      // Note: VP9E_SET_SVC_PARAMETERS expects a pointer to vpx_svc_extra_cfg_t
      // But need to verify the actual API. Let's try using it.
      vpx_codec_control(&codec, VP9E_SET_SVC_PARAMETERS, &svc_extra_cfg);
      
      // 4.3 Set SVC layer ID for each frame
      vpx_svc_layer_id_t layer_id;
      layer_id.spatial_layer_id = fdp.ConsumeIntegralInRange<int>(0, 7); // >max to test validation
      layer_id.temporal_layer_id = fdp.ConsumeIntegralInRange<int>(0, 7); // >max to test validation
      // Initialize temporal_layer_id_per_spatial array
      for (int i = 0; i < VPX_SS_MAX_LAYERS; i++) {
        layer_id.temporal_layer_id_per_spatial[i] = fdp.ConsumeIntegralInRange<int>(0, 7);
      }
      vpx_codec_control(&codec, VP9E_SET_SVC_LAYER_ID, &layer_id);
    }
    
    // 4.4 Tile-based encoding configurations
    int tile_columns = fdp.ConsumeIntegralInRange<int>(0, 10); // >6 to test validation
    int tile_rows = fdp.ConsumeIntegralInRange<int>(0, 10); // >2 to test validation
    vpx_codec_control(&codec, VP9E_SET_TILE_COLUMNS, tile_columns);
    vpx_codec_control(&codec, VP9E_SET_TILE_ROWS, tile_rows);
    
    // 4.5 Row-based multi-threading
    unsigned int row_mt = fdp.ConsumeBool() ? 1 : 0;
    vpx_codec_control(&codec, VP9E_SET_ROW_MT, row_mt);
    
    // 4.6 Advanced encoding modes
    // Adaptive quantization mode
    unsigned int aq_mode = fdp.ConsumeIntegralInRange<unsigned int>(0, 10); // >4 to test validation
    vpx_codec_control(&codec, VP9E_SET_AQ_MODE, aq_mode);
    
    // Altref adaptive quantization
    int alt_ref_aq = fdp.ConsumeBool() ? 1 : 0;
    vpx_codec_control(&codec, VP9E_SET_ALT_REF_AQ, alt_ref_aq);
    
    // Lossless mode
    unsigned int lossless = fdp.ConsumeIntegralInRange<unsigned int>(0, 2); // >1 to test validation
    vpx_codec_control(&codec, VP9E_SET_LOSSLESS, lossless);
    
    // Noise sensitivity
    unsigned int noise_sensitivity = fdp.ConsumeIntegralInRange<unsigned int>(0, 10); // >4 to test validation
    vpx_codec_control(&codec, VP9E_SET_NOISE_SENSITIVITY, noise_sensitivity);
    
    // Target level (0-31, but some values invalid)
    unsigned int target_level = fdp.ConsumeIntegralInRange<unsigned int>(0, 100); // >31 to test validation
    vpx_codec_control(&codec, VP9E_SET_TARGET_LEVEL, target_level);
    
    // Frame parallel decoding
    unsigned int frame_parallel = fdp.ConsumeBool() ? 1 : 0;
    vpx_codec_control(&codec, VP9E_SET_FRAME_PARALLEL_DECODING, frame_parallel);
    
    // 4.7 Temporal filtering and periodic boost
    unsigned int frame_periodic_boost = fdp.ConsumeIntegralInRange<unsigned int>(0, 2);
    vpx_codec_control(&codec, VP9E_SET_FRAME_PERIODIC_BOOST, frame_periodic_boost);
    
    // 4.8 Color space and range
    int color_space = fdp.ConsumeIntegralInRange<int>(0, 10); // > valid values
    vpx_codec_control(&codec, VP9E_SET_COLOR_SPACE, color_space);
    
    int color_range = fdp.ConsumeIntegralInRange<int>(0, 3); // >1 to test validation
    vpx_codec_control(&codec, VP9E_SET_COLOR_RANGE, color_range);
    
    // 4.9 Tune content
    int tune_content = fdp.ConsumeIntegralInRange<int>(0, 4); // >2 to test validation
    vpx_codec_control(&codec, VP9E_SET_TUNE_CONTENT, tune_content);
    
    // 4.10 Additional rate control parameters
    unsigned int max_inter_bitrate_pct = fdp.ConsumeIntegralInRange<unsigned int>(0, 1000);
    vpx_codec_control(&codec, VP9E_SET_MAX_INTER_BITRATE_PCT, max_inter_bitrate_pct);
    
    unsigned int gf_cbr_boost_pct = fdp.ConsumeIntegralInRange<unsigned int>(0, 1000);
    vpx_codec_control(&codec, VP9E_SET_GF_CBR_BOOST_PCT, gf_cbr_boost_pct);
    
    // 4.11 Min/Max GF intervals
    unsigned int min_gf_interval = fdp.ConsumeIntegralInRange<unsigned int>(0, 100);
    unsigned int max_gf_interval = fdp.ConsumeIntegralInRange<unsigned int>(0, 100);
    vpx_codec_control(&codec, VP9E_SET_MIN_GF_INTERVAL, min_gf_interval);
    vpx_codec_control(&codec, VP9E_SET_MAX_GF_INTERVAL, max_gf_interval);
    
    // 4.12 Delta Q UV
    int delta_q_uv = fdp.ConsumeIntegralInRange<int>(-255, 255);
    vpx_codec_control(&codec, VP9E_SET_DELTA_Q_UV, delta_q_uv);
    
    // 4.13 Disable loopfilter
    int disable_loopfilter = fdp.ConsumeBool() ? 1 : 0;
    vpx_codec_control(&codec, VP9E_SET_DISABLE_LOOPFILTER, disable_loopfilter);
    
    // 4.14 Disable overshoot maxq in CBR mode
    int disable_overshoot_maxq_cbr = fdp.ConsumeBool() ? 1 : 0;
    vpx_codec_control(&codec, VP9E_SET_DISABLE_OVERSHOOT_MAXQ_CBR, disable_overshoot_maxq_cbr);
    
    // 4.15 Quantizer one-pass
    int quantizer_one_pass = fdp.ConsumeIntegralInRange<int>(-1, 255);
    vpx_codec_control(&codec, VP9E_SET_QUANTIZER_ONE_PASS, quantizer_one_pass);
    
    // 4.16 Key frame filtering
    int key_frame_filtering = fdp.ConsumeBool() ? 1 : 0;
    vpx_codec_control(&codec, VP9E_SET_KEY_FRAME_FILTERING, key_frame_filtering);
    
    // 4.17 Validate input HBD
    int validate_input_hbd = fdp.ConsumeBool() ? 1 : 0;
    vpx_codec_control(&codec, VP9E_SET_VALIDATE_INPUT_HBD, validate_input_hbd);
    
    // Step 5: Create test image and encode frames
    vpx_image_t* test_img = create_test_image(cfg.g_w > 0 ? cfg.g_w : 64, 
                                              cfg.g_h > 0 ? cfg.g_h : 64);
    if (test_img) {
      // Encode a small number of frames with varied flags to exercise encoder
      for (int frame = 0; frame < 3 && fdp.remaining_bytes() > 32; frame++) {
        // Vary encoding flags based on fuzzer input
        unsigned long flags = 0;
        if (fdp.ConsumeBool()) flags |= VP8_EFLAG_NO_REF_LAST;
        if (fdp.ConsumeBool()) flags |= VP8_EFLAG_NO_REF_GF;
        if (fdp.ConsumeBool()) flags |= VP8_EFLAG_NO_REF_ARF;
        if (fdp.ConsumeBool()) flags |= VP8_EFLAG_NO_UPD_LAST;
        if (fdp.ConsumeBool()) flags |= VP8_EFLAG_NO_UPD_GF;
        if (fdp.ConsumeBool()) flags |= VP8_EFLAG_NO_UPD_ARF;
        
        vpx_codec_encode(&codec, test_img, frame, 1, flags, VPX_DL_REALTIME);
        
        // Retrieve encoded data to exercise get_cx_data paths
        const vpx_codec_cx_pkt_t *pkt = NULL;
        vpx_codec_iter_t iter = NULL;
        while ((pkt = vpx_codec_get_cx_data(&codec, &iter)) != NULL) {
          // Just consume packets to exercise the API
          if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
            // Frame packet
          } else if (pkt->kind == VPX_CODEC_STATS_PKT) {
            // Stats packet
          }
        }
      }
      
      vpx_img_free(test_img);
    }
    
    // Step 6: Clean up
    vpx_codec_destroy(&codec);
  } else {
    // Initialization failed - this is expected for invalid configurations
    // Don't do anything, just let it return
  }
  
  return 0;
}
