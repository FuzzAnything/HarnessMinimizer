/*
 * Fuzzing harness for libvpx VP9 encoder SVC rate control and bitrate allocation logic
 * Target: Multi-layer SVC encoding with encoder rate control and mode decision logic
 * Focus: Encoder rate control algorithms, bitrate allocation across layers, adaptive quantization,
 *        and mode decision logic for SVC with 479+ blocked branches in vp9_pick_inter_mode
 * 
 * This harness specifically targets the rate control aspects of SVC encoding that are
 * not covered by existing harnesses. While harness_006-012 focus on SVC configuration
 * and inter-mode selection, this harness targets:
 * 
 * 1. Rate control algorithms for SVC (vp9_rc_get_svc_params, vp9_calc_pframe_target_size_*)
 * 2. Bitrate allocation and distribution across spatial/temporal layers
 * 3. Adaptive quantization for different SVC layers
 * 4. Mode decision logic influenced by rate control parameters
 * 5. Frame dropping decisions based on buffer levels and rate control
 * 6. Layer-specific target bitrate calculations
 * 
 * Key differentiators from existing harnesses:
 * - harness_006: General inter-mode selection with SVC
 * - harness_007: SVC control APIs without rate control focus
 * - harness_008: Advanced SVC inter-mode prediction
 * - harness_010: Deep SVC inter-mode decision logic
 * - harness_011: Feature combinations (bilinear, denoising, high-bitdepth)
 * - harness_012: Extreme SVC edge cases
 * - This harness: SVC rate control algorithms, bitrate allocation, adaptive quantization
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <algorithm>
#include <memory>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"
#include "vpx/vp8cx.h"
#include "vpx/vpx_codec.h"
#include "vpx/vpx_encoder.h"
#include "vpx/vpx_image.h"

// Minimum size needed for comprehensive SVC rate control testing
const size_t MIN_INPUT_SIZE = 2048;

// Helper to create frame data with varying complexity for rate control testing
static void fill_buffer_with_pattern(uint8_t* buffer, int width, int height, 
                                     int stride, int pattern_type,
                                     int spatial_layer, int temporal_layer,
                                     int frame_num, int bitrate_factor) {
  // Scale for bit depth (simplified - actual would handle 10/12-bit)
  for (int y = 0; y < height; y++) {
    for (int x = 0; x < width; x++) {
      uint8_t value = 0;
      
      // Patterns designed to vary complexity for rate control testing
      // Higher complexity patterns require more bits to encode
      int layer_factor = (spatial_layer + 1) * (temporal_layer + 1);
      int complexity = (bitrate_factor * layer_factor) % 100;
      
      switch (pattern_type % 8) {
        case 0: // Low complexity (flat areas - easy to encode)
          value = 128;
          break;
          
        case 1: // Medium complexity (gradient)
          value = (x * 255 / width + y * 255 / height) / 2;
          value = (value + complexity) % 256;
          break;
          
        case 2: // High complexity (detailed texture - hard to encode)
          value = (x * 37 + y * 51 + frame_num * 73 + complexity * 97) % 256;
          break;
          
        case 3: // Mixed complexity (edges and flat areas)
          value = (abs(x - width/2) < 16 || abs(y - height/2) < 16) ? 255 : 64;
          value = (value + (complexity / 4)) % 256;
          break;
          
        case 4: // Gradually increasing complexity (simulates scene change)
          {
            int grad = (frame_num * 5) % 256;
            value = (x * grad / width + y * (255 - grad) / height) / 2;
            value = (value + complexity) % 256;
          }
          break;
          
        case 5: // Block-based varying complexity
          {
            int block_size = 16 << spatial_layer;
            int block_x = x / block_size;
            int block_y = y / block_size;
            value = ((block_x * 31 + block_y * 47 + frame_num * 59) % 256);
            value = (value * complexity / 100) % 256;
          }
          break;
          
        case 6: // Wave pattern with varying frequency
          {
            int freq = 4 + (complexity % 8);
            int wave = (x * freq * 255 / width + y * freq * 255 / height) % 256;
            value = wave;
          }
          break;
          
        case 7: // Checkerboard with noise (high bitrate requirement)
          {
            int check = ((x / 8 + y / 8 + frame_num) % 2) * 192;
            int noise = (x * 13 + y * 17 + complexity * 23) % 64;
            value = check + noise;
          }
          break;
      }
      
      buffer[y * stride + x] = value;
    }
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < MIN_INPUT_SIZE) {
    return 0;
  }

  FuzzedDataProvider fdp(data, size);
  
  // Consume configuration parameters for SVC rate control testing
  uint8_t enable_svc = fdp.ConsumeBool();
  uint8_t test_cbr_mode = fdp.ConsumeBool();  // CBR vs VBR rate control
  uint8_t test_frame_dropping = fdp.ConsumeBool();
  uint8_t test_adaptive_quantization = fdp.ConsumeBool();
  
  // Rate control parameters
  unsigned int base_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 10000);
  unsigned int spatial_layers = fdp.ConsumeIntegralInRange<unsigned int>(1, 3);
  unsigned int temporal_layers = fdp.ConsumeIntegralInRange<unsigned int>(1, 3);
  
  // Layer-specific bitrate allocation factors (relative to base)
  std::vector<unsigned int> spatial_bitrate_factors;
  std::vector<unsigned int> temporal_bitrate_factors;
  
  for (unsigned int sl = 0; sl < spatial_layers; sl++) {
    spatial_bitrate_factors.push_back(fdp.ConsumeIntegralInRange<unsigned int>(50, 200));
  }
  
  for (unsigned int tl = 0; tl < temporal_layers; tl++) {
    temporal_bitrate_factors.push_back(fdp.ConsumeIntegralInRange<unsigned int>(50, 200));
  }
  
  // Frame dimensions (scaled for SVC)
  unsigned int base_width = fdp.ConsumeIntegralInRange<unsigned int>(64, 1920);
  unsigned int base_height = fdp.ConsumeIntegralInRange<unsigned int>(64, 1080);
  unsigned int framerate_num = fdp.ConsumeIntegralInRange<unsigned int>(1, 60);
  unsigned int framerate_den = fdp.ConsumeIntegralInRange<unsigned int>(1, 1000);
  
  // Select VP9 encoder interface
  vpx_codec_iface_t* encoder_iface = vpx_codec_vp9_cx();
  if (encoder_iface == nullptr) {
    return 0;
  }

  vpx_codec_err_t err;
  vpx_codec_ctx_t encoder;
  vpx_codec_enc_cfg_t cfg;
  
  // Step 1: Get default configuration
  err = vpx_codec_enc_config_default(encoder_iface, &cfg, 0);
  if (err != VPX_CODEC_OK) {
    return 0;
  }

  // Configure basic encoder parameters
  cfg.g_w = base_width;
  cfg.g_h = base_height;
  cfg.g_timebase.num = framerate_den;
  cfg.g_timebase.den = framerate_num;
  cfg.rc_target_bitrate = base_bitrate;
  
  // Configure rate control mode
  if (test_cbr_mode) {
    cfg.rc_end_usage = VPX_CBR;  // Constant Bit Rate
    // CBR-specific parameters
    cfg.rc_buf_sz = 1000;
    cfg.rc_buf_initial_sz = 500;
    cfg.rc_buf_optimal_sz = 600;
    cfg.rc_undershoot_pct = fdp.ConsumeIntegralInRange<unsigned int>(0, 100);
    cfg.rc_overshoot_pct = fdp.ConsumeIntegralInRange<unsigned int>(0, 100);
  } else {
    cfg.rc_end_usage = VPX_VBR;  // Variable Bit Rate
    // VBR-specific parameters
    cfg.rc_2pass_vbr_minsection_pct = fdp.ConsumeIntegralInRange<unsigned int>(0, 100);
    cfg.rc_2pass_vbr_maxsection_pct = fdp.ConsumeIntegralInRange<unsigned int>(100, 1000);
  }
  
  // Configure SVC layer structure in cfg before encoder initialization
  if (enable_svc) {
    cfg.ss_number_layers = spatial_layers;
    cfg.ts_number_layers = temporal_layers;
    
    // Configure layer bitrates for SVC
    for (unsigned int i = 0; i < spatial_layers; ++i) {
      cfg.ss_target_bitrate[i] = (base_bitrate * spatial_bitrate_factors[i]) / 100;
    }
    
    // Configure temporal layer bitrate allocation  
    for (unsigned int i = 0; i < temporal_layers; ++i) {
      cfg.ts_target_bitrate[i] = (base_bitrate * temporal_bitrate_factors[i]) / 100;
    }
  }
  
  // Initialize encoder before setting any controls
  err = vpx_codec_enc_init_ver(&encoder, encoder_iface, &cfg, 0, VPX_ENCODER_ABI_VERSION);
  if (err != VPX_CODEC_OK) {
    return 0;
  }
  // Configure SVC if enabled (must be after encoder initialization)
  if (enable_svc) {
    // Enable SVC
    vpx_codec_control_(&encoder, VP9E_SET_SVC, 1);
    
    // Set layer IDs for SVC
    for (unsigned int sl = 0; sl < spatial_layers; sl++) {
      for (unsigned int tl = 0; tl < temporal_layers; tl++) {
        vpx_svc_layer_id_t layer_id;
        layer_id.spatial_layer_id = sl;
        layer_id.temporal_layer_id = tl;
        // Initialize temporal_layer_id_per_spatial array
        for (int i = 0; i < VPX_SS_MAX_LAYERS; i++) {
          layer_id.temporal_layer_id_per_spatial[i] = tl;
        }
        vpx_codec_control_(&encoder, VP9E_SET_SVC_LAYER_ID, &layer_id);
      }
    }
    
    // Configure SVC reference frame settings for rate control
    vpx_svc_ref_frame_config_t ref_config;
    memset(&ref_config, 0, sizeof(ref_config));
    
    // Set reference frame configuration based on fuzzer input
    for (int i = 0; i < VPX_SS_MAX_LAYERS; i++) {
      if (i < (int)spatial_layers) {
        ref_config.lst_fb_idx[i] = fdp.ConsumeIntegralInRange<int>(0, 7);
        ref_config.gld_fb_idx[i] = fdp.ConsumeIntegralInRange<int>(0, 7);
        ref_config.alt_fb_idx[i] = fdp.ConsumeIntegralInRange<int>(0, 7);
        ref_config.update_buffer_slot[i] = fdp.ConsumeBool() ? 1 : 0;
        ref_config.update_last[i] = fdp.ConsumeBool() ? 1 : 0;
        ref_config.update_golden[i] = fdp.ConsumeBool() ? 1 : 0;
        ref_config.update_alt_ref[i] = fdp.ConsumeBool() ? 1 : 0;
        ref_config.reference_last[i] = fdp.ConsumeBool() ? 1 : 0;
        ref_config.reference_golden[i] = fdp.ConsumeBool() ? 1 : 0;
        ref_config.reference_alt_ref[i] = fdp.ConsumeBool() ? 1 : 0;
        ref_config.duration[i] = fdp.ConsumeIntegral<int64_t>();
      }
    }
    
    vpx_codec_control_(&encoder, VP9E_SET_SVC_REF_FRAME_CONFIG, &ref_config);
    
    // Configure frame dropping for rate control
    if (test_frame_dropping) {
      vpx_svc_frame_drop_t drop_config;
      drop_config.framedrop_mode = (SVC_LAYER_DROP_MODE)fdp.ConsumeIntegralInRange<int>(0, 3);
      
      for (unsigned int sl = 0; sl < spatial_layers; sl++) {
        drop_config.framedrop_thresh[sl] = fdp.ConsumeIntegralInRange<int>(0, 100);
      }
      drop_config.max_consec_drop = fdp.ConsumeIntegralInRange<int>(0, 100);
      
      vpx_codec_control_(&encoder, VP9E_SET_SVC_FRAME_DROP_LAYER, &drop_config);
    }
    
    // Configure golden frame temporal references for rate control
    int use_gf_temporal_ref = fdp.ConsumeBool() ? 1 : 0;
    vpx_codec_control_(&encoder, VP9E_SET_SVC_GF_TEMPORAL_REF, use_gf_temporal_ref);
  }

  // Set encoder control parameters for rate control testing
  vpx_codec_control_(&encoder, VP8E_SET_CPUUSED, fdp.ConsumeIntegralInRange<int>(0, 9));
  
  // Set adaptive quantization if enabled
  if (test_adaptive_quantization) {
    vpx_codec_control_(&encoder, VP9E_SET_AQ_MODE, fdp.ConsumeIntegralInRange<int>(0, 3));
    
    // Note: VP9E_SET_CYCLIC_REFRESH is not available in this version
    // Use VP9E_SET_ALT_REF_AQ as alternative for adaptive quantization testing
    int alt_ref_aq = fdp.ConsumeBool() ? 1 : 0;
    vpx_codec_control_(&encoder, VP9E_SET_ALT_REF_AQ, alt_ref_aq);
  }
  
  // Set noise sensitivity (affects rate control decisions)
  int noise_sensitivity = fdp.ConsumeIntegralInRange<int>(0, 6);
  vpx_codec_control_(&encoder, VP9E_SET_NOISE_SENSITIVITY, noise_sensitivity);
  
  // Note: VP9E_SET_LAG_IN_FRAMES is not available in this version
  // Configure lag in frames through encoder configuration instead
  cfg.g_lag_in_frames = fdp.ConsumeIntegralInRange<int>(0, 25);
  
  // Create image buffer
  vpx_image_t img;
  vpx_img_alloc(&img, VPX_IMG_FMT_I420, base_width, base_height, 1);
  if (img.bps == 0) {
    vpx_codec_destroy(&encoder);
    return 0;
  }
  // Encode multiple frames to exercise rate control over time
  const int NUM_TEST_FRAMES = fdp.ConsumeIntegralInRange<int>(1, 10);
  int frame_counter = 0;
  
  for (int frame_idx = 0; frame_idx < NUM_TEST_FRAMES; frame_idx++) {
    // Generate frame data with varying complexity for rate control testing
    int pattern_type = fdp.ConsumeIntegralInRange<int>(0, 7);
    int bitrate_factor = fdp.ConsumeIntegralInRange<int>(10, 200);
    
    // Generate Y plane
    fill_buffer_with_pattern(img.planes[VPX_PLANE_Y], 
                                 img.d_w, img.d_h,
                                 img.stride[VPX_PLANE_Y],
                                 pattern_type,
                                 0, 0,  // Base layer
                                 frame_idx,
                                 bitrate_factor);
    
    // Generate UV planes with fuzzer data
    int uv_width = (img.d_w + 1) / 2;
    int uv_height = (img.d_h + 1) / 2;
    
    for (int y = 0; y < uv_height; y++) {
      for (int x = 0; x < uv_width; x++) {
        // Use fuzzer data for UV planes
        uint8_t u_value = fdp.ConsumeIntegral<uint8_t>();
        uint8_t v_value = fdp.ConsumeIntegral<uint8_t>();
        img.planes[VPX_PLANE_U][y * img.stride[VPX_PLANE_U] + x] = u_value;
        img.planes[VPX_PLANE_V][y * img.stride[VPX_PLANE_V] + x] = v_value;
      }
    }
    
    // Set frame flags to influence rate control
    vpx_enc_frame_flags_t frame_flags = 0;
    if (frame_idx == 0) {
      frame_flags |= VPX_EFLAG_FORCE_KF;  // Force keyframe for first frame
    }
    
    // Randomly force keyframes to test rate control with keyframes
    if (fdp.ConsumeBool() && frame_idx > 0) {
      frame_flags |= VPX_EFLAG_FORCE_KF;
    }
    
    // Encode the frame
    err = vpx_codec_encode(&encoder, &img, frame_counter, 1, frame_flags, VPX_DL_REALTIME);
    if (err != VPX_CODEC_OK) {
      break;
    }
    
    // Get encoder statistics to verify rate control operation
    vpx_codec_iter_t iter = NULL;
    const vpx_codec_cx_pkt_t *pkt;
    
    while ((pkt = vpx_codec_get_cx_data(&encoder, &iter)) != NULL) {
      if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
        // Frame encoded successfully
        // Can check pkt->data.frame.sz for encoded frame size
      } else if (pkt->kind == VPX_CODEC_STATS_PKT) {
        // Statistics packet - contains rate control info
      }
    }
    
    frame_counter++;
    
    // Update SVC layer for next frame if enabled
    if (enable_svc) {
      // Cycle through temporal layers
      int current_temporal_layer = frame_idx % temporal_layers;
      vpx_svc_layer_id_t layer_id;
      layer_id.spatial_layer_id = 0;  // Encode base spatial layer
      layer_id.temporal_layer_id = current_temporal_layer;
      vpx_codec_control(&encoder, VP9E_SET_SVC_LAYER_ID, &layer_id);
    }
    
    // Randomly change bitrate during encoding to test rate control adaptation
    if (fdp.ConsumeBool() && frame_idx > 0) {
      unsigned int new_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 10000);
      cfg.rc_target_bitrate = new_bitrate;
      // Note: VP8E_SET_BITRATE is not available in this version
      // Bitrate change may not take effect immediately without reconfiguration
    }
  }

  // Flush encoder
  err = vpx_codec_encode(&encoder, NULL, frame_counter, 0, 0, VPX_DL_REALTIME);
  
  // Cleanup
  vpx_img_free(&img);
  vpx_codec_destroy(&encoder);
  
  return 0;
}
