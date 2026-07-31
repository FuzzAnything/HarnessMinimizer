/*
 * Fuzzing harness for libvpx VP9 encoder advanced SVC inter-mode prediction logic
 * Target: vp9_pick_inter_mode function with 407 blocked branches (worst coverage gap)
 * Focus: Advanced SVC encoding configurations to explore uncovered inter-mode prediction paths
 * 
 * This harness specifically targets the most critical coverage gap identified:
 * 407 blocked branches in vp9_pick_inter_mode function for VP9 encoder's inter-mode
 * prediction logic. It focuses on advanced SVC (Scalable Video Coding) configurations
 * that affect inter-mode selection decisions.
 * 
 * Key strategies to target blocked branches:
 * 1. Complex SVC layer configurations (spatial & temporal)
 * 2. Advanced reference frame configurations for SVC
 * 3. Inter-layer prediction modes and constraints
 * 4. SVC-specific motion vector handling
 * 5. Layer-dependent quantization and rate control
 * 6. Golden frame temporal references in SVC context
 * 7. Spatial layer synchronization mechanisms
 * 
 * Differentiated from existing harnesses:
 * - harness_006: Targets general inter-mode selection (197 blocked branches)
 * - harness_007: Targets SVC control APIs (0% coverage APIs)
 * - This harness: Targets SVC-specific inter-mode prediction paths (407 blocked branches)
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <algorithm>
#include <cmath>
#include <memory>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"
#include "vpx/vp8cx.h"
#include "vpx/vpx_codec.h"
#include "vpx/vpx_encoder.h"
#include "vpx/vpx_image.h"
// Minimum size needed for comprehensive SVC inter-mode testing
const size_t MIN_INPUT_SIZE = 512;

// Helper to create synthetic frame data with layer-specific patterns for SVC
static void generate_svc_inter_mode_pattern(uint8_t* buffer, int width, int height, 
                                           int stride, int pattern_type, 
                                           int spatial_layer, int temporal_layer,
                                           int frame_num, int bit_depth) {
  for (int y = 0; y < height; y++) {
    for (int x = 0; x < width; x++) {
      uint16_t value = 0;
      
      // Complex patterns designed to exercise inter-mode prediction
      // Different patterns for different SVC layers to create varied motion
      int layer_complexity = (spatial_layer * 3) + (temporal_layer * 2) + frame_num;
      
      switch (pattern_type % 8) {
        case 0: // Moving gradient (simulates camera pan)
          value = ((x + frame_num * 2) * 255 / width) ^ ((y + frame_num) * 255 / height);
          value = (value + layer_complexity * 17) % 256;
          break;
        case 1: // Expanding/contracting checkerboard (simulates zoom)
          {
            int scale = 8 + (frame_num % 16);
            value = (((x * 100 / width) / scale + (y * 100 / height) / scale + temporal_layer) % 2) * 255;
            value = (value + spatial_layer * 31) % 256;
          }
          break;
        case 2: // Simulated rotating pattern without trig functions
          {
            int dx = x - width/2;
            int dy = y - height/2;
            int angle = (frame_num * 5) % 360;
            // Simple approximation of rotation using modular arithmetic
            int rotated = (dx * angle + dy * (360 - angle)) / 180;
            value = (abs(rotated) + layer_complexity) % 256;
          }
          break;
        case 3: // Wave pattern using integer arithmetic
          {
            int wave_x = (x + frame_num * 3) % 64;
            int wave_y = (y + frame_num) % 64;
            value = 128 + ((wave_x * wave_y) % 127);
            value = (value + spatial_layer * 23 + temporal_layer * 19) % 256;
          }
          break;
        case 4: // Block motion pattern (simulates different block motions)
          {
            int block_size = 16 << spatial_layer;
            int block_x = x / block_size;
            int block_y = y / block_size;
            value = ((block_x + frame_num) ^ (block_y + temporal_layer)) % 256;
          }
          break;
        case 5: // Edge motion pattern (simulates edge following)
          {
            int edge_dist = std::min(std::min(x, width - x), std::min(y, height - y));
            value = (edge_dist * 255 / (std::min(width, height) / 2) + frame_num * 7) % 256;
            value = (value + layer_complexity * 11) % 256;
          }
          break;
        case 6: // Random with temporal coherence (simulates natural motion)
          value = (x * 37 + y * 51 + frame_num * 73 + spatial_layer * 97 + temporal_layer * 113) % 256;
          break;
        case 7: // Gradient with layer-dependent motion
          value = (x * spatial_layer * 255 / (width * 4)) + 
                  (y * temporal_layer * 255 / (height * 4)) + 
                  (frame_num * 29) % 256;
          break;
      }
      
      // Scale value for high bit depth if needed
      if (bit_depth == 10) {
        value = (value << 2) | (value >> 6); // Scale 8-bit to 10-bit (0-1023)
      } else if (bit_depth == 12) {
        value = (value << 4) | (value >> 4); // Scale 8-bit to 12-bit (0-4095)
      }
      
      if (bit_depth > 8) {
        // High bit depth: write 16-bit value
        uint16_t* buffer_16 = reinterpret_cast<uint16_t*>(buffer);
        int stride_pixels = stride / 2; // stride is in bytes, convert to 16-bit pixels
        buffer_16[y * stride_pixels + x] = value;
      } else {
        // 8-bit: write byte value
        buffer[y * stride + x] = static_cast<uint8_t>(value);
      }
    }
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < MIN_INPUT_SIZE) {
    return 0;
  }

  FuzzedDataProvider fdp(data, size);
  
  // Consume configuration parameters for advanced SVC inter-mode testing
  uint8_t test_complex_svc = fdp.ConsumeBool();
  uint8_t test_inter_layer_pred = fdp.ConsumeBool();
  uint8_t test_gf_temporal_ref = fdp.ConsumeBool();
  uint8_t test_spatial_sync = fdp.ConsumeBool();
  uint8_t test_advanced_ratectrl = fdp.ConsumeBool();
  uint8_t test_high_bitdepth = fdp.ConsumeBool();
  
  // Complex SVC layer configuration
  unsigned int spatial_layers = 1;
  unsigned int temporal_layers = 1;
  
  if (test_complex_svc) {
    spatial_layers = fdp.ConsumeIntegralInRange<unsigned int>(1, VPX_SS_MAX_LAYERS);
    temporal_layers = fdp.ConsumeIntegralInRange<unsigned int>(1, VPX_TS_MAX_LAYERS);
  }
  
  // Consume encoder configuration parameters
  unsigned int base_width = fdp.ConsumeIntegralInRange<unsigned int>(64, 1920);
  unsigned int base_height = fdp.ConsumeIntegralInRange<unsigned int>(64, 1080);
  unsigned int bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 10000);
  unsigned int framerate_num = fdp.ConsumeIntegralInRange<unsigned int>(1, 60);
  unsigned int framerate_den = fdp.ConsumeIntegralInRange<unsigned int>(1, 1000);
  
  // Select VP9 encoder interface (SVC is VP9-specific)
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
  cfg.g_timebase.den = framerate_num * framerate_den;
  cfg.rc_target_bitrate = bitrate;
  cfg.g_error_resilient = fdp.ConsumeIntegral<uint8_t>() % 2;
  cfg.g_lag_in_frames = fdp.ConsumeIntegralInRange<unsigned int>(0, 25);
  
  // Configure complex SVC layers
  cfg.ss_number_layers = spatial_layers;
  cfg.ts_number_layers = temporal_layers;
  
  // Configure layer-specific parameters to exercise inter-mode prediction
  for (unsigned int i = 0; i < spatial_layers; ++i) {
    // Layer-specific bitrate allocation (affects rate-distortion in inter-mode)
    cfg.ss_target_bitrate[i] = bitrate / spatial_layers * (i + 1);
    
    // Layer-specific encoder speed (affects inter-mode search complexity)
    cfg.ss_enable_auto_alt_ref[i] = fdp.ConsumeBool();
  }
  
  // Configure temporal layer parameters
  for (unsigned int i = 0; i < temporal_layers; ++i) {
    cfg.ts_target_bitrate[i] = bitrate / temporal_layers * (i + 1);
    cfg.ts_rate_decimator[i] = 1 << i; // Exponential frame rate reduction
  }
  
  // Set encoding mode based on fuzzed input
  uint8_t mode_choice = fdp.ConsumeIntegral<uint8_t>() % 3;
  switch (mode_choice) {
    case 0:
      cfg.rc_end_usage = VPX_VBR; // Variable bitrate
      break;
    case 1:
      cfg.rc_end_usage = VPX_CBR; // Constant bitrate
      break;
    case 2:
      cfg.rc_end_usage = VPX_CQ;  // Constant quality
      // For constant quality mode, use rc_min_quantizer and rc_max_quantizer
      cfg.rc_min_quantizer = fdp.ConsumeIntegralInRange<unsigned int>(0, 63);
      cfg.rc_max_quantizer = fdp.ConsumeIntegralInRange<unsigned int>(0, 63);
      break;
  }
  // Set bit depth based on test
  unsigned int bit_depth = 8;
  vpx_img_fmt_t img_fmt = VPX_IMG_FMT_I420;
  if (test_high_bitdepth) {
    bit_depth = fdp.ConsumeIntegral<uint8_t>() % 2 == 0 ? 10 : 12;
    img_fmt = (bit_depth == 10) ? VPX_IMG_FMT_I42016 : VPX_IMG_FMT_I42016;
  }
  
  // Initialize encoder with advanced SVC configuration
  vpx_codec_flags_t flags = 0;
  if (test_high_bitdepth) {
    flags |= VPX_CODEC_USE_HIGHBITDEPTH;
  }
  
  err = vpx_codec_enc_init_ver(&encoder, encoder_iface, &cfg, flags, VPX_ENCODER_ABI_VERSION);
  if (err != VPX_CODEC_OK) {
    // Try without high bitdepth flag if that failed
    if (test_high_bitdepth) {
      flags &= ~VPX_CODEC_USE_HIGHBITDEPTH;
      err = vpx_codec_enc_init_ver(&encoder, encoder_iface, &cfg, flags, VPX_ENCODER_ABI_VERSION);
    }
    if (err != VPX_CODEC_OK) {
      return 0;
    }
  }
  
  // Step 2: Set up advanced SVC controls to target inter-mode prediction paths
  
  // Enable SVC mode
  int svc_enabled = 1;
  vpx_codec_control_(&encoder, VP9E_SET_SVC, svc_enabled);
  
  // Set SVC layer ID structure
  vpx_svc_layer_id_t layer_id;
  layer_id.spatial_layer_id = 0;
  layer_id.temporal_layer_id = 0;
  
  // Set SVC parameters for complex configurations
  vpx_svc_extra_cfg_t svc_params;
  memset(&svc_params, 0, sizeof(svc_params));
  
  // Configure layer-specific quantization (affects inter-mode RD decisions)
  for (int i = 0; i < VPX_MAX_LAYERS; ++i) {
    svc_params.max_quantizers[i] = fdp.ConsumeIntegralInRange<int>(20, 63);
    svc_params.min_quantizers[i] = fdp.ConsumeIntegralInRange<int>(0, 40);
    svc_params.speed_per_layer[i] = fdp.ConsumeIntegralInRange<int>(0, 9);
  }
  vpx_codec_control_(&encoder, VP9E_SET_SVC_PARAMETERS, &svc_params);
  
  // Set advanced SVC reference frame configuration
  if (test_complex_svc) {
    vpx_svc_ref_frame_config_t ref_config;
    memset(&ref_config, 0, sizeof(ref_config));
    
    // Configure complex reference frame dependencies between layers
    for (int i = 0; i < spatial_layers; ++i) {
      for (int j = 0; j < temporal_layers; ++j) {
        int layer_idx = i * temporal_layers + j;
        if (layer_idx < VPX_MAX_LAYERS) {
          // Set reference frames for this layer
          ref_config.lst_fb_idx[layer_idx] = fdp.ConsumeIntegralInRange<int>(0, 7);
          ref_config.gld_fb_idx[layer_idx] = fdp.ConsumeIntegralInRange<int>(0, 7);
          ref_config.alt_fb_idx[layer_idx] = fdp.ConsumeIntegralInRange<int>(0, 7);
          
          // Set update flags for reference frames
          ref_config.update_buffer_slot[layer_idx] = fdp.ConsumeIntegral<uint8_t>() % 256;
        }
      }
    }
    vpx_codec_control_(&encoder, VP9E_SET_SVC_REF_FRAME_CONFIG, &ref_config);
  }
  
  // Set inter-layer prediction mode
  if (test_inter_layer_pred) {
    unsigned int inter_layer_pred_mode = fdp.ConsumeIntegral<uint8_t>() % 3;
    vpx_codec_control_(&encoder, VP9E_SET_SVC_INTER_LAYER_PRED, inter_layer_pred_mode);
  }
  
  // Set golden frame temporal reference for SVC
  if (test_gf_temporal_ref) {
    unsigned int gf_temporal_ref = fdp.ConsumeBool();
    vpx_codec_control_(&encoder, VP9E_SET_SVC_GF_TEMPORAL_REF, gf_temporal_ref);
  }
  
  // Set spatial layer synchronization
  if (test_spatial_sync) {
    vpx_svc_spatial_layer_sync_t spatial_sync;
    memset(&spatial_sync, 0, sizeof(spatial_sync));
    for (int i = 0; i < VPX_SS_MAX_LAYERS; ++i) {
      spatial_sync.spatial_layer_sync[i] = fdp.ConsumeBool();
    }
    spatial_sync.base_layer_intra_only = fdp.ConsumeBool();
    vpx_codec_control_(&encoder, VP9E_SET_SVC_SPATIAL_LAYER_SYNC, &spatial_sync);
  }
  
  // Set other parameters that affect inter-mode selection in SVC context
  int cpu_used = fdp.ConsumeIntegralInRange<int>(-8, 8);
  vpx_codec_control_(&encoder, VP8E_SET_CPUUSED, cpu_used);
  
  // Set adaptive quantization for SVC
  int aq_mode = fdp.ConsumeIntegralInRange<int>(0, 4);
  vpx_codec_control_(&encoder, VP9E_SET_AQ_MODE, aq_mode);
  
  // Set noise sensitivity (affects filter selection in inter-mode)
  int noise_sensitivity = fdp.ConsumeIntegralInRange<int>(0, 6);
  vpx_codec_control_(&encoder, VP9E_SET_NOISE_SENSITIVITY, noise_sensitivity);
  
  // Set tile columns for parallel processing (affects inter-mode independence)
  int tile_columns = fdp.ConsumeIntegralInRange<int>(0, 6);
  vpx_codec_control_(&encoder, VP9E_SET_TILE_COLUMNS, tile_columns);
  
  // Set frame parallel decoding flag
  int frame_parallel_decoding = fdp.ConsumeBool();
  vpx_codec_control_(&encoder, VP9E_SET_FRAME_PARALLEL_DECODING, frame_parallel_decoding);
  
  // Set adaptive quantization parameters
  if (test_advanced_ratectrl) {
    int alt_ref_aq = fdp.ConsumeBool();
    vpx_codec_control_(&encoder, VP9E_SET_ALT_REF_AQ, alt_ref_aq);
    
    int frame_boost = fdp.ConsumeBool();
    vpx_codec_control_(&encoder, VP9E_SET_FRAME_PERIODIC_BOOST, frame_boost);
  }
  
  // Allocate image buffer for frames
  vpx_image_t img;
  vpx_image_t* img_ptr = vpx_img_alloc(&img, img_fmt, base_width, base_height, 1);
  if (img_ptr == nullptr) {
    vpx_codec_destroy(&encoder);
    return 0;
  }
  
  // Encode multiple frames with varying SVC layer configurations
  int num_frames = fdp.ConsumeIntegralInRange<int>(2, 8);
  int frame_duration = 1;
  
  for (int frame_num = 0; frame_num < num_frames; ++frame_num) {
    // Update SVC layer IDs for each frame to exercise different paths
    layer_id.temporal_layer_id = frame_num % temporal_layers;
    if (spatial_layers > 1) {
      layer_id.spatial_layer_id = (frame_num / 2) % spatial_layers;
    }
    vpx_codec_control_(&encoder, VP9E_SET_SVC_LAYER_ID, &layer_id);
    
    // Generate frame content with layer-specific patterns
    int pattern_type = (frame_num * 7 + layer_id.spatial_layer_id * 11 + 
                       layer_id.temporal_layer_id * 13) % 8;
    
    // Fill Y plane with complex motion patterns
    generate_svc_inter_mode_pattern(img.planes[0], base_width, base_height, 
                                   img.stride[0], pattern_type,
                                   layer_id.spatial_layer_id, 
                                   layer_id.temporal_layer_id,
                                   frame_num, bit_depth);
    
    // Fill U and V planes (simplified - maintain chroma consistency)
    int uv_width = (base_width + 1) / 2;
    int uv_height = (base_height + 1) / 2;
    
    for (int y = 0; y < uv_height; y++) {
      for (int x = 0; x < uv_width; x++) {
        if (bit_depth > 8) {
          uint16_t* u_plane = reinterpret_cast<uint16_t*>(img.planes[1]);
          uint16_t* v_plane = reinterpret_cast<uint16_t*>(img.planes[2]);
          int uv_stride = img.stride[1] / 2;
          u_plane[y * uv_stride + x] = 512; // Mid value for 10-bit
          v_plane[y * uv_stride + x] = 512;
        } else {
          img.planes[1][y * img.stride[1] + x] = 128;
          img.planes[2][y * img.stride[2] + x] = 128;
        }
      }
    }
    
    // Set frame flags with SVC considerations
    vpx_enc_frame_flags_t frame_flags = 0;
    if (frame_num == 0) {
      frame_flags |= VPX_EFLAG_FORCE_KF; // First frame as keyframe
    }
    
    // Encode the frame
    err = vpx_codec_encode(&encoder, &img, frame_num * frame_duration, 
                          frame_duration, frame_flags, VPX_DL_REALTIME);
    
    // Process encoded data
    if (err == VPX_CODEC_OK) {
      const vpx_codec_cx_pkt_t *pkt = nullptr;
      vpx_codec_iter_t iter = nullptr;
      
      while ((pkt = vpx_codec_get_cx_data(&encoder, &iter)) != nullptr) {
        // Process packets if needed
        (void)pkt;
      }
    }
    
    // Occasionally set golden frame CBR boost percentage
    if (frame_num > 0 && (frame_num % 5 == 0)) {
      unsigned int gf_cbr_boost = fdp.ConsumeIntegralInRange<unsigned int>(0, 100);
      vpx_codec_control_(&encoder, VP9E_SET_GF_CBR_BOOST_PCT, gf_cbr_boost);
    }
  }
  
  // Flush encoder
  err = vpx_codec_encode(&encoder, nullptr, -1, 0, 0, VPX_DL_REALTIME);
  
  // Clean up
  vpx_img_free(&img);
  vpx_codec_destroy(&encoder);
  
  return 0;
}
