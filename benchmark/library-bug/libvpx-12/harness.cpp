/*
 * Fuzzing harness for libvpx two-pass VP9 encoding with SVC (Scalable Video Coding)
 * Targets: validate_config function (288 blocked branches) and first_pass_encode (325 undiscovered branches)
 * Primary goal: Exercise two-pass encoding paths with multi-layer SVC configurations to hit deeply
 *               uncovered validation and encoding paths in vp9_cx_iface.c
 * APIs: vpx_codec_enc_config_default, vpx_codec_enc_init_ver, vpx_codec_control_,
 *       vpx_codec_encode, vpx_codec_get_cx_data, vpx_codec_destroy, vpx_img_alloc, vpx_img_free
 * Specific features: Two-pass encoding (VPX_RC_FIRST_PASS/VPX_RC_LAST_PASS), SVC with 2-3 spatial
 *                    and temporal layers, complex rate control with undershoot/overshoot percentages,
 *                    temporal scalability with powers of 2, SVC parameter control via VP9E_SET_SVC_PARAMETERS
 * Semantic diversity: This harness specifically targets two-pass VP9 encoding with SVC configurations,
 *                     which is completely uncovered in existing fuzzers (harnesses 000-012).
 *                     (vs. harness_006: SVC with one-pass encoding, harness_011: control API testing,
 *                      harness_012: high-bit-depth encoding, harness_007: complex encoding features)
 * Coverage goal: Target validate_config (288 blocked branches) and first_pass_encode (325 undiscovered branches)
 *                by testing two-pass encoding validation paths and SVC configuration validation
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <algorithm>
#include <vector>
#include <memory>

#include <fuzzer/FuzzedDataProvider.h>
#include "vpx/vp8cx.h"
#include "vpx/vpx_encoder.h"
#include "vpx/vpx_image.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Minimum size needed for two-pass SVC configuration
  if (size < 512) {
    return 0;
  }

  FuzzedDataProvider fdp(data, size);

  // Step 1: Consume basic encoder configuration from fuzzer input
  unsigned int width = fdp.ConsumeIntegralInRange<unsigned int>(64, 320);
  unsigned int height = fdp.ConsumeIntegralInRange<unsigned int>(64, 240);
  unsigned int bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 10000);
  unsigned int framerate_num = 1;
  unsigned int framerate_den = fdp.ConsumeIntegralInRange<unsigned int>(24, 60);
  
  // Ensure even dimensions for YUV formats
  if (width % 2) width++;
  if (height % 2) height++;

  // Step 2: Get VP9 encoder interface
  vpx_codec_iface_t* iface = vpx_codec_vp9_cx();
  if (iface == NULL) {
    return 0;
  }

  // Step 3: Get default encoder configuration
  vpx_codec_enc_cfg_t cfg;
  vpx_codec_err_t err = vpx_codec_enc_config_default(iface, &cfg, 0);
  if (err != VPX_CODEC_OK) {
    return 0;
  }

  // Step 4: Configure for two-pass encoding with SVC
  cfg.g_w = width;
  cfg.g_h = height;
  cfg.rc_target_bitrate = bitrate;
  cfg.g_timebase.num = framerate_num;
  cfg.g_timebase.den = framerate_den;
  
  // Two-pass encoding mode (FIRST_PASS or LAST_PASS)
  int pass_choice = fdp.ConsumeIntegralInRange<int>(0, 1);
  cfg.g_pass = (pass_choice == 0) ? VPX_RC_FIRST_PASS : VPX_RC_LAST_PASS;
  
  // For two-pass encoding, we need lag_in_frames > 0
  cfg.g_lag_in_frames = fdp.ConsumeIntegralInRange<unsigned int>(1, 25);
  
  // Configure SVC: 2-3 spatial layers and 2-3 temporal layers
  unsigned int spatial_layers = fdp.ConsumeIntegralInRange<unsigned int>(2, 3);
  unsigned int temporal_layers = fdp.ConsumeIntegralInRange<unsigned int>(2, 3);
  
  cfg.ss_number_layers = spatial_layers;
  cfg.ts_number_layers = temporal_layers;
  
  // Configure layer bitrates
  for (unsigned int sl = 0; sl < spatial_layers; ++sl) {
    for (unsigned int tl = 0; tl < temporal_layers; ++tl) {
      unsigned int layer = sl * temporal_layers + tl;
      if (layer < VPX_MAX_LAYERS) {
        cfg.layer_target_bitrate[layer] = bitrate / (spatial_layers * temporal_layers);
      }
    }
  }
  
  // Configure temporal scalability: ts_rate_decimator with powers of 2
  for (unsigned int tl = 0; tl < temporal_layers; ++tl) {
    cfg.ts_rate_decimator[tl] = 1 << (temporal_layers - tl - 1);
  }
  
  // Configure complex rate control
  int rc_end_usage_choice = fdp.ConsumeIntegralInRange<int>(0, 1);
  cfg.rc_end_usage = (rc_end_usage_choice == 0) ? VPX_CBR : VPX_VBR;
  
  // Set undershoot/overshoot percentages for rate control
  cfg.rc_undershoot_pct = fdp.ConsumeIntegralInRange<unsigned int>(0, 100);
  cfg.rc_overshoot_pct = fdp.ConsumeIntegralInRange<unsigned int>(0, 100);
  
  // Set quantizer ranges
  cfg.rc_min_quantizer = fdp.ConsumeIntegralInRange<unsigned int>(0, 63);
  cfg.rc_max_quantizer = fdp.ConsumeIntegralInRange<unsigned int>(cfg.rc_min_quantizer, 63);
  
  // Set other advanced features to exercise validate_config
  cfg.g_error_resilient = fdp.ConsumeBool() ? 1 : 0;
  
  // AQ mode (adaptive quantization)
  int aq_mode = fdp.ConsumeIntegralInRange<int>(0, 4);
  
  // ARNR max frames (alt-ref noise reduction)
  int arnr_max_frames = fdp.ConsumeIntegralInRange<int>(0, 15);
  
  // Tile configuration
  unsigned int tile_columns = fdp.ConsumeIntegralInRange<unsigned int>(0, 6);
  unsigned int tile_rows = fdp.ConsumeIntegralInRange<unsigned int>(0, 6);
  
  // Step 5: Initialize encoder
  vpx_codec_ctx_t codec;
  vpx_codec_flags_t flags = 0;
  
  // Random encoder flags from fuzzer input
  bool use_highbitdepth = fdp.ConsumeBool();
  bool use_psnr = fdp.ConsumeBool();
  
  if (use_highbitdepth) {
    flags |= VPX_CODEC_USE_HIGHBITDEPTH;
  }
  if (use_psnr) {
    flags |= VPX_CODEC_USE_PSNR;
  }
  
  // For two-pass LAST_PASS, we need to provide stats from first pass
  vpx_fixed_buf_t stats_buf = { NULL, 0 };
  if (cfg.g_pass == VPX_RC_LAST_PASS) {
    // Create dummy stats buffer for testing
    size_t stats_size = fdp.ConsumeIntegralInRange<size_t>(100, 1000);
    if (fdp.remaining_bytes() >= stats_size) {
      std::vector<uint8_t> stats_data = fdp.ConsumeBytes<uint8_t>(stats_size);
      stats_buf.buf = malloc(stats_size);
      if (stats_buf.buf) {
        memcpy(stats_buf.buf, stats_data.data(), stats_size);
        stats_buf.sz = stats_size;
        cfg.rc_twopass_stats_in = stats_buf;
      }
    }
  }
  
  err = vpx_codec_enc_init_ver(&codec, iface, &cfg, flags, VPX_ENCODER_ABI_VERSION);
  if (err != VPX_CODEC_OK) {
    if (stats_buf.buf) free(stats_buf.buf);
    return 0;
  }
  
  // Step 6: Set SVC parameters using vpx_codec_control_
  // VP9E_SET_SVC_PARAMETERS expects a pointer to vpx_svc_extra_cfg_t
  
  // Set SVC layer ID
  vpx_svc_layer_id_t layer_id;
  memset(&layer_id, 0, sizeof(layer_id));
  layer_id.spatial_layer_id = fdp.ConsumeIntegralInRange<int>(0, spatial_layers - 1);
  layer_id.temporal_layer_id = fdp.ConsumeIntegralInRange<int>(0, temporal_layers - 1);
  
  for (unsigned int sl = 0; sl < VPX_SS_MAX_LAYERS; ++sl) {
    layer_id.temporal_layer_id_per_spatial[sl] = 
        fdp.ConsumeIntegralInRange<int>(0, temporal_layers - 1);
  }
  
  vpx_codec_control(&codec, VP9E_SET_SVC_LAYER_ID, &layer_id);
  
  // Set SVC (enable/disable)
  int svc_enabled = fdp.ConsumeBool() ? 1 : 0;
  vpx_codec_control(&codec, VP9E_SET_SVC, svc_enabled);
  
  // Set SVC parameters using vpx_svc_extra_cfg_t
  vpx_svc_extra_cfg_t svc_params = {};
  
  // Fill SVC parameters from fuzzer input
  for (unsigned int layer = 0; layer < VPX_MAX_LAYERS; ++layer) {
    svc_params.max_quantizers[layer] = fdp.ConsumeIntegralInRange<int>(0, 63);
    svc_params.min_quantizers[layer] = fdp.ConsumeIntegralInRange<int>(0, 63);
    svc_params.scaling_factor_num[layer] = fdp.ConsumeIntegralInRange<int>(1, 4);
    svc_params.scaling_factor_den[layer] = fdp.ConsumeIntegralInRange<int>(1, 4);
    svc_params.speed_per_layer[layer] = fdp.ConsumeIntegralInRange<int>(-8, 8);
    svc_params.loopfilter_ctrl[layer] = fdp.ConsumeIntegralInRange<int>(0, 1);
  }
  svc_params.temporal_layering_mode = fdp.ConsumeIntegralInRange<int>(0, 2);
  
  vpx_codec_control(&codec, VP9E_SET_SVC_PARAMETERS, &svc_params);
  // Set other encoder controls to exercise validate_config
  vpx_codec_control(&codec, VP8E_SET_CPUUSED, fdp.ConsumeIntegralInRange<int>(-8, 8));
  vpx_codec_control(&codec, VP9E_SET_AQ_MODE, aq_mode);
  vpx_codec_control(&codec, VP8E_SET_ARNR_MAXFRAMES, arnr_max_frames);
  vpx_codec_control(&codec, VP9E_SET_TILE_COLUMNS, tile_columns);
  vpx_codec_control(&codec, VP9E_SET_TILE_ROWS, tile_rows);
  
  // Set color space
  vpx_codec_control(&codec, VP9E_SET_COLOR_SPACE, 
                    fdp.ConsumeIntegralInRange<int>(VPX_CS_UNKNOWN, VPX_CS_SRGB));
  
  // Set color range
  vpx_codec_control(&codec, VP9E_SET_COLOR_RANGE,
                    fdp.ConsumeBool() ? VPX_CR_FULL_RANGE : VPX_CR_STUDIO_RANGE);
  
  // Step 7: Allocate image for encoding
  vpx_image_t *img = NULL;
  vpx_img_fmt_t fmt = VPX_IMG_FMT_I420;
  if (use_highbitdepth) {
    fmt = (vpx_img_fmt_t)(fmt | VPX_IMG_FMT_HIGHBITDEPTH);
  }
  
  img = vpx_img_alloc(NULL, fmt, width, height, 16);
  if (img == NULL) {
    vpx_codec_destroy(&codec);
    if (stats_buf.buf) free(stats_buf.buf);
    return 0;
  }
  
  // Step 8: Fill image with fuzzer data
  size_t y_size = width * height;
  size_t uv_size = ((width + 1) / 2) * ((height + 1) / 2);
  
  // Fill Y plane
  std::vector<uint8_t> y_data = fdp.ConsumeBytes<uint8_t>(y_size);
  if (y_data.size() == y_size) {
    memcpy(img->planes[VPX_PLANE_Y], y_data.data(), y_size);
  }
  
  // Fill U plane
  std::vector<uint8_t> u_data = fdp.ConsumeBytes<uint8_t>(uv_size);
  if (u_data.size() == uv_size) {
    memcpy(img->planes[VPX_PLANE_U], u_data.data(), uv_size);
  }
  
  // Fill V plane
  std::vector<uint8_t> v_data = fdp.ConsumeBytes<uint8_t>(uv_size);
  if (v_data.size() == uv_size) {
    memcpy(img->planes[VPX_PLANE_V], v_data.data(), uv_size);
  }
  
  // Step 9: Encode multiple frames in two-pass loop
  unsigned int num_frames = fdp.ConsumeIntegralInRange<unsigned int>(1, 5);
  
  for (unsigned int frame_idx = 0; frame_idx < num_frames; ++frame_idx) {
    if (fdp.remaining_bytes() < 16) {
      break;  // Not enough data for more frames
    }
    
    // Set frame flags
    vpx_enc_frame_flags_t encode_flags = 0;
    
    // First frame should be keyframe
    if (frame_idx == 0) {
      encode_flags |= VPX_EFLAG_FORCE_KF;
    } else {
      // Randomly force keyframe based on fuzzer input
      bool force_keyframe = fdp.ConsumeBool();
      if (force_keyframe) {
        encode_flags |= VPX_EFLAG_FORCE_KF;
      }
    }
    
    // Randomly set reference frame flags
    bool no_ref_last = fdp.ConsumeBool();
    bool no_ref_gf = fdp.ConsumeBool();
    bool no_ref_arf = fdp.ConsumeBool();
    
    if (no_ref_last) encode_flags |= VP8_EFLAG_NO_REF_LAST;
    if (no_ref_gf) encode_flags |= VP8_EFLAG_NO_REF_GF;
    if (no_ref_arf) encode_flags |= VP8_EFLAG_NO_REF_ARF;
    
    // Encode the frame
    err = vpx_codec_encode(&codec, img, frame_idx, 1, encode_flags, VPX_DL_GOOD_QUALITY);
    
    // For FIRST_PASS, we need to collect stats
    if (cfg.g_pass == VPX_RC_FIRST_PASS) {
      // In first pass, we get stats packets
      const vpx_codec_cx_pkt_t *pkt = NULL;
      vpx_codec_iter_t iter = NULL;
      
      while ((pkt = vpx_codec_get_cx_data(&codec, &iter)) != NULL) {
        if (pkt->kind == VPX_CODEC_STATS_PKT) {
          // Statistics packet from first pass
          // In a real two-pass scenario, we'd accumulate these
        }
      }
    } else if (cfg.g_pass == VPX_RC_LAST_PASS) {
      // In last pass, we get encoded frames
      const vpx_codec_cx_pkt_t *pkt = NULL;
      vpx_codec_iter_t iter = NULL;
      
      while ((pkt = vpx_codec_get_cx_data(&codec, &iter)) != NULL) {
        if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
          // Encoded frame data from last pass
          // Could validate or process frame data here
        }
      }
    }
    
    // Update image data slightly for next frame to create variation
    if (fdp.remaining_bytes() > 0 && frame_idx < num_frames - 1) {
      // Add some noise to Y plane
      size_t modify_count = std::min<size_t>(100, fdp.remaining_bytes());
      std::vector<uint8_t> noise = fdp.ConsumeBytes<uint8_t>(modify_count);
      
      // Apply noise to random positions
      for (size_t i = 0; i < std::min<size_t>(noise.size(), 100); ++i) {
        size_t pos = static_cast<size_t>(noise[i]) % y_size;
        img->planes[VPX_PLANE_Y][pos] ^= 0x01;  // Flip LSB
      }
    }
  }
  
  // Step 10: Flush encoder
  if (cfg.g_pass == VPX_RC_FIRST_PASS) {
    // Flush first pass to get remaining stats
    while (vpx_codec_encode(&codec, NULL, -1, 1, 0, VPX_DL_GOOD_QUALITY) == VPX_CODEC_OK) {
      const vpx_codec_cx_pkt_t *pkt = NULL;
      vpx_codec_iter_t iter = NULL;
      
      while ((pkt = vpx_codec_get_cx_data(&codec, &iter)) != NULL) {
        if (pkt->kind == VPX_CODEC_STATS_PKT) {
          // Collect remaining stats
        }
      }
    }
  } else if (cfg.g_pass == VPX_RC_LAST_PASS) {
    // Flush last pass to get remaining frames
    while (vpx_codec_encode(&codec, NULL, -1, 1, 0, VPX_DL_GOOD_QUALITY) == VPX_CODEC_OK) {
      const vpx_codec_cx_pkt_t *pkt = NULL;
      vpx_codec_iter_t iter = NULL;
      
      while ((pkt = vpx_codec_get_cx_data(&codec, &iter)) != NULL) {
        if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
          // Get remaining encoded frames
        }
      }
    }
  }
  
  // Step 11: Cleanup
  vpx_img_free(img);
  vpx_codec_destroy(&codec);
  if (stats_buf.buf) {
    free(stats_buf.buf);
  }
  
  return 0;
}
