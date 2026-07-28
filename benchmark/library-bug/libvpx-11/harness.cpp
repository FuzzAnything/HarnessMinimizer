/*
 * Fuzzing harness for libvpx targeting vpx_codec_control_ API with 0% fuzzer reachability
 * Primary target: vpx_codec_control_ API to explore configuration validation paths
 * Focus: validate_config function in vp9/vp9_cx_iface.c (278 blocked branches - largest blocker)
 * APIs: vpx_codec_enc_init_ver, vpx_codec_enc_config_default, vpx_codec_control_ (main target),
 *       vpx_codec_encode, vpx_codec_get_cx_data, vpx_codec_destroy, vpx_img_alloc, vpx_img_free
 * Control IDs to test:
 *   - CPU usage: VP8E_SET_CPUUSED (-8..8 for VP9, -16..16 for VP8)
 *   - Auto alt-ref: VP8E_SET_ENABLEAUTOALTREF (0..6 for VP9, 0..1 for VP8)
 *   - Target levels: VP9E_SET_TARGET_LEVEL (valid levels: 10, 11, 20, 21, 30, 31, 40, 41, 50, 51, 52, 60, 61, 62)
 *   - AQ modes: VP9E_SET_AQ_MODE (0..4)
 *   - Color space: VP9E_SET_COLOR_SPACE (VPX_CS_UNKNOWN, VPX_CS_BT_601, VPX_CS_BT_709, VPX_CS_SMPTE_170, VPX_CS_SMPTE_240, VPX_CS_BT_2020, VPX_CS_RESERVED, VPX_CS_SRGB)
 *   - Color range: VP9E_SET_COLOR_RANGE (VPX_CR_STUDIO_RANGE, VPX_CR_FULL_RANGE)
 *   - Tile configurations: VP9E_SET_TILE_COLUMNS (0..6), VP9E_SET_TILE_ROWS (0..6)
 * Semantic diversity: This harness focuses exclusively on vpx_codec_control_ API testing with
 *                     diverse control IDs to systematically exercise validate_config function
 *                     (vs. harness_006: SVC configurations, harness_007: complex encoding,
 *                      harness_008: validation edges, harness_009: comprehensive validation)
 * Coverage goal: Target 278 blocked branches in validate_config by testing vpx_codec_control_
 *                with various control IDs and parameter combinations
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
  // Minimum size needed for comprehensive control parameter testing
  if (size < 256) {
    return 0;
  }

  FuzzedDataProvider fdp(data, size);

  // Step 1: Choose encoder type (VP8 or VP9) from fuzzer input
  // 0 = VP8, 1 = VP9 (focus on VP9 as per guidance but test both)
  int encoder_type = fdp.ConsumeIntegralInRange<int>(0, 1);
  
  // Step 2: Get encoder interface
  vpx_codec_iface_t* iface = nullptr;
  if (encoder_type == 0) {
    iface = vpx_codec_vp8_cx();
  } else {
    iface = vpx_codec_vp9_cx();
  }
  
  if (iface == NULL) {
    return 0;
  }

  // Step 3: Get default encoder configuration
  vpx_codec_enc_cfg_t cfg;
  vpx_codec_err_t err = vpx_codec_enc_config_default(iface, &cfg, 0);
  if (err != VPX_CODEC_OK) {
    return 0;
  }

  // Step 4: Configure basic encoder parameters
  unsigned int width = fdp.ConsumeIntegralInRange<unsigned int>(64, 320);
  unsigned int height = fdp.ConsumeIntegralInRange<unsigned int>(64, 240);
  
  // Ensure even dimensions for YUV formats
  if (width % 2) width++;
  if (height % 2) height++;
  
  cfg.g_w = width;
  cfg.g_h = height;
  cfg.rc_target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 10000);
  cfg.g_timebase.num = 1;
  cfg.g_timebase.den = fdp.ConsumeIntegralInRange<unsigned int>(24, 60);
  cfg.g_pass = VPX_RC_ONE_PASS;
  cfg.g_lag_in_frames = 0;

  // Step 5: Initialize encoder
  vpx_codec_ctx_t codec;
  vpx_codec_flags_t flags = 0;
  
  // Random encoder flags
  bool use_highbitdepth = fdp.ConsumeBool();
  bool use_psnr = fdp.ConsumeBool();
  
  if (use_highbitdepth) {
    flags |= VPX_CODEC_USE_HIGHBITDEPTH;
  }
  if (use_psnr) {
    flags |= VPX_CODEC_USE_PSNR;
  }

  err = vpx_codec_enc_init_ver(&codec, iface, &cfg, flags, VPX_ENCODER_ABI_VERSION);
  if (err != VPX_CODEC_OK) {
    // Try without flags if initialization failed
    flags = 0;
    err = vpx_codec_enc_init_ver(&codec, iface, &cfg, flags, VPX_ENCODER_ABI_VERSION);
    if (err != VPX_CODEC_OK) {
      return 0;
    }
  }

  // Step 6: Systematically test vpx_codec_control_ API with various control IDs
  // This is the primary focus to exercise validate_config function
  
  // 6.1: Test CPU usage setting (affects speed/quality tradeoff)
  // Valid range: VP8: -16..16, VP9: -9..9 (negative values treated as absolute in VP9)
  int cpu_used = fdp.ConsumeIntegral<int>();
  if (encoder_type == 0) {  // VP8
    // Clamp to valid VP8 range
    if (cpu_used < -16) cpu_used = -16;
    if (cpu_used > 16) cpu_used = 16;
  } else {  // VP9
    // Clamp to valid VP9 range
    if (cpu_used < -9) cpu_used = -9;
    if (cpu_used > 9) cpu_used = 9;
  }
  vpx_codec_control(&codec, VP8E_SET_CPUUSED, cpu_used);

  // 6.2: Test auto alt-ref frame setting
  // Valid range: VP8: 0..1, VP9: 0..6
  unsigned int enable_auto_altref = fdp.ConsumeIntegral<unsigned int>();
  if (encoder_type == 0) {  // VP8
    enable_auto_altref = enable_auto_altref % 2;  // 0 or 1
  } else {  // VP9
    enable_auto_altref = enable_auto_altref % 7;  // 0..6
  }
  vpx_codec_control(&codec, VP8E_SET_ENABLEAUTOALTREF, enable_auto_altref);

  // 6.3: Test VP9-specific controls (only for VP9 encoder)
  if (encoder_type == 1) {  // VP9 only
    // Target level setting (valid levels: 10, 11, 20, 21, 30, 31, 40, 41, 50, 51, 52, 60, 61, 62)
    unsigned int valid_levels[] = {10, 11, 20, 21, 30, 31, 40, 41, 50, 51, 52, 60, 61, 62};
    unsigned int target_level = 0;
    if (fdp.ConsumeBool()) {
      // Use valid level
      int level_idx = fdp.ConsumeIntegralInRange<int>(0, sizeof(valid_levels)/sizeof(valid_levels[0]) - 1);
      target_level = valid_levels[level_idx];
    } else {
      // Test invalid level to exercise validation
      target_level = fdp.ConsumeIntegral<unsigned int>();
    }
    vpx_codec_control(&codec, VP9E_SET_TARGET_LEVEL, target_level);

    // AQ mode (0..4)
    unsigned int aq_mode = fdp.ConsumeIntegralInRange<unsigned int>(0, 4);
    vpx_codec_control(&codec, VP9E_SET_AQ_MODE, aq_mode);

    // Color space (0-7 as per vpx_color_space_t)
    int color_space = fdp.ConsumeIntegralInRange<int>(0, 7);
    vpx_codec_control(&codec, VP9E_SET_COLOR_SPACE, color_space);

    // Color range (0-1 as per vpx_color_range_t)
    int color_range = fdp.ConsumeIntegralInRange<int>(0, 1);
    vpx_codec_control(&codec, VP9E_SET_COLOR_RANGE, color_range);

    // Tile columns (0..6)
    int tile_columns = fdp.ConsumeIntegralInRange<int>(0, 6);
    vpx_codec_control(&codec, VP9E_SET_TILE_COLUMNS, tile_columns);

    // Tile rows (0..6)
    int tile_rows = fdp.ConsumeIntegralInRange<int>(0, 6);
    vpx_codec_control(&codec, VP9E_SET_TILE_ROWS, tile_rows);
  }

  // Step 7: Create test image for encoding
  vpx_image_t* img = vpx_img_alloc(NULL, VPX_IMG_FMT_I420, width, height, 16);
  if (img == NULL) {
    vpx_codec_destroy(&codec);
    return 0;
  }

  // Fill image with synthetic data from fuzzer input
  size_t y_size = width * height;
  size_t uv_size = (width / 2) * (height / 2);
  
  if (fdp.remaining_bytes() < y_size + 2 * uv_size) {
    vpx_img_free(img);
    vpx_codec_destroy(&codec);
    return 0;
  }

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

  // Step 8: Encode frames with configured controls
  // Encode multiple frames to exercise encoder with applied controls
  unsigned int num_frames = fdp.ConsumeIntegralInRange<unsigned int>(1, 5);
  
  for (unsigned int frame_idx = 0; frame_idx < num_frames; ++frame_idx) {
    // Vary frame flags to test different encoding modes
    vpx_enc_frame_flags_t frame_flags = 0;
    
    // Set keyframe flag for first frame or randomly
    if (frame_idx == 0 || fdp.ConsumeBool()) {
      frame_flags |= VPX_EFLAG_FORCE_KF;
    }
    
    // Encode the frame
    err = vpx_codec_encode(&codec, img, frame_idx, 1, frame_flags, VPX_DL_REALTIME);
    
    if (err == VPX_CODEC_OK) {
      // Retrieve encoded data to exercise output paths
      const vpx_codec_cx_pkt_t *pkt = NULL;
      vpx_codec_iter_t iter = NULL;
      
      while ((pkt = vpx_codec_get_cx_data(&codec, &iter)) != NULL) {
        // Process different packet types
        switch (pkt->kind) {
          case VPX_CODEC_CX_FRAME_PKT:
            // Frame data available
            break;
          case VPX_CODEC_STATS_PKT:
            // Statistics data
            break;
          case VPX_CODEC_FPMB_STATS_PKT:
            // First pass MB stats
            break;
          default:
            // Other packet types
            break;
        }
      }
    }
    
    // Break if insufficient data for more frames
    if (fdp.remaining_bytes() < 100) {
      break;
    }
  }

  // Step 9: Cleanup
  vpx_img_free(img);
  vpx_codec_destroy(&codec);

  return 0;
}
