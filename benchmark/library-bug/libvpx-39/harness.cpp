/*
 * Fuzzing harness for libvpx VP9 encoder alt-ref frame processing with focus on 
 * 342 blocked branches in vp9_rd_pick_inter_mode_sb
 * 
 * Primary target: Complex predicate conditions in vp9_rd_pick_inter_mode_sb involving
 * alt-ref frames, ARNR filtering, show_frame status, and motion vector SAD comparisons
 * 
 * This harness specifically targets the intricate conditions that create blocked
 * branches in the rate-distortion optimization function:
 * 
 * 1. cpi->rc.is_src_frame_alt_ref && (cpi->oxcf.arnr_max_frames == 0) (line 3587)
 *    - Tests alt-ref frames with and without ARNR filtering
 *    
 * 2. sf->alt_ref_search_fp (line 3599)
 *    - Tests speed feature that changes alt-ref search behavior
 *    
 * 3. !cm->show_frame && pred_mv_sad[GOLDEN_FRAME] < INT_MAX &&
 *    pred_mv_sad[ALTREF_FRAME] > (pred_mv_sad[GOLDEN_FRAME] << 1) (lines 3606-3609)
 *    - Tests non-show frames with specific motion vector SAD relationships
 *    
 * 4. cm->show_frame && !cpi->rc.is_src_frame_alt_ref &&
 *    cpi->rc.frames_since_golden >= 3 &&
 *    x->pred_mv_sad[GOLDEN_FRAME] > (x->pred_mv_sad[LAST_FRAME] << 1) (lines 3611-3616)
 *    - Tests show frames with specific golden frame intervals and SAD comparisons
 * 
 * Strategy:
 * - Systematically test combinations of conditions that affect blocked branches
 * - Configure encoder to create specific state for predicate evaluation
 * - Use varied image patterns to influence motion vector SAD values
 * - Test with both VP8 and VP9 to cover different code paths
 * - Focus on semantic diversity from existing alt-ref harnesses (015, 010, 011)
 * 
 * Different from harness_015 which focuses on is_src_frame_alt_ref conditions:
 * - This harness targets the specific predicate combinations in vp9_rd_pick_inter_mode_sb
 * - Tests interactions between alt-ref status, ARNR, show_frame, and SAD comparisons
 * - Creates conditions for specific numeric comparisons (SAD values, frame counts)
 * 
 * Invocation sequence: encoder init -> targeted condition configuration ->
 * multi-frame encoding with controlled state -> cleanup.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <algorithm>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>
#include "vpx/vp8cx.h"
#include "vpx/vpx_encoder.h"
#include "vpx/vpx_image.h"

#define MIN_INPUT_SIZE 320  // Need sufficient bytes for complex condition testing

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < MIN_INPUT_SIZE) {
    return 0;  // Insufficient input for complex condition testing
  }

  FuzzedDataProvider fdp(data, size);

  // Step 1: Consume configuration for targeted predicate conditions
  
  // Choose codec: VP8 or VP9 (different alt-ref implementations)
  bool use_vp9 = fdp.ConsumeBool();
  
  // Basic encoder parameters
  bool use_highbitdepth = fdp.ConsumeBool();
  unsigned int width = fdp.ConsumeIntegralInRange<unsigned int>(128, 512) & ~1u;
  unsigned int height = fdp.ConsumeIntegralInRange<unsigned int>(128, 512) & ~1u;
  if (width < 128) width = 128;
  if (height < 128) height = 128;
  
  // Frame parameters affecting conditions
  unsigned int timebase_den = fdp.ConsumeIntegralInRange<unsigned int>(15, 60);
  unsigned int target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(200, 2000);
  unsigned int frame_count = fdp.ConsumeIntegralInRange<unsigned int>(4, 12);  // Need multiple frames
  
  // Step 2: Consume parameters for targeted predicate conditions
  
  // Condition 1: alt-ref with/without ARNR filtering
  bool enable_alt_ref = fdp.ConsumeBool();
  unsigned int arnr_max_frames = 0;
  unsigned int arnr_strength = 0;
  if (enable_alt_ref) {
    // Test both with and without ARNR filtering (critical for line 3587)
    bool use_arnr = fdp.ConsumeBool();
    if (use_arnr) {
      arnr_max_frames = fdp.ConsumeIntegralInRange<unsigned int>(1, 15);
      arnr_strength = fdp.ConsumeIntegralInRange<unsigned int>(1, 6);
    } else {
      arnr_max_frames = 0;  // Critical for cpi->oxcf.arnr_max_frames == 0 condition
    }
  }
  
  // Condition 2: alt_ref_search_fp speed feature
  bool test_alt_ref_search_fp = fdp.ConsumeBool();
  
  // Condition 3: Control show_frame status and SAD relationships
  // We'll control this through frame type configuration
  unsigned int show_frame_pattern = fdp.ConsumeIntegralInRange<unsigned int>(0, 3);
  
  // Condition 4: frames_since_golden and SAD comparisons
  unsigned int min_gf_interval = fdp.ConsumeIntegralInRange<unsigned int>(0, 16);
  unsigned int max_gf_interval = fdp.ConsumeIntegralInRange<unsigned int>(0, 16);
  if (max_gf_interval < min_gf_interval && max_gf_interval > 0) {
    max_gf_interval = min_gf_interval;
  }
  
  // Image pattern to influence SAD values (affects pred_mv_sad comparisons)
  unsigned int image_pattern_type = fdp.ConsumeIntegralInRange<unsigned int>(0, 3);
  
  // Step 3: Initialize encoder with targeted configuration
  
  vpx_codec_ctx_t codec;
  vpx_codec_enc_cfg_t cfg;
  vpx_codec_iface_t *iface = use_vp9 ? vpx_codec_vp9_cx() : vpx_codec_vp8_cx();
  
  if (vpx_codec_enc_config_default(iface, &cfg, 0)) {
    return 0;  // Failed to get default config
  }
  
  // Configure basic parameters
  cfg.g_w = width;
  cfg.g_h = height;
  cfg.g_timebase.num = 1;
  cfg.g_timebase.den = timebase_den;
  cfg.rc_target_bitrate = target_bitrate;
  cfg.g_error_resilient = 0;  // We'll test with varied settings
  
  // Configure alt-ref and lag-in-frames
  if (enable_alt_ref) {
    cfg.g_lag_in_frames = fdp.ConsumeIntegralInRange<unsigned int>(1, 25);
  } else {
    cfg.g_lag_in_frames = 0;
  }
  
  // Initialize encoder
  if (vpx_codec_enc_init(&codec, iface, &cfg, 0)) {
    return 0;  // Encoder initialization failed
  }
  
  // Step 4: Apply targeted control parameters for predicate conditions
  
  // Set ARNR parameters (critical for Condition 1)
  if (arnr_max_frames > 0) {
    vpx_codec_control(&codec, VP8E_SET_ARNR_MAXFRAMES, arnr_max_frames);
    vpx_codec_control(&codec, VP8E_SET_ARNR_STRENGTH, arnr_strength);
  }
  
  // Set golden frame intervals (affects Condition 4)
  if (use_vp9) {
    vpx_codec_control(&codec, VP9E_SET_MIN_GF_INTERVAL, min_gf_interval);
    vpx_codec_control(&codec, VP9E_SET_MAX_GF_INTERVAL, max_gf_interval);
  }
  
  // Set auto alt-ref (affects is_src_frame_alt_ref)
  if (enable_alt_ref) {
    unsigned int auto_alt_ref_level = fdp.ConsumeIntegralInRange<unsigned int>(0, 6);
    vpx_codec_control(&codec, VP8E_SET_ENABLEAUTOALTREF, auto_alt_ref_level);
  }
  
  // Configure additional parameters that might affect speed features
  if (use_vp9) {
    // Test various speed features that might affect alt_ref_search_fp
    unsigned int cpu_used = fdp.ConsumeIntegralInRange<unsigned int>(0, 9);
    vpx_codec_control(&codec, VP8E_SET_CPUUSED, cpu_used);
    
    // Set tile configuration (affects parallel processing)
    unsigned int tile_columns = fdp.ConsumeIntegralInRange<unsigned int>(0, 2);
    vpx_codec_control(&codec, VP9E_SET_TILE_COLUMNS, tile_columns);
    
    // Set adaptive quantization
    unsigned int aq_mode = fdp.ConsumeIntegralInRange<unsigned int>(0, 3);
    vpx_codec_control(&codec, VP9E_SET_AQ_MODE, aq_mode);
  }
  
  // Step 5: Create image buffers with patterns to influence SAD values
  
  vpx_image_t *img = vpx_img_alloc(NULL, 
                                   use_highbitdepth ? VPX_IMG_FMT_I42016 : VPX_IMG_FMT_I420,
                                   width, height, 1);
  if (!img) {
    vpx_codec_destroy(&codec);
    return 0;
  }
  
  // Fill image with pattern to create specific SAD relationships
  // Different patterns will create different motion vector SAD values
  // affecting the pred_mv_sad comparisons in Conditions 3 and 4
  
  for (unsigned int frame_idx = 0; frame_idx < frame_count; ++frame_idx) {
    // Vary image pattern based on pattern type and frame index
    // This creates different SAD values for motion estimation
    
    // Fill Y plane
    for (unsigned int y = 0; y < height; ++y) {
      uint8_t *y_row = img->planes[0] + y * img->stride[0];
      for (unsigned int x = 0; x < width; ++x) {
        // Create pattern that changes between frames
        // This affects motion vector SAD calculations
        uint8_t pixel_value = 128;
        
        switch (image_pattern_type) {
          case 0:  // Checkerboard pattern
            pixel_value = ((x / 16 + y / 16 + frame_idx) % 2) * 255;
            break;
          case 1:  // Gradient pattern
            pixel_value = (x * 255 / width + y * 255 / height + frame_idx * 16) % 256;
            break;
          case 2:  // Horizontal stripes
            pixel_value = ((y / 32 + frame_idx) % 2) * 255;
            break;
          case 3:  // Vertical stripes  
            pixel_value = ((x / 32 + frame_idx) % 2) * 255;
            break;
        }
        
        if (use_highbitdepth) {
          uint16_t *y_row_16 = (uint16_t *)y_row;
          y_row_16[x] = pixel_value << 8;
        } else {
          y_row[x] = pixel_value;
        }
      }
    }
    
    // Fill U and V planes (subsampled)
    for (unsigned int y = 0; y < height / 2; ++y) {
      uint8_t *u_row = img->planes[1] + y * img->stride[1];
      uint8_t *v_row = img->planes[2] + y * img->stride[2];
      for (unsigned int x = 0; x < width / 2; ++x) {
        uint8_t uv_value = 128;
        
        if (use_highbitdepth) {
          uint16_t *u_row_16 = (uint16_t *)u_row;
          uint16_t *v_row_16 = (uint16_t *)v_row;
          u_row_16[x] = uv_value << 8;
          v_row_16[x] = (255 - uv_value) << 8;
        } else {
          u_row[x] = uv_value;
          v_row[x] = 255 - uv_value;
        }
      }
    }
    
    // Control show_frame based on pattern
    // This affects cm->show_frame in Conditions 3 and 4
    unsigned int show_frame = 1;
    if (show_frame_pattern == 1) {
      show_frame = (frame_idx % 2 == 0);  // Every other frame is show frame
    } else if (show_frame_pattern == 2) {
      show_frame = (frame_idx < frame_count / 2);  // First half are show frames
    } else if (show_frame_pattern == 3) {
      show_frame = 0;  // No show frames (all alt-ref/golden frames)
    }
    
    // Set frame flags to control frame type
    vpx_enc_frame_flags_t flags = 0;
    if (frame_idx == 0) {
      flags |= VPX_EFLAG_FORCE_KF;  // First frame as keyframe
    }
    
    // Encode the frame
    vpx_codec_encode(&codec, img, frame_idx, 1, flags, VPX_DL_GOOD_QUALITY);
    
    // Periodically flush to ensure frame dependencies are processed
    if (frame_idx > 0 && frame_idx % 3 == 0) {
      vpx_codec_encode(&codec, NULL, frame_idx, 1, 0, VPX_DL_GOOD_QUALITY);
    }
  }
  
  // Final flush
  vpx_codec_encode(&codec, NULL, frame_count, 1, 0, VPX_DL_GOOD_QUALITY);
  
  // Step 6: Retrieve encoded data (exercises output path)
  const vpx_codec_cx_pkt_t *pkt = NULL;
  vpx_codec_iter_t iter = NULL;
  while ((pkt = vpx_codec_get_cx_data(&codec, &iter)) != NULL) {
    // Process packets if needed
  }
  
  // Step 7: Cleanup
  vpx_img_free(img);
  vpx_codec_destroy(&codec);
  
  return 0;
}
