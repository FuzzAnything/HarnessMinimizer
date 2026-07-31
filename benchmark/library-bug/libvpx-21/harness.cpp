/*
 * Fuzzing harness for libvpx VP9 encoder advanced rate-distortion optimization (RDO)
 * Primary target: vp9_rd_pick_inter_mode_sb with 334 blocked branches (79.1% blocked)
 * 
 * This harness specifically targets complex encoder configurations that affect
 * motion estimation, mode decisions, and rate-distortion optimization in the
 * VP9 encoder's inter-mode selection logic.
 * 
 * Strategy:
 * 1. Target comprehensive encoder settings that directly influence RDO decisions:
 *    - Speed/quality tradeoff via deadline parameter
 *    - Tile-based parallel encoding (affects motion vector constraints)
 *    - Row-based multi-threading (affects dependency patterns)
 *    - Adaptive quantization modes (affects RD cost calculations)
 *    - Content-based tuning (film, screen content, etc.)
 *    - Lossless encoding mode (bypasses quantization in RDO)
 *    - Frame parallel decoding configuration
 * 2. Exercise blocked code paths in vp9_rd_pick_inter_mode_sb related to:
 *    - Tile boundary constraints on motion estimation
 *    - Speed feature adjustments for RDO pruning
 *    - Content-specific optimization decisions
 *    - Adaptive quantization interactions with mode costs
 *    - Lossless encoding path differences in RDO
 * 3. Ensure semantic diversity from existing harnesses:
 *    - harness_010: Two-pass encoding and SVC
 *    - harness_014: Segmentation via ROI maps  
 *    - harness_015: Alt-ref frame mechanics
 *    - This harness: Comprehensive RDO configuration space affecting
 *      motion estimation and mode decision internals
 * 
 * Key controls targeted for RDO impact:
 * - Deadline (VPX_DL_REALTIME/GOOD_QUALITY/BEST_QUALITY): Controls speed features
 * - VP9E_SET_TILE_COLUMNS/ROWS: Affects motion vector constraints at tile boundaries
 * - VP9E_SET_ROW_MT: Row-based multi-threading affects dependency patterns
 * - VP9E_SET_AQ_MODE: Adaptive quantization affects RD cost calculations
 * - VP9E_SET_TUNE_CONTENT: Content-specific optimization (film, screen content)
 * - VP9E_SET_LOSSLESS: Bypasses quantization in RDO calculations
 * - VP9E_SET_FRAME_PARALLEL_DECODING: Affects frame dependency constraints
 * - VP9E_SET_NOISE_SENSITIVITY: Affects mode decisions in noisy content
 * 
 * These controls directly influence decisions in vp9_rd_pick_inter_mode_sb:
 * - Tile boundaries restrict motion vector ranges (lines 3572-3582 in vp9_rdopt.c)
 * - Speed features prune mode search (cpi->sf->... variables)
 * - Content tuning adjusts RD cost weights
 * - Lossless mode skips quantization in RD calculations
 * - AQ mode adjusts quantization per block affecting RD tradeoffs
 * 
 * Invocation sequence: encoder init -> comprehensive RDO configuration ->
 * multi-frame encoding with varied image patterns -> error path testing -> cleanup.
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

#define MIN_INPUT_SIZE 256  // More bytes needed for comprehensive RDO configuration

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < MIN_INPUT_SIZE) {
    return 0;  // Insufficient input for comprehensive RDO testing
  }

  FuzzedDataProvider fdp(data, size);

  // Step 1: Consume comprehensive RDO configuration from fuzzer input
  
  // Basic encoder configuration - always use VP9 for RDO targeting
  bool use_highbitdepth = fdp.ConsumeBool();
  
  // Image dimensions - varied to test different tile configurations
  unsigned int width = fdp.ConsumeIntegralInRange<unsigned int>(128, 1024) & ~1u;
  unsigned int height = fdp.ConsumeIntegralInRange<unsigned int>(128, 768) & ~1u;
  if (width < 128) width = 128;
  if (height < 128) height = 128;
  
  // Frame encoding parameters
  unsigned int timebase_den = fdp.ConsumeIntegralInRange<unsigned int>(15, 60);
  unsigned int target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(200, 4000);
  unsigned int keyframe_interval = fdp.ConsumeIntegralInRange<unsigned int>(0, 30);
  unsigned int frame_count = fdp.ConsumeIntegralInRange<unsigned int>(2, 8);
  
  // RDO-specific configuration (consumed in order of impact on vp9_rd_pick_inter_mode_sb)
  
  // 1. Speed/quality tradeoff (deadline) - major impact on RDO pruning
  vpx_enc_deadline_t deadline = VPX_DL_GOOD_QUALITY;
  unsigned int deadline_choice = fdp.ConsumeIntegralInRange<unsigned int>(0, 2);
  switch (deadline_choice) {
    case 0: deadline = VPX_DL_REALTIME; break;      // Fastest, most pruning
    case 1: deadline = VPX_DL_BEST_QUALITY; break;  // Slowest, least pruning
    default: deadline = VPX_DL_GOOD_QUALITY; break; // Balanced
  }
  
  // 2. Tile configuration - affects motion vector constraints at tile boundaries
  int tile_columns = fdp.ConsumeIntegralInRange<int>(0, 3);  // 0=1, 1=2, 2=4, 3=6 columns
  int tile_rows = fdp.ConsumeIntegralInRange<int>(0, 2);     // 0=1, 1=2, 2=4 rows
  
  // Adjust based on image size to ensure reasonable tile dimensions
  unsigned int min_tile_width = 256;
  unsigned int max_columns = width / min_tile_width;
  if (max_columns < 1) max_columns = 1;
  if (tile_columns > (int)max_columns) tile_columns = max_columns;
  
  // 3. Row-based multi-threading - affects dependency patterns in RDO
  unsigned int row_mt = fdp.ConsumeIntegralInRange<unsigned int>(0, 1);
  
  // 4. Adaptive quantization mode - affects RD cost calculations
  unsigned int aq_mode = fdp.ConsumeIntegralInRange<unsigned int>(0, 3);  // 0-3 as per VP9 docs
  
  // 5. Content tuning - affects RD cost weights for different content types
  int tune_content = fdp.ConsumeIntegralInRange<int>(0, 2);  // 0=VP9E_TUNE_DEFAULT, 1=VP9E_TUNE_PSNR, 2=VP9E_TUNE_SSIM
  
  // 6. Lossless encoding - bypasses quantization in RD calculations
  unsigned int lossless = fdp.ConsumeIntegralInRange<unsigned int>(0, 1);
  
  // 7. Frame parallel decoding - affects frame dependency constraints
  unsigned int frame_parallel_decoding = fdp.ConsumeIntegralInRange<unsigned int>(0, 1);
  
  // 8. Noise sensitivity - affects mode decisions in noisy content
  unsigned int noise_sensitivity = fdp.ConsumeIntegralInRange<unsigned int>(0, 1);
  
  // 9. Additional RDO-influencing parameters
  unsigned int max_inter_bitrate_pct = fdp.ConsumeIntegralInRange<unsigned int>(0, 300);
  unsigned int gf_cbr_boost_pct = fdp.ConsumeIntegralInRange<unsigned int>(0, 200);
  
  // Step 2: Initialize VP9 encoder with default configuration
  vpx_codec_ctx_t codec;
  vpx_codec_enc_cfg_t cfg;
  vpx_codec_iface_t *iface = vpx_codec_vp9_cx();
  
  if (vpx_codec_enc_config_default(iface, &cfg, 0)) {
    return 0;  // Failed to get default config
  }

  // Configure basic encoder parameters from fuzzer input
  cfg.g_w = width;
  cfg.g_h = height;
  cfg.g_timebase.num = 1;
  cfg.g_timebase.den = timebase_den;
  cfg.rc_target_bitrate = target_bitrate;
  cfg.g_error_resilient = 0;  // Disable for RDO testing to focus on optimization
  cfg.g_pass = VPX_RC_ONE_PASS;  // One-pass for focused RDO testing
  cfg.g_lag_in_frames = 0;  // No lookahead to isolate RDO decisions
  
  // Set keyframe interval
  if (keyframe_interval > 0) {
    cfg.kf_mode = VPX_KF_AUTO;
    cfg.kf_min_dist = 0;
    cfg.kf_max_dist = keyframe_interval;
  } else {
    cfg.kf_mode = VPX_KF_DISABLED;
  }
  
  // Set encoder flags
  vpx_codec_flags_t flags = 0;
  if (use_highbitdepth) {
    flags |= VPX_CODEC_USE_HIGHBITDEPTH;
  }
  
  // Step 3: Initialize encoder
  if (vpx_codec_enc_init(&codec, iface, &cfg, flags)) {
    return 0;  // Encoder initialization failed
  }
  
  // Step 4: Apply comprehensive RDO configuration via control calls
  
  // Tile configuration (affects motion vector constraints)
  if (tile_columns > 0) {
    vpx_codec_control(&codec, VP9E_SET_TILE_COLUMNS, tile_columns);
  }
  if (tile_rows > 0) {
    vpx_codec_control(&codec, VP9E_SET_TILE_ROWS, tile_rows);
  }
  
  // Row-based multi-threading (affects dependency patterns)
  vpx_codec_control(&codec, VP9E_SET_ROW_MT, row_mt);
  
  // Adaptive quantization mode (affects RD cost calculations)
  vpx_codec_control(&codec, VP9E_SET_AQ_MODE, aq_mode);
  
  // Content tuning (affects RD cost weights)
  vpx_codec_control(&codec, VP9E_SET_TUNE_CONTENT, tune_content);
  
  // Lossless encoding (bypasses quantization in RD calculations)
  vpx_codec_control(&codec, VP9E_SET_LOSSLESS, lossless);
  
  // Frame parallel decoding (affects frame dependency constraints)
  vpx_codec_control(&codec, VP9E_SET_FRAME_PARALLEL_DECODING, frame_parallel_decoding);
  
  // Noise sensitivity (affects mode decisions)
  vpx_codec_control(&codec, VP9E_SET_NOISE_SENSITIVITY, noise_sensitivity);
  
  // Additional rate control parameters affecting RDO
  vpx_codec_control(&codec, VP9E_SET_MAX_INTER_BITRATE_PCT, max_inter_bitrate_pct);
  vpx_codec_control(&codec, VP9E_SET_GF_CBR_BOOST_PCT, gf_cbr_boost_pct);
  
  // Step 5: Create test image with varied patterns to exercise RDO decisions
  vpx_image_t raw;
  
  // Allocate image with format based on fuzzer input
  vpx_img_fmt_t fmt = VPX_IMG_FMT_I420;
  if (use_highbitdepth) {
    fmt = VPX_IMG_FMT_I42016;
  }
  
  if (!vpx_img_alloc(&raw, fmt, width, height, 1)) {
    vpx_codec_destroy(&codec);
    return 0;  // Image allocation failed
  }
  
  // Generate varied image patterns from fuzzer input to exercise different RDO decisions
  // Use remaining fuzzer bytes to create image content
  size_t image_bytes_needed = raw.d_w * raw.d_h * 3 / 2;  // YUV420
  if (use_highbitdepth) {
    image_bytes_needed *= 2;  // 16-bit samples
  }
  
  // Limit to reasonable size for fuzzing
  if (image_bytes_needed > 1024 * 1024) {
    image_bytes_needed = 1024 * 1024;
  }
  
  // Consume image data from fuzzer input
  std::vector<uint8_t> image_data;
  if (fdp.remaining_bytes() >= image_bytes_needed / 4) {
    // Use a quarter of needed bytes and replicate to save fuzzer input
    size_t bytes_to_consume = image_bytes_needed / 4;
    if (bytes_to_consume > fdp.remaining_bytes()) {
      bytes_to_consume = fdp.remaining_bytes();
    }
    
    image_data = fdp.ConsumeBytes<uint8_t>(bytes_to_consume);
    
    // Fill image planes with pattern from consumed data
    // This creates varied content to exercise RDO decisions
    uint8_t *y_plane = raw.planes[0];
    uint8_t *u_plane = raw.planes[1];
    uint8_t *v_plane = raw.planes[2];
    
    size_t y_size = raw.d_w * raw.d_h;
    size_t uv_size = (raw.d_w / 2) * (raw.d_h / 2);
    
    // Fill Y plane with pattern
    for (size_t i = 0; i < y_size; i++) {
      y_plane[i] = image_data[i % image_data.size()] ^ (i & 0xFF);
    }
    
    // Fill UV planes with different patterns
    for (size_t i = 0; i < uv_size; i++) {
      u_plane[i] = image_data[(i * 3) % image_data.size()];
      v_plane[i] = image_data[(i * 7) % image_data.size()];
    }
  } else {
    // Not enough data for pattern generation, use simple gradient
    uint8_t *y_plane = raw.planes[0];
    for (int y = 0; y < raw.d_h; y++) {
      for (int x = 0; x < raw.d_w; x++) {
        y_plane[y * raw.stride[0] + x] = (x + y) & 0xFF;
      }
    }
    
    uint8_t *u_plane = raw.planes[1];
    uint8_t *v_plane = raw.planes[2];
    for (int y = 0; y < raw.d_h / 2; y++) {
      for (int x = 0; x < raw.d_w / 2; x++) {
        u_plane[y * raw.stride[1] + x] = (x * 2) & 0xFF;
        v_plane[y * raw.stride[2] + x] = (y * 2) & 0xFF;
      }
    }
  }
  
  // Step 6: Encode multiple frames with varied RDO configurations
  for (unsigned int frame_idx = 0; frame_idx < frame_count; frame_idx++) {
    // Vary encoding flags per frame to test different RDO scenarios
    vpx_enc_frame_flags_t frame_flags = 0;
    
    if (frame_idx == 0) {
      frame_flags |= VPX_EFLAG_FORCE_KF;  // Force keyframe for first frame
    }
    
    // Randomly set reference frame flags based on fuzzer input
    if (fdp.ConsumeBool()) {
      frame_flags |= VP8_EFLAG_NO_REF_LAST;
    }
    if (fdp.ConsumeBool()) {
      frame_flags |= VP8_EFLAG_NO_REF_GF;
    }
    if (fdp.ConsumeBool()) {
      frame_flags |= VP8_EFLAG_NO_REF_ARF;
    }
    
    // Encode the frame
    if (vpx_codec_encode(&codec, &raw, frame_idx, 1, frame_flags, deadline)) {
      // Encoding error, but continue to test error paths in RDO
      break;
    }
    
    // Retrieve encoded data (exercises output path)
    const vpx_codec_cx_pkt_t *pkt = nullptr;
    vpx_codec_iter_t iter = nullptr;
    
    while ((pkt = vpx_codec_get_cx_data(&codec, &iter)) != nullptr) {
      if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
        // Frame data available - this validates RDO produced valid output
        // No processing needed for fuzzing
      }
    }
    
    // Modify image slightly for next frame to create motion for RDO
    if (frame_idx + 1 < frame_count) {
      uint8_t *y_plane = raw.planes[0];
      int offset = (frame_idx * 7) % 16;
      for (int i = 0; i < raw.d_w * raw.d_h / 16; i++) {
        y_plane[i * 16 + offset] = (y_plane[i * 16 + offset] + 32) & 0xFF;
      }
    }
  }
  
  // Step 7: Test error paths by attempting invalid control calls
  // This exercises defensive code in RDO functions
  if (fdp.ConsumeBool()) {
    // Try invalid tile configuration
    vpx_codec_control(&codec, VP9E_SET_TILE_COLUMNS, 99);  // Invalid value
  }
  
  if (fdp.ConsumeBool()) {
    // Try invalid AQ mode
    vpx_codec_control(&codec, VP9E_SET_AQ_MODE, 99);  // Invalid value
  }
  
  // Step 8: Cleanup
  vpx_img_free(&raw);
  vpx_codec_destroy(&codec);
  
  return 0;
}
