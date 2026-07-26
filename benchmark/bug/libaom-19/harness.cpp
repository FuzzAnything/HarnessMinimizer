/*
 * Fuzzing harness for libaom AV1 encoder
 * Targets main encoder API entry points with semantic diversity from decoder harness
 * Focuses on encoder module which has 0% API coverage (51+ undiscovered branches)
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
#include <memory>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

#include "aom/aom_encoder.h"
#include "aom/aomcx.h"
#include "aom/aom_image.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Minimum size needed for meaningful testing
  // Need enough for: config params + image dimensions + some image data
  const size_t MIN_SIZE = sizeof(int) * 4 + sizeof(unsigned int) * 2 + 16;
  if (size < MIN_SIZE) {
    return 0;
  }

  FuzzedDataProvider fdp(data, size);

  // Get encoder interface for AV1
  aom_codec_iface_t *codec_interface = aom_codec_av1_cx();
  if (!codec_interface) {
    return 0;
  }

  // Consume configuration parameters from fuzzer input
  unsigned int usage = fdp.ConsumeIntegralInRange<unsigned int>(0, 2); // 0: GOOD_QUALITY, 1: REALTIME, 2: ALL_INTRA
  int width = fdp.ConsumeIntegralInRange<int>(1, 512);  // Reasonable max for fuzzing
  int height = fdp.ConsumeIntegralInRange<int>(1, 512);
  
  // Ensure even dimensions for YUV420 format
  if (width % 2 != 0) width -= 1;
  if (height % 2 != 0) height -= 1;
  if (width < 1 || height < 1) {
    return 0;
  }

  // Get default encoder configuration
  aom_codec_enc_cfg_t cfg;
  aom_codec_err_t res = aom_codec_enc_config_default(codec_interface, &cfg, usage);
  if (res != AOM_CODEC_OK) {
    return 0;
  }

  // Update configuration with fuzzed parameters
  cfg.g_w = width;
  cfg.g_h = height;
  cfg.g_timebase.num = 1;
  cfg.g_timebase.den = fdp.ConsumeIntegralInRange<unsigned int>(1, 120);
  cfg.rc_target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 10000);
  cfg.g_error_resilient = fdp.ConsumeBool() ? AOM_ERROR_RESILIENT_DEFAULT : 0;
  cfg.g_pass = fdp.ConsumeBool() ? AOM_RC_ONE_PASS : AOM_RC_FIRST_PASS;
  cfg.g_lag_in_frames = fdp.ConsumeIntegralInRange<unsigned int>(0, 25);

  // Initialize encoder context
  aom_codec_ctx_t codec;
  aom_codec_flags_t flags = 0;
  if (fdp.ConsumeBool()) {
    flags |= AOM_CODEC_USE_HIGHBITDEPTH;
  }
  
  res = aom_codec_enc_init(&codec, codec_interface, &cfg, flags);
  if (res != AOM_CODEC_OK) {
    return 0;
  }

  // Set encoder control parameters from fuzzer input
  int cpu_used = fdp.ConsumeIntegralInRange<int>(-16, 16);
  aom_codec_control(&codec, AOME_SET_CPUUSED, cpu_used);
  
  int enable_auto_alt_ref = fdp.ConsumeBool() ? 1 : 0;
  aom_codec_control(&codec, AOME_SET_ENABLEAUTOALTREF, enable_auto_alt_ref);
  
  int sharpness = fdp.ConsumeIntegralInRange<int>(0, 7);
  aom_codec_control(&codec, AOME_SET_SHARPNESS, sharpness);
  
  int static_thresh = fdp.ConsumeIntegralInRange<int>(0, 1000);
  aom_codec_control(&codec, AOME_SET_STATIC_THRESHOLD, static_thresh);
  
  int noise_sensitivity = fdp.ConsumeBool() ? 1 : 0;
  aom_codec_control(&codec, AV1E_SET_NOISE_SENSITIVITY, noise_sensitivity);
  // Allocate image buffer for input frame
  aom_image_t raw;
  aom_img_fmt_t fmt = AOM_IMG_FMT_I420;
  if (flags & AOM_CODEC_USE_HIGHBITDEPTH) {
    fmt = AOM_IMG_FMT_I42016;
  }
  
  if (!aom_img_alloc(&raw, fmt, width, height, 1)) {
    aom_codec_destroy(&codec);
    return 0;
  }

  // Fill image planes with fuzzer data
  // For I420 format: Y plane = width*height, U/V planes = (width/2)*(height/2)
  size_t y_plane_size = width * height;
  size_t uv_plane_size = (width / 2) * (height / 2);
  
  // Check if we have enough data for image planes
  if (fdp.remaining_bytes() < y_plane_size + uv_plane_size * 2) {
    aom_img_free(&raw);
    aom_codec_destroy(&codec);
    return 0;
  }

  // Fill Y plane
  std::vector<uint8_t> y_plane = fdp.ConsumeBytes<uint8_t>(y_plane_size);
  if (y_plane.size() < y_plane_size) {
    aom_img_free(&raw);
    aom_codec_destroy(&codec);
    return 0;
  }
  
  // Fill U plane
  std::vector<uint8_t> u_plane = fdp.ConsumeBytes<uint8_t>(uv_plane_size);
  if (u_plane.size() < uv_plane_size) {
    aom_img_free(&raw);
    aom_codec_destroy(&codec);
    return 0;
  }
  
  // Fill V plane
  std::vector<uint8_t> v_plane = fdp.ConsumeBytes<uint8_t>(uv_plane_size);
  if (v_plane.size() < uv_plane_size) {
    aom_img_free(&raw);
    aom_codec_destroy(&codec);
    return 0;
  }

  // Copy data to image planes
  for (size_t i = 0; i < y_plane_size; ++i) {
    raw.planes[0][i] = y_plane[i];
  }
  for (size_t i = 0; i < uv_plane_size; ++i) {
    raw.planes[1][i] = u_plane[i];
    raw.planes[2][i] = v_plane[i];
  }

  // Set up encoding flags
  aom_enc_frame_flags_t encode_flags = 0;
  if (fdp.ConsumeBool()) {
    encode_flags |= AOM_EFLAG_FORCE_KF;
  }
  if (fdp.ConsumeBool()) {
    encode_flags |= AOM_EFLAG_NO_REF_LAST;
  }
  if (fdp.ConsumeBool()) {
    encode_flags |= AOM_EFLAG_NO_REF_LAST2;
  }
  if (fdp.ConsumeBool()) {
    encode_flags |= AOM_EFLAG_NO_REF_LAST3;
  }
  if (fdp.ConsumeBool()) {
    encode_flags |= AOM_EFLAG_NO_REF_GF;
  }
  if (fdp.ConsumeBool()) {
    encode_flags |= AOM_EFLAG_NO_REF_ARF;
  }

  // Encode the frame
  int frame_index = 0;
  unsigned long duration = 1; // Show frame for 1 timebase unit
  res = aom_codec_encode(&codec, &raw, frame_index, duration, encode_flags);
  // We don't check the result since invalid inputs are expected in fuzzing

  // Try to get encoded data (even if encoding failed)
  aom_codec_iter_t iter = nullptr;
  const aom_codec_cx_pkt_t *pkt = nullptr;
  while ((pkt = aom_codec_get_cx_data(&codec, &iter)) != nullptr) {
    // Process different packet types
    switch (pkt->kind) {
      case AOM_CODEC_CX_FRAME_PKT:
        // Compressed frame data - we could process it here
        // For fuzzing, we just want to exercise the API
        break;
      case AOM_CODEC_STATS_PKT:
        // Two-pass statistics
        break;
      default:
        // Other packet types
        break;
    }
  }

  // Try to encode a few more frames with remaining fuzzer data
  // This exercises multi-frame encoding scenarios
  int max_additional_frames = fdp.ConsumeIntegralInRange<int>(0, 3);
  for (int i = 0; i < max_additional_frames && fdp.remaining_bytes() > 0; ++i) {
    // Use remaining data for additional frames
    size_t frame_data_size = std::min(fdp.remaining_bytes(), y_plane_size + uv_plane_size * 2);
    if (frame_data_size == 0) break;
    
    // Fill planes with whatever data remains
    std::vector<uint8_t> frame_data = fdp.ConsumeBytes<uint8_t>(frame_data_size);
    
    // Update image with new data (simplified - just overwrite with new pattern)
    for (size_t j = 0; j < std::min(y_plane_size, frame_data.size()); ++j) {
      raw.planes[0][j] = frame_data[j % frame_data.size()];
    }
    
    // Encode with new flags
    aom_enc_frame_flags_t additional_flags = 0;
    if (fdp.ConsumeBool()) {
      additional_flags |= AOM_EFLAG_FORCE_KF;
    }
    
    res = aom_codec_encode(&codec, &raw, ++frame_index, duration, additional_flags);
    
    // Get encoded data
    iter = nullptr;
    while ((pkt = aom_codec_get_cx_data(&codec, &iter)) != nullptr) {
      // Just iterate through packets to exercise the API
    }
  }

  // Cleanup
  aom_img_free(&raw);
  aom_codec_destroy(&codec);
  
  return 0;
}
