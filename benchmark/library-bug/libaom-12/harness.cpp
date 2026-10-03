/*
 * Fuzzing harness for libaom AV1 encoder initialization and configuration testing
 * Targets critical encoder control functions with 0% coverage as identified in guidance
 * Primary focus: aom_codec_enc_init_ver, AV1E_SET_ENABLE_CDEF, AV1E_SET_ENABLE_WARPED_MOTION, 
 *                AV1E_SET_ENABLE_RESTORATION, aom_codec_encode, aom_codec_destroy
 * Semantic diversity: Focuses on specific AV1 coding tools not tested in existing harnesses
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
  // Need enough for: config params + image dimensions + control values
  const size_t MIN_SIZE = sizeof(int) * 4 + sizeof(unsigned int) * 3 + 16;
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
  int width = fdp.ConsumeIntegralInRange<int>(16, 256);  // Reasonable range for fuzzing
  int height = fdp.ConsumeIntegralInRange<int>(16, 256);
  
  // Ensure even dimensions for YUV420 format
  if (width % 2 != 0) width -= 1;
  if (height % 2 != 0) height -= 1;
  if (width < 16 || height < 16) {
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

  // Initialize encoder context using aom_codec_enc_init_ver
  aom_codec_ctx_t codec;
  aom_codec_flags_t flags = 0;
  if (fdp.ConsumeBool()) {
    flags |= AOM_CODEC_USE_HIGHBITDEPTH;
  }
  
  // Use aom_codec_enc_init_ver directly as specified in guidance
  res = aom_codec_enc_init_ver(&codec, codec_interface, &cfg, flags, AOM_ENCODER_ABI_VERSION);
  if (res != AOM_CODEC_OK) {
    return 0;
  }

  // Set basic encoder control parameters from fuzzer input
  int cpu_used = fdp.ConsumeIntegralInRange<int>(-16, 16);
  aom_codec_control(&codec, AOME_SET_CPUUSED, cpu_used);
  
  // Target specific AV1 encoder control functions identified in guidance
  // These have 0% coverage according to the analysis
  
  // 1. AV1E_SET_ENABLE_CDEF - Constrained Directional Enhancement Filter
  unsigned int enable_cdef = fdp.ConsumeBool() ? 1 : 0;
  aom_codec_control(&codec, AV1E_SET_ENABLE_CDEF, enable_cdef);
  
  // 2. AV1E_SET_ENABLE_WARPED_MOTION - Warped motion compensation
  int enable_warped_motion = fdp.ConsumeBool() ? 1 : 0;
  aom_codec_control(&codec, AV1E_SET_ENABLE_WARPED_MOTION, enable_warped_motion);
  
  // 3. AV1E_SET_ENABLE_RESTORATION - Loop restoration filter
  int enable_restoration = fdp.ConsumeBool() ? 1 : 0;
  aom_codec_control(&codec, AV1E_SET_ENABLE_RESTORATION, enable_restoration);
  
  // Additional alternative control functions from guidance if available
  // Try to set them if there's enough input remaining
  if (fdp.remaining_bytes() > 3) {
    // AV1E_SET_ENABLE_OBMC - Overlapped Block Motion Compensation
    int enable_obmc = fdp.ConsumeBool() ? 1 : 0;
    aom_codec_control(&codec, AV1E_SET_ENABLE_OBMC, enable_obmc);
    
    // AV1E_SET_ENABLE_CFL_INTRA - Chroma from Luma
    int enable_cfl_intra = fdp.ConsumeBool() ? 1 : 0;
    aom_codec_control(&codec, AV1E_SET_ENABLE_CFL_INTRA, enable_cfl_intra);
    
    // AV1E_SET_ENABLE_PAETH_INTRA - Paeth intra prediction
    int enable_paeth_intra = fdp.ConsumeBool() ? 1 : 0;
    aom_codec_control(&codec, AV1E_SET_ENABLE_PAETH_INTRA, enable_paeth_intra);
  }

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

  // Fill image plane with fuzzed data
  // Use remaining fuzzer input for image data
  size_t y_plane_size = width * height;
  size_t uv_plane_size = (width / 2) * (height / 2);
  size_t total_image_size = y_plane_size + 2 * uv_plane_size;
  
  if (fmt == AOM_IMG_FMT_I42016) {
    total_image_size *= 2; // 16-bit samples
  }
  
  // Check if we have enough data for at least partial image fill
  if (fdp.remaining_bytes() > 0) {
    // Fill Y plane
    size_t y_bytes_to_fill = std::min(y_plane_size, fdp.remaining_bytes());
    if (y_bytes_to_fill > 0) {
      std::vector<uint8_t> y_data = fdp.ConsumeBytes<uint8_t>(y_bytes_to_fill);
      memcpy(raw.planes[0], y_data.data(), y_data.size());
    }
    
    // Fill U plane if we have more data
    if (fdp.remaining_bytes() > 0) {
      size_t u_bytes_to_fill = std::min(uv_plane_size, fdp.remaining_bytes());
      if (u_bytes_to_fill > 0) {
        std::vector<uint8_t> u_data = fdp.ConsumeBytes<uint8_t>(u_bytes_to_fill);
        memcpy(raw.planes[1], u_data.data(), u_data.size());
      }
    }
    
    // Fill V plane if we have more data
    if (fdp.remaining_bytes() > 0) {
      size_t v_bytes_to_fill = std::min(uv_plane_size, fdp.remaining_bytes());
      if (v_bytes_to_fill > 0) {
        std::vector<uint8_t> v_data = fdp.ConsumeBytes<uint8_t>(v_bytes_to_fill);
        memcpy(raw.planes[2], v_data.data(), v_data.size());
      }
    }
  }

  // Encode the frame using aom_codec_encode
  // Use remaining fuzzer input for encode flags and deadline
  uint32_t encode_flags = 0;
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
  
  long deadline = fdp.ConsumeIntegralInRange<long>(1, 1000000); // Microseconds
  
  res = aom_codec_encode(&codec, &raw, 0, 1, encode_flags);
  // Don't check result - allow failures to test error paths
  
  // Try to encode a second frame with different parameters if we have data
  if (fdp.remaining_bytes() > 0) {
    // Modify some image data for second frame
    if (width > 0 && height > 0 && raw.planes[0]) {
      // Just modify a few pixels
      size_t pixel_count = std::min((size_t)10, y_plane_size);
      for (size_t i = 0; i < pixel_count && fdp.remaining_bytes() > 0; i++) {
        uint8_t pixel_val = fdp.ConsumeIntegral<uint8_t>();
        ((uint8_t*)raw.planes[0])[i % y_plane_size] = pixel_val;
      }
    }
    
    // Different encode flags for second frame
    encode_flags = 0;
    if (fdp.ConsumeBool()) {
      encode_flags |= AOM_EFLAG_NO_REF_ARF;
    }
    if (fdp.ConsumeBool()) {
      encode_flags |= AOM_EFLAG_NO_UPD_GF;
    }
    
    deadline = fdp.ConsumeIntegralInRange<long>(1, 1000000);
    res = aom_codec_encode(&codec, NULL, 1, 1, encode_flags);
  }

  // Try to get encoded data
  const aom_codec_cx_pkt_t *pkt = NULL;
  aom_codec_iter_t iter = NULL;
  while ((pkt = aom_codec_get_cx_data(&codec, &iter)) != NULL) {
    // Process packet if needed
    // For fuzzing purposes, just consuming is enough
  }

  // Clean up
  aom_img_free(&raw);
  aom_codec_destroy(&codec);
  
  return 0;
}
