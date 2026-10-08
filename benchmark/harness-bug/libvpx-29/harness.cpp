/*
 * Fuzzing harness for libvpx encoder preview frame functionality with enhanced robustness
 * Primary target: vpx_codec_get_preview_frame (0% coverage, 10 undiscovered branches)
 * Secondary targets: vpx_codec_enc_init_ver, vpx_codec_enc_init_multi_ver,
 *                    vpx_codec_enc_config_default, vpx_codec_encode,
 *                    vpx_codec_get_cx_data, vpx_codec_destroy, vpx_img_alloc, vpx_img_free
 * 
 * Follows invocation sequence: default config -> image alloc -> encoder init -> encode
 * -> get cx data -> get preview frame -> destroy -> img free.
 * 
 * Enhanced defensive programming based on previous harness_005 crashes:
 * - Checks encoder initialization success thoroughly
 * - Handles error conditions gracefully with fallbacks
 * - Tries both VP8 and VP9 codecs with proper fallback logic
 * - Implements comprehensive cleanup in all code paths
 * - Validates image allocation before use
 * - Uses safe input consumption patterns
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

#define MIN_INPUT_SIZE 128

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < MIN_INPUT_SIZE) {
    return 0;  // Insufficient input for meaningful testing
  }

  FuzzedDataProvider fdp(data, size);

  // Consume configuration parameters from fuzzer input
  uint8_t codec_choice = fdp.ConsumeIntegral<uint8_t>() % 3;  // 0=VP8, 1=VP9, 2=try both
  bool use_multi_encoder = fdp.ConsumeBool();
  uint8_t num_encoders = 1;
  
  if (use_multi_encoder) {
    num_encoders = fdp.ConsumeIntegralInRange<uint8_t>(1, 2);
  }
  
  // Image dimensions from fuzzer input (must be even for YUV)
  uint16_t width = fdp.ConsumeIntegralInRange<uint16_t>(16, 320) & ~1;
  uint16_t height = fdp.ConsumeIntegralInRange<uint16_t>(16, 240) & ~1;
  if (width < 16) width = 16;
  if (height < 16) height = 16;
  
  // Encoding parameters with safe ranges
  int frame_count = fdp.ConsumeIntegralInRange<int>(1, 3);
  unsigned int target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 1000);
  uint8_t keyframe_interval = fdp.ConsumeIntegralInRange<uint8_t>(0, 5);
  
  // Deadline (encoding speed/quality tradeoff) with safe selection
  vpx_enc_deadline_t deadline = VPX_DL_GOOD_QUALITY;
  uint8_t deadline_choice = fdp.ConsumeIntegral<uint8_t>() % 4;
  switch (deadline_choice) {
    case 0: deadline = VPX_DL_REALTIME; break;
    case 1: deadline = VPX_DL_GOOD_QUALITY; break;
    case 2: deadline = VPX_DL_BEST_QUALITY; break;
    default: deadline = VPX_DL_GOOD_QUALITY; break;
  }

  vpx_codec_err_t res = VPX_CODEC_OK;
  vpx_codec_iface_t *iface = nullptr;
  
  // Choose codec interface with fallback logic
  bool vp8_success = false;
  bool vp9_success = false;
  
  if (codec_choice == 0) {
    // Try VP8 first
    iface = vpx_codec_vp8_cx();
  } else if (codec_choice == 1) {
    // Try VP9 first
    iface = vpx_codec_vp9_cx();
  } else {
    // Try both, starting with VP8
    iface = vpx_codec_vp8_cx();
  }

  if (use_multi_encoder && num_encoders > 1) {
    // Multi-encoder test - only supported for VP8
    // Check if we have VP8 interface, otherwise fall back to single encoder
    if (iface != vpx_codec_vp8_cx()) {
      use_multi_encoder = false;
      num_encoders = 1;
    }
  }

  vpx_codec_ctx_t codec[2];
  vpx_codec_enc_cfg_t cfg[2];
  vpx_rational_t dsf[2];
  vpx_image_t raw[2];
  
  // Initialize arrays
  for (int i = 0; i < num_encoders; i++) {
    memset(&codec[i], 0, sizeof(vpx_codec_ctx_t));
    memset(&cfg[i], 0, sizeof(vpx_codec_enc_cfg_t));
    dsf[i].num = 1;
    dsf[i].den = 1;  // Default 1:1 down-sampling
    memset(&raw[i], 0, sizeof(vpx_image_t));
  }

  // Get default encoder configurations
  for (int i = 0; i < num_encoders; i++) {
    if (vpx_codec_enc_config_default(iface, &cfg[i], 0)) {
      // Failed to get default config - try fallback if we haven't already
      if (codec_choice == 2 && iface == vpx_codec_vp8_cx()) {
        // Try VP9 as fallback
        iface = vpx_codec_vp9_cx();
        if (vpx_codec_enc_config_default(iface, &cfg[i], 0)) {
          // Both failed, give up
          return 0;
        }
      } else {
        return 0;
      }
    }
    
    // Set resolution with down-sampling for subsequent encoders
    if (i == 0) {
      cfg[i].g_w = width;
      cfg[i].g_h = height;
    } else {
      // Down-sample by 2 for second encoder
      cfg[i].g_w = width / 2;
      cfg[i].g_h = height / 2;
      cfg[i].g_w &= ~1;
      cfg[i].g_h &= ~1;
      if (cfg[i].g_w < 16) cfg[i].g_w = 16;
      if (cfg[i].g_h < 16) cfg[i].g_h = 16;
    }
    
    // Set safe configuration values
    cfg[i].g_timebase.num = 1;
    cfg[i].g_timebase.den = 30;
    cfg[i].rc_target_bitrate = target_bitrate;
    cfg[i].g_pass = VPX_RC_ONE_PASS;
    cfg[i].g_lag_in_frames = 0;
    cfg[i].g_error_resilient = fdp.ConsumeBool() ? 1 : 0;
  }
  
  // Initialize encoder(s)
  if (use_multi_encoder && num_encoders > 1) {
    // Initialize multiple encoders using vpx_codec_enc_init_multi_ver
    res = vpx_codec_enc_init_multi_ver(codec, iface, cfg, num_encoders, 0, dsf, 
                                       VPX_ENCODER_ABI_VERSION);
  } else {
    // Initialize single encoder using vpx_codec_enc_init_ver
    res = vpx_codec_enc_init_ver(&codec[0], iface, &cfg[0], 0, VPX_ENCODER_ABI_VERSION);
  }
  
  if (res != VPX_CODEC_OK) {
    // Try fallback codec if we haven't already
    if (codec_choice == 2 && iface == vpx_codec_vp8_cx()) {
      iface = vpx_codec_vp9_cx();
      // Reconfigure with new interface
      for (int i = 0; i < num_encoders; i++) {
        if (vpx_codec_enc_config_default(iface, &cfg[i], 0)) {
          return 0;
        }
      }
      
      if (use_multi_encoder && num_encoders > 1) {
        res = vpx_codec_enc_init_multi_ver(codec, iface, cfg, num_encoders, 0, dsf, 
                                           VPX_ENCODER_ABI_VERSION);
      } else {
        res = vpx_codec_enc_init_ver(&codec[0], iface, &cfg[0], 0, VPX_ENCODER_ABI_VERSION);
      }
      
      if (res != VPX_CODEC_OK) {
        return 0;  // Both codecs failed
      }
    } else {
      return 0;  // Initialization failed with no fallback
    }
  }

  // Allocate image buffers
  bool image_alloc_success = true;
  for (int i = 0; i < num_encoders; i++) {
    vpx_img_fmt_t img_fmt = VPX_IMG_FMT_I420;
    if (!vpx_img_alloc(&raw[i], img_fmt, cfg[i].g_w, cfg[i].g_h, 1)) {
      image_alloc_success = false;
      break;
    }
  }
  
  if (!image_alloc_success) {
    // Cleanup allocated images and encoders
    for (int i = 0; i < num_encoders; i++) {
      if (raw[i].planes[0] != nullptr) {
        vpx_img_free(&raw[i]);
      }
      vpx_codec_destroy(&codec[i]);
    }
    return 0;
  }

  // Encode frames with each encoder
  for (int enc_idx = 0; enc_idx < num_encoders; enc_idx++) {
    // Encode multiple frames with safe bounds
    for (int frame_idx = 0; frame_idx < frame_count && fdp.remaining_bytes() > 0; frame_idx++) {
      // Fill image with fuzzer data safely
      size_t y_plane_size = raw[enc_idx].stride[0] * raw[enc_idx].d_h;
      if (fdp.remaining_bytes() >= y_plane_size && y_plane_size > 0) {
        std::vector<uint8_t> y_data = fdp.ConsumeBytes<uint8_t>(y_plane_size);
        if (y_data.size() == y_plane_size && raw[enc_idx].planes[0] != nullptr) {
          memcpy(raw[enc_idx].planes[0], y_data.data(), y_plane_size);
        }
      } else if (raw[enc_idx].planes[0] != nullptr && y_plane_size > 0) {
        // Not enough data or plane size is 0, use safe default
        memset(raw[enc_idx].planes[0], 0, y_plane_size);
      }
      
      // Set encoding flags
      int flags = 0;
      if (keyframe_interval > 0 && frame_idx % keyframe_interval == 0) {
        flags |= VPX_EFLAG_FORCE_KF;
      }
      
      // Encode the frame
      res = vpx_codec_encode(&codec[enc_idx], &raw[enc_idx], frame_idx, 1, flags, deadline);
      
      if (res == VPX_CODEC_OK) {
        // PRIMARY TARGET: Test preview frame retrieval after encode
        const vpx_image_t *preview = vpx_codec_get_preview_frame(&codec[enc_idx]);
        // Preview may be NULL if no preview is available - that's OK
        
        // Get encoded data
        vpx_codec_iter_t iter = nullptr;
        const vpx_codec_cx_pkt_t *pkt = nullptr;
        while ((pkt = vpx_codec_get_cx_data(&codec[enc_idx], &iter)) != nullptr) {
          // Process packet - just consume to exercise the API
          (void)pkt;
        }
      }
    }
    
    // Flush encoder
    int flush_attempts = 0;
    const int MAX_FLUSH_ATTEMPTS = 10;
    while (flush_attempts < MAX_FLUSH_ATTEMPTS) {
      res = vpx_codec_encode(&codec[enc_idx], nullptr, -1, 1, 0, deadline);
      if (res != VPX_CODEC_OK) {
        break;
      }
      
      vpx_codec_iter_t iter = nullptr;
      const vpx_codec_cx_pkt_t *pkt = nullptr;
      while ((pkt = vpx_codec_get_cx_data(&codec[enc_idx], &iter)) != nullptr) {
        (void)pkt;
      }
      flush_attempts++;
    }
    
    // Test preview frame after flush
    const vpx_image_t *preview_after_flush = vpx_codec_get_preview_frame(&codec[enc_idx]);
    // Preview may be NULL - that's OK
  }

  // Cleanup in reverse order of initialization
  for (int i = 0; i < num_encoders; i++) {
    if (raw[i].planes[0] != nullptr) {
      vpx_img_free(&raw[i]);
    }
  }
  
  for (int i = 0; i < num_encoders; i++) {
    vpx_codec_destroy(&codec[i]);
  }

  return 0;
}
