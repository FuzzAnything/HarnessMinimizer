/*
 * Fuzzing harness for libvpx VP8 multi-encoder initialization and configuration
 * Targets: vpx_codec_enc_init_multi_ver (54 undiscovered branches), 
 *          vpx_codec_enc_config_set (12 undiscovered branches),
 *          vpx_codec_vp8_cx interface (0 hits)
 * 
 * This harness specifically targets the severely undertested VP8 module 
 * (0.57% line coverage vs VP9's 31.26%) by focusing on multi-encoder 
 * initialization and configuration APIs.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>
#include "vpx/vp8cx.h"
#include "vpx/vpx_encoder.h"
#include "vpx/vpx_image.h"

#define MAX_ENCODERS 3
#define MIN_INPUT_SIZE 64

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < MIN_INPUT_SIZE) {
    return 0;  // Insufficient input for meaningful testing
  }

  FuzzedDataProvider fdp(data, size);

  // Consume configuration parameters from fuzzer input
  uint8_t num_encoders = fdp.ConsumeIntegralInRange<uint8_t>(1, MAX_ENCODERS);
  bool use_highbitdepth = fdp.ConsumeBool();
  bool use_psnr = fdp.ConsumeBool();
  
  // Arrays for multi-encoder configuration
  vpx_codec_ctx_t codec[MAX_ENCODERS];
  vpx_codec_enc_cfg_t cfg[MAX_ENCODERS];
  vpx_rational_t dsf[MAX_ENCODERS];  // Down-sampling factors
  vpx_image_t raw[MAX_ENCODERS];
  
  // Initialize arrays
  for (int i = 0; i < MAX_ENCODERS; i++) {
    codec[i] = {};
    cfg[i] = {};
    dsf[i] = {1, 1};  // Default 1:1 down-sampling
    raw[i] = {};
  }

  // Choose VP8 encoder interface (targeting VP8 specifically)
  vpx_codec_iface_t *iface = vpx_codec_vp8_cx();
  
  // Get default encoder configurations
  for (int i = 0; i < num_encoders; i++) {
    if (vpx_codec_enc_config_default(iface, &cfg[i], 0)) {
      return 0;  // Failed to get default config
    }
    
    // Consume resolution from fuzzer input (avoid hardcoded values)
    // Ensure width and height are reasonable and multiples of 2 for YUV420
    if (fdp.remaining_bytes() >= 2 * sizeof(uint16_t)) {
      uint16_t base_width = fdp.ConsumeIntegralInRange<uint16_t>(16, 1920);
      uint16_t base_height = fdp.ConsumeIntegralInRange<uint16_t>(16, 1080);
      
      // Ensure even dimensions for YUV420
      cfg[i].g_w = base_width & ~1;  // Make even
      cfg[i].g_h = base_height & ~1; // Make even
      
      // Ensure minimum size
      if (cfg[i].g_w < 16) cfg[i].g_w = 16;
      if (cfg[i].g_h < 16) cfg[i].g_h = 16;
    } else {
      // Not enough input for resolution, use small defaults
      cfg[i].g_w = 64;
      cfg[i].g_h = 48;
    }
    
    // Reduce size for subsequent encoders (multi-resolution scenario)
    if (i > 0) {
      cfg[i].g_w = cfg[i-1].g_w / 2;
      cfg[i].g_h = cfg[i-1].g_h / 2;
      // Ensure minimum size and even dimensions
      if (cfg[i].g_w < 16) cfg[i].g_w = 16;
      if (cfg[i].g_h < 16) cfg[i].g_h = 16;
      cfg[i].g_w &= ~1;
      cfg[i].g_h &= ~1;
      
      // Set down-sampling factor for this encoder
      dsf[i].num = 1;
      dsf[i].den = 2;  // Half size
    }
    
    // Set basic encoder parameters from fuzzer input
    cfg[i].g_timebase.num = 1;
    cfg[i].g_timebase.den = fdp.ConsumeIntegralInRange<unsigned int>(1, 120);  // 1-120 fps
    cfg[i].rc_target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(50, 4000);
    cfg[i].g_error_resilient = fdp.ConsumeBool() ? 1 : 0;
    cfg[i].g_pass = VPX_RC_ONE_PASS;
    cfg[i].g_lag_in_frames = fdp.ConsumeIntegralInRange<unsigned int>(0, 25);
    cfg[i].g_threads = fdp.ConsumeIntegralInRange<unsigned int>(1, 8);
  }

  // Set encoder flags
  vpx_codec_flags_t flags = 0;
  if (use_highbitdepth) {
    flags |= VPX_CODEC_USE_HIGHBITDEPTH;
  }
  if (use_psnr) {
    flags |= VPX_CODEC_USE_PSNR;
  }

  // Initialize multi-encoder using vpx_codec_enc_init_multi_ver
  // Note: We use the convenience macro vpx_codec_enc_init_multi which calls vpx_codec_enc_init_multi_ver
  vpx_codec_err_t init_result = vpx_codec_enc_init_multi(
      &codec[0], iface, &cfg[0], num_encoders, flags, &dsf[0]);
  
  if (init_result != VPX_CODEC_OK) {
    // If initialization fails, try without highbitdepth flag
    if (use_highbitdepth) {
      flags &= ~VPX_CODEC_USE_HIGHBITDEPTH;
      init_result = vpx_codec_enc_init_multi(
          &codec[0], iface, &cfg[0], num_encoders, flags, &dsf[0]);
    }
    
    if (init_result != VPX_CODEC_OK) {
      return 0;  // Initialization failed
    }
  }

  // Allocate image buffers for each encoder
  vpx_img_fmt_t img_fmt = VPX_IMG_FMT_I420;
  if (use_highbitdepth) {
    img_fmt = VPX_IMG_FMT_I42016;
  }
  
  for (int i = 0; i < num_encoders; i++) {
    if (!vpx_img_alloc(&raw[i], img_fmt, cfg[i].g_w, cfg[i].g_h, 32)) {
      // Cleanup already allocated images
      for (int j = 0; j < i; j++) {
        vpx_img_free(&raw[j]);
      }
      // Cleanup encoders
      for (int j = 0; j < num_encoders; j++) {
        vpx_codec_destroy(&codec[j]);
      }
      return 0;
    }
    
    // Fill image with fuzzer data
    for (int plane = 0; plane < 3; ++plane) {
      unsigned char *buf = raw[i].planes[plane];
      const int stride = raw[i].stride[plane];
      int w = (plane > 0) ? (raw[i].d_w + 1) >> raw[i].x_chroma_shift : raw[i].d_w;
      int h = (plane > 0) ? (raw[i].d_h + 1) >> raw[i].y_chroma_shift : raw[i].d_h;
      const size_t bytespp = (raw[i].fmt & VPX_IMG_FMT_HIGHBITDEPTH) ? 2 : 1;
      
      if (fdp.remaining_bytes() == 0) break;
      
      for (int y = 0; y < h; ++y) {
        size_t bytes_to_copy = bytespp * w;
        if (bytes_to_copy > fdp.remaining_bytes()) {
          bytes_to_copy = fdp.remaining_bytes();
        }
        
        if (bytes_to_copy == 0) break;
        
        std::vector<uint8_t> row_data = fdp.ConsumeBytes<uint8_t>(bytes_to_copy);
        if (!row_data.empty()) {
          memcpy(buf, row_data.data(), row_data.size());
        }
        
        // Fill remainder with zeros if needed
        if (row_data.size() < bytes_to_copy) {
          memset(buf + row_data.size(), 0, bytes_to_copy - row_data.size());
        }
        
        buf += stride;
      }
    }
  }

  // Target: vpx_codec_enc_config_set - reconfigure encoder with new settings
  // Modify configuration parameters and try to set them
  for (int i = 0; i < num_encoders; i++) {
    // Create a modified configuration
    vpx_codec_enc_cfg_t modified_cfg = cfg[i];
    
    // Modify some parameters from fuzzer input
    if (fdp.remaining_bytes() > sizeof(unsigned int)) {
      modified_cfg.rc_target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(50, 4000);
    }
    if (fdp.remaining_bytes() > 1) {
      modified_cfg.g_error_resilient = fdp.ConsumeBool() ? 1 : 0;
    }
    
    // Try to set the modified configuration
    vpx_codec_err_t config_result = vpx_codec_enc_config_set(&codec[i], &modified_cfg);
    
    // The function may fail for various reasons, but we still want to test it
    // Don't abort on failure - this is expected testing behavior
    (void)config_result;  // Mark as used
  }

  // Encode a frame with each encoder
  vpx_enc_deadline_t quality = VPX_DL_GOOD_QUALITY;
  
  for (int i = 0; i < num_encoders; i++) {
    int flags = 0;
    
    // Force keyframe occasionally based on fuzzer input
    if (fdp.ConsumeBool()) {
      flags |= VPX_EFLAG_FORCE_KF;
    }
    
    // Encode the frame
    vpx_codec_err_t encode_result = vpx_codec_encode(&codec[i], &raw[i], 
                                                    0 /* pts */, 1 /* duration */, 
                                                    flags, quality);
    
    if (encode_result == VPX_CODEC_OK) {
      // Get encoded data
      vpx_codec_iter_t iter = nullptr;
      const vpx_codec_cx_pkt_t *pkt = nullptr;
      
      while ((pkt = vpx_codec_get_cx_data(&codec[i], &iter)) != nullptr) {
        // Process packet if needed
        if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
          // We could write to /dev/null, but just consuming is enough for fuzzing
          // The goal is to exercise the API, not produce valid output
          (void)pkt->data.frame.sz;  // Mark as used
        }
      }
    }
  }

  // Cleanup: destroy encoders and free images
  for (int i = 0; i < num_encoders; i++) {
    vpx_codec_destroy(&codec[i]);
    vpx_img_free(&raw[i]);
  }

  return 0;
}
