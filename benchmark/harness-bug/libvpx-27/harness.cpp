/*
 * Fuzzing harness for libvpx encoder preview frame functionality
 * Primary target: vpx_codec_get_preview_frame (0% coverage, 10 undiscovered branches)
 * Secondary targets: vpx_codec_enc_init_ver, vpx_codec_enc_init_multi_ver,
 *                    vpx_codec_get_global_headers, vpx_codec_set_cx_data_buf
 * 
 * Follows invocation sequence: default config -> encoder init -> config set -> encode
 * -> get preview frame -> get global headers -> set cx data buffer -> get cx data -> cleanup.
 * Focus on VP8 codec (vpx_codec_vp8_cx) to avoid known VP9 crash in vp9_get_token_cost.
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

#define MIN_INPUT_SIZE 64

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < MIN_INPUT_SIZE) {
    return 0;  // Insufficient input for meaningful testing
  }

  FuzzedDataProvider fdp(data, size);

  // Consume configuration parameters from fuzzer input
  bool use_multi_encoder = fdp.ConsumeBool();
  bool test_set_cx_data_buf = fdp.ConsumeBool();
  bool test_get_global_headers = fdp.ConsumeBool();
  bool test_preview_frame_after_encode = fdp.ConsumeBool();
  bool test_preview_frame_after_flush = fdp.ConsumeBool();
  
  // Image dimensions from fuzzer input (must be even for YUV)
  uint16_t width = fdp.ConsumeIntegralInRange<uint16_t>(16, 640) & ~1;
  uint16_t height = fdp.ConsumeIntegralInRange<uint16_t>(16, 480) & ~1;
  if (width < 16) width = 16;
  if (height < 16) height = 16;
  
  // Encoding parameters
  int frame_count = fdp.ConsumeIntegralInRange<int>(1, 5);
  unsigned int target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 2000);
  uint8_t keyframe_interval = fdp.ConsumeIntegralInRange<uint8_t>(0, 10);
  
  // Buffer configuration for vpx_codec_set_cx_data_buf
  unsigned int pad_before = fdp.ConsumeIntegralInRange<unsigned int>(0, 64);
  unsigned int pad_after = fdp.ConsumeIntegralInRange<unsigned int>(0, 64);
  size_t buffer_size = fdp.ConsumeIntegralInRange<size_t>(1024, 16384);
  
  // Deadline (encoding speed/quality tradeoff)
  vpx_enc_deadline_t deadline = VPX_DL_GOOD_QUALITY;
  uint8_t deadline_choice = fdp.ConsumeIntegral<uint8_t>() % 3;
  switch (deadline_choice) {
    case 0: deadline = VPX_DL_REALTIME; break;
    case 1: deadline = VPX_DL_BEST_QUALITY; break;
    default: deadline = VPX_DL_GOOD_QUALITY; break;
  }

  vpx_codec_err_t res = VPX_CODEC_OK;
  vpx_codec_iface_t *iface = vpx_codec_vp8_cx();  // Use VP8 to avoid VP9 crash

  if (use_multi_encoder) {
    // Multi-encoder test - only supported for VP8
    const int num_encoders = fdp.ConsumeIntegralInRange<int>(1, 2);
    
    vpx_codec_ctx_t codec[2];
    vpx_codec_enc_cfg_t cfg[2];
    vpx_rational_t dsf[2];
    vpx_image_t raw[2];
    
    // Initialize arrays
    for (int i = 0; i < num_encoders; i++) {
      memset(&codec[i], 0, sizeof(vpx_codec_ctx_t));
      memset(&cfg[i], 0, sizeof(vpx_codec_enc_cfg_t));
      dsf[i] = {1, 1};  // Default 1:1 down-sampling
      memset(&raw[i], 0, sizeof(vpx_image_t));
    }
    
    // Get default encoder configurations
    for (int i = 0; i < num_encoders; i++) {
      if (vpx_codec_enc_config_default(iface, &cfg[i], 0)) {
        return 0;  // Failed to get default config
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
      
      cfg[i].g_timebase.num = 1;
      cfg[i].g_timebase.den = 30;
      cfg[i].rc_target_bitrate = target_bitrate;
      cfg[i].g_pass = VPX_RC_ONE_PASS;
      cfg[i].g_lag_in_frames = 0;
      cfg[i].g_error_resilient = fdp.ConsumeBool() ? 1 : 0;
    }
    
    // Initialize multiple encoders using vpx_codec_enc_init_multi_ver
    res = vpx_codec_enc_init_multi_ver(codec, iface, cfg, num_encoders, 0, dsf, 
                                       VPX_ENCODER_ABI_VERSION);
    if (res != VPX_CODEC_OK) {
      return 0;
    }
    
    // Prepare external buffer for compressed data if requested
    vpx_fixed_buf_t output_buf = {nullptr, 0};
    if (test_set_cx_data_buf) {
      output_buf.buf = malloc(buffer_size);
      output_buf.sz = buffer_size;
      if (output_buf.buf) {
        vpx_codec_set_cx_data_buf(&codec[0], &output_buf, pad_before, pad_after);
      }
    }
    
    // Encode frames with each encoder
    for (int enc_idx = 0; enc_idx < num_encoders; enc_idx++) {
      // Allocate image buffer
      vpx_img_fmt_t img_fmt = VPX_IMG_FMT_I420;
      if (!vpx_img_alloc(&raw[enc_idx], img_fmt, cfg[enc_idx].g_w, cfg[enc_idx].g_h, 1)) {
        // Cleanup
        for (int j = 0; j <= enc_idx; j++) {
          vpx_img_free(&raw[j]);
        }
        for (int j = 0; j < num_encoders; j++) {
          vpx_codec_destroy(&codec[j]);
        }
        if (output_buf.buf) free(output_buf.buf);
        return 0;
      }
      
      // Encode multiple frames
      for (int frame_idx = 0; frame_idx < frame_count && fdp.remaining_bytes() > 0; frame_idx++) {
        // Fill image with fuzzer data
        size_t y_plane_size = raw[enc_idx].stride[0] * raw[enc_idx].d_h;
        if (fdp.remaining_bytes() >= y_plane_size) {
          std::vector<uint8_t> y_data = fdp.ConsumeBytes<uint8_t>(y_plane_size);
          memcpy(raw[enc_idx].planes[0], y_data.data(), y_data.size());
        } else {
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
          // Test preview frame retrieval after encode
          if (test_preview_frame_after_encode) {
            const vpx_image_t *preview = vpx_codec_get_preview_frame(&codec[enc_idx]);
            (void)preview;
          }
          
          // Test global headers retrieval
          if (test_get_global_headers) {
            vpx_fixed_buf_t *headers = vpx_codec_get_global_headers(&codec[enc_idx]);
            (void)headers;
          }
          
          // Get encoded data
          vpx_codec_iter_t iter = nullptr;
          const vpx_codec_cx_pkt_t *pkt = nullptr;
          while ((pkt = vpx_codec_get_cx_data(&codec[enc_idx], &iter)) != nullptr) {
            // Process packet
            (void)pkt;
          }
        }
      }
      
      // Flush encoder
      while (vpx_codec_encode(&codec[enc_idx], nullptr, -1, 1, 0, deadline) == VPX_CODEC_OK) {
        vpx_codec_iter_t iter = nullptr;
        const vpx_codec_cx_pkt_t *pkt = nullptr;
        while ((pkt = vpx_codec_get_cx_data(&codec[enc_idx], &iter)) != nullptr) {
          (void)pkt;
        }
      }
      
      // Test preview frame after flush
      if (test_preview_frame_after_flush) {
        const vpx_image_t *preview = vpx_codec_get_preview_frame(&codec[enc_idx]);
        (void)preview;
      }
      
      vpx_img_free(&raw[enc_idx]);
    }
    
    // Cleanup
    for (int i = 0; i < num_encoders; i++) {
      vpx_codec_destroy(&codec[i]);
    }
    if (output_buf.buf) free(output_buf.buf);
    
  } else {
    // Single encoder test
    vpx_codec_ctx_t codec;
    vpx_codec_enc_cfg_t cfg;
    vpx_image_t raw;
    
    memset(&codec, 0, sizeof(vpx_codec_ctx_t));
    memset(&cfg, 0, sizeof(vpx_codec_enc_cfg_t));
    memset(&raw, 0, sizeof(vpx_image_t));
    
    // Get default encoder configuration
    if (vpx_codec_enc_config_default(iface, &cfg, 0)) {
      return 0;
    }
    
    // Set configuration from fuzzer input
    cfg.g_w = width;
    cfg.g_h = height;
    cfg.g_timebase.num = 1;
    cfg.g_timebase.den = 30;
    cfg.rc_target_bitrate = target_bitrate;
    cfg.g_pass = VPX_RC_ONE_PASS;
    cfg.g_lag_in_frames = 0;
    cfg.g_error_resilient = fdp.ConsumeBool() ? 1 : 0;
    
    // Initialize encoder using vpx_codec_enc_init_ver
    res = vpx_codec_enc_init_ver(&codec, iface, &cfg, 0, VPX_ENCODER_ABI_VERSION);
    if (res != VPX_CODEC_OK) {
      return 0;
    }
    
    // Prepare external buffer for compressed data if requested
    vpx_fixed_buf_t output_buf = {nullptr, 0};
    if (test_set_cx_data_buf) {
      output_buf.buf = malloc(buffer_size);
      output_buf.sz = buffer_size;
      if (output_buf.buf) {
        vpx_codec_set_cx_data_buf(&codec, &output_buf, pad_before, pad_after);
      }
    }
    
    // Allocate image buffer
    vpx_img_fmt_t img_fmt = VPX_IMG_FMT_I420;
    if (!vpx_img_alloc(&raw, img_fmt, width, height, 1)) {
      if (output_buf.buf) free(output_buf.buf);
      vpx_codec_destroy(&codec);
      return 0;
    }
    
    // Encode multiple frames
    for (int frame_idx = 0; frame_idx < frame_count && fdp.remaining_bytes() > 0; frame_idx++) {
      // Fill image with fuzzer data
      size_t y_plane_size = raw.stride[0] * raw.d_h;
      if (fdp.remaining_bytes() >= y_plane_size) {
        std::vector<uint8_t> y_data = fdp.ConsumeBytes<uint8_t>(y_plane_size);
        memcpy(raw.planes[0], y_data.data(), y_data.size());
      } else {
        memset(raw.planes[0], 0, y_plane_size);
      }
      
      // Set encoding flags
      int flags = 0;
      if (keyframe_interval > 0 && frame_idx % keyframe_interval == 0) {
        flags |= VPX_EFLAG_FORCE_KF;
      }
      
      // Encode the frame
      res = vpx_codec_encode(&codec, &raw, frame_idx, 1, flags, deadline);
      
      if (res == VPX_CODEC_OK) {
        // Test preview frame retrieval after encode
        if (test_preview_frame_after_encode) {
          const vpx_image_t *preview = vpx_codec_get_preview_frame(&codec);
          (void)preview;
        }
        
        // Test global headers retrieval
        if (test_get_global_headers) {
          vpx_fixed_buf_t *headers = vpx_codec_get_global_headers(&codec);
          (void)headers;
        }
        
        // Get encoded data
        vpx_codec_iter_t iter = nullptr;
        const vpx_codec_cx_pkt_t *pkt = nullptr;
        while ((pkt = vpx_codec_get_cx_data(&codec, &iter)) != nullptr) {
          // Process packet
          (void)pkt;
        }
      }
    }
    
    // Flush encoder
    while (vpx_codec_encode(&codec, nullptr, -1, 1, 0, deadline) == VPX_CODEC_OK) {
      vpx_codec_iter_t iter = nullptr;
      const vpx_codec_cx_pkt_t *pkt = nullptr;
      while ((pkt = vpx_codec_get_cx_data(&codec, &iter)) != nullptr) {
        (void)pkt;
      }
    }
    
    // Test preview frame after flush
    if (test_preview_frame_after_flush) {
      const vpx_image_t *preview = vpx_codec_get_preview_frame(&codec);
      (void)preview;
    }
    
    // Cleanup
    vpx_img_free(&raw);
    if (output_buf.buf) free(output_buf.buf);
    vpx_codec_destroy(&codec);
  }
  
  return 0;
}
