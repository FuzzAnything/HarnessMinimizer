/*
 * Fuzzing harness for libvpx VP8/VP9 encoders
 * Targets: vpx_codec_enc_init, vpx_codec_encode, vpx_codec_get_cx_data,
 *          vpx_codec_enc_config_default, vpx_img_alloc, vpx_codec_control
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fuzzer/FuzzedDataProvider.h>
#include "vpx/vp8cx.h"
#include "vpx/vpx_encoder.h"
#include "vpx/vpx_image.h"

#define FUZZ_HDR_SZ 32

#define VPXC_INTERFACE(name) VPXC_INTERFACE_(name)
#define VPXC_INTERFACE_(name) vpx_codec_##name##_cx()

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < FUZZ_HDR_SZ + 64) {
    return 0;  // Insufficient input for basic image data
  }

  FuzzedDataProvider fdp(data, size);

  // Consume configuration parameters from fuzzer input
  uint8_t encoder_choice = fdp.ConsumeIntegral<uint8_t>() % 2;  // 0=VP8, 1=VP9
  bool use_highbitdepth = fdp.ConsumeBool();
  bool use_realtime_mode = fdp.ConsumeBool();
  bool use_best_quality = fdp.ConsumeBool();
  uint8_t resolution_choice = fdp.ConsumeIntegral<uint8_t>() % 6;
  bool error_resilient = fdp.ConsumeBool();
  bool force_keyframe = fdp.ConsumeBool();
  uint8_t keyframe_interval = fdp.ConsumeIntegral<uint8_t>();
  
  vpx_codec_ctx_t codec;
  vpx_image_t raw;
  vpx_codec_enc_cfg_t cfg;
  vpx_enc_deadline_t quality = VPX_DL_GOOD_QUALITY;
  
  // Choose encoder interface based on fuzzer input
  vpx_codec_iface_t *iface = nullptr;
  if (encoder_choice == 0) {
    iface = vpx_codec_vp8_cx();
  } else {
    iface = vpx_codec_vp9_cx();
  }

  // Get default encoder configuration
  if (vpx_codec_enc_config_default(iface, &cfg, 0)) {
    return 0;
  }

  // Set resolution based on fuzzer input
  switch (resolution_choice) {
    case 0: cfg.g_w = 64; cfg.g_h = 48; break;   // Small resolution
    case 1: cfg.g_w = 128; cfg.g_h = 96; break;  // Medium-small
    case 2: cfg.g_w = 320; cfg.g_h = 240; break; // QVGA
    case 3: cfg.g_w = 640; cfg.g_h = 360; break; // 360p
    case 4: cfg.g_w = 640; cfg.g_h = 480; break; // VGA
    case 5: cfg.g_w = 1280; cfg.g_h = 720; break; // 720p
    default: cfg.g_w = 64; cfg.g_h = 48; break;
  }

  // Set timebase and basic parameters
  cfg.g_timebase.num = 1;
  cfg.g_timebase.den = 30;  // 30 fps
  cfg.rc_target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 2000);
  cfg.g_error_resilient = error_resilient ? 1 : 0;
  cfg.g_pass = VPX_RC_ONE_PASS;
  cfg.g_lag_in_frames = 0;  // Real-time mode
  
  // Set quality/deadline
  if (use_realtime_mode) {
    quality = VPX_DL_REALTIME;
  } else if (use_best_quality) {
    quality = VPX_DL_BEST_QUALITY;
  }

  // Set encoder flags
  vpx_codec_flags_t flags = 0;
  if (use_highbitdepth) {
    flags |= VPX_CODEC_USE_HIGHBITDEPTH;
  }

  // Initialize encoder
  if (vpx_codec_enc_init(&codec, iface, &cfg, flags)) {
    return 0;
  }

  // Set encoder controls based on fuzzer input
  if (encoder_choice == 0) {  // VP8 specific controls
    int cq_level = fdp.ConsumeIntegralInRange<int>(0, 63);
    vpx_codec_control(&codec, VP8E_SET_CQ_LEVEL, cq_level);
    
    int rc_max_intra_bitrate_pct = fdp.ConsumeIntegralInRange<int>(0, 300);
    vpx_codec_control(&codec, VP8E_SET_MAX_INTRA_BITRATE_PCT, rc_max_intra_bitrate_pct);
  } else {  // VP9 specific controls
    int aq_mode = fdp.ConsumeIntegralInRange<int>(0, 3);
    vpx_codec_control(&codec, VP9E_SET_AQ_MODE, aq_mode);
    
    bool frame_parallel_decoding = fdp.ConsumeBool();
    vpx_codec_control(&codec, VP9E_SET_FRAME_PARALLEL_DECODING, 
                     frame_parallel_decoding ? 1 : 0);
    
    int tile_columns = fdp.ConsumeIntegralInRange<int>(0, 6);
    vpx_codec_control(&codec, VP9E_SET_TILE_COLUMNS, tile_columns);
  }

  // Set common controls
  bool enable_denoising = fdp.ConsumeBool();
  vpx_codec_control(&codec, VP8E_SET_NOISE_SENSITIVITY, enable_denoising ? 1 : 0);
  
  int cpu_used = fdp.ConsumeIntegralInRange<int>(0, 9);
  vpx_codec_control(&codec, VP8E_SET_CPUUSED, cpu_used);

  // Allocate image buffer
  vpx_img_fmt_t img_fmt = VPX_IMG_FMT_I420;
  if (use_highbitdepth) {
    img_fmt = VPX_IMG_FMT_I42016;
  }
  
  if (!vpx_img_alloc(&raw, img_fmt, cfg.g_w, cfg.g_h, 1)) {
    vpx_codec_destroy(&codec);
    return 0;
  }

  // Consume fuzz header
  fdp.ConsumeBytes<uint8_t>(FUZZ_HDR_SZ);

  // Encode frames until we run out of input data
  int frame_count = 0;
  FILE *out = fopen("/dev/null", "wb");  // Discard output
  
  while (fdp.remaining_bytes() > 0) {
    int flags = 0;
    
    // Force keyframe based on interval
    if (force_keyframe && keyframe_interval > 0 && 
        frame_count % keyframe_interval == 0) {
      flags |= VPX_EFLAG_FORCE_KF;
    }
    
    // Fill image with fuzzer data
    // Simple approach: fill planes with available data
    for (int plane = 0; plane < 3; ++plane) {
      unsigned char *buf = raw.planes[plane];
      const int stride = raw.stride[plane];
      int w = (plane > 0) ? (raw.d_w + 1) >> raw.x_chroma_shift : raw.d_w;
      int h = (plane > 0) ? (raw.d_h + 1) >> raw.y_chroma_shift : raw.d_h;
      const size_t bytespp = (raw.fmt & VPX_IMG_FMT_HIGHBITDEPTH) ? 2 : 1;
      
      if (fdp.remaining_bytes() == 0) break;
      
      for (int y = 0; y < h; ++y) {
        size_t bytes_to_copy = bytespp * w;
        if (bytes_to_copy > fdp.remaining_bytes()) {
          bytes_to_copy = fdp.remaining_bytes();
        }
        
        // Skip if nothing to copy (avoid calling memcpy with nullptr)
        if (bytes_to_copy == 0) {
          break;
        }
        
        std::vector<uint8_t> row_data = fdp.ConsumeBytes<uint8_t>(bytes_to_copy);
        // Guard against empty vector (though bytes_to_copy > 0 should ensure non-empty)
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
    
    // Encode the frame
    vpx_codec_err_t res = vpx_codec_encode(&codec, &raw, frame_count, 1, flags, quality);
    
    if (res == VPX_CODEC_OK) {
      // Get encoded data (even though we discard it)
      vpx_codec_iter_t iter = nullptr;
      const vpx_codec_cx_pkt_t *pkt = nullptr;
      while ((pkt = vpx_codec_get_cx_data(&codec, &iter)) != nullptr) {
        if (pkt->kind == VPX_CODEC_CX_FRAME_PKT && out != nullptr) {
          fwrite(pkt->data.frame.buf, 1, pkt->data.frame.sz, out);
        }
      }
    }
    
    frame_count++;
    
    // Break after reasonable number of frames to avoid excessive memory usage
    if (frame_count > 50) {
      break;
    }
  }

  // Flush encoder
  while (vpx_codec_encode(&codec, nullptr, -1, 1, 0, quality) == VPX_CODEC_OK) {
    vpx_codec_iter_t iter = nullptr;
    const vpx_codec_cx_pkt_t *pkt = nullptr;
    while ((pkt = vpx_codec_get_cx_data(&codec, &iter)) != nullptr) {
      if (pkt->kind == VPX_CODEC_CX_FRAME_PKT && out != nullptr) {
        fwrite(pkt->data.frame.buf, 1, pkt->data.frame.sz, out);
      }
    }
  }

  // Cleanup
  if (out != nullptr) {
    fclose(out);
  }
  vpx_img_free(&raw);
  vpx_codec_destroy(&codec);
  
  return 0;
}
