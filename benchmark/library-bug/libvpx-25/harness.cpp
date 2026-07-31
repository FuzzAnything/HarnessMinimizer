/*
 * Fuzzing harness for libvpx SVC (Scalable Video Coding) and advanced rate control features
 * Targets: vpx_codec_enc_init_ver, vpx_codec_enc_config_default, vpx_codec_encode,
 *          vpx_codec_get_cx_data, vpx_codec_control_, vpx_codec_destroy
 * 
 * This harness focuses on SVC multi-layer encoding, tile-based parallel processing,
 * and advanced rate control configurations that are currently 0% covered.
 * Specific vpx_codec_control parameters targeted:
 * 1. VP9E_SET_SVC_PARAMETERS - Configure spatial/temporal layers
 * 2. VP9E_SET_TILE_COLUMNS - Enable tile-based parallel processing  
 * 3. VP8E_SET_CPUUSED - Control speed/quality tradeoff
 * 4. VP9E_SET_LOSSLESS - Test lossless coding path
 * 5. VP8E_SET_ARNR_STRENGTH - Temporal noise reduction
 * 6. VP9E_SET_FRAME_PERIODIC_BOOST - Rate control optimization
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <algorithm>
#include <memory>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"
#include "vpx/vp8cx.h"
#include "vpx/vpx_codec.h"
#include "vpx/vpx_encoder.h"
#include "vpx/vpx_image.h"

// Minimum size needed for meaningful SVC testing
const size_t MIN_INPUT_SIZE = 128;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < MIN_INPUT_SIZE) {
    return 0;
  }

  FuzzedDataProvider fdp(data, size);
  
  // Determine which advanced features to test
  uint8_t test_svc = fdp.ConsumeBool();
  uint8_t test_tiles = fdp.ConsumeBool();
  uint8_t test_lossless = fdp.ConsumeBool();
  uint8_t test_advanced_ratectrl = fdp.ConsumeBool();
  
  // Consume encoder configuration parameters from fuzzer input
  unsigned int width = fdp.ConsumeIntegralInRange<unsigned int>(16, 1920);
  unsigned int height = fdp.ConsumeIntegralInRange<unsigned int>(16, 1080);
  unsigned int bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 10000);
  unsigned int framerate_num = fdp.ConsumeIntegralInRange<unsigned int>(1, 60);
  unsigned int framerate_den = fdp.ConsumeIntegralInRange<unsigned int>(1, 1000);
  
  // Select VP9 encoder interface (SVC is VP9-specific)
  vpx_codec_iface_t* encoder_iface = vpx_codec_vp9_cx();
  if (encoder_iface == nullptr) {
    return 0;
  }
  
  vpx_codec_err_t err;
  vpx_codec_ctx_t encoder;
  vpx_codec_enc_cfg_t cfg;
  
  // Step 1: Get default configuration
  err = vpx_codec_enc_config_default(encoder_iface, &cfg, 0);
  if (err != VPX_CODEC_OK) {
    return 0;
  }
  
  // Configure basic encoder parameters from fuzzed input
  cfg.g_w = width;
  cfg.g_h = height;
  cfg.g_timebase.num = framerate_den;
  cfg.g_timebase.den = framerate_num * framerate_den;
  cfg.rc_target_bitrate = bitrate;
  cfg.g_error_resilient = fdp.ConsumeIntegral<uint8_t>() % 2;
  cfg.g_lag_in_frames = fdp.ConsumeIntegralInRange<unsigned int>(0, 25);
  
  // Configure SVC layers if testing SVC
  if (test_svc) {
    // Set up spatial and temporal layers for SVC
    cfg.ss_number_layers = fdp.ConsumeIntegralInRange<unsigned int>(1, VPX_SS_MAX_LAYERS);
    cfg.ts_number_layers = fdp.ConsumeIntegralInRange<unsigned int>(1, VPX_TS_MAX_LAYERS);
    
    // Configure layer bitrates for SVC
    for (unsigned int i = 0; i < cfg.ss_number_layers; ++i) {
      cfg.ss_target_bitrate[i] = bitrate / cfg.ss_number_layers;
    }
    
    // Configure temporal layer bitrate allocation
    for (unsigned int i = 0; i < cfg.ts_number_layers; ++i) {
      cfg.ts_target_bitrate[i] = bitrate / cfg.ts_number_layers;
    }
    
    // Configure layer frame rate scaling
    cfg.ts_rate_decimator[0] = 1;
    for (unsigned int i = 1; i < cfg.ts_number_layers; ++i) {
      cfg.ts_rate_decimator[i] = 2 * cfg.ts_rate_decimator[i - 1];
    }
  }
  
  // Step 2: Initialize encoder
  vpx_codec_flags_t flags = 0;
  if (fdp.ConsumeBool()) {
    flags |= VPX_CODEC_USE_HIGHBITDEPTH;
  }
  
  err = vpx_codec_enc_init_ver(&encoder, encoder_iface, &cfg, flags, VPX_ENCODER_ABI_VERSION);
  if (err != VPX_CODEC_OK) {
    return 0;
  }
  
  // Step 3: Configure SVC parameters if testing SVC
  if (test_svc) {
    vpx_svc_extra_cfg_t svc_params;
    
    // Initialize SVC parameters from fuzzed input
    for (int i = 0; i < VPX_MAX_LAYERS; ++i) {
      svc_params.max_quantizers[i] = fdp.ConsumeIntegralInRange<int>(20, 63);
      svc_params.min_quantizers[i] = fdp.ConsumeIntegralInRange<int>(0, 40);
      svc_params.scaling_factor_num[i] = fdp.ConsumeIntegralInRange<int>(1, 16);
      svc_params.scaling_factor_den[i] = fdp.ConsumeIntegralInRange<int>(1, 16);
      svc_params.speed_per_layer[i] = fdp.ConsumeIntegralInRange<int>(0, 9);
      svc_params.loopfilter_ctrl[i] = fdp.ConsumeIntegralInRange<int>(0, 1);
    }
    svc_params.temporal_layering_mode = fdp.ConsumeIntegralInRange<int>(0, 3);
    
    // Set SVC parameters via control API
    err = vpx_codec_control_(&encoder, VP9E_SET_SVC_PARAMETERS, &svc_params);
    // Note: We don't check error here as different parameter combinations may fail
    // and we want to test error paths too
  }
  
  // Step 4: Configure tile columns for parallel processing
  if (test_tiles) {
    unsigned int tile_columns = fdp.ConsumeIntegralInRange<unsigned int>(0, 6);
    err = vpx_codec_control_(&encoder, VP9E_SET_TILE_COLUMNS, tile_columns);
  }
  
  // Step 5: Configure CPU used (speed/quality tradeoff)
  int cpu_used = fdp.ConsumeIntegralInRange<int>(-8, 8);
  err = vpx_codec_control_(&encoder, VP8E_SET_CPUUSED, cpu_used);
  
  // Step 6: Test lossless coding path
  if (test_lossless) {
    int lossless = fdp.ConsumeBool() ? 1 : 0;
    err = vpx_codec_control_(&encoder, VP9E_SET_LOSSLESS, lossless);
  }
  
  // Step 7: Configure temporal noise reduction
  unsigned int arnr_strength = fdp.ConsumeIntegralInRange<unsigned int>(0, 6);
  unsigned int arnr_type = fdp.ConsumeIntegralInRange<unsigned int>(0, 3);
  err = vpx_codec_control_(&encoder, VP8E_SET_ARNR_STRENGTH, arnr_strength);
  err = vpx_codec_control_(&encoder, VP8E_SET_ARNR_TYPE, arnr_type);
  
  // Step 8: Configure frame periodic boost for rate control
  if (test_advanced_ratectrl) {
    int frame_periodic_boost = fdp.ConsumeIntegralInRange<int>(0, 100);
    err = vpx_codec_control_(&encoder, VP9E_SET_FRAME_PERIODIC_BOOST, frame_periodic_boost);
  }
  
  // Step 9: Create test image for encoding
  // Use remaining fuzzer input as image data
  std::vector<uint8_t> image_data = fdp.ConsumeRemainingBytes<uint8_t>();
  if (image_data.size() < width * height * 3 / 2) {
    // Not enough data for even a minimal YUV image
    vpx_codec_destroy(&encoder);
    return 0;
  }
  
  vpx_image_t img;
  vpx_img_alloc(&img, VPX_IMG_FMT_I420, width, height, 1);
  
  // Fill image planes with fuzzed data
  // For simplicity, we'll just copy data into the planes
  // In a real harness, we would properly format the YUV data
  size_t y_plane_size = width * height;
  size_t uv_plane_size = (width / 2) * (height / 2);
  
  if (y_plane_size + 2 * uv_plane_size <= image_data.size()) {
    // Copy Y plane
    memcpy(img.planes[VPX_PLANE_Y], image_data.data(), y_plane_size);
    // Copy U plane  
    memcpy(img.planes[VPX_PLANE_U], image_data.data() + y_plane_size, uv_plane_size);
    // Copy V plane
    memcpy(img.planes[VPX_PLANE_V], image_data.data() + y_plane_size + uv_plane_size, uv_plane_size);
  }
  
  // Step 10: Encode the frame
  err = vpx_codec_encode(&encoder, &img, 0, 1, 0, VPX_DL_REALTIME);
  
  // Step 11: Retrieve encoded data packets
  const vpx_codec_cx_pkt_t *pkt;
  vpx_codec_iter_t iter = nullptr;
  while ((pkt = vpx_codec_get_cx_data(&encoder, &iter)) != nullptr) {
    // Process packets - just consume them to exercise the API
    if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
      // Frame packet - could be saved or analyzed in a real fuzzer
      (void)pkt->data.frame;
    } else if (pkt->kind == VPX_CODEC_STATS_PKT) {
      // Stats packet
      (void)pkt->data.twopass_stats;
    }
  }
  
  // Step 12: Clean up
  vpx_img_free(&img);
  vpx_codec_destroy(&encoder);
  
  return 0;
}
