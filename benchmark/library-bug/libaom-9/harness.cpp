/*
 * Fuzzing harness for libaom AV1 encoder control parameter fuzzing
 * Targets critical coverage gaps identified in coverage guidance: 0.33% API coverage, common/ module with 0% coverage
 * 
 * APIs targeted from coverage guidance:
 * - aom_codec_control_typechecked_AV1E_SET_SVC_PARAMS (Scalable Video Coding parameters)
 * - aom_codec_control_typechecked_AV1E_SET_TILE_COLUMNS (Tile configuration)
 * - aom_codec_control_typechecked_AV1E_SET_TILE_ROWS (Tile configuration)
 * - aom_codec_control_typechecked_AV1E_SET_MAX_PARTITION_SIZE (Partition settings)
 * - aom_codec_control_typechecked_AOME_SET_CPUUSED (CPU utilization)
 * - aom_codec_control_typechecked_AOME_SET_CQ_LEVEL (Constant Quality level)
 * 
 * Required helper APIs:
 * - aom_codec_enc_init (Encoder initialization - must be called first)
 * - aom_img_alloc (Image creation for input frames)
 * - aom_codec_encode (Frame encoding - core operation)
 * - aom_codec_destroy (Cleanup - must be called last)
 * 
 * Follows exact invocation sequence from coverage guidance:
 * 1. Initialization: Call aom_codec_enc_init to create encoder instance
 * 2. Configuration: Call aom_codec_control with various control IDs and parameter values from fuzzer input
 * 3. Image Setup: Create input frames using aom_img_alloc
 * 4. Encoding: Call aom_codec_encode to process frames with configured parameters
 * 5. Cleanup: Call aom_codec_destroy to free resources
 * 
 * Semantic diversity from existing harnesses (000-012):
 * - Specifically targets SVC (Scalable Video Coding) parameter configuration
 * - Focuses on comprehensive encoder control API testing beyond basic tile/config settings
 * - Tests complex parameter structures like aom_svc_params_t
 * - Aims to reach 0%-covered "common/" module through control API pathways
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <algorithm>
#include <memory>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

#include "aom/aom_encoder.h"
#include "aom/aomcx.h"
#include "aom/aom_image.h"

// Define constants for array sizes
#define AOM_MAX_LAYERS 32
#define AOM_MAX_SS_LAYERS 4
#define AOM_MAX_TS_LAYERS 8

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Minimum size needed for meaningful testing
  // Need enough for: basic config + SVC params + control parameters + minimal image data
  const size_t MIN_SIZE = sizeof(int) * 8 + sizeof(unsigned int) * 10 + 128;
  if (size < MIN_SIZE) {
    return 0;
  }

  FuzzedDataProvider fdp(data, size);

  // Get encoder interface for AV1
  aom_codec_iface_t *codec_interface = aom_codec_av1_cx();
  if (!codec_interface) {
    return 0;
  }

  // Consume basic configuration parameters from fuzzer input
  unsigned int usage = fdp.ConsumeIntegralInRange<unsigned int>(0, 2); // 0: GOOD_QUALITY, 1: REALTIME, 2: ALL_INTRA
  int width = fdp.ConsumeIntegralInRange<int>(16, 256);  // Reasonable size for fuzzing
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
  cfg.g_pass = AOM_RC_ONE_PASS; // Simple one-pass for control testing
  cfg.g_lag_in_frames = 0; // No lookahead for simpler fuzzing

  // Initialize encoder context
  aom_codec_ctx_t codec;
  aom_codec_flags_t flags = 0;
  
  res = aom_codec_enc_init(&codec, codec_interface, &cfg, flags);
  if (res != AOM_CODEC_OK) {
    return 0;
  }

  // ====================
  // CONFIGURATION PHASE
  // ====================
  
  // 1. AOME_SET_CPUUSED - CPU utilization parameter
  int cpu_used = fdp.ConsumeIntegralInRange<int>(-16, 16);
  AOM_CODEC_CONTROL_TYPECHECKED(&codec, AOME_SET_CPUUSED, cpu_used);
  
  // 2. AOME_SET_CQ_LEVEL - Constant Quality level
  unsigned int cq_level = fdp.ConsumeIntegralInRange<unsigned int>(0, 63);
  AOM_CODEC_CONTROL_TYPECHECKED(&codec, AOME_SET_CQ_LEVEL, cq_level);
  
  // 3. AV1E_SET_TILE_COLUMNS - Tile columns configuration
  unsigned int tile_columns = fdp.ConsumeIntegralInRange<unsigned int>(0, 6);
  AOM_CODEC_CONTROL_TYPECHECKED(&codec, AV1E_SET_TILE_COLUMNS, tile_columns);
  
  // 4. AV1E_SET_TILE_ROWS - Tile rows configuration
  unsigned int tile_rows = fdp.ConsumeIntegralInRange<unsigned int>(0, 6);
  AOM_CODEC_CONTROL_TYPECHECKED(&codec, AV1E_SET_TILE_ROWS, tile_rows);
  
  // 5. AV1E_SET_MAX_PARTITION_SIZE - Maximum partition size
  int max_partition_size = fdp.ConsumeIntegralInRange<int>(8, 128);
  AOM_CODEC_CONTROL_TYPECHECKED(&codec, AV1E_SET_MAX_PARTITION_SIZE, max_partition_size);
  
  // 6. AV1E_SET_SVC_PARAMS - Scalable Video Coding parameters
  // This is a complex structure that needs proper initialization
  aom_svc_params_t svc_params;
  memset(&svc_params, 0, sizeof(svc_params));
  
  // Set SVC layer configuration from fuzzer input
  svc_params.number_spatial_layers = fdp.ConsumeIntegralInRange<int>(1, 3);
  svc_params.number_temporal_layers = fdp.ConsumeIntegralInRange<int>(1, 3);
  
  // Calculate total layers
  int total_layers = svc_params.number_spatial_layers * svc_params.number_temporal_layers;
  if (total_layers > AOM_MAX_LAYERS) {
    total_layers = AOM_MAX_LAYERS;
  }
  
  // Set quantization parameters for each layer
  for (int i = 0; i < total_layers && i < AOM_MAX_LAYERS; i++) {
    svc_params.max_quantizers[i] = fdp.ConsumeIntegralInRange<int>(0, 63);
    svc_params.min_quantizers[i] = fdp.ConsumeIntegralInRange<int>(0, 63);
    svc_params.layer_target_bitrate[i] = fdp.ConsumeIntegralInRange<int>(100, 10000);
  }
  
  // Set scaling factors for spatial layers
  for (int i = 0; i < svc_params.number_spatial_layers && i < AOM_MAX_SS_LAYERS; i++) {
    svc_params.scaling_factor_num[i] = fdp.ConsumeIntegralInRange<int>(1, 4);
    svc_params.scaling_factor_den[i] = fdp.ConsumeIntegralInRange<int>(1, 4);
  }
  
  // Set framerate factors for temporal layers
  for (int i = 0; i < svc_params.number_temporal_layers && i < AOM_MAX_TS_LAYERS; i++) {
    svc_params.framerate_factor[i] = fdp.ConsumeIntegralInRange<int>(1, 4);
  }
  
  // Apply SVC parameters to encoder
  AOM_CODEC_CONTROL_TYPECHECKED(&codec, AV1E_SET_SVC_PARAMS, &svc_params);
  
  // ====================
  // IMAGE SETUP PHASE
  // ====================
  
  // Allocate image buffer for input frame
  aom_image_t raw;
  aom_img_fmt_t fmt = AOM_IMG_FMT_I420;
  
  if (!aom_img_alloc(&raw, fmt, width, height, 1)) {
    aom_codec_destroy(&codec);
    return 0;
  }
  
  // Fill YUV planes with fuzzed data
  // Calculate required bytes for I420 format: Y plane + U plane + V plane
  size_t y_plane_size = width * height;
  size_t uv_plane_size = (width / 2) * (height / 2);
  size_t total_image_size = y_plane_size + uv_plane_size * 2;
  
  if (fdp.remaining_bytes() < total_image_size) {
    aom_img_free(&raw);
    aom_codec_destroy(&codec);
    return 0;
  }
  
  // Fill Y plane (luma)
  std::vector<uint8_t> y_plane = fdp.ConsumeBytes<uint8_t>(y_plane_size);
  if (y_plane.size() == y_plane_size) {
    memcpy(raw.planes[0], y_plane.data(), y_plane_size);
  }
  
  // Fill U plane (chroma blue)
  std::vector<uint8_t> u_plane = fdp.ConsumeBytes<uint8_t>(uv_plane_size);
  if (u_plane.size() == uv_plane_size) {
    memcpy(raw.planes[1], u_plane.data(), uv_plane_size);
  }
  
  // Fill V plane (chroma red)
  std::vector<uint8_t> v_plane = fdp.ConsumeBytes<uint8_t>(uv_plane_size);
  if (v_plane.size() == uv_plane_size) {
    memcpy(raw.planes[2], v_plane.data(), uv_plane_size);
  }
  
  // ====================
  // ENCODING PHASE
  // ====================
  
  // Encode the frame with configured parameters
  res = aom_codec_encode(&codec, &raw, 0, 1, 0);
  
  // Get compressed data (optional, but exercises more code paths)
  const aom_codec_cx_pkt_t *pkt = NULL;
  aom_codec_iter_t iter = NULL;
  
  while ((pkt = aom_codec_get_cx_data(&codec, &iter)) != NULL) {
    // Process packets if any (compressed frames, etc.)
    // This exercises the packet retrieval code paths
    if (pkt->kind == AOM_CODEC_CX_FRAME_PKT) {
      // Frame packet received
      (void)pkt->data.frame.buf; // Access to avoid unused warning
      (void)pkt->data.frame.sz;  // Access to avoid unused warning
    }
  }
  
  // ====================
  // CLEANUP PHASE
  // ====================
  
  // Free image resources
  aom_img_free(&raw);
  
  // Destroy encoder context
  aom_codec_destroy(&codec);
  
  return 0;
}
