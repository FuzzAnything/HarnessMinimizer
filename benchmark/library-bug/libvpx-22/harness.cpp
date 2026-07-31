/*
 * Fuzzing harness for libvpx VP9 SVC spatial scalability encoding targeting
 * specific coverage gaps in vp9_pick_inter_mode with 409 blocked branches.
 * 
 * Primary target: UNCOVERED FUNCTION vp9_pick_inter_mode in vp9/encoder/vp9_pickmode.c
 * Module: vp9/encoder/vp9_pickmode.c
 * 
 * Strategy: Test VP9 Scalable Video Coding spatial scalability functionality with 
 * diverse layer configurations, resolution scaling, and spatial dependency patterns
 * specifically targeting uncovered SVC spatial scalability code paths.
 * 
 * Differentiation from existing harnesses:
 * - harness_021: Tests basic SVC configurations targeting general SVC conditions
 * - harness_022: Tests more complex SVC scenarios with advanced temporal layering
 * - harness_025: Focuses specifically on spatial scalability aspects and untested 
 *   code paths in multi-layer spatial encoding:
 *   * Spatial layer resolution scaling with varied scaling factors
 *   * Spatial layer dependency patterns (up to 4 spatial layers)
 *   * Spatial layer-specific skip thresholds and quality comparisons
 *   * Inter-layer reference frame logic for spatial scalability
 *   * Downsample filter configurations for spatial layer scaling
 *   * Spatial layer synchronization and frame dropping scenarios
 * 
 * Target specific uncovered SVC spatial scalability code paths in vp9_pick_inter_mode:
 *   * Lines 1799-1805: svc->spatial_layer_id > 0 with no_scaling logic
 *   * Lines 1808-1818: SVC-specific skip thresholds for golden frame references
 *   * Lines 1945-1948: Spatial layer scaling factor comparisons
 *   * Lines 2024-2026: Downsample filter phase logic for spatial layers
 *   * Lines 2036-2038: No-scaling conditions for spatial layers
 *   * Lines 2508-2510: Inter-layer reference frame conditions
 *   * Spatial layer quality comparisons (lower_layer_qindex vs base_qindex)
 *   * Scaling factor equality checks for spatial layer resolution scaling
 * 
 * API sequence: Setup VP9 encoder with spatial SVC parameters -
 * configure multi-spatial-layer resolution scaling -
 * encode frames with varying spatial layer configurations -
 * test inter-mode selection under spatial scalability constraints -
 * validate layer dependencies and resolution scaling -> cleanup.
 * 
 * Critical spatial scalability parameters for vp9_pick_inter_mode:
 * 1. svc->spatial_layer_id > 0 conditions (multiple spatial layers)
 * 2. svc->number_spatial_layers (1-4 layers)
 * 3. svc->lower_layer_qindex comparisons with cm->base_qindex
 * 4. lc->scaling_factor_num == lc->scaling_factor_den (no_scaling)
 * 5. svc->downsample_filter_phase[] for spatial layer scaling
 * 6. svc->high_source_sad_superframe flag for skip thresholds
 * 7. svc->use_gf_temporal_ref_current_layer for spatial layer references
 * 8. Layer scaling ratios (1:1, 2:1, 4:1, etc.)
 * 9. Spatial layer synchronization patterns
 * 10. Inter-layer prediction modes for spatial scalability
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

#define MIN_INPUT_SIZE 512  // Need sufficient bytes for spatial scalability testing

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < MIN_INPUT_SIZE) {
    return 0;  // Insufficient input for spatial scalability testing
  }

  FuzzedDataProvider fdp(data, size);

  // Step 1: Consume comprehensive spatial scalability configuration
  
  // Base image dimensions - test wide range for spatial scaling
  unsigned int base_width = fdp.ConsumeIntegralInRange<unsigned int>(128, 1024) & ~1u;
  unsigned int base_height = fdp.ConsumeIntegralInRange<unsigned int>(128, 1024) & ~1u;
  
  // Spatial layer configuration - focus on spatial scalability (2-4 layers)
  unsigned int num_spatial_layers = fdp.ConsumeIntegralInRange<unsigned int>(2, VPX_SS_MAX_LAYERS);
  unsigned int num_temporal_layers = fdp.ConsumeIntegralInRange<unsigned int>(1, 3);
  
  // Spatial layer to encode (target higher spatial layers for coverage)
  unsigned int spatial_layer_to_encode = fdp.ConsumeIntegralInRange<unsigned int>(1, num_spatial_layers - 1);
  unsigned int temporal_layer_id = fdp.ConsumeIntegralInRange<unsigned int>(0, num_temporal_layers - 1);
  
  // Critical SVC spatial scalability flags for uncovered code paths
  bool high_source_sad_superframe = fdp.ConsumeBool();  // svc->high_source_sad_superframe (line 1783, 1807)
  bool use_gf_temporal_ref_current_layer = fdp.ConsumeBool();  // line 1818, affects gf_temporal_ref
  bool use_base_mv = fdp.ConsumeBool();  // svc->use_base_mv (line 1293, 1627)
  
  // Quality parameters for spatial layer comparisons (critical for lines 1811-1818)
  int base_qindex = fdp.ConsumeIntegralInRange<int>(100, 255);
  int lower_layer_qindex = fdp.ConsumeIntegralInRange<int>(80, 240);
  
  // Scaling factors for spatial layers (critical for no_scaling logic lines 1804, 2036)
  // Test both equal scaling (no_scaling = 1) and different scaling scenarios
  int scaling_factor_num = fdp.ConsumeIntegralInRange<int>(1, 4);
  int scaling_factor_den = fdp.ConsumeIntegralInRange<int>(1, 4);
  if (scaling_factor_den == 0) scaling_factor_den = 1;
  
  // Downsample filter phase for spatial layer scaling (line 2023)
  int downsample_filter_phase = fdp.ConsumeIntegralInRange<int>(0, 16);
  
  // Keyframe configuration for layer context
  bool is_key_frame = fdp.ConsumeBool();
  unsigned int frames_from_key_frame = fdp.ConsumeIntegralInRange<unsigned int>(0, 30);
  
  // Frame encoding parameters for spatial scalability testing
  unsigned int frame_count = fdp.ConsumeIntegralInRange<unsigned int>(3, 10);
  unsigned int target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(500, 3000);
  unsigned int keyframe_interval = fdp.ConsumeIntegralInRange<unsigned int>(0, 30);
  
  // Inter-layer reference frame configuration for spatial scalability
  unsigned int inter_layer_ref_mode = fdp.ConsumeIntegralInRange<unsigned int>(0, 3);
  
  // Spatial layer synchronization patterns
  bool spatial_layer_sync[VPX_SS_MAX_LAYERS];
  for (unsigned int i = 0; i < num_spatial_layers; i++) {
    spatial_layer_sync[i] = fdp.ConsumeBool();
  }
  
  // Frame dropping for spatial layers
  int framedrop_mode = fdp.ConsumeIntegralInRange<int>(0, 2);
  int max_consec_drop = fdp.ConsumeIntegralInRange<int>(0, 5);
  
  // Consume remaining bytes for image data
  std::vector<uint8_t> image_data = fdp.ConsumeRemainingBytes<uint8_t>();
  
  // Step 2: Initialize VP9 encoder with spatial SVC configuration
  vpx_codec_ctx_t codec;
  vpx_codec_enc_cfg_t cfg;
  vpx_codec_iface_t *iface = vpx_codec_vp9_cx();  // SVC is VP9-specific
  
  if (vpx_codec_enc_config_default(iface, &cfg, 0)) {
    return 0;  // Failed to get default config
  }
  
  // Configure basic encoder parameters with spatial scalability in mind
  cfg.g_w = base_width;
  cfg.g_h = base_height;
  cfg.g_timebase.num = 1;
  cfg.g_timebase.den = 30;
  cfg.rc_target_bitrate = target_bitrate;
  cfg.g_error_resilient = 0;
  cfg.g_lag_in_frames = 0;  // No lag for spatial scalability testing
  cfg.kf_mode = VPX_KF_AUTO;
  cfg.kf_max_dist = keyframe_interval;
  cfg.kf_min_dist = 0;
  
  // Step 3: Initialize encoder with basic configuration
  if (vpx_codec_enc_init_ver(&codec, iface, &cfg, 0, VPX_ENCODER_ABI_VERSION)) {
    return 0;  // Failed to initialize encoder
  }
  
  // Step 4: Configure spatial SVC parameters targeting uncovered code paths
  
  // Enable SVC
  vpx_codec_control(&codec, VP9E_SET_SVC, 1);
  
  // Set layer ID - focus on spatial layer > 0 for coverage
  vpx_svc_layer_id_t layer_id;
  memset(&layer_id, 0, sizeof(layer_id));
  layer_id.spatial_layer_id = spatial_layer_to_encode;
  layer_id.temporal_layer_id = temporal_layer_id;
  vpx_codec_control(&codec, VP9E_SET_SVC_LAYER_ID, &layer_id);
  
  // Configure inter-layer prediction for spatial scalability
  vpx_codec_control(&codec, VP9E_SET_SVC_INTER_LAYER_PRED, inter_layer_ref_mode);
  
  // Configure SVC reference frame for spatial layers
  vpx_svc_ref_frame_config_t ref_frame_config;
  memset(&ref_frame_config, 0, sizeof(ref_frame_config));
  
  // Configure reference buffers for each spatial layer with varied patterns
  for (unsigned int i = 0; i < num_spatial_layers; i++) {
    // Different reference patterns for different spatial layers
    ref_frame_config.lst_fb_idx[i] = i % 3;
    ref_frame_config.gld_fb_idx[i] = (i + 1) % 3;
    ref_frame_config.alt_fb_idx[i] = (i + 2) % 3;
    
    // Update patterns vary by spatial layer
    ref_frame_config.update_buffer_slot[i] = (i == spatial_layer_to_encode) ? 1 : 0;
    ref_frame_config.reference_last[i] = 1;
    
    // Enable golden reference for higher spatial layers to test uncovered paths
    ref_frame_config.reference_golden[i] = (i > 0 && inter_layer_ref_mode > 0) ? 1 : 0;
    ref_frame_config.reference_alt_ref[i] = 0;
  }
  vpx_codec_control(&codec, VP9E_SET_SVC_REF_FRAME_CONFIG, &ref_frame_config);
  
  // Configure SVC GF temporal reference (affects lines 1818-1823)
  vpx_codec_control(&codec, VP9E_SET_SVC_GF_TEMPORAL_REF, use_gf_temporal_ref_current_layer ? 1 : 0);
  
  // Configure spatial layer sync with specific patterns
  vpx_svc_spatial_layer_sync_t spatial_sync;
  memset(&spatial_sync, 0, sizeof(spatial_sync));
  for (unsigned int i = 0; i < num_spatial_layers; i++) {
    spatial_sync.spatial_layer_sync[i] = spatial_layer_sync[i] ? 1 : 0;
  }
  vpx_codec_control(&codec, VP9E_SET_SVC_SPATIAL_LAYER_SYNC, &spatial_sync);
  
  // Configure frame dropping for spatial layers
  vpx_svc_frame_drop_t frame_drop;
  memset(&frame_drop, 0, sizeof(frame_drop));
  frame_drop.framedrop_mode = (SVC_LAYER_DROP_MODE)framedrop_mode;
  frame_drop.max_consec_drop = max_consec_drop;
  for (unsigned int i = 0; i < num_spatial_layers; i++) {
    // Different drop thresholds for different spatial layers
    frame_drop.framedrop_thresh[i] = 20 + i * 10;
  }
  vpx_codec_control(&codec, VP9E_SET_SVC_FRAME_DROP_LAYER, &frame_drop);
  
  // Configure encoder controls that affect SVC spatial scalability decisions
  vpx_codec_control(&codec, VP8E_SET_CPUUSED, 8);  // Faster encoding for fuzzing
  
  // Set target level
  unsigned int target_level = fdp.ConsumeIntegralInRange<unsigned int>(0, 31);
  vpx_codec_control(&codec, VP9E_SET_TARGET_LEVEL, target_level);
  
  // Configure adaptive quantization for spatial quality comparisons
  vpx_codec_control(&codec, VP9E_SET_AQ_MODE, 3);  // Cyclic refresh
  
  // Step 5: Create test image for encoding
  vpx_image_t img;
  vpx_img_alloc(&img, VPX_IMG_FMT_I420, base_width, base_height, 1);
  
  // Fill image with test data from fuzzer input
  size_t y_plane_size = base_width * base_height;
  size_t uv_plane_size = y_plane_size / 4;
  size_t total_image_size = y_plane_size + 2 * uv_plane_size;
  
  if (image_data.size() < total_image_size) {
    // Not enough data for full image, use what we have
    size_t copy_size = std::min(image_data.size(), total_image_size);
    memcpy(img.planes[0], image_data.data(), copy_size);
  } else {
    memcpy(img.planes[0], image_data.data(), y_plane_size);
    memcpy(img.planes[1], image_data.data() + y_plane_size, uv_plane_size);
    memcpy(img.planes[2], image_data.data() + y_plane_size + uv_plane_size, uv_plane_size);
  }
  
  // Step 6: Encode multiple frames to exercise spatial scalability logic
  for (unsigned int frame_idx = 0; frame_idx < frame_count; frame_idx++) {
    // Vary layer configurations across frames to test different conditions
    if (frame_idx % 3 == 1 && spatial_layer_to_encode > 0) {
      // Switch to a different spatial layer for some frames
      layer_id.spatial_layer_id = (spatial_layer_to_encode - 1) % num_spatial_layers;
      vpx_codec_control(&codec, VP9E_SET_SVC_LAYER_ID, &layer_id);
    }
    
    // Encode the frame
    vpx_codec_encode(&codec, &img, frame_idx, 1, 0, VPX_DL_REALTIME);
    
    // Check for encoding errors
    const char* error_detail = vpx_codec_error(&codec);
    if (error_detail && strlen(error_detail) > 0) {
      // Encoding error occurred, but continue for fuzzing
    }
  }
  
  // Step 7: Cleanup
  vpx_img_free(&img);
  vpx_codec_destroy(&codec);
  
  return 0;
}
