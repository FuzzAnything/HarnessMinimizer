/*
 * Fuzzing harness for libaom AV1 encoder configuration validation (Deep Coverage Phase 2)
 * 
 * PRIMARY TARGET: validate_config function in av1/av1_cx_iface.c (268 blocked branches, 33% blocked)
 * 
 * CRITICAL UNCOVERED VALIDATION PATHS:
 * 1. Two-pass encoding (g_pass >= AOM_RC_SECOND_PASS) - lines 807-824 in av1_cx_iface.c
 * 2. Constrained frame dimensions (g_forced_max_frame_width/height) - lines 688-693
 * 3. Golden frame interval constraints (max_gf_interval > 0) - lines 738-741
 * 4. Large scale tile + adaptive quantization validation - lines 790-793
 * 
 * PRIMARY TARGET APIS:
 * - aom_codec_enc_init_ver (Primary Entry Point, 58% branches blocked)
 * - aom_codec_enc_config_default (Config Setup)
 * - aom_codec_enc_config_set (Config Modification)
 * - aom_codec_encode (Required for two-pass data flow)
 * - aom_codec_destroy (Cleanup)
 * 
 * ADDITIONAL HELPER APIS:
 * - aom_img_alloc (Create input frames)
 * - aom_img_free (Cleanup)
 * 
 * SEMANTIC DIFFERENTIATION FROM EXISTING HARNESSES:
 * - harness_001: Basic encoder workflow with single-pass encoding
 * - harness_008: Encoder output retrieval functions
 * - harness_010: Focus on DEEP COVERAGE of encoder configuration validation logic
 *               Specifically targets two-pass encoding validation, constrained dimensions,
 *               golden frame intervals, and complex validation error paths
 * 
 * TESTING STRATEGY:
 * 1. Generate valid/invalid FIRSTPASS_STATS buffers for two-pass validation
 * 2. Test both SECOND_PASS and THIRD_PASS encoding modes
 * 3. Test with/without frame dimension constraints
 * 4. Test various golden frame interval configurations
 * 5. Test edge cases in configuration validation
 * 6. Test large scale tile + adaptive quantization conflict
 */

#include <stddef.h>
#include <stdint.h>
#include <vector>
#include <memory>
#include <cstdlib>
#include <cstring>
#include <cmath>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
#include "aom/aom_encoder.h"
#include "aom/aomcx.h"
#include "aom/aom_image.h"
#include "aom/aom_codec.h"
}

// Forward declaration of FIRSTPASS_STATS structure (defined in firstpass.h)
// We need this to create valid two-pass stats buffers
typedef struct FIRSTPASS_STATS {
  double frame;
  double weight;
  double intra_error;
  double frame_avg_wavelet_energy;
  double coded_error;
  double sr_coded_error;
  double lt_coded_error;
  double pcnt_inter;
  double pcnt_motion;
  double pcnt_second_ref;
  double pcnt_neutral;
  double intra_skip_pct;
  double inactive_zone_rows;
  double inactive_zone_cols;
  double MVr;
  double MVc;
  double MVrv;
  double MVcv;
  double mv_in_out_count;
  double duration;
  double count;
} FIRSTPASS_STATS;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Minimum size check - need enough data for complex configuration
  if (size < 128) {
    return 0;
  }

  FuzzedDataProvider fdp(data, size);

  // 1. Get encoder interface
  aom_codec_iface_t *encoder = aom_codec_av1_cx();
  if (!encoder) {
    return 0;
  }

  // 2. Initialize encoder configuration with defaults
  aom_codec_enc_cfg_t cfg;
  aom_codec_err_t res;
  
  // Consume usage mode (0=GOOD_QUALITY, 1=REALTIME, 2=ALL_INTRA)
  unsigned int usage = fdp.ConsumeIntegralInRange<unsigned int>(0, 2);
  
  res = aom_codec_enc_config_default(encoder, &cfg, usage);
  if (res != AOM_CODEC_OK) {
    // Error handling
    const char *error_str = aom_codec_err_to_string(res);
    (void)error_str;
    return 0;
  }

  // 3. Configure basic parameters from fuzzer input
  unsigned int width = (fdp.ConsumeIntegralInRange<unsigned int>(16, 256) / 2) * 2;
  unsigned int height = (fdp.ConsumeIntegralInRange<unsigned int>(16, 256) / 2) * 2;
  
  cfg.g_w = width;
  cfg.g_h = height;
  
  // Consume timebase values
  cfg.g_timebase.num = fdp.ConsumeIntegralInRange<int>(1, 100);
  cfg.g_timebase.den = fdp.ConsumeIntegralInRange<int>(1, 100);
  
  // Consume bitrate
  cfg.rc_target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 10000);
  
  // 4. CRITICAL: Configure for two-pass encoding validation
  // Determine which pass to test (ONE_PASS, SECOND_PASS, THIRD_PASS)
  uint8_t pass_choice = fdp.ConsumeIntegral<uint8_t>() % 3;
  
  if (pass_choice == 1) {
    cfg.g_pass = AOM_RC_SECOND_PASS;
  } else if (pass_choice == 2) {
    cfg.g_pass = AOM_RC_THIRD_PASS;
  } else {
    cfg.g_pass = AOM_RC_ONE_PASS;
  }
  
  // 5. If testing two-pass, create valid FIRSTPASS_STATS buffer
  aom_fixed_buf_t stats_buf = {0};
  std::vector<uint8_t> stats_data;
  
  if (cfg.g_pass >= AOM_RC_SECOND_PASS) {
    // Create a valid stats buffer that will pass validation
    // Need at least 2 packets, each packet size = sizeof(FIRSTPASS_STATS)
    // Last packet must have count = n_packets - 1
    
    size_t packet_sz = sizeof(FIRSTPASS_STATS);
    int n_packets = fdp.ConsumeIntegralInRange<int>(2, 10);
    size_t total_sz = n_packets * packet_sz;
    
    // Allocate buffer
    stats_data.resize(total_sz);
    
    // Fill with valid stats data
    for (int i = 0; i < n_packets; i++) {
      FIRSTPASS_STATS* stats = reinterpret_cast<FIRSTPASS_STATS*>(stats_data.data() + i * packet_sz);
      
      // Initialize all fields
      stats->frame = i;
      stats->weight = 1.0;
      stats->intra_error = 100.0 + i * 10.0;
      stats->frame_avg_wavelet_energy = 50.0;
      stats->coded_error = 80.0 + i * 5.0;
      stats->sr_coded_error = 90.0;
      stats->lt_coded_error = 85.0;
      stats->pcnt_inter = 0.7;
      stats->pcnt_motion = 0.5;
      stats->pcnt_second_ref = 0.2;
      stats->pcnt_neutral = 0.1;
      stats->intra_skip_pct = 0.05;
      stats->inactive_zone_rows = 0.0;
      stats->inactive_zone_cols = 0.0;
      stats->MVr = 0.1;
      stats->MVc = 0.1;
      stats->MVrv = 0.01;
      stats->MVcv = 0.01;
      stats->mv_in_out_count = 0.5;
      stats->duration = 1.0;
      
      // CRITICAL: Last packet must have count = n_packets - 1
      if (i == n_packets - 1) {
        stats->count = n_packets - 1;
      } else {
        stats->count = i;
      }
    }
    
    // Set up the stats buffer
    stats_buf.buf = stats_data.data();
    stats_buf.sz = total_sz;
    cfg.rc_twopass_stats_in = stats_buf;
    
    // Also test with invalid stats buffer based on fuzzer choice
    if (fdp.ConsumeBool() && fdp.remaining_bytes() > 16) {
      // Create invalid buffer (truncated or wrong count)
      int invalid_type = fdp.ConsumeIntegralInRange<int>(0, 2);
      if (invalid_type == 0) {
        // Truncated buffer (not multiple of packet size)
        stats_buf.sz = total_sz - 1;
      } else if (invalid_type == 1) {
        // Too small buffer
        stats_buf.sz = packet_sz;  // Only 1 packet, need at least 2
      } else {
        // Wrong count in last packet
        if (n_packets >= 2) {
          FIRSTPASS_STATS* last_stats = reinterpret_cast<FIRSTPASS_STATS*>(stats_data.data() + (n_packets - 1) * packet_sz);
          last_stats->count = n_packets;  // Wrong: should be n_packets - 1
        }
      }
      cfg.rc_twopass_stats_in = stats_buf;
    }
  }

  // 6. CRITICAL: Test constrained frame dimensions (g_forced_max_frame_width/height)
  if (fdp.ConsumeBool()) {
    cfg.g_forced_max_frame_width = fdp.ConsumeIntegralInRange<unsigned int>(width, width * 2);
    cfg.g_forced_max_frame_height = fdp.ConsumeIntegralInRange<unsigned int>(height, height * 2);
    
    // Also test with invalid constraints (smaller than actual frame)
    if (fdp.ConsumeBool() && fdp.remaining_bytes() > 8) {
      cfg.g_forced_max_frame_width = fdp.ConsumeIntegralInRange<unsigned int>(1, width - 1);
      cfg.g_forced_max_frame_height = fdp.ConsumeIntegralInRange<unsigned int>(1, height - 1);
    }
  }

  // 7. CRITICAL: Test golden frame interval constraints
  // This requires setting extra_cfg parameters
  // We'll test via aom_codec_control after initialization
  bool test_gf_intervals = fdp.ConsumeBool();
  unsigned int min_gf_interval = 0;
  unsigned int max_gf_interval = 0;
  
  if (test_gf_intervals && fdp.remaining_bytes() > 8) {
    min_gf_interval = fdp.ConsumeIntegralInRange<unsigned int>(0, 32);
    max_gf_interval = fdp.ConsumeIntegralInRange<unsigned int>(0, 32);
    
    // Ensure max >= min when both > 0
    if (max_gf_interval > 0 && min_gf_interval > max_gf_interval) {
      std::swap(min_gf_interval, max_gf_interval);
    }
    
    // Test the condition: if max_gf_interval > 0, must be >= max(2, min_gf_interval)
    if (max_gf_interval > 0 && max_gf_interval < 2) {
      max_gf_interval = 2;
    }
  }

  // 8. CRITICAL: Test large scale tile + adaptive quantization conflict
  bool test_large_scale_tile = fdp.ConsumeBool();
  if (test_large_scale_tile) {
    cfg.large_scale_tile = 1;
    // Will test with aq_mode via aom_codec_control
  }

  // 9. Initialize encoder context
  aom_codec_ctx_t codec;
  aom_codec_flags_t flags = 0;
  
  if (fdp.ConsumeBool()) {
    flags |= AOM_CODEC_USE_HIGHBITDEPTH;
  }
  
  res = aom_codec_enc_init_ver(&codec, encoder, &cfg, flags, AOM_ENCODER_ABI_VERSION);
  
  // Even if initialization fails, we've exercised validation paths
  // Record the error for coverage
  if (res != AOM_CODEC_OK) {
    const char *error_str = aom_codec_err_to_string(res);
    (void)error_str;
    
    // Try to get error details
    aom_codec_error_detail(&codec);
    
    // Don't proceed if initialization failed
    return 0;
  }

  // 10. Apply additional configuration via aom_codec_control
  // Test golden frame intervals
  if (test_gf_intervals) {
    if (min_gf_interval > 0) {
      aom_codec_control(&codec, AV1E_SET_MIN_GF_INTERVAL, min_gf_interval);
    }
    if (max_gf_interval > 0) {
      aom_codec_control(&codec, AV1E_SET_MAX_GF_INTERVAL, max_gf_interval);
    }
  }
  
  // Test adaptive quantization with large scale tile (should trigger error)
  if (test_large_scale_tile && fdp.ConsumeBool()) {
    // Try to set aq_mode when large_scale_tile is enabled (should fail)
    aom_codec_control(&codec, AV1E_SET_AQ_MODE, fdp.ConsumeIntegralInRange<int>(0, 3));
  }

  // 11. Create input image and encode frames (required for two-pass flow)
  if (fdp.remaining_bytes() > 64) {
    aom_image_t raw;
    aom_img_fmt_t fmt = AOM_IMG_FMT_I420;
    
    // Consume image format choice
    uint8_t fmt_choice = fdp.ConsumeIntegral<uint8_t>() % 3;
    if (fmt_choice == 1 && (flags & AOM_CODEC_USE_HIGHBITDEPTH)) {
      fmt = AOM_IMG_FMT_I42016;
    } else if (fmt_choice == 2) {
      fmt = AOM_IMG_FMT_NV12;
    }
    
    unsigned int align = 32;
    
    if (aom_img_alloc(&raw, fmt, width, height, align) == nullptr) {
      aom_codec_destroy(&codec);
      return 0;
    }
    
    // Fill image with fuzzer data
    size_t bytes_to_fill = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes());
    std::vector<uint8_t> image_data = fdp.ConsumeBytes<uint8_t>(bytes_to_fill);
    
    if (!image_data.empty()) {
      size_t copy_size = image_data.size();
      if (copy_size > raw.sz) {
        copy_size = raw.sz;
      }
      memcpy(raw.planes[0], image_data.data(), copy_size);
    }
    
    // Encode the frame
    aom_codec_encode(&codec, &raw, 0, 1, 0);
    
    // Get encoded data (required for two-pass stats accumulation)
    const aom_codec_cx_pkt_t *pkt;
    aom_codec_iter_t iter = nullptr;
    while ((pkt = aom_codec_get_cx_data(&codec, &iter)) != nullptr) {
      // Process packet if needed
      (void)pkt;
    }
    
    // Clean up image
    aom_img_free(&raw);
  }

  // 12. Clean up
  aom_codec_destroy(&codec);

  return 0;
}
