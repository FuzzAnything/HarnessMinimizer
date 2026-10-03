/*
 * Fuzzing harness for libaom AV1 encoder configuration parameter validation (Deep Coverage Phase 3)
 * 
 * PRIMARY TARGET: validate_config function in av1/av1_cx_iface.c (292 blocked branches, 375 blocker hits)
 * SECONDARY TARGET: encoder_set_option function (129 blocked branches)
 * 
 * CRITICAL UNCOVERED VALIDATION PATHS (Based on source code analysis):
 * 1. Individual parameter range validation with extreme values
 * 2. Parameter interdependency validation (e.g., min_gf_interval vs max_gf_interval)
 * 3. Profile-specific validation constraints (Profile 1 monochrome, bit-depth limits)
 * 4. End-usage specific validation (AOM_Q with use_fixed_qp_offsets)
 * 5. Bit-depth and profile compatibility validation
 * 6. Two-pass stats packet structure validation
 * 
 * SEMANTIC DIFFERENTIATION FROM EXISTING HARNESSES:
 * - harness_010: Two-pass encoding validation and general configuration
 * - harness_011: Runtime reconfiguration validation after encoder initialization  
 * - harness_012: SYSTEMATIC EDGE-CASE VALIDATION of individual configuration parameters
 *               Focuses on testing each validation check in isolation with extreme values
 *               Targets parameter interdependencies and profile-specific constraints
 *               Tests validation logic that triggers specific error messages
 * 
 * TESTING STRATEGY:
 * 1. Test individual configuration parameters with extreme/edge values
 * 2. Test parameter interdependencies (e.g., width > forced_max_width)
 * 3. Test profile-specific validation failures
 * 4. Test end-usage specific validation constraints
 * 5. Test encoder_set_option with various option names/values including invalid ones
 * 6. Test two-pass stats buffer validation with malformed data
 * 
 * PRIMARY TARGET APIS:
 * - aom_codec_enc_init (Required Helper: Initialization)
 * - aom_codec_enc_config_set (Target: Tests encoder_set_config → validate_config)
 * - aom_codec_set_option (Target: Tests encoder_set_option)
 * - aom_codec_enc_config_default (Required Helper: Config setup)
 * - aom_codec_destroy (Cleanup)
 */

#include <stddef.h>
#include <stdint.h>
#include <vector>
#include <memory>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <string>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
#include "aom/aom_encoder.h"
#include "aom/aomcx.h"
#include "aom/aom_image.h"
#include "aom/aom_codec.h"
}

// Forward declaration of FIRSTPASS_STATS structure from firstpass.h
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
  double new_mv_count;
  double duration;
  double count;
  double raw_error_stdev;
  int64_t is_flash;
  double noise_var;
  double cor_coeff;
  double log_intra_error;
  double log_coded_error;
} FIRSTPASS_STATS;

// Helper to create malformed two-pass stats buffer for validation testing
aom_fixed_buf_t create_malformed_stats_buffer(FuzzedDataProvider& fdp, bool valid) {
  aom_fixed_buf_t stats_buf = {0};
  size_t packet_sz = sizeof(FIRSTPASS_STATS);
  
  if (valid) {
    // Create valid stats buffer
    int n_packets = fdp.ConsumeIntegralInRange<int>(2, 10);
    size_t total_sz = n_packets * packet_sz;
    
    uint8_t* buffer = new uint8_t[total_sz];
    
    for (int i = 0; i < n_packets; i++) {
      FIRSTPASS_STATS* stats = reinterpret_cast<FIRSTPASS_STATS*>(buffer + i * packet_sz);
      
      // Initialize with reasonable values
      stats->frame = fdp.ConsumeFloatingPoint<double>();
      stats->weight = fdp.ConsumeFloatingPointInRange<double>(0.1, 10.0);
      stats->intra_error = fdp.ConsumeFloatingPointInRange<double>(10.0, 1000.0);
      stats->frame_avg_wavelet_energy = fdp.ConsumeFloatingPointInRange<double>(1.0, 500.0);
      stats->coded_error = fdp.ConsumeFloatingPointInRange<double>(10.0, 1000.0);
      stats->sr_coded_error = fdp.ConsumeFloatingPointInRange<double>(10.0, 1000.0);
      stats->lt_coded_error = fdp.ConsumeFloatingPointInRange<double>(10.0, 1000.0);
      stats->pcnt_inter = fdp.ConsumeFloatingPointInRange<double>(0.0, 1.0);
      stats->pcnt_motion = fdp.ConsumeFloatingPointInRange<double>(0.0, 1.0);
      stats->pcnt_second_ref = fdp.ConsumeFloatingPointInRange<double>(0.0, 1.0);
      stats->pcnt_neutral = fdp.ConsumeFloatingPointInRange<double>(0.0, 1.0);
      stats->intra_skip_pct = fdp.ConsumeFloatingPointInRange<double>(0.0, 1.0);
      stats->inactive_zone_rows = fdp.ConsumeFloatingPointInRange<double>(0.0, 1.0);
      stats->inactive_zone_cols = fdp.ConsumeFloatingPointInRange<double>(0.0, 1.0);
      stats->MVr = fdp.ConsumeFloatingPointInRange<double>(-10.0, 10.0);
      stats->MVc = fdp.ConsumeFloatingPointInRange<double>(-10.0, 10.0);
      stats->MVrv = fdp.ConsumeFloatingPointInRange<double>(-1.0, 1.0);
      stats->MVcv = fdp.ConsumeFloatingPointInRange<double>(-1.0, 1.0);
      stats->mv_in_out_count = fdp.ConsumeFloatingPointInRange<double>(-1.0, 1.0);
      stats->new_mv_count = fdp.ConsumeFloatingPointInRange<double>(0.0, 100.0);
      stats->duration = fdp.ConsumeFloatingPointInRange<double>(0.1, 10.0);
      stats->count = (i == n_packets - 1) ? (n_packets - 1) : i;
    }
    
    stats_buf.buf = buffer;
    stats_buf.sz = total_sz;
  } else {
    // Create malformed stats buffer to trigger validation errors
    int n_packets = fdp.ConsumeIntegralInRange<int>(1, 5);
    size_t total_sz = n_packets * packet_sz;
    
    // Truncate or extend size to trigger validation errors
    if (fdp.ConsumeBool()) {
      total_sz -= packet_sz / 2;  // Truncated packet
    } else if (fdp.ConsumeBool()) {
      total_sz += packet_sz / 3;  // Extra bytes
    }
    
    uint8_t* buffer = new uint8_t[total_sz];
    
    // Fill with random data
    std::vector<uint8_t> random_data = fdp.ConsumeBytes<uint8_t>(total_sz);
    if (random_data.size() >= total_sz) {
      memcpy(buffer, random_data.data(), total_sz);
    } else {
      memset(buffer, 0, total_sz);
    }
    
    stats_buf.buf = buffer;
    stats_buf.sz = total_sz;
  }
  
  return stats_buf;
}

// List of encoder options to test from encoder_set_option function
static const char* encoder_options[] = {
  "min-gf-interval",
  "max-gf-interval", 
  "gf-min-pyr-height",
  "gf-max-pyr-height",
  "cpu-used",
  "auto-altref",
  "noise-sensitivity",
  "sharpness",
  "enable-adaptive-sharpness",
  "static-thresh",
  "row-mt",
  "fp-mt",
  "tile-cols",
  "tile-rows",
  "auto-tiles",
  "enable-tpl-model",
  "arnr-maxframes",
  "arnr-strength",
  "cq-level",
  "aq-mode",
  "deltaq-mode",
  "deltalf-mode",
  "frame-periodic-boost",
  "superblock-size",
  "error-resilient-mode",
  "cdf-update-mode",
  "enable-rect-partitions",
  "enable-ab-partitions",
  "enable-1to4-partitions",
  "min-partition-size",
  "max-partition-size",
  "enable-intra-edge-filter",
  "enable-order-hint",
  "enable-tx64",
  "enable-flip-idtx",
  "enable-rect-tx",
  "enable-dist-wtd-comp",
  "max-reference-frames",
  "reduced-referenc-frame-set",
  "enable-obmc",
  "enable-warped-motion",
  "enable-global-motion",
  "enable-filter-intra",
  "enable-intrabc",
  "enable-palette",
  "enable-intra-angle-delta",
  "enable-cdef",
  "enable-restoration",
  "enable-dual-filter",
  "enable-chroma-deltaq",
  "enable-jnt-comp",
  "enable-ref-frame-mvs",
  "enable-superres",
  "resize-mode",
  "resize-denominator",
  "resize-kf-denominator",
  "superres-mode",
  "superres-denominator",
  "superres-kf-denominator",
  "superres-qthresh",
  "superres-kf-qthresh",
  "monochrome",
  "color-primaries",
  "transfer-characteristics",
  "matrix-coefficients",
  "chroma-sample-position",
  "render-width",
  "render-height",
  "film-grain-test-vector",
  "film-grain-table",
  "bit-depth",
  "input-bit-depth",
  "tune",
  "tune-content",
  "aq-mode",
  "deltaq-mode",
  "deltalf-mode",
  "enable-keyframe-filtering",
  "enable-fwd-kf",
  "enable-bwd-kf",
  "kf-min-dist",
  "kf-max-dist",
  "lag-in-frames",
  "rc-end-usage",
  "rc-target-bitrate",
  "rc-min-quantizer",
  "rc-max-quantizer",
  "rc-undershoot-pct",
  "rc-overshoot-pct",
  "rc-buf-sz",
  "rc-buf-initial-sz",
  "rc-buf-optimal-sz",
  "rc-2pass-vbr-bias-pct",
  "rc-2pass-vbr-minsection-pct",
  "rc-2pass-vbr-maxsection-pct",
  "kf-mode",
  "adaptive-quantization",
  "aq-strength",
  "arnr-type",
  "speed",
  "frame-parallel",
  "tile-groups",
  "profile",
  "disable-kf",
  "static-thresh",
  "drop-frame",
  "resize-allowed",
  "resize-up-thresh",
  "resize-down-thresh",
  "end-usage",
  "undershoot-pct",
  "overshoot-pct",
  "buf-sz",
  "buf-initial-sz",
  "buf-optimal-sz",
  "2pass-vbr-bias-pct",
  "2pass-vbr-minsection-pct",
  "2pass-vbr-maxsection-pct",
  "fwd-kf",
  "bwd-kf",
  "no-scene-cut",
  "frame-boost",
  "noise-sens",
  "sharp",
  "static-thr",
  "temporal-layers",
  "min-q",
  "max-q",
  "min-bitrate",
  "max-bitrate",
  "min-section-pct",
  "max-section-pct"
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Minimum size check - need enough data for complex validation testing
  if (size < 256) {
    return 0;
  }

  FuzzedDataProvider fdp(data, size);
  
  // Get encoder interface
  aom_codec_iface_t *encoder = aom_codec_av1_cx();
  if (!encoder) {
    return 0;
  }

  // Initialize encoder configuration with defaults
  aom_codec_enc_cfg_t cfg;
  aom_codec_err_t res;
  
  // Consume usage mode
  unsigned int usage = fdp.ConsumeIntegralInRange<unsigned int>(0, 2);
  
  res = aom_codec_enc_config_default(encoder, &cfg, usage);
  if (res != AOM_CODEC_OK) {
    return 0;
  }

  // Test Strategy 1: Individual parameter validation with extreme values
  // Based on validate_config function analysis
  
  uint8_t test_case = fdp.ConsumeIntegral<uint8_t>() % 8;
  
  switch (test_case) {
    case 0: {
      // Test g_forced_max_frame_width/height validation (lines 688-693)
      cfg.g_forced_max_frame_width = fdp.ConsumeIntegralInRange<unsigned int>(0, 65536);
      cfg.g_forced_max_frame_height = fdp.ConsumeIntegralInRange<unsigned int>(0, 65536);
      
      // Set width/height to potentially exceed forced max
      if (cfg.g_forced_max_frame_width > 0) {
        cfg.g_w = fdp.ConsumeIntegralInRange<unsigned int>(1, 65536);
      }
      if (cfg.g_forced_max_frame_height > 0) {
        cfg.g_h = fdp.ConsumeIntegralInRange<unsigned int>(1, 65536);
      }
      break;
    }
    
    case 1: {
      // Test max_frame_area > 2^30 validation (lines 703-705)
      // Set very large dimensions to potentially exceed 2^30 area
      cfg.g_w = fdp.ConsumeIntegralInRange<unsigned int>(32768, 65536);
      cfg.g_h = fdp.ConsumeIntegralInRange<unsigned int>(32768, 65536);
      cfg.g_forced_max_frame_width = 0;
      cfg.g_forced_max_frame_height = 0;
      break;
    }
    
    case 2: {
      // Test golden frame interval constraints (lines 738-741)
      // This requires extra_cfg which we can't directly modify
      // We'll test via encoder_set_option instead
      break;
    }
    
    case 3: {
      // Test profile-specific validation (lines 834-845)
      cfg.g_profile = fdp.ConsumeIntegralInRange<unsigned int>(0, 2);
      cfg.monochrome = fdp.ConsumeBool() ? 1 : 0;
      // Use correct enum values for bit depth
      unsigned int bit_depth_val = fdp.ConsumeIntegralInRange<unsigned int>(8, 12);
      if (bit_depth_val == 8) cfg.g_bit_depth = AOM_BITS_8;
      else if (bit_depth_val == 10) cfg.g_bit_depth = AOM_BITS_10;
      else if (bit_depth_val == 12) cfg.g_bit_depth = AOM_BITS_12;
      else cfg.g_bit_depth = AOM_BITS_8;
      cfg.g_input_bit_depth = fdp.ConsumeIntegralInRange<unsigned int>(8, 12);
      break;
    }
    
    case 4: {
      // Test end-usage specific validation (lines 847-853)
      cfg.rc_end_usage = static_cast<aom_rc_mode>(fdp.ConsumeIntegralInRange<int>(AOM_VBR, AOM_Q));
      cfg.use_fixed_qp_offsets = fdp.ConsumeIntegralInRange<unsigned int>(0, 2);
      break;
    }
    
    case 5: {
      // Test two-pass encoding validation (lines 804-823)
      cfg.g_pass = static_cast<aom_enc_pass>(fdp.ConsumeIntegralInRange<int>(AOM_RC_ONE_PASS, AOM_RC_THIRD_PASS));
      
      if (cfg.g_pass >= AOM_RC_SECOND_PASS) {
        bool create_valid_stats = fdp.ConsumeBool();
        aom_fixed_buf_t stats_buf = create_malformed_stats_buffer(fdp, create_valid_stats);
        cfg.rc_twopass_stats_in = stats_buf;
        // Note: Buffer memory leak here but acceptable for fuzzing
      }
      break;
    }
    
    case 6: {
      // Test large scale tile + aq_mode conflict (lines 790-793)
      cfg.large_scale_tile = fdp.ConsumeBool() ? 1 : 0;
      // aq_mode is in extra_cfg, test via encoder_set_option
      break;
    }
    
    case 7: {
      // Test various other validation constraints
      cfg.g_timebase.num = fdp.ConsumeIntegralInRange<int>(1, 1000000000);
      cfg.g_timebase.den = fdp.ConsumeIntegralInRange<int>(1, 1000000000);
      cfg.rc_target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(0, 2000000);
      cfg.rc_max_quantizer = fdp.ConsumeIntegralInRange<unsigned int>(0, 63);
      cfg.rc_min_quantizer = fdp.ConsumeIntegralInRange<unsigned int>(0, cfg.rc_max_quantizer);
      cfg.g_threads = fdp.ConsumeIntegralInRange<unsigned int>(0, 64);
      cfg.g_lag_in_frames = fdp.ConsumeIntegralInRange<unsigned int>(0, 25);
      break;
    }
  }

  // Initialize encoder to test configuration validation
  aom_codec_ctx_t codec;
  aom_codec_flags_t flags = 0;
  
  if (fdp.ConsumeBool()) {
    flags |= AOM_CODEC_USE_HIGHBITDEPTH;
  }
  
  // Try to initialize with potentially invalid configuration
  res = aom_codec_enc_init_ver(&codec, encoder, &cfg, flags, AOM_ENCODER_ABI_VERSION);
  
  if (res == AOM_CODEC_OK) {
    // Test Strategy 2: encoder_set_option with various options
    // This tests the encoder_set_option function (129 blocked branches)
    
    int num_options_to_test = fdp.ConsumeIntegralInRange<int>(1, 10);
    for (int i = 0; i < num_options_to_test && fdp.remaining_bytes() > 10; i++) {
      // Select random option from the list
      size_t option_idx = fdp.ConsumeIntegralInRange<size_t>(0, sizeof(encoder_options)/sizeof(encoder_options[0]) - 1);
      const char* option_name = encoder_options[option_idx];
      
      // Generate random value for the option
      std::string option_value;
      if (fdp.ConsumeBool()) {
        // Numeric value
        int int_val = fdp.ConsumeIntegral<int>();
        option_value = std::to_string(int_val);
      } else {
        // String value
        option_value = fdp.ConsumeRandomLengthString(50);
      }
      
      // Try to set the option
      aom_codec_set_option(&codec, option_name, option_value.c_str());
      
      // Also test with invalid option names
      if (fdp.ConsumeBool() && fdp.remaining_bytes() > 5) {
        std::string invalid_option = fdp.ConsumeRandomLengthString(20);
        aom_codec_set_option(&codec, invalid_option.c_str(), "1");
      }
    }
    
    // Test Strategy 3: Try to set configuration after initialization
    // This tests runtime validation paths
    if (fdp.ConsumeBool() && fdp.remaining_bytes() > 32) {
      // Modify some configuration values
      aom_codec_enc_cfg_t new_cfg = cfg;
      new_cfg.g_w = fdp.ConsumeIntegralInRange<unsigned int>(16, 256);
      new_cfg.g_h = fdp.ConsumeIntegralInRange<unsigned int>(16, 256);
      
      res = aom_codec_enc_config_set(&codec, &new_cfg);
      // Ignore result - we're testing validation paths
    }
    
    // Clean up
    aom_codec_destroy(&codec);
  }
  
  // Clean up any allocated two-pass stats buffers
  if (cfg.g_pass >= AOM_RC_SECOND_PASS && cfg.rc_twopass_stats_in.buf) {
    delete[] static_cast<uint8_t*>(cfg.rc_twopass_stats_in.buf);
  }

  return 0;
}
