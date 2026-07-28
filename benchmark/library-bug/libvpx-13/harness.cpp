/*
 * Fuzzing harness for libvpx VP9 encoder configuration validation testing
 * Target: validate_config function in vp9/vp9_cx_iface.c with 309 blocked branches
 * Focus: Advanced two-pass statistics validation and complex configuration relationships
 *        with semantic diversity from harness_017 and harness_018
 * APIs: vpx_codec_enc_config_default, vpx_codec_enc_init_ver, vpx_codec_enc_config_set, 
 *       vpx_codec_control, vpx_codec_encode, vpx_codec_destroy
 * Semantic diversity: This harness specifically targets complex validation paths not covered
 *                     by previous harnesses:
 *                     1. Two-pass statistics packet validation (complex error paths)
 *                     2. Profile-bit-depth relationship constraints
 *                     3. New vizier RC parameter validation (lines 375-389)
 *                     4. Color space and range validation
 *                     5. Complex golden frame interval relationships
 *                     6. ARF group formation validation
 * Coverage goal: Target remaining blocked branches in validate_config function by testing:
 *                1. Two-pass statistics validation with packet count, EOS, and layer-specific checks
 *                2. Profile-bit-depth constraints (PROFILE_1 can't use high bit-depth, etc.)
 *                3. vizier RC parameter denominator validation (1-1000 range)
 *                4. Color space (VPX_CS_UNKNOWN to VPX_CS_SRGB) and range validation
 *                5. Complex min_gf_interval/max_gf_interval relationships with conditional checks
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <algorithm>
#include <vector>
#include <memory>

#include <fuzzer/FuzzedDataProvider.h>
#include "vpx/vp8cx.h"
#include "vpx/vpx_encoder.h"
#include "vpx/vpx_image.h"

// Copy of FIRSTPASS_STATS from vp9/encoder/vp9_firstpass_stats.h
// to avoid dependency on internal headers not installed in fuzzer build
typedef struct {
  double frame;
  double weight;
  double intra_error;
  double coded_error;
  double sr_coded_error;
  double frame_noise_energy;
  double pcnt_inter;
  double pcnt_motion;
  double pcnt_second_ref;
  double pcnt_neutral;
  double pcnt_intra_low;   // Coded intra but low variance
  double pcnt_intra_high;  // Coded intra high variance
  double intra_skip_pct;
  double intra_smooth_pct;    // % of blocks that are smooth
  double inactive_zone_rows;  // Image mask rows top and bottom.
  double inactive_zone_cols;  // Image mask columns at left and right edges.
  double MVr;
  double mvr_abs;
  double MVc;
  double mvc_abs;
  double MVrv;
  double MVcv;
  double mv_in_out_count;
  double duration;
  double count;
  double new_mv_count;
  int64_t spatial_layer_id;
} FIRSTPASS_STATS;
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Minimum size needed: configuration parameters + two-pass stats
  if (size < 1024) {
    return 0;
  }

  FuzzedDataProvider fdp(data, size);

  // Step 1: Get VP9 encoder interface
  vpx_codec_iface_t* iface = vpx_codec_vp9_cx();
  if (iface == NULL) {
    return 0;
  }

  // Step 2: Get default encoder configuration
  vpx_codec_enc_cfg_t cfg;
  vpx_codec_err_t err = vpx_codec_enc_config_default(iface, &cfg, 0);
  if (err != VPX_CODEC_OK) {
    return 0;
  }

  // Step 3: Consume basic configuration parameters
  unsigned int width = fdp.ConsumeIntegralInRange<unsigned int>(64, 512);
  unsigned int height = fdp.ConsumeIntegralInRange<unsigned int>(64, 512);
  
  // Ensure even dimensions for YUV formats
  if (width % 2) width++;
  if (height % 2) height++;
  
  cfg.g_w = width;
  cfg.g_h = height;
  cfg.rc_target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 10000);
  cfg.g_timebase.num = 1;
  cfg.g_timebase.den = fdp.ConsumeIntegralInRange<unsigned int>(24, 60);

  // Step 4: Choose test scenario based on fuzzer input
  unsigned int test_scenario = fdp.ConsumeIntegralInRange<unsigned int>(0, 5);

  switch (test_scenario) {
    case 0: {
      // Test 1: Two-pass statistics validation (complex error paths)
      // From validate_config lines 302-353
      
      // Set two-pass mode
      cfg.g_pass = VPX_RC_LAST_PASS;
      
      // Create simulated two-pass statistics
      size_t packet_sz = sizeof(FIRSTPASS_STATS);
      unsigned int n_packets = fdp.ConsumeIntegralInRange<unsigned int>(2, 20);
      size_t stats_size = n_packets * packet_sz;
      
      // Consume bytes for stats buffer
      std::vector<uint8_t> stats_buffer = fdp.ConsumeBytes<uint8_t>(stats_size);
      
      if (stats_buffer.size() >= 2 * packet_sz) {
        // Configure spatial and temporal layers for layer-specific validation
        cfg.ss_number_layers = fdp.ConsumeIntegralInRange<unsigned int>(1, 3);
        cfg.ts_number_layers = fdp.ConsumeIntegralInRange<unsigned int>(1, 3);
        
        // Ensure we don't exceed VPX_MAX_LAYERS
        if (cfg.ss_number_layers * cfg.ts_number_layers > VPX_MAX_LAYERS) {
          cfg.ss_number_layers = 1;
          cfg.ts_number_layers = 1;
        }
        
        // Set the stats buffer
        cfg.rc_twopass_stats_in.buf = stats_buffer.data();
        cfg.rc_twopass_stats_in.sz = stats_buffer.size();
        
        // Initialize encoder to trigger validate_config
        vpx_codec_ctx_t codec;
        vpx_codec_flags_t flags = 0;
        
        err = vpx_codec_enc_init_ver(&codec, iface, &cfg, flags, VPX_ENCODER_ABI_VERSION);
        
        // Clean up regardless of result
        if (err == VPX_CODEC_OK) {
          vpx_codec_destroy(&codec);
        }
      }
      break;
    }
    
    case 1: {
      // Test 2: Profile-bit-depth relationship constraints
      // From validate_config lines 355-371
      
      // Consume profile and bit-depth values
      unsigned int profile = fdp.ConsumeIntegralInRange<unsigned int>(0, 3);
      unsigned int bit_depth = fdp.ConsumeIntegralInRange<unsigned int>(8, 12);
      unsigned int input_bit_depth = fdp.ConsumeIntegralInRange<unsigned int>(8, 12);
      
      cfg.g_profile = profile;
      cfg.g_bit_depth = (vpx_bit_depth_t)bit_depth;
      cfg.g_input_bit_depth = input_bit_depth;
      
      // Test high bit-depth constraints
      if (profile <= 1 && bit_depth > 8) {
        // This should trigger validation error: "Codec high bit-depth not supported in profile < 2"
      }
      
      if (profile <= 1 && input_bit_depth > 8) {
        // This should trigger validation error: "Source high bit-depth not supported in profile < 2"
      }
      
      if (profile > 1 && bit_depth == 8) {
        // This should trigger validation error: "Codec bit-depth 8 not supported in profile > 1"
      }
      
      // Initialize encoder
      vpx_codec_ctx_t codec;
      vpx_codec_flags_t flags = 0;
      
      err = vpx_codec_enc_init_ver(&codec, iface, &cfg, flags, VPX_ENCODER_ABI_VERSION);
      
      if (err == VPX_CODEC_OK) {
        vpx_codec_destroy(&codec);
      }
      break;
    }
    
    case 2: {
      // Test 3: New vizier RC parameter validation (lines 375-389)
      // These parameters have denominator validation (1-1000 range)
      
      // Set various vizier RC parameters with fuzzed denominators
      cfg.use_vizier_rc_params = fdp.ConsumeBool() ? 1 : 0;
      cfg.active_wq_factor.den = fdp.ConsumeIntegralInRange<unsigned int>(1, 1000);
      cfg.err_per_mb_factor.den = fdp.ConsumeIntegralInRange<unsigned int>(1, 1000);
      cfg.sr_default_decay_limit.den = fdp.ConsumeIntegralInRange<unsigned int>(1, 1000);
      cfg.sr_diff_factor.den = fdp.ConsumeIntegralInRange<unsigned int>(1, 1000);
      cfg.kf_err_per_mb_factor.den = fdp.ConsumeIntegralInRange<unsigned int>(1, 1000);
      cfg.kf_frame_min_boost_factor.den = fdp.ConsumeIntegralInRange<unsigned int>(1, 1000);
      cfg.kf_frame_max_boost_subs_factor.den = fdp.ConsumeIntegralInRange<unsigned int>(1, 1000);
      cfg.kf_max_total_boost_factor.den = fdp.ConsumeIntegralInRange<unsigned int>(1, 1000);
      cfg.gf_max_total_boost_factor.den = fdp.ConsumeIntegralInRange<unsigned int>(1, 1000);
      cfg.gf_frame_max_boost_factor.den = fdp.ConsumeIntegralInRange<unsigned int>(1, 1000);
      cfg.zm_factor.den = fdp.ConsumeIntegralInRange<unsigned int>(1, 1000);
      cfg.rd_mult_inter_qp_fac.den = fdp.ConsumeIntegralInRange<unsigned int>(1, 1000);
      cfg.rd_mult_arf_qp_fac.den = fdp.ConsumeIntegralInRange<unsigned int>(1, 1000);
      cfg.rd_mult_key_qp_fac.den = fdp.ConsumeIntegralInRange<unsigned int>(1, 1000);
      
      // Set numerators (not validated but need reasonable values)
      cfg.active_wq_factor.num = 1;
      cfg.err_per_mb_factor.num = 1;
      cfg.sr_default_decay_limit.num = 1;
      cfg.sr_diff_factor.num = 1;
      cfg.kf_err_per_mb_factor.num = 1;
      cfg.kf_frame_min_boost_factor.num = 1;
      cfg.kf_frame_max_boost_subs_factor.num = 1;
      cfg.kf_max_total_boost_factor.num = 1;
      cfg.gf_max_total_boost_factor.num = 1;
      cfg.gf_frame_max_boost_factor.num = 1;
      cfg.zm_factor.num = 1;
      cfg.rd_mult_inter_qp_fac.num = 1;
      cfg.rd_mult_arf_qp_fac.num = 1;
      cfg.rd_mult_key_qp_fac.num = 1;
      
      // Initialize encoder
      vpx_codec_ctx_t codec;
      vpx_codec_flags_t flags = 0;
      
      err = vpx_codec_enc_init_ver(&codec, iface, &cfg, flags, VPX_ENCODER_ABI_VERSION);
      
      if (err == VPX_CODEC_OK) {
        vpx_codec_destroy(&codec);
      }
      break;
    }
    
    case 3: {
      // Test 4: Color space and range validation (lines 371-372)
      
      // Consume color space and range values
      unsigned int color_space_val = fdp.ConsumeIntegralInRange<unsigned int>(VPX_CS_UNKNOWN, VPX_CS_SRGB);
      unsigned int color_range_val = fdp.ConsumeIntegralInRange<unsigned int>(VPX_CR_STUDIO_RANGE, VPX_CR_FULL_RANGE);
      
      // Initialize encoder first
      vpx_codec_ctx_t codec;
      vpx_codec_flags_t flags = 0;
      
      err = vpx_codec_enc_init_ver(&codec, iface, &cfg, flags, VPX_ENCODER_ABI_VERSION);
      
      if (err == VPX_CODEC_OK) {
        // Set color space via control API (these map to extra_cfg fields)
        vpx_codec_control(&codec, VP9E_SET_COLOR_SPACE, color_space_val);
        vpx_codec_control(&codec, VP9E_SET_COLOR_RANGE, color_range_val);
        
        // Also test invalid values beyond range
        unsigned int invalid_color_space = fdp.ConsumeIntegralInRange<unsigned int>(VPX_CS_SRGB + 1, 255);
        unsigned int invalid_color_range = fdp.ConsumeIntegralInRange<unsigned int>(VPX_CR_FULL_RANGE + 1, 255);
        
        vpx_codec_control(&codec, VP9E_SET_COLOR_SPACE, invalid_color_space);
        vpx_codec_control(&codec, VP9E_SET_COLOR_RANGE, invalid_color_range);
        
        vpx_codec_destroy(&codec);
      }
      break;
    }
    
    case 4: {
      // Test 5: Complex golden frame interval relationships (lines 224-230)
      // and ARF group formation validation (lines 232-237)
      
      // Consume golden frame interval values
      unsigned int min_gf_interval = fdp.ConsumeIntegralInRange<unsigned int>(0, 20);
      unsigned int max_gf_interval = fdp.ConsumeIntegralInRange<unsigned int>(0, 20);
      
      // Test different combinations:
      // 1. max_gf_interval > 0 but < 2 (should trigger error at line 225)
      // 2. Both > 0 but max < min (should trigger error at line 228)
      // 3. Valid combinations
      
      // Set lag-in-frames to test ARF group formation
      unsigned int lag_in_frames;
      unsigned int lag_choice = fdp.ConsumeIntegralInRange<unsigned int>(0, 2);
      
      switch (lag_choice) {
        case 0: lag_in_frames = 0; break;  // low delay mode (always valid)
        case 1: 
          // Valid: lag >= max_gf_interval + 2
          lag_in_frames = (max_gf_interval > 0) ? max_gf_interval + 2 + fdp.ConsumeIntegralInRange<unsigned int>(0, 5) : 5;
          break;
        case 2:
          // Invalid: lag > 0 but < max_gf_interval + 2
          lag_in_frames = (max_gf_interval > 0) ? fdp.ConsumeIntegralInRange<unsigned int>(1, max_gf_interval + 1) : 1;
          break;
        default: lag_in_frames = 0; break;
      }
      
      cfg.g_lag_in_frames = lag_in_frames;
      
      // Initialize encoder
      vpx_codec_ctx_t codec;
      vpx_codec_flags_t flags = 0;
      
      err = vpx_codec_enc_init_ver(&codec, iface, &cfg, flags, VPX_ENCODER_ABI_VERSION);
      
      if (err == VPX_CODEC_OK) {
        // Set golden frame intervals via control API
        vpx_codec_control(&codec, VP9E_SET_MIN_GF_INTERVAL, min_gf_interval);
        vpx_codec_control(&codec, VP9E_SET_MAX_GF_INTERVAL, max_gf_interval);
        
        vpx_codec_destroy(&codec);
      }
      break;
    }
    
    case 5: {
      // Test 6: Resize validation (lines 239-242) and miscellaneous range checks
      
      // Enable resize allowed
      cfg.rc_resize_allowed = 1;
      
      // Set scaled dimensions (must be 0 <= scaled <= original)
      unsigned int scaled_width = fdp.ConsumeIntegralInRange<unsigned int>(0, width);
      unsigned int scaled_height = fdp.ConsumeIntegralInRange<unsigned int>(0, height);
      
      cfg.rc_scaled_width = scaled_width;
      cfg.rc_scaled_height = scaled_height;
      
      // Test various other range checks with edge cases
      cfg.rc_max_quantizer = fdp.ConsumeIntegralInRange<unsigned int>(0, 63);
      cfg.rc_min_quantizer = fdp.ConsumeIntegralInRange<unsigned int>(0, cfg.rc_max_quantizer);
      
      // Test boolean validation
      cfg.rc_resize_allowed = fdp.ConsumeBool() ? 1 : 0;
      
      // Initialize encoder
      vpx_codec_ctx_t codec;
      vpx_codec_flags_t flags = 0;
      
      err = vpx_codec_enc_init_ver(&codec, iface, &cfg, flags, VPX_ENCODER_ABI_VERSION);
      
      if (err == VPX_CODEC_OK) {
        // Test various control parameters that map to extra_cfg validation
        unsigned int aq_mode = fdp.ConsumeIntegralInRange<unsigned int>(0, 3);  // AQ_MODE_COUNT - 2
        unsigned int alt_ref_aq = fdp.ConsumeIntegralInRange<unsigned int>(0, 1);
        unsigned int frame_periodic_boost = fdp.ConsumeIntegralInRange<unsigned int>(0, 1);
        
        vpx_codec_control(&codec, VP9E_SET_AQ_MODE, aq_mode);
        vpx_codec_control(&codec, VP9E_SET_ALT_REF_AQ, alt_ref_aq);
        vpx_codec_control(&codec, VP9E_SET_FRAME_PERIODIC_BOOST, frame_periodic_boost);
        
        vpx_codec_destroy(&codec);
      }
      break;
    }
  }

  return 0;
}
