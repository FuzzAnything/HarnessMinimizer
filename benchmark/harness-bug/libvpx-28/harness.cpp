/*
 * Fuzzing harness for libvpx decoder initialization and control operations
 * Targets: vpx_codec_dec_init_ver (17 undiscovered branches), 
 *          vpx_codec_control_ (7 undiscovered branches),
 *          vpx_codec_error_detail (6 undiscovered branches), 
 *          vpx_codec_iface_name (2 undiscovered branches),
 *          vpx_codec_get_caps (2 undiscovered branches),
 *          vpx_codec_error (3 undiscovered branches)
 * 
 * This harness targets decoder initialization paths, control operations, and
 * error handling APIs that are currently 0-50% covered. Follows invocation
 * sequence: iface name -> get caps -> dec init ver -> control -> decode -> 
 * get frame -> error/detail -> destroy. Focuses on semantic diversity from
 * existing decoder harnesses (000: basic decode, 003: decoder customization).
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <algorithm>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>
#include "vpx/vp8dx.h"
#include "vpx/vpx_decoder.h"
#include "vpx/vpx_codec.h"

#define MIN_INPUT_SIZE 64

// Simple IVF frame header simulation
#define IVF_FRAME_HDR_SZ (4 + 8) /* 4 byte size + 8 byte timestamp */

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < MIN_INPUT_SIZE) {
    return 0;  // Insufficient input for meaningful testing
  }

  FuzzedDataProvider fdp(data, size);

  // Step 1: Consume decoder choice and configuration from fuzzer input
  uint8_t decoder_choice = fdp.ConsumeIntegral<uint8_t>() % 3;  // 0=VP8, 1=VP9, 2=try both
  uint8_t thread_count = fdp.ConsumeIntegralInRange<uint8_t>(1, 64);
  bool use_postproc = fdp.ConsumeBool();
  bool use_error_concealment = fdp.ConsumeBool();
  bool use_frame_threading = fdp.ConsumeBool();
  bool use_input_fragments = fdp.ConsumeBool();
  uint8_t init_flags_variation = fdp.ConsumeIntegral<uint8_t>() % 4;

  // Step 2: Choose decoder interface based on fuzzer input
  vpx_codec_iface_t* iface = nullptr;
  const char* iface_name = nullptr;
  
  if (decoder_choice == 0) {
    iface = vpx_codec_vp8_dx();
  } else if (decoder_choice == 1) {
    iface = vpx_codec_vp9_dx();
  } else {
    // Try both interfaces sequentially
    iface = vpx_codec_vp8_dx();
    // We'll test VP9 later in the control operations
  }

  // Step 3: Call vpx_codec_iface_name to identify decoder interface
  if (iface != nullptr) {
    iface_name = vpx_codec_iface_name(iface);
    // iface_name is a string describing the decoder interface
    // Can be used for logging or conditional logic
  }

  // Step 4: Call vpx_codec_get_caps to query decoder capabilities
  vpx_codec_caps_t caps = 0;
  if (iface != nullptr) {
    caps = vpx_codec_get_caps(iface);
    // caps contains bitfield of supported capabilities
  }

  // Step 5: Configure decoder initialization
  vpx_codec_ctx_t codec;
  vpx_codec_dec_cfg_t cfg = { thread_count, 0, 0 };
  vpx_codec_flags_t flags = 0;

  // Set flags based on fuzzer input
  if (use_postproc && (caps & VPX_CODEC_CAP_POSTPROC)) {
    flags |= VPX_CODEC_USE_POSTPROC;
  }
  if (use_error_concealment && (caps & VPX_CODEC_CAP_ERROR_CONCEALMENT)) {
    flags |= VPX_CODEC_USE_ERROR_CONCEALMENT;
  }
  if (use_frame_threading && (caps & VPX_CODEC_CAP_FRAME_THREADING)) {
    flags |= VPX_CODEC_USE_FRAME_THREADING;
  }
  if (use_input_fragments && (caps & VPX_CODEC_CAP_INPUT_FRAGMENTS)) {
    flags |= VPX_CODEC_USE_INPUT_FRAGMENTS;
  }

  // Vary initialization approach based on fuzzer input
  vpx_codec_err_t init_err = VPX_CODEC_ERROR;
  
  switch (init_flags_variation) {
    case 0:
      // Standard initialization with all configured flags
      init_err = vpx_codec_dec_init_ver(&codec, iface, &cfg, flags, VPX_DECODER_ABI_VERSION);
      break;
    case 1:
      // Initialize with NULL config (let decoder determine defaults)
      init_err = vpx_codec_dec_init_ver(&codec, iface, NULL, flags, VPX_DECODER_ABI_VERSION);
      break;
    case 2:
      // Initialize with minimal flags (0)
      init_err = vpx_codec_dec_init_ver(&codec, iface, &cfg, 0, VPX_DECODER_ABI_VERSION);
      break;
    case 3:
      // Try initialization, fall back on VPX_CODEC_INCAPABLE
      init_err = vpx_codec_dec_init_ver(&codec, iface, &cfg, flags, VPX_DECODER_ABI_VERSION);
      if (init_err == VPX_CODEC_INCAPABLE) {
        // Try without the problematic flags
        flags = 0;
        init_err = vpx_codec_dec_init_ver(&codec, iface, &cfg, flags, VPX_DECODER_ABI_VERSION);
      }
      break;
  }

  // Step 6: Check initialization result and handle errors
  if (init_err != VPX_CODEC_OK) {
    // Test error handling APIs even when initialization fails
    const char* error_str = vpx_codec_error(&codec);
    const char* error_detail = vpx_codec_error_detail(&codec);
    
    // Use the error strings (they may be NULL if context not properly initialized)
    if (error_str != nullptr) {
      // Could log or use error string for conditional logic
    }
    if (error_detail != nullptr) {
      // Could log or use error detail for conditional logic
    }
    
    // Try alternative decoder if first attempt failed and we were in "try both" mode
    if (decoder_choice == 2 && iface == vpx_codec_vp8_dx()) {
      // Try VP9 instead
      iface = vpx_codec_vp9_dx();
      init_err = vpx_codec_dec_init_ver(&codec, iface, &cfg, flags, VPX_DECODER_ABI_VERSION);
    }
    
    if (init_err != VPX_CODEC_OK) {
      return 0;  // Cannot proceed without valid decoder context
    }
  }

  // Step 7: Test vpx_codec_control_ with various control IDs
  // Consume control operation parameters from fuzzer input
  uint8_t num_control_ops = fdp.ConsumeIntegralInRange<uint8_t>(0, 8);
  
  for (uint8_t i = 0; i < num_control_ops && fdp.remaining_bytes() > 0; i++) {
    uint8_t control_id_type = fdp.ConsumeIntegral<uint8_t>() % 4;
    vpx_codec_err_t control_err = VPX_CODEC_ERROR;
    
    switch (control_id_type) {
      case 0:
        // VP8/VP9 common control: VP8D_GET_LAST_REF_UPDATES
        {
          int ref_updates = 0;
          control_err = vpx_codec_control(&codec, VP8D_GET_LAST_REF_UPDATES, &ref_updates);
        }
        break;
      case 1:
        // VP8/VP9 common control: VP8D_GET_FRAME_CORRUPTED  
        {
          int frame_corrupted = 0;
          control_err = vpx_codec_control(&codec, VP8D_GET_FRAME_CORRUPTED, &frame_corrupted);
        }
        break;
      case 2:
        // VP9-specific control if using VP9 decoder
        if (iface == vpx_codec_vp9_dx() || decoder_choice == 1) {
          // VP9D_GET_FRAME_SIZE - takes int[2] array
          {
            int frame_size[2] = {0, 0};
            control_err = vpx_codec_control(&codec, VP9D_GET_FRAME_SIZE, frame_size);
          }
        }
        break;
      case 3:
        // VP9-specific control: VP9D_SET_LOOP_FILTER_OPT
        if (iface == vpx_codec_vp9_dx() || decoder_choice == 1) {
          bool loop_filter_opt = fdp.ConsumeBool();
          control_err = vpx_codec_control(&codec, VP9D_SET_LOOP_FILTER_OPT, loop_filter_opt ? 1 : 0);
        }
        break;
    }
    
    // Check control operation result
    if (control_err != VPX_CODEC_OK) {
      // Test error handling for failed control operations
      const char* control_error = vpx_codec_error(&codec);
      const char* control_error_detail = vpx_codec_error_detail(&codec);
      
      // Use error information (may be NULL)
      if (control_error != nullptr) {
        // Could log or use for conditional logic
      }
    }
  }

  // Step 8: Test decoding with remaining fuzzer input as compressed data
  // Prepare compressed data for decoding
  size_t decode_data_size = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes());
  std::vector<uint8_t> decode_data = fdp.ConsumeBytes<uint8_t>(decode_data_size);
  
  if (decode_data_size > 0) {
    vpx_codec_err_t decode_err = vpx_codec_decode(&codec, 
                                                  decode_data.data(), 
                                                  decode_data_size, 
                                                  NULL,  // user_priv
                                                  0);    // deadline
    
    // Step 9: Try to get decoded frame(s)
    if (decode_err == VPX_CODEC_OK) {
      vpx_codec_iter_t iter = NULL;
      vpx_image_t* img;
      
      while ((img = vpx_codec_get_frame(&codec, &iter)) != NULL) {
        // Frame retrieved successfully
        // Could process frame data here
        (void)img;  // Avoid unused variable warning
      }
    }
    
    // Step 10: Check decoding errors
    if (decode_err != VPX_CODEC_OK) {
      const char* decode_error = vpx_codec_error(&codec);
      const char* decode_error_detail = vpx_codec_error_detail(&codec);
      
      // Use error information
      if (decode_error != nullptr) {
        // Could log or use for conditional logic
      }
    }
  }

  // Step 11: Test stream info APIs
  if (fdp.remaining_bytes() > 4) {
    vpx_codec_stream_info_t si;
    si.sz = sizeof(si);
    
    // Test vpx_codec_peek_stream_info (doesn't require initialized decoder)
    size_t peek_size = fdp.ConsumeIntegralInRange<size_t>(0, std::min<size_t>(fdp.remaining_bytes(), 1024));
    std::vector<uint8_t> peek_data = fdp.ConsumeBytes<uint8_t>(peek_size);
    
    if (peek_size > 0 && iface != nullptr) {
      vpx_codec_err_t peek_err = vpx_codec_peek_stream_info(iface, 
                                                           peek_data.data(), 
                                                           peek_data.size(), 
                                                           &si);
      (void)peek_err;  // Result not critical for fuzzing
    }
    
    // Test vpx_codec_get_stream_info (requires initialized decoder)
    vpx_codec_err_t stream_info_err = vpx_codec_get_stream_info(&codec, &si);
    (void)stream_info_err;  // Result not critical for fuzzing
  }

  // Step 12: Final error checking before cleanup
  const char* final_error = vpx_codec_error(&codec);
  const char* final_error_detail = vpx_codec_error_detail(&codec);
  
  // Use error information one last time
  if (final_error != nullptr) {
    // Could log or use for conditional logic
  }

  // Step 13: Clean up decoder instance
  vpx_codec_err_t destroy_err = vpx_codec_destroy(&codec);
  (void)destroy_err;  // Result not critical for fuzzing

  return 0;
}
