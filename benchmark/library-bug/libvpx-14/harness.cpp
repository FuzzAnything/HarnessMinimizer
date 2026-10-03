/*
 * Harness 015: Advanced decoder callback APIs with comprehensive lifecycle testing
 * 
 * Target APIs: vpx_codec_set_frame_buffer_functions, vpx_codec_register_put_slice_cb, 
 *              vpx_codec_register_put_frame_cb
 * 
 * Differentiation from harness_005:
 * 1. Tests callback registration at different lifecycle stages (before/after decode)
 * 2. Tests multiple callback combinations and permutations
 * 3. Focuses on error conditions and edge cases in callback APIs
 * 4. Tests callback behavior with different decoder configurations
 * 5. Tests callback chaining and sequential registration
 * 6. Uses more dynamic callback implementations based on fuzzer input
 * 
 * Strategy:
 * 1. Test callback registration before and after decoder initialization
 * 2. Test multiple callback registration sequences
 * 3. Test callback behavior with different decoder flags
 * 4. Test error conditions (NULL callbacks, invalid parameters)
 * 5. Test external frame buffer allocation failure scenarios
 * 6. Test callback invocation with corrupted/partial frame data
 */

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <algorithm>
#include <memory>
#include <vector>
#include <cstring>
#include <functional>
#include <iostream>

#include "vpx/vp8dx.h"
#include "vpx/vpx_decoder.h"
#include "vpx/vpx_frame_buffer.h"
#include <fuzzer/FuzzedDataProvider.h>

// IVF frame/header sizes
#define IVF_FRAME_HDR_SZ (4 + 8) /* 4 byte size + 8 byte timestamp */
#define IVF_FILE_HDR_SZ 32

// Helper function to read little-endian 32-bit values
static uint32_t mem_get_le32(const void *vmem) {
  const uint8_t *mem = (const uint8_t *)vmem;
  return (uint32_t)mem[0] | ((uint32_t)mem[1] << 8) | 
         ((uint32_t)mem[2] << 16) | ((uint32_t)mem[3] << 24);
}

// Advanced frame buffer structure with allocation tracking
typedef struct {
  std::vector<uint8_t> data;
  size_t size;
  bool in_use;
  int allocation_id;
  bool should_fail; // Simulate allocation failure
} AdvancedFrameBuffer;

// Comprehensive callback context
typedef struct {
  int frame_callback_count;
  int slice_callback_count;
  int get_buffer_count;
  int release_buffer_count;
  int allocation_failures;
  int callback_errors;
  std::vector<int> callback_sequence;
  void* user_data;
} AdvancedCallbackContext;

// Thread-safe callback context (simplified for fuzzing)
static AdvancedCallbackContext g_adv_cb_context = {0};

// Dynamic get frame buffer callback that can fail based on input
static int dynamic_get_frame_buffer_cb(void* cb_priv, size_t min_size, 
                                       vpx_codec_frame_buffer_t* fb) {
  if (!fb) return -1;
  
  g_adv_cb_context.get_buffer_count++;
  g_adv_cb_context.callback_sequence.push_back(1); // 1 = get_buffer
  
  // Check if we should simulate allocation failure
  if (cb_priv) {
    bool* should_fail = static_cast<bool*>(cb_priv);
    if (*should_fail) {
      g_adv_cb_context.allocation_failures++;
      return -1; // Simulate allocation failure
    }
  }
  
  // Dynamic buffer sizing based on requirements
  size_t alloc_size = std::max(min_size, (size_t)4096);
  
  // Add some randomness to allocation size
  static int counter = 0;
  counter++;
  if (counter % 3 == 0) {
    alloc_size *= 2; // Sometimes allocate more
  } else if (counter % 5 == 0) {
    alloc_size = std::max(min_size, (size_t)1024); // Sometimes allocate less
  }
  
  AdvancedFrameBuffer* ext_buf = new AdvancedFrameBuffer();
  ext_buf->data.resize(alloc_size);
  ext_buf->size = alloc_size;
  ext_buf->in_use = true;
  ext_buf->allocation_id = g_adv_cb_context.get_buffer_count;
  ext_buf->should_fail = false;
  
  // Zero out the buffer as required by the API
  memset(ext_buf->data.data(), 0, alloc_size);
  
  fb->data = ext_buf->data.data();
  fb->size = alloc_size;
  fb->priv = ext_buf;
  
  return 0;
}

// Dynamic release frame buffer callback
static int dynamic_release_frame_buffer_cb(void* cb_priv, vpx_codec_frame_buffer_t* fb) {
  if (!fb || !fb->priv) {
    g_adv_cb_context.callback_errors++;
    return -1;
  }
  
  g_adv_cb_context.release_buffer_count++;
  g_adv_cb_context.callback_sequence.push_back(2); // 2 = release_buffer
  
  AdvancedFrameBuffer* ext_buf = static_cast<AdvancedFrameBuffer*>(fb->priv);
  ext_buf->in_use = false;
  
  // Clean up buffer after release (different from harness_005)
  delete ext_buf;
  fb->priv = nullptr;
  
  return 0;
}

// Dynamic put frame callback with validation
static void dynamic_put_frame_cb(void* user_priv, const vpx_image_t* img) {
  g_adv_cb_context.frame_callback_count++;
  g_adv_cb_context.callback_sequence.push_back(3); // 3 = put_frame
  
  if (user_priv) {
    // User data provided, could be validation context
  }
  
  if (img) {
    // Perform more comprehensive validation than harness_005
    if (img->w > 16384 || img->h > 16384) {
      g_adv_cb_context.callback_errors++;
    }
    
    if (img->fmt < 0 || img->fmt > 20) {
      g_adv_cb_context.callback_errors++;
    }
  }
}

// Dynamic put slice callback with rectangle validation
static void dynamic_put_slice_cb(void* user_priv, const vpx_image_t* img,
                                 const vpx_image_rect_t* valid,
                                 const vpx_image_rect_t* update) {
  g_adv_cb_context.slice_callback_count++;
  g_adv_cb_context.callback_sequence.push_back(4); // 4 = put_slice
  
  if (img) {
    // Validate image dimensions
    if (img->w == 0 || img->h == 0) {
      g_adv_cb_context.callback_errors++;
    }
  }
  
  if (valid) {
    // Validate rectangle coordinates
    if (valid->x > 10000 || valid->y > 10000 || 
        valid->w > 10000 || valid->h > 10000) {
      g_adv_cb_context.callback_errors++;
    }
  }
  
  if (update) {
    // Validate update rectangle
    if (update->x > 10000 || update->y > 10000 || 
        update->w > 10000 || update->h > 10000) {
      g_adv_cb_context.callback_errors++;
    }
  }
}

// Test different callback registration sequences
enum CallbackSequence {
  SEQUENCE_FRAME_FIRST = 0,
  SEQUENCE_SLICE_FIRST = 1,
  SEQUENCE_BUFFER_FIRST = 2,
  SEQUENCE_ALL_AT_ONCE = 3,
  SEQUENCE_NONE = 4
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Minimum size check: need configuration data
  if (size < 50) {
    return 0;
  }

  FuzzedDataProvider fdp(data, size);
  
  // Reset callback context for this iteration
  g_adv_cb_context = {0};
  g_adv_cb_context.user_data = nullptr;
  
  // Consume comprehensive configuration from fuzzer input
  uint8_t config_byte1 = fdp.ConsumeIntegral<uint8_t>();
  uint8_t config_byte2 = fdp.ConsumeIntegral<uint8_t>();
  uint8_t callback_sequence_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 4);
  
  // Set thread count dynamically
  const unsigned int threads = (config_byte1 & 0x3f) + 1;
  vpx_codec_dec_cfg_t cfg = { threads, 0, 0 };
  
  // Set comprehensive decoder flags based on input
  vpx_codec_flags_t flags = 0;
  
  // Test various flag combinations
  if ((config_byte1 & 0x01) != 0) {
    flags |= VPX_CODEC_USE_POSTPROC;
  }
  if ((config_byte1 & 0x02) != 0) {
    flags |= VPX_CODEC_USE_ERROR_CONCEALMENT;
  }
  if ((config_byte1 & 0x04) != 0) {
    flags |= VPX_CODEC_USE_INPUT_FRAGMENTS;
  }
  if ((config_byte1 & 0x08) != 0) {
    flags |= VPX_CODEC_USE_FRAME_THREADING;
  }
  
  // Choose decoder interface with bias towards VP9 (better callback support)
  vpx_codec_iface_t* decoder_iface = nullptr;
  uint8_t decoder_choice = fdp.ConsumeIntegral<uint8_t>() % 3;
  if (decoder_choice == 0) {
    decoder_iface = vpx_codec_vp8_dx();  // VP8
  } else {
    decoder_iface = vpx_codec_vp9_dx();  // VP9 (better for callbacks)
  }
  
  // Initialize decoder context
  vpx_codec_ctx_t codec;
  vpx_codec_err_t err = VPX_CODEC_OK;
  
  // Test 1: Try callback registration BEFORE initialization (should fail)
  if ((config_byte2 & 0x01) != 0) {
    // Attempt premature callback registration
    vpx_codec_register_put_frame_cb(&codec, dynamic_put_frame_cb, nullptr);
    vpx_codec_register_put_slice_cb(&codec, dynamic_put_slice_cb, nullptr);
  }
  
  // Initialize decoder
  err = vpx_codec_dec_init(&codec, decoder_iface, &cfg, flags);
  
  // Handle initialization failures
  if (err == VPX_CODEC_INCAPABLE) {
    // Try with reduced flags
    flags &= ~(VPX_CODEC_USE_POSTPROC | VPX_CODEC_USE_FRAME_THREADING);
    if (vpx_codec_dec_init(&codec, decoder_iface, &cfg, flags) != VPX_CODEC_OK) {
      return 0;
    }
  } else if (err != VPX_CODEC_OK) {
    return 0;
  }
  
  // Setup callback failure simulation
  bool simulate_allocation_failure = (config_byte2 & 0x02) != 0;
  
  // Test different callback registration sequences
  switch (callback_sequence_type) {
    case SEQUENCE_FRAME_FIRST:
      // Frame -> Slice -> Buffer
      vpx_codec_register_put_frame_cb(&codec, dynamic_put_frame_cb, nullptr);
      vpx_codec_register_put_slice_cb(&codec, dynamic_put_slice_cb, nullptr);
      if (decoder_choice == 1) { // VP9
        vpx_codec_set_frame_buffer_functions(&codec, 
                                           dynamic_get_frame_buffer_cb,
                                           dynamic_release_frame_buffer_cb,
                                           simulate_allocation_failure ? &simulate_allocation_failure : nullptr);
      }
      break;
      
    case SEQUENCE_SLICE_FIRST:
      // Slice -> Frame -> Buffer
      vpx_codec_register_put_slice_cb(&codec, dynamic_put_slice_cb, nullptr);
      vpx_codec_register_put_frame_cb(&codec, dynamic_put_frame_cb, nullptr);
      if (decoder_choice == 1) { // VP9
        vpx_codec_set_frame_buffer_functions(&codec, 
                                           dynamic_get_frame_buffer_cb,
                                           dynamic_release_frame_buffer_cb,
                                           simulate_allocation_failure ? &simulate_allocation_failure : nullptr);
      }
      break;
      
    case SEQUENCE_BUFFER_FIRST:
      // Buffer -> Frame -> Slice (VP9 only)
      if (decoder_choice == 1) { // VP9
        vpx_codec_set_frame_buffer_functions(&codec, 
                                           dynamic_get_frame_buffer_cb,
                                           dynamic_release_frame_buffer_cb,
                                           simulate_allocation_failure ? &simulate_allocation_failure : nullptr);
      }
      vpx_codec_register_put_frame_cb(&codec, dynamic_put_frame_cb, nullptr);
      vpx_codec_register_put_slice_cb(&codec, dynamic_put_slice_cb, nullptr);
      break;
      
    case SEQUENCE_ALL_AT_ONCE:
      // Test all callbacks
      vpx_codec_register_put_frame_cb(&codec, dynamic_put_frame_cb, nullptr);
      vpx_codec_register_put_slice_cb(&codec, dynamic_put_slice_cb, nullptr);
      if (decoder_choice == 1) { // VP9
        vpx_codec_set_frame_buffer_functions(&codec, 
                                           dynamic_get_frame_buffer_cb,
                                           dynamic_release_frame_buffer_cb,
                                           simulate_allocation_failure ? &simulate_allocation_failure : nullptr);
      }
      break;
      
    case SEQUENCE_NONE:
      // No callbacks - test basic decode
      break;
  }
  
  // Test 2: Re-registration of callbacks (should work or fail gracefully)
  if ((config_byte2 & 0x04) != 0) {
    vpx_codec_register_put_frame_cb(&codec, dynamic_put_frame_cb, nullptr);
  }
  
  // Get remaining data as potential video content
  std::vector<uint8_t> video_data = fdp.ConsumeRemainingBytes<uint8_t>();
  const uint8_t* video_ptr = video_data.data();
  size_t video_size = video_data.size();
  
  // Process video data in different ways based on input
  uint8_t decode_strategy = config_byte2 & 0x18;
  
  if (video_size > 0) {
    switch (decode_strategy >> 3) {
      case 0: // Normal decode
        if (video_size >= IVF_FILE_HDR_SZ && memcmp(video_ptr, "DKIF", 4) == 0) {
          video_ptr += IVF_FILE_HDR_SZ;
          video_size -= IVF_FILE_HDR_SZ;
        }
        if (video_size > 0) {
          vpx_codec_decode(&codec, video_ptr, (unsigned int)video_size, nullptr, 0);
        }
        break;
        
      case 1: // Multiple decode calls with partial data
        if (video_size > 10) {
          size_t chunk_size = video_size / 3;
          vpx_codec_decode(&codec, video_ptr, (unsigned int)chunk_size, nullptr, 0);
          vpx_codec_decode(&codec, video_ptr + chunk_size, (unsigned int)chunk_size, nullptr, 0);
          vpx_codec_decode(&codec, video_ptr + 2*chunk_size, (unsigned int)(video_size - 2*chunk_size), nullptr, 0);
        }
        break;
        
      case 2: // Decode with NULL data (edge case)
        vpx_codec_decode(&codec, nullptr, 0, nullptr, 0);
        break;
        
      case 3: // Decode with invalid parameters
        vpx_codec_decode(&codec, video_ptr, (unsigned int)video_size, nullptr, 1000000);
        break;
    }
    
    // Try to get decoded frames (triggers callbacks)
    vpx_codec_iter_t iter = nullptr;
    vpx_image_t* img;
    int frames_retrieved = 0;
    while ((img = vpx_codec_get_frame(&codec, &iter)) != nullptr && frames_retrieved < 10) {
      frames_retrieved++;
      
      // Test callback behavior with retrieved frames
      if ((config_byte2 & 0x20) != 0) {
        // Simulate additional callback after frame retrieval
      }
    }
  }
  
  // Test 3: Callback registration after decode (should still work)
  if ((config_byte2 & 0x40) != 0) {
    vpx_codec_register_put_frame_cb(&codec, dynamic_put_frame_cb, nullptr);
  }
  
  // Clean up decoder
  vpx_codec_destroy(&codec);
  
  // Additional tests with fresh decoder
  if ((config_byte2 & 0x80) != 0 && size > 100) {
    // Reinitialize with different configuration
    FuzzedDataProvider fdp2(data, size);
    fdp2.ConsumeBytes<uint8_t>(50); // Skip consumed data
    
    vpx_codec_ctx_t codec2;
    vpx_codec_dec_init(&codec2, decoder_iface, &cfg, 0);
    
    // Test minimal callback setup
    vpx_codec_register_put_frame_cb(&codec2, dynamic_put_frame_cb, nullptr);
    
    vpx_codec_destroy(&codec2);
  }
  
  return 0;
}
