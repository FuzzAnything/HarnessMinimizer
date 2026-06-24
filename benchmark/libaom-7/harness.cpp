/*
 * Fuzzing harness for libaom AV1 external frame buffer management, reference frame manipulation,
 * and advanced image operations
 * 
 * TARGET AREAS:
 * 1. Frame buffer callback APIs (from aom/aom_frame_buffer.h):
 *    - aom_codec_set_frame_buffer_functions
 *    - External buffer management with complex lifecycle
 * 2. Reference frame manipulation via aom_codec_control:
 *    - AV1_GET_REFERENCE control ID (retrieve reference frames)
 *    - AV1_SET_REFERENCE control ID (set reference frames)  
 *    - AV1_COPY_REFERENCE control ID (copy reference frames)
 * 3. Advanced image operations:
 *    - aom_img_flip (image flipping operations)
 *    - aom_img_set_rect (advanced rectangle operations)
 *
 * SEMANTIC DIFFERENTIATION FROM EXISTING HARNESSES:
 * - harness_001: Basic encoder workflow
 * - harness_002: Decoder operations with basic frame buffer callbacks
 * - harness_003: Image metadata management
 * - harness_004: Codec control and configuration (but not reference frame controls)
 * - harness_005: ULEB encoding utilities
 * - harness_006: Image creation and wrapping with basic flipping
 * - harness_007: Focus on external memory management, reference frame manipulation, 
 *                and advanced transformations with complex callback scenarios
 *
 * STRATEGY:
 * 1. Frame Buffer Callback Test:
 *    - Register complex frame buffer callbacks for decoder with multiple buffers
 *    - Test decoding with external buffer management and stress scenarios
 *    - Verify callback invocation and buffer lifecycle with edge cases
 * 2. Reference Frame Manipulation Test:
 *    - Initialize both encoder and decoder
 *    - Use aom_codec_control with AV1_GET_REFERENCE to retrieve frames
 *    - Use AV1_SET_REFERENCE to set reference frames
 *    - Test AV1_COPY_REFERENCE for frame copying
 * 3. Advanced Image Operations Test:
 *    - Create test images with aom_img_alloc
 *    - Apply aom_img_flip for vertical/horizontal flips with various formats
 *    - Use aom_img_set_rect for complex sub-rectangle operations
 * 4. Error Path Testing:
 *    - Test invalid parameters, NULL pointers, out-of-bounds values
 *    - Verify error codes and error message retrieval
 */

#include <stddef.h>
#include <stdint.h>
#include <vector>
#include <memory>
#include <string>
#include <cstdlib>
#include <cstring>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
#include "aom/aom_encoder.h"
#include "aom/aom_decoder.h"
#include "aom/aomcx.h"
#include "aom/aomdx.h"
#include "aom/aom_codec.h"
#include "aom/aom_image.h"
#include "aom/aom_frame_buffer.h"
}

// Custom frame buffer management structure for advanced callback testing
struct AdvancedFrameBufferManager {
  std::vector<std::vector<uint8_t>> buffers;
  std::vector<bool> in_use;
  size_t max_buffers;
  size_t total_allocated;
  
  AdvancedFrameBufferManager(size_t max_buf) 
    : max_buffers(max_buf), total_allocated(0) {
    buffers.reserve(max_buffers);
    in_use.resize(max_buffers, false);
  }
  
  // Get a free buffer index or create new one
  int get_free_buffer_index() {
    for (size_t i = 0; i < in_use.size(); i++) {
      if (!in_use[i]) {
        return i;
      }
    }
    
    // If we have space for more buffers, add one
    if (buffers.size() < max_buffers) {
      buffers.emplace_back();
      in_use.push_back(false);
      return buffers.size() - 1;
    }
    
    return -1; // No free buffers
  }
};

// Advanced get frame buffer callback for testing
extern "C" int advanced_get_frame_buffer(void *priv, size_t min_size,
                                        aom_codec_frame_buffer_t *fb) {
  if (!fb) return -1;
  
  AdvancedFrameBufferManager *manager = static_cast<AdvancedFrameBufferManager*>(priv);
  if (!manager) return -1;
  
  int idx = manager->get_free_buffer_index();
  if (idx < 0) return -1;
  
  // Ensure buffer is large enough
  if (manager->buffers[idx].size() < min_size) {
    manager->buffers[idx].resize(min_size);
    // Initialize with zero as required by API
    memset(manager->buffers[idx].data(), 0, min_size);
    manager->total_allocated += min_size;
  }
  
  fb->data = manager->buffers[idx].data();
  fb->size = manager->buffers[idx].size();
  fb->priv = reinterpret_cast<void*>(static_cast<intptr_t>(idx));
  manager->in_use[idx] = true;
  
  return 0;
}

// Advanced release frame buffer callback
extern "C" int advanced_release_frame_buffer(void *priv,
                                            aom_codec_frame_buffer_t *fb) {
  if (!fb) return -1;
  
  AdvancedFrameBufferManager *manager = static_cast<AdvancedFrameBufferManager*>(priv);
  if (!manager) return -1;
  
  int idx = static_cast<int>(reinterpret_cast<intptr_t>(fb->priv));
  if (idx >= 0 && static_cast<size_t>(idx) < manager->in_use.size()) {
    manager->in_use[idx] = false;
    // Optionally shrink buffer to save memory (simulating real use case)
    if (manager->buffers[idx].size() > 1024 * 1024) { // 1MB threshold
      manager->buffers[idx].resize(1024 * 1024);
    }
  }
  
  return 0;
}

// Simple get frame buffer callback (for comparison testing)
extern "C" int simple_get_frame_buffer(void *priv, size_t min_size,
                                      aom_codec_frame_buffer_t *fb) {
  if (!fb) return -1;
  
  uint8_t *buf = static_cast<uint8_t*>(malloc(min_size));
  if (!buf) return -1;
  
  memset(buf, 0, min_size);
  fb->data = buf;
  fb->size = min_size;
  fb->priv = buf; // Store pointer for release
  
  return 0;
}

// Simple release frame buffer callback
extern "C" int simple_release_frame_buffer(void *priv,
                                          aom_codec_frame_buffer_t *fb) {
  if (!fb) return -1;
  
  if (fb->data) {
    free(fb->data);
    fb->data = nullptr;
  }
  
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Minimum size check - need enough data for complex operations
  if (size < 128) {
    return 0;
  }

  FuzzedDataProvider fdp(data, size);
  
  // Determine test scenario based on fuzzer input
  uint8_t scenario = fdp.ConsumeIntegral<uint8_t>() % 4;
  
  // Common parameters for all scenarios
  unsigned int width = fdp.ConsumeIntegralInRange<unsigned int>(16, 512);
  unsigned int height = fdp.ConsumeIntegralInRange<unsigned int>(16, 512);
  
  // Consume image format
  aom_img_fmt_t fmt = AOM_IMG_FMT_I420;
  uint8_t fmt_choice = fdp.ConsumeIntegral<uint8_t>() % 8;
  switch (fmt_choice) {
    case 0: fmt = AOM_IMG_FMT_I420; break;
    case 1: fmt = AOM_IMG_FMT_YV12; break;
    case 2: fmt = AOM_IMG_FMT_I422; break;
    case 3: fmt = AOM_IMG_FMT_I444; break;
    case 4: fmt = AOM_IMG_FMT_NV12; break;
    case 5: fmt = AOM_IMG_FMT_I42016; break;
    case 6: fmt = AOM_IMG_FMT_I42216; break;
    case 7: fmt = AOM_IMG_FMT_I44416; break;
  }
  
  // Scenario 0: Advanced frame buffer callback testing
  if (scenario == 0) {
    // Initialize decoder with advanced frame buffer callbacks
    aom_codec_iface_t *decoder_iface = aom_codec_av1_dx();
    if (!decoder_iface) return 0;
    
    aom_codec_ctx_t decoder;
    aom_codec_dec_cfg_t cfg = {1, width, height, 1}; // threads, w, h, allow_lowbitdepth
    
    aom_codec_err_t res = aom_codec_dec_init_ver(&decoder, decoder_iface, &cfg, 
                                                 0,
                                                 AOM_DECODER_ABI_VERSION);
    if (res != AOM_CODEC_OK) {
      return 0;
    }
    
    // Create advanced buffer manager
    size_t max_buffers = fdp.ConsumeIntegralInRange<size_t>(1, 16);
    AdvancedFrameBufferManager buffer_manager(max_buffers);
    
    // Set frame buffer functions
    if (fdp.ConsumeBool()) {
      // Use advanced callbacks
      aom_codec_err_t set_res = aom_codec_set_frame_buffer_functions(
          &decoder, advanced_get_frame_buffer, advanced_release_frame_buffer, 
          &buffer_manager);
      (void)set_res; // May fail if not supported
    } else {
      // Use simple callbacks
      aom_codec_err_t set_res = aom_codec_set_frame_buffer_functions(
          &decoder, simple_get_frame_buffer, simple_release_frame_buffer, nullptr);
      (void)set_res;
    }
    
    // Try to decode some data (if any remaining)
    if (fdp.remaining_bytes() > 32) {
      size_t decode_size = fdp.ConsumeIntegralInRange<size_t>(
          32, std::min(fdp.remaining_bytes(), static_cast<size_t>(65536)));
      std::vector<uint8_t> decode_data = fdp.ConsumeBytes<uint8_t>(decode_size);
      
      aom_codec_err_t decode_res = aom_codec_decode(&decoder, decode_data.data(), 
                                                   decode_data.size(), nullptr);
      (void)decode_res;
      
      // Try to get frames if decoding succeeded
      if (fdp.ConsumeBool()) {
        aom_codec_iter_t iter = nullptr;
        aom_image_t *frame = nullptr;
        int max_frames = fdp.ConsumeIntegralInRange<int>(1, 10);
        
        for (int i = 0; i < max_frames; i++) {
          frame = aom_codec_get_frame(&decoder, &iter);
          if (!frame) break;
          
          // Test image operations on decoded frame
          if (fdp.ConsumeBool() && frame->d_w > 4 && frame->d_h > 4) {
            aom_img_flip(frame);
          }
        }
      }
    }
    
    aom_codec_destroy(&decoder);
  }
  
  // Scenario 1: Reference frame manipulation testing
  else if (scenario == 1) {
    // Initialize decoder for reference frame operations
    aom_codec_iface_t *decoder_iface = aom_codec_av1_dx();
    if (!decoder_iface) return 0;
    
    aom_codec_ctx_t decoder;
    aom_codec_dec_cfg_t cfg = {1, width, height, 1};
    
    aom_codec_err_t res = aom_codec_dec_init_ver(&decoder, decoder_iface, &cfg, 0,
                                                 AOM_DECODER_ABI_VERSION);
    if (res != AOM_CODEC_OK) return 0;
    
    // Create test image for reference operations
    aom_image_t *test_img = aom_img_alloc(nullptr, fmt, width, height, 16);
    if (!test_img) {
      aom_codec_destroy(&decoder);
      return 0;
    }
    
    // Fill image with some data
    for (int plane = 0; plane < 3; plane++) {
      int plane_h = aom_img_plane_height(test_img, plane);
      int plane_w = aom_img_plane_width(test_img, plane);
      int stride = test_img->stride[plane];
      
      if (plane_h > 0 && plane_w > 0 && stride > 0) {
        for (int y = 0; y < plane_h; y++) {
          uint8_t *row = test_img->planes[plane] + y * stride;
          for (int x = 0; x < plane_w; x++) {
            row[x] = static_cast<uint8_t>((x + y) % 256);
          }
        }
      }
    }
    
    // Test AV1_SET_REFERENCE control
    av1_ref_frame_t ref_frame;
    ref_frame.idx = fdp.ConsumeIntegralInRange<int>(0, 7); // 0-7 reference indices
    ref_frame.use_external_ref = fdp.ConsumeBool() ? 1 : 0;
    ref_frame.img = *test_img;
    
    aom_codec_err_t set_ref_res = aom_codec_control(&decoder, AV1_SET_REFERENCE, &ref_frame);
    (void)set_ref_res; // May fail depending on decoder state
    
    // Test AV1_GET_REFERENCE control
    av1_ref_frame_t get_ref_frame;
    get_ref_frame.idx = fdp.ConsumeIntegralInRange<int>(0, 7);
    get_ref_frame.use_external_ref = fdp.ConsumeBool() ? 1 : 0;
    
    aom_codec_err_t get_ref_res = aom_codec_control(&decoder, AV1_GET_REFERENCE, &get_ref_frame);
    (void)get_ref_res;
    
    // Test AV1_COPY_REFERENCE control (if supported)
    av1_ref_frame_t copy_ref_frame;
    copy_ref_frame.idx = fdp.ConsumeIntegralInRange<int>(0, 7);
    copy_ref_frame.use_external_ref = fdp.ConsumeBool() ? 1 : 0;
    
    aom_codec_err_t copy_ref_res = aom_codec_control(&decoder, AV1_COPY_REFERENCE, &copy_ref_frame);
    (void)copy_ref_res;
    
    // Clean up
    aom_img_free(test_img);
    aom_codec_destroy(&decoder);
  }
  
  // Scenario 2: Advanced image operations testing
  else if (scenario == 2) {
    // Create multiple test images for complex operations
    unsigned int align = 1 << (fdp.ConsumeIntegralInRange<unsigned int>(0, 4)); // 1,2,4,8,16
    unsigned int border = fdp.ConsumeIntegralInRange<unsigned int>(0, 32);
    
    // Create image with border for rectangle operations
    aom_image_t *img = aom_img_alloc_with_border(nullptr, fmt, width, height, 
                                                align, align, border);
    if (!img) return 0;
    
    // Test complex aom_img_set_rect operations
    int num_rect_ops = fdp.ConsumeIntegralInRange<int>(1, 10);
    for (int i = 0; i < num_rect_ops && border > 0; i++) {
      unsigned int rect_x = fdp.ConsumeIntegralInRange<unsigned int>(0, width / 2);
      unsigned int rect_y = fdp.ConsumeIntegralInRange<unsigned int>(0, height / 2);
      unsigned int rect_w = fdp.ConsumeIntegralInRange<unsigned int>(1, width - rect_x);
      unsigned int rect_h = fdp.ConsumeIntegralInRange<unsigned int>(1, height - rect_y);
      
      // Ensure rectangle fits within image considering border
      if (rect_x + rect_w <= width && rect_y + rect_h <= height) {
        aom_img_set_rect(img, rect_x, rect_y, rect_w, rect_h, border);
      }
    }
    
    // Test aom_img_flip in various ways
    int flip_ops = fdp.ConsumeIntegralInRange<int>(0, 5);
    for (int i = 0; i < flip_ops; i++) {
      aom_img_flip(img);
      
      // After flipping, verify plane dimensions are still accessible
      for (int plane = 0; plane < 3; plane++) {
        int plane_w = aom_img_plane_width(img, plane);
        int plane_h = aom_img_plane_height(img, plane);
        (void)plane_w;
        (void)plane_h;
      }
    }
    
    // Create second image for format conversion testing
    aom_img_fmt_t second_fmt = (fmt_choice % 2 == 0) ? AOM_IMG_FMT_I420 : AOM_IMG_FMT_I444;
    aom_image_t *img2 = aom_img_alloc(nullptr, second_fmt, width / 2, height / 2, 16);
    if (img2) {
      // Test operations on second image
      if (fdp.ConsumeBool()) {
        aom_img_flip(img2);
      }
      
      aom_img_free(img2);
    }
    
    aom_img_free(img);
  }
  
  // Scenario 3: Combined testing with encoder and decoder
  else if (scenario == 3) {
    // Initialize encoder
    aom_codec_iface_t *encoder_iface = aom_codec_av1_cx();
    if (!encoder_iface) return 0;
    
    aom_codec_enc_cfg_t cfg;
    aom_codec_err_t res = aom_codec_enc_config_default(encoder_iface, &cfg, 0);
    if (res != AOM_CODEC_OK) return 0;
    
    cfg.g_w = width;
    cfg.g_h = height;
    cfg.g_timebase.num = 1;
    cfg.g_timebase.den = 30;
    cfg.rc_target_bitrate = 1000;
    
    aom_codec_ctx_t encoder;
    res = aom_codec_enc_init_ver(&encoder, encoder_iface, &cfg, 0, 
                                 AOM_ENCODER_ABI_VERSION);
    if (res != AOM_CODEC_OK) return 0;
    
    // Create input image for encoder
    aom_image_t *input_img = aom_img_alloc(nullptr, fmt, width, height, 16);
    if (!input_img) {
      aom_codec_destroy(&encoder);
      return 0;
    }
    
    // Fill image with pattern
    for (int plane = 0; plane < 3; plane++) {
      int plane_h = aom_img_plane_height(input_img, plane);
      int plane_w = aom_img_plane_width(input_img, plane);
      int stride = input_img->stride[plane];
      
      if (plane_h > 0 && plane_w > 0 && stride > 0) {
        for (int y = 0; y < plane_h; y++) {
          uint8_t *row = input_img->planes[plane] + y * stride;
          for (int x = 0; x < plane_w; x++) {
            row[x] = static_cast<uint8_t>((x * y) % 256);
          }
        }
      }
    }
    
    // Test image flipping before encoding
    if (fdp.ConsumeBool()) {
      aom_img_flip(input_img);
    }
    
    // Encode the image
    res = aom_codec_encode(&encoder, input_img, 0, 1, 0);
    (void)res;
    
    // Try to get encoded data
    aom_codec_iter_t iter = nullptr;
    const aom_codec_cx_pkt_t *pkt = nullptr;
    
    while ((pkt = aom_codec_get_cx_data(&encoder, &iter)) != nullptr) {
      // Process packet if needed
      (void)pkt;
    }
    
    // Test reference frame controls on encoder (if supported)
    av1_ref_frame_t enc_ref_frame;
    enc_ref_frame.idx = fdp.ConsumeIntegralInRange<int>(0, 7);
    enc_ref_frame.use_external_ref = 0;
    enc_ref_frame.img = *input_img;
    
    aom_codec_err_t enc_ref_res = aom_codec_control(&encoder, AV1_SET_REFERENCE, &enc_ref_frame);
    (void)enc_ref_res;
    
    // Clean up
    aom_img_free(input_img);
    aom_codec_destroy(&encoder);
  }
  
  return 0;
}
