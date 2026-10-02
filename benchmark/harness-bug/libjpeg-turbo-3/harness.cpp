/*
 * Fuzzing harness for libjpeg-turbo targeting decompression APIs
 * Specifically focuses on tj3DecompressToYUVPlanes8 which is not covered
 * in existing fuzzing harnesses.
 */

#include <fuzzer/FuzzedDataProvider.h>
#include "turbojpeg.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Minimum size needed for basic decompression
  if (size < 100) return 0;
  
  FuzzedDataProvider fdp(data, size);
  
  // Consume fixed-size parameters first
  bool use_planes_api = fdp.ConsumeBool();
  int pixel_format_idx = fdp.ConsumeIntegralInRange<int>(0, 11); // TJPF enum range
  bool bottom_up = fdp.ConsumeBool();
  bool fast_upsample = fdp.ConsumeBool();
  bool fast_dct = fdp.ConsumeBool();
  int scaling_num = fdp.ConsumeIntegralInRange<int>(1, 8);
  int scaling_denom = fdp.ConsumeIntegralInRange<int>(1, 8);
  int align = 1 << fdp.ConsumeIntegralInRange<int>(0, 4); // Power of 2 alignment
  
  // Get the remaining JPEG data
  std::vector<uint8_t> jpeg_data = fdp.ConsumeRemainingBytes<uint8_t>();
  if (jpeg_data.size() < 100) return 0; // Need enough JPEG data
  
  tjhandle handle = tj3Init(TJINIT_DECOMPRESS);
  if (!handle) return 0;
  
  // Set decompression parameters based on fuzzed input
  tj3Set(handle, TJPARAM_BOTTOMUP, bottom_up);
  tj3Set(handle, TJPARAM_FASTUPSAMPLE, fast_upsample);
  tj3Set(handle, TJPARAM_FASTDCT, fast_dct);
  
  // Set scaling factor
  tjscalingfactor scaling_factor = {scaling_num, scaling_denom};
  tj3SetScalingFactor(handle, scaling_factor);
  
  // Try to read JPEG header (ignore errors for fuzzing)
  tj3DecompressHeader(handle, jpeg_data.data(), jpeg_data.size());
  
  int width = tj3Get(handle, TJPARAM_JPEGWIDTH);
  int height = tj3Get(handle, TJPARAM_JPEGHEIGHT);
  int subsamp = tj3Get(handle, TJPARAM_SUBSAMP);
  int precision = tj3Get(handle, TJPARAM_PRECISION);
  
  // Skip invalid or too large images
  if (width < 1 || height < 1 || (uint64_t)width * height > 1048576) {
    tj3Destroy(handle);
    return 0;
  }
  
  // Skip high precision images for 8-bit API
  if (precision > 8) {
    tj3Destroy(handle);
    return 0;
  }
  
  // Calculate scaled dimensions
  int scaled_width = TJSCALED(width, scaling_factor);
  int scaled_height = TJSCALED(height, scaling_factor);
  
  // Convert pixel format index to actual enum
  enum TJPF pixel_format;
  switch (pixel_format_idx % 12) {
    case 0: pixel_format = TJPF_RGB; break;
    case 1: pixel_format = TJPF_BGR; break;
    case 2: pixel_format = TJPF_RGBX; break;
    case 3: pixel_format = TJPF_BGRX; break;
    case 4: pixel_format = TJPF_XBGR; break;
    case 5: pixel_format = TJPF_XRGB; break;
    case 6: pixel_format = TJPF_GRAY; break;
    case 7: pixel_format = TJPF_RGBA; break;
    case 8: pixel_format = TJPF_BGRA; break;
    case 9: pixel_format = TJPF_ABGR; break;
    case 10: pixel_format = TJPF_ARGB; break;
    case 11: pixel_format = TJPF_CMYK; break;
    default: pixel_format = TJPF_RGB; break;
  }
  
  if (use_planes_api && subsamp != TJSAMP_GRAY) {
    // Test tj3DecompressToYUVPlanes8 API
    unsigned char* planes[3] = {nullptr, nullptr, nullptr};
    int strides[3] = {0, 0, 0};
    
    // Allocate plane buffers
    for (int i = 0; i < 3; i++) {
      size_t plane_size = tj3YUVPlaneSize(i, scaled_width, 0, scaled_height, subsamp);
      if (plane_size > 0) {
        planes[i] = (unsigned char*)tj3Alloc(plane_size);
        if (!planes[i]) {
          // Cleanup already allocated planes
          for (int j = 0; j < i; j++) {
            if (planes[j]) tj3Free(planes[j]);
          }
          tj3Destroy(handle);
          return 0;
        }
      }
    }
    
    // Try decompression to YUV planes
    int result = tj3DecompressToYUVPlanes8(handle, jpeg_data.data(), jpeg_data.size(),
                                           planes, strides);
    
    // Cleanup planes
    for (int i = 0; i < 3; i++) {
      if (planes[i]) tj3Free(planes[i]);
    }
    
  } else {
    // Test regular decompression APIs
    
    // Allocate destination buffer for packed pixel output
    size_t dst_buf_size = scaled_width * scaled_height * tjPixelSize[pixel_format];
    unsigned char* dst_buf = (unsigned char*)tj3Alloc(dst_buf_size);
    if (!dst_buf) {
      tj3Destroy(handle);
      return 0;
    }
    // Try 8-bit decompression
    int result = tj3Decompress8(handle, jpeg_data.data(), jpeg_data.size(),
                                dst_buf, 0, pixel_format);
    
    // Also test YUV buffer API
    if (result == 0 && subsamp != TJSAMP_GRAY) {
      size_t yuv_buf_size = tj3YUVBufSize(scaled_width, align, scaled_height, subsamp);
      unsigned char* yuv_buf = (unsigned char*)tj3Alloc(yuv_buf_size);
      if (yuv_buf) {
        // Decompress to YUV buffer
        tj3DecompressToYUV8(handle, jpeg_data.data(), jpeg_data.size(),
                           yuv_buf, align);
        
        // Decode YUV to RGB
        tj3DecodeYUV8(handle, yuv_buf, align, dst_buf, scaled_width, 0,
                     scaled_height, pixel_format);
        
        tj3Free(yuv_buf);
      }
    }

    
    tj3Free(dst_buf);
  }
  
  tj3Destroy(handle);
  return 0;
}
