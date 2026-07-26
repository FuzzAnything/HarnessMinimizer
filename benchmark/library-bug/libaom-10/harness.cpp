/*
 * Fuzzing harness for libaom AV1 decoder control information retrieval
 * Targets specific decoder control APIs identified in coverage guidance with 0% coverage:
 * - aom_codec_control_typechecked_AOMD_GET_FRAME_FLAGS
 * - aom_codec_control_typechecked_AOMD_GET_TILE_INFO  
 * - aom_codec_control_typechecked_AOMD_GET_SCREEN_CONTENT_TOOLS_INFO
 * - aom_codec_control_typechecked_AOMD_GET_STILL_PICTURE
 * - aom_codec_control_typechecked_AV1D_GET_TILE_DATA
 * - aom_codec_control_typechecked_AV1D_GET_FRAME_SIZE
 * 
 * Required helper APIs as per coverage guidance:
 * - aom_codec_dec_init_ver (decoder initialization)
 * - aom_codec_decode (must decode frames before querying)
 * - aom_codec_destroy (cleanup)
 * 
 * Invocation sequence from coverage guidance:
 * 1. Call aom_codec_dec_init_ver to initialize decoder context
 * 2. Call aom_codec_decode to decode one or more frames from fuzzer input
 * 3. Call various decoder control APIs (AOMD_GET_*, AV1D_GET_*) to retrieve decoder state information
 * 4. Call aom_codec_destroy to clean up resources
 * 
 * Semantic diversity from existing harnesses (000-013):
 * - Specifically targets typechecked decoder control API variants
 * - Focuses on comprehensive decoder state querying after successful decoding
 * - Tests complex decoder information structures like tile data and screen content tools
 * - Aims to reach 0%-covered "common/" module through decoder control pathways
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
#include <memory>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

#include "aom/aom_decoder.h"
#include "aom/aomdx.h"

// mem_get_le32 implementation for IVF frame parsing
static inline unsigned int mem_get_le32(const void *vmem) {
  const unsigned char *mem = (const unsigned char *)vmem;
  return ((unsigned int)mem[0]) |
         ((unsigned int)mem[1] << 8) |
         ((unsigned int)mem[2] << 16) |
         ((unsigned int)mem[3] << 24);
}

#define IVF_FRAME_HDR_SZ (4 + 8) /* 4 byte size + 8 byte timestamp */
#define IVF_FILE_HDR_SZ 32

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Minimum size needed for meaningful testing: IVF header + at least one frame header + some data
  if (size < IVF_FILE_HDR_SZ + IVF_FRAME_HDR_SZ + 1) {
    return 0;
  }

  FuzzedDataProvider fdp(data, size);

  // Extract decoder configuration parameters from fuzzer input
  // Use the IVF file header bytes for configuration flags
  std::vector<uint8_t> ivf_header = fdp.ConsumeBytes<uint8_t>(IVF_FILE_HDR_SZ);
  if (ivf_header.size() < IVF_FILE_HDR_SZ) {
    return 0;
  }

  // Extract configuration flags from the IVF header
  unsigned int threads = (ivf_header[0] & 0x3f) + 1;  // Threads: 1-64
  unsigned int allow_lowbitdepth = (ivf_header[IVF_FILE_HDR_SZ - 1] & 1) != 0;
  unsigned int tile_mode = (ivf_header[IVF_FILE_HDR_SZ - 1] & 2) != 0;
  unsigned int ext_tile_debug = (ivf_header[IVF_FILE_HDR_SZ - 1] & 4) != 0;
  unsigned int is_annexb = (ivf_header[IVF_FILE_HDR_SZ - 1] & 8) != 0;
  int output_all_layers = (ivf_header[IVF_FILE_HDR_SZ - 1] & 0x10) != 0;
  int operating_point = ivf_header[IVF_FILE_HDR_SZ - 2] & 0x1F;

  // Get decoder interface for AV1
  aom_codec_iface_t *codec_interface = aom_codec_av1_dx();
  if (!codec_interface) {
    return 0;
  }

  aom_codec_ctx_t codec;

  // Initialize decoder configuration
  aom_codec_dec_cfg_t cfg = { threads, 0, 0, allow_lowbitdepth };

  // Initialize decoder using aom_codec_dec_init_ver as per coverage guidance
  // Note: aom_codec_dec_init_ver is the versioned initialization function
  if (aom_codec_dec_init_ver(&codec, codec_interface, &cfg, 0, AOM_DECODER_ABI_VERSION)) {
    return 0;
  }

  // Set decoder control parameters from fuzzer input
  AOM_CODEC_CONTROL_TYPECHECKED(&codec, AV1_SET_TILE_MODE, tile_mode);
  AOM_CODEC_CONTROL_TYPECHECKED(&codec, AV1D_EXT_TILE_DEBUG, ext_tile_debug);
  AOM_CODEC_CONTROL_TYPECHECKED(&codec, AV1D_SET_IS_ANNEXB, is_annexb);
  AOM_CODEC_CONTROL_TYPECHECKED(&codec, AV1D_SET_OUTPUT_ALL_LAYERS, output_all_layers);
  AOM_CODEC_CONTROL_TYPECHECKED(&codec, AV1D_SET_OPERATING_POINT, operating_point);

  // Process remaining data as IVF frames
  bool frame_decoded = false;
  while (fdp.remaining_bytes() > IVF_FRAME_HDR_SZ) {
    // Consume frame header
    std::vector<uint8_t> frame_header = fdp.ConsumeBytes<uint8_t>(IVF_FRAME_HDR_SZ);
    if (frame_header.size() < IVF_FRAME_HDR_SZ) {
      break;
    }

    // Extract frame size from header (first 4 bytes, little-endian)
    size_t frame_size = mem_get_le32(frame_header.data());
    
    // Ensure we don't consume more than remaining bytes
    size_t remaining = fdp.remaining_bytes();
    frame_size = std::min(remaining, frame_size);
    
    if (frame_size == 0) {
      // No data to decode
      break;
    }

    // Consume frame data
    std::vector<uint8_t> frame_data = fdp.ConsumeBytes<uint8_t>(frame_size);

    // Decode the frame using aom_codec_decode as per coverage guidance
    aom_codec_err_t decode_res = aom_codec_decode(&codec, 
                                                   frame_data.data(), 
                                                   frame_size, 
                                                   NULL);
    
    if (decode_res == AOM_CODEC_OK) {
      frame_decoded = true;
      
      // Now query decoder state information using typechecked controls as per coverage guidance
      // PRIMARY TARGET APIs from coverage guidance:
      
      // 1. AOMD_GET_FRAME_FLAGS (typechecked version)
      int frame_flags = 0;
      AOM_CODEC_CONTROL_TYPECHECKED(&codec, AOMD_GET_FRAME_FLAGS, &frame_flags);
      
      // 2. AOMD_GET_TILE_INFO (typechecked version)
      aom_tile_info tile_info;
      memset(&tile_info, 0, sizeof(tile_info));
      AOM_CODEC_CONTROL_TYPECHECKED(&codec, AOMD_GET_TILE_INFO, &tile_info);
      
      // 3. AOMD_GET_SCREEN_CONTENT_TOOLS_INFO (typechecked version)
      aom_screen_content_tools_info screen_content_info;
      memset(&screen_content_info, 0, sizeof(screen_content_info));
      AOM_CODEC_CONTROL_TYPECHECKED(&codec, AOMD_GET_SCREEN_CONTENT_TOOLS_INFO, &screen_content_info);
      
      // 4. AOMD_GET_STILL_PICTURE (typechecked version)
      aom_still_picture_info still_picture_info;
      memset(&still_picture_info, 0, sizeof(still_picture_info));
      AOM_CODEC_CONTROL_TYPECHECKED(&codec, AOMD_GET_STILL_PICTURE, &still_picture_info);
      
      // 5. AV1D_GET_TILE_DATA (typechecked version)
      aom_tile_data tile_data;
      memset(&tile_data, 0, sizeof(tile_data));
      // Need to set tile position first using AV1_SET_DECODE_TILE_ROW/COL
      // Use fuzzer input to determine which tile to query
      int tile_row = fdp.ConsumeIntegralInRange<int>(0, 31); // Reasonable max
      int tile_col = fdp.ConsumeIntegralInRange<int>(0, 31); // Reasonable max
      AOM_CODEC_CONTROL_TYPECHECKED(&codec, AV1_SET_DECODE_TILE_ROW, tile_row);
      AOM_CODEC_CONTROL_TYPECHECKED(&codec, AV1_SET_DECODE_TILE_COL, tile_col);
      // Now get tile data for the specified tile position
      AOM_CODEC_CONTROL_TYPECHECKED(&codec, AV1D_GET_TILE_DATA, &tile_data);
      // 6. AV1D_GET_FRAME_SIZE (typechecked version)
      int frame_size_info[2] = {0, 0}; // width, height
      AOM_CODEC_CONTROL_TYPECHECKED(&codec, AV1D_GET_FRAME_SIZE, frame_size_info);
      
      // Additional decoder state queries for comprehensive coverage
      // These complement the primary targets and may help reach more uncovered code
      
      // Get last reference updates
      int last_ref_updates = 0;
      AOM_CODEC_CONTROL_TYPECHECKED(&codec, AOMD_GET_LAST_REF_UPDATES, &last_ref_updates);
      
      // Get frame corrupted flag
      int frame_corrupted = 0;
      AOM_CODEC_CONTROL_TYPECHECKED(&codec, AOMD_GET_FRAME_CORRUPTED, &frame_corrupted);
      
      // Get last reference used
      int last_ref_used = 0;
      AOM_CODEC_CONTROL_TYPECHECKED(&codec, AOMD_GET_LAST_REF_USED, &last_ref_used);
      
      // Get display size (complementary to frame size)
      int display_size[2] = {0, 0};
      AOM_CODEC_CONTROL_TYPECHECKED(&codec, AV1D_GET_DISPLAY_SIZE, display_size);
      
      // Get bit depth
      unsigned int bit_depth = 0;
      AOM_CODEC_CONTROL_TYPECHECKED(&codec, AV1D_GET_BIT_DEPTH, &bit_depth);
      
      // Get image format
      aom_img_fmt_t img_format;
      AOM_CODEC_CONTROL_TYPECHECKED(&codec, AV1D_GET_IMG_FORMAT, &img_format);
      
      // Try to get a frame (optional, may fail if no frame available)
      aom_image_t *img = NULL;
      aom_codec_iter_t iter = NULL;
      img = aom_codec_get_frame(&codec, &iter);
      
      // Break after first successful decode and queries to avoid infinite loops
      // with minimal input data
      break;
    } else {
      // Decode failed, try next frame
      continue;
    }
  }

  // Clean up decoder resources using aom_codec_destroy as per coverage guidance
  aom_codec_destroy(&codec);

  return 0;
}
