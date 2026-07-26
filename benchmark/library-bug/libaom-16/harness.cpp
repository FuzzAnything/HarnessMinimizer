/*
 * Copyright (c) 2024, FuzzAgent Project. All rights reserved.
 *
 * Fuzzing harness for libaom decoder API.
 * This harness targets AV1 decoding functions with varied configurations.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <algorithm>
#include <memory>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"
#include "aom/aom_decoder.h"
#include "aom/aomdx.h"
#include "aom/aom_image.h"

// Minimum input size required to start fuzzing
#define MIN_INPUT_SIZE 64

// Helper function to consume data for decoder configuration
static void configure_decoder(aom_codec_ctx_t *codec, FuzzedDataProvider &fdp) {
    // Set various decoder controls based on fuzzed data
    
    // Tile mode
    unsigned int tile_mode = fdp.ConsumeBool();
    AOM_CODEC_CONTROL_TYPECHECKED(codec, AV1_SET_TILE_MODE, tile_mode);
    
    // Extended tile debug
    unsigned int ext_tile_debug = fdp.ConsumeBool();
    AOM_CODEC_CONTROL_TYPECHECKED(codec, AV1D_EXT_TILE_DEBUG, ext_tile_debug);
    
    // Annex B format
    unsigned int is_annexb = fdp.ConsumeBool();
    AOM_CODEC_CONTROL_TYPECHECKED(codec, AV1D_SET_IS_ANNEXB, is_annexb);
    
    // Output all layers
    int output_all_layers = fdp.ConsumeBool();
    AOM_CODEC_CONTROL_TYPECHECKED(codec, AV1D_SET_OUTPUT_ALL_LAYERS, output_all_layers);
    
    // Operating point (0-31)
    int operating_point = fdp.ConsumeIntegralInRange<int>(0, 31);
    AOM_CODEC_CONTROL_TYPECHECKED(codec, AV1D_SET_OPERATING_POINT, operating_point);
    
    // Set skip film grain
    unsigned int skip_film_grain = fdp.ConsumeBool();
    AOM_CODEC_CONTROL_TYPECHECKED(codec, AV1D_SET_SKIP_FILM_GRAIN, skip_film_grain);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Require minimum input size
    if (size < 64) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);

    // Initialize decoder
    aom_codec_iface_t *codec_interface = aom_codec_av1_dx();
    aom_codec_ctx_t codec;

    // Consume configuration parameters with extremely strict limits to avoid OOM
    unsigned int threads = 1;  // Fixed to 1 thread
    unsigned int w = fdp.ConsumeIntegralInRange<unsigned int>(16, 64);     // Reduced max to 64
    unsigned int h = fdp.ConsumeIntegralInRange<unsigned int>(16, 64);     // Reduced max to 64
    // Avoid large images (max 0.004MP = 64x64)
    if (w * h > 4096) {
        return 0;
    }
    unsigned int allow_lowbitdepth = fdp.ConsumeBool();

    aom_codec_dec_cfg_t cfg = { threads, w, h, allow_lowbitdepth };

    if (aom_codec_dec_init(&codec, codec_interface, &cfg, 0)) {
        return 0;
    }

    // Apply decoder controls (optional, but keep minimal)
    // We'll call configure_decoder but it only sets flags, not large allocations.
    configure_decoder(&codec, fdp);

    // Consume remaining data as the bitstream to decode
    // Only process one frame to minimize memory
    const size_t MAX_FRAMES = 1;  // Only one frame
    size_t frame_count = 0;
    while (fdp.remaining_bytes() > 0 && frame_count < MAX_FRAMES) {
        // Limit chunk size to 8KB to avoid large allocations
        size_t max_chunk_size = std::min<size_t>(8192, fdp.remaining_bytes());
        size_t chunk_size = fdp.ConsumeIntegralInRange<size_t>(1, max_chunk_size);
        std::vector<uint8_t> chunk = fdp.ConsumeBytes<uint8_t>(chunk_size);
        
        // Peek stream info (optional, can fail)
        aom_codec_stream_info_t stream_info;
        stream_info.is_annexb = 0; // Default, but we set via control
        aom_codec_peek_stream_info(codec_interface, chunk.data(), chunk.size(), &stream_info);
        
        // Decode the chunk
        aom_codec_decode(&codec, chunk.data(), chunk.size(), nullptr);
        
        // Get decoded frames (if any)
        aom_codec_iter_t iter = nullptr;
        aom_image_t *img = nullptr;
        while ((img = aom_codec_get_frame(&codec, &iter)) != nullptr) {
            // Access image data to ensure coverage
            // Just reading some properties without processing deeply
            (void)img->fmt;
            (void)img->d_w;
            (void)img->d_h;
        }
        
        frame_count++;
    }
    // Destroy the decoder
    aom_codec_destroy(&codec);
    
    return 0;
}
