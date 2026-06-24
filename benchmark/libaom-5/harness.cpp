/*
 * Copyright (c) 2024 Fuzzing Harness Generator
 *
 * AV1 Encoder Fuzzing Harness for libaom
 * Targets encoder initialization, configuration, and frame encoding APIs
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
#include <vector>
#include <memory>
#include <fuzzer/FuzzedDataProvider.h>

#include "aom/aom.h"
#include "aom/aom_encoder.h"
#include "aom/aomcx.h"
#include "aom/aom_image.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 64) {
        return 0;  // Need minimum data for meaningful testing
    }

    FuzzedDataProvider fdp(data, size);

    // Consume encoder configuration parameters
    uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(16, 4096);
    uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(16, 4096);
    uint32_t bit_depth = fdp.ConsumeBool() ? 8 : 10;
    uint32_t threads = fdp.ConsumeIntegralInRange<uint32_t>(1, 64);
    uint32_t usage = fdp.ConsumeIntegralInRange<uint32_t>(0, 3); // AOM_USAGE_GOOD_QUALITY, etc
    uint32_t deadline = fdp.ConsumeIntegralInRange<uint32_t>(0, 10); // AOM_DL_GOOD_QUALITY, etc
    
    // Consume encoder control parameters
    int cpu_used = fdp.ConsumeIntegralInRange<int>(-8, 8);
    unsigned int rc_mode = fdp.ConsumeIntegralInRange<unsigned int>(0, 3); // AOM_VBR, AOM_CBR, etc
    unsigned int kf_mode = fdp.ConsumeIntegralInRange<unsigned int>(0, 2); // AOM_KF_AUTO, etc
    int max_q = fdp.ConsumeIntegralInRange<int>(0, 255);
    int min_q = fdp.ConsumeIntegralInRange<int>(0, 255);
    int cq_level = fdp.ConsumeIntegralInRange<int>(0, 63);
    
    // Get remaining bytes for frame data
    size_t frame_data_size = fdp.ConsumeIntegralInRange<size_t>(1, 
        std::min(fdp.remaining_bytes(), static_cast<size_t>(1024 * 1024)));
    std::vector<uint8_t> frame_data = fdp.ConsumeBytes<uint8_t>(frame_data_size);

    // Initialize encoder
    aom_codec_iface_t *encoder_iface = aom_codec_av1_cx();
    aom_codec_ctx_t encoder;
    
    aom_codec_enc_cfg_t cfg;
    aom_codec_enc_config_default(encoder_iface, &cfg, usage);
    
    cfg.g_w = width;
    cfg.g_h = height;
    cfg.g_threads = threads;
    cfg.g_timebase.num = 1;
    cfg.g_timebase.den = 30; // 30 fps
    cfg.rc_target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 10000);
    cfg.g_error_resilient = fdp.ConsumeBool() ? AOM_ERROR_RESILIENT_DEFAULT : 0;
    cfg.g_input_bit_depth = bit_depth;
    cfg.g_pass = AOM_RC_ONE_PASS;
    
    // Initialize encoder with configuration
    if (aom_codec_enc_init(&encoder, encoder_iface, &cfg, 0) != AOM_CODEC_OK) {
        return 0;
    }
    
    // Set various encoder controls based on fuzzed data
    aom_codec_control(&encoder, AOME_SET_CPUUSED, cpu_used);
    aom_codec_control(&encoder, AOME_SET_CQ_LEVEL, cq_level);
    aom_codec_control(&encoder, AOME_SET_MAX_INTRA_BITRATE_PCT, 
                      fdp.ConsumeIntegralInRange<int>(0, 1000));
    aom_codec_control(&encoder, AV1E_SET_COLOR_RANGE, 
                      fdp.ConsumeIntegralInRange<int>(0, 1));
    aom_codec_control(&encoder, AV1E_SET_TILE_COLUMNS, 
                      fdp.ConsumeIntegralInRange<int>(0, 6));
    aom_codec_control(&encoder, AV1E_SET_TILE_ROWS, 
                      fdp.ConsumeIntegralInRange<int>(0, 6));
    aom_codec_control(&encoder, AV1E_SET_ENABLE_CDEF, 
                      fdp.ConsumeBool() ? 1 : 0);
    aom_codec_control(&encoder, AV1E_SET_ENABLE_RESTORATION, 
                      fdp.ConsumeBool() ? 1 : 0);
    aom_codec_control(&encoder, AV1E_SET_ENABLE_OBMC, 
                      fdp.ConsumeBool() ? 1 : 0);
    aom_codec_control(&encoder, AV1E_SET_DENOISE_NOISE_LEVEL, 
                      fdp.ConsumeIntegralInRange<int>(0, 50));
    aom_codec_control(&encoder, AV1E_SET_ENABLE_PALETTE, 
                      fdp.ConsumeBool() ? 1 : 0);
    aom_codec_control(&encoder, AV1E_SET_ENABLE_INTRABC, 
                      fdp.ConsumeBool() ? 1 : 0);
    
    // Create a test image
    aom_image_t img;
    aom_img_alloc(&img, 
                  bit_depth == 8 ? AOM_IMG_FMT_I420 : AOM_IMG_FMT_I42016,
                  width, height, 16);
    
    // Fill image with fuzzed data (truncated to fit)
    size_t bytes_to_copy = std::min(frame_data.size(), 
                                    static_cast<size_t>(img.stride[0] * height * 3 / 2));
    for (size_t i = 0; i < bytes_to_copy; ++i) {
        ((uint8_t*)img.planes[0])[i] = frame_data[i % frame_data.size()];
    }
    
    // Encode the frame - timestamp parameter is passed to aom_codec_encode, not in img
    aom_codec_encode(&encoder, &img, 0, 1, 0);
    
    // Get compressed data
    const aom_codec_cx_pkt_t *pkt = NULL;
    aom_codec_iter_t iter = NULL;
    while ((pkt = aom_codec_get_cx_data(&encoder, &iter)) != NULL) {
        // Process packet if needed
        if (pkt->kind == AOM_CODEC_CX_FRAME_PKT) {
            // Frame data available in pkt->data.frame.buf
            // We could do something with it, but for fuzzing we just want to exercise the API
        }
    }
    
    // Encode a few more frames with flush
    for (int i = 0; i < 3 && fdp.remaining_bytes() > 100; ++i) {
        // Update some image data
        for (size_t j = 0; j < bytes_to_copy && fdp.remaining_bytes() > 0; ++j) {
            ((uint8_t*)img.planes[0])[j] = fdp.ConsumeIntegral<uint8_t>();
        }
        
        aom_codec_encode(&encoder, &img, i + 1, 1, 0);
        
        // Get compressed data
        iter = NULL;
        while ((pkt = aom_codec_get_cx_data(&encoder, &iter)) != NULL) {
            // Process packet
        }
    }
    
    // Flush encoder
    aom_codec_encode(&encoder, NULL, 0, 0, 0);
    
    // Cleanup
    aom_img_free(&img);
    aom_codec_destroy(&encoder);
    
    return 0;
}
