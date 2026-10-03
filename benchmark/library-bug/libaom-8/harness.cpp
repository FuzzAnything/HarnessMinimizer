/*
 * Fuzzing harness for libaom AV1 encoder
 * Targets: aom_codec_enc_init, aom_codec_encode, aom_codec_get_cx_data, aom_codec_destroy
 * Tests various encoder configurations, controls, and encoding modes
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory>
#include <vector>

#include "aom/aom_encoder.h"
#include "aom/aomcx.h"
#include "aom/aom_image.h"
#include "fuzzer/FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Need sufficient data for encoder configuration
    if (size < 64) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);

    // Get the AV1 encoder interface
    aom_codec_iface_t *codec_interface = aom_codec_av1_cx();
    if (!codec_interface) {
        return 0;
    }

    // Initialize encoder configuration with default values
    aom_codec_enc_cfg_t cfg;
    if (aom_codec_enc_config_default(codec_interface, &cfg, AOM_USAGE_GOOD_QUALITY) != AOM_CODEC_OK) {
        return 0;
    }

    // Consume configuration parameters from the input
    // Frame dimensions (keep them small for fuzzing efficiency)
    cfg.g_w = fdp.ConsumeIntegralInRange<unsigned int>(16, 256);
    cfg.g_h = fdp.ConsumeIntegralInRange<unsigned int>(16, 256);
    
    // Limit number of frames to encode
    cfg.g_limit = fdp.ConsumeIntegralInRange<unsigned int>(1, 5);
    
    // Thread configuration
    cfg.g_threads = fdp.ConsumeIntegralInRange<unsigned int>(1, 8);
    
    // Bitrate and rate control parameters
    cfg.rc_target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 1000);
    cfg.rc_end_usage = static_cast<aom_rc_mode>(fdp.ConsumeIntegralInRange<int>(AOM_VBR, AOM_CQ));
    
    // Keyframe settings
    cfg.kf_mode = static_cast<aom_kf_mode>(fdp.ConsumeIntegralInRange<int>(AOM_KF_DISABLED, AOM_KF_AUTO));
    cfg.kf_min_dist = fdp.ConsumeIntegralInRange<unsigned int>(0, 100);
    cfg.kf_max_dist = fdp.ConsumeIntegralInRange<unsigned int>(0, 100);
    
    // Error resilience
    cfg.g_error_resilient = fdp.ConsumeBool() ? AOM_ERROR_RESILIENT_DEFAULT : 0;
    
    // Color format and bit depth
    aom_img_fmt_t img_fmt = fdp.ConsumeBool() ? AOM_IMG_FMT_I420 : AOM_IMG_FMT_I42016;
    
    // Initialize encoder context
    aom_codec_ctx_t codec;
    unsigned long init_flags = 0;
    if (img_fmt == AOM_IMG_FMT_I42016) {
        init_flags = AOM_CODEC_USE_HIGHBITDEPTH;
    }
    
    if (aom_codec_enc_init(&codec, codec_interface, &cfg, init_flags) != AOM_CODEC_OK) {
        return 0;
    }

    // Set various encoder controls based on fuzzed input
    // Note: We ignore errors from control calls as some combinations may be invalid
    aom_codec_err_t ctrl_err;
    
    // Set quality/quantizer
    int cq_level = fdp.ConsumeIntegralInRange<int>(0, 63);
    ctrl_err = aom_codec_control(&codec, AOME_SET_CQ_LEVEL, cq_level);
    (void)ctrl_err;
    
    // Set CPU used
    int cpu_used = fdp.ConsumeIntegralInRange<int>(0, 9);
    ctrl_err = aom_codec_control(&codec, AOME_SET_CPUUSED, cpu_used);
    (void)ctrl_err;
    
    // Enable/disable various features
    int enable_filter_intra = fdp.ConsumeBool() ? 1 : 0;
    ctrl_err = aom_codec_control(&codec, AV1E_SET_ENABLE_FILTER_INTRA, enable_filter_intra);
    (void)ctrl_err;
    
    int enable_smooth_intra = fdp.ConsumeBool() ? 1 : 0;
    ctrl_err = aom_codec_control(&codec, AV1E_SET_ENABLE_SMOOTH_INTRA, enable_smooth_intra);
    (void)ctrl_err;
    
    int enable_palette = fdp.ConsumeBool() ? 1 : 0;
    ctrl_err = aom_codec_control(&codec, AV1E_SET_ENABLE_PALETTE, enable_palette);
    (void)ctrl_err;
    
    int enable_intrabc = fdp.ConsumeBool() ? 1 : 0;
    ctrl_err = aom_codec_control(&codec, AV1E_SET_ENABLE_INTRABC, enable_intrabc);
    (void)ctrl_err;
    
    // Tile configuration
    int tile_columns = fdp.ConsumeIntegralInRange<int>(0, 6);
    int tile_rows = fdp.ConsumeIntegralInRange<int>(0, 6);
    ctrl_err = aom_codec_control(&codec, AV1E_SET_TILE_COLUMNS, tile_columns);
    (void)ctrl_err;
    ctrl_err = aom_codec_control(&codec, AV1E_SET_TILE_ROWS, tile_rows);
    (void)ctrl_err;
    
    // Create a dummy image for encoding
    aom_image_t img;
    unsigned int align = 1;
    if (aom_img_alloc(&img, img_fmt, cfg.g_w, cfg.g_h, align) == nullptr) {
        aom_codec_destroy(&codec);
        return 0;
    }
    
    // Fill image planes with random data from fuzzer input
    // For I420 format: Y plane, U plane, V plane
    size_t y_size = cfg.g_w * cfg.g_h;
    size_t uv_size = ((cfg.g_w + 1) / 2) * ((cfg.g_h + 1) / 2);
    
    // Get remaining data for image content
    std::vector<uint8_t> image_data = fdp.ConsumeRemainingBytes<uint8_t>();
    const uint8_t* image_ptr = image_data.data();
    size_t image_size = image_data.size();
    
    // Fill Y plane
    size_t fill_size = y_size;
    if (img_fmt == AOM_IMG_FMT_I42016) {
        fill_size *= 2; // 16-bit samples
    }
    
    if (image_size >= fill_size) {
        for (size_t i = 0; i < fill_size && i < image_size; i++) {
            if (img_fmt == AOM_IMG_FMT_I42016) {
                ((uint16_t*)img.planes[0])[i] = image_ptr[i] * 257; // Scale 8-bit to 16-bit
            } else {
                img.planes[0][i] = image_ptr[i];
            }
        }
        image_ptr += fill_size;
        image_size -= fill_size;
    }
    
    // Fill U and V planes if we have enough data
    for (int plane = 1; plane <= 2; plane++) {
        if (image_size >= uv_size) {
            for (size_t i = 0; i < uv_size && i < image_size; i++) {
                if (img_fmt == AOM_IMG_FMT_I42016) {
                    ((uint16_t*)img.planes[plane])[i] = image_ptr[i] * 257;
                } else {
                    img.planes[plane][i] = image_ptr[i];
                }
            }
            image_ptr += uv_size;
            image_size -= uv_size;
        }
    }
    
    // Encode frames
    unsigned long pts = 0;
    unsigned long duration = 1;
    aom_enc_frame_flags_t flags = 0;
    
    // Determine number of frames to encode from remaining input or configuration
    unsigned int num_frames = cfg.g_limit;
    if (num_frames > 10) num_frames = 10; // Safety limit
    
    for (unsigned int frame_idx = 0; frame_idx < num_frames; frame_idx++) {
        // Set frame flags based on fuzzed input
        if (frame_idx == 0 || fdp.ConsumeBool()) {
            flags = fdp.ConsumeBool() ? AOM_EFLAG_FORCE_KF : 0;
        }
        
        // Encode the frame
        aom_codec_err_t encode_err = aom_codec_encode(&codec, &img, pts, duration, flags);
        (void)encode_err; // Ignore errors - invalid configurations are expected
        
        pts += duration;
        
        // Get encoded data packets
        const aom_codec_cx_pkt_t *pkt = nullptr;
        aom_codec_iter_t iter = nullptr;
        
        while ((pkt = aom_codec_get_cx_data(&codec, &iter)) != nullptr) {
            // Process different packet types
            switch (pkt->kind) {
                case AOM_CODEC_CX_FRAME_PKT:
                    // Compressed frame data - we don't need to do anything with it
                    break;
                case AOM_CODEC_STATS_PKT:
                    // Statistics data - we don't need to do anything with it
                    break;
                default:
                    // Ignore other packet types
                    break;
            }
        }
    }
    
    // Flush the encoder
    aom_codec_encode(&codec, nullptr, 0, 0, 0);
    
    // Get any remaining encoded data
    const aom_codec_cx_pkt_t *pkt = nullptr;
    aom_codec_iter_t iter = nullptr;
    while ((pkt = aom_codec_get_cx_data(&codec, &iter)) != nullptr) {
        // Process packets (no-op for fuzzing)
    }
    
    // Clean up
    aom_img_free(&img);
    aom_codec_destroy(&codec);
    
    return 0;
}
