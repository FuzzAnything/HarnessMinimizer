/*
 *
 * Fuzzing harness for AV1 encoder workflow with custom data buffer configuration.
 * This harness targets currently uncovered APIs:
 *   - aom_codec_set_cx_data_buf (completely uncovered, 6 undiscovered branches)
 *   - aom_codec_enc_config_set (6 undiscovered branches)
 *   - aom_codec_encode (22 undiscovered branches)
 *   - aom_codec_get_cx_data (11 undiscovered branches)
 *   - aom_codec_enc_init_ver (Required Helper: Initialization)
 *   - aom_codec_destroy (Required Helper: Cleanup)
 *   - aom_codec_enc_config_default (Required Helper: Default configuration)
 * Strategy: Test complete encoder lifecycle with custom compressed data buffer
 * management using aom_codec_set_cx_data_buf. Explore different buffer sizes,
 * padding configurations, and encoder parameters to target 45+ points of
 * undiscovered complexity.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <algorithm>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"
#include "aom/aom_codec.h"
#include "aom/aom_image.h"
#include "aom/aomcx.h"
#include "aom/aom_encoder.h"

// Minimum input size required for meaningful testing
#define MIN_INPUT_SIZE 256

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Require minimum input size for encoder configuration
    if (size < MIN_INPUT_SIZE) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);

    // 1. Get the AV1 encoder interface
    aom_codec_iface_t *encoder = aom_codec_av1_cx();
    if (!encoder) {
        return 0;
    }

    // 2. Initialize encoder configuration with default values
    aom_codec_enc_cfg_t cfg;
    if (aom_codec_enc_config_default(encoder, &cfg, 0) != AOM_CODEC_OK) {
        return 0;
    }

    // Consume configuration parameters with reasonable limits to avoid OOM
    cfg.g_w = fdp.ConsumeIntegralInRange<unsigned int>(16, 64);
    cfg.g_h = fdp.ConsumeIntegralInRange<unsigned int>(16, 64);
    // Limit total pixels to prevent excessive memory usage
    if (cfg.g_w * cfg.g_h > 4096) {  // Limit to 64x64
        return 0;
    }
    
    // Consume other configuration parameters from fuzzer input
    cfg.g_bit_depth = fdp.ConsumeBool() ? AOM_BITS_8 : AOM_BITS_10;
    cfg.g_timebase.num = fdp.ConsumeIntegralInRange<int>(1, 100);
    cfg.g_timebase.den = fdp.ConsumeIntegralInRange<int>(1, 100);
    cfg.g_error_resilient = fdp.ConsumeBool();
    int pass_choice = fdp.ConsumeIntegralInRange<int>(0, 3);
    cfg.g_pass = static_cast<aom_enc_pass>(pass_choice);
    cfg.g_lag_in_frames = fdp.ConsumeIntegralInRange<unsigned int>(0, 25);
    cfg.g_threads = fdp.ConsumeIntegralInRange<unsigned int>(1, 4);
    cfg.g_profile = fdp.ConsumeIntegralInRange<unsigned int>(0, 3);
    
    // 3. Initialize encoder context
    aom_codec_ctx_t codec;
    if (aom_codec_enc_init_ver(&codec, encoder, &cfg, 0, AOM_ENCODER_ABI_VERSION) != AOM_CODEC_OK) {
        return 0;
    }

    // 4. Apply configuration changes with aom_codec_enc_config_set
    // Modify some additional configuration values
    cfg.g_forced_max_frame_width = fdp.ConsumeIntegralInRange<unsigned int>(0, 128);
    cfg.g_forced_max_frame_height = fdp.ConsumeIntegralInRange<unsigned int>(0, 128);
    cfg.rc_end_usage = static_cast<aom_rc_mode>(fdp.ConsumeIntegralInRange<int>(0, 3));
    cfg.rc_target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 1000000);
    
    aom_codec_enc_config_set(&codec, &cfg);

    // 5. Prepare custom compressed data buffer for aom_codec_set_cx_data_buf
    // Consume buffer size and padding parameters
    size_t buffer_size = fdp.ConsumeIntegralInRange<size_t>(1024, 65536);  // Reasonable buffer size
    unsigned int pad_before = fdp.ConsumeIntegralInRange<unsigned int>(0, 256);
    unsigned int pad_after = fdp.ConsumeIntegralInRange<unsigned int>(0, 256);
    
    // Allocate buffer for compressed data
    uint8_t *cx_buffer = static_cast<uint8_t*>(malloc(buffer_size + pad_before + pad_after));
    if (!cx_buffer) {
        aom_codec_destroy(&codec);
        return 0;
    }
    
    // Initialize buffer with fuzzed data
    size_t init_data_size = std::min(buffer_size, fdp.remaining_bytes());
    if (init_data_size > 0) {
        std::vector<uint8_t> init_data = fdp.ConsumeBytes<uint8_t>(init_data_size);
        memcpy(cx_buffer + pad_before, init_data.data(), init_data_size);
    }
    
    // Create aom_fixed_buf_t structure
    aom_fixed_buf_t buf;
    buf.buf = cx_buffer + pad_before;  // Point to data area after pad_before
    buf.sz = buffer_size;
    
    // 6. Set custom compressed data buffer
    aom_codec_set_cx_data_buf(&codec, &buf, pad_before, pad_after);
    
    // 7. Create and fill test image for encoding
    aom_image_t *img = nullptr;
    // List of valid image formats
    static const aom_img_fmt_t valid_fmts[] = {
        AOM_IMG_FMT_I420, AOM_IMG_FMT_YV12, AOM_IMG_FMT_AOMYV12, AOM_IMG_FMT_AOMI420,
        AOM_IMG_FMT_I422, AOM_IMG_FMT_I444, AOM_IMG_FMT_NV12,
        AOM_IMG_FMT_I42016, AOM_IMG_FMT_YV1216, AOM_IMG_FMT_I42216, AOM_IMG_FMT_I44416
    };
    size_t fmt_index = fdp.ConsumeIntegralInRange<size_t>(0, sizeof(valid_fmts)/sizeof(valid_fmts[0])-1);
    aom_img_fmt_t fmt = valid_fmts[fmt_index];
    unsigned int align = 1 << fdp.ConsumeIntegralInRange<unsigned int>(0, 4); // 1,2,4,8,16
    
    img = aom_img_alloc(nullptr, fmt, cfg.g_w, cfg.g_h, align);
    if (img == nullptr) {
        free(cx_buffer);
        aom_codec_destroy(&codec);
        return 0;
    }
    
    // Fill image planes with fuzzed data
    for (int plane = 0; plane < AOM_PLANE_PACKED; ++plane) {
        unsigned char *plane_buf = img->planes[plane];
        if (plane_buf) {
            size_t plane_height = aom_img_plane_height(img, plane);
            size_t stride = img->stride[plane];
            size_t plane_width = aom_img_plane_width(img, plane);
            
            // Calculate bytes per sample based on format
            size_t bytes_per_sample = (fmt & AOM_IMG_FMT_HIGHBITDEPTH) ? 2 : 1;
            size_t row_data_size = plane_width * bytes_per_sample;
            
            // Fill each row with fuzzed data
            for (size_t row = 0; row < plane_height; ++row) {
                if (fdp.remaining_bytes() < row_data_size) {
                    break;  // Not enough data for this row
                }
                std::vector<uint8_t> row_data = fdp.ConsumeBytes<uint8_t>(row_data_size);
                memcpy(plane_buf + row * stride, row_data.data(), row_data_size);
            }
        }
    }
    
    // 8. Encode the image using aom_codec_encode
    // Consume encoding parameters
    aom_codec_pts_t pts = fdp.ConsumeIntegral<aom_codec_pts_t>();
    unsigned long duration = fdp.ConsumeIntegralInRange<unsigned long>(1, 1000);
    aom_enc_frame_flags_t flags = fdp.ConsumeIntegral<aom_enc_frame_flags_t>();
    
    aom_codec_encode(&codec, img, pts, duration, flags);
    
    // 9. Retrieve compressed data using aom_codec_get_cx_data
    aom_codec_iter_t iter = nullptr;
    const aom_codec_cx_pkt_t *pkt;
    size_t total_encoded_size = 0;
    
    while ((pkt = aom_codec_get_cx_data(&codec, &iter)) != nullptr) {
        if (pkt->kind == AOM_CODEC_CX_FRAME_PKT) {
            total_encoded_size += pkt->data.frame.sz;
            // The compressed data should be in our custom buffer if it fit
            // (though the API may use internal buffer if our buffer is too small)
        }
    }
    
    // 10. Test aom_codec_set_cx_data_buf with NULL buffer to restore default behavior
    aom_codec_set_cx_data_buf(&codec, nullptr, 0, 0);
    
    // 11. Clean up resources
    aom_img_free(img);
    free(cx_buffer);
    aom_codec_destroy(&codec);
    
    return 0;
}
