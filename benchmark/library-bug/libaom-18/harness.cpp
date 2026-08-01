#include <aom/aom_decoder.h>
#include <aom/aomcx.h>
#include <aom/aomdx.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <vector>
#include <fstream>
#include <iostream>
#include <sstream>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

    // Initialize libaom encoder context
    aom_codec_ctx_t encoder_ctx;
    memset(&encoder_ctx, 0, sizeof(aom_codec_ctx_t));
    aom_codec_iface_t *encoder_iface = aom_codec_av1_cx();

    // Set encoder configuration
    aom_codec_enc_cfg_t encoder_cfg;
    memset(&encoder_cfg, 0, sizeof(aom_codec_enc_cfg_t));
    aom_codec_enc_config_default(encoder_iface, &encoder_cfg, AOM_USAGE_ALL_INTRA);

    // Initialize encoder
    aom_codec_err_t encoder_init_result = aom_codec_enc_init_ver(
        &encoder_ctx, encoder_iface, &encoder_cfg, 0, AOM_ENCODER_ABI_VERSION
    );

    if (encoder_init_result != AOM_CODEC_OK) {
        return 0;
    }

    // Create an image to hold the frame
    aom_image_t *frame = aom_img_alloc(
        NULL,
        AOM_IMG_FMT_I420,
        encoder_cfg.g_w,
        encoder_cfg.g_h,
        32
    );

    if (!frame) {
        aom_codec_destroy(&encoder_ctx);
        return 0;
    }

    // Encode the frame
    aom_codec_encode(&encoder_ctx, frame, 0, 0x1, AOM_CODEC_USE_PSNR);

    // Cleanup
    aom_img_free(frame);
    aom_codec_destroy(&encoder_ctx);

    return 0;
}