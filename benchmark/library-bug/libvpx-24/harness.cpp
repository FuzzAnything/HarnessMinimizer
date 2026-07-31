#include <vpx/vp8dx.h>
#include <vpx/vp8cx.h>
#include <vpx/vpx_decoder.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <vector>
#include <fstream>
#include <iostream>




extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {

    // Initialize variables
    vpx_codec_ctx_t encoder;
    vpx_codec_ctx_t decoder;
    vpx_codec_enc_cfg_t config;
    vpx_image_t raw;
    vpx_img_fmt_t fmt = VPX_IMG_FMT_I420;
    vpx_codec_iter_t iter = NULL;
    const vpx_codec_cx_pkt_t* pkt;

    // Create input and output files
    FILE* in_file = fmemopen((void*)data, size, "rb");

    // Initialize encoder configuration
    vpx_codec_enc_config_default(vpx_codec_vp8_cx(), &config, 0);

    // Initialize encoder
    vpx_codec_enc_init_ver(&encoder, vpx_codec_vp8_cx(), &config, 0, VPX_ENCODER_ABI_VERSION);


    // Allocate image buffer
    vpx_img_alloc(&raw, fmt, config.g_w, config.g_h, 1);

    // Read input file and encode frames
    while (!feof(in_file)) {
        // Read image data
        size_t bytes_read = fread(raw.img_data, 1, config.g_w * config.g_h * 3 / 2, in_file);
        if (bytes_read <= 0) {
            break;
        }

        // Encode frame
        vpx_codec_encode(&encoder, &raw, 0, 0xbd6b566b15c7, 0, 0);

        // Get encoded packets
        while ((pkt = vpx_codec_get_cx_data(&encoder, &iter)) != NULL) {
            // Write encoded data to output file
        }
    }
    // Cleanup
    vpx_img_free(&raw);
    vpx_codec_destroy(&encoder);
        return 0;
}