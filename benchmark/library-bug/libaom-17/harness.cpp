#include <stdlib.h>  
#include <string.h>  
#include <stdint.h>  
#include <vector>  
#include <fstream>  
#include <iostream>  
#include <sstream> 

#include "aom/aom_codec.h"
#include "aom/aom_image.h"
#include <aom/aomcx.h> 

// poc.cc
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* f_data, size_t f_size) {
  // Initialize codec
  aom_codec_iface_t *codec_iface = aom_codec_av1_cx();
  if (codec_iface == nullptr) {
        return 0;
  }

  aom_codec_ctx_t codec_ctx;
  aom_codec_enc_cfg_t enc_cfg;
  if (aom_codec_enc_config_default(codec_iface, &enc_cfg, 0) != AOM_CODEC_OK) {
    aom_codec_destroy(&codec_ctx);
          return 0;
  }

  if (aom_codec_enc_init_ver(&codec_ctx, codec_iface, &enc_cfg, AOM_CODEC_USE_HIGHBITDEPTH, AOM_ENCODER_ABI_VERSION) != AOM_CODEC_OK) {
    aom_codec_destroy(&codec_ctx);
        return 0;
  }

  // Create image buffer
  aom_image_t *image = aom_img_alloc(NULL, AOM_IMG_FMT_I420, enc_cfg.g_w, enc_cfg.g_h, 0);
  if (image == nullptr) {
    aom_codec_destroy(&codec_ctx);
        return 0;
  }

  if (aom_codec_encode(&codec_ctx, image, 0, 1, 0) != AOM_CODEC_OK) {
    aom_img_free(image);
    aom_codec_destroy(&codec_ctx);
        return 0;
  }

  aom_img_free(image);
  aom_codec_destroy(&codec_ctx);
        return 0;
}