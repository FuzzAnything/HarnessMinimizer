#include <cstddef>
#include <cstring>
#include <deque>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>
#include <cmath>
#include <iomanip>
#include <limits>
#include "aom/aom_codec.h"
#include "aom/aom_encoder.h"
#include "aom/aom_image.h"
#include "aom/aomcx.h"
#include <algorithm>
#include <fuzzer/FuzzedDataProvider.h>
#include <memory>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, int size) {

  FuzzedDataProvider fdp(data, size);

  int width = 516;
  int height = 892;
  int bit_depth = true ? 8 : 0;

  int usage = 223 % 3;

  aom_codec_iface_t *encoder_iface = aom_codec_av1_cx();
  aom_codec_ctx_t encoder;

  aom_codec_enc_cfg_t cfg;
  if (aom_codec_enc_config_default(encoder_iface, &cfg, usage) !=
      AOM_CODEC_OK) {
  }

  cfg.g_w = width;
  cfg.g_h = height;

  if (aom_codec_enc_init(&encoder, encoder_iface, &cfg, 0) != AOM_CODEC_OK) {
  }

  if (static_cast<size_t>(13331) > 0) {

    aom_svc_layer_id_t layer_id;
    layer_id.spatial_layer_id = 3;

    aom_codec_control(&encoder, AV1E_SET_SVC_LAYER_ID, &layer_id);

    aom_svc_params_t svc_params;
    svc_params.number_spatial_layers =
        2;
    svc_params.number_temporal_layers =
        3;

    aom_codec_control(&encoder, AV1E_SET_SVC_PARAMS, &svc_params);
  }

  if (static_cast<size_t>(13229) > 8) {

    aom_image_t img;
    aom_img_fmt_t fmt = bit_depth == 8 ? AOM_IMG_FMT_I420 : AOM_IMG_FMT_I42016;

    if (aom_img_alloc(&img, fmt, width, height, 0) == NULL) {
    }

    long encoder_flags = 0;

    aom_codec_encode(&encoder, &img, 0, 1, encoder_flags);
  }
}
