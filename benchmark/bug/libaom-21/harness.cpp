// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_dec_init_ver at aom_decoder.c:25:17 in aom_decoder.h
// aom_codec_decode at aom_decoder.c:94:17 in aom_decoder.h
// aom_codec_get_stream_info at aom_decoder.c:75:17 in aom_decoder.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
// aom_codec_av1_dx at av1_dx_iface.c:1796:20 in aomdx.h
// aom_codec_dec_init_ver at aom_decoder.c:25:17 in aom_decoder.h
// aom_codec_dec_init_ver at aom_decoder.c:25:17 in aom_decoder.h
// aom_codec_set_option at aom_codec.c:119:17 in aom_codec.h
// aom_codec_decode at aom_decoder.c:94:17 in aom_decoder.h
// aom_codec_get_stream_info at aom_decoder.c:75:17 in aom_decoder.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "aom/aom_codec.h"
#include "aom/aom_decoder.h"
#include "aom/aomdx.h"

static const char *option_names[] = {
    "threads", "cpu-used", "profile", "limit", "error-resilient", NULL
};

static const char *option_values[] = {
    "0", "1", "2", "3", "4", "auto", "none", "default", NULL
};

static int control_ids[] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 256, 512, 1024, 2048, 4096
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    aom_codec_ctx_t ctx;
    aom_codec_iface_t *iface = aom_codec_av1_dx();
    aom_codec_dec_cfg_t cfg;
    aom_codec_stream_info_t si;
    aom_codec_err_t res;

    // Initialize configuration with some defaults
    memset(&cfg, 0, sizeof(cfg));
    cfg.threads = 1;
    cfg.w = 320;
    cfg.h = 240;

    // Initialize stream info
    memset(&si, 0, sizeof(si));

    // Initialize decoder with version checking
    res = aom_codec_dec_init_ver(&ctx, iface, &cfg, 0, AOM_DECODER_ABI_VERSION);
    if (res != AOM_CODEC_OK) {
        // If initialization fails, try with NULL config
        res = aom_codec_dec_init_ver(&ctx, iface, NULL, 0, AOM_DECODER_ABI_VERSION);
        if (res != AOM_CODEC_OK) {
            return 0;
        }
    }

    // Try to set some options using fuzz data
    if (Size > 10) {
        size_t name_idx = Data[0] % 5;
        size_t value_idx = Data[1] % 8;
        aom_codec_set_option(&ctx, option_names[name_idx], option_values[value_idx]);
    }

    // Try to decode the input data
    if (Size > 0) {
        // Use first byte as user_priv pointer (will be truncated but that's OK for fuzzing)
        void *user_priv = (void *)(uintptr_t)Data[0];
        size_t decode_size = Size > 1024 ? 1024 : Size;
        aom_codec_decode(&ctx, Data, decode_size, user_priv);
    }

    // Try to get stream info
    aom_codec_get_stream_info(&ctx, &si);

    // Try some control operations
    if (Size > 2) {
        size_t ctrl_idx = Data[2] % (sizeof(control_ids) / sizeof(control_ids[0]));
        int ctrl_id = control_ids[ctrl_idx];
        int param = (int)Data[3];
        aom_codec_control(&ctx, ctrl_id, param);
    }

    // Try another control with different parameter type
    if (Size > 4) {
        void *param = (void *)(uintptr_t)Data[4];
        aom_codec_control(&ctx, 1, param);
    }

    // Clean up
    aom_codec_destroy(&ctx);

    // Try to initialize and destroy multiple times with different configurations
    if (Size > 20) {
        aom_codec_ctx_t ctx2;
        aom_codec_dec_cfg_t cfg2;
        
        memset(&cfg2, 0, sizeof(cfg2));
        cfg2.threads = Data[5] % 8 + 1;
        cfg2.w = (Data[6] << 8) | Data[7];
        cfg2.h = (Data[8] << 8) | Data[9];
        
        // Limit dimensions to reasonable values
        if (cfg2.w > 4096) cfg2.w = 4096;
        if (cfg2.h > 4096) cfg2.h = 4096;
        if (cfg2.w < 16) cfg2.w = 16;
        if (cfg2.h < 16) cfg2.h = 16;
        
        aom_codec_flags_t flags = Data[10] % 4;
        
        res = aom_codec_dec_init_ver(&ctx2, iface, &cfg2, flags, AOM_DECODER_ABI_VERSION);
        if (res == AOM_CODEC_OK) {
            // Try to decode remaining data
            size_t remaining = Size - 20;
            if (remaining > 0 && remaining < Size) {
                aom_codec_decode(&ctx2, Data + 20, remaining, NULL);
                aom_codec_get_stream_info(&ctx2, &si);
            }
            aom_codec_destroy(&ctx2);
        }
    }

    return 0;
}
