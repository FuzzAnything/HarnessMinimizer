// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
// aom_codec_av1_dx at av1_dx_iface.c:1796:20 in aomdx.h
// aom_codec_dec_init_ver at aom_decoder.c:25:17 in aom_decoder.h
// aom_codec_dec_init_ver at aom_decoder.c:25:17 in aom_decoder.h
// aom_codec_set_option at aom_codec.c:119:17 in aom_codec.h
// aom_codec_decode at aom_decoder.c:94:17 in aom_decoder.h
// aom_codec_get_stream_info at aom_decoder.c:75:17 in aom_decoder.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "aom/aom_codec.h"
#include "aom/aom_decoder.h"
#include "aom/aomdx.h"

static void dummy_user_priv(void) {
    // Dummy user_priv for decode
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Initialize decoder context
    aom_codec_ctx_t ctx;
    aom_codec_iface_t *iface = aom_codec_av1_dx();
    
    // Initialize decoder with default config
    aom_codec_dec_cfg_t cfg = {0};
    cfg.threads = 1;
    
    aom_codec_err_t err = aom_codec_dec_init_ver(&ctx, iface, &cfg, 0, AOM_DECODER_ABI_VERSION);
    if (err != AOM_CODEC_OK) {
        // If init fails, try without config
        err = aom_codec_dec_init_ver(&ctx, iface, NULL, 0, AOM_DECODER_ABI_VERSION);
        if (err != AOM_CODEC_OK) {
            return 0;
        }
    }
    
    // Try to set options using fuzzer data
    if (Size > 4) {
        // Extract potential key-value pairs from data
        size_t key_len = Data[0] % 16 + 1;
        size_t val_len = Data[1] % 16 + 1;
        
        if (key_len + val_len + 2 <= Size) {
            char key[17] = {0};
            char val[17] = {0};
            
            memcpy(key, Data + 2, key_len % sizeof(key));
            memcpy(val, Data + 2 + key_len, val_len % sizeof(val));
            
            // Ensure null termination
            key[sizeof(key)-1] = '\0';
            val[sizeof(val)-1] = '\0';
            
            aom_codec_set_option(&ctx, key, val);
        }
    }
    
    // Decode the input data
    if (Size > 0) {
        aom_codec_decode(&ctx, Data, Size, reinterpret_cast<void *>(&dummy_user_priv));
        
        // Try to get stream info after decode
        aom_codec_stream_info_t si;
        memset(&si, 0, sizeof(si));
        aom_codec_get_stream_info(&ctx, &si);
    }
    
    // Try various control IDs with different parameters
    if (Size > 0) {
        // Use first byte to select control ID from a set of valid ones
        uint8_t control_selector = Data[0];
        
        // Try different control IDs based on fuzzer input
        switch (control_selector % 7) {
            case 0: {
                int value = (Size > 1) ? Data[1] : 0;
                aom_codec_control(&ctx, AOMD_GET_FRAME_CORRUPTED, &value);
                break;
            }
            case 1: {
                int value = (Size > 1) ? Data[1] : 0;
                aom_codec_control(&ctx, AOMD_GET_LAST_REF_UPDATES, &value);
                break;
            }
            case 2: {
                int value = 0;
                aom_codec_control(&ctx, AOMD_GET_LAST_REF_USED, &value);
                break;
            }
            case 3: {
                unsigned int value = (Size > 1) ? Data[1] : 0;
                aom_codec_control(&ctx, AV1D_GET_FRAME_SIZE, &value);
                break;
            }
            case 4: {
                int value = (Size > 1) ? Data[1] : 0;
                aom_codec_control(&ctx, AV1D_GET_BIT_DEPTH, &value);
                break;
            }
            case 5: {
                int value = (Size > 1) ? Data[1] : 0;
                aom_codec_control(&ctx, AV1D_GET_TILE_SIZE, &value);
                break;
            }
            case 6: {
                int value = 0;
                aom_codec_control(&ctx, AV1D_GET_DISPLAY_SIZE, &value);
                break;
            }
        }
    }
    
    // Clean up
    aom_codec_destroy(&ctx);
    
    return 0;
}
