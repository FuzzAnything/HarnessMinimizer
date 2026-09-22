// This fuzz driver is generated for library libaom, aiming to fuzz the following functions:
// aom_codec_encode at aom_encoder.c:168:17 in aom_encoder.h
// aom_codec_encode at aom_encoder.c:168:17 in aom_encoder.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
// aom_codec_enc_init_ver at aom_encoder.c:38:17 in aom_encoder.h
// aom_codec_destroy at aom_codec.c:68:17 in aom_codec.h
// aom_codec_enc_config_default at aom_encoder.c:100:17 in aom_encoder.h
// aom_codec_enc_init_ver at aom_encoder.c:38:17 in aom_encoder.h
// aom_codec_set_option at aom_codec.c:119:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_control at aom_codec.c:88:17 in aom_codec.h
// aom_codec_enc_config_set at aom_encoder.c:298:17 in aom_encoder.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "aom/aom.h"
#include "aom/aom_codec.h"
#include "aom/aom_encoder.h"
#include "aom/aomcx.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize codec context
    aom_codec_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    
    // Initialize encoder configuration
    aom_codec_enc_cfg_t cfg;
    aom_codec_iface_t *iface = aom_codec_av1_cx();
    
    // Get default configuration
    aom_codec_err_t err = aom_codec_enc_config_default(iface, &cfg, 0);
    if (err != AOM_CODEC_OK) {
        return 0;
    }
    
    // Modify some configuration parameters with fuzzer data
    if (Size > sizeof(unsigned int)) {
        cfg.g_w = *(unsigned int*)Data % 1024 + 1;
        cfg.g_h = *(unsigned int*)(Data + sizeof(unsigned int)) % 1024 + 1;
        cfg.rc_target_bitrate = *(unsigned int*)Data % 2000000;
    }
    
    // Initialize encoder
    err = aom_codec_enc_init_ver(&ctx, iface, &cfg, 0, AOM_ENCODER_ABI_VERSION);
    if (err != AOM_CODEC_OK) {
        return 0;
    }
    
    // Use first byte to determine which operations to perform
    uint8_t operation = Data[0];
    size_t data_offset = 1;
    
    // Test aom_codec_set_option
    if (Size > data_offset + 2) {
        char key[64] = {0};
        char value[64] = {0};
        size_t key_len = Data[data_offset] % 63 + 1;
        size_t val_len = Data[data_offset + 1] % 63 + 1;
        
        if (Size > data_offset + 2 + key_len + val_len) {
            memcpy(key, Data + data_offset + 2, key_len);
            memcpy(value, Data + data_offset + 2 + key_len, val_len);
            key[key_len] = '\0';
            value[val_len] = '\0';
            aom_codec_set_option(&ctx, key, value);
            data_offset += 2 + key_len + val_len;
        }
    }
    
    // Test aom_codec_control with various control IDs
    if (Size > data_offset + sizeof(int)) {
        int ctrl_id = *(int*)(Data + data_offset);
        data_offset += sizeof(int);
        
        // Try different control IDs based on fuzzer input
        if (operation & 0x01) {
            // AOME_SET_CPUUSED
            int cpu_used = ctrl_id % 9;
            aom_codec_control(&ctx, AOME_SET_CPUUSED, cpu_used);
        }
        if (operation & 0x02) {
            // AOME_SET_ENABLEAUTOALTREF
            int enable = ctrl_id & 1;
            aom_codec_control(&ctx, AOME_SET_ENABLEAUTOALTREF, enable);
        }
        if (operation & 0x04) {
            // AOME_SET_ARNR_MAXFRAMES
            int arnr_frames = ctrl_id % 16;
            aom_codec_control(&ctx, AOME_SET_ARNR_MAXFRAMES, arnr_frames);
        }
        if (operation & 0x08) {
            // AOME_SET_ARNR_STRENGTH
            int arnr_strength = ctrl_id % 7;
            aom_codec_control(&ctx, AOME_SET_ARNR_STRENGTH, arnr_strength);
        }
    }
    
    // Test aom_codec_enc_config_set
    if (operation & 0x10) {
        // Modify configuration and try to set it
        if (Size > data_offset + sizeof(unsigned int)) {
            cfg.rc_min_quantizer = *(unsigned int*)(Data + data_offset) % 64;
            cfg.rc_max_quantizer = *(unsigned int*)(Data + data_offset + sizeof(unsigned int)) % 64;
            data_offset += 2 * sizeof(unsigned int);
            aom_codec_enc_config_set(&ctx, &cfg);
        }
    }
    
    // Test aom_codec_encode
    if (operation & 0x20) {
        // Create a dummy image
        aom_image_t img;
        memset(&img, 0, sizeof(img));
        img.fmt = AOM_IMG_FMT_I420;
        img.bit_depth = 8;
        img.w = cfg.g_w;
        img.h = cfg.g_h;
        img.d_w = cfg.g_w;
        img.d_h = cfg.g_h;
        img.x_chroma_shift = 1;
        img.y_chroma_shift = 1;
        img.planes[0] = (unsigned char*)malloc(cfg.g_w * cfg.g_h);
        img.planes[1] = (unsigned char*)malloc((cfg.g_w/2) * (cfg.g_h/2));
        img.planes[2] = (unsigned char*)malloc((cfg.g_w/2) * (cfg.g_h/2));
        
        if (img.planes[0] && img.planes[1] && img.planes[2]) {
            // Fill with some data from fuzzer input
            size_t y_size = cfg.g_w * cfg.g_h;
            size_t uv_size = (cfg.g_w/2) * (cfg.g_h/2);
            
            if (Size > data_offset) {
                size_t copy_size = Size - data_offset;
                if (copy_size > y_size) copy_size = y_size;
                memcpy(img.planes[0], Data + data_offset, copy_size);
                data_offset += copy_size;
                
                if (Size > data_offset && uv_size > 0) {
                    copy_size = Size - data_offset;
                    if (copy_size > uv_size) copy_size = uv_size;
                    memcpy(img.planes[1], Data + data_offset, copy_size);
                    data_offset += copy_size;
                    
                    if (Size > data_offset && uv_size > 0) {
                        copy_size = Size - data_offset;
                        if (copy_size > uv_size) copy_size = uv_size;
                        memcpy(img.planes[2], Data + data_offset, copy_size);
                    }
                }
            }
            
            // Encode the frame
            aom_codec_encode(&ctx, &img, 0, 1, 0);
            
            // Flush encoder
            aom_codec_encode(&ctx, NULL, 0, 1, 0);
            
            free(img.planes[0]);
            free(img.planes[1]);
            free(img.planes[2]);
        }
    }
    
    // Test aom_codec_destroy
    if (operation & 0x40) {
        aom_codec_destroy(&ctx);
        // Re-initialize for potential subsequent operations
        aom_codec_enc_init_ver(&ctx, iface, &cfg, 0, AOM_ENCODER_ABI_VERSION);
    }
    
    // Always destroy at the end
    aom_codec_destroy(&ctx);
    
    return 0;
}
