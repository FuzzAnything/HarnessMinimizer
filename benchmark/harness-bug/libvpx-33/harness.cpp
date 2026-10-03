/*
 * Fuzzing harness for libvpx multi-encoder scenarios with varied configurations
 * Targets: vpx_codec_enc_init_multi_ver (29 undiscovered branches), vpx_codec_encode (18 undiscovered branches),
 *          vpx_codec_enc_init_ver (16 undiscovered branches), vpx_codec_get_cx_data (11 undiscovered branches)
 *          img_alloc_helper function edge cases (73 blocked branches)
 * Focus: Multi-encoder scenarios with different configurations, codec interfaces (VP8 and VP9), 
 *        image formats, alignment constraints, and error handling paths
 * Semantic differentiation: First harness specifically targeting multi-encoder initialization (vpx_codec_enc_init_multi_ver)
 *                          and comprehensive encoder configuration variations
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
#include <memory>
#include <vector>
#include <cstring>

#include <fuzzer/FuzzedDataProvider.h>

#include "vpx/vp8cx.h"
#include "vpx/vp8dx.h"
#include "vpx/vpx_encoder.h"
#include "vpx/vpx_decoder.h"
#include "vpx/vpx_codec.h"
#include "vpx/vpx_image.h"

// Maximum number of encoders for multi-encoder test
#define MAX_MULTI_ENCODERS 3

// Helper function to generate random image data
static void generate_test_image(vpx_image_t* img, FuzzedDataProvider& fdp) {
    if (!img || !img->planes[0]) return;
    
    // Fill Y plane
    size_t y_size = img->stride[VPX_PLANE_Y] * img->d_h;
    if (y_size > 0) {
        std::vector<uint8_t> y_data = fdp.ConsumeBytes<uint8_t>(y_size);
        if (y_data.size() == y_size) {
            memcpy(img->planes[VPX_PLANE_Y], y_data.data(), y_size);
        }
    }
    
    // Fill U plane for planar formats
    if (img->fmt & VPX_IMG_FMT_PLANAR) {
        size_t u_size = img->stride[VPX_PLANE_U] * ((img->d_h + 1) / 2);
        if (u_size > 0) {
            std::vector<uint8_t> u_data = fdp.ConsumeBytes<uint8_t>(u_size);
            if (u_data.size() == u_size) {
                memcpy(img->planes[VPX_PLANE_U], u_data.data(), u_size);
            }
        }
    }
    
    // Fill V plane for planar formats
    if (img->fmt & VPX_IMG_FMT_PLANAR) {
        size_t v_size = img->stride[VPX_PLANE_V] * ((img->d_h + 1) / 2);
        if (v_size > 0) {
            std::vector<uint8_t> v_data = fdp.ConsumeBytes<uint8_t>(v_size);
            if (v_data.size() == v_size) {
                memcpy(img->planes[VPX_PLANE_V], v_data.data(), v_size);
            }
        }
    }
}

// Test single encoder initialization and encoding
static void test_single_encoder(FuzzedDataProvider& fdp, vpx_codec_iface_t* iface, 
                                vpx_img_fmt_t img_fmt, unsigned int align) {
    if (fdp.remaining_bytes() < 50) return;
    
    vpx_codec_ctx_t codec;
    vpx_codec_enc_cfg_t cfg;
    
    // Get default configuration
    vpx_codec_err_t err = vpx_codec_enc_config_default(iface, &cfg, 0);
    if (err != VPX_CODEC_OK) return;
    
    // Consume configuration parameters from fuzzed input
    cfg.g_w = fdp.ConsumeIntegralInRange<unsigned int>(16, 512);
    cfg.g_h = fdp.ConsumeIntegralInRange<unsigned int>(16, 512);
    cfg.rc_target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 5000);
    cfg.g_timebase.num = 1;
    cfg.g_timebase.den = fdp.ConsumeIntegralInRange<unsigned int>(24, 60);
    cfg.g_error_resilient = fdp.ConsumeBool() ? 1 : 0;
    cfg.g_lag_in_frames = fdp.ConsumeIntegralInRange<unsigned int>(0, 5);
    
    // Consume rate control parameters
    cfg.rc_min_quantizer = fdp.ConsumeIntegralInRange<unsigned int>(0, 63);
    cfg.rc_max_quantizer = fdp.ConsumeIntegralInRange<unsigned int>(cfg.rc_min_quantizer, 63);
    cfg.rc_undershoot_pct = fdp.ConsumeIntegralInRange<unsigned int>(0, 100);
    cfg.rc_overshoot_pct = fdp.ConsumeIntegralInRange<unsigned int>(0, 100);
    
    // Consume encoder flags
    vpx_codec_flags_t flags = 0;
    if (fdp.ConsumeBool()) flags |= VPX_CODEC_USE_PSNR;
    if (fdp.ConsumeBool() && img_fmt == VPX_IMG_FMT_I42016) flags |= VPX_CODEC_USE_HIGHBITDEPTH;
    
    // Initialize encoder with vpx_codec_enc_init_ver (targeting 16 undiscovered branches)
    err = vpx_codec_enc_init_ver(&codec, iface, &cfg, flags, VPX_ENCODER_ABI_VERSION);
    if (err != VPX_CODEC_OK) {
        // Test error path - don't proceed if initialization fails
        return;
    }
    
    // Allocate image with specific alignment (testing img_alloc_helper edge cases)
    vpx_image_t raw;
    if (!vpx_img_alloc(&raw, img_fmt, cfg.g_w, cfg.g_h, align)) {
        vpx_codec_destroy(&codec);
        return;
    }
    
    // Generate test image data
    generate_test_image(&raw, fdp);
    
    // Encode frame with vpx_codec_encode (targeting 18 undiscovered branches)
    err = vpx_codec_encode(&codec, &raw, 0, 1, 0, VPX_DL_REALTIME);
    
    // Get encoded data with vpx_codec_get_cx_data (targeting 11 undiscovered branches)
    vpx_codec_iter_t iter = NULL;
    const vpx_codec_cx_pkt_t* pkt;
    while ((pkt = vpx_codec_get_cx_data(&codec, &iter)) != NULL) {
        // Process packet if needed
        (void)pkt;
    }
    
    // Test encoding with NULL image (flush)
    err = vpx_codec_encode(&codec, NULL, 0, 1, 0, VPX_DL_REALTIME);
    
    // Get remaining data
    iter = NULL;
    while ((pkt = vpx_codec_get_cx_data(&codec, &iter)) != NULL) {
        // Process packet if needed
        (void)pkt;
    }
    
    // Cleanup
    vpx_img_free(&raw);
    vpx_codec_destroy(&codec);
}

// Test multi-encoder initialization and encoding
static void test_multi_encoder(FuzzedDataProvider& fdp, vpx_codec_iface_t* iface) {
    // Multi-encoder is only supported for VP8
    if (iface != vpx_codec_vp8_cx()) return;
    
    if (fdp.remaining_bytes() < 200) return;
    
    int num_encoders = fdp.ConsumeIntegralInRange<int>(1, MAX_MULTI_ENCODERS);
    vpx_codec_ctx_t codec[MAX_MULTI_ENCODERS];
    vpx_codec_enc_cfg_t cfg[MAX_MULTI_ENCODERS];
    vpx_rational_t dsf[MAX_MULTI_ENCODERS];
    vpx_image_t raw[MAX_MULTI_ENCODERS];
    
    // Initialize configurations for each encoder
    for (int i = 0; i < num_encoders; i++) {
        vpx_codec_err_t err = vpx_codec_enc_config_default(iface, &cfg[i], 0);
        if (err != VPX_CODEC_OK) return;
        
        // Consume different configurations for each encoder
        unsigned int base_width = fdp.ConsumeIntegralInRange<unsigned int>(64, 512);
        unsigned int base_height = fdp.ConsumeIntegralInRange<unsigned int>(64, 512);
        
        // Apply downsampling factor
        unsigned int dsf_num = 1 << i;  // 1, 2, 4 for i=0,1,2
        unsigned int dsf_den = 1;
        dsf[i].num = dsf_num;
        dsf[i].den = dsf_den;
        
        cfg[i].g_w = base_width / dsf_num;
        cfg[i].g_h = base_height / dsf_num;
        if (cfg[i].g_w < 16) cfg[i].g_w = 16;
        if (cfg[i].g_h < 16) cfg[i].g_h = 16;
        
        cfg[i].rc_target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 2000);
        cfg[i].g_timebase.num = 1;
        cfg[i].g_timebase.den = fdp.ConsumeIntegralInRange<unsigned int>(24, 60);
        
        // Allocate image for each encoder
        unsigned int align = 1 << fdp.ConsumeIntegralInRange<unsigned int>(0, 5); // 1, 2, 4, 8, 16, 32
        if (!vpx_img_alloc(&raw[i], VPX_IMG_FMT_I420, cfg[i].g_w, cfg[i].g_h, align)) {
            // Cleanup already allocated images
            for (int j = 0; j < i; j++) {
                vpx_img_free(&raw[j]);
            }
            return;
        }
        
        // Generate test image data
        generate_test_image(&raw[i], fdp);
    }
    
    // Consume flags
    vpx_codec_flags_t flags = 0;
    if (fdp.ConsumeBool()) flags |= VPX_CODEC_USE_PSNR;
    
    // Initialize multi-encoder with vpx_codec_enc_init_multi_ver (targeting 29 undiscovered branches)
    vpx_codec_err_t err = vpx_codec_enc_init_multi_ver(&codec[0], iface, &cfg[0], 
                                                       num_encoders, flags, &dsf[0],
                                                       VPX_ENCODER_ABI_VERSION);
    if (err != VPX_CODEC_OK) {
        // Cleanup on failure
        for (int i = 0; i < num_encoders; i++) {
            vpx_img_free(&raw[i]);
        }
        return;
    }
    
    // Encode frames with each encoder
    for (int i = 0; i < num_encoders; i++) {
        err = vpx_codec_encode(&codec[i], &raw[i], 0, 1, 0, VPX_DL_REALTIME);
        
        // Get encoded data
        vpx_codec_iter_t iter = NULL;
        const vpx_codec_cx_pkt_t* pkt;
        while ((pkt = vpx_codec_get_cx_data(&codec[i], &iter)) != NULL) {
            // Process packet if needed
            (void)pkt;
        }
    }
    
    // Flush encoders
    for (int i = 0; i < num_encoders; i++) {
        err = vpx_codec_encode(&codec[i], NULL, 0, 1, 0, VPX_DL_REALTIME);
        
        vpx_codec_iter_t iter = NULL;
        const vpx_codec_cx_pkt_t* pkt;
        while ((pkt = vpx_codec_get_cx_data(&codec[i], &iter)) != NULL) {
            // Process packet if needed
            (void)pkt;
        }
    }
    
    // Cleanup
    for (int i = 0; i < num_encoders; i++) {
        vpx_img_free(&raw[i]);
        vpx_codec_destroy(&codec[i]);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum input size for meaningful testing
    if (size < 100) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Consume test type
    uint8_t test_type = fdp.ConsumeIntegral<uint8_t>();
    
    // Consume image format
    uint8_t format_choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 3);
    vpx_img_fmt_t img_fmt;
    switch (format_choice) {
        case 0: img_fmt = VPX_IMG_FMT_I420; break;
        case 1: img_fmt = VPX_IMG_FMT_YV12; break;
        case 2: img_fmt = VPX_IMG_FMT_I422; break;
        case 3: img_fmt = VPX_IMG_FMT_I42016; break;
        default: img_fmt = VPX_IMG_FMT_I420; break;
    }
    
    // Consume alignment (must be power of 2)
    unsigned int align_choice = fdp.ConsumeIntegralInRange<unsigned int>(0, 6);
    unsigned int align = 1 << align_choice; // 1, 2, 4, 8, 16, 32, 64
    
    // Limit alignment to safe value
    if (align > 256) align = 256;
    
    // Determine which codec interface to test
    uint8_t codec_choice = fdp.ConsumeIntegral<uint8_t>();
    vpx_codec_iface_t* iface = NULL;
    
    if (codec_choice & 0x01) {
        iface = vpx_codec_vp8_cx();
    } else {
        iface = vpx_codec_vp9_cx();
    }
    
    if (!iface) {
        return 0;
    }
    
    // Execute tests based on test_type
    if (test_type & 0x01) {
        // Test single encoder
        test_single_encoder(fdp, iface, img_fmt, align);
    }
    
    if (test_type & 0x02) {
        // Test multi-encoder (only for VP8)
        if (iface == vpx_codec_vp8_cx()) {
            test_multi_encoder(fdp, iface);
        }
    }
    
    return 0;
}
