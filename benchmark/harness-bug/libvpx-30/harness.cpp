/*
 * Fuzzing harness for libvpx encoder configuration and advanced features
 * Targets: vpx_codec_enc_config_set, vpx_codec_get_global_headers, vpx_codec_get_preview_frame,
 *          vpx_codec_set_cx_data_buf, vpx_img_wrap, vpx_codec_get_caps, vpx_codec_iface_name
 * Focuses on encoder configuration lifecycle: capabilities checking -> config setup -> 
 * buffer management -> encoding -> header/preview retrieval
 * 
 * Recommended fuzzer flags to prevent OOM:
 * -rss_limit_mb=4096 -max_len=10485760 -max_total_time=600 -max_corpus_size=500
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
#include <memory>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"
#include "vpx/vp8cx.h"
#include "vpx/vpx_encoder.h"
#include "vpx/vpx_image.h"

#define MAX_WIDTH 1920
#define MAX_HEIGHT 1080
#define MIN_WIDTH 16
#define MIN_HEIGHT 16
#define MAX_BUFFER_SIZE (2 * 1024 * 1024) // 2MB maximum buffer size
#define OUTPUT_BUFFER_PADDING 1024 // Padding for output buffer

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum input size: enough for basic configuration choices
    if (size < 64) {
        return 0;  // Not enough data for meaningful testing
    }

    FuzzedDataProvider fdp(data, size);

    // Choose encoder type: 0 = VP8, 1 = VP9
    uint8_t encoder_choice = fdp.ConsumeIntegral<uint8_t>() % 2;
    
    // Choose image format: limited to formats supported by both codecs
    uint8_t format_choice = fdp.ConsumeIntegral<uint8_t>() % 3; // 0=I420, 1=I422, 2=I444
    
    // Choose image dimensions with reasonable limits
    unsigned int width = fdp.ConsumeIntegralInRange<unsigned int>(MIN_WIDTH, MAX_WIDTH);
    unsigned int height = fdp.ConsumeIntegralInRange<unsigned int>(MIN_HEIGHT, MAX_HEIGHT);
    
    // Choose number of threads [1, 8]
    unsigned int threads = fdp.ConsumeIntegralInRange<unsigned int>(1, 8);
    
    // Choose target bitrate [100, 10000] kbps
    unsigned int target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 10000);
    
    // Choose whether to dynamically change config after initialization
    bool change_config = fdp.ConsumeBool();
    
    // Choose whether to test global headers retrieval (mainly VP9)
    bool test_global_headers = fdp.ConsumeBool();
    
    // Choose whether to test preview frame retrieval
    bool test_preview_frame = fdp.ConsumeBool();
    
    // Get the interface for chosen encoder
    vpx_codec_iface_t* encoder_iface = nullptr;
    if (encoder_choice == 0) {
        encoder_iface = vpx_codec_vp8_cx();
    } else {
        encoder_iface = vpx_codec_vp9_cx();
    }
    
    if (!encoder_iface) {
        return 0;  // Encoder interface not available
    }
    
    // STEP 1: Check encoder capabilities using vpx_codec_get_caps
    vpx_codec_caps_t caps = vpx_codec_get_caps(encoder_iface);
    (void)caps;  // Use the result to prevent optimization
    
    // STEP 2: Get codec interface name using vpx_codec_iface_name
    const char* iface_name = vpx_codec_iface_name(encoder_iface);
    (void)iface_name;  // Use the result to prevent optimization
    
    // Set image format based on choice
    vpx_img_fmt_t img_fmt = VPX_IMG_FMT_I420;
    switch (format_choice) {
        case 0: img_fmt = VPX_IMG_FMT_I420; break;
        case 1: img_fmt = VPX_IMG_FMT_I422; break;
        case 2: img_fmt = VPX_IMG_FMT_I444; break;
    }
    
    // STEP 3: Get default encoder configuration using vpx_codec_enc_config_default
    vpx_codec_enc_cfg_t cfg;
    vpx_codec_err_t err = vpx_codec_enc_config_default(encoder_iface, &cfg, 0);
    
    if (err != VPX_CODEC_OK) {
        return 0;  // Failed to get default configuration
    }
    
    // Set initial configuration parameters from fuzzer input
    cfg.g_w = width;
    cfg.g_h = height;
    cfg.g_threads = threads;
    cfg.g_timebase.num = 1;
    cfg.g_timebase.den = 30;  // 30 fps
    cfg.rc_target_bitrate = target_bitrate;
    cfg.g_pass = VPX_RC_ONE_PASS;
    cfg.g_lag_in_frames = 0;
    
    // STEP 4: Initialize encoder using vpx_codec_enc_init_ver
    vpx_codec_ctx_t codec;
    vpx_codec_flags_t flags = 0;
    
    err = vpx_codec_enc_init_ver(&codec, encoder_iface, &cfg, flags, VPX_ENCODER_ABI_VERSION);
    
    if (err != VPX_CODEC_OK) {
        return 0;  // Encoder initialization failed
    }
    
    // STEP 5: Dynamically change configuration if requested using vpx_codec_enc_config_set
    if (change_config) {
        // Modify some configuration parameters
        cfg.rc_target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 10000);
        cfg.g_threads = fdp.ConsumeIntegralInRange<unsigned int>(1, 8);
        
        err = vpx_codec_enc_config_set(&codec, &cfg);
        // Accept both OK and errors - testing error paths is also valuable
        (void)err;
    }
    
    // STEP 6: Create image buffers using vpx_img_wrap
    // Calculate required buffer size for image
    size_t y_plane_size = width * height;
    size_t uv_plane_size = 0;
    
    switch (img_fmt) {
        case VPX_IMG_FMT_I420:
            uv_plane_size = (width / 2) * (height / 2);
            break;
        case VPX_IMG_FMT_I422:
            uv_plane_size = (width / 2) * height;
            break;
        case VPX_IMG_FMT_I444:
            uv_plane_size = width * height;
            break;
        default:
            uv_plane_size = (width / 2) * (height / 2); // Default to I420
    }
    
    size_t total_img_size = y_plane_size + 2 * uv_plane_size;
    
    // Limit image size to prevent excessive memory usage
    if (total_img_size > MAX_BUFFER_SIZE) {
        vpx_codec_destroy(&codec);
        return 0;
    }
    
    // Allocate image buffer
    uint8_t* img_buffer = (uint8_t*)malloc(total_img_size);
    if (!img_buffer) {
        vpx_codec_destroy(&codec);
        return 0;
    }
    
    // Fill image buffer with fuzzer data
    size_t bytes_to_fill = std::min(fdp.remaining_bytes(), total_img_size);
    if (bytes_to_fill > 0) {
        std::vector<uint8_t> img_data = fdp.ConsumeBytes<uint8_t>(bytes_to_fill);
        memcpy(img_buffer, img_data.data(), bytes_to_fill);
    }
    
    // Wrap the buffer as a vpx_image_t
    vpx_image_t img;
    vpx_img_wrap(&img, img_fmt, width, height, 1, img_buffer);
    
    // STEP 7: Set output buffer using vpx_codec_set_cx_data_buf
    // Allocate output buffer with padding
    size_t output_buffer_size = 256 * 1024 + OUTPUT_BUFFER_PADDING; // 256KB + padding
    uint8_t* output_buffer = (uint8_t*)malloc(output_buffer_size);
    if (!output_buffer) {
        free(img_buffer);
        vpx_codec_destroy(&codec);
        return 0;
    }
    
    vpx_fixed_buf_t output_buf;
    output_buf.buf = output_buffer;
    output_buf.sz = output_buffer_size;
    
    err = vpx_codec_set_cx_data_buf(&codec, &output_buf, OUTPUT_BUFFER_PADDING, 0);
    // Accept both OK and errors - testing error paths is also valuable
    (void)err;
    
    // STEP 8: Encode frame using vpx_codec_encode
    // Use remaining fuzzer data for PTS and duration
    int64_t pts = fdp.ConsumeIntegral<int64_t>();
    unsigned long duration = fdp.ConsumeIntegral<unsigned long>();
    vpx_enc_frame_flags_t encode_flags = 0;
    
    // Randomly choose deadline mode
    uint8_t deadline_choice = fdp.ConsumeIntegral<uint8_t>() % 3;
    vpx_enc_deadline_t deadline = VPX_DL_BEST_QUALITY;
    switch (deadline_choice) {
        case 0: deadline = VPX_DL_REALTIME; break;
        case 1: deadline = VPX_DL_GOOD_QUALITY; break;
        case 2: deadline = VPX_DL_BEST_QUALITY; break;
    }
    
    err = vpx_codec_encode(&codec, &img, pts, duration, encode_flags, deadline);
    // Accept both OK and errors - testing error paths is also valuable
    (void)err;
    // STEP 9: Retrieve encoded data using vpx_codec_get_cx_data
    vpx_codec_iter_t iter = nullptr;
    const vpx_codec_cx_pkt_t* pkt = nullptr;
    while ((pkt = vpx_codec_get_cx_data(&codec, &iter)) != nullptr) {
        // Process packet if needed
        (void)pkt;
    }
    // STEP 10: Get global headers if requested (mainly for VP9)
    if (test_global_headers) {
        vpx_fixed_buf_t* global_headers = vpx_codec_get_global_headers(&codec);
        (void)global_headers;  // Use the result to prevent optimization
    }
    
    // STEP 11: Get preview frame if requested
    if (test_preview_frame) {
        const vpx_image_t* preview_frame = vpx_codec_get_preview_frame(&codec);
        (void)preview_frame;  // Use the result to prevent optimization
    }
    
    // STEP 12: Clean up resources
    free(img_buffer);
    free(output_buffer);
    vpx_codec_destroy(&codec);
    
    return 0;
}
