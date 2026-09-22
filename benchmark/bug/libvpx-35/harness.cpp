/*
 * Fuzzing harness for libvpx multi-resolution encoding and advanced encoder control
 * Targets: vpx_codec_enc_init_multi_ver, vpx_codec_enc_config_set, 
 *          vpx_codec_get_global_headers, vpx_codec_get_preview_frame,
 *          vpx_codec_set_cx_data_buf
 */

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <memory>

#include "fuzzer/FuzzedDataProvider.h"

// libvpx headers
#include "vpx/vpx_codec.h"
#include "vpx/vpx_encoder.h"
#include "vpx/vpx_image.h"
#include "vpx/vp8cx.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check - need enough for configuration and fuzzed parameters
    if (size < 64) {
        return 0;
    }
    FuzzedDataProvider fdp(data, size);

    // Consume configuration parameters
    uint8_t codec_choice = fdp.ConsumeIntegral<uint8_t>() % 2; // 0: VP8, 1: VP9
    uint8_t num_encoders = fdp.ConsumeIntegralInRange<uint8_t>(2, 4); // 2-4 encoders as per guidance
    uint16_t base_width = fdp.ConsumeIntegralInRange<uint16_t>(64, 1920);
    uint16_t base_height = fdp.ConsumeIntegralInRange<uint16_t>(64, 1080);
    uint32_t base_bitrate = fdp.ConsumeIntegralInRange<uint32_t>(1000, 10000000);
    uint8_t test_advanced = fdp.ConsumeIntegral<uint8_t>() % 4; // Which advanced feature to test
    uint8_t frame_count = fdp.ConsumeIntegralInRange<uint8_t>(1, 3);
    
    // Select codec interface based on choice
    vpx_codec_iface_t* codec_iface = nullptr;
    if (codec_choice == 0) {
        codec_iface = vpx_codec_vp8_cx();
    } else {
        codec_iface = vpx_codec_vp9_cx();
    }
    
    if (!codec_iface) {
        return 0;
    }

    // Array of encoder contexts, configurations, and downsampling factors
    std::vector<vpx_codec_ctx_t> encoders(num_encoders);
    std::vector<vpx_codec_enc_cfg_t> configs(num_encoders);
    std::vector<vpx_rational_t> dsf(num_encoders);
    
    // Initialize downsampling factors - different for each encoder
    for (size_t i = 0; i < num_encoders; ++i) {
        dsf[i].num = fdp.ConsumeIntegralInRange<int>(1, 4);
        dsf[i].den = fdp.ConsumeIntegralInRange<int>(1, 4);
        // Ensure valid downsampling (denominator > 0)
        if (dsf[i].den == 0) dsf[i].den = 1;
    }
    
    // Get default configuration for each encoder
    for (size_t i = 0; i < num_encoders; ++i) {
        if (vpx_codec_enc_config_default(codec_iface, &configs[i], 0) != VPX_CODEC_OK) {
            return 0;
        }
        
        // Configure each encoder with different resolutions based on downsampling
        configs[i].g_w = base_width * dsf[i].den / dsf[i].num;
        configs[i].g_h = base_height * dsf[i].den / dsf[i].num;
        if (configs[i].g_w < 16) configs[i].g_w = 16;
        if (configs[i].g_h < 16) configs[i].g_h = 16;
        
        configs[i].rc_target_bitrate = base_bitrate / (i + 1);
        configs[i].g_timebase.num = 1;
        configs[i].g_timebase.den = 30;
        configs[i].g_lag_in_frames = 0;
        configs[i].g_error_resilient = fdp.ConsumeBool() ? 1 : 0;
    }
    
    // Initialize multi-encoder context
    vpx_codec_err_t res = vpx_codec_enc_init_multi_ver(
        encoders.data(), codec_iface, configs.data(), num_encoders, 
        0, dsf.data(), VPX_ENCODER_ABI_VERSION);
    
    if (res != VPX_CODEC_OK) {
        // Clean up any partially initialized encoders
        for (size_t i = 0; i < num_encoders; ++i) {
            if (encoders[i].err) {
                vpx_codec_destroy(&encoders[i]);
            }
        }
        return 0;
    }
    
    // Optionally modify configuration with vpx_codec_enc_config_set
    if (fdp.ConsumeBool() && num_encoders > 0) {
        // Modify first encoder's configuration
        vpx_codec_enc_cfg_t modified_cfg = configs[0];
        modified_cfg.rc_target_bitrate = fdp.ConsumeIntegralInRange<uint32_t>(500, 5000000);
        modified_cfg.g_w = fdp.ConsumeIntegralInRange<uint16_t>(64, 1920);
        modified_cfg.g_h = fdp.ConsumeIntegralInRange<uint16_t>(64, 1080);
        
        vpx_codec_enc_config_set(&encoders[0], &modified_cfg);
    }
    
    // Test advanced features based on test_advanced value
    switch (test_advanced) {
        case 0: {
            // Test vpx_codec_get_global_headers
            vpx_fixed_buf_t* global_headers = vpx_codec_get_global_headers(&encoders[0]);
            // Nothing to do with result - just testing the call
            break;
        }
        case 1: {
            // Test vpx_codec_get_preview_frame
            const vpx_image_t* preview_frame = vpx_codec_get_preview_frame(&encoders[0]);
            // Nothing to do with result - just testing the call
            break;
        }
        case 2: {
            // Test vpx_codec_set_cx_data_buf
            if (fdp.remaining_bytes() >= 1024) {
                std::vector<uint8_t> buffer = fdp.ConsumeBytes<uint8_t>(1024);
                vpx_fixed_buf_t cx_buf;
                cx_buf.buf = buffer.data();
                cx_buf.sz = buffer.size();
                
                unsigned int pad_before = fdp.ConsumeIntegralInRange<unsigned int>(0, 64);
                unsigned int pad_after = fdp.ConsumeIntegralInRange<unsigned int>(0, 64);
                
                vpx_codec_set_cx_data_buf(&encoders[0], &cx_buf, pad_before, pad_after);
            }
            break;
        }
        default:
            // Test all three
            vpx_fixed_buf_t* global_headers = vpx_codec_get_global_headers(&encoders[0]);
            const vpx_image_t* preview_frame = vpx_codec_get_preview_frame(&encoders[0]);
            // Just test calls, ignore results
            break;
    }
    
    // Allocate image buffer for encoding
    vpx_image_t* img = vpx_img_alloc(nullptr, VPX_IMG_FMT_I420, 
                                    configs[0].g_w, configs[0].g_h, 1);
    if (!img) {
        for (size_t i = 0; i < num_encoders; ++i) {
            vpx_codec_destroy(&encoders[i]);
        }
        return 0;
    }
    
    // Fill image with fuzzed data
    size_t y_plane_size = img->stride[0] * img->d_h;
    size_t uv_plane_size = img->stride[1] * ((img->d_h + 1) / 2);
    
    if (fdp.remaining_bytes() >= y_plane_size + 2 * uv_plane_size) {
        std::vector<uint8_t> y_plane = fdp.ConsumeBytes<uint8_t>(y_plane_size);
        std::vector<uint8_t> u_plane = fdp.ConsumeBytes<uint8_t>(uv_plane_size);
        std::vector<uint8_t> v_plane = fdp.ConsumeBytes<uint8_t>(uv_plane_size);
        
        memcpy(img->planes[0], y_plane.data(), y_plane_size);
        memcpy(img->planes[1], u_plane.data(), uv_plane_size);
        memcpy(img->planes[2], v_plane.data(), uv_plane_size);
    } else {
        // Fill with simple pattern if not enough fuzzed data
        for (unsigned int i = 0; i < img->d_h; ++i) {
            memset(img->planes[0] + i * img->stride[0], 128, img->d_w);
        }
        unsigned int uv_h = (img->d_h + 1) / 2;
        unsigned int uv_w = (img->d_w + 1) / 2;
        for (unsigned int i = 0; i < uv_h; ++i) {
            memset(img->planes[1] + i * img->stride[1], 128, uv_w);
            memset(img->planes[2] + i * img->stride[2], 128, uv_w);
        }
    }
    
    // Encode frames using each encoder
    for (size_t enc_idx = 0; enc_idx < num_encoders; ++enc_idx) {
        for (uint8_t frame = 0; frame < frame_count; ++frame) {
            vpx_codec_encode(&encoders[enc_idx], img, frame * 33, 33, 0, 
                           fdp.ConsumeIntegral<uint32_t>());
            
            // Retrieve encoded data
            vpx_codec_iter_t iter = nullptr;
            const vpx_codec_cx_pkt_t* pkt;
            while ((pkt = vpx_codec_get_cx_data(&encoders[enc_idx], &iter)) != nullptr) {
                // Just iterate through packets - testing the API
                if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
                    // Frame data available
                }
            }
        }
    }
    
    // Cleanup
    vpx_img_free(img);
    for (size_t i = 0; i < num_encoders; ++i) {
        vpx_codec_destroy(&encoders[i]);
    }
    
    return 0;
}
