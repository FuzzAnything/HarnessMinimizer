#include <cstdint>
#include <cstddef>
#include <cstring>
#include <memory>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>
#include "aom/aom_encoder.h"
#include "aom/aomcx.h"
#include "aom/aom_codec.h"
#include "aom/aom_image.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Need minimal data for encoder configuration
    if (size < 64) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);

    // Get the AV1 encoder interface
    aom_codec_iface_t* encoder_iface = aom_codec_av1_cx();
    if (!encoder_iface) {
        return 0;
    }

    // Initialize encoder configuration
    aom_codec_enc_cfg_t cfg;
    aom_codec_err_t res = aom_codec_enc_config_default(encoder_iface, &cfg, 0);
    if (res != AOM_CODEC_OK) {
        return 0;
    }

    // Use small dimensions for fuzzing efficiency
    cfg.g_w = fdp.ConsumeIntegralInRange<unsigned int>(16, 128);
    cfg.g_h = fdp.ConsumeIntegralInRange<unsigned int>(16, 128);
    cfg.g_timebase.num = 1;
    cfg.g_timebase.den = fdp.ConsumeIntegralInRange<unsigned int>(1, 60);
    cfg.rc_target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 1000);
    
    // Test different encoding passes (multi-pass encoding)
    uint8_t pass_choice = fdp.ConsumeIntegral<uint8_t>() % 3;
    switch (pass_choice) {
        case 0: cfg.g_pass = AOM_RC_ONE_PASS; break;
        case 1: cfg.g_pass = AOM_RC_FIRST_PASS; break;
        case 2: cfg.g_pass = AOM_RC_LAST_PASS; break;
        default: cfg.g_pass = AOM_RC_ONE_PASS; break;
    }
    
    cfg.g_lag_in_frames = fdp.ConsumeIntegralInRange<unsigned int>(0, 5);
    cfg.g_error_resilient = fdp.ConsumeBool() ? AOM_ERROR_RESILIENT_DEFAULT : 0;

    // Initialize encoder context
    aom_codec_ctx_t codec;
    aom_codec_flags_t flags = fdp.ConsumeBool() ? AOM_CODEC_USE_HIGHBITDEPTH : 0;
    res = aom_codec_enc_init(&codec, encoder_iface, &cfg, flags);
    if (res != AOM_CODEC_OK) {
        return 0;
    }

    // ==============================================
    // Test 1: Color Space Configuration Controls
    // ==============================================
    
    // Set color primaries (BT.709, BT.601, BT.2020, etc.)
    uint8_t primaries_choice = fdp.ConsumeIntegral<uint8_t>() % 13;
    int color_primaries = 1;  // Default BT.709
    switch (primaries_choice) {
        case 0: color_primaries = AOM_CICP_CP_BT_709; break;
        case 1: color_primaries = AOM_CICP_CP_UNSPECIFIED; break;
        case 2: color_primaries = AOM_CICP_CP_BT_470_M; break;
        case 3: color_primaries = AOM_CICP_CP_BT_470_B_G; break;
        case 4: color_primaries = AOM_CICP_CP_BT_601; break;
        case 5: color_primaries = AOM_CICP_CP_SMPTE_240; break;
        case 6: color_primaries = AOM_CICP_CP_GENERIC_FILM; break;
        case 7: color_primaries = AOM_CICP_CP_BT_2020; break;
        case 8: color_primaries = AOM_CICP_CP_XYZ; break;
        case 9: color_primaries = AOM_CICP_CP_SMPTE_431; break;
        case 10: color_primaries = AOM_CICP_CP_SMPTE_432; break;
        case 11: color_primaries = AOM_CICP_CP_EBU_3213; break;
        default: color_primaries = AOM_CICP_CP_BT_709; break;
    }
    aom_codec_control(&codec, AV1E_SET_COLOR_PRIMARIES, color_primaries);
    
    // Set transfer characteristics
    uint8_t transfer_choice = fdp.ConsumeIntegral<uint8_t>() % 13;
    int transfer_char = 1;  // Default BT.709
    switch (transfer_choice) {
        case 0: transfer_char = AOM_CICP_TC_BT_709; break;
        case 1: transfer_char = AOM_CICP_TC_UNSPECIFIED; break;
        case 2: transfer_char = AOM_CICP_TC_BT_470_M; break;
        case 3: transfer_char = AOM_CICP_TC_BT_470_B_G; break;
        case 4: transfer_char = AOM_CICP_TC_BT_601; break;
        case 5: transfer_char = AOM_CICP_TC_SMPTE_240; break;
        case 6: transfer_char = AOM_CICP_TC_LINEAR; break;
        case 7: transfer_char = AOM_CICP_TC_LOG_100; break;
        case 8: transfer_char = AOM_CICP_TC_LOG_100_SQRT10; break;
        case 9: transfer_char = AOM_CICP_TC_IEC_61966; break;
        case 10: transfer_char = AOM_CICP_TC_BT_1361; break;
        case 11: transfer_char = AOM_CICP_TC_SRGB; break;
        default: transfer_char = AOM_CICP_TC_BT_709; break;
    }
    aom_codec_control(&codec, AV1E_SET_TRANSFER_CHARACTERISTICS, transfer_char);
    
    // Set matrix coefficients
    uint8_t matrix_choice = fdp.ConsumeIntegral<uint8_t>() % 13;
    int matrix_coeff = 1;  // Default BT.709
    switch (matrix_choice) {
        case 0: matrix_coeff = AOM_CICP_MC_IDENTITY; break;
        case 1: matrix_coeff = AOM_CICP_MC_BT_709; break;
        case 2: matrix_coeff = AOM_CICP_MC_UNSPECIFIED; break;
        case 3: matrix_coeff = AOM_CICP_MC_FCC; break;
        case 4: matrix_coeff = AOM_CICP_MC_BT_470_B_G; break;
        case 5: matrix_coeff = AOM_CICP_MC_BT_601; break;
        case 6: matrix_coeff = AOM_CICP_MC_SMPTE_240; break;
        case 7: matrix_coeff = AOM_CICP_MC_SMPTE_YCGCO; break;
        case 8: matrix_coeff = AOM_CICP_MC_BT_2020_NCL; break;
        case 9: matrix_coeff = AOM_CICP_MC_BT_2020_CL; break;
        case 10: matrix_coeff = AOM_CICP_MC_SMPTE_2085; break;
        case 11: matrix_coeff = AOM_CICP_MC_CHROMAT_NCL; break;
        default: matrix_coeff = AOM_CICP_MC_BT_709; break;
    }
    aom_codec_control(&codec, AV1E_SET_MATRIX_COEFFICIENTS, matrix_coeff);
    
    // Set color range (limited vs full range)
    int color_range = fdp.ConsumeBool() ? AOM_CR_FULL_RANGE : AOM_CR_STUDIO_RANGE;
    aom_codec_control(&codec, AV1E_SET_COLOR_RANGE, color_range);
    
    // Set chroma sample position
    uint8_t chroma_pos_choice = fdp.ConsumeIntegral<uint8_t>() % 4;
    int chroma_sample_pos = AOM_CSP_UNKNOWN;
    switch (chroma_pos_choice) {
        case 0: chroma_sample_pos = AOM_CSP_VERTICAL; break;
        case 1: chroma_sample_pos = AOM_CSP_COLOCATED; break;
        case 2: chroma_sample_pos = AOM_CSP_RESERVED; break;
        default: chroma_sample_pos = AOM_CSP_UNKNOWN; break;
    }
    aom_codec_control(&codec, AV1E_SET_CHROMA_SAMPLE_POSITION, chroma_sample_pos);

    // ==============================================
    // Test 2: Advanced Encoding Features & Rate Control
    // ==============================================
    
    // Set CPU usage (speed/quality tradeoff)
    int cpu_used = fdp.ConsumeIntegralInRange<int>(-8, 8);
    aom_codec_control(&codec, AOME_SET_CPUUSED, cpu_used);
    
    // Set tuning (PSNR, SSIM, VMAF)
    int tuning = fdp.ConsumeIntegralInRange<int>(0, 2);
    aom_codec_control(&codec, AOME_SET_TUNING, tuning);
    
    // Set CQ level (constant quality)
    int cq_level = fdp.ConsumeIntegralInRange<int>(0, 63);
    aom_codec_control(&codec, AOME_SET_CQ_LEVEL, cq_level);
    
    // Set AQ mode (adaptive quantization)
    int aq_mode = fdp.ConsumeIntegralInRange<int>(0, 4);
    aom_codec_control(&codec, AV1E_SET_AQ_MODE, aq_mode);
    
    // Set error resilient mode
    int error_resilient = fdp.ConsumeIntegralInRange<int>(0, 1);
    aom_codec_control(&codec, AV1E_SET_ERROR_RESILIENT_MODE, error_resilient);
    
    // Set row-based multi-threading
    int row_mt = fdp.ConsumeBool() ? 1 : 0;
    aom_codec_control(&codec, AV1E_SET_ROW_MT, row_mt);
    
    // Set frame parallel decoding
    int frame_parallel = fdp.ConsumeBool() ? 1 : 0;
    aom_codec_control(&codec, AV1E_SET_FRAME_PARALLEL_DECODING, frame_parallel);
    
    // Set S-frame mode for error resilience
    int s_frame_mode = fdp.ConsumeIntegralInRange<int>(0, 2);
    aom_codec_control(&codec, AV1E_SET_S_FRAME_MODE, s_frame_mode);
    
    // Set CDEF (constrained directional enhancement filter)
    int enable_cdef = fdp.ConsumeBool() ? 1 : 0;
    aom_codec_control(&codec, AV1E_SET_ENABLE_CDEF, enable_cdef);
    
    // Set lossless mode
    int lossless = fdp.ConsumeBool() ? 1 : 0;
    aom_codec_control(&codec, AV1E_SET_LOSSLESS, lossless);
    
    // Set auto altref (automatic alternate reference frames)
    int enable_auto_altref = fdp.ConsumeBool() ? 1 : 0;
    aom_codec_control(&codec, AOME_SET_ENABLEAUTOALTREF, enable_auto_altref);
    
    // Set sharpness
    int sharpness = fdp.ConsumeIntegralInRange<int>(0, 7);
    aom_codec_control(&codec, AOME_SET_SHARPNESS, sharpness);
    
    // Set ARNR (altref noise reduction) parameters
    int arnr_max_frames = fdp.ConsumeIntegralInRange<int>(0, 15);
    int arnr_strength = fdp.ConsumeIntegralInRange<int>(0, 6);
    aom_codec_control(&codec, AOME_SET_ARNR_MAXFRAMES, arnr_max_frames);
    aom_codec_control(&codec, AOME_SET_ARNR_STRENGTH, arnr_strength);

    // ==============================================
    // Test 3: Create and encode a simple test frame
    // ==============================================
    
    // Create a simple image for encoding
    aom_image_t img;
    aom_img_fmt_t fmt = fdp.ConsumeBool() ? AOM_IMG_FMT_I420 : AOM_IMG_FMT_I42016;
    aom_img_alloc(&img, fmt, cfg.g_w, cfg.g_h, 1);
    
    if (img.planes[0]) {
        // Fill with simple pattern
        size_t y_plane_size = cfg.g_w * cfg.g_h;
        for (size_t i = 0; i < y_plane_size && i < 1000; i++) {
            if (fmt == AOM_IMG_FMT_I42016) {
                uint16_t* y_plane = (uint16_t*)img.planes[0];
                y_plane[i] = static_cast<uint16_t>((i * 257) % 65536);  // Scale 0-255 to 0-65535
            } else {
                img.planes[0][i] = static_cast<uint8_t>(i % 256);
            }
        }
        
        // Encode the frame
        aom_enc_frame_flags_t encode_flags = 0;
        if (fdp.ConsumeBool()) encode_flags |= AOM_EFLAG_FORCE_KF;
        
        aom_codec_pts_t pts = fdp.ConsumeIntegral<aom_codec_pts_t>();
        unsigned long duration = fdp.ConsumeIntegralInRange<unsigned long>(1, 10);
        
        res = aom_codec_encode(&codec, &img, pts, duration, encode_flags);
        
        // Try to get encoded data
        const aom_codec_cx_pkt_t *pkt = nullptr;
        aom_codec_iter_t iter = nullptr;
        while ((pkt = aom_codec_get_cx_data(&codec, &iter)) != nullptr) {
            // Just iterate through packets for coverage
            if (pkt->kind == AOM_CODEC_CX_FRAME_PKT) {
                // Frame packet - we have encoded data
            }
        }
        
        // Free the image
        aom_img_free(&img);
    }

    // Cleanup
    aom_codec_destroy(&codec);
    return 0;
}
