#include <cstdint>
#include <cstddef>
#include <cstring>
#include <memory>
#include <vector>
#include <algorithm>

#include <fuzzer/FuzzedDataProvider.h>
#include "aom/aom_encoder.h"
#include "aom/aom_codec.h"
#include "aom/aom_image.h"
#include "aom/aomcx.h"
#include "aom/aomdx.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Need minimal data for screen content and scaling operations
    if (size < 64) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);

    // ==============================================
    // Test 1: Screen Content Detection and Analysis
    // ==============================================
    
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
    // Test 2: Screen Content Detection Controls
    // ==============================================
    
    // Set screen content detection mode from fuzzed data - only valid values 1 and 2
    uint8_t screen_detection_choice = fdp.ConsumeIntegral<uint8_t>() % 2;
    aom_screen_detection_mode detection_mode;
    switch (screen_detection_choice) {
        case 0: detection_mode = AOM_SCREEN_DETECTION_STANDARD; break;
        case 1: detection_mode = AOM_SCREEN_DETECTION_ANTIALIASING_AWARE; break;
        default: detection_mode = AOM_SCREEN_DETECTION_STANDARD; break;
    }
    aom_codec_control(&codec, AV1E_SET_SCREEN_CONTENT_DETECTION_MODE, detection_mode);
    
    // Set tune content - valid values: DEFAULT(0), SCREEN(1), FILM(2)
    uint8_t content_choice = fdp.ConsumeIntegral<uint8_t>() % 3;
    int tune_content = (content_choice == 0) ? AOM_CONTENT_DEFAULT : 
                      (content_choice == 1) ? AOM_CONTENT_SCREEN : AOM_CONTENT_FILM;
    aom_codec_control(&codec, AV1E_SET_TUNE_CONTENT, tune_content);
    // Set CPU used (affects screen content detection sensitivity)
    int cpu_used = fdp.ConsumeIntegralInRange<int>(-8, 8);
    aom_codec_control(&codec, AOME_SET_CPUUSED, cpu_used);
    
    // ==============================================
    // Test 3: Create Test Image with Various Bit Depths
    // ==============================================
    
    // Choose image format that includes high bit depth to trigger crash path
    uint8_t fmt_choice = fdp.ConsumeIntegral<uint8_t>() % 4;
    aom_img_fmt_t fmt;
    switch (fmt_choice) {
        case 0: fmt = AOM_IMG_FMT_I420; break;
        case 1: fmt = AOM_IMG_FMT_I42016; break;  // High bit depth for crash testing
        case 2: fmt = AOM_IMG_FMT_I422; break;
        case 3: fmt = AOM_IMG_FMT_I444; break;
        default: fmt = AOM_IMG_FMT_I420; break;
    }
    
    aom_image_t img;
    aom_image_t* img_ptr = aom_img_alloc(&img, fmt, cfg.g_w, cfg.g_h, 1);
    if (!img_ptr || !img.planes[0]) {
        aom_codec_destroy(&codec);
        return 0;
    }
    
    // Fill image planes with fuzzed data
    size_t y_plane_size = cfg.g_w * cfg.g_h;
    size_t uv_plane_size = (cfg.g_w / 2) * (cfg.g_h / 2);
    
    if (fdp.remaining_bytes() >= y_plane_size + uv_plane_size * 2) {
        // Fill Y plane
        std::vector<uint8_t> y_data = fdp.ConsumeBytes<uint8_t>(y_plane_size);
        if (y_data.size() == y_plane_size) {
            memcpy(img.planes[0], y_data.data(), y_plane_size);
        }
        
        // Fill U and V planes
        std::vector<uint8_t> u_data = fdp.ConsumeBytes<uint8_t>(uv_plane_size);
        std::vector<uint8_t> v_data = fdp.ConsumeBytes<uint8_t>(uv_plane_size);
        if (u_data.size() == uv_plane_size && v_data.size() == uv_plane_size) {
            memcpy(img.planes[1], u_data.data(), uv_plane_size);
            memcpy(img.planes[2], v_data.data(), uv_plane_size);
        }
    } else {
        // Use simple patterns if not enough fuzzer data
        for (size_t i = 0; i < y_plane_size; i++) {
            img.planes[0][i] = static_cast<uint8_t>(i % 256);
        }
        for (size_t i = 0; i < uv_plane_size; i++) {
            img.planes[1][i] = 128;
            img.planes[2][i] = 128;
        }
    }
    
    // ==============================================
    // Test 4: Scaling Controls (Only if available)
    // ==============================================
    
    // Set scaling mode (1D scaling) - use correct control name
    uint8_t scaling_choice = fdp.ConsumeIntegral<uint8_t>() % 9;
    AOM_SCALING_MODE scaling_mode_val;
    switch (scaling_choice) {
        case 0: scaling_mode_val = AOME_NORMAL; break;
        case 1: scaling_mode_val = AOME_FOURFIVE; break;
        case 2: scaling_mode_val = AOME_THREEFIVE; break;
        case 3: scaling_mode_val = AOME_THREEFOUR; break;
        case 4: scaling_mode_val = AOME_ONEFOUR; break;
        case 5: scaling_mode_val = AOME_ONEEIGHT; break;
        case 6: scaling_mode_val = AOME_ONETWO; break;
        case 7: scaling_mode_val = AOME_TWOTHREE; break;
        case 8: scaling_mode_val = AOME_ONETHREE; break;
        default: scaling_mode_val = AOME_NORMAL; break;
    }
    
    // Create scaling mode struct for horizontal and vertical scaling
    aom_scaling_mode_t scaling_mode;
    scaling_mode.h_scaling_mode = scaling_mode_val;
    scaling_mode.v_scaling_mode = scaling_mode_val;
    aom_codec_control(&codec, AOME_SET_SCALEMODE, &scaling_mode);
    
    // Enable superres if available
    int enable_superres = fdp.ConsumeBool() ? 1 : 0;
    aom_codec_control(&codec, AV1E_SET_ENABLE_SUPERRES, enable_superres);
    
    // ==============================================
    // Test 5: Encode Frame to Trigger Screen Content Analysis
    // ==============================================
    
    // Encode flags
    aom_enc_frame_flags_t encode_flags = 0;
    if (fdp.ConsumeBool()) encode_flags |= AOM_EFLAG_FORCE_KF;
    
    // Presentation timestamp and duration
    aom_codec_pts_t pts = fdp.ConsumeIntegral<aom_codec_pts_t>();
    unsigned long duration = fdp.ConsumeIntegralInRange<unsigned long>(1, 10);
    
    // Encode the frame - this will trigger screen content analysis
    // and potentially the crash in av1_count_colors_highbd
    res = aom_codec_encode(&codec, &img, pts, duration, encode_flags);
    
    // Try to get any compressed data (ignore result)
    aom_codec_iter_t iter = nullptr;
    const aom_codec_cx_pkt_t* pkt;
    while ((pkt = aom_codec_get_cx_data(&codec, &iter)) != nullptr) {
        // Just consume packets, don't process them
    }
    
    // Set additional controls that might affect screen content analysis
    // Note: We avoid controls that may not exist in the library version
    
    // Set CQ level (affects quantization)
    int cq_level = fdp.ConsumeIntegralInRange<int>(0, 63);
    aom_codec_control(&codec, AOME_SET_CQ_LEVEL, cq_level);
    
    // Set tuning (affects encoding decisions) - use valid aom_tune_metric values
    // Valid values: 0 (PSNR), 1 (SSIM), 4-11 (various metrics, 2 and 3 unused)
    uint8_t tuning_choice = fdp.ConsumeIntegral<uint8_t>() % 10;
    int tuning;
    switch (tuning_choice) {
        case 0: tuning = AOM_TUNE_PSNR; break;
        case 1: tuning = AOM_TUNE_SSIM; break;
        case 2: tuning = AOM_TUNE_VMAF_WITH_PREPROCESSING; break;
        case 3: tuning = AOM_TUNE_VMAF_WITHOUT_PREPROCESSING; break;
        case 4: tuning = AOM_TUNE_VMAF_MAX_GAIN; break;
        case 5: tuning = AOM_TUNE_VMAF_NEG_MAX_GAIN; break;
        case 6: tuning = AOM_TUNE_BUTTERAUGLI; break;
        case 7: tuning = AOM_TUNE_VMAF_SALIENCY_MAP; break;
        case 8: tuning = AOM_TUNE_IQ; break;
        case 9: tuning = AOM_TUNE_SSIMULACRA2; break;
        default: tuning = AOM_TUNE_PSNR; break;
    }
    aom_codec_control(&codec, AOME_SET_TUNING, tuning);
    // Set sharpness (affects filtering)
    int sharpness = fdp.ConsumeIntegralInRange<int>(0, 7);
    aom_codec_control(&codec, AOME_SET_SHARPNESS, sharpness);
    
    // ==============================================
    // Cleanup
    // ==============================================
    
    aom_img_free(&img);
    aom_codec_destroy(&codec);
    
    return 0;
}
