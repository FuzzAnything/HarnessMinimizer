/*
 * Fuzzing harness for libaom AV1 encoder-specific advanced features
 * Targets comprehensive encoder-specific APIs from aomcx.h including:
 * - SVC (Scalable Video Coding) configuration and controls
 * - Film grain synthesis and test vector configuration
 * - Denoising and noise level controls
 * - Advanced encoder flags for reference frame control
 * - Timing information and specialized encoder settings
 * 
 * Distinct from all previous harnesses:
 * - harness_000.cpp (basic encoder/decoder APIs)
 * - harness_001.cpp (metadata management)
 * - harness_002.cpp (basic encoder codec control APIs)
 * - harness_003.cpp (decoder initialization)
 * - harness_004.cpp (encoder configuration APIs)
 * - harness_005.cpp (error handling)
 * - harness_006.cpp (image allocation)
 * - harness_007.cpp (frame buffer APIs)
 * - harness_008.cpp (external rate control APIs)
 * - harness_009.cpp (external partition APIs)
 * - harness_010.cpp (decoder-specific control APIs)
 * 
 * Focuses on advanced encoder-specific features not covered by previous harnesses:
 * - SVC layer configuration and reference frame management
 * - Film grain synthesis for cinematic effects
 * - Denoising algorithms and noise modeling
 * - Advanced reference frame control through encoder flags
 * - Timing information and specialized encoder optimizations
 * 
 * Testing strategy: Test complex SVC setups, film grain configurations,
 * denoising parameters, and advanced encoder flags using fuzzed input data
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <algorithm>
#include <memory>
#include <vector>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>

#include "aom/aom_encoder.h"
#include "aom/aom_codec.h"
#include "aom/aomcx.h"
#include "aom/aom_image.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Minimum input size: need enough for complex encoder configuration
    const size_t MIN_SIZE = sizeof(uint32_t) * 12 + sizeof(uint8_t) * 32 + 128;
    if (size < MIN_SIZE) {
        return 0;  // Insufficient input for meaningful testing
    }

    FuzzedDataProvider fdp(data, size);

    // Consume basic encoder configuration parameters
    uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(64, 1024);
    uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(64, 1024);
    uint8_t bit_depth = fdp.ConsumeBool() ? 8 : 10;
    uint32_t threads = fdp.ConsumeIntegralInRange<uint32_t>(1, 16);
    uint32_t usage = fdp.ConsumeIntegral<uint8_t>() % 3;  // 0-2: GOOD_QUALITY, REALTIME, ALL_INTRA
    uint32_t profile = fdp.ConsumeIntegral<uint8_t>() % 4;  // 0-3
    
    // Initialize encoder with default configuration
    aom_codec_iface_t *encoder_iface = aom_codec_av1_cx();
    aom_codec_ctx_t encoder;
    
    aom_codec_enc_cfg_t cfg;
    if (aom_codec_enc_config_default(encoder_iface, &cfg, usage) != AOM_CODEC_OK) {
        return 0;
    }
    
    // Configure encoder with fuzzed parameters
    cfg.g_w = width;
    cfg.g_h = height;
    cfg.g_threads = threads;
    cfg.g_usage = usage;
    cfg.g_profile = profile;
    cfg.g_bit_depth = static_cast<aom_bit_depth_t>(bit_depth);
    cfg.g_input_bit_depth = static_cast<aom_bit_depth_t>(bit_depth);
    
    // Timebase configuration
    cfg.g_timebase.num = fdp.ConsumeIntegralInRange<uint32_t>(1, 1000);
    cfg.g_timebase.den = fdp.ConsumeIntegralInRange<uint32_t>(1, 120);
    
    // Initialize encoder
    if (aom_codec_enc_init(&encoder, encoder_iface, &cfg, 0) != AOM_CODEC_OK) {
        return 0;
    }
    
    // Test SVC (Scalable Video Coding) configuration
    if (fdp.remaining_bytes() > 256) {
        // Test 1: SVC layer ID configuration
        aom_svc_layer_id_t layer_id;
        layer_id.spatial_layer_id = fdp.ConsumeIntegralInRange<int>(0, 3);
        layer_id.temporal_layer_id = fdp.ConsumeIntegralInRange<int>(0, 7);
        aom_codec_control(&encoder, AV1E_SET_SVC_LAYER_ID, &layer_id);
        
        // Test 2: SVC parameters configuration
        aom_svc_params_t svc_params;
        svc_params.number_spatial_layers = fdp.ConsumeIntegralInRange<int>(1, 3);
        svc_params.number_temporal_layers = fdp.ConsumeIntegralInRange<int>(1, 3);
        
        // Initialize arrays with fuzzed values
        for (int i = 0; i < AOM_MAX_LAYERS && i < svc_params.number_spatial_layers * svc_params.number_temporal_layers; i++) {
            svc_params.max_quantizers[i] = fdp.ConsumeIntegralInRange<int>(0, 63);
            svc_params.min_quantizers[i] = fdp.ConsumeIntegralInRange<int>(0, 63);
            svc_params.layer_target_bitrate[i] = fdp.ConsumeIntegralInRange<int>(100, 10000);
        }
        
        for (int i = 0; i < AOM_MAX_SS_LAYERS && i < svc_params.number_spatial_layers; i++) {
            svc_params.scaling_factor_num[i] = fdp.ConsumeIntegralInRange<int>(1, 4);
            svc_params.scaling_factor_den[i] = fdp.ConsumeIntegralInRange<int>(1, 4);
        }
        
        for (int i = 0; i < AOM_MAX_TS_LAYERS && i < svc_params.number_temporal_layers; i++) {
            svc_params.framerate_factor[i] = fdp.ConsumeIntegralInRange<int>(1, 8);
        }
        
        aom_codec_control(&encoder, AV1E_SET_SVC_PARAMS, &svc_params);
        
        // Test 3: SVC reference frame configuration (if enough data)
        if (fdp.remaining_bytes() > 64) {
            aom_svc_ref_frame_config_t ref_config;
            for (int i = 0; i < 7; i++) {
                ref_config.reference[i] = fdp.ConsumeBool() ? 1 : 0;
                ref_config.ref_idx[i] = fdp.ConsumeIntegralInRange<int>(0, 7);
            }
            for (int i = 0; i < 8; i++) {
                ref_config.refresh[i] = fdp.ConsumeBool() ? 1 : 0;
            }
            aom_codec_control(&encoder, AV1E_SET_SVC_REF_FRAME_CONFIG, &ref_config);
        }
        
        // Test 4: SVC frame drop mode
        uint32_t frame_drop_mode = fdp.ConsumeBool() ? AOM_LAYER_DROP : AOM_FULL_SUPERFRAME_DROP;
        aom_codec_control(&encoder, AV1E_SET_SVC_FRAME_DROP_MODE, frame_drop_mode);
    }
    
    // Test film grain synthesis controls
    if (fdp.remaining_bytes() > 32) {
        // Test 1: Film grain test vector
        int film_grain_test_vector = fdp.ConsumeIntegralInRange<int>(0, 2);
        aom_codec_control(&encoder, AV1E_SET_FILM_GRAIN_TEST_VECTOR, film_grain_test_vector);
        
        // Test 2: Film grain table (simulate with dummy string if enough data)
        if (fdp.remaining_bytes() > 16) {
            std::string film_grain_table = fdp.ConsumeRandomLengthString(32);
            aom_codec_control(&encoder, AV1E_SET_FILM_GRAIN_TABLE, film_grain_table.c_str());
        }
    }
    
    // Test denoising and noise level controls
    if (fdp.remaining_bytes() > 16) {
        // Test 1: Denoise noise level
        int denoise_noise_level = fdp.ConsumeIntegralInRange<int>(0, 50);
        aom_codec_control(&encoder, AV1E_SET_DENOISE_NOISE_LEVEL, denoise_noise_level);
        
        // Test 2: Denoise block size
        uint32_t denoise_block_size = fdp.ConsumeIntegralInRange<uint32_t>(8, 64);
        aom_codec_control(&encoder, AV1E_SET_DENOISE_BLOCK_SIZE, denoise_block_size);
        
        // Test 3: Enable DNL denoising
        int enable_dnl_denoising = fdp.ConsumeBool() ? 1 : 0;
        aom_codec_control(&encoder, AV1E_SET_ENABLE_DNL_DENOISING, enable_dnl_denoising);
    }
    
    // Test advanced encoder feature controls
    if (fdp.remaining_bytes() > 48) {
        // Test 1: Timing information type
        int timing_info_type = fdp.ConsumeIntegralInRange<int>(0, 2);
        aom_codec_control(&encoder, AV1E_SET_TIMING_INFO_TYPE, timing_info_type);
        
        // Test 2: Chroma subsampling
        uint32_t chroma_subsampling_x = fdp.ConsumeIntegralInRange<uint32_t>(0, 2);
        uint32_t chroma_subsampling_y = fdp.ConsumeIntegralInRange<uint32_t>(0, 2);
        aom_codec_control(&encoder, AV1E_SET_CHROMA_SUBSAMPLING_X, chroma_subsampling_x);
        aom_codec_control(&encoder, AV1E_SET_CHROMA_SUBSAMPLING_Y, chroma_subsampling_y);
        
        // Test 3: Enable/disable various advanced features
        int enable_global_motion = fdp.ConsumeBool() ? 1 : 0;
        aom_codec_control(&encoder, AV1E_SET_ENABLE_GLOBAL_MOTION, enable_global_motion);
        
        int enable_warped_motion = fdp.ConsumeBool() ? 1 : 0;
        aom_codec_control(&encoder, AV1E_SET_ENABLE_WARPED_MOTION, enable_warped_motion);
        
        int enable_superres = fdp.ConsumeBool() ? 1 : 0;
        aom_codec_control(&encoder, AV1E_SET_ENABLE_SUPERRES, enable_superres);
        
        int enable_palette = fdp.ConsumeBool() ? 1 : 0;
        aom_codec_control(&encoder, AV1E_SET_ENABLE_PALETTE, enable_palette);
        
        int enable_intrabc = fdp.ConsumeBool() ? 1 : 0;
        aom_codec_control(&encoder, AV1E_SET_ENABLE_INTRABC, enable_intrabc);
    }
    
    // Test encoder flags for reference frame control
    if (fdp.remaining_bytes() > 8) {
        // Create test image for encoding with flags
        aom_image_t img;
        aom_img_fmt_t fmt = bit_depth == 8 ? AOM_IMG_FMT_I420 : AOM_IMG_FMT_I42016;
        
        if (aom_img_alloc(&img, fmt, width, height, 16) == NULL) {
            aom_codec_destroy(&encoder);
            return 0;
        }
        
        // Fill image with fuzzed data if available
        std::vector<uint8_t> image_data = fdp.ConsumeRemainingBytes<uint8_t>();
        if (image_data.size() > 0 && img.planes[0] != NULL) {
            size_t y_size = img.stride[0] * height;
            if (y_size > 0 && image_data.size() >= y_size) {
                memcpy(img.planes[0], image_data.data(), std::min(y_size, image_data.size()));
            }
        }
        
        // Test encoding with different encoder flags
        unsigned long encoder_flags = 0;
        
        // Set flags based on fuzzed input
        if (fdp.ConsumeBool()) encoder_flags |= AOM_EFLAG_NO_REF_LAST;
        if (fdp.ConsumeBool()) encoder_flags |= AOM_EFLAG_NO_REF_LAST2;
        if (fdp.ConsumeBool()) encoder_flags |= AOM_EFLAG_NO_REF_LAST3;
        if (fdp.ConsumeBool()) encoder_flags |= AOM_EFLAG_NO_REF_GF;
        if (fdp.ConsumeBool()) encoder_flags |= AOM_EFLAG_NO_REF_ARF;
        if (fdp.ConsumeBool()) encoder_flags |= AOM_EFLAG_NO_REF_BWD;
        if (fdp.ConsumeBool()) encoder_flags |= AOM_EFLAG_NO_REF_ARF2;
        if (fdp.ConsumeBool()) encoder_flags |= AOM_EFLAG_NO_UPD_LAST;
        if (fdp.ConsumeBool()) encoder_flags |= AOM_EFLAG_NO_UPD_GF;
        if (fdp.ConsumeBool()) encoder_flags |= AOM_EFLAG_NO_UPD_ARF;
        if (fdp.ConsumeBool()) encoder_flags |= AOM_EFLAG_NO_UPD_ENTROPY;
        if (fdp.ConsumeBool()) encoder_flags |= AOM_EFLAG_NO_REF_FRAME_MVS;
        if (fdp.ConsumeBool()) encoder_flags |= AOM_EFLAG_ERROR_RESILIENT;
        if (fdp.ConsumeBool()) encoder_flags |= AOM_EFLAG_SET_S_FRAME;
        if (fdp.ConsumeBool()) encoder_flags |= AOM_EFLAG_SET_PRIMARY_REF_NONE;
        
        // Encode with flags
        aom_codec_encode(&encoder, &img, 0, 1, encoder_flags);
        
        // Get compressed data
        aom_codec_iter_t iter = NULL;
        const aom_codec_cx_pkt_t *pkt;
        while ((pkt = aom_codec_get_cx_data(&encoder, &iter)) != NULL) {
            // Process packets (just consume them)
        }
        
        // Cleanup image
        aom_img_free(&img);
    }
    
    // Test GOP info retrieval (getter control)
    if (fdp.remaining_bytes() > 8) {
        aom_gop_info_t gop_info;
        aom_codec_control(&encoder, AV1E_GET_GOP_INFO, &gop_info);
    }
    
    // Cleanup
    aom_codec_destroy(&encoder);
    
    return 0;
}
