/*
 * Fuzzing harness for libvpx VP8 encoder with comprehensive control API testing
 * Targets: VP8 encoder control functions (VP8E_SET_*) without SVC features
 * 
 * Key design principles:
 * 1. AVOID SVC CONFIGURATIONS ENTIRELY - No spatial/temporal layer controls
 * 2. Use simple encoding parameters for lightweight execution
 * 3. AFL-compatible with good coverage feedback
 * 4. Target different APIs than previous successful harnesses
 * 5. Lightweight to avoid calibration timeouts
 * 
 * APIs targeted (non-SVC):
 * - vpx_codec_enc_config_default (Helper: Configuration setup)
 * - vpx_codec_enc_init_ver (Target: Encoder initialization)
 * - vpx_codec_control_ with various VP8E_SET controls (Target: Control API testing)
 * - vpx_img_alloc (Helper: Input frame allocation)
 * - vpx_codec_encode (Target: Encoding process)
 * - vpx_codec_get_cx_data (Target: Output retrieval)
 * - vpx_img_free (Helper: Cleanup)
 * - vpx_codec_destroy (Helper: Cleanup)
 * 
 * Specific VP8E_SET controls tested (non-exhaustive):
 * - VP8E_SET_CPUUSED: Speed/quality tradeoff
 * - VP8E_SET_NOISE_SENSITIVITY: Noise sensitivity
 * - VP8E_SET_SHARPNESS: Sharpness control
 * - VP8E_SET_STATIC_THRESHOLD: Static threshold
 * - VP8E_SET_TOKEN_PARTITIONS: Token partitions
 * - VP8E_SET_TUNING: Tuning for content type
 * - VP8E_SET_CQ_LEVEL: Constant quality level
 * - VP8E_SET_ENABLEAUTOALTREF: Auto altref frames
 * - VP8E_SET_SCREEN_CONTENT_MODE: Screen content mode
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <algorithm>
#include <memory>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

#include "vpx/vp8cx.h"
#include "vpx/vpx_encoder.h"
#include "vpx/vpx_codec.h"
#include "vpx/vpx_image.h"

// Optimized constants for AFL calibration performance
#define MIN_INPUT_SIZE 256      // Reasonable minimum for control parameters
#define FIXED_WIDTH 64          // Fixed small dimensions for speed
#define FIXED_HEIGHT 48         // Fixed small dimensions for speed
#define MAX_FRAMES 2            // Limited to 2 frames for speed

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Early return for insufficient input
    if (size < MIN_INPUT_SIZE) return 0;
    
    FuzzedDataProvider fdp(data, size);
    
    // 1. Choose encoder (VP8 only for this harness - avoids VP9 SVC complexities)
    vpx_codec_iface_t *encoder_iface = vpx_codec_vp8_cx();
    if (!encoder_iface) return 0;
    
    // 2. Consume basic configuration parameters from fuzzed input
    int cpu_used = fdp.ConsumeIntegralInRange<int>(-16, 16);  // VP8 valid range
    unsigned int noise_sensitivity = fdp.ConsumeIntegralInRange<unsigned int>(0, 4);
    unsigned int sharpness = fdp.ConsumeIntegralInRange<unsigned int>(0, 7);
    unsigned int static_threshold = fdp.ConsumeIntegral<unsigned int>();
    int token_partitions = fdp.ConsumeIntegralInRange<int>(0, 3);  // 0-3 valid
    int tuning = fdp.ConsumeIntegralInRange<int>(0, 2);  // 0=VP8_TUNE_PSNR, 1=VP8_TUNE_SSIM, 2=VP8_TUNE_CONSISTENCY
    unsigned int cq_level = fdp.ConsumeIntegralInRange<unsigned int>(0, 63);
    unsigned int enable_auto_altref = fdp.ConsumeBool() ? 1 : 0;
    unsigned int screen_content_mode = fdp.ConsumeIntegralInRange<unsigned int>(0, 2);
    
    // 3. Simple frame count (1 or 2 frames only)
    int max_frames = fdp.ConsumeBool() ? 2 : 1;
    
    // 4. Bitrate parameter
    unsigned int bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 1000);
    
    // Initialize encoder configuration
    vpx_codec_enc_cfg_t cfg;
    if (vpx_codec_enc_config_default(encoder_iface, &cfg, 0) != VPX_CODEC_OK) {
        return 0;
    }
    
    // Basic configuration with fixed small dimensions
    cfg.g_w = FIXED_WIDTH;
    cfg.g_h = FIXED_HEIGHT;
    cfg.g_timebase.num = 1;
    cfg.g_timebase.den = 30;  // 30 FPS
    cfg.rc_target_bitrate = bitrate;
    cfg.g_threads = 1;  // Single thread for determinism and speed
    cfg.g_error_resilient = 1;  // Error resilience for robustness
    
    // NO SVC CONFIGURATION - explicitly avoid spatial/temporal layers
    // cfg.ss_number_layers = 1;  // Single spatial layer (default)
    // cfg.ts_number_layers = 1;  // Single temporal layer (default)
    
    // Initialize encoder
    vpx_codec_ctx_t codec;
    memset(&codec, 0, sizeof(codec));
    
    vpx_codec_flags_t flags = 0;
    vpx_codec_err_t err = vpx_codec_enc_init_ver(&codec, encoder_iface, &cfg, flags, VPX_ENCODER_ABI_VERSION);
    if (err != VPX_CODEC_OK) {
        return 0;
    }
    
    // Apply various encoder control functions (non-SVC)
    // These are the main targets for coverage
    
    // 1. CPU used (speed/quality tradeoff)
    vpx_codec_control(&codec, VP8E_SET_CPUUSED, cpu_used);
    
    // 2. Noise sensitivity
    vpx_codec_control(&codec, VP8E_SET_NOISE_SENSITIVITY, noise_sensitivity);
    
    // 3. Sharpness control
    vpx_codec_control(&codec, VP8E_SET_SHARPNESS, sharpness);
    
    // 4. Static threshold
    vpx_codec_control(&codec, VP8E_SET_STATIC_THRESHOLD, static_threshold);
    
    // 5. Token partitions
    vpx_codec_control(&codec, VP8E_SET_TOKEN_PARTITIONS, token_partitions);
    
    // 6. Tuning for content type
    vpx_codec_control(&codec, VP8E_SET_TUNING, tuning);
    
    // 7. Constant quality level
    vpx_codec_control(&codec, VP8E_SET_CQ_LEVEL, cq_level);
    
    // 8. Auto altref frames
    vpx_codec_control(&codec, VP8E_SET_ENABLEAUTOALTREF, enable_auto_altref);
    
    // 9. Screen content mode
    vpx_codec_control(&codec, VP8E_SET_SCREEN_CONTENT_MODE, screen_content_mode);
    
    // Allocate input image
    vpx_image_t *img = vpx_img_alloc(nullptr, VPX_IMG_FMT_I420, cfg.g_w, cfg.g_h, 1);
    if (!img) {
        vpx_codec_destroy(&codec);
        return 0;
    }
    
    // Calculate image buffer sizes
    size_t y_size = cfg.g_w * cfg.g_h;
    size_t uv_size = y_size / 4;  // For 4:2:0 format
    
    // Fill image with fuzzed data if available
    if (fdp.remaining_bytes() >= y_size) {
        std::vector<uint8_t> y_data = fdp.ConsumeBytes<uint8_t>(y_size);
        memcpy(img->planes[VPX_PLANE_Y], y_data.data(), y_size);
    } else {
        // Fill with simple pattern if not enough data
        for (size_t i = 0; i < y_size; i++) {
            img->planes[VPX_PLANE_Y][i] = (i % 256);
        }
    }
    
    // Fill U and V planes with mid-gray
    memset(img->planes[VPX_PLANE_U], 128, uv_size);
    memset(img->planes[VPX_PLANE_V], 128, uv_size);
    
    // Encode frames
    for (int frame_idx = 0; frame_idx < max_frames; ++frame_idx) {
        // Simple frame flags - no complex SVC layer flags
        vpx_codec_flags_t frame_flags = 0;
        
        // Use some frame flags based on fuzzed input
        uint8_t frame_flag_bits = fdp.ConsumeIntegral<uint8_t>();
        if (frame_flag_bits & 0x01) {
            frame_flags |= VP8_EFLAG_NO_REF_LAST;
        }
        if (frame_flag_bits & 0x02) {
            frame_flags |= VP8_EFLAG_NO_REF_GF;
        }
        if (frame_flag_bits & 0x04) {
            frame_flags |= VP8_EFLAG_NO_UPD_LAST;
        }
        if (frame_flag_bits & 0x08) {
            frame_flags |= VP8_EFLAG_NO_UPD_GF;
        }
        
        // Set frame flags control
        vpx_codec_control(&codec, VP8E_SET_FRAME_FLAGS, frame_flags);
        
        // Encode frame
        err = vpx_codec_encode(&codec, img, frame_idx, 1, frame_flags, VPX_DL_REALTIME);
        if (err != VPX_CODEC_OK) {
            // Continue with next frame even if this one fails
            continue;
        }
        
        // Retrieve encoded data
        vpx_codec_iter_t iter = nullptr;
        const vpx_codec_cx_pkt_t *pkt = nullptr;
        while ((pkt = vpx_codec_get_cx_data(&codec, &iter)) != nullptr) {
            if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
                // Frame packet received - we don't need to process it for fuzzing
                // Just ensure the API works correctly
            }
        }
    }
    
    // Cleanup
    vpx_img_free(img);
    vpx_codec_destroy(&codec);
    
    return 0;
}
