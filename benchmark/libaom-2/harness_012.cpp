/*
 * Fuzzing harness for AV1 sorting network functions (av1_sort_fi32_16 and av1_sort_fi32_8)
 * targeting 465 blocked branches with current 40.20% branch coverage.
 * 
 * Primary target: Sorting network functions used in transform type selection
 * during encoding (prune_tx_2D in tx_search.c). These functions implement
 * branch-less sorting algorithms with many conditional swaps that need to
 * be exercised with varied input patterns.
 * 
 * Strategy: Exercise aom_codec_encode with varied input patterns to trigger
 * transform type selection which uses the sorting network functions.
 * Focus on encoder settings that affect transform selection and pruning.
 * 
 * The sorting network functions are called in prune_tx_2D() which is part of
 * the transform search during encoding. By varying encoder parameters and
 * input data, we can trigger different transform selection paths that
 * exercise the sorting networks.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <algorithm>
#include <vector>
#include <cmath>

#include <fuzzer/FuzzedDataProvider.h>

#include "aom/aom_encoder.h"
#include "aom/aomcx.h"
#include "aom/aom_codec.h"
#include "aom/aom_image.h"

// Test encoding with varied transform settings to exercise sorting networks
void test_encoding_with_transform_selection(FuzzedDataProvider& fdp) {
    // Skip if not enough input
    if (fdp.remaining_bytes() < 512) {
        return;
    }
    
    // Get encoder interface
    aom_codec_iface_t* iface = aom_codec_av1_cx();
    if (!iface) {
        return;
    }
    
    // Initialize encoder configuration
    aom_codec_enc_cfg_t cfg;
    unsigned int usage = fdp.ConsumeIntegral<uint8_t>() % 3; // 0, 1, or 2
    if (aom_codec_enc_config_default(iface, &cfg, usage) != AOM_CODEC_OK) {
        return;
    }
    // Set small dimensions for faster fuzzing
    cfg.g_w = fdp.ConsumeIntegralInRange<unsigned int>(64, 128);
    cfg.g_h = fdp.ConsumeIntegralInRange<unsigned int>(64, 128);
    cfg.g_timebase.num = 1;
    cfg.g_timebase.den = 30;
    
    // Set transform-related parameters that might affect sorting network usage
    cfg.rc_end_usage = static_cast<aom_rc_mode>(
        fdp.ConsumeIntegralInRange<unsigned int>(AOM_VBR, AOM_Q));
    
    // Target bitrate
    cfg.rc_target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 1000);
    
    // Parameters that affect transform search and pruning
    cfg.g_lag_in_frames = fdp.ConsumeIntegralInRange<unsigned int>(0, 25);
    cfg.g_error_resilient = fdp.ConsumeIntegral<aom_codec_er_flags_t>();
    
    // Initialize encoder
    aom_codec_ctx_t codec;
    if (aom_codec_enc_init(&codec, iface, &cfg, 0) != AOM_CODEC_OK) {
        return;
    }
    
    // Set various encoder controls that affect transform type selection
    // Use only public API control IDs
    
    // CPU usage affects transform search (public API)
    int cpu_used = fdp.ConsumeIntegralInRange<int>(0, 9);
    aom_codec_control(&codec, AOME_SET_CPUUSED, cpu_used);
    
    // Set encoder usage profile (public API)
    int usage_profile = fdp.ConsumeIntegralInRange<int>(0, 3);
    aom_codec_control(&codec, AOME_SET_CQ_LEVEL, usage_profile);
    
    // Re-apply configuration to ensure changes take effect
    aom_codec_enc_config_set(&codec, &cfg);
    
    // Create a test image with varied format
    aom_image_t img;
    aom_img_fmt_t fmt = static_cast<aom_img_fmt_t>(
        fdp.ConsumeIntegralInRange<unsigned int>(AOM_IMG_FMT_I420, AOM_IMG_FMT_I444));
    
    if (!aom_img_alloc(&img, fmt, cfg.g_w, cfg.g_h, 1)) {
        aom_codec_destroy(&codec);
        return;
    }
    
    // Fill image with varied data patterns to affect transform selection
    // Different patterns will produce different energy distributions
    // which affect the transform type scores that get sorted
    
    uint8_t pattern_type = fdp.ConsumeIntegral<uint8_t>() % 4;
    
    for (int plane = 0; plane < 3; plane++) {
        if (img.planes[plane]) {
            size_t plane_size = img.stride[plane] * (plane == 0 ? cfg.g_h : cfg.g_h / 2);
            if (plane_size > 0 && fdp.remaining_bytes() >= plane_size) {
                std::vector<uint8_t> plane_data = fdp.ConsumeBytes<uint8_t>(plane_size);
                
                // Apply different patterns to affect transform selection
                switch (pattern_type) {
                    case 0: // Random noise
                        memcpy(img.planes[plane], plane_data.data(), 
                               std::min(plane_size, plane_data.size()));
                        break;
                    case 1: // Gradient (more structured)
                        for (size_t i = 0; i < plane_size; i++) {
                            img.planes[plane][i] = (i % 256);
                        }
                        break;
                    case 2: // Checkerboard pattern
                        for (size_t i = 0; i < plane_size; i++) {
                            img.planes[plane][i] = ((i / 16) % 2) * 255;
                        }
                        break;
                    case 3: // Mixed pattern
                        for (size_t i = 0; i < plane_size && i < plane_data.size(); i++) {
                            img.planes[plane][i] = plane_data[i] ^ ((i % 16) * 16);
                        }
                        break;
                }
            }
        }
    }
    
    // Encode frames with different flags to exercise different transform paths
    int frames_to_encode = fdp.ConsumeIntegralInRange<int>(1, 4);
    for (int frame_idx = 0; frame_idx < frames_to_encode; frame_idx++) {
        aom_enc_frame_flags_t flags = 0;
        
        // Vary flags that affect transform selection
        if (fdp.ConsumeBool()) {
            flags |= AOM_EFLAG_FORCE_KF; // Force keyframe
        }
        if (fdp.ConsumeBool()) {
            flags |= AOM_EFLAG_NO_UPD_ENTROPY;
        }
        if (fdp.ConsumeBool()) {
            flags |= AOM_EFLAG_NO_UPD_LAST;
        }
        if (fdp.ConsumeBool()) {
            flags |= AOM_EFLAG_NO_UPD_GF;
        }
        
        // Vary presentation timestamp to affect temporal coding
        aom_codec_pts_t pts = frame_idx * 1000 + fdp.ConsumeIntegralInRange<int>(0, 100);
        
        // Vary duration
        unsigned long duration = 1 + (fdp.ConsumeIntegral<uint8_t>() % 10);
        
        // Encode the frame - this will eventually call prune_tx_2D which uses sorting networks
        aom_codec_encode(&codec, &img, pts, duration, flags);
        
        // Get encoded data (drain the encoder)
        const aom_codec_cx_pkt_t* pkt = NULL;
        aom_codec_iter_t iter = NULL;
        while ((pkt = aom_codec_get_cx_data(&codec, &iter)) != NULL) {
            // Process packet if needed
        }
        
        // Occasionally flush the encoder to trigger different states
        if (frame_idx == frames_to_encode - 1 && fdp.ConsumeBool()) {
            // Flush encoder
            aom_codec_encode(&codec, NULL, 0, 0, 0);
            while ((pkt = aom_codec_get_cx_data(&codec, &iter)) != NULL) {
                // Process packet
            }
        }
    }
    
    // Clean up
    aom_img_free(&img);
    aom_codec_destroy(&codec);
}

// Additional test: Multiple encoding sessions with different configurations
// to increase chance of hitting different sorting network paths
void test_multiple_encoding_sessions(FuzzedDataProvider& fdp) {
    // Run multiple encoding sessions with different parameters
    int num_sessions = fdp.ConsumeIntegralInRange<int>(1, 3);
    
    for (int session = 0; session < num_sessions && fdp.remaining_bytes() >= 256; session++) {
        test_encoding_with_transform_selection(fdp);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 128) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Determine test approach from fuzzer input
    uint8_t test_mode = fdp.ConsumeIntegral<uint8_t>() % 2;
    
    switch (test_mode) {
        case 0:
            // Single encoding session with varied parameters
            test_encoding_with_transform_selection(fdp);
            break;
            
        case 1:
            // Multiple encoding sessions to increase coverage
            test_multiple_encoding_sessions(fdp);
            break;
    }
    
    return 0;
}
