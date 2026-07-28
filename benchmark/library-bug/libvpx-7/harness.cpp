/*
 * Fuzzing harness for vpx_codec_control_ API
 * Targets: vpx_codec_control_ function with 7 undiscovered branches (38.9% uncovered)
 * Tests various control IDs for both encoder and decoder contexts
 * Tests error conditions, parameter validation, and control dispatch paths
 * 
 * Recommended fuzzer flags to prevent OOM:
 * -rss_limit_mb=4096 -max_len=10485760 -max_total_time=600 -max_corpus_size=500
 */
#define VPX_DISABLE_CTRL_TYPECHECKS 1
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <climits>
#include <algorithm>
#include <memory>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"
#include "vpx/vpx_tpl.h"
#include "vpx/vp8cx.h"
#include "vpx/vpx_encoder.h"
#include "vpx/vpx_image.h"
#include "vpx/vp8dx.h"
#include "vpx/vpx_decoder.h"

#define MAX_WIDTH 1920
#define MAX_HEIGHT 1080
#define MIN_WIDTH 16
#define MIN_HEIGHT 16

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum input size: enough for basic configuration choices
    if (size < 32) {
        return 0;  // Not enough data for meaningful testing
    }

    FuzzedDataProvider fdp(data, size);

    // Choose context type: 0 = encoder, 1 = decoder, 2 = NULL/invalid
    uint8_t context_type = fdp.ConsumeIntegral<uint8_t>() % 3;
    
    // Choose codec type: 0 = VP8, 1 = VP9
    uint8_t codec_type = fdp.ConsumeIntegral<uint8_t>() % 2;
    
    vpx_codec_ctx_t codec;
    vpx_codec_ctx_t* codec_ptr = nullptr;
    bool codec_initialized = false;
    
    // Initialize codec context if needed
    if (context_type == 0 || context_type == 1) {
        vpx_codec_iface_t* iface = nullptr;
        
        if (context_type == 0) {  // Encoder
            if (codec_type == 0) {
                iface = vpx_codec_vp8_cx();
            } else {
                iface = vpx_codec_vp9_cx();
            }
        } else {  // Decoder
            if (codec_type == 0) {
                iface = vpx_codec_vp8_dx();
            } else {
                iface = vpx_codec_vp9_dx();
            }
        }
        
        if (!iface) {
            return 0;  // Interface not available
        }
        
        // Initialize with basic configuration
        if (context_type == 0) {  // Encoder
            vpx_codec_enc_cfg_t cfg;
            vpx_codec_err_t err = vpx_codec_enc_config_default(iface, &cfg, 0);
            if (err != VPX_CODEC_OK) {
                return 0;
            }
            
            // Set reasonable dimensions
            cfg.g_w = fdp.ConsumeIntegralInRange<unsigned int>(MIN_WIDTH, MAX_WIDTH);
            cfg.g_h = fdp.ConsumeIntegralInRange<unsigned int>(MIN_HEIGHT, MAX_HEIGHT);
            cfg.g_threads = 1;
            cfg.g_timebase.num = 1;
            cfg.g_timebase.den = 30;
            cfg.rc_target_bitrate = 1000;
            
            err = vpx_codec_enc_init_ver(&codec, iface, &cfg, 0, VPX_ENCODER_ABI_VERSION);
            if (err != VPX_CODEC_OK) {
                return 0;
            }
        } else {  // Decoder
            vpx_codec_dec_cfg_t cfg = {1, 0, 0};
            vpx_codec_err_t err = vpx_codec_dec_init(&codec, iface, &cfg, 0);
            if (err != VPX_CODEC_OK) {
                return 0;
            }
        }
        
        codec_ptr = &codec;
        codec_initialized = true;
    } else {
        // context_type == 2: NULL or invalid context
        // Sometimes use NULL, sometimes use uninitialized struct
        if (fdp.ConsumeBool()) {
            codec_ptr = nullptr;
        } else {
            codec_ptr = &codec;
            // Don't initialize - will have invalid iface/priv
        }
    }
    
    // Choose control ID strategy
    uint8_t control_strategy = fdp.ConsumeIntegral<uint8_t>() % 4;
    int control_id = 0;
    
    switch (control_strategy) {
        case 0: {  // Valid control IDs based on codec type
            if (context_type == 0) {  // Encoder
                if (codec_type == 0) {  // VP8 encoder
                    // VP8 encoder control IDs from vp8cx.h
                    control_id = fdp.ConsumeIntegralInRange<int>(1, 50);
                } else {  // VP9 encoder
                    // VP9 encoder control IDs from vp8cx.h  
                    control_id = fdp.ConsumeIntegralInRange<int>(128, 180);
                }
            } else if (context_type == 1) {  // Decoder
                if (codec_type == 0) {  // VP8 decoder
                    // VP8 decoder control IDs from vp8dx.h
                    control_id = fdp.ConsumeIntegralInRange<int>(256, 280);
                } else {  // VP9 decoder
                    // VP9 decoder control IDs from vp8dx.h
                    control_id = fdp.ConsumeIntegralInRange<int>(512, 600);
                }
            } else {
                // Invalid context, use random
                control_id = fdp.ConsumeIntegral<int>();
            }
            break;
        }
        case 1:  // Edge cases
            control_id = fdp.ConsumeIntegral<int>();
            // Force some edge values
            if (fdp.ConsumeBool()) control_id = 0;
            if (fdp.ConsumeBool()) control_id = -1;
            if (fdp.ConsumeBool()) control_id = INT_MAX;
            if (fdp.ConsumeBool()) control_id = INT_MIN;
            break;
        case 2:  // Random
            control_id = fdp.ConsumeIntegral<int>();
            break;
        case 3:  // Mix
            if (fdp.ConsumeBool()) {
                // Valid range
                control_id = fdp.ConsumeIntegralInRange<int>(1, 100);
            } else {
                // Invalid range
                control_id = fdp.ConsumeIntegralInRange<int>(-100, 0);
            }
            break;
    }
    
    // Generate parameter based on control ID type
    // Test different parameter types to exercise different validation paths
    uint8_t param_type = fdp.ConsumeIntegral<uint8_t>() % 5;
    vpx_codec_err_t result = VPX_CODEC_ERROR;
    
    // Helper function to check if control ID requires pointer parameter
    auto control_requires_pointer = [](int control_id) -> bool {
        // Based on VPX_CTRL_USE_TYPE macros in header files:
        // From vp8.h:
        // VP8_SET_REFERENCE (1) expects vpx_ref_frame_t*
        // VP8_COPY_REFERENCE (2) expects vpx_ref_frame_t*
        // VP8_SET_POSTPROC (3) expects vp8_postproc_cfg_t*
        // VP9_GET_REFERENCE (128) expects vp9_ref_frame_t*
        
        // From vp8cx.h:
        // VP8E_SET_ROI_MAP (8) expects vpx_roi_map_t*
        // VP8E_SET_ACTIVEMAP (9) expects vpx_active_map_t*
        // VP8E_SET_SCALEMODE (11) expects vpx_scaling_mode_t*
        // VP8E_GET_LAST_QUANTIZER (?) expects int*
        // VP8E_GET_LAST_QUANTIZER_64 (?) expects int*
        // And many others...
        
        // From vp8dx.h:
        // Various GET controls expect pointer parameters
        
        // Common pointer-requiring control IDs
        static const int pointer_control_ids[] = {
            1, 2, 3, 128,  // From vp8.h
            8, 9, 11,       // From vp8cx.h (VP8E_SET_ROI_MAP, VP8E_SET_ACTIVEMAP, VP8E_SET_SCALEMODE)
        };
        
        for (int id : pointer_control_ids) {
            if (control_id == id) return true;
        }
        return false;
    };
    
    // Check if control ID requires pointer parameter
    if (control_requires_pointer(control_id)) {
        // These control IDs require pointer parameters
        // Allocate appropriate structure on stack
        if (control_id == 1 || control_id == 2) {
            // vpx_ref_frame_t for VP8_SET_REFERENCE or VP8_COPY_REFERENCE
            vpx_ref_frame_t ref_frame;
            // Initialize with fuzzer data
            ref_frame.frame_type = static_cast<vpx_ref_frame_type_t>(
                fdp.ConsumeIntegralInRange<int>(1, 4));
            // Note: vpx_image_t img is complex, but passing partially initialized
            // structure should still test parameter validation paths
            result = vpx_codec_control(codec_ptr, control_id, &ref_frame);
        } else if (control_id == 3) {
            // vp8_postproc_cfg_t for VP8_SET_POSTPROC
            vp8_postproc_cfg_t pp_cfg;
            pp_cfg.post_proc_flag = fdp.ConsumeIntegral<int>();
            pp_cfg.deblocking_level = fdp.ConsumeIntegralInRange<int>(0, 16);
            pp_cfg.noise_level = fdp.ConsumeIntegralInRange<int>(0, 16);
            result = vpx_codec_control(codec_ptr, control_id, &pp_cfg);
        } else if (control_id == 8) {
            // vpx_roi_map_t for VP8E_SET_ROI_MAP
            // Note: We'll pass NULL since creating a valid ROI map is complex
            result = vpx_codec_control(codec_ptr, control_id, nullptr);
        } else if (control_id == 9) {
            // vpx_active_map_t for VP8E_SET_ACTIVEMAP  
            // Note: We'll pass NULL since creating a valid active map is complex
            result = vpx_codec_control(codec_ptr, control_id, nullptr);
        } else if (control_id == 11) {
            // vpx_scaling_mode_t for VP8E_SET_SCALEMODE
            // Note: We'll pass NULL since creating a valid scaling mode is complex
            result = vpx_codec_control(codec_ptr, control_id, nullptr);
        } else if (control_id == 128) {
            // vp9_ref_frame_t for VP9_GET_REFERENCE
            vp9_ref_frame_t vp9_ref;
            vp9_ref.idx = fdp.ConsumeIntegral<int>();
            // vpx_image_t img is complex, but passing partially initialized
            // structure should still test parameter validation paths
            result = vpx_codec_control(codec_ptr, control_id, &vp9_ref);
        } else {
            // For other pointer-requiring controls, pass NULL
            result = vpx_codec_control(codec_ptr, control_id, nullptr);
        }
    } else {
        // For other control IDs, use the original random parameter type strategy
        // Try calling vpx_codec_control with different parameter types
        switch (param_type) {
            case 0: {  // Integer parameter
                int int_param = fdp.ConsumeIntegral<int>();
                result = vpx_codec_control(codec_ptr, control_id, int_param);
                break;
            }
            case 1: {  // Unsigned integer parameter
                unsigned int uint_param = fdp.ConsumeIntegral<unsigned int>();
                result = vpx_codec_control(codec_ptr, control_id, uint_param);
                break;
            }
            case 2: {  // Pointer parameter (could be NULL)
                void* ptr_param = nullptr;
                // Sometimes pass NULL, sometimes pass a valid pointer address
                if (fdp.ConsumeBool() && fdp.remaining_bytes() >= sizeof(int)) {
                    // Use stack variable address
                    int temp = fdp.ConsumeIntegral<int>();
                    ptr_param = &temp;
                }
                result = vpx_codec_control(codec_ptr, control_id, ptr_param);
                break;
            }
            case 3: {  // Boolean-like parameter
                int bool_param = fdp.ConsumeBool() ? 1 : 0;
                result = vpx_codec_control(codec_ptr, control_id, bool_param);
                break;
            }
            case 4: {  // No parameter (void)
                // Some controls take no parameters - pass dummy 0 with type checking disabled
                result = vpx_codec_control(codec_ptr, control_id, 0);
                break;
            }
        }
    }
    
    // Test multiple control calls in sequence
    // This can test state accumulation and error propagation
    if (codec_initialized && fdp.ConsumeBool() && fdp.remaining_bytes() > 10) {
        int num_additional_calls = fdp.ConsumeIntegralInRange<int>(1, 5);
        for (int i = 0; i < num_additional_calls && fdp.remaining_bytes() > 0; i++) {
            int additional_control_id = fdp.ConsumeIntegralInRange<int>(1, 50);
            
            // Handle control IDs that require pointer parameters
            if (additional_control_id == 1 || additional_control_id == 2) {
                // vpx_ref_frame_t for VP8_SET_REFERENCE or VP8_COPY_REFERENCE
                vpx_ref_frame_t ref_frame;
                ref_frame.frame_type = static_cast<vpx_ref_frame_type_t>(
                    fdp.ConsumeIntegralInRange<int>(1, 4));
                vpx_codec_control(codec_ptr, additional_control_id, &ref_frame);
            } else if (additional_control_id == 3) {
                // vp8_postproc_cfg_t for VP8_SET_POSTPROC
                vp8_postproc_cfg_t pp_cfg;
                pp_cfg.post_proc_flag = fdp.ConsumeIntegral<int>();
                pp_cfg.deblocking_level = fdp.ConsumeIntegralInRange<int>(0, 16);
                pp_cfg.noise_level = fdp.ConsumeIntegralInRange<int>(0, 16);
                vpx_codec_control(codec_ptr, additional_control_id, &pp_cfg);
            } else if (additional_control_id == 8 || additional_control_id == 9 || additional_control_id == 11) {
                // Pointer-requiring controls from vp8cx.h
                // Pass NULL for complex structures
                vpx_codec_control(codec_ptr, additional_control_id, nullptr);
            } else {
                // For other control IDs, use integer parameter
                int additional_param = fdp.ConsumeIntegral<int>();
                vpx_codec_control(codec_ptr, additional_control_id, additional_param);
            }
        }
    }
    
    // Test error detail retrieval functions
    // Exercise the error handling paths in vpx_codec.c
    if (codec_ptr) {
        const char* error_detail = vpx_codec_error_detail(codec_ptr);
        const char* error_str = vpx_codec_error(codec_ptr);
        // Call vpx_codec_err_to_string with various error codes
        for (int err_code = 0; err_code < 10; err_code++) {
            const char* err_str = vpx_codec_err_to_string(static_cast<vpx_codec_err_t>(err_code));
            (void)err_str;
        }
        (void)error_detail;
        (void)error_str;
    }
    
    // Test vpx_codec_destroy with various states
    // This exercises the cleanup paths
    if (codec_initialized) {
        vpx_codec_destroy(&codec);
    } else if (fdp.ConsumeBool()) {
        // Test destroy with potentially invalid state
        vpx_codec_destroy(codec_ptr);
    }
    
    return 0;
}
