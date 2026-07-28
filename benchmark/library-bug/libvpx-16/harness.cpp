/*
 * Fuzzing harness for libvpx error handling and encoder control APIs
 * Target APIs: vpx_codec_error, vpx_codec_error_detail, vpx_codec_err_to_string,
 *              vpx_codec_control, vpx_codec_enc_init, vpx_codec_destroy,
 *              vpx_codec_enc_config_default, vpx_codec_get_caps
 * Focus: Error handling paths, encoder control functions, and API error state management
 *        Specifically targets error retrieval APIs and encoder control with various parameters
 *        Exercises error conditions, invalid parameters, and control validation
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <algorithm>
#include <vector>
#include <memory>
#include <string>

#include <fuzzer/FuzzedDataProvider.h>
#include "vpx/vpx_encoder.h"
#include "vpx/vp8cx.h"
#include "vpx/vpx_codec.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Minimum size check: need enough for basic configuration
    const size_t MIN_SIZE = 64;
    if (size < MIN_SIZE) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Consume configuration parameters from fuzzer input
    
    // Choose encoder type: VP8 or VP9
    bool use_vp9 = fdp.ConsumeBool();
    
    // Image dimensions (limited to reasonable sizes for fuzzing)
    unsigned int width = fdp.ConsumeIntegralInRange<unsigned int>(16, 512);
    unsigned int height = fdp.ConsumeIntegralInRange<unsigned int>(16, 512);
    
    // Choose encoder interface
    vpx_codec_iface_t* encoder_iface = nullptr;
    if (use_vp9) {
        encoder_iface = vpx_codec_vp9_cx();
    } else {
        encoder_iface = vpx_codec_vp8_cx();
    }
    
    if (!encoder_iface) {
        return 0;
    }
    
    // Get encoder capabilities
    vpx_codec_caps_t caps = vpx_codec_get_caps(encoder_iface);
    
    // Get default encoder configuration
    vpx_codec_enc_cfg_t cfg;
    vpx_codec_err_t config_err = vpx_codec_enc_config_default(encoder_iface, &cfg, 0);
    
    // Test error retrieval on config error
    if (config_err != VPX_CODEC_OK) {
        const char* err_str = vpx_codec_err_to_string(config_err);
        // Just consume the string - we're testing that the API can be called
        (void)err_str;
        return 0;
    }
    
    // Override configuration with fuzzed data
    cfg.g_w = width;
    cfg.g_h = height;
    cfg.g_timebase.num = 1;
    cfg.g_timebase.den = fdp.ConsumeIntegralInRange<unsigned int>(24, 60);
    cfg.rc_target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 10000);
    
    // Initialize encoder context with fuzzed flags
    vpx_codec_flags_t flags = 0;
    bool use_psnr = fdp.ConsumeBool();
    bool use_output_partition = fdp.ConsumeBool();
    
    if (use_psnr) {
        flags |= VPX_CODEC_USE_PSNR;
    }
    if (use_output_partition) {
        flags |= VPX_CODEC_USE_OUTPUT_PARTITION;
    }
    
    vpx_codec_ctx_t codec;
    vpx_codec_err_t init_err = vpx_codec_enc_init(&codec, encoder_iface, &cfg, flags);
    
    // Handle initialization failures and test error APIs
    if (init_err != VPX_CODEC_OK) {
        // Test error retrieval APIs on failed initialization
        const char* err_str = vpx_codec_err_to_string(init_err);
        const char* ctx_err = vpx_codec_error(&codec);
        const char* ctx_detail = vpx_codec_error_detail(&codec);
        
        // Consume the strings to ensure APIs can be called
        (void)err_str;
        (void)ctx_err;
        (void)ctx_detail;
        
        // Try alternative initialization (without problematic flags)
        flags &= ~(VPX_CODEC_USE_PSNR | VPX_CODEC_USE_OUTPUT_PARTITION);
        if (vpx_codec_enc_init(&codec, encoder_iface, &cfg, flags) != VPX_CODEC_OK) {
            return 0;
        }
    }
    
    // Test error APIs on successful initialization
    const char* ctx_err = vpx_codec_error(&codec);
    const char* ctx_detail = vpx_codec_error_detail(&codec);
    (void)ctx_err;
    (void)ctx_detail;
    
    // Determine number of control operations to test
    int num_controls = fdp.ConsumeIntegralInRange<int>(1, 20);
    
    // Test various encoder control functions
    for (int i = 0; i < num_controls && fdp.remaining_bytes() > 0; i++) {
        // Choose a control ID based on encoder type
        int control_id;
        if (use_vp9) {
            // VP9 specific controls
            uint8_t vp9_control_idx = fdp.ConsumeIntegral<uint8_t>() % 12;
            switch (vp9_control_idx) {
                case 0: control_id = VP9E_SET_TILE_COLUMNS; break;
                case 1: control_id = VP9E_SET_TILE_ROWS; break;
                case 2: control_id = VP9E_SET_FRAME_PARALLEL_DECODING; break;
                case 3: control_id = VP9E_SET_AQ_MODE; break;
                case 4: control_id = VP9E_SET_LOSSLESS; break;
                case 5: control_id = VP9E_SET_COLOR_SPACE; break;
                case 6: control_id = VP9E_SET_COLOR_RANGE; break;
                case 7: control_id = VP9E_SET_ROW_MT; break;
                case 8: control_id = VP9E_SET_TUNE_CONTENT; break;
                case 9: control_id = VP9E_SET_TARGET_LEVEL; break;
                case 10: control_id = VP9E_SET_MAX_INTER_BITRATE_PCT; break;
                case 11: control_id = VP9E_SET_GF_CBR_BOOST_PCT; break;
                default: control_id = VP8E_SET_CPUUSED; break;
            }
        } else {
            // VP8 specific controls
            uint8_t vp8_control_idx = fdp.ConsumeIntegral<uint8_t>() % 15;
            switch (vp8_control_idx) {
                case 0: control_id = VP8E_SET_CPUUSED; break;
                case 1: control_id = VP8E_SET_CQ_LEVEL; break;
                case 2: control_id = VP8E_SET_MAX_INTRA_BITRATE_PCT; break;
                case 3: control_id = VP8E_SET_ARNR_MAXFRAMES; break;
                case 4: control_id = VP8E_SET_ARNR_STRENGTH; break;
                case 5: control_id = VP8E_SET_ARNR_TYPE; break;
                case 6: control_id = VP8E_SET_TUNING; break;
                case 7: control_id = VP8E_SET_TEMPORAL_LAYER_ID; break;
                case 8: control_id = VP8E_SET_SCREEN_CONTENT_MODE; break;
                case 9: control_id = VP8E_SET_SCALEMODE; break;
                case 10: control_id = VP8E_SET_ACTIVEMAP; break;
                case 11: control_id = VP8E_SET_FRAME_FLAGS; break;
                case 12: control_id = VP8E_SET_NOISE_SENSITIVITY; break;
                case 13: control_id = VP8E_SET_SHARPNESS; break;
                case 14: control_id = VP8E_SET_TOKEN_PARTITIONS; break;
                default: control_id = VP8E_SET_CPUUSED; break;
            }
        }
        
        // Prepare control value based on control ID type
        vpx_codec_err_t control_err = VPX_CODEC_ERROR;
        
        // Try different data types based on control ID
        if (control_id == VP8E_SET_CPUUSED) {
            int cpu_used = fdp.ConsumeIntegralInRange<int>(-16, 16);
            control_err = vpx_codec_control_(&codec, control_id, cpu_used);
        }
        else if (control_id == VP8E_SET_CQ_LEVEL) {
            unsigned int cq_level = fdp.ConsumeIntegralInRange<unsigned int>(0, 63);
            control_err = vpx_codec_control_(&codec, control_id, cq_level);
        }
        else if (control_id == VP9E_SET_TUNE_CONTENT) {
            int tune_content = fdp.ConsumeIntegralInRange<int>(0, 2);
            control_err = vpx_codec_control_(&codec, control_id, tune_content);
        }
        else if (control_id == VP9E_SET_COLOR_SPACE) {
            int color_space = fdp.ConsumeIntegralInRange<int>(0, 7);
            control_err = vpx_codec_control_(&codec, control_id, color_space);
        }
        else if (control_id == VP9E_SET_COLOR_RANGE) {
            int color_range = fdp.ConsumeIntegralInRange<int>(0, 1);
            control_err = vpx_codec_control_(&codec, control_id, color_range);
        }
        else if (control_id == VP9E_SET_TILE_COLUMNS) {
            int tile_columns = fdp.ConsumeIntegralInRange<int>(0, 6);
            control_err = vpx_codec_control_(&codec, control_id, tile_columns);
        }
        else if (control_id == VP9E_SET_TILE_ROWS) {
            int tile_rows = fdp.ConsumeIntegralInRange<int>(0, 6);
            control_err = vpx_codec_control_(&codec, control_id, tile_rows);
        }
        else if (control_id == VP9E_SET_FRAME_PARALLEL_DECODING) {
            unsigned int frame_parallel = fdp.ConsumeBool() ? 1 : 0;
            control_err = vpx_codec_control_(&codec, control_id, frame_parallel);
        }
        else if (control_id == VP9E_SET_AQ_MODE) {
            unsigned int aq_mode = fdp.ConsumeIntegralInRange<unsigned int>(0, 4);
            control_err = vpx_codec_control_(&codec, control_id, aq_mode);
        }
        else if (control_id == VP9E_SET_LOSSLESS) {
            unsigned int lossless = fdp.ConsumeBool() ? 1 : 0;
            control_err = vpx_codec_control_(&codec, control_id, lossless);
        }
        else if (control_id == VP9E_SET_ROW_MT) {
            unsigned int row_mt = fdp.ConsumeBool() ? 1 : 0;
            control_err = vpx_codec_control_(&codec, control_id, row_mt);
        }
        else if (control_id == VP8E_SET_ACTIVEMAP) {
            // VP8E_SET_ACTIVEMAP expects vpx_active_map_t* pointer
            vpx_active_map_t active_map = {0, 0, 0};
            // Set reasonable dimensions based on image size
            active_map.rows = (height + 15) / 16;
            active_map.cols = (width + 15) / 16;
            
            // Allocate and fill active_map if dimensions are reasonable
            if (active_map.rows > 0 && active_map.cols > 0 && 
                active_map.rows <= 64 && active_map.cols <= 64) {
                size_t map_size = active_map.rows * active_map.cols;
                if (fdp.remaining_bytes() >= map_size) {
                    // Allocate and fill with fuzzed data
                    active_map.active_map = (unsigned char*)malloc(map_size);
                    if (active_map.active_map) {
                        for (size_t i = 0; i < map_size && fdp.remaining_bytes() > 0; i++) {
                            active_map.active_map[i] = fdp.ConsumeBool() ? 1 : 0;
                        }
                        control_err = vpx_codec_control_(&codec, control_id, &active_map);
                        free(active_map.active_map);
                    } else {
                        // Memory allocation failed, skip this control
                        control_err = VPX_CODEC_MEM_ERROR;
                    }
                } else {
                    // Not enough data for active map, skip
                    control_err = VPX_CODEC_INVALID_PARAM;
                }
            } else {
                // Invalid dimensions, skip
                control_err = VPX_CODEC_INVALID_PARAM;
            }
        }
        else if (control_id == VP9E_SET_ROI_MAP) {
            // VP9E_SET_ROI_MAP expects vpx_roi_map_t* pointer
            vpx_roi_map_t roi_map = {0};
            // Set reasonable dimensions based on image size
            roi_map.rows = (height + 15) / 16;
            roi_map.cols = (width + 15) / 16;
            
            // Allocate and fill roi_map if dimensions are reasonable
            if (roi_map.rows > 0 && roi_map.cols > 0 && 
                roi_map.rows <= 64 && roi_map.cols <= 64) {
                size_t map_size = roi_map.rows * roi_map.cols;
                if (fdp.remaining_bytes() >= map_size) {
                    // Allocate and fill with fuzzed data
                    roi_map.roi_map = (unsigned char*)malloc(map_size);
                    if (roi_map.roi_map) {
                        for (size_t i = 0; i < map_size && fdp.remaining_bytes() > 0; i++) {
                            roi_map.roi_map[i] = fdp.ConsumeIntegral<uint8_t>() % 8; // VP9 uses 8 segments
                        }
                        control_err = vpx_codec_control_(&codec, control_id, &roi_map);
                        free(roi_map.roi_map);
                    } else {
                        // Memory allocation failed, skip this control
                        control_err = VPX_CODEC_MEM_ERROR;
                    }
                } else {
                    // Not enough data for ROI map, skip
                    control_err = VPX_CODEC_INVALID_PARAM;
                }
            } else {
                // Invalid dimensions, skip
                control_err = VPX_CODEC_INVALID_PARAM;
            }
        }
        else if (control_id == VP8E_SET_SCALEMODE) {
            // VP8E_SET_SCALEMODE expects vpx_scaling_mode_t* pointer
            vpx_scaling_mode_t scaling_mode;
            scaling_mode.h_scaling_mode = static_cast<VPX_SCALING_MODE>(fdp.ConsumeIntegralInRange<int>(0, 3));
            scaling_mode.v_scaling_mode = static_cast<VPX_SCALING_MODE>(fdp.ConsumeIntegralInRange<int>(0, 3));
            control_err = vpx_codec_control_(&codec, control_id, &scaling_mode);
        }
        else if (control_id == VP8E_SET_TOKEN_PARTITIONS) {
            // VP8E_SET_TOKEN_PARTITIONS expects vp8e_token_partitions enum
            int partitions = fdp.ConsumeIntegralInRange<int>(0, 3);
            control_err = vpx_codec_control_(&codec, control_id, partitions);
        }
        else {
            // For other controls, try with a simple integer
            int simple_value = fdp.ConsumeIntegral<int>();
            control_err = vpx_codec_control_(&codec, control_id, simple_value);
        }
        
        // Test error retrieval after control operation
        if (control_err != VPX_CODEC_OK) {
            const char* control_err_str = vpx_codec_err_to_string(control_err);
            const char* control_ctx_err = vpx_codec_error(&codec);
            const char* control_ctx_detail = vpx_codec_error_detail(&codec);
            
            (void)control_err_str;
            (void)control_ctx_err;
            (void)control_ctx_detail;
        }
    }
    
    // Test error APIs with NULL/invalid parameters (error handling paths)
    
    // Test vpx_codec_error with NULL context
    const char* null_err = vpx_codec_error(nullptr);
    (void)null_err;
    
    // Test vpx_codec_error_detail with NULL context  
    const char* null_detail = vpx_codec_error_detail(nullptr);
    (void)null_detail;
    
    // Test vpx_codec_err_to_string with valid error codes
    // Create an array of valid vpx_codec_err_t enum values
    vpx_codec_err_t valid_error_codes[] = {
        VPX_CODEC_OK,
        VPX_CODEC_ERROR,
        VPX_CODEC_MEM_ERROR,
        VPX_CODEC_ABI_MISMATCH,
        VPX_CODEC_INCAPABLE,
        VPX_CODEC_UNSUP_BITSTREAM,
        VPX_CODEC_UNSUP_FEATURE,
        VPX_CODEC_CORRUPT_FRAME,
        VPX_CODEC_INVALID_PARAM,
        VPX_CODEC_LIST_END
    };
    const size_t num_valid_errors = sizeof(valid_error_codes) / sizeof(valid_error_codes[0]);
    
    // Pick a valid error code using fuzzed data
    size_t error_index = fdp.ConsumeIntegralInRange<size_t>(0, num_valid_errors - 1);
    vpx_codec_err_t test_err = valid_error_codes[error_index];
    const char* test_err_str = vpx_codec_err_to_string(test_err);
    (void)test_err_str;
    // Test vpx_codec_control with invalid control ID
    int invalid_control_id = 99999;
    int invalid_value = fdp.ConsumeIntegral<int>();
    vpx_codec_control_(&codec, invalid_control_id, invalid_value);
    // Error will be set in context, test retrieval
    const char* invalid_control_err = vpx_codec_error(&codec);
    const char* invalid_control_detail = vpx_codec_error_detail(&codec);
    (void)invalid_control_err;
    (void)invalid_control_detail;
    
    // Test re-initialization error (context already initialized)
    vpx_codec_err_t reinit_err = vpx_codec_enc_init(&codec, encoder_iface, &cfg, flags);
    if (reinit_err != VPX_CODEC_OK) {
        const char* reinit_err_str = vpx_codec_err_to_string(reinit_err);
        (void)reinit_err_str;
    }
    
    // Test configuration set with NULL config
    vpx_codec_enc_config_set(&codec, nullptr);
    const char* null_config_err = vpx_codec_error(&codec);
    (void)null_config_err;
    
    // Clean up
    vpx_codec_err_t destroy_err = vpx_codec_destroy(&codec);
    if (destroy_err != VPX_CODEC_OK) {
        const char* destroy_err_str = vpx_codec_err_to_string(destroy_err);
        (void)destroy_err_str;
    }
    
    // Test error APIs after destruction
    const char* post_destroy_err = vpx_codec_error(&codec);
    const char* post_destroy_detail = vpx_codec_error_detail(&codec);
    (void)post_destroy_err;
    (void)post_destroy_detail;
    
    return 0;
}
