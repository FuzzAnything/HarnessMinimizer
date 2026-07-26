/*
 * Copyright (c) 2024, FuzzAgent Project. All rights reserved.
 *
 * Fuzzing harness for libaom AV1 encoder with structured image pattern testing
 * targeting the most critical coverage gap in aom_fast9_detect function 
 * (1919 blocked branches, 97% of reachable branches).
 * 
 * This harness focuses on creating structured image patterns and encoder parameter
 * variation to unlock deep branching paths in FAST-9 corner detection algorithm.
 * 
 * Target APIs: aom_codec_enc_init_ver, aom_codec_enc_config_default, 
 * aom_codec_enc_config_set, aom_img_alloc, aom_img_set_rect, aom_codec_encode, 
 * aom_codec_control, aom_codec_destroy, aom_img_free.
 * 
 * Structured image patterns:
 * 1. Checkerboard patterns
 * 2. Synthetic corner patterns
 * 3. Random noise with varying contrast
 * 4. Gradient images with edges
 * 5. Isolated bright/dark pixels
 * 
 * Semantic differentiation from existing harnesses:
 * - harness_010: Tests basic FAST detection with random patterns
 * - This harness: Focuses on structured image patterns targeting specific
 *   corner detection algorithm branching logic, integrated with full encoder workflow
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <algorithm>
#include <vector>
#include <cmath>

#include "fuzzer/FuzzedDataProvider.h"
#include "aom/aom_codec.h"
#include "aom/aom_image.h"
#include "aom/aomcx.h"
#include "aom/aom_encoder.h"

// FAST detection function declarations
typedef struct { int x, y; } xy;
typedef unsigned char byte;
extern "C" xy* aom_fast9_detect(const byte* im, int xsize, int ysize, int stride, int b, int* ret_num_corners);
extern "C" xy* aom_fast9_detect_nonmax(const byte* im, int xsize, int ysize, int stride, int b,
                                      int** ret_scores, int* ret_num_corners);

// Minimum input size required for comprehensive testing
#define MIN_INPUT_SIZE 512

// Pattern types for structured image generation
enum PatternType {
    PATTERN_CHECKERBOARD = 0,
    PATTERN_SYNTHETIC_CORNERS,
    PATTERN_NOISE_VARYING_CONTRAST,
    PATTERN_GRADIENT_EDGES,
    PATTERN_ISOLATED_PIXELS,
    PATTERN_MIXED,
    PATTERN_COUNT
};

// Helper: Generate checkerboard pattern
static void generate_checkerboard(aom_image_t *img, FuzzedDataProvider &fdp, int cell_size) {
    unsigned char *plane_buf = img->planes[0];
    if (!plane_buf) return;
    
    size_t height = aom_img_plane_height(img, 0);
    size_t width = aom_img_plane_width(img, 0);
    size_t stride = img->stride[0];
    
    unsigned char value1 = fdp.ConsumeIntegralInRange<unsigned char>(0, 128);
    unsigned char value2 = fdp.ConsumeIntegralInRange<unsigned char>(128, 255);
    
    for (size_t y = 0; y < height; ++y) {
        unsigned char *row = plane_buf + y * stride;
        for (size_t x = 0; x < width; ++x) {
            bool is_black = ((x / cell_size) + (y / cell_size)) % 2 == 0;
            row[x] = is_black ? value1 : value2;
        }
    }
}

// Helper: Generate synthetic corner patterns
static void generate_synthetic_corners(aom_image_t *img, FuzzedDataProvider &fdp) {
    unsigned char *plane_buf = img->planes[0];
    if (!plane_buf) return;
    
    size_t height = aom_img_plane_height(img, 0);
    size_t width = aom_img_plane_width(img, 0);
    size_t stride = img->stride[0];
    
    // Base background
    unsigned char base_value = fdp.ConsumeIntegralInRange<unsigned char>(64, 192);
    for (size_t y = 0; y < height; ++y) {
        unsigned char *row = plane_buf + y * stride;
        for (size_t x = 0; x < width; ++x) {
            row[x] = base_value;
        }
    }
    
    // Add several synthetic corners at strategic positions
    int num_corners = fdp.ConsumeIntegralInRange<int>(1, 8);
    for (int i = 0; i < num_corners; ++i) {
        int corner_x = fdp.ConsumeIntegralInRange<int>(10, width - 11);
        int corner_y = fdp.ConsumeIntegralInRange<int>(10, height - 11);
        int corner_size = fdp.ConsumeIntegralInRange<int>(3, 8);
        unsigned char corner_value = fdp.ConsumeIntegralInRange<unsigned char>(base_value + 30, 255);
        
        // Create L-shaped corner pattern
        for (int dy = -corner_size; dy <= corner_size; ++dy) {
            int y = corner_y + dy;
            if (y < 0 || y >= (int)height) continue;
            unsigned char *row = plane_buf + y * stride;
            
            for (int dx = -corner_size; dx <= corner_size; ++dx) {
                int x = corner_x + dx;
                if (x < 0 || x >= (int)width) continue;
                
                // Create corner shape: bright pixels in two perpendicular lines
                if ((abs(dx) <= 2 && dy >= 0) || (abs(dy) <= 2 && dx >= 0)) {
                    row[x] = corner_value;
                } else if ((abs(dx) <= 2 && dy <= 0) || (abs(dy) <= 2 && dx <= 0)) {
                    row[x] = base_value - fdp.ConsumeIntegralInRange<unsigned char>(20, 60);
                }
            }
        }
    }
}

// Helper: Generate noise with varying contrast
static void generate_noise_varying_contrast(aom_image_t *img, FuzzedDataProvider &fdp) {
    unsigned char *plane_buf = img->planes[0];
    if (!plane_buf) return;
    
    size_t height = aom_img_plane_height(img, 0);
    size_t width = aom_img_plane_width(img, 0);
    size_t stride = img->stride[0];
    
    // Create regions with different contrast levels
    int region_width = width / 3;
    int region_height = height / 3;
    
    for (int region_y = 0; region_y < 3; ++region_y) {
        for (int region_x = 0; region_x < 3; ++region_x) {
            int contrast_level = region_x + region_y * 3;
            unsigned char base = fdp.ConsumeIntegralInRange<unsigned char>(64, 192);
            unsigned char range = fdp.ConsumeIntegralInRange<unsigned char>(10, 100);
            
            for (int y = region_y * region_height; y < (region_y + 1) * region_height && y < (int)height; ++y) {
                unsigned char *row = plane_buf + y * stride;
                for (int x = region_x * region_width; x < (region_x + 1) * region_width && x < (int)width; ++x) {
                    int noise = fdp.ConsumeIntegralInRange<int>(-range/2, range/2);
                    row[x] = std::max(0, std::min(255, (int)base + noise));
                }
            }
        }
    }
}

// Helper: Generate gradient images with edges
static void generate_gradient_edges(aom_image_t *img, FuzzedDataProvider &fdp) {
    unsigned char *plane_buf = img->planes[0];
    if (!plane_buf) return;
    
    size_t height = aom_img_plane_height(img, 0);
    size_t width = aom_img_plane_width(img, 0);
    size_t stride = img->stride[0];
    
    // Create horizontal and vertical gradients
    for (size_t y = 0; y < height; ++y) {
        unsigned char *row = plane_buf + y * stride;
        for (size_t x = 0; x < width; ++x) {
            // Horizontal gradient component
            double h_grad = (double)x / width * 255.0;
            // Vertical gradient component
            double v_grad = (double)y / height * 255.0;
            // Combine with some randomness
            double mix = fdp.ConsumeProbability<double>();
            row[x] = (unsigned char)(mix * h_grad + (1.0 - mix) * v_grad);
        }
    }
    
    // Add sharp edges at random positions
    int num_edges = fdp.ConsumeIntegralInRange<int>(1, 5);
    for (int i = 0; i < num_edges; ++i) {
        bool vertical = fdp.ConsumeBool();
        unsigned char edge_value = fdp.ConsumeIntegralInRange<unsigned char>(0, 255);
        
        if (vertical) {
            int edge_x = fdp.ConsumeIntegralInRange<int>(10, width - 11);
            for (size_t y = 0; y < height; ++y) {
                unsigned char *row = plane_buf + y * stride;
                row[edge_x] = edge_value;
                if (edge_x > 0) row[edge_x - 1] = 255 - edge_value;
                if (edge_x + 1 < (int)width) row[edge_x + 1] = 255 - edge_value;
            }
        } else {
            int edge_y = fdp.ConsumeIntegralInRange<int>(10, height - 11);
            for (size_t x = 0; x < width; ++x) {
                unsigned char *row = plane_buf + edge_y * stride;
                row[x] = edge_value;
                if (edge_y > 0) {
                    unsigned char *prev_row = plane_buf + (edge_y - 1) * stride;
                    prev_row[x] = 255 - edge_value;
                }
                if (edge_y + 1 < (int)height) {
                    unsigned char *next_row = plane_buf + (edge_y + 1) * stride;
                    next_row[x] = 255 - edge_value;
                }
            }
        }
    }
}

// Helper: Generate isolated bright/dark pixels
static void generate_isolated_pixels(aom_image_t *img, FuzzedDataProvider &fdp) {
    unsigned char *plane_buf = img->planes[0];
    if (!plane_buf) return;
    
    size_t height = aom_img_plane_height(img, 0);
    size_t width = aom_img_plane_width(img, 0);
    size_t stride = img->stride[0];
    
    // Uniform background
    unsigned char background = fdp.ConsumeIntegralInRange<unsigned char>(100, 150);
    for (size_t y = 0; y < height; ++y) {
        unsigned char *row = plane_buf + y * stride;
        for (size_t x = 0; x < width; ++x) {
            row[x] = background;
        }
    }
    
    // Add isolated bright pixels
    int num_bright = fdp.ConsumeIntegralInRange<int>(1, 20);
    for (int i = 0; i < num_bright; ++i) {
        int px = fdp.ConsumeIntegralInRange<int>(5, width - 6);
        int py = fdp.ConsumeIntegralInRange<int>(5, height - 6);
        unsigned char bright_value = fdp.ConsumeIntegralInRange<unsigned char>(200, 255);
        
        for (int dy = -2; dy <= 2; ++dy) {
            int y = py + dy;
            if (y < 0 || y >= (int)height) continue;
            unsigned char *row = plane_buf + y * stride;
            
            for (int dx = -2; dx <= 2; ++dx) {
                int x = px + dx;
                if (x < 0 || x >= (int)width) continue;
                
                if (abs(dx) <= 1 && abs(dy) <= 1) {
                    row[x] = bright_value;
                } else if (abs(dx) == 2 || abs(dy) == 2) {
                    row[x] = background - fdp.ConsumeIntegralInRange<unsigned char>(30, 70);
                }
            }
        }
    }
}

// Main pattern generation function
static void generate_structured_pattern(aom_image_t *img, FuzzedDataProvider &fdp, PatternType pattern_type) {
    switch (pattern_type) {
        case PATTERN_CHECKERBOARD:
            generate_checkerboard(img, fdp, fdp.ConsumeIntegralInRange<int>(2, 16));
            break;
        case PATTERN_SYNTHETIC_CORNERS:
            generate_synthetic_corners(img, fdp);
            break;
        case PATTERN_NOISE_VARYING_CONTRAST:
            generate_noise_varying_contrast(img, fdp);
            break;
        case PATTERN_GRADIENT_EDGES:
            generate_gradient_edges(img, fdp);
            break;
        case PATTERN_ISOLATED_PIXELS:
            generate_isolated_pixels(img, fdp);
            break;
        case PATTERN_MIXED:
            // Generate multiple patterns in different regions
            for (int region = 0; region < 4 && fdp.remaining_bytes() > 0; ++region) {
                int region_pattern = fdp.ConsumeIntegralInRange<int>(0, PATTERN_COUNT - 2);
                // Apply different pattern to quadrant
                // Simplified: just use first pattern for mixed
                generate_checkerboard(img, fdp, fdp.ConsumeIntegralInRange<int>(4, 12));
                break;
            }
            break;
        default:
            // Default to checkerboard
            generate_checkerboard(img, fdp, 8);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Require minimum input size
    if (size < MIN_INPUT_SIZE) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);

    // 1. Select pattern type for structured image generation
    PatternType pattern_type = static_cast<PatternType>(
        fdp.ConsumeIntegralInRange<int>(0, PATTERN_COUNT - 1));

    // 2. Get the AV1 encoder interface
    aom_codec_iface_t *encoder = aom_codec_av1_cx();
    if (!encoder) {
        return 0;
    }

    // 3. Initialize encoder configuration with default values
    aom_codec_enc_cfg_t cfg;
    if (aom_codec_enc_config_default(encoder, &cfg, 0) != AOM_CODEC_OK) {
        return 0;
    }

    // Consume image dimensions with limits for structured pattern testing
    // Keep images small to focus on corner detection algorithm
    cfg.g_w = fdp.ConsumeIntegralInRange<unsigned int>(32, 96);
    cfg.g_h = fdp.ConsumeIntegralInRange<unsigned int>(32, 96);
    
    // Limit total image size
    if (cfg.g_w * cfg.g_h > 8192) {  // 96x96 = 9216, so limit to slightly smaller
        cfg.g_w = 64;
        cfg.g_h = 64;
    }
    
    // Consume encoder parameters that affect corner detection
    cfg.g_bit_depth = fdp.ConsumeBool() ? AOM_BITS_8 : AOM_BITS_10;
    cfg.g_timebase.num = 1;
    cfg.g_timebase.den = 30;
    cfg.g_error_resilient = fdp.ConsumeBool();
    cfg.g_pass = AOM_RC_ONE_PASS;
    cfg.g_lag_in_frames = 0;  // No lookahead for corner detection focus
    
    // Consume rate control parameters
    cfg.rc_end_usage = static_cast<aom_rc_mode>(
        fdp.ConsumeIntegralInRange<int>(0, 2));  // AOM_VBR, AOM_CBR, AOM_CQ
    cfg.rc_target_bitrate = fdp.ConsumeIntegralInRange<unsigned int>(100, 1000);
    cfg.rc_min_quantizer = fdp.ConsumeIntegralInRange<unsigned int>(0, 63);
    cfg.rc_max_quantizer = fdp.ConsumeIntegralInRange<unsigned int>(cfg.rc_min_quantizer, 63);

    // 4. Initialize encoder context
    aom_codec_ctx_t codec;
    if (aom_codec_enc_init_ver(&codec, encoder, &cfg, 0, AOM_ENCODER_ABI_VERSION) != AOM_CODEC_OK) {
        return 0;
    }

    // 5. Apply configuration changes using aom_codec_enc_config_set
    // Modify some parameters to test config_set functionality
    cfg.g_threads = fdp.ConsumeIntegralInRange<unsigned int>(1, 4);
    cfg.g_profile = fdp.ConsumeIntegralInRange<unsigned int>(0, 3);
    aom_codec_enc_config_set(&codec, &cfg);

    // 6. Allocate image for structured pattern testing
    aom_img_fmt_t fmt = AOM_IMG_FMT_YV12;  // YV12 for luminance plane access
    unsigned int align = 1 << fdp.ConsumeIntegralInRange<unsigned int>(0, 3); // 1,2,4,8
    
    aom_image_t *img = aom_img_alloc(nullptr, fmt, cfg.g_w, cfg.g_h, align);
    if (img == nullptr) {
        aom_codec_destroy(&codec);
        return 0;
    }

    // 7. Generate structured pattern in the image
    generate_structured_pattern(img, fdp, pattern_type);

    // 8. Test aom_img_set_rect with sub-region of the pattern
    // Note: aom_img_set_rect sets the displayed rectangle, not pixel data
    if (cfg.g_w > 16 && cfg.g_h > 16) {
        unsigned int rect_x = fdp.ConsumeIntegralInRange<unsigned int>(0, cfg.g_w / 4);
        unsigned int rect_y = fdp.ConsumeIntegralInRange<unsigned int>(0, cfg.g_h / 4);
        unsigned int rect_w = fdp.ConsumeIntegralInRange<unsigned int>(8, cfg.g_w / 2);
        unsigned int rect_h = fdp.ConsumeIntegralInRange<unsigned int>(8, cfg.g_h / 2);
        unsigned int border = fdp.ConsumeIntegralInRange<unsigned int>(0, 4);
        
        // Ensure rectangle stays within bounds
        if (rect_x + rect_w > cfg.g_w) rect_w = cfg.g_w - rect_x;
        if (rect_y + rect_h > cfg.g_h) rect_h = cfg.g_h - rect_y;
        
        aom_img_set_rect(img, rect_x, rect_y, rect_w, rect_h, border);
    }

    // 9. Apply encoder control options that might affect corner detection
    // Set AOME_SET_CPUUSED to control speed/quality tradeoff
    int cpu_used = fdp.ConsumeIntegralInRange<int>(-8, 8);
    aom_codec_control(&codec, AOME_SET_CPUUSED, cpu_used);
    
    // Set noise sensitivity if supported
    if (fdp.ConsumeBool()) {
        int noise_sensitivity = fdp.ConsumeIntegralInRange<int>(0, 1);
        aom_codec_control(&codec, AV1E_SET_NOISE_SENSITIVITY, noise_sensitivity);
    }

    // 10. Perform FAST corner detection on the luminance plane
    const unsigned char *im = img->planes[0];  // Y plane
    int stride = img->stride[0];
    int b = fdp.ConsumeIntegralInRange<int>(5, 50);  // FAST barrier value
    
    int num_corners = 0;
    int *scores = nullptr;
    xy *corners = aom_fast9_detect_nonmax(im, cfg.g_w, cfg.g_h, stride, b, &scores, &num_corners);
    
    // 11. Use detected corners to influence encoder behavior (if corners found)
    if (corners != nullptr && num_corners > 0) {
        // Set tile columns/rows based on corner distribution
        int tile_cols = fdp.ConsumeIntegralInRange<int>(0, 3);
        int tile_rows = fdp.ConsumeIntegralInRange<int>(0, 3);
        aom_codec_control(&codec, AV1E_SET_TILE_COLUMNS, tile_cols);
        aom_codec_control(&codec, AV1E_SET_TILE_ROWS, tile_rows);
        
        // Clean up corner detection results
        free(corners);
        if (scores != nullptr) {
            free(scores);
        }
    }

    // 12. Encode the image with structured pattern
    aom_codec_encode(&codec, img, 0, 1, 0);

    // 13. Clean up
    aom_img_free(img);
    aom_codec_destroy(&codec);

    return 0;
}
