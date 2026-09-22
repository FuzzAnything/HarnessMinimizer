/*
 * Fuzzing harness for tinygltf library targeting UNCOVERED image writing core functions in stb_image_write.h
 * Goal: Exercise deeply uncovered internal core functions with 0% coverage:
 *   - stbi_write_hdr_core: 0% lines hit, 68 undiscovered branches
 *   - stbi_write_jpg_core: 0% lines hit, 114 undiscovered branches  
 *   - stbi_write_tga_core: 0% lines hit, 94 undiscovered branches
 *   - stbi_write_bmp_core: 0% lines hit, 56 undiscovered branches
 * Also target high-level APIs with 0% coverage:
 *   - stbi_write_png: 0% function lines hit, 4 branches (all undiscovered)
 *   - stbi_write_bmp: 0% function lines hit, 2 branches (all undiscovered)
 *   - stbi_write_jpg: 0% function lines hit, 2 branches (all undiscovered)
 *   - stbi_write_tga: 0% function lines hit, 2 branches (all undiscovered)
 *   - stbi_write_hdr: 0% function lines hit, 2 branches (all undiscovered)
 * Strategy: Direct testing of internal core functions via their public API wrappers with extensive
 *           parameter variation, edge cases, and synthetic image data generation
 * Differentiation from existing harnesses:
 *   - harness_007: Tests high-level APIs but may not reach core functions effectively
 *   - harness_017: Complete lifecycle but focuses on loading→writing pipeline
 *   - harness_018: FOCUSES ON CORE FUNCTIONS with synthetic data, edge cases, and direct parameter manipulation
 */

#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <algorithm>
#include <memory>
#include <cmath>

#include <fuzzer/FuzzedDataProvider.h>

// Include STB headers (implementation already built via tinygltf)
#include "stb_image_write.h"

// Simple write callback context for in-memory writing
struct WriteCallbackContext {
    std::vector<uint8_t> buffer;
    size_t total_written = 0;
};

// Write callback function for stbi_write_*_to_func APIs
static void write_callback(void* context, void* data, int size) {
    WriteCallbackContext* ctx = static_cast<WriteCallbackContext*>(context);
    if (data && size > 0) {
        uint8_t* bytes = static_cast<uint8_t*>(data);
        ctx->buffer.insert(ctx->buffer.end(), bytes, bytes + size);
        ctx->total_written += size;
    }
}

// Generate synthetic image data of various types
static std::vector<uint8_t> generate_8bit_image(int width, int height, int channels, int pattern_type) {
    std::vector<uint8_t> data(width * height * channels);
    size_t idx = 0;
    
    for (int y = 0; y < height; y++) {
        for (int x = 0; x < width; x++) {
            for (int c = 0; c < channels; c++) {
                uint8_t value = 0;
                switch (pattern_type % 5) {
                    case 0: // Gradient
                        value = static_cast<uint8_t>((x + y) % 256);
                        break;
                    case 1: // Checkerboard
                        value = ((x / 8) % 2) ^ ((y / 8) % 2) ? 255 : 0;
                        break;
                    case 2: // Vertical stripes
                        value = (x % 16 < 8) ? 128 : 64;
                        break;
                    case 3: // Horizontal stripes  
                        value = (y % 16 < 8) ? 192 : 32;
                        break;
                    case 4: // Random-like but deterministic
                        value = static_cast<uint8_t>((x * 17 + y * 13 + c * 11) % 256);
                        break;
                }
                data[idx++] = value;
            }
        }
    }
    return data;
}

static std::vector<float> generate_float_image(int width, int height, int channels, int pattern_type) {
    std::vector<float> data(width * height * channels);
    size_t idx = 0;
    
    for (int y = 0; y < height; y++) {
        for (int x = 0; x < width; x++) {
            for (int c = 0; c < channels; c++) {
                float value = 0.0f;
                switch (pattern_type % 5) {
                    case 0: // HDR gradient
                        value = (x + y) / static_cast<float>(width + height);
                        break;
                    case 1: // High contrast
                        value = ((x / 8) % 2) ^ ((y / 8) % 2) ? 10.0f : 0.01f;
                        break;
                    case 2: // Sine pattern
                        value = 0.5f + 0.5f * sinf(x * 0.1f) * cosf(y * 0.1f);
                        break;
                    case 3: // Exponential
                        value = expf(-(x*x + y*y) / (width*height / 10.0f));
                        break;
                    case 4: // Random-like but deterministic
                        value = fmodf((x * 1.7f + y * 1.3f + c * 1.1f) / 100.0f, 1.0f);
                        break;
                }
                data[idx++] = value;
            }
        }
    }
    return data;
}

// Test specific core function patterns with various edge cases
static void test_core_function_patterns(FuzzedDataProvider& fdp, int width, int height, int channels, 
                                        const std::vector<uint8_t>& image_data_8bit,
                                        const std::vector<float>& image_data_float) {
    // Consume operation type
    int operation_type = fdp.ConsumeIntegralInRange<int>(0, 15);
    
    // Set global configuration parameters from fuzzer input
    stbi_write_tga_with_rle = fdp.ConsumeBool() ? 1 : 0;
    stbi_write_png_compression_level = fdp.ConsumeIntegralInRange<int>(0, 9);
    stbi_write_force_png_filter = fdp.ConsumeIntegralInRange<int>(-1, 5);
    stbi_flip_vertically_on_write(fdp.ConsumeBool() ? 1 : 0);
    
    WriteCallbackContext write_ctx;
    int quality = fdp.ConsumeIntegralInRange<int>(1, 100);
    
    // Test different operation patterns to reach various core functions
    switch (operation_type) {
        case 0: // Test PNG with various strides (affects stbi_write_png_to_mem -> core compression)
            {
                int stride = width * channels;
                int stride_variant = fdp.ConsumeIntegralInRange<int>(-stride, stride * 2);
                if (stride_variant > 0) stride = stride_variant;
                
                stbi_write_png_to_func(write_callback, &write_ctx,
                                      width, height, channels, image_data_8bit.data(), stride);
            }
            break;
            
        case 1: // Test BMP core with various channel configurations
            {
                // BMP core handles different channel counts differently
                int bmp_channels = channels;
                if (channels == 1) bmp_channels = 3; // BMP expands monochrome to RGB
                
                stbi_write_bmp_to_func(write_callback, &write_ctx,
                                      width, height, bmp_channels, image_data_8bit.data());
            }
            break;
            
        case 2: // Test TGA core with and without RLE
            {
                // Save current RLE setting, test both
                int original_rle = stbi_write_tga_with_rle;
                
                // Test with RLE
                stbi_write_tga_with_rle = 1;
                stbi_write_tga_to_func(write_callback, &write_ctx,
                                      width, height, channels, image_data_8bit.data());
                
                // Test without RLE  
                stbi_write_tga_with_rle = 0;
                stbi_write_tga_to_func(write_callback, &write_ctx,
                                      width, height, channels, image_data_8bit.data());
                
                // Restore original
                stbi_write_tga_with_rle = original_rle;
            }
            break;
            
        case 3: // Test HDR core with float data
            {
                if (!image_data_float.empty()) {
                    stbi_write_hdr_to_func(write_callback, &write_ctx,
                                          width, height, channels, image_data_float.data());
                }
            }
            break;
            
        case 4: // Test JPEG core with various quality settings
            {
                // JPEG only supports 1, 3 channels
                int jpg_channels = (channels == 2 || channels == 4) ? 3 : channels;
                if (jpg_channels > 0 && jpg_channels <= 4) {
                    stbi_write_jpg_to_func(write_callback, &write_ctx,
                                          width, height, jpg_channels, image_data_8bit.data(), quality);
                }
            }
            break;
            
        case 5: // Test edge case: minimal dimensions (1x1)
            {
                int min_width = fdp.ConsumeBool() ? 1 : width;
                int min_height = fdp.ConsumeBool() ? 1 : height;
                if (min_width > 0 && min_height > 0) {
                    // Create minimal image
                    std::vector<uint8_t> min_image(min_width * min_height * channels, 128);
                    stbi_write_png_to_func(write_callback, &write_ctx,
                                          min_width, min_height, channels, min_image.data(), 
                                          min_width * channels);
                }
            }
            break;
            
        case 6: // Test edge case: large stride (may trigger different code paths)
            {
                int large_stride = width * channels + fdp.ConsumeIntegralInRange<int>(0, 100);
                stbi_write_png_to_func(write_callback, &write_ctx,
                                      width, height, channels, image_data_8bit.data(), large_stride);
            }
            break;
            
        case 7: // Test invalid/null data pointers (error paths in core functions)
            {
                // Test with null data - should fail gracefully in core functions
                if (fdp.ConsumeBool()) {
                    stbi_write_png_to_func(write_callback, &write_ctx,
                                          width, height, channels, nullptr, width * channels);
                }
            }
            break;
            
        case 8: // Test with zero or negative dimensions (error paths)
            {
                int test_width = fdp.ConsumeBool() ? 0 : width;
                int test_height = fdp.ConsumeBool() ? 0 : height;
                if (test_width > 0 && test_height > 0) {
                    stbi_write_bmp_to_func(write_callback, &write_ctx,
                                          test_width, test_height, channels, image_data_8bit.data());
                }
            }
            break;
            
        case 9: // Test monochrome (1 channel) specifically
            {
                if (channels != 1) {
                    // Create monochrome version
                    std::vector<uint8_t> mono_image(width * height);
                    for (size_t i = 0; i < mono_image.size(); i++) {
                        mono_image[i] = image_data_8bit[i * channels];
                    }
                    stbi_write_png_to_func(write_callback, &write_ctx,
                                          width, height, 1, mono_image.data(), width);
                }
            }
            break;
            
        case 10: // Test alpha channels (2 or 4 channels)
            {
                if (channels == 2 || channels == 4) {
                    // Already has alpha, test as-is
                    stbi_write_png_to_func(write_callback, &write_ctx,
                                          width, height, channels, image_data_8bit.data(), 
                                          width * channels);
                } else {
                    // Create version with alpha
                    std::vector<uint8_t> alpha_image(width * height * 4);
                    for (int i = 0; i < width * height; i++) {
                        for (int c = 0; c < 3; c++) {
                            alpha_image[i * 4 + c] = image_data_8bit[i * channels + (c % channels)];
                        }
                        alpha_image[i * 4 + 3] = 255; // Full opacity
                    }
                    stbi_write_png_to_func(write_callback, &write_ctx,
                                          width, height, 4, alpha_image.data(), width * 4);
                }
            }
            break;
            
        case 11: // Test HDR with extreme values (very small/very large)
            {
                if (!image_data_float.empty()) {
                    std::vector<float> extreme_data = image_data_float;
                    // Modify some values to be extreme
                    for (size_t i = 0; i < extreme_data.size(); i += 7) {
                        if (fdp.ConsumeBool()) {
                            extreme_data[i] = 0.0f; // Very small
                        } else {
                            extreme_data[i] = 1000.0f; // Very large
                        }
                    }
                    stbi_write_hdr_to_func(write_callback, &write_ctx,
                                          width, height, channels, extreme_data.data());
                }
            }
            break;
            
        case 12: // Test with flipped orientation
            {
                // Test flipped
                stbi_flip_vertically_on_write(1);
                stbi_write_png_to_func(write_callback, &write_ctx,
                                      width, height, channels, image_data_8bit.data(), 
                                      width * channels);
                
                // Test not flipped
                stbi_flip_vertically_on_write(0);
                stbi_write_png_to_func(write_callback, &write_ctx,
                                      width, height, channels, image_data_8bit.data(), 
                                      width * channels);
            }
            break;
        case 13: // Test compression level variations for PNG
            {
                int original_level = stbi_write_png_compression_level;
                
                // Test multiple compression levels
                for (int level : {0, 1, 4, 8, 9}) {
                    stbi_write_png_compression_level = level;
                    stbi_write_png_to_func(write_callback, &write_ctx,
                                          width, height, channels, image_data_8bit.data(), 
                                          width * channels);
                }
                
                stbi_write_png_compression_level = original_level;
            }
            break;
            
        case 14: // Test force PNG filter variations
            {
                int original_filter = stbi_write_force_png_filter;
                
                // Test all filter modes
                for (int filter = 0; filter <= 5; filter++) {
                    stbi_write_force_png_filter = filter;
                    stbi_write_png_to_func(write_callback, &write_ctx,
                                          width, height, channels, image_data_8bit.data(), 
                                          width * channels);
                }
                
                stbi_write_force_png_filter = original_filter;
            }
            break;
            
        case 15: // Comprehensive test: all formats sequentially
            {
                // Test all major formats in sequence
                stbi_write_png_to_func(write_callback, &write_ctx,
                                      width, height, channels, image_data_8bit.data(), 
                                      width * channels);
                
                stbi_write_bmp_to_func(write_callback, &write_ctx,
                                      width, height, channels, image_data_8bit.data());
                
                stbi_write_tga_to_func(write_callback, &write_ctx,
                                      width, height, channels, image_data_8bit.data());
                
                // JPEG only supports 1 or 3 channels
                int jpg_channels = (channels == 1 || channels == 3) ? channels : 3;
                stbi_write_jpg_to_func(write_callback, &write_ctx,
                                      width, height, jpg_channels, image_data_8bit.data(), 
                                      fdp.ConsumeIntegralInRange<int>(1, 100));
                
                if (!image_data_float.empty()) {
                    stbi_write_hdr_to_func(write_callback, &write_ctx,
                                          width, height, channels, image_data_float.data());
                }
            }
            break;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Need minimum input for meaningful testing
    if (size < 64) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Consume image parameters from fuzzer input
    int width = fdp.ConsumeIntegralInRange<int>(1, 256);
    int height = fdp.ConsumeIntegralInRange<int>(1, 256);
    int channels = fdp.ConsumeIntegralInRange<int>(1, 4);
    int pattern_type = fdp.ConsumeIntegralInRange<int>(0, 4);
    
    // Generate synthetic image data for testing
    std::vector<uint8_t> image_data_8bit = generate_8bit_image(width, height, channels, pattern_type);
    std::vector<float> image_data_float = generate_float_image(width, height, channels, pattern_type);
    
    // Test core function patterns with various edge cases
    test_core_function_patterns(fdp, width, height, channels, image_data_8bit, image_data_float);
    
    return 0;
}
