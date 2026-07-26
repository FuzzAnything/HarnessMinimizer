/*
 * Copyright (c) 2024, FuzzAgent Project. All rights reserved.
 *
 * Fuzzing harness for libaom AV1 decoder memory management and stream analysis.
 * This harness targets severely under-covered decoder APIs with custom memory management:
 *   - aom_codec_set_frame_buffer_functions (7/14 branches undiscovered)
 *   - aom_codec_get_stream_info (5/10 branches undiscovered)
 *   - aom_codec_peek_stream_info (4/8 branches undiscovered)
 *   - aom_codec_get_frame (4/8 branches undiscovered)
 * 
 * Semantic differentiation from existing harnesses:
 *   - FAST corner detection (010,011): image feature extraction
 *   - Encoder configuration validation (012): parameter validation  
 *   - This harness: decoder memory management & stream analysis
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <vector>
#include <algorithm>
#include <cstring>

#include "fuzzer/FuzzedDataProvider.h"
#include "aom/aom_decoder.h"
#include "aom/aomdx.h"
#include "aom/aom_frame_buffer.h"
#include "aom/aom_image.h"

// Minimum input size required to start fuzzing
#define MIN_INPUT_SIZE 256

// Maximum number of frame buffers to manage
#define MAX_FRAME_BUFFERS 8

// Custom frame buffer management structure
typedef struct {
    uint8_t* data;
    size_t size;
    bool in_use;
    size_t alloc_id;
} CustomFrameBuffer;

// Global frame buffer pool for custom memory management
static CustomFrameBuffer frame_buffer_pool[MAX_FRAME_BUFFERS];
static size_t next_buffer_id = 0;
static size_t total_allocations = 0;
static size_t total_releases = 0;

// Custom get_frame_buffer callback with various allocation strategies
static int custom_get_frame_buffer_cb(void *priv, size_t min_size,
                                     aom_codec_frame_buffer_t *fb) {
    if (!fb) {
        return -1;
    }
    
    // Determine allocation strategy based on private data
    int strategy = priv ? *(static_cast<int*>(priv)) : 0;
    
    // Find an available buffer or allocate a new one
    CustomFrameBuffer* target = nullptr;
    size_t buffer_index = 0;
    
    switch (strategy % 4) {
        case 0:  // First-fit strategy
            for (size_t i = 0; i < MAX_FRAME_BUFFERS; ++i) {
                if (!frame_buffer_pool[i].in_use || 
                    (frame_buffer_pool[i].in_use && frame_buffer_pool[i].size >= min_size)) {
                    target = &frame_buffer_pool[i];
                    buffer_index = i;
                    break;
                }
            }
            break;
            
        case 1:  // Best-fit strategy (smallest sufficient buffer)
            for (size_t i = 0; i < MAX_FRAME_BUFFERS; ++i) {
                if (!frame_buffer_pool[i].in_use || 
                    (frame_buffer_pool[i].in_use && frame_buffer_pool[i].size >= min_size)) {
                    if (!target || frame_buffer_pool[i].size < target->size) {
                        target = &frame_buffer_pool[i];
                        buffer_index = i;
                    }
                }
            }
            break;
            
        case 2:  // Round-robin allocation
            buffer_index = next_buffer_id % MAX_FRAME_BUFFERS;
            target = &frame_buffer_pool[buffer_index];
            next_buffer_id++;
            break;
            
        case 3:  // Always allocate new buffer
            for (size_t i = 0; i < MAX_FRAME_BUFFERS; ++i) {
                if (!frame_buffer_pool[i].in_use) {
                    target = &frame_buffer_pool[i];
                    buffer_index = i;
                    break;
                }
            }
            break;
    }
    
    if (!target) {
        // No available buffer found
        return -1;
    }
    
    // Release existing buffer if in use
    if (target->in_use && target->data) {
        free(target->data);
        target->data = nullptr;
        target->size = 0;
    }
    
    // Allocate new buffer with zero-initialization
    target->data = static_cast<uint8_t*>(calloc(1, min_size));
    if (!target->data) {
        return -1;
    }
    
    target->size = min_size;
    target->in_use = true;
    target->alloc_id = total_allocations++;
    
    // Set the frame buffer structure for libaom
    fb->data = target->data;
    fb->size = target->size;
    fb->priv = reinterpret_cast<void*>(buffer_index);  // Store buffer index as private data
    
    return 0;
}

// Custom release_frame_buffer callback with various release strategies
static int custom_release_frame_buffer_cb(void *priv, aom_codec_frame_buffer_t *fb) {
    if (!fb || !fb->data) {
        return 0;  // Nothing to release
    }
    
    // Get buffer index from private data
    size_t buffer_index = reinterpret_cast<size_t>(fb->priv);
    if (buffer_index >= MAX_FRAME_BUFFERS) {
        return -1;  // Invalid buffer index
    }
    
    CustomFrameBuffer* target = &frame_buffer_pool[buffer_index];
    
    // Verify this is the correct buffer
    if (target->data != fb->data || target->size != fb->size) {
        return -1;  // Buffer mismatch
    }
    
    // Determine release strategy based on private data
    int strategy = priv ? *(static_cast<int*>(priv)) : 0;
    
    switch (strategy % 3) {
        case 0:  // Immediate release
            free(target->data);
            target->data = nullptr;
            target->size = 0;
            target->in_use = false;
            break;
            
        case 1:  // Keep buffer but mark as unused (pooling)
            target->in_use = false;
            break;
            
        case 2:  // Reallocate with different size (stress test)
            {
                size_t new_size = target->size + 1024;  // Different size
                uint8_t* new_data = static_cast<uint8_t*>(realloc(target->data, new_size));
                if (new_data) {
                    target->data = new_data;
                    target->size = new_size;
                    // Don't mark as unused since we're keeping it
                } else {
                    free(target->data);
                    target->data = nullptr;
                    target->size = 0;
                    target->in_use = false;
                }
            }
            break;
    }
    
    fb->data = nullptr;
    fb->size = 0;
    fb->priv = nullptr;
    
    total_releases++;
    
    return 0;
}

// Helper to initialize frame buffer pool
static void init_frame_buffer_pool() {
    for (size_t i = 0; i < MAX_FRAME_BUFFERS; ++i) {
        frame_buffer_pool[i].data = nullptr;
        frame_buffer_pool[i].size = 0;
        frame_buffer_pool[i].in_use = false;
        frame_buffer_pool[i].alloc_id = 0;
    }
    next_buffer_id = 0;
    total_allocations = 0;
    total_releases = 0;
}

// Test various stream info scenarios
static void test_stream_info_apis(aom_codec_ctx_t* codec, 
                                 aom_codec_iface_t* iface,
                                 FuzzedDataProvider& fdp,
                                 const uint8_t* data, 
                                 size_t data_size) {
    aom_codec_stream_info_t stream_info;
    
    // Test 1: aom_codec_peek_stream_info (non-destructive stream inspection)
    // Initialize with fuzzed values
    stream_info.w = fdp.ConsumeIntegralInRange<unsigned int>(0, 8192);
    stream_info.h = fdp.ConsumeIntegralInRange<unsigned int>(0, 8192);
    stream_info.is_kf = fdp.ConsumeBool();
    stream_info.number_spatial_layers = fdp.ConsumeIntegralInRange<unsigned int>(0, 8);
    stream_info.number_temporal_layers = fdp.ConsumeIntegralInRange<unsigned int>(0, 8);
    stream_info.is_annexb = fdp.ConsumeBool();
    
    // Try to peek stream info from the data
    // This may fail, which is okay - we're testing error paths too
    aom_codec_peek_stream_info(iface, data, data_size, &stream_info);
    
    // Test 2: aom_codec_get_stream_info (requires active decoder context)
    // Reset stream info with different fuzzed values
    stream_info.w = fdp.ConsumeIntegralInRange<unsigned int>(0, 8192);
    stream_info.h = fdp.ConsumeIntegralInRange<unsigned int>(0, 8192);
    stream_info.is_kf = fdp.ConsumeBool();
    stream_info.number_spatial_layers = fdp.ConsumeIntegralInRange<unsigned int>(0, 8);
    stream_info.number_temporal_layers = fdp.ConsumeIntegralInRange<unsigned int>(0, 8);
    stream_info.is_annexb = fdp.ConsumeBool();
    
    // Try to get stream info from decoder context
    // This will only work after successful decode operations
    aom_codec_get_stream_info(codec, &stream_info);
}

// Test frame retrieval with various iteration strategies
static void test_frame_retrieval(aom_codec_ctx_t* codec, FuzzedDataProvider& fdp) {
    aom_codec_iter_t iter = nullptr;
    int max_frames_to_retrieve = fdp.ConsumeIntegralInRange<int>(0, 10);
    int frames_retrieved = 0;
    
    // Test different iteration strategies
    int strategy = fdp.ConsumeIntegralInRange<int>(0, 3);
    
    switch (strategy) {
        case 0:  // Normal iteration until nullptr
            while (frames_retrieved < max_frames_to_retrieve) {
                aom_image_t* img = aom_codec_get_frame(codec, &iter);
                if (!img) {
                    break;
                }
                frames_retrieved++;
                
                // Test getting frame multiple times with same iterator
                if (fdp.ConsumeBool() && frames_retrieved < max_frames_to_retrieve) {
                    aom_image_t* img2 = aom_codec_get_frame(codec, &iter);
                    if (img2) {
                        frames_retrieved++;
                    }
                }
            }
            break;
            
        case 1:  // Reset iterator and start over
            iter = nullptr;
            for (int i = 0; i < 2 && frames_retrieved < max_frames_to_retrieve; ++i) {
                aom_image_t* img = aom_codec_get_frame(codec, &iter);
                if (img) {
                    frames_retrieved++;
                }
                // Reset and try again
                if (i == 0 && fdp.ConsumeBool()) {
                    iter = nullptr;
                }
            }
            break;
            
        case 2:  // Mixed valid and invalid iterator usage
            {
                aom_codec_iter_t invalid_iter;
                // Try with uninitialized iterator
                aom_image_t* img = aom_codec_get_frame(codec, &invalid_iter);
                if (img) {
                    frames_retrieved++;
                }
                
                // Now try with proper iterator
                iter = nullptr;
                img = aom_codec_get_frame(codec, &iter);
                if (img) {
                    frames_retrieved++;
                }
            }
            break;
            
        case 3:  // Test after decode failure
            // Just test with nullptr iterator
            iter = nullptr;
            aom_image_t* img = aom_codec_get_frame(codec, &iter);
            if (img) {
                frames_retrieved++;
            }
            break;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Require minimum input size for meaningful testing
    if (size < MIN_INPUT_SIZE) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);
    
    // Initialize frame buffer pool
    init_frame_buffer_pool();
    
    // Initialize decoder interface
    aom_codec_iface_t *codec_interface = aom_codec_av1_dx();
    if (!codec_interface) {
        return 0;
    }

    // Consume decoder configuration with safe limits
    unsigned int threads = fdp.ConsumeIntegralInRange<unsigned int>(1, 4);
    unsigned int width = fdp.ConsumeIntegralInRange<unsigned int>(16, 256);
    unsigned int height = fdp.ConsumeIntegralInRange<unsigned int>(16, 256);
    
    // Limit dimensions to prevent excessive memory usage
    if (width * height > 65536) {  // Limit to 256x256
        width = 256;
        height = 256;
    }
    
    unsigned int allow_lowbitdepth = fdp.ConsumeBool();
    
    aom_codec_dec_cfg_t cfg = { threads, width, height, allow_lowbitdepth };
    aom_codec_ctx_t codec;

    // Initialize decoder with ABI version
    aom_codec_err_t init_result = aom_codec_dec_init_ver(&codec, codec_interface, 
                                                        &cfg, 0, AOM_DECODER_ABI_VERSION);
    if (init_result != AOM_CODEC_OK) {
        // If initialization fails, we can still test some APIs
        // Test peek_stream_info without active decoder
        if (size >= sizeof(aom_codec_stream_info_t)) {
            aom_codec_stream_info_t si;
            memset(&si, 0, sizeof(si));
            si.is_annexb = fdp.ConsumeBool();
            aom_codec_peek_stream_info(codec_interface, data, 
                                      std::min(size, static_cast<size_t>(1024)), &si);
        }
        return 0;
    }

    // Determine memory management strategy
    int mem_strategy = fdp.ConsumeIntegralInRange<int>(0, 7);
    
    // Set custom frame buffer functions with our strategy
    aom_codec_err_t fb_result = aom_codec_set_frame_buffer_functions(
        &codec, 
        custom_get_frame_buffer_cb,
        custom_release_frame_buffer_cb,
        &mem_strategy);
    
    // Test stream information APIs before decoding
    if (fdp.remaining_bytes() > 64) {
        size_t test_data_size = fdp.ConsumeIntegralInRange<size_t>(1, 
            std::min(static_cast<size_t>(1024), fdp.remaining_bytes()));
        std::vector<uint8_t> test_data = fdp.ConsumeBytes<uint8_t>(test_data_size);
        
        test_stream_info_apis(&codec, codec_interface, fdp, 
                             test_data.data(), test_data.size());
    }
    
    // Decode operations with custom memory management
    const size_t MAX_DECODE_CHUNKS = 3;
    size_t decode_count = 0;
    
    while (fdp.remaining_bytes() > 64 && decode_count < MAX_DECODE_CHUNKS) {
        // Determine chunk size for this decode operation
        size_t chunk_size = fdp.ConsumeIntegralInRange<size_t>(
            1, std::min(static_cast<size_t>(8192), fdp.remaining_bytes()));
        
        std::vector<uint8_t> chunk = fdp.ConsumeBytes<uint8_t>(chunk_size);
        
        // Test peek_stream_info on this chunk
        aom_codec_stream_info_t peek_si;
        memset(&peek_si, 0, sizeof(peek_si));
        peek_si.is_annexb = fdp.ConsumeBool();
        aom_codec_peek_stream_info(codec_interface, chunk.data(), 
                                  chunk.size(), &peek_si);
        
        // Perform decode operation
        aom_codec_err_t decode_result = aom_codec_decode(&codec, chunk.data(), 
                                                        chunk.size(), nullptr);
        
        // Test get_stream_info after decode (regardless of decode result)
        aom_codec_stream_info_t get_si;
        memset(&get_si, 0, sizeof(get_si));
        get_si.is_annexb = fdp.ConsumeBool();
        aom_codec_get_stream_info(&codec, &get_si);
        
        // Test frame retrieval if decode was successful
        if (decode_result == AOM_CODEC_OK) {
            test_frame_retrieval(&codec, fdp);
        }
        
        decode_count++;
    }
    
    // Additional stream info tests with various invalid parameters
    if (fdp.remaining_bytes() > 32) {
        // Test with NULL pointers (should trigger error paths)
        aom_codec_stream_info_t si;
        memset(&si, 0, sizeof(si));
        si.is_annexb = fdp.ConsumeBool();
        
        // Test edge cases
        size_t remaining = fdp.remaining_bytes();
        if (remaining > 0) {
            size_t edge_size = fdp.ConsumeIntegralInRange<size_t>(0, 
                std::min(static_cast<size_t>(16), remaining));
            std::vector<uint8_t> edge_data = fdp.ConsumeBytes<uint8_t>(edge_size);
            
            if (edge_size > 0) {
                // Test with very small data
                aom_codec_peek_stream_info(codec_interface, edge_data.data(), 
                                          edge_size, &si);
                                          
                // Test get_stream_info with decoder
                aom_codec_get_stream_info(&codec, &si);
            } else {
                // Test with zero-sized data
                aom_codec_peek_stream_info(codec_interface, nullptr, 0, &si);
            }
        }
    }
    
    // Cleanup decoder
    aom_codec_destroy(&codec);
    
    // Clean up any remaining frame buffers
    for (size_t i = 0; i < MAX_FRAME_BUFFERS; ++i) {
        if (frame_buffer_pool[i].data) {
            free(frame_buffer_pool[i].data);
            frame_buffer_pool[i].data = nullptr;
            frame_buffer_pool[i].size = 0;
            frame_buffer_pool[i].in_use = false;
        }
    }
    
    return 0;
}
