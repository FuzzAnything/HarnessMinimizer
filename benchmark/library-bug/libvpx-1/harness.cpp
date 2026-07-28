#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <memory>
#include <algorithm>

#include <fuzzer/FuzzedDataProvider.h>
#include "vpx_mem.h"
#include "vpx/vpx_image.h"


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 32) {
        return 0;  // Need enough data for basic parameters
    }

    FuzzedDataProvider fdp(data, size);

    // --- Memory allocation tests ---
    // Test vpx_memalign with a fuzzed alignment (power of two) and size
    // Alignment must be power of two and at least sizeof(void*).
    // We'll consume an alignment value from 1 to 256, then round up to next power of two.
    uint32_t align_raw = fdp.ConsumeIntegralInRange<uint32_t>(1, 256);
    // Round up to next power of two
    align_raw--;
    align_raw |= align_raw >> 1;
    align_raw |= align_raw >> 2;
    align_raw |= align_raw >> 4;
    align_raw |= align_raw >> 8;
    align_raw |= align_raw >> 16;
    align_raw++;
    // Ensure at least sizeof(void*)
    if (align_raw < sizeof(void*)) align_raw = sizeof(void*);
    size_t mem_size = fdp.ConsumeIntegralInRange<size_t>(1, 1024);
    
    void *mem = vpx_memalign(align_raw, mem_size);
    if (mem == nullptr) {
        // Allocation failed, skip further tests that depend on it
        return 0;
    }
    // Write some fuzzed data into the allocated memory
    if (mem_size > 0 && fdp.remaining_bytes() > 0) {
        size_t bytes_to_write = std::min(mem_size, fdp.remaining_bytes());
        std::vector<uint8_t> bytes = fdp.ConsumeBytes<uint8_t>(bytes_to_write);
        memcpy(mem, bytes.data(), bytes.size());
    }

    // Test vpx_malloc and vpx_calloc
    size_t malloc_size = fdp.ConsumeIntegralInRange<size_t>(1, 512);
    void *malloc_mem = vpx_malloc(malloc_size);
    if (malloc_mem != nullptr) {
        // Optionally fill with fuzzed data
        if (malloc_size > 0 && fdp.remaining_bytes() > 0) {
            size_t fill_size = std::min(malloc_size, fdp.remaining_bytes());
            std::vector<uint8_t> fill = fdp.ConsumeBytes<uint8_t>(fill_size);
            memcpy(malloc_mem, fill.data(), fill_size);
        }
    }

    size_t num = fdp.ConsumeIntegralInRange<size_t>(1, 100);
    size_t elem_size = fdp.ConsumeIntegralInRange<size_t>(1, 10);
    void *calloc_mem = vpx_calloc(num, elem_size);
    // calloc should zero-initialize, but we can still write fuzzed data
    if (calloc_mem != nullptr) {
        size_t total = num * elem_size;
        if (total > 0 && fdp.remaining_bytes() > 0) {
            size_t write_size = std::min(total, fdp.remaining_bytes());
            std::vector<uint8_t> write_data = fdp.ConsumeBytes<uint8_t>(write_size);
            memcpy(calloc_mem, write_data.data(), write_size);
        }
    }

    // --- Image utility tests ---
    // Consume image parameters
    unsigned int width = fdp.ConsumeIntegralInRange<unsigned int>(1, 1024);
    unsigned int height = fdp.ConsumeIntegralInRange<unsigned int>(1, 1024);
    // Choose a format from a subset of supported formats
    vpx_img_fmt_t fmt = VPX_IMG_FMT_I420;
    uint8_t fmt_choice = fdp.ConsumeIntegral<uint8_t>() % 4;
    switch (fmt_choice) {
        case 0: fmt = VPX_IMG_FMT_I420; break;
        case 1: fmt = VPX_IMG_FMT_I422; break;
        case 2: fmt = VPX_IMG_FMT_I444; break;
        case 3: fmt = VPX_IMG_FMT_YV12; break;
    }
    // Stride alignment (must be power of two, and <= 65536)
    unsigned int stride_align = 1;
    uint32_t stride_align_raw = fdp.ConsumeIntegralInRange<uint32_t>(1, 256);
    // Round to next power of two
    stride_align_raw--;
    stride_align_raw |= stride_align_raw >> 1;
    stride_align_raw |= stride_align_raw >> 2;
    stride_align_raw |= stride_align_raw >> 4;
    stride_align_raw |= stride_align_raw >> 8;
    stride_align_raw |= stride_align_raw >> 16;
    stride_align_raw++;
    stride_align = stride_align_raw;
    if (stride_align > 65536) stride_align = 65536;
    
    // Test vpx_img_alloc
    vpx_image_t *img_alloc = vpx_img_alloc(nullptr, fmt, width, height, stride_align);
    if (img_alloc != nullptr) {
        // We can optionally fill the image planes with fuzzed data
        // but the harness is about the utility functions, so we can skip.
        // However, we can call vpx_img_set_rect and vpx_img_flip on this image.
        // Consume rectangle parameters (within image bounds)
        unsigned int rect_x = fdp.ConsumeIntegralInRange<unsigned int>(0, width-1);
        unsigned int rect_y = fdp.ConsumeIntegralInRange<unsigned int>(0, height-1);
        unsigned int rect_w = fdp.ConsumeIntegralInRange<unsigned int>(1, width - rect_x);
        unsigned int rect_h = fdp.ConsumeIntegralInRange<unsigned int>(1, height - rect_y);
        
        int set_rect_ret = vpx_img_set_rect(img_alloc, rect_x, rect_y, rect_w, rect_h);
        (void)set_rect_ret;  // Ignore return value for fuzzing
        
        // Flip the image
        vpx_img_flip(img_alloc);
        
        // Free the image
        vpx_img_free(img_alloc);
    }
    
    // Test vpx_img_wrap
    // We need to allocate a buffer for the image data. We'll use vpx_memalign again.
    // Calculate the required buffer size approximately. We'll use a simplified calculation.
    // For simplicity, we'll allocate a buffer of size width * height * 4 (worst case for 32bpp).
    // But we can also use the same allocation as we did for vpx_img_alloc? Actually, vpx_img_wrap expects an already allocated buffer.
    // We'll allocate a buffer with vpx_memalign using the same stride_align.
    size_t buffer_size = width * height * 4;  // Overestimation
    if (buffer_size == 0) buffer_size = 1;
    void *img_buf = vpx_memalign(stride_align, buffer_size);
    if (img_buf != nullptr) {
        // Wrap the buffer
        vpx_image_t *img_wrap = vpx_img_wrap(nullptr, fmt, width, height, stride_align, (unsigned char *)img_buf);
        if (img_wrap != nullptr) {
            // Again, set rectangle and flip
            unsigned int rect_x2 = fdp.ConsumeIntegralInRange<unsigned int>(0, width-1);
            unsigned int rect_y2 = fdp.ConsumeIntegralInRange<unsigned int>(0, height-1);
            unsigned int rect_w2 = fdp.ConsumeIntegralInRange<unsigned int>(1, width - rect_x2);
            unsigned int rect_h2 = fdp.ConsumeIntegralInRange<unsigned int>(1, height - rect_y2);
            
            int set_rect_ret2 = vpx_img_set_rect(img_wrap, rect_x2, rect_y2, rect_w2, rect_h2);
            (void)set_rect_ret2;
            
            vpx_img_flip(img_wrap);
            
            // Note: vpx_img_free does not free the buffer, only the descriptor.
            vpx_img_free(img_wrap);
        }
        // Free the buffer we allocated for wrapping
        vpx_free(img_buf);
    }
    
    // Clean up memory allocations
    if (calloc_mem != nullptr) vpx_free(calloc_mem);
    if (malloc_mem != nullptr) vpx_free(malloc_mem);
    if (mem != nullptr) vpx_free(mem);
    
    return 0;
}

