/*
 * libjpeg-turbo fuzzing harness for turbojpeg decompression APIs
 * Targets high-complexity turbojpeg decompression functions with 0% coverage:
 * - tjDecompress, tjDecompress2, tjDecompressToYUV, tjDecompressToYUV2, tjDecompressToYUVPlanes
 * Follows logical invocation sequence: tjInitDecompress -> tjDecompressHeader3 -> 
 * memory allocation -> core decompression -> cleanup
 * This harness complements harness_000.cpp by targeting modern turbojpeg API
 * instead of classic libjpeg API
 */

#include <fuzzer/FuzzedDataProvider.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

extern "C" {
#include "turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    
    // Need minimum data for meaningful testing (enough for JPEG header + small buffer)
    if (size < 64) return 0;
    
    // Consume parameters from fuzzer input
    int operation = fdp.ConsumeIntegralInRange<int>(0, 4);  // Which decompression API to test
    int flags = fdp.ConsumeIntegral<int>();  // Flags for decompression
    int pixel_format = fdp.ConsumeIntegralInRange<int>(0, 11);  // Pixel format (0-11 for TJPF enum)
    int subsamp = fdp.ConsumeIntegralInRange<int>(0, 5);  // Chrominance subsampling
    
    // Consume image dimensions (limited to reasonable sizes for fuzzing)
    int width = fdp.ConsumeIntegralInRange<int>(1, 256);
    int height = fdp.ConsumeIntegralInRange<int>(1, 256);
    int align = fdp.ConsumeIntegralInRange<int>(1, 16);  // Alignment for YUV buffers
    
    // Remaining bytes are JPEG data
    std::vector<uint8_t> jpeg_data = fdp.ConsumeRemainingBytes<uint8_t>();
    if (jpeg_data.size() < 2) return 0;  // Need at least something resembling JPEG
    
    // Initialize decompressor
    tjhandle handle = tjInitDecompress();
    if (!handle) {
        return 0;  // Failed to initialize
    }
    
    int ret = 0;
    int jpeg_width = 0, jpeg_height = 0, jpeg_subsamp = 0, jpeg_colorspace = 0;
    
    // Parse JPEG header to get actual dimensions
    ret = tjDecompressHeader3(handle, jpeg_data.data(), jpeg_data.size(),
                             &jpeg_width, &jpeg_height, &jpeg_subsamp, &jpeg_colorspace);
    
    if (ret != 0) {
        // Header parsing failed, try with simpler header functions
        ret = tjDecompressHeader2(handle, jpeg_data.data(), jpeg_data.size(),
                                 &jpeg_width, &jpeg_height, &jpeg_subsamp);
        
        if (ret != 0) {
            ret = tjDecompressHeader(handle, jpeg_data.data(), jpeg_data.size(),
                                    &jpeg_width, &jpeg_height);
        }
        
        if (ret != 0) {
            // Can't parse header, use fuzzer-provided dimensions
            jpeg_width = width;
            jpeg_height = height;
            jpeg_subsamp = subsamp;
        }
    }
    
    // Ensure dimensions are reasonable
    if (jpeg_width <= 0) jpeg_width = width;
    if (jpeg_height <= 0) jpeg_height = height;
    if (jpeg_width > 4096) jpeg_width = 4096;  // Limit for safety
    if (jpeg_height > 4096) jpeg_height = 4096;
    
    // Choose decompression operation based on fuzzer input
    switch (operation) {
        case 0: {  // tjDecompress (legacy API)
            int pixel_size = fdp.ConsumeIntegralInRange<int>(1, 4);  // 1-4 bytes per pixel
            unsigned long buf_size = jpeg_width * jpeg_height * pixel_size;
            unsigned char *dst_buf = (unsigned char *)tjAlloc(buf_size);
            if (dst_buf) {
                ret = tjDecompress(handle, jpeg_data.data(), jpeg_data.size(),
                                  dst_buf, jpeg_width, 0, jpeg_height, pixel_size, flags);
                tjFree(dst_buf);
            }
            break;
        }
        
        case 1: {  // tjDecompress2 (modern RGB decompression)
            // Calculate pitch (row stride)
            int pitch = jpeg_width * 3;  // Assume RGB (3 bytes per pixel)
            if (pixel_format == TJPF_GRAY) pitch = jpeg_width;
            else if (pixel_format == TJPF_RGBX || pixel_format == TJPF_BGRX ||
                     pixel_format == TJPF_XRGB || pixel_format == TJPF_XBGR ||
                     pixel_format == TJPF_RGBA || pixel_format == TJPF_BGRA ||
                     pixel_format == TJPF_ARGB || pixel_format == TJPF_ABGR) {
                pitch = jpeg_width * 4;
            } else if (pixel_format == TJPF_CMYK) {
                pitch = jpeg_width * 4;  // CMYK also uses 4 bytes
            }
            
            unsigned long buf_size = pitch * jpeg_height;
            unsigned char *dst_buf = (unsigned char *)tjAlloc(buf_size);
            if (dst_buf) {
                ret = tjDecompress2(handle, jpeg_data.data(), jpeg_data.size(),
                                   dst_buf, jpeg_width, pitch, jpeg_height,
                                   pixel_format, flags);
                tjFree(dst_buf);
            }
            break;
        }
        
        case 2: {  // tjDecompressToYUV (legacy YUV decompression)
            unsigned long yuv_buf_size = tjBufSizeYUV(jpeg_width, jpeg_height, jpeg_subsamp);
            unsigned char *yuv_buf = (unsigned char *)tjAlloc(yuv_buf_size);
            if (yuv_buf) {
                ret = tjDecompressToYUV(handle, jpeg_data.data(), jpeg_data.size(),
                                       yuv_buf, flags);
                tjFree(yuv_buf);
            }
            break;
        }
        
        case 3: {  // tjDecompressToYUV2 (modern YUV decompression)
            unsigned long yuv_buf_size = tjBufSizeYUV2(jpeg_width, align, jpeg_height, jpeg_subsamp);
            unsigned char *yuv_buf = (unsigned char *)tjAlloc(yuv_buf_size);
            if (yuv_buf) {
                ret = tjDecompressToYUV2(handle, jpeg_data.data(), jpeg_data.size(),
                                        yuv_buf, jpeg_width, align, jpeg_height, flags);
                tjFree(yuv_buf);
            }
            break;
        }
        
        case 4: {  // tjDecompressToYUVPlanes (planar YUV decompression)
            // For planar output, we need separate plane pointers
            unsigned char *planes[3] = {NULL, NULL, NULL};
            int strides[3] = {0, 0, 0};
            
            // Calculate plane widths and heights
            int plane_width = tjPlaneWidth(0, jpeg_width, jpeg_subsamp);
            int plane_height = tjPlaneHeight(0, jpeg_height, jpeg_subsamp);
            
            if (plane_width > 0 && plane_height > 0) {
                // Set reasonable strides
                strides[0] = plane_width;
                strides[1] = tjPlaneWidth(1, jpeg_width, jpeg_subsamp);
                strides[2] = tjPlaneWidth(2, jpeg_width, jpeg_subsamp);
                
                // Allocate planes
                unsigned long plane_size0 = tjPlaneSizeYUV(0, plane_width, strides[0], plane_height, jpeg_subsamp);
                unsigned long plane_size1 = tjPlaneSizeYUV(1, plane_width, strides[1], plane_height, jpeg_subsamp);
                unsigned long plane_size2 = tjPlaneSizeYUV(2, plane_width, strides[2], plane_height, jpeg_subsamp);
                
                planes[0] = (unsigned char *)tjAlloc(plane_size0);
                planes[1] = (unsigned char *)tjAlloc(plane_size1);
                planes[2] = (unsigned char *)tjAlloc(plane_size2);
                
                if (planes[0] && planes[1] && planes[2]) {
                    ret = tjDecompressToYUVPlanes(handle, jpeg_data.data(), jpeg_data.size(),
                                                 planes, jpeg_width, strides, jpeg_height, flags);
                }
                
                // Clean up planes
                if (planes[0]) tjFree(planes[0]);
                if (planes[1]) tjFree(planes[1]);
                if (planes[2]) tjFree(planes[2]);
            }
            break;
        }
    }
    
    // Clean up
    tjDestroy(handle);
    
    return 0;
}
