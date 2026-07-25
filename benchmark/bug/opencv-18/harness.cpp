// OpenCV fuzzing harness targeting image warping and affine transformations
// Focuses on imgproc module warp functions which have low coverage (13.48% line coverage)
// APIs targeted: cv::warpAffine, cv::warpPerspective, cv::getAffineTransform, cv::getPerspectiveTransform
// Strategy: Create source/destination cv::Mat objects, generate transformation matrices, 
//           apply warp transformations with different interpolation methods, and test with
//           various image sizes, depths, and border types.
#include <cstddef>
#include <cstdint>
#include <vector>
#include <opencv4/opencv2/core.hpp>
#include <opencv4/opencv2/imgproc.hpp>
#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check: need enough data for image creation and transformation parameters
    if (size < 64) return 0;
    
    FuzzedDataProvider fdp(data, size);
    
    try {
        // ===== 1. Determine image parameters from fuzzer input =====
        int img_width = fdp.ConsumeIntegralInRange<int>(1, 256);
        int img_height = fdp.ConsumeIntegralInRange<int>(1, 256);
        
        // Determine image depth/type
        uint8_t depth_type = fdp.ConsumeIntegral<uint8_t>() % 6;
        int cv_type;
        switch (depth_type) {
            case 0: cv_type = CV_8U; break;
            case 1: cv_type = CV_8S; break;
            case 2: cv_type = CV_16U; break;
            case 3: cv_type = CV_16S; break;
            case 4: cv_type = CV_32F; break;
            case 5: cv_type = CV_64F; break;
            default: cv_type = CV_8U;
        }
        
        // Determine number of channels (1-4)
        int channels = fdp.ConsumeIntegralInRange<int>(1, 4);
        int full_type = CV_MAKETYPE(cv_type, channels);
        
        // ===== 2. Create source image with random data =====
        cv::Mat src(img_height, img_width, full_type);
        size_t src_data_size = img_width * img_height * channels * CV_ELEM_SIZE(cv_type);
        
        if (fdp.remaining_bytes() >= src_data_size) {
            // Fill image with random data from fuzzer input
            std::vector<uint8_t> src_data = fdp.ConsumeBytes<uint8_t>(src_data_size);
            if (src_data.size() == src_data_size) {
                memcpy(src.data, src_data.data(), src_data_size);
            }
        } else {
            // If not enough data, fill with zeros and continue with what we have
            src = cv::Scalar::all(0);
        }
        
        // ===== 3. Determine warp operation type =====
        uint8_t operation_type = fdp.ConsumeIntegral<uint8_t>() % 3;
        
        // ===== 4. Create transformation matrix =====
        cv::Mat transform_matrix;
        cv::Size dst_size;
        
        if (operation_type == 0 || operation_type == 1) {
            // Affine transformation (2x3 matrix)
            // Create source and destination triangles for getAffineTransform
            std::vector<cv::Point2f> src_tri(3), dst_tri(3);
            
            for (int i = 0; i < 3; ++i) {
                src_tri[i].x = fdp.ConsumeFloatingPointInRange<float>(0.0f, static_cast<float>(img_width));
                src_tri[i].y = fdp.ConsumeFloatingPointInRange<float>(0.0f, static_cast<float>(img_height));
                dst_tri[i].x = fdp.ConsumeFloatingPointInRange<float>(-100.0f, static_cast<float>(img_width + 100));
                dst_tri[i].y = fdp.ConsumeFloatingPointInRange<float>(-100.0f, static_cast<float>(img_height + 100));
            }
            
            transform_matrix = cv::getAffineTransform(src_tri, dst_tri);
            
            // Determine destination size
            int dst_width = fdp.ConsumeIntegralInRange<int>(1, 512);
            int dst_height = fdp.ConsumeIntegralInRange<int>(1, 512);
            dst_size = cv::Size(dst_width, dst_height);
        } else {
            // Perspective transformation (3x3 matrix)
            // Create source and destination quadrilaterals for getPerspectiveTransform
            std::vector<cv::Point2f> src_quad(4), dst_quad(4);
            
            for (int i = 0; i < 4; ++i) {
                src_quad[i].x = fdp.ConsumeFloatingPointInRange<float>(0.0f, static_cast<float>(img_width));
                src_quad[i].y = fdp.ConsumeFloatingPointInRange<float>(0.0f, static_cast<float>(img_height));
                dst_quad[i].x = fdp.ConsumeFloatingPointInRange<float>(-100.0f, static_cast<float>(img_width + 100));
                dst_quad[i].y = fdp.ConsumeFloatingPointInRange<float>(-100.0f, static_cast<float>(img_height + 100));
            }
            
            transform_matrix = cv::getPerspectiveTransform(src_quad, dst_quad);
            
            // Determine destination size
            int dst_width = fdp.ConsumeIntegralInRange<int>(1, 512);
            int dst_height = fdp.ConsumeIntegralInRange<int>(1, 512);
            dst_size = cv::Size(dst_width, dst_height);
        }
        
        // ===== 5. Determine interpolation method =====
        uint8_t interp_type = fdp.ConsumeIntegral<uint8_t>() % 6;
        int interpolation;
        switch (interp_type) {
            case 0: interpolation = cv::INTER_NEAREST; break;
            case 1: interpolation = cv::INTER_LINEAR; break;
            case 2: interpolation = cv::INTER_CUBIC; break;
            case 3: interpolation = cv::INTER_AREA; break;
            case 4: interpolation = cv::INTER_LANCZOS4; break;
            case 5: interpolation = cv::INTER_LINEAR_EXACT; break;
            default: interpolation = cv::INTER_LINEAR;
        }
        
        // ===== 6. Determine border type =====
        uint8_t border_type = fdp.ConsumeIntegral<uint8_t>() % 6;
        int border_mode;
        switch (border_type) {
            case 0: border_mode = cv::BORDER_CONSTANT; break;
            case 1: border_mode = cv::BORDER_REPLICATE; break;
            case 2: border_mode = cv::BORDER_REFLECT; break;
            case 3: border_mode = cv::BORDER_WRAP; break;
            case 4: border_mode = cv::BORDER_REFLECT_101; break;
            case 5: border_mode = cv::BORDER_TRANSPARENT; break;
            default: border_mode = cv::BORDER_CONSTANT;
        }
        
        // ===== 7. Create border value (for BORDER_CONSTANT) =====
        cv::Scalar border_value;
        if (channels == 1) {
            border_value = cv::Scalar(fdp.ConsumeIntegral<uint8_t>());
        } else if (channels == 2) {
            border_value = cv::Scalar(fdp.ConsumeIntegral<uint8_t>(), fdp.ConsumeIntegral<uint8_t>());
        } else if (channels == 3) {
            border_value = cv::Scalar(fdp.ConsumeIntegral<uint8_t>(), fdp.ConsumeIntegral<uint8_t>(), 
                                     fdp.ConsumeIntegral<uint8_t>());
        } else { // channels == 4
            border_value = cv::Scalar(fdp.ConsumeIntegral<uint8_t>(), fdp.ConsumeIntegral<uint8_t>(),
                                     fdp.ConsumeIntegral<uint8_t>(), fdp.ConsumeIntegral<uint8_t>());
        }
        
        // ===== 8. Apply warp transformation =====
        cv::Mat dst;
        
        if (operation_type == 0) {
            // Test warpAffine with standard flags
            cv::warpAffine(src, dst, transform_matrix, dst_size, interpolation, border_mode, border_value);
        } else if (operation_type == 1) {
            // Test warpAffine with inverse map flag
            cv::warpAffine(src, dst, transform_matrix, dst_size, 
                          interpolation | cv::WARP_INVERSE_MAP, border_mode, border_value);
        } else {
            // Test warpPerspective
            cv::warpPerspective(src, dst, transform_matrix, dst_size, interpolation, border_mode, border_value);
        }
        
        // ===== 9. Additional testing: Test with different combinations =====
        if (fdp.remaining_bytes() > 16) {
            // Test rotation matrix
            cv::Point2f center(fdp.ConsumeFloatingPointInRange<float>(0.0f, static_cast<float>(img_width)),
                              fdp.ConsumeFloatingPointInRange<float>(0.0f, static_cast<float>(img_height)));
            double angle = fdp.ConsumeFloatingPointInRange<double>(-180.0, 180.0);
            double scale = fdp.ConsumeFloatingPointInRange<double>(0.1, 3.0);
            
            cv::Mat rotation_matrix = cv::getRotationMatrix2D(center, angle, scale);
            cv::Mat dst2;
            cv::warpAffine(src, dst2, rotation_matrix, src.size(), interpolation, border_mode, border_value);
            
            // Test with identity matrix
            if (fdp.remaining_bytes() > 8) {
                cv::Mat identity = cv::Mat::eye(2, 3, CV_64F);
                cv::Mat dst3;
                cv::warpAffine(src, dst3, identity, src.size(), interpolation, border_mode, border_value);
            }
        }
        
    } catch (const cv::Exception& e) {
        // Silently catch OpenCV exceptions during fuzzing
        return 0;
    } catch (...) {
        // Catch any other exceptions
        return 0;
    }
    
    return 0;
}
