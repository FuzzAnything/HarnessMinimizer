#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include <opencv2/opencv.hpp>
#include <opencv2/imgproc.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check - need enough data for matrix dimensions, transformation matrices, and image data
    if (size < 128) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Consume fixed-size data for operation selection and parameters
    uint8_t operation = fdp.ConsumeIntegral<uint8_t>() % 3; // 0: warpAffine, 1: warpPerspective, 2: both
    int border_type = fdp.ConsumeIntegral<uint8_t>() % 6; // Select border type: 0-5 (BORDER_CONSTANT to BORDER_TRANSPARENT)
    int interpolation = fdp.ConsumeIntegral<uint8_t>() % 4; // Select interpolation method
    
    // Map border_type to OpenCV border types
    int cv_border_type;
    switch (border_type) {
        case 0: cv_border_type = cv::BORDER_CONSTANT; break;
        case 1: cv_border_type = cv::BORDER_REPLICATE; break;
        case 2: cv_border_type = cv::BORDER_REFLECT; break;
        case 3: cv_border_type = cv::BORDER_WRAP; break;
        case 4: cv_border_type = cv::BORDER_REFLECT_101; break;
        case 5: cv_border_type = cv::BORDER_TRANSPARENT; break;
        default: cv_border_type = cv::BORDER_CONSTANT; break;
    }
    
    // Map interpolation to OpenCV interpolation flags
    int cv_interpolation;
    switch (interpolation) {
        case 0: cv_interpolation = cv::INTER_NEAREST; break;
        case 1: cv_interpolation = cv::INTER_LINEAR; break;
        case 2: cv_interpolation = cv::INTER_CUBIC; break;
        case 3: cv_interpolation = cv::INTER_AREA; break;
        default: cv_interpolation = cv::INTER_LINEAR; break;
    }
    
    // Consume matrix dimensions (keep them reasonable for performance)
    int src_rows = fdp.ConsumeIntegralInRange<int>(10, 200);
    int src_cols = fdp.ConsumeIntegralInRange<int>(10, 200);
    int dst_rows = fdp.ConsumeIntegralInRange<int>(10, 200);
    int dst_cols = fdp.ConsumeIntegralInRange<int>(10, 200);
    
    // Select matrix data type
    int mat_type = fdp.ConsumeIntegral<uint8_t>() % 3; // 0: CV_8UC1, 1: CV_8UC3, 2: CV_32FC1
    int cv_mat_type;
    int channels;
    switch (mat_type) {
        case 0: cv_mat_type = CV_8UC1; channels = 1; break;
        case 1: cv_mat_type = CV_8UC3; channels = 3; break;
        case 2: cv_mat_type = CV_32FC1; channels = 1; break;
        default: cv_mat_type = CV_8UC1; channels = 1; break;
    }
    
    // Create source matrix with random data
    cv::Mat src(src_rows, src_cols, cv_mat_type);
    
    // Fill source matrix with random data from fuzzer
    size_t src_total_bytes = src_rows * src_cols * channels * ((cv_mat_type == CV_32FC1) ? sizeof(float) : sizeof(uint8_t));
    if (fdp.remaining_bytes() < src_total_bytes) {
        // Not enough data for source matrix
        return 0;
    }
    
    if (cv_mat_type == CV_32FC1) {
        // Fill with float data
        std::vector<uint8_t> src_data = fdp.ConsumeBytes<uint8_t>(src_total_bytes);
        memcpy(src.data, src_data.data(), src_total_bytes);
    } else {
        // Fill with uint8_t data
        std::vector<uint8_t> src_data = fdp.ConsumeBytes<uint8_t>(src_total_bytes);
        memcpy(src.data, src_data.data(), src_total_bytes);
    }
    
    // Create destination matrix
    cv::Mat dst(dst_rows, dst_cols, cv_mat_type);
    
    // Create border value for BORDER_CONSTANT
    cv::Scalar border_value;
    if (cv_border_type == cv::BORDER_CONSTANT) {
        // Consume border value components
        if (channels == 1) {
            if (cv_mat_type == CV_32FC1) {
                float val = fdp.ConsumeFloatingPoint<float>();
                border_value = cv::Scalar(val);
            } else {
                uint8_t val = fdp.ConsumeIntegral<uint8_t>();
                border_value = cv::Scalar(val);
            }
        } else if (channels == 3) {
            uint8_t b = fdp.ConsumeIntegral<uint8_t>();
            uint8_t g = fdp.ConsumeIntegral<uint8_t>();
            uint8_t r = fdp.ConsumeIntegral<uint8_t>();
            border_value = cv::Scalar(b, g, r);
        }
    }
    
    // Test warpAffine operation
    if (operation == 0 || operation == 2) {
        // Create 2x3 affine transformation matrix
        cv::Mat affine_mat(2, 3, CV_64FC1);
        
        // Fill affine matrix with random values
        size_t affine_bytes = 2 * 3 * sizeof(double);
        if (fdp.remaining_bytes() < affine_bytes) {
            // Not enough data for affine matrix
            return 0;
        }
        
        std::vector<uint8_t> affine_data = fdp.ConsumeBytes<uint8_t>(affine_bytes);
        memcpy(affine_mat.data, affine_data.data(), affine_bytes);
        
        try {
            // Apply affine transformation
            cv::warpAffine(src, dst, affine_mat, cv::Size(dst_cols, dst_rows),
                          cv_interpolation, cv_border_type, border_value);
            
            // The above operation internally calls borderInterpolate for out-of-bounds pixels
            // and may call cv::hal::warpAffineBlockline internally
        } catch (const cv::Exception& e) {
            // Ignore OpenCV exceptions during fuzzing
        } catch (...) {
            // Ignore any other exceptions
        }
    }
    
    // Test warpPerspective operation
    if (operation == 1 || operation == 2) {
        // Create 3x3 perspective transformation matrix
        cv::Mat perspective_mat(3, 3, CV_64FC1);
        
        // Fill perspective matrix with random values
        size_t perspective_bytes = 3 * 3 * sizeof(double);
        if (fdp.remaining_bytes() < perspective_bytes) {
            // Not enough data for perspective matrix
            return 0;
        }
        
        std::vector<uint8_t> perspective_data = fdp.ConsumeBytes<uint8_t>(perspective_bytes);
        memcpy(perspective_mat.data, perspective_data.data(), perspective_bytes);
        
        try {
            // Apply perspective transformation
            cv::warpPerspective(src, dst, perspective_mat, cv::Size(dst_cols, dst_rows),
                               cv_interpolation, cv_border_type, border_value);
            
            // The above operation internally calls borderInterpolate for out-of-bounds pixels
            // and may call cv::hal::warpPerspectiveBlockline internally
        } catch (const cv::Exception& e) {
            // Ignore OpenCV exceptions during fuzzing
        } catch (...) {
            // Ignore any other exceptions
        }
    }
    
    // Additionally, test borderInterpolate directly with random parameters
    if (fdp.remaining_bytes() >= 3 * sizeof(int)) {
        int p = fdp.ConsumeIntegral<int>();
        int len = fdp.ConsumeIntegralInRange<int>(1, 1000);
        int direct_border_type = fdp.ConsumeIntegral<uint8_t>() % 6;
        
        // Map to OpenCV border type
        int cv_direct_border_type;
        switch (direct_border_type) {
            case 0: cv_direct_border_type = cv::BORDER_CONSTANT; break;
            case 1: cv_direct_border_type = cv::BORDER_REPLICATE; break;
            case 2: cv_direct_border_type = cv::BORDER_REFLECT; break;
            case 3: cv_direct_border_type = cv::BORDER_WRAP; break;
            case 4: cv_direct_border_type = cv::BORDER_REFLECT_101; break;
            case 5: cv_direct_border_type = cv::BORDER_TRANSPARENT; break;
            default: cv_direct_border_type = cv::BORDER_CONSTANT; break;
        }
        
        // Directly call borderInterpolate (if accessible)
        // Note: borderInterpolate is in cv namespace but might not be publicly exposed
        // The warp operations above will call it internally
        
        // Test with getRectSubPix which also uses border handling
        if (fdp.remaining_bytes() >= 2 * sizeof(float)) {
            float center_x = fdp.ConsumeFloatingPoint<float>();
            float center_y = fdp.ConsumeFloatingPoint<float>();
            
            try {
                cv::Mat patch;
                cv::getRectSubPix(src, cv::Size(50, 50), 
                                 cv::Point2f(center_x, center_y), patch,
                                 cv_direct_border_type);
            } catch (const cv::Exception& e) {
                // Ignore OpenCV exceptions
            } catch (...) {
                // Ignore any other exceptions
            }
        }
    }
    
    return 0;
}
