// Fuzzing harness for OpenCV Photo/Image Processing Module - Seamless Cloning APIs
// Targets high-level seamless cloning operations: cv::seamlessClone, cv::colorChange, 
// cv::illuminationChange, cv::textureFlattening
// Focuses on photo module which is virtually untouched (0% coverage for localColorChange 
// with 11338 undiscovered branches)
// Creates synthetic source/destination images and masks using cv::Mat
// Tests various cloning modes: NORMAL_CLONE, MIXED_CLONE, MONOCHROME_TRANSFER, and their WIDE variants
// Ensures semantic diversity from existing harnesses - while harness_006 targeted HAL mathematical
// operations, harness_007 targets high-level image processing with complex data flow

#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <cmath>
#include <limits>
#include <fuzzer/FuzzedDataProvider.h>
#include <opencv2/opencv.hpp>
#include <opencv2/photo.hpp>

// Helper function to create a synthetic image with random content
cv::Mat createSyntheticImage(FuzzedDataProvider& fdp, int width, int height, int type) {
    cv::Mat image(height, width, type);
    
    if (type == CV_8UC3) {
        // 3-channel 8-bit unsigned
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                cv::Vec3b& pixel = image.at<cv::Vec3b>(y, x);
                pixel[0] = fdp.ConsumeIntegral<uint8_t>();  // B
                pixel[1] = fdp.ConsumeIntegral<uint8_t>();  // G  
                pixel[2] = fdp.ConsumeIntegral<uint8_t>();  // R
            }
        }
    } else if (type == CV_8UC1) {
        // 1-channel 8-bit unsigned
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                image.at<uint8_t>(y, x) = fdp.ConsumeIntegral<uint8_t>();
            }
        }
    } else if (type == CV_32FC1) {
        // 1-channel 32-bit float
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                image.at<float>(y, x) = fdp.ConsumeFloatingPoint<float>();
            }
        }
    } else if (type == CV_32FC3) {
        // 3-channel 32-bit float
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                cv::Vec3f& pixel = image.at<cv::Vec3f>(y, x);
                pixel[0] = fdp.ConsumeFloatingPoint<float>();  // B
                pixel[1] = fdp.ConsumeFloatingPoint<float>();  // G
                pixel[2] = fdp.ConsumeFloatingPoint<float>();  // R
            }
        }
    }
    
    return image;
}

// Helper function to create a binary mask with random shape
cv::Mat createRandomMask(FuzzedDataProvider& fdp, int width, int height) {
    cv::Mat mask(height, width, CV_8UC1, cv::Scalar(0));
    
    // Determine mask type: rectangle, circle, ellipse, or random
    uint8_t mask_type = fdp.ConsumeIntegral<uint8_t>() % 4;
    
    switch (mask_type) {
        case 0: { // Rectangle mask
            int x1 = fdp.ConsumeIntegralInRange<int>(0, width - 1);
            int y1 = fdp.ConsumeIntegralInRange<int>(0, height - 1);
            int x2 = fdp.ConsumeIntegralInRange<int>(x1 + 1, width);
            int y2 = fdp.ConsumeIntegralInRange<int>(y1 + 1, height);
            cv::rectangle(mask, cv::Point(x1, y1), cv::Point(x2, y2), cv::Scalar(255), -1);
            break;
        }
        case 1: { // Circle mask
            int center_x = fdp.ConsumeIntegralInRange<int>(0, width - 1);
            int center_y = fdp.ConsumeIntegralInRange<int>(0, height - 1);
            int radius = fdp.ConsumeIntegralInRange<int>(1, std::min(width, height) / 2);
            cv::circle(mask, cv::Point(center_x, center_y), radius, cv::Scalar(255), -1);
            break;
        }
        case 2: { // Ellipse mask
            int center_x = fdp.ConsumeIntegralInRange<int>(0, width - 1);
            int center_y = fdp.ConsumeIntegralInRange<int>(0, height - 1);
            int axes_x = fdp.ConsumeIntegralInRange<int>(1, width / 2);
            int axes_y = fdp.ConsumeIntegralInRange<int>(1, height / 2);
            double angle = fdp.ConsumeFloatingPointInRange<double>(0.0, 360.0);
            cv::ellipse(mask, cv::Point(center_x, center_y), cv::Size(axes_x, axes_y), 
                       angle, 0.0, 360.0, cv::Scalar(255), -1);
            break;
        }
        case 3: { // Random pixel mask
            for (int y = 0; y < height; y++) {
                for (int x = 0; x < width; x++) {
                    if (fdp.ConsumeBool()) {
                        mask.at<uint8_t>(y, x) = 255;
                    }
                }
            }
            break;
        }
    }
    
    return mask;
}

// Helper function to test seamlessClone with different modes
void testSeamlessClone(FuzzedDataProvider& fdp, const cv::Mat& src, const cv::Mat& dst, const cv::Mat& mask) {
    if (src.empty() || dst.empty() || mask.empty()) {
        return;
    }
    
    // Ensure images have compatible sizes for cloning
    if (src.size() != mask.size()) {
        return;
    }
    
    // Choose cloning mode from fuzzer input
    int clone_mode = fdp.ConsumeIntegralInRange<int>(1, 11);
    
    // Filter to valid clone modes
    if (clone_mode != cv::NORMAL_CLONE && clone_mode != cv::MIXED_CLONE && 
        clone_mode != cv::MONOCHROME_TRANSFER && clone_mode != cv::NORMAL_CLONE_WIDE &&
        clone_mode != cv::MIXED_CLONE_WIDE && clone_mode != cv::MONOCHROME_TRANSFER_WIDE) {
        clone_mode = cv::NORMAL_CLONE;
    }
    
    // Choose target point in destination image
    cv::Point target_point;
    target_point.x = fdp.ConsumeIntegralInRange<int>(0, dst.cols - 1);
    target_point.y = fdp.ConsumeIntegralInRange<int>(0, dst.rows - 1);
    
    // Apply seamless cloning
    cv::Mat result;
    try {
        cv::seamlessClone(src, dst, mask, target_point, result, clone_mode);
    } catch (...) {
        // Ignore exceptions during fuzzing
    }
}

// Helper function to test colorChange with random parameters
void testColorChange(FuzzedDataProvider& fdp, const cv::Mat& src, const cv::Mat& mask) {
    if (src.empty() || mask.empty()) {
        return;
    }
    
    if (src.size() != mask.size()) {
        return;
    }
    
    // Generate random color multipliers in range 0.5 to 2.5
    float red_mul = fdp.ConsumeFloatingPointInRange<float>(0.5f, 2.5f);
    float green_mul = fdp.ConsumeFloatingPointInRange<float>(0.5f, 2.5f);
    float blue_mul = fdp.ConsumeFloatingPointInRange<float>(0.5f, 2.5f);
    
    // Apply color change
    cv::Mat result;
    try {
        cv::colorChange(src, mask, result, red_mul, green_mul, blue_mul);
    } catch (...) {
        // Ignore exceptions during fuzzing
    }
}

// Helper function to test illuminationChange with random parameters
void testIlluminationChange(FuzzedDataProvider& fdp, const cv::Mat& src, const cv::Mat& mask) {
    if (src.empty() || mask.empty()) {
        return;
    }
    
    if (src.size() != mask.size()) {
        return;
    }
    
    // Generate random alpha and beta in range 0.0 to 2.0
    float alpha = fdp.ConsumeFloatingPointInRange<float>(0.0f, 2.0f);
    float beta = fdp.ConsumeFloatingPointInRange<float>(0.0f, 2.0f);
    
    // Apply illumination change
    cv::Mat result;
    try {
        cv::illuminationChange(src, mask, result, alpha, beta);
    } catch (...) {
        // Ignore exceptions during fuzzing
    }
}

// Helper function to test textureFlattening with random parameters
void testTextureFlattening(FuzzedDataProvider& fdp, const cv::Mat& src, const cv::Mat& mask) {
    if (src.empty() || mask.empty()) {
        return;
    }
    
    if (src.size() != mask.size()) {
        return;
    }
    
    // Generate random thresholds and kernel size
    float low_threshold = fdp.ConsumeFloatingPointInRange<float>(0.0f, 100.0f);
    float high_threshold = fdp.ConsumeFloatingPointInRange<float>(100.0f, 255.0f);
    int kernel_size = fdp.ConsumeIntegralInRange<int>(1, 7);
    
    // Ensure kernel size is odd
    if (kernel_size % 2 == 0) {
        kernel_size++;
    }
    
    // Apply texture flattening
    cv::Mat result;
    try {
        cv::textureFlattening(src, mask, result, low_threshold, high_threshold, kernel_size);
    } catch (...) {
        // Ignore exceptions during fuzzing
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum input size check - need enough for image parameters and content
    if (size < 256) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    try {
        // Determine image dimensions from fuzzer input
        int width = fdp.ConsumeIntegralInRange<int>(16, 128);
        int height = fdp.ConsumeIntegralInRange<int>(16, 128);
        
        // Determine image type from fuzzer input
        int image_type_idx = fdp.ConsumeIntegral<uint8_t>() % 4;
        int image_type;
        switch (image_type_idx) {
            case 0: image_type = CV_8UC3; break;  // 3-channel 8-bit
            case 1: image_type = CV_8UC1; break;  // 1-channel 8-bit  
            case 2: image_type = CV_32FC1; break; // 1-channel 32-bit float
            case 3: image_type = CV_32FC3; break; // 3-channel 32-bit float
            default: image_type = CV_8UC3; break;
        }
        
        // Create source, destination images and mask
        cv::Mat src = createSyntheticImage(fdp, width, height, image_type);
        cv::Mat dst = createSyntheticImage(fdp, width, height, image_type);
        cv::Mat mask = createRandomMask(fdp, width, height);
        
        // Choose which photo processing API to test
        uint8_t api_choice = fdp.ConsumeIntegral<uint8_t>() % 5;
        
        switch (api_choice) {
            case 0:
                // Test seamlessClone
                testSeamlessClone(fdp, src, dst, mask);
                break;
            case 1:
                // Test colorChange (requires 8-bit 3-channel images)
                if (src.type() == CV_8UC3) {
                    testColorChange(fdp, src, mask);
                }
                break;
            case 2:
                // Test illuminationChange (requires 8-bit 3-channel images)
                if (src.type() == CV_8UC3) {
                    testIlluminationChange(fdp, src, mask);
                }
                break;
            case 3:
                // Test textureFlattening (requires 8-bit 3-channel images)
                if (src.type() == CV_8UC3) {
                    testTextureFlattening(fdp, src, mask);
                }
                break;
            case 4:
                // Test multiple APIs in sequence
                if (src.type() == CV_8UC3) {
                    testSeamlessClone(fdp, src, dst, mask);
                    testColorChange(fdp, src, mask);
                    testIlluminationChange(fdp, src, mask);
                    testTextureFlattening(fdp, src, mask);
                }
                break;
        }
        
    } catch (...) {
        // Catch any exceptions to prevent crashes during fuzzing
    }
    
    return 0;
}
