#include <opencv2/core.hpp>
#include <opencv2/imgproc.hpp>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include <cstdlib>
#include <climits>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 16) return 0;
    
    FuzzedDataProvider fdp(data, size);
    
    // Consume matrix dimensions with validation
    int rows = fdp.ConsumeIntegralInRange<int>(1, 100);
    int cols = fdp.ConsumeIntegralInRange<int>(1, 100);
    int channels = fdp.ConsumeIntegralInRange<int>(1, 4);
    
    // Check for memory allocation limits
    size_t required_bytes = rows * cols * channels;
    const size_t MAX_ALLOWED_BYTES = 10 * 1024 * 1024; // 10MB max
    if (required_bytes == 0 || required_bytes > MAX_ALLOWED_BYTES) {
        return 0;
    }
    
    // Check if we have enough input data
    if (fdp.remaining_bytes() < required_bytes) {
        return 0;
    }
    
    // Create matrix with consumed data
    cv::Mat mat(rows, cols, CV_8UC(channels));
    std::vector<uint8_t> mat_data = fdp.ConsumeBytes<uint8_t>(required_bytes);
    
    // Copy data to matrix
    size_t copy_len = std::min(mat_data.size(), mat.total() * mat.elemSize());
    if (copy_len > 0) {
        memcpy(mat.data, mat_data.data(), copy_len);
    }
    
    try {
        // Test various image processing operations (no image decoding)
        
        // 1. Convert to different format
        cv::Mat mat_float;
        mat.convertTo(mat_float, CV_32F);
        
        // 2. Compute mean and standard deviation
        cv::Scalar mean, stddev;
        cv::meanStdDev(mat, mean, stddev);
        
        // 3. Test thresholding with fuzzed threshold value
        int threshold_val = fdp.ConsumeIntegralInRange<int>(0, 255);
        cv::Mat thresholded;
        cv::threshold(mat, thresholded, threshold_val, 255, cv::THRESH_BINARY);
        
        // 4. Test morphological operations
        cv::Mat eroded, dilated;
        cv::erode(mat, eroded, cv::Mat());
        cv::dilate(mat, dilated, cv::Mat());
        
        // 5. Test blur with fuzzed kernel size
        int kernel_size = fdp.ConsumeIntegralInRange<int>(1, 7) * 2 + 1; // odd numbers
        cv::Mat blurred;
        cv::blur(mat, blurred, cv::Size(kernel_size, kernel_size));
        
        // 6. Test resize if we have enough remaining data
        if (fdp.remaining_bytes() > 4) {
            double scale = fdp.ConsumeFloatingPointInRange<double>(0.1, 3.0);
            cv::Mat resized;
            cv::resize(mat, resized, cv::Size(), scale, scale);
        }
        
        // 7. Test Gaussian blur
        if (fdp.remaining_bytes() > 4) {
            double sigma = fdp.ConsumeFloatingPointInRange<double>(0.1, 5.0);
            cv::Mat gaussian;
            cv::GaussianBlur(mat, gaussian, cv::Size(kernel_size, kernel_size), sigma);
        }
        
        // 8. Test Sobel edge detection
        if (fdp.remaining_bytes() > 4) {
            int dx = fdp.ConsumeIntegralInRange<int>(0, 2);
            int dy = fdp.ConsumeIntegralInRange<int>(0, 2);
            cv::Mat sobel;
            cv::Sobel(mat, sobel, CV_16S, dx, dy, 3);
        }
        
    } catch (const cv::Exception& e) {
        // Ignore OpenCV exceptions during fuzzing
    } catch (const std::exception& e) {
        // Ignore other exceptions during fuzzing
    }
    
    return 0;
}
