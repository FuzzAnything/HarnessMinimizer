#include <opencv2/core.hpp>
#include <opencv2/imgproc.hpp>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include <cstdlib>
#include <climits>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 16) return 0; // Minimum size for meaningful testing
    
    FuzzedDataProvider fdp(data, size);
    
    // Consume matrix dimensions and type with validation
    unsigned int rows = fdp.ConsumeIntegralInRange<unsigned int>(1, 100);
    unsigned int cols = fdp.ConsumeIntegralInRange<unsigned int>(1, 100);
    int raw_mat_type = fdp.ConsumeIntegral<int>();
    
    // SAFE FIX: Avoid std::abs overflow for INT_MIN
    unsigned int channels;
    if (raw_mat_type == INT_MIN) {
        channels = 1; // Default to 1 channel for INT_MIN
    } else {
        channels = (static_cast<unsigned int>(std::abs(raw_mat_type)) % 8) + 1; // 1-8 channels
    }
    
    // Check for multiplication overflow before allocating memory
    if (rows == 0 || cols == 0 || channels == 0) return 0;
    
    // Safe multiplication with overflow checking
    size_t required_bytes;
    if (__builtin_mul_overflow(rows, cols, &required_bytes)) return 0;
    if (__builtin_mul_overflow(required_bytes, channels, &required_bytes)) return 0;
    
    // Additional safety: limit maximum allocation to prevent excessive memory usage
    const size_t MAX_ALLOWED_BYTES = 10 * 1024 * 1024; // 10MB max
    if (required_bytes > MAX_ALLOWED_BYTES) {
        return 0;
    }
    
    // Check if we have enough input data before consuming
    if (fdp.remaining_bytes() < required_bytes) {
        return 0; // Not enough input data
    }
    
    // Allocate matrix data with exception handling
    std::vector<uint8_t> mat_data;
    try {
        mat_data = fdp.ConsumeBytes<uint8_t>(required_bytes);
    } catch (const std::bad_alloc& e) {
        return 0; // Memory allocation failed
    }
    
    // CRITICAL FIX: Verify we actually got the requested number of bytes
    if (mat_data.size() != required_bytes) {
        return 0; // Insufficient data consumed
    }
    
    try {
        // Create matrix from consumed data
        cv::Mat mat(rows, cols, CV_8UC(channels), mat_data.data());
        
        if (mat.empty()) return 0;
        
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
        
        // 6. Test resize
        cv::Mat resized;
        double scale = fdp.ConsumeFloatingPointInRange<double>(0.1, 3.0);
        cv::resize(mat, resized, cv::Size(), scale, scale);
        
        // 7. Test edge detection (Canny)
        cv::Mat edges;
        double threshold1 = fdp.ConsumeFloatingPointInRange<double>(10.0, 100.0);
        double threshold2 = fdp.ConsumeFloatingPointInRange<double>(30.0, 200.0);
        cv::Canny(mat, edges, threshold1, threshold2);
        
        // 8. Test color conversion if applicable
        if (mat.channels() == 3) {
            cv::Mat gray;
            cv::cvtColor(mat, gray, cv::COLOR_BGR2GRAY);
        }
        
    } catch (const cv::Exception& e) {
        // Ignore OpenCV exceptions during fuzzing
    } catch (...) {
        // Ignore all other exceptions
    }
    
    return 0;
}
