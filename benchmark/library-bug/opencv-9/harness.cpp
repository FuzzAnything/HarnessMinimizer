// OpenCV comprehensive fuzzing harness
// Targets fundamental image processing and matrix operations
// harness_000.cpp

#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include <opencv2/opencv.hpp>
#include <opencv2/imgcodecs.hpp>
#include <opencv2/imgproc.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check - need enough data for basic operations
    if (size < 16) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    try {
        // Part 1: Image decoding from raw bytes
        // Consume a portion of input for image data
        size_t image_data_size = fdp.ConsumeIntegralInRange<size_t>(1, std::min(size/2, size_t(4096)));
        std::vector<uint8_t> image_data = fdp.ConsumeBytes<uint8_t>(image_data_size);
        
        if (!image_data.empty()) {
            // Try to decode image from raw bytes
            cv::Mat decoded_image = cv::imdecode(image_data, cv::IMREAD_UNCHANGED);
            
            if (!decoded_image.empty()) {
                // Part 2: Basic image processing operations
                
                // Get some parameters from fuzzer input
                int operation = fdp.ConsumeIntegralInRange<int>(0, 4);
                int width = fdp.ConsumeIntegralInRange<int>(1, 512);
                int height = fdp.ConsumeIntegralInRange<int>(1, 512);
                
                cv::Mat processed_image;
                
                switch (operation % 5) {
                    case 0:
                        // Resize operation
                        cv::resize(decoded_image, processed_image, cv::Size(width, height));
                        break;
                    case 1:
                        // Convert color space (if applicable)
                        if (decoded_image.channels() == 3) {
                            cv::cvtColor(decoded_image, processed_image, cv::COLOR_BGR2GRAY);
                        } else if (decoded_image.channels() == 1) {
                            cv::cvtColor(decoded_image, processed_image, cv::COLOR_GRAY2BGR);
                        }
                        break;
                    case 2:
                        // Gaussian blur
                        cv::GaussianBlur(decoded_image, processed_image, cv::Size(3, 3), 0);
                        break;
                    case 3:
                        // Threshold operation (for grayscale images)
                        if (decoded_image.channels() == 1) {
                            double thresh = fdp.ConsumeFloatingPointInRange<double>(0, 255);
                            cv::threshold(decoded_image, processed_image, thresh, 255, cv::THRESH_BINARY);
                        }
                        break;
                    case 4:
                        // Matrix operations - basic arithmetic
                        double scale = fdp.ConsumeFloatingPointInRange<double>(0.1, 3.0);
                        decoded_image.convertTo(processed_image, -1, scale, 0);
                        break;
                }
                
                // Part 3: Try image encoding if we have processed image
                if (!processed_image.empty()) {
                    std::vector<uint8_t> encoded_buffer;
                    int encode_format = fdp.ConsumeIntegralInRange<int>(0, 2);
                    
                    const char* ext = "";
                    switch (encode_format) {
                        case 0: ext = ".jpg"; break;
                        case 1: ext = ".png"; break;
                        case 2: ext = ".bmp"; break;
                    }
                    
                    cv::imencode(ext, processed_image, encoded_buffer);
                }
            }
        }
        
        // Part 4: Test matrix operations on synthetic data
        // Use remaining input to create and manipulate matrices
        if (fdp.remaining_bytes() >= 12) {
            int rows = fdp.ConsumeIntegralInRange<int>(1, 50);
            int cols = fdp.ConsumeIntegralInRange<int>(1, 50);
            int type = fdp.ConsumeIntegralInRange<int>(0, 2);
            
            int mat_type;
            switch (type % 3) {
                case 0: mat_type = CV_8UC1; break;
                case 1: mat_type = CV_32FC1; break;
                case 2: mat_type = CV_64FC1; break;
            }
            
            // Create matrix with random data from remaining input
            size_t matrix_data_size = rows * cols * CV_ELEM_SIZE(mat_type);
            if (fdp.remaining_bytes() >= matrix_data_size) {
                std::vector<uint8_t> matrix_data = fdp.ConsumeBytes<uint8_t>(matrix_data_size);
                
                if (!matrix_data.empty()) {
                    cv::Mat test_mat(rows, cols, mat_type, matrix_data.data());
                    
                    // Test basic matrix operations
                    if (!test_mat.empty()) {
                        cv::Mat transposed = test_mat.t();
                        cv::Scalar mean = cv::mean(test_mat);
                        cv::Scalar sum = cv::sum(test_mat);
                        
                        // Test matrix multiplication with itself (if square)
                        if (rows == cols) {
                            cv::Mat squared;
                            cv::multiply(test_mat, test_mat, squared);
                        }
                    }
                }
            }
        }
        
    } catch (const cv::Exception& e) {
        // Ignore OpenCV exceptions - they're expected during fuzzing
    } catch (...) {
        // Catch any other exceptions
    }
    
    return 0;
}
