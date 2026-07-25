#include <opencv4/opencv2/imgcodecs.hpp>
#include <opencv4/opencv2/imgproc.hpp>
#include <opencv4/opencv2/core.hpp>
#include <fuzzer/FuzzedDataProvider.h>

#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check: need at least some bytes for meaningful testing
    if (size < 32) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Consume fixed-size data first
    int imread_flags = fdp.ConsumeIntegralInRange<int>(-1, 256);  // Range of ImreadModes
    int imwrite_params_type = fdp.ConsumeIntegralInRange<int>(0, 3);  // Which format to test
    
    // Consume variable-size data
    std::string filename_prefix = fdp.ConsumeRandomLengthString(16);
    
    // Use the remaining bytes as image data
    std::vector<uint8_t> image_data = fdp.ConsumeRemainingBytes<uint8_t>();
    
    if (image_data.empty()) {
        return 0;
    }
    
    // Create a temporary file with the image data
    std::string temp_filename = "/tmp/fuzz_image_" + filename_prefix;
    FILE* temp_file = fopen(temp_filename.c_str(), "wb");
    if (!temp_file) {
        return 0;
    }
    fwrite(image_data.data(), 1, image_data.size(), temp_file);
    fclose(temp_file);
    
    try {
        // Read the image using imread
        cv::Mat image = cv::imread(temp_filename, imread_flags);
        
        if (!image.empty()) {
            // Perform basic image operations
            
            // 1. Convert color space based on fuzzed input
            cv::Mat converted;
            int color_conv_type = fdp.ConsumeIntegralInRange<int>(0, 5);
            switch (color_conv_type % 3) {
                case 0:
                    if (image.channels() == 3) {
                        cv::cvtColor(image, converted, cv::COLOR_BGR2GRAY);
                    } else if (image.channels() == 1) {
                        cv::cvtColor(image, converted, cv::COLOR_GRAY2BGR);
                    }
                    break;
                case 1:
                    if (image.channels() == 3) {
                        cv::cvtColor(image, converted, cv::COLOR_BGR2HSV);
                    }
                    break;
                case 2:
                    if (image.channels() == 3) {
                        cv::cvtColor(image, converted, cv::COLOR_BGR2RGB);
                    }
                    break;
            }
            
            // 2. Resize image based on fuzzed input
            if (!image.empty()) {
                cv::Mat resized;
                int new_width = fdp.ConsumeIntegralInRange<int>(10, 500);
                int new_height = fdp.ConsumeIntegralInRange<int>(10, 500);
                cv::resize(image, resized, cv::Size(new_width, new_height));
            }
            
            // Write the image back using imwrite with different formats
            std::string output_filename;
            std::vector<int> write_params;
            
            switch (imwrite_params_type) {
                case 0:  // JPEG
                    output_filename = temp_filename + "_out.jpg";
                    write_params.push_back(cv::IMWRITE_JPEG_QUALITY);
                    write_params.push_back(fdp.ConsumeIntegralInRange<int>(0, 100));
                    break;
                case 1:  // PNG
                    output_filename = temp_filename + "_out.png";
                    write_params.push_back(cv::IMWRITE_PNG_COMPRESSION);
                    write_params.push_back(fdp.ConsumeIntegralInRange<int>(0, 9));
                    break;
                case 2:  // BMP
                    output_filename = temp_filename + "_out.bmp";
                    // BMP doesn't have compression parameters in OpenCV
                    break;
                case 3:  // TIFF
                    output_filename = temp_filename + "_out.tiff";
                    write_params.push_back(cv::IMWRITE_TIFF_COMPRESSION);
                    write_params.push_back(fdp.ConsumeIntegralInRange<int>(1, 173));
                    break;
            }
            
            if (!output_filename.empty()) {
                bool write_success = cv::imwrite(output_filename, image, write_params);
                // Clean up output file
                if (write_success) {
                    std::remove(output_filename.c_str());
                }
            }
        }
    } catch (...) {
        // Catch any exceptions from OpenCV to prevent crashes
    }
    
    // Clean up temporary file
    std::remove(temp_filename.c_str());
    
    return 0;
}
