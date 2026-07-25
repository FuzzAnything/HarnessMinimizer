#include <cstddef>
#include <cstdint>
#include <vector>
#include <algorithm>
#include <fuzzer/FuzzedDataProvider.h>
#include <opencv2/opencv.hpp>
#include <opencv2/imgproc/hal/hal.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check: need enough data for all parameters
    if (size < 64) return 0;
    
    try {
        FuzzedDataProvider fdp(data, size);
        
        // 1. Create test image matrices using Mat constructors with various sizes, types, and channels
        int rows = fdp.ConsumeIntegralInRange<int>(1, 100);
        int cols = fdp.ConsumeIntegralInRange<int>(1, 100);
        int mat_type_choice = fdp.ConsumeIntegralInRange<int>(0, 7);
        
        // Map to common OpenCV types for testing
        int cv_type;
        switch (mat_type_choice) {
            case 0: cv_type = CV_8UC1; break;   // 8-bit single channel
            case 1: cv_type = CV_8UC3; break;   // 8-bit 3 channels
            case 2: cv_type = CV_16UC1; break;  // 16-bit unsigned single channel
            case 3: cv_type = CV_16SC1; break;  // 16-bit signed single channel
            case 4: cv_type = CV_32FC1; break;  // 32-bit float single channel
            case 5: cv_type = CV_64FC1; break;  // 64-bit double single channel
            case 6: cv_type = CV_8UC4; break;   // 8-bit 4 channels
            case 7: cv_type = CV_32SC1; break;  // 32-bit integer single channel
            default: cv_type = CV_8UC1;
        }
        
        // Create source matrix with consumed dimensions
        cv::Mat src_mat(rows, cols, cv_type);
        
        // Fill matrix with random data if available
        if (fdp.remaining_bytes() > 0) {
            size_t bytes_to_use = std::min(fdp.remaining_bytes(), 
                                          static_cast<size_t>(src_mat.total() * src_mat.elemSize()));
            std::vector<uint8_t> buffer = fdp.ConsumeBytes<uint8_t>(bytes_to_use);
            
            if (!buffer.empty() && buffer.size() <= src_mat.total() * src_mat.elemSize()) {
                std::memcpy(src_mat.data, buffer.data(), buffer.size());
            }
        }
        
        // 2. Call cv::borderInterpolate with fuzzed parameters (pixel position, length, borderType)
        int p = fdp.ConsumeIntegral<int>();  // Can be negative or positive
        int len = fdp.ConsumeIntegralInRange<int>(1, 1000);  // Length must be positive
        int borderType_choice = fdp.ConsumeIntegralInRange<int>(0, 4);
        
        // Map to OpenCV border types
        int borderType;
        switch (borderType_choice) {
            case 0: borderType = cv::BORDER_CONSTANT; break;
            case 1: borderType = cv::BORDER_REPLICATE; break;
            case 2: borderType = cv::BORDER_REFLECT; break;
            case 3: borderType = cv::BORDER_WRAP; break;
            case 4: borderType = cv::BORDER_REFLECT_101; break;
            default: borderType = cv::BORDER_DEFAULT;
        }
        
        // Test border interpolation function
        int interpolated_idx = cv::borderInterpolate(p, len, borderType);
        
        // 3. Set up affine and perspective transformation matrices
        // Create a small destination matrix for warping operations
        int dst_rows = fdp.ConsumeIntegralInRange<int>(1, 50);
        int dst_cols = fdp.ConsumeIntegralInRange<int>(1, 50);
        cv::Mat dst_mat(dst_rows, dst_cols, src_mat.type());
        
        // Set up affine transformation matrix (2x3 for affine)
        double affine_M[6];
        for (int i = 0; i < 6; i++) {
            affine_M[i] = fdp.ConsumeFloatingPointInRange<double>(-10.0, 10.0);
        }
        
        // Set up perspective transformation matrix (3x3)
        double perspective_M[9];
        for (int i = 0; i < 9; i++) {
            perspective_M[i] = fdp.ConsumeFloatingPointInRange<double>(-10.0, 10.0);
        }
        
        // Ensure perspective matrix is not singular (simple check)
        if (std::abs(perspective_M[8]) < 1e-10) {
            perspective_M[8] = 1.0;
        }
        
        // 4. Call cv::hal::warpAffineBlockline
        // Prepare parameters for warpAffineBlockline
        int block_width = fdp.ConsumeIntegralInRange<int>(1, std::min(100, dst_cols));
        std::vector<int> adelta(block_width);
        std::vector<int> bdelta(block_width);
        std::vector<short> xy(block_width * 2);  // x,y coordinates
        std::vector<short> alpha(block_width);   // interpolation coefficients
        
        // Initialize delta arrays with fuzzed data
        for (int i = 0; i < block_width; i++) {
            adelta[i] = fdp.ConsumeIntegralInRange<int>(-1000, 1000);
            bdelta[i] = fdp.ConsumeIntegralInRange<int>(-1000, 1000);
        }
        
        int X0 = fdp.ConsumeIntegralInRange<int>(-1000, 1000);
        int Y0 = fdp.ConsumeIntegralInRange<int>(-1000, 1000);
        
        // Call warpAffineBlockline with interpolation
        if (block_width > 0 && fdp.remaining_bytes() > 0) {
            cv::hal::warpAffineBlockline(adelta.data(), bdelta.data(), xy.data(), 
                                         alpha.data(), X0, Y0, block_width);
        }
        
        // 5. Call cv::hal::warpPerspectiveBlockline
        // Prepare parameters for warpPerspectiveBlockline
        int persp_block_width = fdp.ConsumeIntegralInRange<int>(1, std::min(100, dst_cols));
        std::vector<short> persp_xy(persp_block_width * 2);
        std::vector<short> persp_alpha(persp_block_width);
        
        double X0_persp = fdp.ConsumeFloatingPointInRange<double>(-1000.0, 1000.0);
        double Y0_persp = fdp.ConsumeFloatingPointInRange<double>(-1000.0, 1000.0);
        double W0_persp = fdp.ConsumeFloatingPointInRange<double>(0.1, 10.0);  // Avoid zero
        
        // Call warpPerspectiveBlockline with interpolation
        if (persp_block_width > 0 && fdp.remaining_bytes() > 0) {
            cv::hal::warpPerspectiveBlockline(perspective_M, persp_xy.data(), 
                                             persp_alpha.data(), X0_persp, Y0_persp, 
                                             W0_persp, persp_block_width);
        }
        
        // Also test the NN (nearest neighbor) versions if we have enough data
        if (fdp.remaining_bytes() > 0) {
            // Test warpAffineBlocklineNN
            int block_width_nn = fdp.ConsumeIntegralInRange<int>(1, std::min(50, dst_cols));
            std::vector<int> adelta_nn(block_width_nn);
            std::vector<int> bdelta_nn(block_width_nn);
            std::vector<short> xy_nn(block_width_nn * 2);
            
            for (int i = 0; i < block_width_nn; i++) {
                adelta_nn[i] = fdp.ConsumeIntegralInRange<int>(-500, 500);
                bdelta_nn[i] = fdp.ConsumeIntegralInRange<int>(-500, 500);
            }
            
            int X0_nn = fdp.ConsumeIntegralInRange<int>(-500, 500);
            int Y0_nn = fdp.ConsumeIntegralInRange<int>(-500, 500);
            
            if (block_width_nn > 0) {
                cv::hal::warpAffineBlocklineNN(adelta_nn.data(), bdelta_nn.data(), 
                                              xy_nn.data(), X0_nn, Y0_nn, block_width_nn);
            }
            
            // Test warpPerspectiveBlocklineNN
            if (fdp.remaining_bytes() > 0) {
                int persp_block_width_nn = fdp.ConsumeIntegralInRange<int>(1, std::min(50, dst_cols));
                std::vector<short> persp_xy_nn(persp_block_width_nn * 2);
                
                double X0_persp_nn = fdp.ConsumeFloatingPointInRange<double>(-500.0, 500.0);
                double Y0_persp_nn = fdp.ConsumeFloatingPointInRange<double>(-500.0, 500.0);
                double W0_persp_nn = fdp.ConsumeFloatingPointInRange<double>(0.5, 2.0);
                
                if (persp_block_width_nn > 0) {
                    cv::hal::warpPerspectiveBlocklineNN(perspective_M, persp_xy_nn.data(), 
                                                       X0_persp_nn, Y0_persp_nn, 
                                                       W0_persp_nn, persp_block_width_nn);
                }
            }
        }
        
        // 6. Clean up resources (RAII handles cleanup automatically)
        // All resources are managed by RAII (vectors and cv::Mat objects)
        
        // Additional testing: Test border interpolation with different parameters
        if (fdp.remaining_bytes() > 0) {
            // Test with various pixel positions and lengths
            for (int i = 0; i < 5 && fdp.remaining_bytes() > 0; i++) {
                int test_p = fdp.ConsumeIntegralInRange<int>(-100, 200);
                int test_len = fdp.ConsumeIntegralInRange<int>(1, 500);
                int test_border = fdp.ConsumeIntegralInRange<int>(0, 4);
                
                int border_type;
                switch (test_border) {
                    case 0: border_type = cv::BORDER_CONSTANT; break;
                    case 1: border_type = cv::BORDER_REPLICATE; break;
                    case 2: border_type = cv::BORDER_REFLECT; break;
                    case 3: border_type = cv::BORDER_WRAP; break;
                    case 4: border_type = cv::BORDER_REFLECT_101; break;
                    default: border_type = cv::BORDER_DEFAULT;
                }
                
                cv::borderInterpolate(test_p, test_len, border_type);
            }
        }
        
    } catch (const cv::Exception& e) {
        // Catch OpenCV exceptions and continue
        // Don't crash on invalid parameters
    } catch (...) {
        // Catch any other exceptions
    }
    
    return 0;
}
