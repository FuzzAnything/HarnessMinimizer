#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>
#include <algorithm>
#include <fuzzer/FuzzedDataProvider.h>

#include <opencv2/core.hpp>
#include <opencv2/core/mat.hpp>
#include <opencv2/core/types.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum input size check - need enough for basic parameters
    if (size < 32) return 0;
    
    FuzzedDataProvider fdp(data, size);
    
    // Consume operation type to test different core data structure operations
    uint8_t operation = fdp.ConsumeIntegral<uint8_t>() % 8;
    
    // Consume parameters for matrix creation and operations
    int rows = fdp.ConsumeIntegralInRange<int>(1, 100);
    int cols = fdp.ConsumeIntegralInRange<int>(1, 100);
    int mat_type = fdp.ConsumeIntegral<uint8_t>() % 8; // Limited to common types
    
    // Convert mat_type to OpenCV types
    int cv_type;
    switch (mat_type % 4) {
        case 0: cv_type = CV_8UC1; break;
        case 1: cv_type = CV_8UC3; break;
        case 2: cv_type = CV_32FC1; break;
        case 3: cv_type = CV_64FC1; break;
        default: cv_type = CV_8UC1; break;
    }
    
    // Test different core data structure operations
    switch (operation) {
        case 0: {
            // Test Mat creation and basic operations
            cv::Mat mat(rows, cols, cv_type);
            
            // Fill with random data if we have enough
            if (fdp.remaining_bytes() >= static_cast<size_t>(rows * cols * mat.elemSize())) {
                std::vector<uint8_t> mat_data = fdp.ConsumeBytes<uint8_t>(rows * cols * mat.elemSize());
                memcpy(mat.data, mat_data.data(), std::min(mat_data.size(), static_cast<size_t>(rows * cols * mat.elemSize())));
            }
            
            // Test Mat properties
            int actual_rows = mat.rows;
            int actual_cols = mat.cols;
            int actual_type = mat.type();
            size_t elem_size = mat.elemSize();
            size_t total_elements = mat.total();
            bool is_continuous = mat.isContinuous();
            bool is_submatrix = mat.isSubmatrix();
            bool empty_check = mat.empty();
            
            // Test clone operation
            cv::Mat mat_clone = mat.clone();
            
            // Test copy operation
            cv::Mat mat_copy;
            mat.copyTo(mat_copy);
            
            // Test element access (if matrix is small enough)
            if (rows > 0 && cols > 0) {
                if (cv_type == CV_8UC1) {
                    uint8_t val = mat.at<uint8_t>(0, 0);
                    mat.at<uint8_t>(0, 0) = val;
                } else if (cv_type == CV_32FC1) {
                    float val = mat.at<float>(0, 0);
                    mat.at<float>(0, 0) = val;
                }
            }
            
            // Test reshape operation
            if (rows * cols > 1) {
                cv::Mat reshaped = mat.reshape(1, rows * cols);
            }
            
            break;
        }
        
        case 1: {
            // Test Scalar operations
            double val0 = fdp.ConsumeFloatingPoint<double>();
            double val1 = fdp.ConsumeFloatingPoint<double>();
            double val2 = fdp.ConsumeFloatingPoint<double>();
            double val3 = fdp.ConsumeFloatingPoint<double>();
            
            cv::Scalar scalar1(val0, val1, val2, val3);
            cv::Scalar scalar2(fdp.ConsumeFloatingPoint<double>());
            
            // Test scalar operations
            cv::Scalar sum = scalar1 + scalar2;
            cv::Scalar diff = scalar1 - scalar2;
            cv::Scalar mult = scalar1 * scalar2;
            cv::Scalar div = scalar1 / (scalar2[0] != 0 ? scalar2 : cv::Scalar(1.0));
            
            // Test scalar properties
            double scalar_norm = cv::norm(scalar1);
            bool is_real = scalar1.isReal();
            
            // Test scalar with Mat
            cv::Mat scalar_mat(rows, cols, cv_type, scalar1);
            
            break;
        }
        
        case 2: {
            // Test Point operations
            int x1 = fdp.ConsumeIntegral<int>();
            int y1 = fdp.ConsumeIntegral<int>();
            int x2 = fdp.ConsumeIntegral<int>();
            int y2 = fdp.ConsumeIntegral<int>();
            
            cv::Point pt1(x1, y1);
            cv::Point pt2(x2, y2);
            cv::Point2f pt1f(static_cast<float>(x1), static_cast<float>(y1));
            cv::Point2f pt2f(static_cast<float>(x2), static_cast<float>(y2));
            
            // Test point operations
            cv::Point sum_pt = pt1 + pt2;
            cv::Point diff_pt = pt1 - pt2;
            cv::Point mult_pt = pt1 * 2;
            cv::Point div_pt = pt1 / 2;
            
            // Test dot product and cross product
            double dot_product = pt1.dot(pt2);
            double cross_product = pt1.cross(pt2);
            
            // Test point conversions
            cv::Point2d pt1d = pt1;
            cv::Point pt_rounded = pt1f;
            
            // Test point inside check (create a dummy rect)
            cv::Rect rect(0, 0, 100, 100);
            bool inside = rect.contains(pt1);
            
            break;
        }
        
        case 3: {
            // Test Rect operations
            int x = fdp.ConsumeIntegral<int>();
            int y = fdp.ConsumeIntegral<int>();
            int width = fdp.ConsumeIntegralInRange<int>(1, 100);
            int height = fdp.ConsumeIntegralInRange<int>(1, 100);
            
            cv::Rect rect1(x, y, width, height);
            
            // Test Rect from points
            cv::Point pt1(fdp.ConsumeIntegral<int>(), fdp.ConsumeIntegral<int>());
            cv::Point pt2(fdp.ConsumeIntegral<int>(), fdp.ConsumeIntegral<int>());
            cv::Rect rect2(pt1, pt2);
            
            // Test rect operations
            cv::Rect union_rect = rect1 | rect2;
            cv::Rect intersect_rect = rect1 & rect2;
            
            // Test rect properties
            cv::Point tl = rect1.tl();
            cv::Point br = rect1.br();
            cv::Size rect_size = rect1.size();
            int area = rect1.area();
            bool empty_rect = rect1.empty();
            
            // Test rect adjustments
            cv::Rect adjusted = rect1 + cv::Point(10, 10);
            cv::Rect scaled = rect1 + cv::Size(10, 10);
            
            // Test contains method
            cv::Point test_pt(x + width/2, y + height/2);
            bool contains_pt = rect1.contains(test_pt);
            
            break;
        }
        
        case 4: {
            // Test Mat arithmetic operations
            cv::Mat mat1(rows, cols, cv_type);
            cv::Mat mat2(rows, cols, cv_type);
            
            // Fill with some data if available
            if (fdp.remaining_bytes() >= 2 * static_cast<size_t>(rows * cols * mat1.elemSize())) {
                size_t data_size = rows * cols * mat1.elemSize();
                std::vector<uint8_t> data1 = fdp.ConsumeBytes<uint8_t>(data_size);
                std::vector<uint8_t> data2 = fdp.ConsumeBytes<uint8_t>(data_size);
                
                if (data1.size() == data_size) memcpy(mat1.data, data1.data(), data_size);
                if (data2.size() == data_size) memcpy(mat2.data, data2.data(), data_size);
            }
            
            // Test arithmetic operations
            cv::Mat add_result, sub_result, mul_result, div_result;
            
            cv::add(mat1, mat2, add_result);
            cv::subtract(mat1, mat2, sub_result);
            cv::multiply(mat1, mat2, mul_result);
            
            // Avoid division by zero
            cv::Mat mat2_nonzero = mat2.clone();
            if (cv_type == CV_8UC1 || cv_type == CV_8UC3) {
                // For uint8, add 1 to avoid division by zero
                mat2_nonzero += cv::Scalar(1);
            }
            cv::divide(mat1, mat2_nonzero, div_result);
            
            // Test scalar operations
            cv::Scalar scalar_val(fdp.ConsumeFloatingPoint<double>());
            cv::Mat add_scalar, mul_scalar;
            cv::add(mat1, scalar_val, add_scalar);
            cv::multiply(mat1, scalar_val, mul_scalar);
            
            break;
        }
        
        case 5: {
            // Test Mat comparison and logical operations
            cv::Mat mat1(rows, cols, cv_type);
            cv::Mat mat2(rows, cols, cv_type);
            
            // Test comparison operations
            cv::Mat cmp_eq, cmp_gt, cmp_lt, cmp_ge, cmp_le, cmp_ne;
            
            cv::compare(mat1, mat2, cmp_eq, cv::CMP_EQ);
            cv::compare(mat1, mat2, cmp_gt, cv::CMP_GT);
            cv::compare(mat1, mat2, cmp_lt, cv::CMP_LT);
            
            // Test bitwise operations (for integer types)
            if (cv_type == CV_8UC1 || cv_type == CV_8UC3) {
                cv::Mat bitwise_and, bitwise_or, bitwise_xor, bitwise_not;
                
                cv::bitwise_and(mat1, mat2, bitwise_and);
                cv::bitwise_or(mat1, mat2, bitwise_or);
                cv::bitwise_xor(mat1, mat2, bitwise_xor);
                cv::bitwise_not(mat1, bitwise_not);
            }
            
            // Test min/max operations
            cv::Mat min_result, max_result;
            cv::min(mat1, mat2, min_result);
            cv::max(mat1, mat2, max_result);
            
            // Test inRange operation
            cv::Scalar lower_bound(fdp.ConsumeFloatingPoint<double>());
            cv::Scalar upper_bound(fdp.ConsumeFloatingPoint<double>());
            cv::Mat in_range_result;
            cv::inRange(mat1, lower_bound, upper_bound, in_range_result);
            
            break;
        }
        
        case 6: {
            // Test Mat statistics operations
            cv::Mat mat(rows, cols, cv_type);
            
            // Fill with some data if available
            if (fdp.remaining_bytes() >= static_cast<size_t>(rows * cols * mat.elemSize())) {
                size_t data_size = rows * cols * mat.elemSize();
                std::vector<uint8_t> data = fdp.ConsumeBytes<uint8_t>(data_size);
                if (data.size() == data_size) memcpy(mat.data, data.data(), data_size);
            }
            
            // Test statistical operations
            cv::Scalar mean_val = cv::mean(mat);
            cv::Scalar stddev_val;
            cv::meanStdDev(mat, mean_val, stddev_val);
            
            double min_val, max_val;
            cv::Point min_loc, max_loc;
            cv::minMaxLoc(mat, &min_val, &max_val, &min_loc, &max_loc);
            
            cv::Scalar sum_val = cv::sum(mat);
            int non_zero = cv::countNonZero(mat);
            
            // Test norm operations
            double norm_l1 = cv::norm(mat, cv::NORM_L1);
            double norm_l2 = cv::norm(mat, cv::NORM_L2);
            double norm_inf = cv::norm(mat, cv::NORM_INF);
            
            break;
        }
        
        case 7: {
            // Test Mat transformations and utility functions
            cv::Mat mat(rows, cols, cv_type);
            
            // Test transpose
            cv::Mat transposed = mat.t();
            
            // Test diag (for square matrices)
            if (rows == cols && rows > 0) {
                cv::Mat diag_mat = cv::Mat::diag(mat.diag());
            }
            
            // Test eye (identity matrix)
            cv::Mat eye_mat = cv::Mat::eye(rows, cols, cv_type);
            
            // Test ones matrix
            cv::Mat ones_mat = cv::Mat::ones(rows, cols, cv_type);
            
            // Test zeros matrix
            cv::Mat zeros_mat = cv::Mat::zeros(rows, cols, cv_type);
            
            // Test setTo operation
            cv::Scalar fill_value(fdp.ConsumeFloatingPoint<double>());
            mat.setTo(fill_value);
            
            // Test convertTo operation
            cv::Mat converted;
            mat.convertTo(converted, CV_32FC1);
            
            // Test ROI (Region of Interest)
            if (rows > 2 && cols > 2) {
                cv::Rect roi_rect(1, 1, cols-2, rows-2);
                cv::Mat roi = mat(roi_rect);
            }
            
            // Test row/column access
            if (rows > 0) {
                cv::Mat row_mat = mat.row(0);
            }
            if (cols > 0) {
                cv::Mat col_mat = mat.col(0);
            }
            
            break;
        }
    }
    
    return 0;
}
