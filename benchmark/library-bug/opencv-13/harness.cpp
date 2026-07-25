#include <opencv4/opencv2/core/base.hpp>
#include <opencv4/opencv2/core.hpp>
#include <fuzzer/FuzzedDataProvider.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <algorithm>
#include <cmath>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check: need enough bytes for matrix dimensions, cubeRoot values, and Cholesky data
    if (size < 512) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Consume fixed-size data first: matrix dimensions and operation parameters
    int matrix_size = fdp.ConsumeIntegralInRange<int>(2, 50);   // Size for Cholesky matrix (must be positive definite)
    int num_cube_values = fdp.ConsumeIntegralInRange<int>(10, 100);  // Number of values for cubeRoot testing
    bool test_double_precision = fdp.ConsumeBool();  // Whether to test double (64f) functions
    bool test_cholesky = fdp.ConsumeBool();  // Whether to test Cholesky decomposition
    
    // Calculate required bytes for cubeRoot test values
    size_t float_cube_bytes = num_cube_values * sizeof(float);
    size_t double_cube_bytes = num_cube_values * sizeof(double);
    
    // Calculate required bytes for Cholesky matrices
    // Cholesky needs a symmetric positive definite matrix A (size x size)
    // and a right-hand side vector b (size x 1)
    size_t matrix_elements = matrix_size * matrix_size;
    size_t vector_elements = matrix_size;
    
    size_t float_matrix_bytes = matrix_elements * sizeof(float);
    size_t float_vector_bytes = vector_elements * sizeof(float);
    size_t double_matrix_bytes = matrix_elements * sizeof(double);
    size_t double_vector_bytes = vector_elements * sizeof(double);
    
    // Check if we have enough data for all operations
    size_t total_required_bytes = float_cube_bytes + double_cube_bytes + 
                                   float_matrix_bytes + float_vector_bytes + 
                                   double_matrix_bytes + double_vector_bytes;
    
    if (fdp.remaining_bytes() < total_required_bytes) {
        return 0;
    }
    
    try {
        // ================ cubeRoot FUNCTION TESTING ================
        
        // Step 1: Test cubeRoot with float values
        std::vector<uint8_t> float_cube_bytes_data = fdp.ConsumeBytes<uint8_t>(float_cube_bytes);
        float* float_cube_values = reinterpret_cast<float*>(float_cube_bytes_data.data());
        
        std::vector<float> float_cube_results(num_cube_values);
        
        // Test cubeRoot on each float value
        for (int i = 0; i < num_cube_values; ++i) {
            // cubeRoot handles negative arguments correctly
            float_cube_results[i] = cv::cubeRoot(float_cube_values[i]);
            
            // Test edge cases with additional fuzzer input
            if (i % 5 == 0 && fdp.remaining_bytes() >= 3 * sizeof(float)) {
                // Test with scaled values from fuzzer input
                float scale_extreme = fdp.ConsumeFloatingPointInRange<float>(1e-20f, 1e20f);
                float extreme_val = float_cube_values[i] * scale_extreme;
                cv::cubeRoot(extreme_val);
                
                // Test with very small values from fuzzer input
                float scale_small = fdp.ConsumeFloatingPointInRange<float>(1e-20f, 1e20f);
                float small_val = float_cube_values[i] * scale_small;
                cv::cubeRoot(small_val);
                
                // Test with negative values from fuzzer input
                float neg_scale = fdp.ConsumeFloatingPointInRange<float>(-1e20f, -1e-20f);
                float neg_val = float_cube_values[i] * neg_scale;
                cv::cubeRoot(neg_val);
            }
        }
        
        // Step 2: Test cubeRoot with double values (if enabled)
        if (test_double_precision) {
            std::vector<uint8_t> double_cube_bytes_data = fdp.ConsumeBytes<uint8_t>(double_cube_bytes);
            double* double_cube_values = reinterpret_cast<double*>(double_cube_bytes_data.data());
            
            std::vector<double> double_cube_results(num_cube_values);
            
            // Test cubeRoot on each double value
            for (int i = 0; i < num_cube_values; ++i) {
                // The double version calls std::cbrt
                double_cube_results[i] = cv::cubeRoot(double_cube_values[i]);
                
                // Test edge cases using additional fuzzer data
                if (i % 7 == 0 && fdp.remaining_bytes() >= 3 * sizeof(double)) {
                    // Test with zero and edge cases from fuzzer input
                    double zero_test = 0.0;
                    cv::cubeRoot(zero_test);
                    
                    // Test with scaled values from fuzzer input
                    double scale_factor = fdp.ConsumeFloatingPointInRange<double>(1e-100, 1e100);
                    double scaled_val = double_cube_values[i] * scale_factor;
                    cv::cubeRoot(scaled_val);
                    
                    // Test with negative values from fuzzer input
                    double neg_scale = fdp.ConsumeFloatingPointInRange<double>(-1e100, -1e-100);
                    double neg_val = double_cube_values[i] * neg_scale;
                    cv::cubeRoot(neg_val);
                }
            }
        }
        // ================ Cholesky DECOMPOSITION TESTING ================
        
        if (test_cholesky) {
            // Step 3: Create a symmetric positive definite matrix for Cholesky decomposition
            // We need to construct A = M * M^T + epsilon*I to ensure positive definiteness
            
            // Create random matrix M (float)
            std::vector<uint8_t> float_M_bytes = fdp.ConsumeBytes<uint8_t>(float_matrix_bytes);
            float* float_M_data = reinterpret_cast<float*>(float_M_bytes.data());
            
            // Create vector b (float)
            std::vector<uint8_t> float_b_bytes = fdp.ConsumeBytes<uint8_t>(float_vector_bytes);
            float* float_b_data = reinterpret_cast<float*>(float_b_bytes.data());
            
            // Create matrix A = M * M^T + epsilon*I
            std::vector<float> float_A_data(matrix_elements, 0.0f);
            
            // Compute M * M^T
            for (int i = 0; i < matrix_size; ++i) {
                for (int j = 0; j < matrix_size; ++j) {
                    float sum = 0.0f;
                    for (int k = 0; k < matrix_size; ++k) {
                        float m_ik = float_M_data[i * matrix_size + k];
                        float m_jk = float_M_data[j * matrix_size + k];
                        sum += m_ik * m_jk;
                    }
                    float_A_data[i * matrix_size + j] = sum;
                }
            }
            
            // Add epsilon*I to ensure positive definiteness
            float epsilon = 0.1f;
            for (int i = 0; i < matrix_size; ++i) {
                float_A_data[i * matrix_size + i] += epsilon;
            }
            
            // Step 4: Test float Cholesky decomposition
            std::vector<float> float_x_data(vector_elements, 0.0f);
            
            bool cholesky_success_float = cv::Cholesky(
                float_A_data.data(),          // A matrix data
                matrix_size * sizeof(float),  // astep: row stride in bytes
                matrix_size,                  // m: matrix size
                float_b_data,                 // b vector data
                sizeof(float),                // bstep: element stride in bytes
                1                             // n: number of right-hand sides
            );
            
            // If Cholesky succeeded, we can optionally solve the system
            if (cholesky_success_float) {
                // The solution is stored in b_data after Cholesky call
                // We can copy it to x_data for verification
                std::copy(float_b_data, float_b_data + vector_elements, float_x_data.data());
            }
            
            // Step 5: Test double Cholesky decomposition (if enabled)
            if (test_double_precision) {
                // Create random matrix M (double)
                std::vector<uint8_t> double_M_bytes = fdp.ConsumeBytes<uint8_t>(double_matrix_bytes);
                double* double_M_data = reinterpret_cast<double*>(double_M_bytes.data());
                
                // Create vector b (double)
                std::vector<uint8_t> double_b_bytes = fdp.ConsumeBytes<uint8_t>(double_vector_bytes);
                double* double_b_data = reinterpret_cast<double*>(double_b_bytes.data());
                
                // Create matrix A = M * M^T + epsilon*I
                std::vector<double> double_A_data(matrix_elements, 0.0);
                
                // Compute M * M^T
                for (int i = 0; i < matrix_size; ++i) {
                    for (int j = 0; j < matrix_size; ++j) {
                        double sum = 0.0;
                        for (int k = 0; k < matrix_size; ++k) {
                            double m_ik = double_M_data[i * matrix_size + k];
                            double m_jk = double_M_data[j * matrix_size + k];
                            sum += m_ik * m_jk;
                        }
                        double_A_data[i * matrix_size + j] = sum;
                    }
                }
                
                // Add epsilon*I to ensure positive definiteness
                double epsilon_double = 0.1;
                for (int i = 0; i < matrix_size; ++i) {
                    double_A_data[i * matrix_size + i] += epsilon_double;
                }
                
                // Test double Cholesky decomposition
                std::vector<double> double_x_data(vector_elements, 0.0);
                
                bool cholesky_success_double = cv::Cholesky(
                    double_A_data.data(),           // A matrix data
                    matrix_size * sizeof(double),   // astep: row stride in bytes
                    matrix_size,                    // m: matrix size
                    double_b_data,                  // b vector data
                    sizeof(double),                 // bstep: element stride in bytes
                    1                               // n: number of right-hand sides
                );
                
                // If Cholesky succeeded, copy solution
                if (cholesky_success_double) {
                    std::copy(double_b_data, double_b_data + vector_elements, double_x_data.data());
                }
            }
            
            // Step 6: Test edge cases for Cholesky
            // Create a small 2x2 matrix explicitly to test boundary conditions
            if (matrix_size >= 2) {
                float small_A[4] = {5.0f, 2.0f, 2.0f, 5.0f};  // Positive definite
                float small_b[2] = {1.0f, 2.0f};
                
                bool small_cholesky = cv::Cholesky(
                    small_A,
                    2 * sizeof(float),
                    2,
                    small_b,
                    sizeof(float),
                    1
                );
                
                // Test with 1x1 matrix (degenerate case)
                float tiny_A[1] = {4.0f};  // Positive definite (2^2)
                float tiny_b[1] = {8.0f};
                
                bool tiny_cholesky = cv::Cholesky(
                    tiny_A,
                    sizeof(float),
                    1,
                    tiny_b,
                    sizeof(float),
                    1
                );
            }
        }
        
        // ================ ADDITIONAL MATHEMATICAL FUNCTIONS ================
        
        // Test fastAtan2 which is nearby in the header and may have coverage gaps
        if (fdp.remaining_bytes() >= 2 * sizeof(float)) {
            float y = fdp.ConsumeFloatingPoint<float>();
            float x = fdp.ConsumeFloatingPoint<float>();
            float angle = cv::fastAtan2(y, x);
            
            // Test edge cases
            cv::fastAtan2(0.0f, 1.0f);   // 0 degrees
            cv::fastAtan2(1.0f, 0.0f);   // 90 degrees  
            cv::fastAtan2(0.0f, -1.0f);  // 180 degrees
            cv::fastAtan2(-1.0f, 0.0f);  // 270 degrees
        }
        
        // Test LU decomposition (also in the same header region)
        if (test_cholesky && fdp.remaining_bytes() >= float_matrix_bytes + float_vector_bytes) {
            std::vector<uint8_t> lu_A_bytes = fdp.ConsumeBytes<uint8_t>(float_matrix_bytes);
            float* lu_A_data = reinterpret_cast<float*>(lu_A_bytes.data());
            
            std::vector<uint8_t> lu_b_bytes = fdp.ConsumeBytes<uint8_t>(float_vector_bytes);
            float* lu_b_data = reinterpret_cast<float*>(lu_b_bytes.data());
            
            int lu_result = cv::LU(
                lu_A_data,
                matrix_size * sizeof(float),
                matrix_size,
                lu_b_data,
                sizeof(float),
                1
            );
        }
        
    } catch (...) {
        // Catch any exceptions to prevent crash
    }
    
    return 0;
}
