#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>
#include <algorithm>
#include <cmath>
#include <fuzzer/FuzzedDataProvider.h>
#include <opencv4/opencv2/core.hpp>
#include <opencv4/opencv2/ml.hpp>
// Maximum input size to prevent processing large inputs
constexpr size_t MAX_INPUT_SIZE = 8192;

// Maximum number of training samples to prevent excessive computation
constexpr int MAX_TRAINING_SAMPLES = 100;
constexpr int MAX_FEATURES = 20;

// Maximum number of classes for classification
constexpr int MAX_CLASSES = 10;

// Maximum training iterations to prevent long-running training
constexpr int MAX_TRAINING_ITERATIONS = 50;

// Helper function to sanitize floating-point values
// Returns a valid finite float, replaces NaN/inf with safe values
template<typename T>
T sanitize_float(T value, T fallback = T(0.0)) {
    if (!std::isfinite(value)) {
        return fallback;
    }
    return value;
}

// Helper function to consume and sanitize a floating-point value
template<typename T>
T consume_sanitized_float(FuzzedDataProvider& fdp, T min_val = -1000.0, T max_val = 1000.0) {
    T value = fdp.ConsumeFloatingPoint<T>();
    if (!std::isfinite(value)) {
        // Replace NaN/inf with a random finite value in range
        return fdp.ConsumeFloatingPointInRange<T>(min_val, max_val);
    }
    return value;
}

// Helper function to consume and sanitize a floating-point value within range
template<typename T>
T consume_sanitized_float_in_range(FuzzedDataProvider& fdp, T min_val, T max_val) {
    T value = fdp.ConsumeFloatingPointInRange<T>(min_val, max_val);
    // Ensure the value is finite, if not fall back to midpoint
    if (!std::isfinite(value)) {
        return (min_val + max_val) / T(2.0);
    }
    return value;
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Size limits: reject too small or too large inputs
    if (size < 128 || size > MAX_INPUT_SIZE) return 0;
    
    FuzzedDataProvider fdp(data, size);
    
    try {
        // Step 1: Early validation - check if we have enough data for basic operations
        if (fdp.remaining_bytes() < 100) return 0;
        
        // Step 2: Determine ML algorithm to test (multiple algorithms for coverage)
        uint8_t algorithm_choice = fdp.ConsumeIntegral<uint8_t>() % 3;
        
        // Step 3: Generate synthetic training data
        int num_samples = fdp.ConsumeIntegralInRange<int>(10, MAX_TRAINING_SAMPLES);
        int num_features = fdp.ConsumeIntegralInRange<int>(2, MAX_FEATURES);
        int num_classes = fdp.ConsumeIntegralInRange<int>(2, MAX_CLASSES);
        
        // Check remaining bytes before allocating large structures
        size_t bytes_needed = num_samples * num_features * sizeof(float) + 
                             num_samples * sizeof(int) + 100;
        if (fdp.remaining_bytes() < bytes_needed) {
            return 0;  // Not enough data for meaningful ML training
        }
        
        // Create feature matrix (samples x features)
        cv::Mat features(num_samples, num_features, CV_32F);
        for (int i = 0; i < num_samples; ++i) {
            for (int j = 0; j < num_features; ++j) {
                features.at<float>(i, j) = consume_sanitized_float<float>(fdp, -1000.0f, 1000.0f);
            }
        }
        
        // Create response vector (labels)
        cv::Mat responses(num_samples, 1, CV_32S);
        for (int i = 0; i < num_samples; ++i) {
            responses.at<int>(i, 0) = fdp.ConsumeIntegralInRange<int>(0, num_classes - 1);
        }
        
        // Step 4: Create training data using cv::ml::TrainData::create()
        // This is a key API from the guidance
        cv::Ptr<cv::ml::TrainData> train_data = cv::ml::TrainData::create(
            features, cv::ml::ROW_SAMPLE, responses);
        
        // Step 5: Split data into train/test sets (optional, for error calculation)
        train_data->setTrainTestSplitRatio(0.7, true);
        
        // Step 6: Create and configure ML model based on algorithm choice
        cv::Ptr<cv::ml::StatModel> model;
        
        switch (algorithm_choice) {
            case 0: {
                // Support Vector Machine (SVM) - primary target from guidance
                cv::Ptr<cv::ml::SVM> svm = cv::ml::SVM::create();
                
                // Configure SVM parameters using guidance APIs
                // SVM::setType - use integer values directly
                int svm_type_choice = fdp.ConsumeIntegralInRange<int>(0, 4);
                svm->setType(svm_type_choice + 100);  // C_SVC=100, NU_SVC=101, etc.
                
                // SVM::setKernel - use integer values directly
                int kernel_type = fdp.ConsumeIntegralInRange<int>(0, 5);
                svm->setKernel(kernel_type);
                
                // Set kernel parameters based on kernel type
                if (kernel_type == 1) {  // POLY
                    svm->setDegree(consume_sanitized_float_in_range<double>(fdp, 1.0, 5.0));
                    svm->setGamma(consume_sanitized_float_in_range<double>(fdp, 0.1, 5.0));
                    svm->setCoef0(consume_sanitized_float_in_range<double>(fdp, 0.0, 1.0));
                } else if (kernel_type == 2 || kernel_type == 3) {  // RBF or SIGMOID
                    svm->setGamma(consume_sanitized_float_in_range<double>(fdp, 0.1, 5.0));
                    if (kernel_type == 3) {  // SIGMOID
                        svm->setCoef0(consume_sanitized_float_in_range<double>(fdp, 0.0, 1.0));
                    }
                }
                // Set C parameter for C_SVC, EPS_SVR, NU_SVR
                if (svm_type_choice == 0 || svm_type_choice == 3 || svm_type_choice == 4) {
                    svm->setC(consume_sanitized_float_in_range<double>(fdp, 0.1, 10.0));
                }
                
                // Set nu parameter for NU_SVC, ONE_CLASS, NU_SVR
                if (svm_type_choice == 1 || svm_type_choice == 2 || svm_type_choice == 4) {
                    svm->setNu(consume_sanitized_float_in_range<double>(fdp, 0.01, 1.0));
                }
                
                // Set p parameter for EPS_SVR
                if (svm_type_choice == 3) {
                    svm->setP(consume_sanitized_float_in_range<double>(fdp, 0.01, 1.0));
                }
                
                // SVM::setTermCriteria - termination criteria
                cv::TermCriteria term_criteria;
                term_criteria.type = cv::TermCriteria::MAX_ITER + cv::TermCriteria::EPS;
                term_criteria.maxCount = fdp.ConsumeIntegralInRange<int>(10, MAX_TRAINING_ITERATIONS);
                term_criteria.epsilon = consume_sanitized_float_in_range<double>(fdp, 1e-3, 1e-1);
                svm->setTermCriteria(term_criteria);
                
                model = svm;
                break;
            }
            
            case 1: {
                // Decision Trees (DTrees) - another target from guidance
                cv::Ptr<cv::ml::DTrees> dtree = cv::ml::DTrees::create();
                
                // Configure DTrees parameters
                dtree->setMaxDepth(fdp.ConsumeIntegralInRange<int>(1, 10));
                dtree->setMinSampleCount(fdp.ConsumeIntegralInRange<int>(1, 10));
                dtree->setCVFolds(fdp.ConsumeIntegralInRange<int>(0, 5));
                dtree->setUseSurrogates(fdp.ConsumeBool());
                dtree->setUse1SERule(fdp.ConsumeBool());
                dtree->setRegressionAccuracy(consume_sanitized_float_in_range<float>(fdp, 0.001f, 0.1f));
                model = dtree;
                break;
            }
            
            case 2: {
                // K-Nearest Neighbors (additional algorithm for coverage)
                cv::Ptr<cv::ml::KNearest> knn = cv::ml::KNearest::create();
                
                // Configure KNN parameters
                knn->setDefaultK(fdp.ConsumeIntegralInRange<int>(1, 10));
                knn->setIsClassifier(fdp.ConsumeBool());
                knn->setEmax(fdp.ConsumeIntegralInRange<int>(0, 10));
                
                model = knn;
                break;
            }
        }
        
        // Step 7: Train the model using cv::ml::StatModel::train()
        // This is a key API from the guidance
        if (model && fdp.ConsumeBool()) {
            bool train_success = model->train(train_data);
            
            // Alternative: Try trainAuto for SVM if we have enough data
            if (algorithm_choice == 0 && train_success && fdp.ConsumeBool() && 
                fdp.remaining_bytes() > 50) {
                cv::Ptr<cv::ml::SVM> svm = model.dynamicCast<cv::ml::SVM>();
                if (!svm.empty()) {
                    // Try trainAuto with limited grid search
                    bool auto_train_success = svm->trainAuto(train_data, 5);
                }
            }
        }
        
        // Step 8: If model was trained, test prediction
        if (model && model->isTrained()) {
            // Test prediction on training data
            cv::Mat test_features = train_data->getTrainSamples();
            cv::Mat predictions;
            
            // cv::ml::StatModel::predict() - key API from guidance
            float prediction_result = model->predict(test_features, predictions);
            
            // Calculate error if we have enough data
            if (fdp.remaining_bytes() > 20) {
                cv::Mat test_responses = train_data->getTrainResponses();
                cv::Mat test_resp_output;
                float error = model->calcError(train_data, false, test_resp_output);
            }
            
            // Test prediction on a few random samples
            int num_test_samples = fdp.ConsumeIntegralInRange<int>(1, 5);
            if (fdp.remaining_bytes() > num_test_samples * num_features * sizeof(float)) {
                cv::Mat random_test(num_test_samples, num_features, CV_32F);
                for (int i = 0; i < num_test_samples; ++i) {
                    for (int j = 0; j < num_features; ++j) {
                        random_test.at<float>(i, j) = consume_sanitized_float<float>(fdp, -1000.0f, 1000.0f);
                    }
                }
                
                cv::Mat random_predictions;
                model->predict(random_test, random_predictions);
            }
        }
        
        // Step 9: Test other StatModel methods
        if (model) {
            // Test basic properties
            int var_count = model->getVarCount();
            bool is_classifier = model->isClassifier();
            bool is_trained = model->isTrained();
            bool is_empty = model->empty();
            
            // Try alternative train method signature
            if (fdp.ConsumeBool() && fdp.remaining_bytes() > 50) {
                // Create a simple dataset for alternative train method
                int alt_samples = fdp.ConsumeIntegralInRange<int>(5, 20);
                int alt_features = fdp.ConsumeIntegralInRange<int>(2, 5);
                
                cv::Mat alt_features_mat(alt_samples, alt_features, CV_32F);
                cv::Mat alt_responses(alt_samples, 1, CV_32S);
                
                for (int i = 0; i < alt_samples && fdp.remaining_bytes() > 10; ++i) {
                    for (int j = 0; j < alt_features; ++j) {
                        alt_features_mat.at<float>(i, j) = consume_sanitized_float<float>(fdp, -1000.0f, 1000.0f);
                    }
                    alt_responses.at<int>(i, 0) = fdp.ConsumeIntegralInRange<int>(0, 2);
                }
                
                // Try training with the alternative signature
                if (alt_samples > 0 && alt_features > 0) {
                    bool alt_train_success = model->train(alt_features_mat, 
                                                         cv::ml::ROW_SAMPLE, 
                                                         alt_responses);
                }
            }
        }
        
        // Step 10: Cleanup is automatic with cv::Ptr smart pointers
        // No explicit cleanup needed
        
    } catch (const cv::Exception& e) {
        // OpenCV exceptions are expected during fuzzing
    } catch (...) {
        // Catch any other exceptions
    }
    
    return 0;
}
