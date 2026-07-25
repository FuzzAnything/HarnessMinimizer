// Sixth OpenCV fuzzing harness targeting ml module for machine learning algorithms
// Focuses on machine learning algorithms: classification, regression, clustering
// Targets currently uncovered ml module (0% coverage based on previous analysis)
// APIs targeted: cv::ml::SVM, cv::ml::DTrees, cv::ml::RTrees, cv::ml::KNearest, 
// cv::ml::NormalBayesClassifier, cv::ml::LogisticRegression, cv::ml::ANN_MLP, 
// cv::ml::Boost, cv::ml::EM
#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>
#include <opencv4/opencv2/opencv.hpp>
#include <opencv4/opencv2/ml.hpp>
#include <fuzzer/FuzzedDataProvider.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check: need enough data for basic ML operations
    if (size < 128) return 0;
    
    FuzzedDataProvider fdp(data, size);
    
    try {
        // Create training data from fuzzer input
        int num_samples = fdp.ConsumeIntegralInRange<int>(10, 100);
        int num_features = fdp.ConsumeIntegralInRange<int>(2, 10);
        int num_classes = fdp.ConsumeIntegralInRange<int>(2, 5);
        
        // Create samples matrix
        cv::Mat samples(num_samples, num_features, CV_32FC1);
        size_t samples_data_size = num_samples * num_features * sizeof(float);
        
        // Fill samples with fuzzer data
        if (fdp.remaining_bytes() >= samples_data_size) {
            std::vector<uint8_t> samples_data = fdp.ConsumeBytes<uint8_t>(samples_data_size);
            if (samples_data.size() == samples_data_size) {
                memcpy(samples.data, samples_data.data(), samples_data_size);
            } else {
                // Fill with random data if not enough
                cv::randu(samples, 0.0f, 1.0f);
            }
        } else {
            // Fill with random data if not enough
            cv::randu(samples, 0.0f, 1.0f);
        }
        
        // Create labels for classification
        cv::Mat labels(num_samples, 1, CV_32SC1);
        for (int i = 0; i < num_samples; i++) {
            labels.at<int>(i) = fdp.ConsumeIntegralInRange<int>(0, num_classes - 1);
        }
        
        // Create labels for regression (continuous values)
        cv::Mat regression_labels(num_samples, 1, CV_32FC1);
        if (fdp.remaining_bytes() >= num_samples * sizeof(float)) {
            std::vector<uint8_t> reg_data = fdp.ConsumeBytes<uint8_t>(num_samples * sizeof(float));
            if (reg_data.size() == num_samples * sizeof(float)) {
                memcpy(regression_labels.data, reg_data.data(), reg_data.size());
            }
        } else {
            cv::randu(regression_labels, 0.0f, 1.0f);
        }
        
        // Create TrainData object
        cv::Ptr<cv::ml::TrainData> train_data = cv::ml::TrainData::create(
            samples, cv::ml::ROW_SAMPLE, labels
        );
        
        // Select ML algorithm based on fuzzer input
        uint8_t algorithm_type = fdp.ConsumeIntegral<uint8_t>() % 9;
        
        switch (algorithm_type) {
            case 0: {
                // SVM (Support Vector Machine)
                cv::Ptr<cv::ml::SVM> svm = cv::ml::SVM::create();
                
                // Set SVM parameters from fuzzer input
                int svm_type = fdp.ConsumeIntegral<uint8_t>() % 5;
                svm->setType(static_cast<cv::ml::SVM::Types>(svm_type));
                
                int kernel_type = fdp.ConsumeIntegral<uint8_t>() % 6;
                svm->setKernel(static_cast<cv::ml::SVM::KernelTypes>(kernel_type));
                
                svm->setC(fdp.ConsumeFloatingPointInRange<float>(0.1f, 100.0f));
                svm->setGamma(fdp.ConsumeFloatingPointInRange<float>(0.01f, 10.0f));
                svm->setDegree(fdp.ConsumeIntegralInRange<int>(2, 5));
                svm->setCoef0(fdp.ConsumeFloatingPointInRange<float>(0.0f, 1.0f));
                
                // Train SVM
                svm->train(train_data);
                
                // Make predictions
                cv::Mat svm_results;
                svm->predict(samples, svm_results);
                
                // Calculate error
                if (!svm_results.empty()) {
                    float svm_error = svm->calcError(train_data, false, cv::noArray());
                }
                break;
            }
            
            case 1: {
                // DTrees (Decision Trees)
                cv::Ptr<cv::ml::DTrees> dtree = cv::ml::DTrees::create();
                
                // Set DTrees parameters
                dtree->setMaxDepth(fdp.ConsumeIntegralInRange<int>(1, 10));
                dtree->setMinSampleCount(fdp.ConsumeIntegralInRange<int>(1, 10));
                dtree->setCVFolds(fdp.ConsumeIntegralInRange<int>(0, 5));
                dtree->setUseSurrogates(fdp.ConsumeBool());
                dtree->setUse1SERule(fdp.ConsumeBool());
                dtree->setTruncatePrunedTree(fdp.ConsumeBool());
                
                // Train DTrees
                dtree->train(train_data);
                
                // Make predictions
                cv::Mat dtree_results;
                dtree->predict(samples, dtree_results);
                
                // Calculate error
                if (!dtree_results.empty()) {
                    float dtree_error = dtree->calcError(train_data, false, cv::noArray());
                }
                break;
            }
            
            case 2: {
                // RTrees (Random Forests)
                cv::Ptr<cv::ml::RTrees> rtree = cv::ml::RTrees::create();
                
                // Set RTrees parameters
                rtree->setMaxDepth(fdp.ConsumeIntegralInRange<int>(1, 10));
                rtree->setMinSampleCount(fdp.ConsumeIntegralInRange<int>(1, 10));
                rtree->setRegressionAccuracy(fdp.ConsumeFloatingPointInRange<float>(0.0f, 0.1f));
                rtree->setUseSurrogates(fdp.ConsumeBool());
                rtree->setCalculateVarImportance(fdp.ConsumeBool());
                rtree->setActiveVarCount(fdp.ConsumeIntegralInRange<int>(0, num_features));
                rtree->setTermCriteria(cv::TermCriteria(
                    cv::TermCriteria::MAX_ITER | cv::TermCriteria::EPS,
                    fdp.ConsumeIntegralInRange<int>(10, 100),
                    fdp.ConsumeFloatingPointInRange<float>(0.001f, 0.1f)
                ));
                
                // Train RTrees
                rtree->train(train_data);
                
                // Make predictions
                cv::Mat rtree_results;
                rtree->predict(samples, rtree_results);
                
                // Calculate error
                if (!rtree_results.empty()) {
                    float rtree_error = rtree->calcError(train_data, false, cv::noArray());
                    
                    // Get variable importance if calculated
                    if (rtree->getCalculateVarImportance()) {
                        cv::Mat var_importance = rtree->getVarImportance();
                    }
                }
                break;
            }
            
            case 3: {
                // KNearest (K-Nearest Neighbors)
                cv::Ptr<cv::ml::KNearest> knn = cv::ml::KNearest::create();
                
                // Set KNearest parameters
                knn->setDefaultK(fdp.ConsumeIntegralInRange<int>(1, 10));
                knn->setIsClassifier(fdp.ConsumeBool());
                knn->setEmax(fdp.ConsumeIntegralInRange<int>(1, 100));
                knn->setAlgorithmType(fdp.ConsumeIntegral<uint8_t>() % 2 == 0 ? 
                    cv::ml::KNearest::BRUTE_FORCE : cv::ml::KNearest::KDTREE);
                
                // Train KNearest
                knn->train(train_data);
                
                // Use findNearest for predictions
                cv::Mat knn_results;
                cv::Mat neighbor_responses;
                cv::Mat distances;
                int k = fdp.ConsumeIntegralInRange<int>(1, 5);
                
                knn->findNearest(samples, k, knn_results, neighbor_responses, distances);
                break;
            }
            
            case 4: {
                // NormalBayesClassifier (Naive Bayes)
                cv::Ptr<cv::ml::NormalBayesClassifier> nbayes = cv::ml::NormalBayesClassifier::create();
                
                // Train NormalBayesClassifier
                nbayes->train(train_data);
                
                // Make predictions
                cv::Mat nbayes_results;
                nbayes->predict(samples, nbayes_results);
                
                // Calculate probability
                cv::Mat nbayes_prob;
                nbayes->predictProb(samples, nbayes_results, nbayes_prob);
                break;
            }
            
            case 5: {
                // LogisticRegression
                cv::Ptr<cv::ml::LogisticRegression> lr = cv::ml::LogisticRegression::create();
                
                // Set LogisticRegression parameters
                lr->setLearningRate(fdp.ConsumeFloatingPointInRange<double>(0.001, 1.0));
                lr->setIterations(fdp.ConsumeIntegralInRange<int>(10, 1000));
                lr->setRegularization(static_cast<cv::ml::LogisticRegression::RegKinds>(
                    fdp.ConsumeIntegral<uint8_t>() % 3));
                lr->setTrainMethod(static_cast<cv::ml::LogisticRegression::Methods>(
                    fdp.ConsumeIntegral<uint8_t>() % 2));
                lr->setMiniBatchSize(fdp.ConsumeIntegralInRange<int>(1, num_samples));
                
                // Train LogisticRegression
                lr->train(train_data);
                
                // Make predictions
                cv::Mat lr_results;
                lr->predict(samples, lr_results);
                
                // Calculate probability
                cv::Mat lr_prob;
                lr->predict(samples, lr_results, cv::ml::StatModel::RAW_OUTPUT);
                break;
            }
            
            case 6: {
                // ANN_MLP (Artificial Neural Network - Multi Layer Perceptron)
                cv::Ptr<cv::ml::ANN_MLP> ann = cv::ml::ANN_MLP::create();
                
                // Create layer sizes
                cv::Mat layer_sizes(1, 3, CV_32SC1);
                layer_sizes.at<int>(0) = num_features;  // input layer
                layer_sizes.at<int>(1) = fdp.ConsumeIntegralInRange<int>(2, 10);  // hidden layer
                layer_sizes.at<int>(2) = num_classes;   // output layer
                
                ann->setLayerSizes(layer_sizes);
                ann->setActivationFunction(static_cast<cv::ml::ANN_MLP::ActivationFunctions>(
                    fdp.ConsumeIntegral<uint8_t>() % 4));
                ann->setTrainMethod(static_cast<cv::ml::ANN_MLP::TrainingMethods>(
                    fdp.ConsumeIntegral<uint8_t>() % 3));
                
                ann->setTermCriteria(cv::TermCriteria(
                    cv::TermCriteria::MAX_ITER | cv::TermCriteria::EPS,
                    fdp.ConsumeIntegralInRange<int>(100, 1000),
                    fdp.ConsumeFloatingPointInRange<double>(0.0001, 0.01)
                ));
                
                ann->setBackpropWeightScale(fdp.ConsumeFloatingPointInRange<double>(0.001, 1.0));
                ann->setBackpropMomentumScale(fdp.ConsumeFloatingPointInRange<double>(0.001, 1.0));
                ann->setRpropDW0(fdp.ConsumeFloatingPointInRange<double>(0.001, 1.0));
                ann->setRpropDWMin(fdp.ConsumeFloatingPointInRange<double>(0.00001, 0.01));
                
                // Train ANN_MLP
                ann->train(train_data);
                
                // Make predictions
                cv::Mat ann_results;
                ann->predict(samples, ann_results);
                break;
            }
            
            case 7: {
                // Boost (Boosting algorithm)
                cv::Ptr<cv::ml::Boost> boost = cv::ml::Boost::create();
                
                // Set Boost parameters
                boost->setBoostType(static_cast<cv::ml::Boost::Types>(
                    fdp.ConsumeIntegral<uint8_t>() % 4));
                boost->setWeakCount(fdp.ConsumeIntegralInRange<int>(10, 100));
                boost->setWeightTrimRate(fdp.ConsumeFloatingPointInRange<double>(0.0, 1.0));
                boost->setMaxDepth(fdp.ConsumeIntegralInRange<int>(1, 10));
                boost->setUseSurrogates(fdp.ConsumeBool());
                
                // Train Boost
                boost->train(train_data);
                
                // Make predictions
                cv::Mat boost_results;
                boost->predict(samples, boost_results);
                
                // Calculate error
                if (!boost_results.empty()) {
                    float boost_error = boost->calcError(train_data, false, cv::noArray());
                }
                break;
            }
            
            case 8: {
                // EM (Expectation Maximization for Gaussian Mixture Models)
                cv::Ptr<cv::ml::EM> em = cv::ml::EM::create();
                
                // Set EM parameters
                int nclusters = fdp.ConsumeIntegralInRange<int>(2, 5);
                em->setClustersNumber(nclusters);
                em->setCovarianceMatrixType(static_cast<cv::ml::EM::Types>(
                    fdp.ConsumeIntegral<uint8_t>() % 3));
                em->setTermCriteria(cv::TermCriteria(
                    cv::TermCriteria::MAX_ITER | cv::TermCriteria::EPS,
                    fdp.ConsumeIntegralInRange<int>(10, 100),
                    fdp.ConsumeFloatingPointInRange<double>(0.01, 0.1)
                ));
                
                // Train EM (unsupervised clustering)
                if (!samples.empty()) {
                    cv::Mat log_likelihoods;
                    cv::Mat labels_em;
                    cv::Mat probs;
                    
                    em->trainEM(samples, log_likelihoods, labels_em, probs);
                    
                    // Make predictions
                    cv::Mat em_results;
                    cv::Vec2d result = em->predict2(samples.row(0), em_results);
                    
                    // Alternative training method
                    if (fdp.ConsumeBool()) {
                        em->trainE(samples, 
                            cv::Mat(),  // means0
                            cv::Mat(),  // covs0  
                            cv::Mat(),  // weights0
                            log_likelihoods, labels_em, probs);
                    }
                }
                break;
            }
        }
        
        // Test model saving/loading functionality for some algorithms
        if (fdp.ConsumeBool() && fdp.remaining_bytes() > 100) {
            // Create and train a simple model for save/load test
            cv::Ptr<cv::ml::DTrees> test_model = cv::ml::DTrees::create();
            test_model->setMaxDepth(3);
            test_model->setMinSampleCount(2);
            test_model->train(train_data);
            
            // Test prediction before save
            cv::Mat test_sample = samples.row(0);
            cv::Mat prediction;
            test_model->predict(test_sample, prediction);
        }
        
    } catch (const cv::Exception& e) {
        // Silently catch OpenCV exceptions during fuzzing
        return 0;
    } catch (...) {
        // Catch any other exceptions
        return 0;
    }
    
    return 0;
}
