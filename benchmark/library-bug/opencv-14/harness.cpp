#include <opencv4/opencv2/features2d.hpp>
#include <opencv4/opencv2/imgproc.hpp>
#include <opencv4/opencv2/core.hpp>
#include <fuzzer/FuzzedDataProvider.h>

#include <cstdint>
#include <cstdlib>
#include <vector>
#include <string>
#include <algorithm>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check: need enough bytes for image dimensions, parameters, and image data
    // We need data for 2 images (grayscale) plus various detector parameters
    if (size < 1024) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Step 1: Consume fixed-size data for image dimensions and algorithm selection
    int img_width = fdp.ConsumeIntegralInRange<int>(32, 256);
    int img_height = fdp.ConsumeIntegralInRange<int>(32, 256);
    int detector_type = fdp.ConsumeIntegralInRange<int>(0, 5); // 0: BRISK, 1: FAST, 2: AKAZE, 3: MSER, 4: GFTT, 5: Agast
    
    // Step 2: Calculate required bytes for two synthetic grayscale images
    size_t image_data_size = img_width * img_height;  // Grayscale only
    size_t total_image_bytes = 2 * image_data_size;
    
    // Check if we have enough data for both images
    if (fdp.remaining_bytes() < total_image_bytes) {
        return 0;
    }
    
    // Create synthetic grayscale images from fuzzer input
    std::vector<uint8_t> image1_data = fdp.ConsumeBytes<uint8_t>(image_data_size);
    std::vector<uint8_t> image2_data = fdp.ConsumeBytes<uint8_t>(image_data_size);
    
    cv::Mat image1(img_height, img_width, CV_8UC1, image1_data.data());
    cv::Mat image2(img_height, img_width, CV_8UC1, image2_data.data());
    
    // Ensure images are continuous in memory
    if (!image1.isContinuous()) {
        image1 = image1.clone();
    }
    if (!image2.isContinuous()) {
        image2 = image2.clone();
    }
    
    try {
        // Step 3: Create feature detector based on fuzzed type
        cv::Ptr<cv::Feature2D> detector;
        
        switch (detector_type) {
            case 0: { // BRISK detector
                int thresh = fdp.ConsumeIntegralInRange<int>(10, 100);
                int octaves = fdp.ConsumeIntegralInRange<int>(0, 5);
                float patternScale = fdp.ConsumeFloatingPointInRange<float>(0.5f, 2.0f);
                
                detector = cv::BRISK::create(thresh, octaves, patternScale);
                break;
            }
            case 1: { // FAST detector
                int threshold = fdp.ConsumeIntegralInRange<int>(5, 50);
                bool nonmaxSuppression = fdp.ConsumeBool();
                int type_choice = fdp.ConsumeIntegralInRange<int>(0, 2);
                cv::FastFeatureDetector::DetectorType type;
                switch (type_choice) {
                    case 0: type = cv::FastFeatureDetector::TYPE_5_8; break;
                    case 1: type = cv::FastFeatureDetector::TYPE_7_12; break;
                    case 2: type = cv::FastFeatureDetector::TYPE_9_16; break;
                    default: type = cv::FastFeatureDetector::TYPE_9_16; break;
                }
                
                detector = cv::FastFeatureDetector::create(threshold, nonmaxSuppression, type);
                break;
            }
            case 2: { // AKAZE detector
                int descriptor_type_choice = fdp.ConsumeIntegralInRange<int>(0, 2);
                cv::AKAZE::DescriptorType descriptor_type;
                switch (descriptor_type_choice) {
                    case 0: descriptor_type = cv::AKAZE::DESCRIPTOR_KAZE_UPRIGHT; break;
                    case 1: descriptor_type = cv::AKAZE::DESCRIPTOR_KAZE; break;
                    case 2: descriptor_type = cv::AKAZE::DESCRIPTOR_MLDB_UPRIGHT; break;
                    default: descriptor_type = cv::AKAZE::DESCRIPTOR_MLDB; break;
                }
                
                int descriptor_size = fdp.ConsumeIntegralInRange<int>(0, 2);
                int descriptor_channels = fdp.ConsumeIntegralInRange<int>(1, 3);
                float threshold = fdp.ConsumeFloatingPointInRange<float>(0.001f, 0.1f);
                int nOctaves = fdp.ConsumeIntegralInRange<int>(2, 6);
                int nOctaveLayers = fdp.ConsumeIntegralInRange<int>(2, 6);
                int diffusivity = fdp.ConsumeIntegralInRange<int>(0, 2);
                
                detector = cv::AKAZE::create(descriptor_type, descriptor_size, descriptor_channels,
                                           threshold, nOctaves, nOctaveLayers,
                                           static_cast<cv::KAZE::DiffusivityType>(diffusivity));
                break;
            }
            case 3: { // MSER detector
                int delta = fdp.ConsumeIntegralInRange<int>(1, 20);
                int min_area = fdp.ConsumeIntegralInRange<int>(10, 1000);
                int max_area = fdp.ConsumeIntegralInRange<int>(1000, 50000);
                double max_variation = fdp.ConsumeFloatingPointInRange<double>(0.1, 1.0);
                double min_diversity = fdp.ConsumeFloatingPointInRange<double>(0.1, 1.0);
                int max_evolution = fdp.ConsumeIntegralInRange<int>(50, 300);
                double area_threshold = fdp.ConsumeFloatingPointInRange<double>(1.0, 5.0);
                double min_margin = fdp.ConsumeFloatingPointInRange<double>(0.001, 0.1);
                int edge_blur_size = fdp.ConsumeIntegralInRange<int>(1, 10);
                
                detector = cv::MSER::create(delta, min_area, max_area, max_variation,
                                          min_diversity, max_evolution, area_threshold,
                                          min_margin, edge_blur_size);
                break;
            }
            case 4: { // GFTT (Good Features To Track) detector
                int maxCorners = fdp.ConsumeIntegralInRange<int>(10, 1000);
                double qualityLevel = fdp.ConsumeFloatingPointInRange<double>(0.001, 0.1);
                double minDistance = fdp.ConsumeFloatingPointInRange<double>(1.0, 20.0);
                int blockSize = fdp.ConsumeIntegralInRange<int>(3, 11);
                bool useHarrisDetector = fdp.ConsumeBool();
                double k = fdp.ConsumeFloatingPointInRange<double>(0.01, 0.1);
                
                detector = cv::GFTTDetector::create(maxCorners, qualityLevel, minDistance,
                                                  blockSize, useHarrisDetector, k);
                break;
            }
            case 5: { // Agast detector
                int threshold = fdp.ConsumeIntegralInRange<int>(5, 50);
                bool nonmaxSuppression = fdp.ConsumeBool();
                int type_choice = fdp.ConsumeIntegralInRange<int>(0, 3);
                cv::AgastFeatureDetector::DetectorType type;
                switch (type_choice) {
                    case 0: type = cv::AgastFeatureDetector::AGAST_5_8; break;
                    case 1: type = cv::AgastFeatureDetector::AGAST_7_12d; break;
                    case 2: type = cv::AgastFeatureDetector::AGAST_7_12s; break;
                    case 3: type = cv::AgastFeatureDetector::OAST_9_16; break;
                    default: type = cv::AgastFeatureDetector::OAST_9_16; break;
                }
                
                detector = cv::AgastFeatureDetector::create(threshold, nonmaxSuppression, type);
                break;
            }
            default: {
                // Default to FAST detector
                detector = cv::FastFeatureDetector::create(10, true);
                break;
            }
        }
        // Step 4: Detect keypoints in both images
        std::vector<cv::KeyPoint> keypoints1, keypoints2;
        
        // Use detect method for all detectors including MSER
        detector->detect(image1, keypoints1);
        detector->detect(image2, keypoints2);
        
        // For MSER, also test detectRegions method
        if (detector_type == 3) { // MSER
            cv::Ptr<cv::MSER> mser_detector = detector.dynamicCast<cv::MSER>();
            if (mser_detector) {
                std::vector<std::vector<cv::Point>> regions1, regions2;
                std::vector<cv::Rect> bboxes1, bboxes2;
                mser_detector->detectRegions(image1, regions1, bboxes1);
                mser_detector->detectRegions(image2, regions2, bboxes2);
            }
        }
        
        // Step 5: Test KeyPointsFilter functions
        if (!keypoints1.empty()) {
            // Filter by image border
            int borderSize = fdp.ConsumeIntegralInRange<int>(1, 20);
            std::vector<cv::KeyPoint> filtered_border = keypoints1;
            cv::KeyPointsFilter::runByImageBorder(filtered_border, cv::Size(img_width, img_height), borderSize);
            
            // Filter by keypoint size
            float minSize = fdp.ConsumeFloatingPointInRange<float>(1.0f, 10.0f);
            float maxSize = fdp.ConsumeFloatingPointInRange<float>(10.0f, 50.0f);
            std::vector<cv::KeyPoint> filtered_size = keypoints1;
            cv::KeyPointsFilter::runByKeypointSize(filtered_size, minSize, maxSize);
            
            // Remove duplicated keypoints
            std::vector<cv::KeyPoint> deduplicated = keypoints1;
            cv::KeyPointsFilter::removeDuplicated(deduplicated);
            
            // Retain best keypoints
            std::vector<cv::KeyPoint> best_keypoints = keypoints1;
            int npoints = fdp.ConsumeIntegralInRange<int>(1, std::min(100, (int)best_keypoints.size()));
            cv::KeyPointsFilter::retainBest(best_keypoints, npoints);
        }
        
        // Step 6: Test descriptor computation if detector supports it
        if (detector_type != 1 && detector_type != 5 && detector_type != 4) {
            // BRISK, AKAZE, and MSER support descriptor computation
            cv::Mat descriptors1, descriptors2;
            
            if (!keypoints1.empty()) {
                detector->compute(image1, keypoints1, descriptors1);
            }
            if (!keypoints2.empty()) {
                detector->compute(image2, keypoints2, descriptors2);
            }
            
            // Step 7: Test matching if we have descriptors
            if (!descriptors1.empty() && !descriptors2.empty()) {
                // Choose matcher type based on detector
                int matcher_type = fdp.ConsumeIntegralInRange<int>(0, 1); // 0: BFMatcher, 1: FlannBasedMatcher
                cv::Ptr<cv::DescriptorMatcher> matcher;
                
                if (matcher_type == 0) {
                    // BFMatcher
                    int normType;
                    if (detector_type == 0 || detector_type == 2) { // BRISK or AKAZE
                        normType = cv::NORM_HAMMING;
                    } else {
                        normType = cv::NORM_L2;
                    }
                    bool crossCheck = fdp.ConsumeBool();
                    matcher = cv::BFMatcher::create(normType, crossCheck);
                } else {
                    // FlannBasedMatcher
                    matcher = cv::FlannBasedMatcher::create();
                }
                
                // Test different matching methods
                std::vector<cv::DMatch> matches;
                matcher->match(descriptors1, descriptors2, matches);
                
                // Test knnMatch
                if (matches.size() > 2) {
                    int k = fdp.ConsumeIntegralInRange<int>(1, std::min(3, (int)matches.size()));
                    std::vector<std::vector<cv::DMatch>> knn_matches;
                    matcher->knnMatch(descriptors1, descriptors2, knn_matches, k);
                }
                
                // Test radiusMatch
                if (!matches.empty()) {
                    float max_distance = fdp.ConsumeFloatingPointInRange<float>(10.0f, 100.0f);
                    std::vector<std::vector<cv::DMatch>> radius_matches;
                    matcher->radiusMatch(descriptors1, descriptors2, radius_matches, max_distance);
                }
            }
        }
        
        // Step 8: Test individual detect and compute for detectors that support both
        if (detector_type == 0 || detector_type == 2) { // BRISK or AKAZE
            // Test detectAndCompute method
            std::vector<cv::KeyPoint> det_keypoints1, det_keypoints2;
            cv::Mat det_descriptors1, det_descriptors2;
            
            detector->detectAndCompute(image1, cv::noArray(), det_keypoints1, det_descriptors1);
            detector->detectAndCompute(image2, cv::noArray(), det_keypoints2, det_descriptors2);
        }
        
        // Step 9: Test drawing functions
        if (!keypoints1.empty()) {
            cv::Mat keypoint_image;
            int draw_mode = fdp.ConsumeIntegralInRange<int>(0, 2);
            cv::DrawMatchesFlags flags;
            
            switch (draw_mode) {
                case 0: flags = cv::DrawMatchesFlags::DEFAULT; break;
                case 1: flags = cv::DrawMatchesFlags::DRAW_RICH_KEYPOINTS; break;
                case 2: flags = cv::DrawMatchesFlags::NOT_DRAW_SINGLE_POINTS; break;
                default: flags = cv::DrawMatchesFlags::DEFAULT; break;
            }
            
            cv::drawKeypoints(image1, keypoints1, keypoint_image,
                             cv::Scalar::all(-1), flags);
        }
        
    } catch (const cv::Exception& e) {
        // OpenCV exceptions are expected during fuzzing
        return 0;
    } catch (...) {
        // Catch any other exceptions
        return 0;
    }
    
    return 0;
}
