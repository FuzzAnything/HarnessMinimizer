// Fuzzing harness for OpenCV Object Detection module - Cascade Classifier Operations
// Harness 012: Targets OpenCV objdetect module's Cascade Classifier APIs
// - Creates/uses CascadeClassifier objects with constructor and load() methods
// - Tests detectMultiScale() with various parameter combinations
// - Uses built-in cascade XML files for face/eye detection
// - Creates synthetic test images of different sizes and formats
// - Implements complete object detection pipeline: load classifier → process image → detect objects
// - Tests groupRectangles() for post-processing detected regions
// - Ensures semantic diversity from existing harnesses - while harness_011 targeted ML module
//   and harness_010 targeted FLANN, harness_012 targets computer vision object detection
// - Targets objdetect module which has 0% coverage (709 functions, 15589 lines)

#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <cstring>
#include <algorithm>
#include <fuzzer/FuzzedDataProvider.h>
#include <opencv2/opencv.hpp>
#include <opencv2/objdetect.hpp>
#include <opencv2/imgproc.hpp>
#include <opencv2/imgcodecs.hpp>

using namespace cv;
using namespace std;

// List of built-in cascade classifier files for testing
const std::vector<std::string> CASCADE_FILES = {
    "haarcascade_frontalface_default.xml",
    "haarcascade_frontalface_alt.xml", 
    "haarcascade_frontalface_alt2.xml",
    "haarcascade_frontalface_alt_tree.xml",
    "haarcascade_eye.xml",
    "haarcascade_eye_tree_eyeglasses.xml",
    "haarcascade_lefteye_2splits.xml",
    "haarcascade_righteye_2splits.xml",
    "haarcascade_smile.xml",
    "haarcascade_fullbody.xml"
};

// Helper to create synthetic test images from fuzzer input
Mat createTestImage(FuzzedDataProvider& fdp, int max_width = 640, int max_height = 480) {
    // Consume image dimensions from fuzzer input
    int width = fdp.ConsumeIntegralInRange<int>(32, max_width);
    int height = fdp.ConsumeIntegralInRange<int>(32, max_height);
    
    // Randomly choose image type (grayscale for cascade classifiers)
    int image_type = fdp.ConsumeBool() ? CV_8UC1 : CV_8UC3; // Cascade classifiers work with grayscale
    
    Mat image(height, width, image_type);
    
    if (image.empty()) {
        return Mat();
    }
    
    // Fill image with fuzzer data or random patterns
    size_t bytes_needed = image.total() * image.elemSize();
    
    if (fdp.remaining_bytes() >= bytes_needed && bytes_needed > 0) {
        std::vector<uint8_t> image_data = fdp.ConsumeBytes<uint8_t>(bytes_needed);
        if (image_data.size() == bytes_needed && image.isContinuous()) {
            memcpy(image.data, image_data.data(), bytes_needed);
        } else {
            // Create synthetic patterns if insufficient data
            if (image_type == CV_8UC1) {
                // Grayscale: create gradient or random pattern
                for (int y = 0; y < height; y++) {
                    uint8_t* row = image.ptr<uint8_t>(y);
                    for (int x = 0; x < width; x++) {
                        row[x] = static_cast<uint8_t>((x + y) % 256);
                    }
                }
            } else {
                // Color: create colored rectangles or gradients
                for (int y = 0; y < height; y++) {
                    Vec3b* row = image.ptr<Vec3b>(y);
                    for (int x = 0; x < width; x++) {
                        row[x][0] = static_cast<uint8_t>((x * 255) / width);        // Blue
                        row[x][1] = static_cast<uint8_t>((y * 255) / height);       // Green
                        row[x][2] = static_cast<uint8_t>(((x + y) * 255) / (width + height)); // Red
                    }
                }
            }
        }
    } else {
        // Create default test pattern
        if (image_type == CV_8UC1) {
            rectangle(image, Rect(0, 0, width, height), Scalar(128), -1);
            rectangle(image, Rect(width/4, height/4, width/2, height/2), Scalar(255), -1);
            circle(image, Point(width/2, height/2), min(width, height)/4, Scalar(64), -1);
        } else {
            rectangle(image, Rect(0, 0, width, height), Scalar(128, 128, 128), -1);
            rectangle(image, Rect(width/4, height/4, width/2, height/2), Scalar(255, 0, 0), -1);
            circle(image, Point(width/2, height/2), min(width, height)/4, Scalar(0, 255, 0), -1);
        }
    }
    
    return image;
}

// Helper to get cascade file path from built-in OpenCV data
std::string getCascadeFilePath(const std::string& cascade_name) {
    // Try multiple possible locations for cascade files
    std::vector<std::string> possible_paths = {
        "build/sanitizer/share/opencv4/haarcascades/" + cascade_name,
        "./build/sanitizer/share/opencv4/haarcascades/" + cascade_name,
        "/root/src/opencv/data/haarcascades/" + cascade_name,
        "/usr/local/share/opencv4/haarcascades/" + cascade_name,
        "/usr/share/opencv4/haarcascades/" + cascade_name,
        "/usr/local/share/OpenCV/haarcascades/" + cascade_name,
        "/usr/share/OpenCV/haarcascades/" + cascade_name
    };
    
    for (const auto& path : possible_paths) {
        FILE* f = fopen(path.c_str(), "r");
        if (f) {
            fclose(f);
            return path;
        }
    }
    
    return ""; // File not found
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Need minimum input for meaningful testing
    if (size < 32) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    try {
        // Phase 1: Consume fixed-size parameters for cascade operations
        uint8_t test_scenario = fdp.ConsumeIntegral<uint8_t>() % 4;
        double scale_factor = fdp.ConsumeFloatingPointInRange<double>(1.01, 3.0);
        int min_neighbors = fdp.ConsumeIntegralInRange<int>(0, 10);
        int flags = fdp.ConsumeIntegral<uint8_t>() % 16; // Combination of flag bits
        
        // Consume min and max size parameters
        int min_width = fdp.ConsumeIntegralInRange<int>(10, 100);
        int min_height = fdp.ConsumeIntegralInRange<int>(10, 100);
        int max_width = fdp.ConsumeIntegralInRange<int>(min_width + 1, 200);
        int max_height = fdp.ConsumeIntegralInRange<int>(min_height + 1, 200);
        
        Size min_size(min_width, min_height);
        Size max_size(max_width, max_height);
        
        // Consume groupRectangles parameters
        int group_threshold = fdp.ConsumeIntegralInRange<int>(0, 10);
        double eps = fdp.ConsumeFloatingPointInRange<double>(0.0, 1.0);
        
        // Phase 2: Create test image from remaining input
        Mat test_image = createTestImage(fdp);
        if (test_image.empty()) {
            return 0;
        }
        
        // Convert to grayscale if needed (CascadeClassifier expects grayscale)
        Mat gray_image;
        if (test_image.channels() == 3) {
            cvtColor(test_image, gray_image, COLOR_BGR2GRAY);
        } else {
            gray_image = test_image;
        }
        
        // Ensure image is CV_8U type
        if (gray_image.type() != CV_8UC1) {
            gray_image.convertTo(gray_image, CV_8UC1);
        }
        
        // Phase 3: Test different CascadeClassifier scenarios
        switch (test_scenario) {
            case 0: {
                // Scenario 1: Default constructor then load
                CascadeClassifier classifier;
                
                // Test empty() on unloaded classifier
                bool is_empty = classifier.empty();
                (void)is_empty; // Use variable to avoid warning
                
                // Try to load a cascade file
                if (!CASCADE_FILES.empty()) {
                    size_t cascade_idx = fdp.ConsumeIntegralInRange<size_t>(0, CASCADE_FILES.size() - 1);
                    std::string cascade_path = getCascadeFilePath(CASCADE_FILES[cascade_idx]);
                    
                    if (!cascade_path.empty()) {
                        bool load_success = classifier.load(cascade_path);
                        
                        if (load_success && !classifier.empty()) {
                            // Perform detection if classifier loaded successfully
                            vector<Rect> objects;
                            classifier.detectMultiScale(gray_image, objects, scale_factor, 
                                                       min_neighbors, flags, min_size, max_size);
                            
                            // Test groupRectangles on detected objects
                            if (!objects.empty()) {
                                vector<Rect> grouped_objects = objects;
                                groupRectangles(grouped_objects, group_threshold, eps);
                            }
                        }
                    }
                }
                break;
            }
            
            case 1: {
                // Scenario 2: Constructor with filename
                if (!CASCADE_FILES.empty()) {
                    size_t cascade_idx = fdp.ConsumeIntegralInRange<size_t>(0, CASCADE_FILES.size() - 1);
                    std::string cascade_path = getCascadeFilePath(CASCADE_FILES[cascade_idx]);
                    
                    if (!cascade_path.empty()) {
                        CascadeClassifier classifier(cascade_path);
                        
                        if (!classifier.empty()) {
                            // Test detectMultiScale with numDetections output
                            vector<Rect> objects;
                            vector<int> num_detections;
                            classifier.detectMultiScale(gray_image, objects, num_detections,
                                                       scale_factor, min_neighbors, flags, 
                                                       min_size, max_size);
                            
                            // Test isOldFormatCascade and getOriginalWindowSize
                            bool is_old_format = classifier.isOldFormatCascade();
                            Size orig_window_size = classifier.getOriginalWindowSize();
                            int feature_type = classifier.getFeatureType();
                            
                            (void)is_old_format;
                            (void)orig_window_size;
                            (void)feature_type;
                        }
                    }
                }
                break;
            }
            
            case 2: {
                // Scenario 3: Test multiple overloads of detectMultiScale
                CascadeClassifier classifier;
                
                if (!CASCADE_FILES.empty()) {
                    size_t cascade_idx = fdp.ConsumeIntegralInRange<size_t>(0, CASCADE_FILES.size() - 1);
                    std::string cascade_path = getCascadeFilePath(CASCADE_FILES[cascade_idx]);
                    
                    if (!cascade_path.empty() && classifier.load(cascade_path)) {
                        // Test the third overload with rejectLevels and levelWeights
                        vector<Rect> objects;
                        vector<int> reject_levels;
                        vector<double> level_weights;
                        bool output_reject_levels = fdp.ConsumeBool();
                        
                        classifier.detectMultiScale(gray_image, objects, reject_levels, level_weights,
                                                   scale_factor, min_neighbors, flags,
                                                   min_size, max_size, output_reject_levels);
                        
                        // Test groupRectangles with weights
                        if (!objects.empty()) {
                            vector<Rect> grouped_objects = objects;
                            vector<int> weights;
                            groupRectangles(grouped_objects, weights, group_threshold, eps);
                        }
                    }
                }
                break;
            }
            
            case 3: {
                // Scenario 4: Test with empty/invalid images and edge cases
                CascadeClassifier classifier;
                
                // Test with very small image
                Mat tiny_image(10, 10, CV_8UC1, Scalar(128));
                vector<Rect> tiny_objects;
                
                if (!CASCADE_FILES.empty()) {
                    size_t cascade_idx = fdp.ConsumeIntegralInRange<size_t>(0, CASCADE_FILES.size() - 1);
                    std::string cascade_path = getCascadeFilePath(CASCADE_FILES[cascade_idx]);
                    
                    if (!cascade_path.empty() && classifier.load(cascade_path)) {
                        classifier.detectMultiScale(tiny_image, tiny_objects, 1.1, 3, 0, 
                                                   Size(20, 20), Size(20, 20));
                        
                        // Test with extreme parameters
                        vector<Rect> extreme_objects;
                        classifier.detectMultiScale(gray_image, extreme_objects, 
                                                   3.0,  // Very aggressive scaling
                                                   0,    // No neighbor filtering  
                                                   CASCADE_FIND_BIGGEST_OBJECT | CASCADE_SCALE_IMAGE,
                                                   Size(1, 1), Size());
                    }
                }
                break;
            }
        }
        
        // Phase 4: Test standalone groupRectangles function with synthetic rectangles
        if (fdp.remaining_bytes() > sizeof(int) * 4 * 10) { // Enough for 10 rectangles
            vector<Rect> synthetic_rects;
            int num_rects = fdp.ConsumeIntegralInRange<int>(1, 20);
            
            for (int i = 0; i < num_rects && fdp.remaining_bytes() >= sizeof(int) * 4; i++) {
                int x = fdp.ConsumeIntegralInRange<int>(0, gray_image.cols - 1);
                int y = fdp.ConsumeIntegralInRange<int>(0, gray_image.rows - 1);
                int width = fdp.ConsumeIntegralInRange<int>(1, gray_image.cols - x);
                int height = fdp.ConsumeIntegralInRange<int>(1, gray_image.rows - y);
                synthetic_rects.push_back(Rect(x, y, width, height));
            }
            
            if (!synthetic_rects.empty()) {
                // Test different groupRectangles overloads
                vector<Rect> grouped1 = synthetic_rects;
                groupRectangles(grouped1, group_threshold, eps);
                
                vector<Rect> grouped2 = synthetic_rects;
                vector<int> weights;
                groupRectangles(grouped2, weights, group_threshold, eps);
                
                // Test with level weights (simulate detection confidence)
                if (synthetic_rects.size() >= 3 && fdp.remaining_bytes() > sizeof(double) * synthetic_rects.size()) {
                    vector<Rect> grouped3 = synthetic_rects;
                    vector<int> reject_levels(synthetic_rects.size(), 1);
                    vector<double> level_weights;
                    
                    for (size_t i = 0; i < synthetic_rects.size(); i++) {
                        level_weights.push_back(fdp.ConsumeFloatingPointInRange<double>(0.0, 1.0));
                    }
                    
                    groupRectangles(grouped3, reject_levels, level_weights, group_threshold, eps);
                }
            }
        }
        
    } catch (const cv::Exception& e) {
        // Catch OpenCV exceptions - acceptable in fuzzing
        (void)e;
    } catch (...) {
        // Catch any other exceptions - acceptable for fuzzing
    }
    
    return 0;
}
