// Fuzzing harness for OpenCV stitching module (image stitching/panorama creation)
// Harness 015: Targets stitching module which currently has 0% coverage
// - Tests Stitcher::create for stitcher initialization
// - Tests Stitcher::stitch for panoramic image stitching
// - Tests Stitcher::estimateTransform for transform estimation
// - Tests imdecode for image loading from memory
// - Focuses on image stitching/panorama creation rather than previous targets
// - Provides semantic diversity compared to existing harnesses (image processing, calibration, features, GUI)

#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>
#include <algorithm>
#include <memory>
#include <fuzzer/FuzzedDataProvider.h>
#include <opencv2/opencv.hpp>
#include <opencv2/stitching.hpp>

using namespace cv;
using namespace std;

// Helper function to create a synthetic test image with a simple pattern
// This creates images that can be stitched together (shifted patterns to simulate overlapping views)
Mat createSyntheticTestImage(int width, int height, int pattern_id, int x_offset = 0, int y_offset = 0) {
    Mat image(height, width, CV_8UC3, Scalar(128, 128, 128));  // Gray background
    
    // Different patterns for different "views"
    switch (pattern_id % 4) {
        case 0:
            // Pattern 0: Simple colored rectangles
            rectangle(image, 
                     Rect(10 + x_offset, 10 + y_offset, width/3, height/3), 
                     Scalar(255, 0, 0), -1);  // Blue rectangle
            rectangle(image, 
                     Rect(width/2 + x_offset, height/2 + y_offset, width/4, height/4), 
                     Scalar(0, 255, 0), -1);  // Green rectangle
            break;
        case 1:
            // Pattern 1: Circles
            circle(image, 
                  Point(width/2 + x_offset, height/2 + y_offset), 
                  std::min(width, height)/4, 
                  Scalar(0, 0, 255), -1);  // Red circle
            circle(image, 
                  Point(width/4 + x_offset, height/4 + y_offset), 
                  std::min(width, height)/6, 
                  Scalar(255, 255, 0), -1);  // Cyan circle
            break;
        case 2:
            // Pattern 2: Lines and texturing
            for (int i = 0; i < 5; i++) {
                line(image, 
                    Point(i * width/5 + x_offset, 0 + y_offset), 
                    Point((i+1) * width/5 + x_offset, height + y_offset), 
                    Scalar(255, 255 * i/5, 0), 2);
            }
            break;
        case 3:
            // Pattern 3: Checkerboard-like pattern
            for (int y = 0; y < height; y += 20) {
                for (int x = 0; x < width; x += 20) {
                    if (((x/20 + y/20) % 2) == 0) {
                        rectangle(image, 
                                 Rect(x + x_offset, y + y_offset, 20, 20), 
                                 Scalar(255, 200, 100), -1);
                    }
                }
            }
            break;
    }
    
    return image;
}

// Helper to generate multiple overlapping images for stitching
vector<Mat> generateTestImagesForStitching(FuzzedDataProvider& fdp) {
    vector<Mat> images;
    
    // Consume parameters for image generation
    int num_images = fdp.ConsumeIntegralInRange<int>(2, 5);  // Need at least 2 images for stitching
    int base_width = fdp.ConsumeIntegralInRange<int>(100, 400);
    int base_height = fdp.ConsumeIntegralInRange<int>(100, 300);
    
    // Generate images with overlapping patterns
    for (int i = 0; i < num_images; i++) {
        // Create offset to simulate camera movement (overlapping images)
        int x_offset = fdp.ConsumeIntegralInRange<int>(-base_width/4, base_width/4);
        int y_offset = fdp.ConsumeIntegralInRange<int>(-base_height/4, base_height/4);
        
        Mat img = createSyntheticTestImage(base_width, base_height, i, x_offset, y_offset);
        images.push_back(img);
    }
    
    return images;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum input size check - we need enough data for parameters
    if (size < 32) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    try {
        // ==============================================
        // TEST 1: Image loading from memory using imdecode
        // ==============================================
        vector<Mat> decoded_images;
        if (fdp.remaining_bytes() > 100) {
            // Try to decode image data from fuzzer input
            size_t image_data_size = fdp.ConsumeIntegralInRange<size_t>(10, std::min<size_t>(fdp.remaining_bytes(), static_cast<size_t>(10000)));
            vector<uint8_t> image_data = fdp.ConsumeBytes<uint8_t>(image_data_size);
            
            if (!image_data.empty()) {
                // Try decoding as image
                Mat decoded = imdecode(image_data, IMREAD_COLOR);
                if (!decoded.empty()) {
                    decoded_images.push_back(decoded);
                }
                
                // Try with different flags
                Mat decoded_grayscale = imdecode(image_data, IMREAD_GRAYSCALE);
                if (!decoded_grayscale.empty()) {
                    decoded_images.push_back(decoded_grayscale);
                }
            }
        }
        
        // ==============================================
        // TEST 2: Generate synthetic test images for stitching
        // ==============================================
        vector<Mat> synthetic_images = generateTestImagesForStitching(fdp);
        
        // Combine decoded and synthetic images for testing
        vector<Mat> all_images = synthetic_images;
        all_images.insert(all_images.end(), decoded_images.begin(), decoded_images.end());
        
        // Need at least 2 images for stitching
        if (all_images.size() < 2) {
            // Create at least 2 synthetic images if we don't have enough
            while (all_images.size() < 2) {
                Mat img = createSyntheticTestImage(200, 150, all_images.size());
                all_images.push_back(img);
            }
        }
        
        // ==============================================
        // TEST 3: Stitcher creation and configuration
        // ==============================================
        
        // Consume stitcher mode from fuzzer input
        int mode_selector = fdp.ConsumeIntegral<uint8_t>() % 2;
        Stitcher::Mode mode = (mode_selector == 0) ? Stitcher::PANORAMA : Stitcher::SCANS;
        
        // Create stitcher
        Ptr<Stitcher> stitcher = Stitcher::create(mode);
        if (!stitcher) {
            return 0;  // Failed to create stitcher
        }
        
        // Configure stitcher parameters from fuzzer input
        if (fdp.remaining_bytes() > 0) {
            double registration_resol = fdp.ConsumeFloatingPointInRange<double>(0.1, 1.0);
            stitcher->setRegistrationResol(registration_resol);
        }
        
        if (fdp.remaining_bytes() > 0) {
            double seam_resol = fdp.ConsumeFloatingPointInRange<double>(0.1, 1.0);
            stitcher->setSeamEstimationResol(seam_resol);
        }
        
        if (fdp.remaining_bytes() > 0) {
            bool wave_correction = fdp.ConsumeBool();
            stitcher->setWaveCorrection(wave_correction);
        }
        
        // ==============================================
        // TEST 4: Estimate transform (optional pipeline step)
        // ==============================================
        if (all_images.size() >= 2 && fdp.ConsumeBool()) {
            Stitcher::Status est_status = stitcher->estimateTransform(all_images);
            // Note: We don't check status as estimateTransform may fail with synthetic images
            // This is okay - we're testing the API call itself
        }
        
        // ==============================================
        // TEST 5: Main stitching operation
        // ==============================================
        Mat panorama;
        Stitcher::Status stitch_status = stitcher->stitch(all_images, panorama);
        
        // Check status and handle different outcomes
        switch (stitch_status) {
            case Stitcher::OK:
                // Successfully stitched - panorama should be valid
                if (!panorama.empty()) {
                    // Test some basic operations on the result
                    Size panorama_size = panorama.size();
                    int channels = panorama.channels();
                    // Just accessing these properties exercises more code
                }
                break;
                
            case Stitcher::ERR_NEED_MORE_IMGS:
                // Not enough images or images don't overlap enough
                // This is expected with synthetic images
                break;
                
            case Stitcher::ERR_HOMOGRAPHY_EST_FAIL:
                // Homography estimation failed
                // Expected with random/synthetic images
                break;
                
            case Stitcher::ERR_CAMERA_PARAMS_ADJUST_FAIL:
                // Camera parameter adjustment failed
                // Expected with synthetic images
                break;
        }
        
        // ==============================================
        // TEST 6: Alternative stitching with masks
        // ==============================================
        if (fdp.remaining_bytes() > 0 && fdp.ConsumeBool()) {
            // Create simple masks for images
            vector<Mat> masks;
            for (size_t i = 0; i < all_images.size(); i++) {
                // Create a simple mask (all white = use entire image)
                Mat mask(all_images[i].size(), CV_8U, Scalar(255));
                masks.push_back(mask);
            }
            
            Mat panorama_with_mask;
            stitcher->stitch(all_images, masks, panorama_with_mask);
            // Don't check result - just exercise the API
        }
        
        // ==============================================
        // TEST 7: Compose panorama separately
        // ==============================================
        if (fdp.remaining_bytes() > 0 && fdp.ConsumeBool()) {
            // First estimate transform
            stitcher->estimateTransform(all_images);
            
            // Then compose
            Mat composed_pano;
            stitcher->composePanorama(composed_pano);
            // Don't check result - just exercise the API
        }
        
    } catch (const cv::Exception& e) {
        // Catch OpenCV exceptions - these are expected during fuzzing
        // with invalid/random input
    } catch (...) {
        // Catch any other exceptions
    }
    
    return 0;
}
