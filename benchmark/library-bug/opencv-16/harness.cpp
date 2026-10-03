#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <algorithm>
#include <fuzzer/FuzzedDataProvider.h>

#include <opencv2/core/core_c.h>
#include <opencv2/imgproc/imgproc_c.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum input size check - need enough for basic parameters and some image data
    if (size < 32) return 0;
    
    FuzzedDataProvider fdp(data, size);
    
    // Consume image dimensions
    int width = fdp.ConsumeIntegralInRange<int>(10, 500);
    int height = fdp.ConsumeIntegralInRange<int>(10, 500);
    CvSize image_size = cvSize(width, height);
    
    // Consume operation type to test different edge detection and contour analysis paths
    uint8_t operation = fdp.ConsumeIntegral<uint8_t>() % 4;
    
    // Consume parameters for Canny edge detection
    double threshold1 = fdp.ConsumeFloatingPointInRange<double>(0.0, 255.0);
    double threshold2 = fdp.ConsumeFloatingPointInRange<double>(0.0, 255.0);
    int aperture_size = fdp.ConsumeIntegralInRange<int>(3, 7);
    if (aperture_size % 2 == 0) aperture_size++; // Ensure odd aperture size
    // Consume parameters for contour drawing
    CvScalar external_color = cvScalar(
        fdp.ConsumeIntegralInRange<int>(0, 255),
        fdp.ConsumeIntegralInRange<int>(0, 255),
        fdp.ConsumeIntegralInRange<int>(0, 255),
        0
    );
    CvScalar hole_color = cvScalar(
        fdp.ConsumeIntegralInRange<int>(0, 255),
        fdp.ConsumeIntegralInRange<int>(0, 255),
        fdp.ConsumeIntegralInRange<int>(0, 255),
        0
    );
    int max_level = fdp.ConsumeIntegralInRange<int>(0, 5);
    int thickness = fdp.ConsumeIntegralInRange<int>(1, 5);
    int line_type = fdp.ConsumeIntegral<uint8_t>() % 4;
    
    // Create memory storage for contours
    CvMemStorage* storage = cvCreateMemStorage(0);
    if (!storage) return 0;
    
    // Create input image (grayscale for edge detection)
    IplImage* src_image = cvCreateImage(image_size, IPL_DEPTH_8U, 1);
    if (!src_image) {
        cvReleaseMemStorage(&storage);
        return 0;
    }
    
    // Fill image with random data from fuzzer input
    size_t image_data_size = src_image->width * src_image->height * src_image->nChannels;
    if (fdp.remaining_bytes() < image_data_size) {
        cvReleaseImage(&src_image);
        cvReleaseMemStorage(&storage);
        return 0;
    }
    
    std::vector<uint8_t> image_data = fdp.ConsumeBytes<uint8_t>(image_data_size);
    memcpy(src_image->imageData, image_data.data(), image_data_size);
    
    // Create output image for edge detection
    IplImage* edge_image = cvCreateImage(image_size, IPL_DEPTH_8U, 1);
    if (!edge_image) {
        cvReleaseImage(&src_image);
        cvReleaseMemStorage(&storage);
        return 0;
    }
    
    // Create output image for contour drawing
    IplImage* contour_image = cvCreateImage(image_size, IPL_DEPTH_8U, 3); // 3-channel for color drawing
    if (!contour_image) {
        cvReleaseImage(&src_image);
        cvReleaseImage(&edge_image);
        cvReleaseMemStorage(&storage);
        return 0;
    }
    
    // Initialize contour image with black background
    cvSet(contour_image, cvScalarAll(0), NULL);
    // Test different edge detection and contour analysis workflows
    CvSeq* first_contour = NULL;
    int num_contours = 0;
    
    switch (operation) {
        case 0: {
            // Basic Canny edge detection
            cvCanny(src_image, edge_image, threshold1, threshold2, aperture_size);
            
            // Find contours in edge image
            num_contours = cvFindContours(
                edge_image, storage, &first_contour,
                sizeof(CvContour), CV_RETR_LIST, CV_CHAIN_APPROX_SIMPLE, cvPoint(0, 0)
            );
            
            // Draw all contours on contour image
            if (first_contour) {
                cvDrawContours(
                    contour_image, first_contour, external_color, hole_color,
                    max_level, thickness, line_type, cvPoint(0, 0)
                );
            }
            break;
        }
        
        case 1: {
            // Canny with different threshold ratio
            double adjusted_threshold1 = threshold1;
            double adjusted_threshold2 = threshold1 * 2.0; // Standard ratio
            cvCanny(src_image, edge_image, adjusted_threshold1, adjusted_threshold2, aperture_size);
            
            // Find contours with tree retrieval mode
            num_contours = cvFindContours(
                edge_image, storage, &first_contour,
                sizeof(CvContour), CV_RETR_TREE, CV_CHAIN_APPROX_SIMPLE, cvPoint(0, 0)
            );
            
            // Draw contours with different max_level
            if (first_contour) {
                cvDrawContours(
                    contour_image, first_contour, external_color, hole_color,
                    1, thickness, line_type, cvPoint(0, 0) // Only first level
                );
            }
            break;
        }
        
        case 2: {
            // Canny with very low thresholds for more edges
            cvCanny(src_image, edge_image, 10.0, 30.0, aperture_size);
            
            // Find contours with external retrieval mode
            num_contours = cvFindContours(
                edge_image, storage, &first_contour,
                sizeof(CvContour), CV_RETR_EXTERNAL, CV_CHAIN_APPROX_SIMPLE, cvPoint(0, 0)
            );
            
            // Draw contours with thick lines
            if (first_contour) {
                cvDrawContours(
                    contour_image, first_contour, external_color, hole_color,
                    max_level, 3, line_type, cvPoint(0, 0) // Thicker lines
                );
            }
            break;
        }
        
        case 3: {
            // Canny with high thresholds for fewer edges
            cvCanny(src_image, edge_image, 100.0, 200.0, aperture_size);
            
            // Find contours with approximated chains
            num_contours = cvFindContours(
                edge_image, storage, &first_contour,
                sizeof(CvContour), CV_RETR_LIST, CV_CHAIN_APPROX_TC89_L1, cvPoint(0, 0)
            );
            
            // Draw contours with offset
            CvPoint offset = cvPoint(
                fdp.ConsumeIntegralInRange<int>(-10, 10),
                fdp.ConsumeIntegralInRange<int>(-10, 10)
            );
            
            if (first_contour) {
                cvDrawContours(
                    contour_image, first_contour, external_color, hole_color,
                    max_level, thickness, line_type, offset
                );
            }
            break;
        }
    }
    
    // Test additional contour operations if contours were found
    if (first_contour && num_contours > 0) {
        // Calculate total contour area and perimeter
        double total_area = 0.0;
        double total_perimeter = 0.0;
        
        CvSeq* contour = first_contour;
        while (contour) {
            double area = fabs(cvContourArea(contour, CV_WHOLE_SEQ));
            double perimeter = cvArcLength(contour, CV_WHOLE_SEQ, 1);
            
            total_area += area;
            total_perimeter += perimeter;
            
            // Get bounding rectangle
            CvRect bbox = cvBoundingRect(contour);
            
            // Get minimal enclosing circle
            CvPoint2D32f center;
            float radius;
            cvMinEnclosingCircle(contour, &center, &radius);
            
            contour = contour->h_next;
        }
        
        // Test contour moments if we have contours
        if (first_contour) {
            CvMoments moments;
            cvMoments(first_contour, &moments, 0);
            
            // Calculate some moment-based features
            double m00 = cvGetSpatialMoment(&moments, 0, 0);
            double m10 = cvGetSpatialMoment(&moments, 1, 0);
            double m01 = cvGetSpatialMoment(&moments, 0, 1);
            
            if (m00 > 0) {
                double cx = m10 / m00;
                double cy = m01 / m00;
            }
        }
    }
    
    // Test edge image properties
    if (!edge_image->imageData) {
        // Edge image should have data
    }
    
    // Test contour image properties  
    if (!contour_image->imageData) {
        // Contour image should have data
    }
    
    // Clean up all resources
    cvReleaseMemStorage(&storage);
    cvReleaseImage(&src_image);
    cvReleaseImage(&edge_image);
    cvReleaseImage(&contour_image);
    
    return 0;
}
