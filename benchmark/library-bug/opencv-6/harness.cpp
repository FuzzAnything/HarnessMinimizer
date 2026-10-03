#include <cstddef>
#include <cstdint>
#include <vector>
#include <opencv2/core.hpp>
#include <opencv2/imgproc.hpp>
#include <opencv2/features2d.hpp>
#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 50) return 0;  // Minimum size for meaningful testing

  FuzzedDataProvider fdp(data, size);

  try {
    // Create a simple synthetic image for testing
    int width = fdp.ConsumeIntegralInRange<int>(10, 100);
    int height = fdp.ConsumeIntegralInRange<int>(10, 100);
    int channels = fdp.ConsumeBool() ? 1 : 3;
    int cv_type = (channels == 1) ? CV_8UC1 : CV_8UC3;
    
    cv::Mat image(height, width, cv_type);
    
    // Fill image with random data
    size_t bytes_needed = image.total() * image.elemSize();
    if (fdp.remaining_bytes() < bytes_needed) {
      return 0;
    }
    std::vector<uint8_t> image_data = fdp.ConsumeBytes<uint8_t>(bytes_needed);
    memcpy(image.data, image_data.data(), bytes_needed);

    // Simple morphology operation if single channel
    if (image.channels() == 1 && fdp.ConsumeBool()) {
      cv::Mat morphed;
      int kernel_size = fdp.ConsumeIntegralInRange<int>(1, 5);
      if (kernel_size % 2 == 0) kernel_size++;
      cv::Mat kernel = cv::getStructuringElement(
        cv::MORPH_RECT, 
        cv::Size(kernel_size, kernel_size)
      );
      int op_type = fdp.ConsumeIntegralInRange<int>(0, 2);
      cv::MorphTypes morph_op;
      switch (op_type) {
        case 0: morph_op = cv::MORPH_ERODE; break;
        case 1: morph_op = cv::MORPH_DILATE; break;
        case 2: morph_op = cv::MORPH_OPEN; break;
        default: morph_op = cv::MORPH_ERODE; break;
      }
      cv::morphologyEx(image, morphed, morph_op, kernel);
    }

    // BRISK feature detection
    int thresh = fdp.ConsumeIntegralInRange<int>(5, 50);
    int octaves = fdp.ConsumeIntegralInRange<int>(0, 3);
    float patternScale = fdp.ConsumeFloatingPointInRange<float>(0.5f, 1.5f);
    
    cv::Ptr<cv::BRISK> brisk_detector = cv::BRISK::create(thresh, octaves, patternScale);
    if (!brisk_detector) return 0;
    
    std::vector<cv::KeyPoint> keypoints;
    cv::Mat descriptors;
    
    brisk_detector->detectAndCompute(image, cv::noArray(), keypoints, descriptors);

    // Simple test of parameter getters
    if (fdp.ConsumeBool() && keypoints.size() > 0) {
      int current_thresh = brisk_detector->getThreshold();
      int current_octaves = brisk_detector->getOctaves();
      float current_patternScale = brisk_detector->getPatternScale();
    }

  } catch (cv::Exception& e) {
    // Ignore OpenCV exceptions during fuzzing
  } catch (...) {
    // Catch any other exceptions
  }

  return 0;
}
