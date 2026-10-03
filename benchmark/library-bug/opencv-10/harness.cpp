#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include <opencv4/opencv2/core.hpp>
#include <opencv4/opencv2/videoio.hpp>
#include <opencv4/opencv2/imgproc.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check: need enough data for basic video parameters and frame data
    if (size < 128) return 0;
    
    FuzzedDataProvider fdp(data, size);
    
    try {
        // Step 1: Create synthetic frame (cv::Mat) for testing
        // Consume frame dimensions from fuzzer input
        int frame_width = fdp.ConsumeIntegralInRange<int>(1, 256);  // Limit to reasonable size
        int frame_height = fdp.ConsumeIntegralInRange<int>(1, 256);
        int frame_channels = fdp.ConsumeIntegralInRange<int>(1, 4); // 1-4 channels
        int frame_type = CV_8UC(frame_channels);  // Use 8-bit unsigned
        
        // Calculate required bytes for frame data
        size_t frame_bytes = frame_width * frame_height * frame_channels;
        
        // Ensure we have enough data for the frame
        if (fdp.remaining_bytes() < frame_bytes) {
            return 0;
        }
        
        // Create frame data from fuzzer input
        std::vector<uint8_t> frame_data = fdp.ConsumeBytes<uint8_t>(frame_bytes);
        
        // Create cv::Mat with the consumed data
        cv::Mat test_frame(frame_height, frame_width, frame_type, frame_data.data());
        
        // Step 2: Test VideoCapture APIs
        // Consume operation choice: 0=default constructor, 1=camera constructor, 2=file constructor
        uint8_t capture_choice = fdp.ConsumeIntegral<uint8_t>() % 3;
        cv::VideoCapture cap;
        
        if (capture_choice == 0) {
            // Test default constructor and open()
            cap = cv::VideoCapture();
            
            // Consume device ID or filename
            if (fdp.ConsumeBool()) {
                // Try to open with device ID
                int device_id = fdp.ConsumeIntegralInRange<int>(0, 10); // 0-10 cameras
                int api_id = fdp.ConsumeIntegralInRange<int>(0, 10); // Various API backends
                cap.open(device_id, api_id);
            } else {
                // Try to open with filename (won't work but tests API)
                std::string dummy_filename = fdp.ConsumeRandomLengthString(64);
                cap.open(dummy_filename);
            }
        } else if (capture_choice == 1) {
            // Test camera constructor
            int device_id = fdp.ConsumeIntegralInRange<int>(0, 10);
            int api_id = fdp.ConsumeIntegralInRange<int>(0, 10);
            cap = cv::VideoCapture(device_id, api_id);
        } else {
            // Test file constructor
            std::string dummy_filename = fdp.ConsumeRandomLengthString(64);
            int api_id = fdp.ConsumeIntegralInRange<int>(0, 10);
            cap = cv::VideoCapture(dummy_filename, api_id);
        }
        
        // Test VideoCapture methods if opened (or even if not)
        if (cap.isOpened() || fdp.ConsumeBool()) {
            // Test get() for various properties
            int prop_ids[] = {
                cv::CAP_PROP_POS_MSEC,
                cv::CAP_PROP_POS_FRAMES,
                cv::CAP_PROP_POS_AVI_RATIO,
                cv::CAP_PROP_FRAME_WIDTH,
                cv::CAP_PROP_FRAME_HEIGHT,
                cv::CAP_PROP_FPS,
                cv::CAP_PROP_FOURCC,
                cv::CAP_PROP_FRAME_COUNT,
                cv::CAP_PROP_FORMAT,
                cv::CAP_PROP_MODE,
                cv::CAP_PROP_BRIGHTNESS,
                cv::CAP_PROP_CONTRAST,
                cv::CAP_PROP_SATURATION,
                cv::CAP_PROP_HUE,
                cv::CAP_PROP_GAIN,
                cv::CAP_PROP_EXPOSURE,
                cv::CAP_PROP_CONVERT_RGB
            };
            
            // Try to get a few properties
            for (int i = 0; i < 5 && i < static_cast<int>(sizeof(prop_ids)/sizeof(prop_ids[0])); i++) {
                if (fdp.remaining_bytes() > 0) {
                    int prop_idx = fdp.ConsumeIntegralInRange<int>(0, sizeof(prop_ids)/sizeof(prop_ids[0]) - 1);
                    double prop_value = cap.get(prop_ids[prop_idx]);
                    (void)prop_value; // Use value to avoid unused variable warning
                }
            }
            
            // Try to set some properties
            for (int i = 0; i < 3 && fdp.remaining_bytes() > sizeof(double); i++) {
                int prop_idx = fdp.ConsumeIntegralInRange<int>(0, sizeof(prop_ids)/sizeof(prop_ids[0]) - 1);
                double prop_value = fdp.ConsumeFloatingPoint<double>();
                cap.set(prop_ids[prop_idx], prop_value);
            }
            
            // Test read() method with synthetic frame
            cv::Mat captured_frame;
            bool read_success = cap.read(captured_frame);
            (void)read_success; // Use result to avoid unused variable warning
            
            // Test operator>> as alternative to read()
            cap >> captured_frame;
            
            // Test grab() and retrieve()
            bool grab_success = cap.grab();
            if (grab_success) {
                cap.retrieve(captured_frame);
            }
        }
        
        // Step 3: Test VideoWriter APIs
        // Consume operation choice: 0=default constructor, 1=full constructor
        uint8_t writer_choice = fdp.ConsumeIntegral<uint8_t>() % 2;
        cv::VideoWriter writer;
        cv::Size frame_size(frame_width, frame_height);
        
        // Consume video writer parameters
        std::string output_filename = "/tmp/fuzz_video_" + fdp.ConsumeRandomLengthString(16) + ".avi";
        int fourcc_codec = 0; // Default/uncompressed
        
        // Try different fourcc codes
        uint8_t fourcc_choice = fdp.ConsumeIntegral<uint8_t>() % 5;
        switch (fourcc_choice) {
            case 0: fourcc_codec = cv::VideoWriter::fourcc('M', 'J', 'P', 'G'); break; // Motion JPEG
            case 1: fourcc_codec = cv::VideoWriter::fourcc('D', 'I', 'V', 'X'); break; // DivX
            case 2: fourcc_codec = cv::VideoWriter::fourcc('X', '2', '6', '4'); break; // H.264
            case 3: fourcc_codec = cv::VideoWriter::fourcc('F', 'M', 'P', '4'); break; // FFMPEG MP4
            case 4: fourcc_codec = -1; break; // Pop up codec selection dialog
        }
        
        double fps = fdp.ConsumeFloatingPointInRange<double>(1.0, 60.0);
        bool is_color = fdp.ConsumeBool();
        
        if (writer_choice == 0) {
            // Test default constructor and open()
            writer = cv::VideoWriter();
            
            // Try to open with parameters
            if (fdp.ConsumeBool()) {
                // With API preference
                int api_id = fdp.ConsumeIntegralInRange<int>(0, 10);
                writer.open(output_filename, api_id, fourcc_codec, fps, frame_size, is_color);
            } else {
                // Without API preference
                writer.open(output_filename, fourcc_codec, fps, frame_size, is_color);
            }
        } else {
            // Test full constructor
            if (fdp.ConsumeBool()) {
                // With API preference
                int api_id = fdp.ConsumeIntegralInRange<int>(0, 10);
                writer = cv::VideoWriter(output_filename, api_id, fourcc_codec, fps, frame_size, is_color);
            } else {
                // Without API preference
                writer = cv::VideoWriter(output_filename, fourcc_codec, fps, frame_size, is_color);
            }
        }
        
        // Test VideoWriter methods if opened (or even if not)
        if (writer.isOpened() || fdp.ConsumeBool()) {
            // Test write() method with synthetic frame
            writer.write(test_frame);
            
            // Test operator<< as alternative to write()
            writer << test_frame;
            
            // Test get() for writer properties
            int writer_prop_ids[] = {
                cv::VIDEOWRITER_PROP_QUALITY,
                cv::VIDEOWRITER_PROP_FRAMEBYTES,
                cv::VIDEOWRITER_PROP_NSTRIPES,
                cv::VIDEOWRITER_PROP_IS_COLOR,
                cv::VIDEOWRITER_PROP_DEPTH,
                cv::VIDEOWRITER_PROP_HW_ACCELERATION,
                cv::VIDEOWRITER_PROP_HW_DEVICE
            };
            
            // Try to get a few properties
            for (int i = 0; i < 3 && i < static_cast<int>(sizeof(writer_prop_ids)/sizeof(writer_prop_ids[0])); i++) {
                if (fdp.remaining_bytes() > 0) {
                    int prop_idx = fdp.ConsumeIntegralInRange<int>(0, sizeof(writer_prop_ids)/sizeof(writer_prop_ids[0]) - 1);
                    double prop_value = writer.get(writer_prop_ids[prop_idx]);
                    (void)prop_value; // Use value to avoid unused variable warning
                }
            }
            
            // Try to set some properties
            for (int i = 0; i < 2 && fdp.remaining_bytes() > sizeof(double); i++) {
                int prop_idx = fdp.ConsumeIntegralInRange<int>(0, sizeof(writer_prop_ids)/sizeof(writer_prop_ids[0]) - 1);
                double prop_value = fdp.ConsumeFloatingPoint<double>();
                writer.set(writer_prop_ids[prop_idx], prop_value);
            }
        }
        
        // Step 4: Test combined VideoCapture -> VideoWriter workflow
        // Create additional synthetic frames for testing
        if (fdp.remaining_bytes() >= frame_bytes * 2) {
            std::vector<uint8_t> frame2_data = fdp.ConsumeBytes<uint8_t>(frame_bytes);
            std::vector<uint8_t> frame3_data = fdp.ConsumeBytes<uint8_t>(frame_bytes);
            
            cv::Mat frame2(frame_height, frame_width, frame_type, frame2_data.data());
            cv::Mat frame3(frame_height, frame_width, frame_type, frame3_data.data());
            
            // Simulate capture->write workflow
            cv::VideoCapture dummy_cap;
            cv::VideoWriter dummy_writer;
            
            // Try to write multiple frames
            if (dummy_writer.isOpened() || fdp.ConsumeBool()) {
                dummy_writer.write(test_frame);
                dummy_writer.write(frame2);
                dummy_writer.write(frame3);
            }
        }
        
        // Step 5: Test release() methods (cleanup)
        // These should be called automatically by destructors, but test explicit calls
        if (fdp.ConsumeBool()) {
            cap.release();
        }
        
        if (fdp.ConsumeBool()) {
            writer.release();
        }
        
        // Step 6: Test additional helper functions
        // Test cv::Size constructor (already used)
        cv::Size test_size(frame_width, frame_height);
        
        // Test cv::Mat constructors with different parameters
        if (fdp.remaining_bytes() > 0) {
            // Test Mat constructor with specified type
            int mat_type = CV_8UC(fdp.ConsumeIntegralInRange<int>(1, 4));
            cv::Mat custom_mat(frame_height, frame_width, mat_type);
            
            // Test clone()
            cv::Mat cloned_mat = test_frame.clone();
            
            // Test ROI extraction
            if (frame_width > 10 && frame_height > 10) {
                int roi_x = fdp.ConsumeIntegralInRange<int>(0, frame_width/2);
                int roi_y = fdp.ConsumeIntegralInRange<int>(0, frame_height/2);
                int roi_width = fdp.ConsumeIntegralInRange<int>(1, frame_width - roi_x);
                int roi_height = fdp.ConsumeIntegralInRange<int>(1, frame_height - roi_y);
                
                cv::Rect roi(roi_x, roi_y, roi_width, roi_height);
                cv::Mat roi_mat = test_frame(roi);
            }
        }
        
    } catch (const cv::Exception& e) {
        // OpenCV exceptions are expected during fuzzing, especially for invalid parameters
    } catch (...) {
        // Catch any other exceptions
    }
    
    return 0;
}
