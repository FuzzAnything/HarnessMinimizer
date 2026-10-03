// Protocol Buffers fuzzing harness for comprehensive Cord-based I/O operations
// This harness targets 6 key Cord I/O APIs identified as having 150+ undiscovered branches
// Specifically targets: EpsCopyOutputStream::WriteString, EpsCopyOutputStream::WriteCord,
// ZeroCopyOutputStream::WriteCord, CodedInputStream::ReadCord,
// CopyingOutputStreamAdaptor::WriteCord, CodedOutputStream::WriteCordToArray

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory>

#include <fuzzer/FuzzedDataProvider.h>
#include "google/protobuf/io/coded_stream.h"
#include "google/protobuf/io/zero_copy_stream.h"
#include "google/protobuf/io/zero_copy_stream_impl_lite.h"
#include "absl/strings/cord.h"
#include "absl/strings/cord_buffer.h"

using google::protobuf::io::CodedInputStream;
using google::protobuf::io::CodedOutputStream;
using google::protobuf::io::EpsCopyOutputStream;
using google::protobuf::io::ZeroCopyOutputStream;
using google::protobuf::io::ZeroCopyInputStream;
using google::protobuf::io::ArrayInputStream;
using google::protobuf::io::ArrayOutputStream;
using google::protobuf::io::CopyingOutputStreamAdaptor;
using google::protobuf::io::StringOutputStream;
using google::protobuf::io::CopyingOutputStream;
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Need minimum input for meaningful Cord operations
    if (size < 64) return 0;  // Need enough for multiple parameters and Cord data
    
    FuzzedDataProvider fdp(data, size);
    
    // Step 1: Create Cord objects with various payloads
    // Determine payload types and sizes from fuzzer input
    uint8_t cord_type = fdp.ConsumeIntegral<uint8_t>() % 4;
    size_t cord_size = fdp.ConsumeIntegralInRange<size_t>(0, 1024);
    
    absl::Cord test_cord;
    
    switch (cord_type) {
        case 0:  // Empty cord
            // test_cord already empty
            break;
            
        case 1:  // Small cord from string data
            if (fdp.remaining_bytes() > 0) {
                std::string small_data = fdp.ConsumeRandomLengthString(256);
                test_cord = absl::Cord(small_data);
            }
            break;
            
        case 2:  // Larger cord from multiple chunks
            if (fdp.remaining_bytes() > 0) {
                // Create cord with multiple chunks
                size_t num_chunks = fdp.ConsumeIntegralInRange<size_t>(1, 8);
                for (size_t i = 0; i < num_chunks && fdp.remaining_bytes() > 0; i++) {
                    size_t chunk_size = fdp.ConsumeIntegralInRange<size_t>(1, 128);
                    std::string chunk_data = fdp.ConsumeBytesAsString(chunk_size);
                    test_cord.Append(chunk_data);
                }
            }
            break;
            
        case 3:  // Cord from buffer
            if (fdp.remaining_bytes() > 0) {
                size_t buffer_size = std::min(fdp.remaining_bytes(), cord_size);
                std::vector<uint8_t> buffer_data = fdp.ConsumeBytes<uint8_t>(buffer_size);
                absl::CordBuffer cord_buffer = absl::CordBuffer::CreateWithDefaultLimit(buffer_size);
                if (cord_buffer.capacity() >= buffer_size) {
                    memcpy(cord_buffer.data(), buffer_data.data(), buffer_size);
                    cord_buffer.SetLength(buffer_size);
                    test_cord.Append(std::move(cord_buffer));
                }
            }
            break;
    }
    
    // Create a second cord for additional testing
    absl::Cord second_cord;
    if (fdp.remaining_bytes() > 0) {
        std::string second_data = fdp.ConsumeRandomLengthString(512);
        second_cord = absl::Cord(second_data);
    }
    
    // Step 2: Test EpsCopyOutputStream::WriteString and WriteCord
    if (fdp.remaining_bytes() > 0) {
        // Create buffer for EpsCopyOutputStream
        size_t buffer_size = fdp.ConsumeIntegralInRange<size_t>(256, 4096);
        std::vector<uint8_t> eps_buffer(buffer_size);
        uint8_t* ptr = eps_buffer.data();
        uint8_t* end = ptr + buffer_size;
        
        // Create EpsCopyOutputStream from buffer
        bool deterministic = fdp.ConsumeBool();
        EpsCopyOutputStream eps_stream(eps_buffer.data(), buffer_size, deterministic);
        
        // Get field number from fuzzer input
        uint32_t field_num = fdp.ConsumeIntegral<uint32_t>();
        
        // Test WriteString with Cord
        if (!eps_stream.HadError()) {
            ptr = eps_stream.WriteString(field_num, test_cord, ptr);
        }
        
        // Test WriteCord
        if (!eps_stream.HadError() && ptr < end) {
            ptr = eps_stream.WriteCord(second_cord, ptr);
        }
        
        // Trim the stream
        if (!eps_stream.HadError()) {
            ptr = eps_stream.Trim(ptr);
        }
    }
    
    // Step 3: Test ZeroCopyOutputStream::WriteCord using ArrayOutputStream
    if (fdp.remaining_bytes() > 0) {
        size_t array_size = fdp.ConsumeIntegralInRange<size_t>(512, 4096);
        std::vector<uint8_t> output_array(array_size);
        ArrayOutputStream array_stream(output_array.data(), array_size);
        
        // Write Cord to ArrayOutputStream (inherits ZeroCopyOutputStream::WriteCord)
        if (!test_cord.empty()) {
            bool write_result = array_stream.WriteCord(test_cord);
            (void)write_result;  // Result not used, just exercise the API
        }
    }
    
    // Step 4: Test CopyingOutputStreamAdaptor::WriteCord
    if (fdp.remaining_bytes() > 0) {
        // Create a custom CopyingOutputStream that writes to a string
        class StringCopyingOutputStream : public CopyingOutputStream {
        private:
            std::string* output_;
        public:
            explicit StringCopyingOutputStream(std::string* output) : output_(output) {}
            bool Write(const void* buffer, int size) override {
                if (size < 0) return false;
                output_->append(static_cast<const char*>(buffer), size);
                return true;
            }
        };
        
        // Create backing string and custom copying stream
        std::string backing_string;
        StringCopyingOutputStream string_copying_stream(&backing_string);
        
        // Create CopyingOutputStreamAdaptor wrapping the custom copying stream
        CopyingOutputStreamAdaptor copying_adaptor(&string_copying_stream);
        
        // Write Cord to CopyingOutputStreamAdaptor
        if (!test_cord.empty()) {
            bool write_result = copying_adaptor.WriteCord(test_cord);
            (void)write_result;  // Result not used, just exercise the API
        }
    }
    
    // Step 5: Test CodedOutputStream::WriteCordToArray
    if (fdp.remaining_bytes() > 0) {
        size_t coded_array_size = fdp.ConsumeIntegralInRange<size_t>(512, 4096);
        std::vector<uint8_t> coded_array(coded_array_size);
        
        // Write Cord directly to array
        if (!test_cord.empty()) {
            uint8_t* target = CodedOutputStream::WriteCordToArray(test_cord, coded_array.data());
            (void)target;  // Result not used, just exercise the API
        }
    }
    
    // Step 6: Create input streams from output data and test CodedInputStream::ReadCord
    if (fdp.remaining_bytes() > 0) {
        // Create some output data to read back
        size_t input_size = fdp.ConsumeIntegralInRange<size_t>(128, 2048);
        std::vector<uint8_t> input_data = fdp.ConsumeBytes<uint8_t>(input_size);
        
        if (!input_data.empty()) {
            // Create ArrayInputStream from the data
            ArrayInputStream array_input(input_data.data(), input_data.size());
            
            // Create CodedInputStream from ArrayInputStream
            CodedInputStream coded_input(&array_input);
            
            // Create Cord to read into
            absl::Cord read_cord;
            
            // Determine how much to read
            int read_size = fdp.ConsumeIntegralInRange<int>(0, input_data.size());
            
            // Test ReadCord
            bool read_result = coded_input.ReadCord(&read_cord, read_size);
            (void)read_result;  // Result not used, just exercise the API
            
            // Test reading with different sizes
            if (fdp.remaining_bytes() > 0) {
                absl::Cord another_cord;
                int another_size = fdp.ConsumeIntegralInRange<int>(0, 256);
                bool another_result = coded_input.ReadCord(&another_cord, another_size);
                (void)another_result;
            }
        }
    }
    
    // Step 7: Verify round-trip integrity for one of the operations
    // This is simplified - in reality we'd compare original and round-tripped data
    if (fdp.remaining_bytes() > 0) {
        // Create a simple round-trip test
        std::string test_string = fdp.ConsumeRandomLengthString(256);
        if (!test_string.empty()) {
            absl::Cord original_cord(test_string);
            
            // Write to array
            std::vector<uint8_t> buffer(original_cord.size() + 100);
            uint8_t* ptr = buffer.data();
            ptr = CodedOutputStream::WriteCordToArray(original_cord, ptr);
            
            // Read back (simplified - would need proper parsing)
            // For now just verify the write happened
            size_t bytes_written = ptr - buffer.data();
            (void)bytes_written;
        }
    }
    
    // Step 8: Clean up is automatic (RAII handles stream and Cord destruction)
    
    return 0;
}
