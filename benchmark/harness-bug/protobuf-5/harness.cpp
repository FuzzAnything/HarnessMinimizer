// Protobuf advanced Cord-based streaming API fuzzing harness
// This harness tests comprehensive Cord streaming operations targeting
// zero_copy_stream_impl_lite.cc with focus on complex scenarios and edge cases
// APIs: CordInputStream, CordOutputStream with CordBuffer variants, 
// advanced CodedStream integration, and memory sharing patterns
// This complements harness_004 by testing more complex Cord operations

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <memory>

#include "absl/strings/cord.h"
#include "absl/strings/cord_buffer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "google/protobuf/io/coded_stream.h"
#include "google/protobuf/io/zero_copy_stream_impl_lite.h"

using google::protobuf::io::CodedInputStream;
using google::protobuf::io::CodedOutputStream;
using google::protobuf::io::CordInputStream;
using google::protobuf::io::CordOutputStream;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Check minimum size for meaningful testing
  if (size < 32) return 0;  // Need enough for complex configuration
  
  FuzzedDataProvider fdp(data, size);
  
  // Consume configuration parameters
  uint8_t test_scenario = fdp.ConsumeIntegral<uint8_t>() % 8;
  size_t size_hint = fdp.ConsumeIntegralInRange<size_t>(0, 65536);
  size_t max_cord_size = fdp.ConsumeIntegralInRange<size_t>(64, 8192);
  size_t max_buffer_size = fdp.ConsumeIntegralInRange<size_t>(32, 2048);
  
  // Scenario 0: Advanced CordOutputStream with CordBuffer constructors
  if (test_scenario == 0) {
    // Test CordOutputStream with initial CordBuffer
    size_t buffer_size = fdp.ConsumeIntegralInRange<size_t>(16, max_buffer_size);
    // Determine how many bytes we can actually fill
    size_t fill_size = std::min<size_t>(buffer_size, fdp.remaining_bytes());
    std::vector<char> buffer_data(buffer_size);  // Allocate full size, but we'll only fill fill_size
    
    for (size_t i = 0; i < fill_size && fdp.remaining_bytes() > 0; ++i) {
      buffer_data[i] = fdp.ConsumeIntegral<char>();
    }
    
    // Create CordBuffer with initial data (only copy filled portion)
    auto cord_buffer = absl::CordBuffer::CreateWithDefaultLimit(buffer_size);
    memcpy(cord_buffer.data(), buffer_data.data(), fill_size);
    cord_buffer.SetLength(fill_size);
    
    // Create CordOutputStream with donated buffer
    CordOutputStream cord_output(std::move(cord_buffer), size_hint);
    CodedOutputStream coded_output(&cord_output);
    
    // Write various data types
    if (fdp.remaining_bytes() > sizeof(uint32_t)) {
      uint32_t val1 = fdp.ConsumeIntegral<uint32_t>();
      uint32_t val2 = fdp.ConsumeIntegral<uint32_t>();
      coded_output.WriteVarint32(val1);
      coded_output.WriteLittleEndian32(val2);
    }
    
    // Write string data if available
    if (fdp.remaining_bytes() > 0) {
      std::string str_data = fdp.ConsumeRandomLengthString(
          std::min<size_t>(512, fdp.remaining_bytes()));
      coded_output.WriteString(str_data);
    }
    
    coded_output.Trim();
    absl::Cord result = cord_output.Consume();
    (void)result;
  }
  
  // Scenario 1: CordOutputStream with donated Cord and CordBuffer
  else if (test_scenario == 1) {
    // Create initial cord
    size_t initial_cord_size = fdp.ConsumeIntegralInRange<size_t>(16, max_cord_size);
    std::string initial_data = fdp.ConsumeBytesAsString(
        std::min<size_t>(initial_cord_size, fdp.remaining_bytes()));
    absl::Cord initial_cord(initial_data);
    
    // Create buffer with some data
    size_t buffer_size = fdp.ConsumeIntegralInRange<size_t>(16, max_buffer_size);
    auto cord_buffer = absl::CordBuffer::CreateWithDefaultLimit(buffer_size);
    
    // Fill buffer with fuzzed data
    size_t fill_size = std::min<size_t>(buffer_size, fdp.remaining_bytes());
    for (size_t i = 0; i < fill_size && fdp.remaining_bytes() > 0; ++i) {
      cord_buffer.data()[i] = fdp.ConsumeIntegral<char>();
    }
    cord_buffer.SetLength(fill_size);
    
    // Create CordOutputStream with donated cord and buffer
    CordOutputStream cord_output(std::move(initial_cord), std::move(cord_buffer), size_hint);
    
    // Use Next()/BackUp() pattern directly
    void* buffer_ptr;
    int buffer_len;
    if (cord_output.Next(&buffer_ptr, &buffer_len)) {
      // Write some data to the buffer
      size_t write_len = std::min<size_t>(buffer_len, fdp.remaining_bytes());
      for (size_t i = 0; i < write_len && fdp.remaining_bytes() > 0; ++i) {
        static_cast<char*>(buffer_ptr)[i] = fdp.ConsumeIntegral<char>();
      }
      
      // Sometimes back up partially
      if (write_len > 1 && fdp.ConsumeBool()) {
        size_t backup_amount = fdp.ConsumeIntegralInRange<size_t>(1, write_len - 1);
        cord_output.BackUp(backup_amount);
      }
    }
    
    // Consume result
    absl::Cord result = cord_output.Consume();
    (void)result;
  }
  
  // Scenario 2: Complex CordInputStream chunk traversal
  else if (test_scenario == 2) {
    // Create a cord with multiple chunks (by appending multiple strings)
    absl::Cord multi_chunk_cord;
    int num_chunks = fdp.ConsumeIntegralInRange<int>(1, 10);
    
    for (int i = 0; i < num_chunks && fdp.remaining_bytes() > 0; ++i) {
      size_t chunk_size = fdp.ConsumeIntegralInRange<size_t>(1, 
          std::min<size_t>(256, fdp.remaining_bytes()));
      std::string chunk_data = fdp.ConsumeBytesAsString(chunk_size);
      multi_chunk_cord.Append(chunk_data);
    }
    
    if (multi_chunk_cord.size() > 0) {
      CordInputStream cord_input(&multi_chunk_cord);
      // Removed CodedInputStream declaration as it's not used and causes state desynchronization
      // when mixing direct CordInputStream operations with CodedInputStream wrapper
      // Test advanced traversal patterns
      const void* buffer;
      int buffer_size;
      int total_bytes_read = 0;
      int iteration = 0;
      
      while (cord_input.Next(&buffer, &buffer_size) && iteration < 20) {
        total_bytes_read += buffer_size;
        iteration++;
        
        // Occasionally skip or backup
        if (buffer_size > 1) {
          uint8_t action = fdp.ConsumeIntegral<uint8_t>() % 4;
          switch (action) {
            case 0:
              // Skip forward within chunk
              if (buffer_size > 10) {
                size_t skip = fdp.ConsumeIntegralInRange<size_t>(1, buffer_size / 2);
                cord_input.Skip(skip);
                total_bytes_read -= skip;  // Skip reduces bytes to read
              }
              break;
            case 1:
              // Backup partially
              if (total_bytes_read > 0) {
                size_t backup = fdp.ConsumeIntegralInRange<size_t>(1, 
                    std::min<size_t>(buffer_size, total_bytes_read));
                cord_input.BackUp(backup);
                total_bytes_read -= backup;
              }
              break;
            case 2:
              // ReadCord operation
              if (multi_chunk_cord.size() - total_bytes_read > 10) {
                absl::Cord read_cord;
                int read_count = fdp.ConsumeIntegralInRange<int>(1, 
                    std::min<int>(100, multi_chunk_cord.size() - total_bytes_read));
                cord_input.ReadCord(&read_cord, read_count);
                total_bytes_read += read_count;
              }
              break;
            default:
              // Do nothing
              break;
          }
        }
      }
      
      // Test ByteCount after operations
      int64_t byte_count = cord_input.ByteCount();
      (void)byte_count;
    }
  }
  
  // Scenario 3: CordOutputStream WriteCord with memory sharing patterns
  else if (test_scenario == 3) {
    // Create source cord with multiple chunks
    absl::Cord source_cord;
    int num_source_chunks = fdp.ConsumeIntegralInRange<int>(1, 5);
    
    for (int i = 0; i < num_source_chunks && fdp.remaining_bytes() > 0; ++i) {
      // Ensure min <= max for ConsumeIntegralInRange
      size_t remaining = fdp.remaining_bytes();
      if (remaining < 16) break;  // Not enough for minimum chunk size
      size_t chunk_size = fdp.ConsumeIntegralInRange<size_t>(16, 
          std::min<size_t>(512, remaining));
      std::string chunk_data = fdp.ConsumeBytesAsString(chunk_size);
      source_cord.Append(chunk_data);
    }
    
    // Create CordOutputStream
    CordOutputStream cord_output(size_hint);
    
    // Write the source cord (should try to share memory)
    bool write_success = cord_output.WriteCord(source_cord);
    (void)write_success;
    
    // Write additional data
    CodedOutputStream coded_output(&cord_output);
    
    // Write mixed data types
    if (fdp.remaining_bytes() > sizeof(uint64_t)) {
      uint64_t varint_val = fdp.ConsumeIntegral<uint64_t>();
      int32_t le_val = fdp.ConsumeIntegral<int32_t>();
      coded_output.WriteVarint64(varint_val);
      coded_output.WriteLittleEndian32(le_val);
    }
    
    // Write raw data
    if (fdp.remaining_bytes() > 0) {
      size_t raw_size = fdp.ConsumeIntegralInRange<size_t>(1, 
          std::min<size_t>(1024, fdp.remaining_bytes()));
      std::vector<uint8_t> raw_data = fdp.ConsumeBytes<uint8_t>(raw_size);
      coded_output.WriteRaw(raw_data.data(), raw_data.size());
    }
    
    coded_output.Trim();
    
    // Consume and potentially use the result
    absl::Cord result = cord_output.Consume();
    
    // Create a new CordInputStream from the result
    if (result.size() > 0) {
      CordInputStream result_input(&result);
      CodedInputStream coded_result_input(&result_input);
      
      // Try reading back some data
      uint64_t read_varint = 0;
      coded_result_input.ReadVarint64(&read_varint);
      
      // Skip some bytes
      if (result.size() > 20) {
        coded_result_input.Skip(10);
      }
    }
  }
  
  // Scenario 4: CordOutputStream GetAppendBuffer simulation
  else if (test_scenario == 4) {
    // Create initial cord with some data
    size_t initial_size = fdp.ConsumeIntegralInRange<size_t>(64, max_cord_size);
    std::string initial_str = fdp.ConsumeBytesAsString(
        std::min<size_t>(initial_size, fdp.remaining_bytes()));
    absl::Cord cord(initial_str);
    
    // Manually use GetAppendBuffer to simulate CordOutputStream internals
    size_t desired_size = fdp.ConsumeIntegralInRange<size_t>(64, 4096);
    absl::CordBuffer append_buffer = cord.GetAppendBuffer(desired_size);
    
    // Write data to the append buffer
    size_t write_size = std::min<size_t>(append_buffer.capacity(), fdp.remaining_bytes());
    for (size_t i = 0; i < write_size && fdp.remaining_bytes() > 0; ++i) {
      append_buffer.data()[i] = fdp.ConsumeIntegral<char>();
    }
    append_buffer.SetLength(write_size);
    
    // Append the buffer to the cord
    cord.Append(std::move(append_buffer));
    
    // Now create CordOutputStream with this cord
    CordOutputStream cord_output(std::move(cord), size_hint);
    
    // Write additional data
    CodedOutputStream coded_output(&cord_output);
    if (fdp.remaining_bytes() > sizeof(uint32_t)) {
      uint32_t val = fdp.ConsumeIntegral<uint32_t>();
      coded_output.WriteVarint32(val);
    }
    
    coded_output.Trim();
    absl::Cord final_cord = cord_output.Consume();
    (void)final_cord;
  }
  
  // Scenario 5: CordInputStream with empty and small cords
  else if (test_scenario == 5) {
    // Test edge cases with small or empty cords
    uint8_t cord_type = fdp.ConsumeIntegral<uint8_t>() % 3;
    absl::Cord test_cord;
    
    switch (cord_type) {
      case 0:
        // Empty cord
        break;
      case 1:
        // Very small cord (1-16 bytes)
        if (fdp.remaining_bytes() > 0) {
          size_t small_size = fdp.ConsumeIntegralInRange<size_t>(1, 16);
          std::string small_data = fdp.ConsumeBytesAsString(
              std::min<size_t>(small_size, fdp.remaining_bytes()));
          test_cord = absl::Cord(small_data);
        }
        break;
      case 2:
        // Single byte cord
        if (fdp.remaining_bytes() > 0) {
          char single_byte = fdp.ConsumeIntegral<char>();
          test_cord = absl::Cord(std::string(1, single_byte));
        }
        break;
    }
    
    CordInputStream cord_input(&test_cord);
    
    // Test operations that should handle edge cases
    const void* buffer;
    int buffer_size;
    bool has_next = cord_input.Next(&buffer, &buffer_size);
    (void)has_next;
    
    // Test Skip on small/empty cord
    if (test_cord.size() > 0) {
      size_t skip_amount = fdp.ConsumeIntegralInRange<size_t>(0, test_cord.size() + 5);
      cord_input.Skip(skip_amount);
    }
    
    // Test ByteCount
    int64_t byte_count = cord_input.ByteCount();
    (void)byte_count;
    
    // Test ReadCord on small cord
    if (test_cord.size() > 0) {
      absl::Cord read_cord;
      int read_count = fdp.ConsumeIntegralInRange<int>(0, test_cord.size() + 10);
      cord_input.ReadCord(&read_cord, read_count);
    }
  }
  
  // Scenario 6: Roundtrip with CordBuffer optimizations
  else if (test_scenario == 6) {
    // Create complex data structure
    struct TestData {
      uint32_t header;
      uint64_t id;
      std::string payload;
    } test_data;
    
    if (fdp.remaining_bytes() > sizeof(uint32_t) + sizeof(uint64_t)) {
      test_data.header = fdp.ConsumeIntegral<uint32_t>();
      test_data.id = fdp.ConsumeIntegral<uint64_t>();
    }
    
    if (fdp.remaining_bytes() > 0) {
      test_data.payload = fdp.ConsumeRandomLengthString(
          std::min<size_t>(1024, fdp.remaining_bytes()));
    }
    
    // Write to CordOutputStream with size hint
    CordOutputStream cord_output(size_hint);
    CodedOutputStream coded_output(&cord_output);
    
    coded_output.WriteVarint32(test_data.header);
    coded_output.WriteVarint64(test_data.id);
    coded_output.WriteString(test_data.payload);
    
    // Write some additional raw data
    if (fdp.remaining_bytes() > 0) {
      size_t extra_size = fdp.ConsumeIntegralInRange<size_t>(1, 
          std::min<size_t>(512, fdp.remaining_bytes()));
      std::vector<uint8_t> extra_data = fdp.ConsumeBytes<uint8_t>(extra_size);
      coded_output.WriteRaw(extra_data.data(), extra_data.size());
    }
    
    coded_output.Trim();
    absl::Cord serialized_cord = cord_output.Consume();
    
    // Read back with CordInputStream
    if (serialized_cord.size() > 0) {
      CordInputStream cord_input(&serialized_cord);
      CodedInputStream coded_input(&cord_input);
      
      // Set total bytes limit
      coded_input.SetTotalBytesLimit(serialized_cord.size() * 2);
      
      uint32_t read_header;
      uint64_t read_id;
      std::string read_payload;
      
      if (coded_input.ReadVarint32(&read_header)) {
        (void)read_header;
      }
      if (coded_input.ReadVarint64(&read_id)) {
        (void)read_id;
      }
      
      // Try to read string with length prefix
      uint32_t payload_len;
      if (coded_input.ReadVarint32(&payload_len) && payload_len > 0) {
        coded_input.ReadString(&read_payload, payload_len);
      }
      
      // Test recursion limit
      coded_input.SetRecursionLimit(100);
      
      // Test remaining bytes
      int remaining = coded_input.BytesUntilLimit();
      (void)remaining;
    }
  }
  
  // Scenario 7: Stress test with many small operations
  else if (test_scenario == 7) {
    CordOutputStream cord_output(size_hint);
    CodedOutputStream coded_output(&cord_output);
    
    // Perform many small writes
    int num_operations = fdp.ConsumeIntegralInRange<int>(10, 100);
    
    for (int i = 0; i < num_operations && fdp.remaining_bytes() > 0; ++i) {
      uint8_t op_type = fdp.ConsumeIntegral<uint8_t>() % 5;
      
      switch (op_type) {
        case 0:
          if (fdp.remaining_bytes() >= sizeof(uint32_t)) {
            uint32_t val = fdp.ConsumeIntegral<uint32_t>();
            coded_output.WriteVarint32(val);
          }
          break;
        case 1:
          if (fdp.remaining_bytes() >= sizeof(uint64_t)) {
            uint64_t val = fdp.ConsumeIntegral<uint64_t>();
            coded_output.WriteVarint64(val);
          }
          break;
        case 2:
          if (fdp.remaining_bytes() > 0) {
            std::string short_str = fdp.ConsumeRandomLengthString(
                std::min<size_t>(16, fdp.remaining_bytes()));
            coded_output.WriteString(short_str);
          }
          break;
        case 3:
          if (fdp.remaining_bytes() > 0) {
            size_t raw_len = fdp.ConsumeIntegralInRange<size_t>(1, 
                std::min<size_t>(32, fdp.remaining_bytes()));
            std::vector<uint8_t> raw_data = fdp.ConsumeBytes<uint8_t>(raw_len);
            coded_output.WriteRaw(raw_data.data(), raw_data.size());
          }
          break;
        case 4:
          // Direct buffer access via Next/BackUp
          void* buf;
          int buf_len;
          if (cord_output.Next(&buf, &buf_len)) {
            size_t write_len = std::min<size_t>(buf_len, fdp.remaining_bytes());
            for (size_t j = 0; j < write_len && fdp.remaining_bytes() > 0; ++j) {
              static_cast<char*>(buf)[j] = fdp.ConsumeIntegral<char>();
            }
            
            // Occasionally back up
            if (write_len > 1 && fdp.ConsumeBool()) {
              cord_output.BackUp(1);
            }
          }
          break;
      }
    }
    
    coded_output.Trim();
    absl::Cord result = cord_output.Consume();
    
    // Quick read back test
    if (result.size() > 0) {
      CordInputStream cord_input(&result);
      CodedInputStream coded_input(&cord_input);
      
      // Try reading a few values back
      for (int i = 0; i < 5 && !coded_input.ExpectAtEnd(); ++i) {
        uint64_t dummy;
        coded_input.ReadVarint64(&dummy);
      }
    }
  }
  
  return 0;
}
