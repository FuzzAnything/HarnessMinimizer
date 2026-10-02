// Protocol Buffers fuzzing harness for Cord-based I/O stream operations
// Targets CordInputStream and CordOutputStream APIs for semantic diversity
// from harness_000 (binary parsing) and harness_001 (text format parsing)
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <memory>

#include <fuzzer/FuzzedDataProvider.h>
#include "google/protobuf/message.h"
#include "google/protobuf/descriptor.h"
#include "google/protobuf/reflection.h"
#include "google/protobuf/descriptor.pb.h"
#include "google/protobuf/io/zero_copy_stream_impl_lite.h"
#include "google/protobuf/io/coded_stream.h"
#include "absl/strings/cord.h"
#include "absl/strings/cord_buffer.h"

using google::protobuf::io::CordInputStream;
using google::protobuf::io::CordOutputStream;
using google::protobuf::io::ZeroCopyInputStream;
using google::protobuf::io::ZeroCopyOutputStream;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 16) {
        return 0;  // Minimum size for meaningful testing
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Test 1: Create Cord from fuzzed data and use CordInputStream
    {
        // Create a Cord from the fuzzed data
        std::string cord_data = fdp.ConsumeRandomLengthString(fdp.remaining_bytes() / 2);
        absl::Cord source_cord(cord_data);
        
        // Create CordInputStream
        CordInputStream input(&source_cord);
        
        // Test basic operations
        const void* read_data;
        int read_size;
        
        // Try to get next chunk
        bool has_next = input.Next(&read_data, &read_size);
        if (has_next && read_size > 0) {
            // We got data, back up partially
            int backup_amount = fdp.ConsumeIntegralInRange<int>(0, read_size);
            if (backup_amount > 0) {
                input.BackUp(backup_amount);
            }
            
            // Try to skip some bytes
            int skip_amount = fdp.ConsumeIntegralInRange<int>(0, 100);
            if (skip_amount > 0) {
                input.Skip(skip_amount);
            }
            
            // Check byte count
            int64_t byte_count = input.ByteCount();
        }
        
        // Test ReadCord operation
        if (fdp.remaining_bytes() > 10) {
            absl::Cord dest_cord;
            int read_cord_count = fdp.ConsumeIntegralInRange<int>(1, 100);
            bool read_success = input.ReadCord(&dest_cord, read_cord_count);
        }
    }
    
    // Test 2: CordOutputStream basic operations
    {
        // Create CordOutputStream with size hint
        size_t size_hint = fdp.ConsumeIntegralInRange<size_t>(0, 4096);
        CordOutputStream output(size_hint);
        
        // Write some data using Next()
        void* write_data;
        int write_size;
        
        bool has_next = output.Next(&write_data, &write_size);
        if (has_next && write_size > 0) {
            // Write some fuzzed data
            std::vector<uint8_t> random_data = fdp.ConsumeBytes<uint8_t>(
                fdp.ConsumeIntegralInRange<size_t>(0, std::min<size_t>(write_size, fdp.remaining_bytes()))
            );
            
            if (!random_data.empty()) {
                memcpy(write_data, random_data.data(), random_data.size());
                
                // Back up unused portion
                int unused = write_size - random_data.size();
                if (unused > 0) {
                    output.BackUp(unused);
                }
            }
            
            // Check byte count
            int64_t byte_count = output.ByteCount();
        }
        
        // Consume the cord
        absl::Cord output_cord = output.Consume();
    }
    
    // Test 3: CordOutputStream with donated Cord
    if (fdp.remaining_bytes() > 20) {
        std::string initial_data = fdp.ConsumeRandomLengthString(fdp.remaining_bytes() / 3);
        absl::Cord initial_cord(initial_data);
        
        size_t size_hint = fdp.ConsumeIntegralInRange<size_t>(0, 4096);
        CordOutputStream output(std::move(initial_cord), size_hint);
        
        // Write additional data
        void* write_data;
        int write_size;
        if (output.Next(&write_data, &write_size) && write_size > 0) {
            std::vector<uint8_t> more_data = fdp.ConsumeBytes<uint8_t>(
                fdp.ConsumeIntegralInRange<size_t>(0, std::min<size_t>(write_size, fdp.remaining_bytes()))
            );
            
            if (!more_data.empty()) {
                memcpy(write_data, more_data.data(), more_data.size());
                
                // Back up unused portion
                int unused = write_size - more_data.size();
                if (unused > 0) {
                    output.BackUp(unused);
                }
            }
        }
        
        // Consume final cord
        absl::Cord final_cord = output.Consume();
    }
    
    // Test 4: CordOutputStream with donated CordBuffer
    if (fdp.remaining_bytes() > 30) {
        // Create a CordBuffer
        size_t buffer_size = fdp.ConsumeIntegralInRange<size_t>(100, 1000);
        absl::CordBuffer buffer = absl::CordBuffer::CreateWithDefaultLimit(buffer_size);
        
        // Write some initial data to the buffer
        absl::Span<char> available = buffer.available();
        size_t initial_write = fdp.ConsumeIntegralInRange<size_t>(0, available.size());
        
        if (initial_write > 0) {
            std::vector<uint8_t> init_data = fdp.ConsumeBytes<uint8_t>(initial_write);
            memcpy(available.data(), init_data.data(), init_data.size());
            buffer.IncreaseLengthBy(initial_write);
        }
        
        // Create CordOutputStream with the buffer
        size_t size_hint = fdp.ConsumeIntegralInRange<size_t>(0, 4096);
        CordOutputStream output(std::move(buffer), size_hint);
        
        // Write more data
        void* write_data;
        int write_size;
        if (output.Next(&write_data, &write_size) && write_size > 0) {
            std::vector<uint8_t> more_data = fdp.ConsumeBytes<uint8_t>(
                fdp.ConsumeIntegralInRange<size_t>(0, std::min<size_t>(write_size, fdp.remaining_bytes()))
            );
            
            if (!more_data.empty()) {
                memcpy(write_data, more_data.data(), more_data.size());
            }
        }
        
        // Consume the cord
        absl::Cord buffer_cord = output.Consume();
    }
    
    // Test 5: Complete write/read cycle with CodedStream
    if (fdp.remaining_bytes() > 50) {
        // Create CordOutputStream
        CordOutputStream cord_output;
        
        // Create CodedOutputStream wrapper
        google::protobuf::io::CodedOutputStream coded_output(&cord_output);
        
        // Write some fuzzed data using CodedOutputStream
        while (fdp.remaining_bytes() > 10) {
            uint8_t operation = fdp.ConsumeIntegral<uint8_t>() % 4;
            
            switch (operation) {
                case 0: {
                    // Write varint
                    uint32_t value = fdp.ConsumeIntegral<uint32_t>();
                    coded_output.WriteVarint32(value);
                    break;
                }
                case 1: {
                    // Write little-endian 32-bit
                    uint32_t value = fdp.ConsumeIntegral<uint32_t>();
                    coded_output.WriteLittleEndian32(value);
                    break;
                }
                case 2: {
                    // Write raw bytes
                    size_t bytes_to_write = fdp.ConsumeIntegralInRange<size_t>(1, 100);
                    if (bytes_to_write <= fdp.remaining_bytes()) {
                        std::vector<uint8_t> raw_bytes = fdp.ConsumeBytes<uint8_t>(bytes_to_write);
                        coded_output.WriteRaw(raw_bytes.data(), raw_bytes.size());
                    }
                    break;
                }
                case 3: {
                    // Write string
                    std::string str = fdp.ConsumeRandomLengthString(100);
                    coded_output.WriteString(str);
                    break;
                }
            }
            
            // Small chance to break early
            if ((fdp.ConsumeIntegral<uint8_t>() % 10) == 0) {
                break;
            }
        }
        
        // Consume the cord
        absl::Cord written_cord = cord_output.Consume();
        
        // Now read it back using CordInputStream and CodedInputStream
        if (!written_cord.empty()) {
            CordInputStream cord_input(&written_cord);
            google::protobuf::io::CodedInputStream coded_input(&cord_input);
            
            // Read some data back
            while (!coded_input.ExpectAtEnd() && fdp.remaining_bytes() > 5) {
                uint8_t read_op = fdp.ConsumeIntegral<uint8_t>() % 3;
                
                switch (read_op) {
                    case 0: {
                        // Try to read varint
                        uint32_t value;
                        if (coded_input.ReadVarint32(&value)) {
                            // Successfully read
                        }
                        break;
                    }
                    case 1: {
                        // Try to read raw bytes
                        size_t bytes_to_read = fdp.ConsumeIntegralInRange<size_t>(1, 100);
                        std::vector<uint8_t> buffer(bytes_to_read);
                        if (coded_input.ReadRaw(buffer.data(), bytes_to_read)) {
                            // Successfully read
                        }
                        break;
                    }
                    case 2: {
                        // Try to read string
                        std::string str;
                        if (coded_input.ReadString(&str, 100)) {
                            // Successfully read
                        }
                        break;
                    }
                }
                
                // Small chance to break early
                if ((fdp.ConsumeIntegral<uint8_t>() % 10) == 0) {
                    break;
                }
            }
        }
    }
    
    // Test 6: WriteCord operation
    if (fdp.remaining_bytes() > 20) {
        // Create a cord to write
        std::string cord_content = fdp.ConsumeRandomLengthString(fdp.remaining_bytes() / 2);
        absl::Cord source_cord(cord_content);
        
        // Create CordOutputStream
        CordOutputStream output;
        
        // Use WriteCord to write the entire cord
        bool write_success = output.WriteCord(source_cord);
        
        if (write_success) {
            // Consume and verify
            absl::Cord written_cord = output.Consume();
        }
    }
    
    // Test 7: Fragmented cord reading
    if (fdp.remaining_bytes() > 40) {
        // Create a fragmented cord by appending multiple small strings
        absl::Cord fragmented_cord;
        int num_fragments = fdp.ConsumeIntegralInRange<int>(2, 10);
        
        for (int i = 0; i < num_fragments && fdp.remaining_bytes() > 5; i++) {
            std::string fragment = fdp.ConsumeRandomLengthString(
                fdp.ConsumeIntegralInRange<size_t>(1, 50)
            );
            fragmented_cord.Append(fragment);
        }
        
        // Read from fragmented cord
        if (!fragmented_cord.empty()) {
            CordInputStream input(&fragmented_cord);
            
            // Try various operations
            const void* chunk_data;
            int chunk_size;
            
            while (input.Next(&chunk_data, &chunk_size)) {
                if (chunk_size <= 0) {
                    break;
                }
                
                // Possibly skip some bytes
                if (fdp.ConsumeBool() && chunk_size > 1) {
                    int skip = fdp.ConsumeIntegralInRange<int>(0, chunk_size - 1);
                    if (skip > 0) {
                        input.Skip(skip);
                    }
                }
                
                // Possibly back up
                if (fdp.ConsumeBool() && chunk_size > 1) {
                    int backup = fdp.ConsumeIntegralInRange<int>(0, chunk_size - 1);
                    if (backup > 0) {
                        input.BackUp(backup);
                    }
                }
                
                // Small chance to break
                if ((fdp.ConsumeIntegral<uint8_t>() % 5) == 0) {
                    break;
                }
            }
        }
    }
    
    return 0;
}
