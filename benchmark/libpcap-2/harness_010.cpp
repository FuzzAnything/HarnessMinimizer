#include <fuzzer/FuzzedDataProvider.h>
#include <pcap/pcap.h>
#include <pcap/bpf.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check: need enough data for basic parameters and filter string
    if (size < 64) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Consume configuration parameters for pcap_compile_nopcap
    int snaplen = fdp.ConsumeIntegralInRange<int>(68, 65535);  // Snap length (68-65535)
    int linktype = fdp.ConsumeIntegralInRange<int>(0, 255);    // Link type (0-255)
    bool optimize = fdp.ConsumeBool();                         // Optimization flag
    bpf_u_int32 netmask = fdp.ConsumeIntegral<bpf_u_int32>();  // Netmask for BPF
    
    // Consume filter string (BPF filter expression)
    size_t filter_size = fdp.ConsumeIntegralInRange<size_t>(1, 1024);
    if (filter_size > fdp.remaining_bytes()) {
        filter_size = fdp.remaining_bytes();
    }
    std::string filter_str = fdp.ConsumeBytesAsString(filter_size);
    
    // TARGET 1: pcap_compile_nopcap - BPF compilation without pcap handle
    struct bpf_program program;
    memset(&program, 0, sizeof(program));
    
    int compile_result = pcap_compile_nopcap(snaplen, linktype, &program, 
                                             filter_str.c_str(), optimize ? 1 : 0, netmask);
    
    if (compile_result == 0 && program.bf_len > 0 && program.bf_insns != NULL) {
        // BPF program compiled successfully
        
        // TARGET 2: bpf_validate - Validate BPF program structure
        // This function has 0% coverage according to the analysis
        int validation_result = bpf_validate(program.bf_insns, program.bf_len);
        
        // Only execute bpf_filter if the program is validated
        if (validation_result != 0) {
            // Program is valid, we can safely execute it
            
            // TARGET 3: bpf_filter - Apply BPF filter to packet data
            // This function has 0% coverage according to the analysis
            if (fdp.remaining_bytes() > 0) {
                // Consume packet data for filtering
                size_t packet_size = fdp.ConsumeIntegralInRange<size_t>(0, std::min((size_t)1500, fdp.remaining_bytes()));
                std::vector<uint8_t> packet_data = fdp.ConsumeBytes<uint8_t>(packet_size);
                
                if (!packet_data.empty()) {
                    // Apply filter with different wirelen/buflen combinations
                    // Test with wirelen >= buflen (normal case)
                    u_int filter_result1 = bpf_filter(program.bf_insns, packet_data.data(), 
                                                      packet_size, packet_size);
                    (void)filter_result1;
                    
                    // Test with wirelen > buflen (truncated packet)
                    if (packet_size > 10) {
                        u_int filter_result2 = bpf_filter(program.bf_insns, packet_data.data(), 
                                                          packet_size, packet_size - 10);
                        (void)filter_result2;
                    }
                    
                    // Test with wirelen < buflen (invalid but should be handled)
                    if (packet_size > 0) {
                        u_int filter_result3 = bpf_filter(program.bf_insns, packet_data.data(), 
                                                          packet_size - 1, packet_size);
                        (void)filter_result3;
                    }
                    
                    // Test with zero length packet
                    if (packet_size > 0) {
                        u_int filter_result4 = bpf_filter(program.bf_insns, packet_data.data(), 
                                                          0, 0);
                        (void)filter_result4;
                    }
                }
            }
        } else {
            // Program failed validation - test error handling paths
            // We should NOT call bpf_filter with invalid programs
            // But we can still test edge cases with NULL/NULL parameters
            if (fdp.remaining_bytes() > 10) {
                std::vector<uint8_t> test_packet = fdp.ConsumeBytes<uint8_t>(10);
                u_int null_filter = bpf_filter(NULL, test_packet.data(), 10, 10);
                (void)null_filter;
            }
        }
        // Test edge cases for bpf_validate
        
        // Test with NULL program
        int null_validate = bpf_validate(NULL, 0);
        (void)null_validate;
        
        // Test with zero-length program
        if (program.bf_len > 0) {
            int zero_len_validate = bpf_validate(program.bf_insns, 0);
            (void)zero_len_validate;
        }
        
        // Test with negative length
        if (program.bf_len > 0) {
            int neg_len_validate = bpf_validate(program.bf_insns, -1);
            (void)neg_len_validate;
        }
        
        // Test edge cases for bpf_filter
        
        // Test with NULL program
        if (fdp.remaining_bytes() > 10) {
            std::vector<uint8_t> test_packet = fdp.ConsumeBytes<uint8_t>(10);
            u_int null_filter = bpf_filter(NULL, test_packet.data(), 10, 10);
            (void)null_filter;
        }
        
        // Test with NULL packet data
        if (program.bf_len > 0) {
            u_int null_packet_filter = bpf_filter(program.bf_insns, NULL, 0, 0);
            (void)null_packet_filter;
        }
        
        // Clean up compiled program
        pcap_freecode(&program);
    } else {
        // Compilation failed - test error handling paths
        // The program might be partially initialized, try to free it anyway
        if (program.bf_insns != NULL || program.bf_len > 0) {
            pcap_freecode(&program);
        }
    }
    
    // Additional tests with random BPF instruction generation
    if (fdp.remaining_bytes() > 100) {
        // Generate random BPF instructions for validation testing
        size_t num_instructions = fdp.ConsumeIntegralInRange<size_t>(1, 50);
        if (num_instructions * sizeof(struct bpf_insn) <= fdp.remaining_bytes()) {
            std::vector<struct bpf_insn> random_instructions(num_instructions);
            
            // Consume raw bytes for instruction data
            size_t bytes_needed = num_instructions * sizeof(struct bpf_insn);
            std::vector<uint8_t> instruction_bytes = fdp.ConsumeBytes<uint8_t>(bytes_needed);
            
            // Copy bytes to instruction structures (may create invalid instructions)
            if (instruction_bytes.size() == bytes_needed) {
                memcpy(random_instructions.data(), instruction_bytes.data(), bytes_needed);
                
                // Test validation on random instruction data
                int random_validate = bpf_validate(random_instructions.data(), num_instructions);
                (void)random_validate;
                
                // Only test filtering with random instructions if they are validated
                if (random_validate != 0) {
                    // Test filtering with random instructions if we have packet data
                    if (fdp.remaining_bytes() > 20) {
                        size_t test_packet_size = fdp.ConsumeIntegralInRange<size_t>(1, 100);
                        if (test_packet_size <= fdp.remaining_bytes()) {
                            std::vector<uint8_t> test_packet = fdp.ConsumeBytes<uint8_t>(test_packet_size);
                            u_int random_filter = bpf_filter(random_instructions.data(), 
                                                             test_packet.data(), 
                                                             test_packet_size, 
                                                             test_packet_size);
                            (void)random_filter;
                        }
                    }
                }
            }
        }
    }
    
    return 0;
}
