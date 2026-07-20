/*
 * Harness_031: Comprehensive pcap dump file operations with append functionality and error handling
 * Primary Target: pcap_dump_open_append (56 undiscovered branches, 0% coverage) - focus on error cases
 * Secondary Targets: pcap_dump_open, pcap_dump, pcap_dump_fopen, pcap_dump_flush, pcap_dump_close
 * Setup: pcap_open_dead, pcap_close
 * 
 * Testing Strategy: Focus on append functionality with comprehensive error handling and edge cases
 * Different from harness_030 which focuses on lifecycle testing
 * This harness focuses on:
 *   1. Append to non-existent files (should create new)
 *   2. Append to empty files (should create header)
 *   3. Append to corrupted files (test error handling)
 *   4. Append to files with different pcap magic numbers
 *   5. Error path testing for all dump operations
 * 
 * Key differentiators from harness_030:
 * - More focus on error conditions and edge cases
 * - Testing corrupted pcap files with different magic numbers
 * - Testing append to files with invalid headers
 * - Comprehensive error path coverage for dump APIs
 */

#include <fuzzer/FuzzedDataProvider.h>
#include <pcap/pcap.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctime>
#include <algorithm>
#include <memory>

// Maximum sizes for safety
#define MAX_PACKET_SIZE 65536
#define MAX_PACKETS 10
#define MAX_FILENAME_LEN 256

// Timestamp precision constants
#ifndef PCAP_TSTAMP_PRECISION_MICRO
#define PCAP_TSTAMP_PRECISION_MICRO 0
#endif
#ifndef PCAP_TSTAMP_PRECISION_NANO
#define PCAP_TSTAMP_PRECISION_NANO 1
#endif

// Pcap magic numbers
#define PCAP_MAGIC 0xa1b2c3d4
#define PCAP_MAGIC_SWAPPED 0xd4c3b2a1
#define PCAP_NS_MAGIC 0xa1b23c4d
#define PCAP_NS_MAGIC_SWAPPED 0x4d3cb2a1

// Helper function to create a temporary filename
static std::string create_temp_file(const char* prefix) {
    char template_path[] = "/tmp/libpcap_fuzz_append_XXXXXX";
    int fd = mkstemp(template_path);
    if (fd < 0) {
        return "";
    }
    close(fd);
    return std::string(template_path);
}

// Helper to write different pcap magic numbers to files
static void write_pcap_magic(FILE* f, uint32_t magic) {
    if (f == nullptr) return;
    fwrite(&magic, sizeof(magic), 1, f);
}

// Helper to create a simple pcap packet header
static void create_packet_header(struct pcap_pkthdr* hdr, 
                                 u_int tstamp_precision,
                                 FuzzedDataProvider& fdp) {
    if (hdr == nullptr) return;
    
    hdr->ts.tv_sec = fdp.ConsumeIntegral<time_t>();
    if (tstamp_precision == PCAP_TSTAMP_PRECISION_MICRO) {
        hdr->ts.tv_usec = fdp.ConsumeIntegralInRange<suseconds_t>(0, 999999);
    } else {
        hdr->ts.tv_usec = fdp.ConsumeIntegralInRange<suseconds_t>(0, 999999999);
    }
    hdr->caplen = fdp.ConsumeIntegralInRange<bpf_u_int32>(0, MAX_PACKET_SIZE);
    hdr->len = fdp.ConsumeIntegralInRange<bpf_u_int32>(hdr->caplen, MAX_PACKET_SIZE);
}

// Helper to write packets to dumper
static void write_packets_to_dumper(pcap_dumper_t* dumper, 
                                   u_int tstamp_precision,
                                   size_t num_packets,
                                   FuzzedDataProvider& fdp) {
    if (dumper == nullptr || num_packets == 0) return;
    
    for (size_t i = 0; i < num_packets && fdp.remaining_bytes() > 0; i++) {
        struct pcap_pkthdr hdr;
        create_packet_header(&hdr, tstamp_precision, fdp);
        
        std::vector<uint8_t> packet_data;
        if (hdr.caplen > 0 && fdp.remaining_bytes() > 0) {
            size_t data_size = std::min(static_cast<size_t>(hdr.caplen), fdp.remaining_bytes());
            packet_data = fdp.ConsumeBytes<uint8_t>(data_size);
            if (packet_data.size() < hdr.caplen) {
                packet_data.resize(hdr.caplen, 0);
            }
        } else {
            packet_data.resize(hdr.caplen, 0);
        }
        
        pcap_dump(reinterpret_cast<u_char*>(dumper), &hdr, packet_data.data());
    }
}

// Test append to non-existent file (should create new)
static void test_append_to_nonexistent(pcap_t* pcap, const std::string& filename, 
                                       u_int tstamp_precision, FuzzedDataProvider& fdp) {
    // Ensure file doesn't exist
    unlink(filename.c_str());
    
    // Try to append to non-existent file
    pcap_dumper_t* dumper = pcap_dump_open_append(pcap, filename.c_str());
    if (dumper != nullptr) {
        // Should create new file and write header
        size_t num_packets = fdp.ConsumeIntegralInRange<size_t>(1, 3);
        write_packets_to_dumper(dumper, tstamp_precision, num_packets, fdp);
        
        pcap_dump_flush(dumper);
        pcap_dump_close(dumper);
    }
}

// Test append to empty file (should create header then packets)
static void test_append_to_empty(pcap_t* pcap, const std::string& filename, 
                                 u_int tstamp_precision, FuzzedDataProvider& fdp) {
    // Create truly empty file
    FILE* f = fopen(filename.c_str(), "wb");
    if (f != nullptr) {
        fclose(f);
    }
    
    // Append to empty file
    pcap_dumper_t* dumper = pcap_dump_open_append(pcap, filename.c_str());
    if (dumper != nullptr) {
        size_t num_packets = fdp.ConsumeIntegralInRange<size_t>(1, 3);
        write_packets_to_dumper(dumper, tstamp_precision, num_packets, fdp);
        
        pcap_dump_flush(dumper);
        pcap_dump_close(dumper);
    }
}

// Test append to corrupted pcap file with different magic numbers
static void test_append_to_corrupted(pcap_t* pcap, const std::string& filename, 
                                     u_int tstamp_precision, FuzzedDataProvider& fdp) {
    uint8_t magic_type = fdp.ConsumeIntegral<uint8_t>() % 4;
    uint32_t magic;
    
    switch (magic_type) {
        case 0: magic = PCAP_MAGIC; break;
        case 1: magic = PCAP_MAGIC_SWAPPED; break;
        case 2: magic = PCAP_NS_MAGIC; break;
        case 3: magic = PCAP_NS_MAGIC_SWAPPED; break;
        default: magic = PCAP_MAGIC; break;
    }
    
    // Create file with specific magic number but corrupted content
    FILE* f = fopen(filename.c_str(), "wb");
    if (f != nullptr) {
        write_pcap_magic(f, magic);
        
        // Write some corrupted/incomplete pcap header
        uint16_t version_major = 2;
        uint16_t version_minor = 4;
        int32_t thiszone = 0;
        uint32_t sigfigs = 0;
        uint32_t snaplen = 65535;
        uint32_t network = 1;  // Ethernet
        
        fwrite(&version_major, sizeof(version_major), 1, f);
        fwrite(&version_minor, sizeof(version_minor), 1, f);
        fwrite(&thiszone, sizeof(thiszone), 1, f);
        fwrite(&sigfigs, sizeof(sigfigs), 1, f);
        fwrite(&snaplen, sizeof(snaplen), 1, f);
        fwrite(&network, sizeof(network), 1, f);
        
        // Write some corrupted packet data
        for (int i = 0; i < 10 && fdp.remaining_bytes() > 0; i++) {
            uint8_t byte = fdp.ConsumeIntegral<uint8_t>();
            fwrite(&byte, sizeof(byte), 1, f);
        }
        
        fclose(f);
    }
    
    // Try to append to corrupted file
    pcap_dumper_t* dumper = pcap_dump_open_append(pcap, filename.c_str());
    if (dumper != nullptr) {
        // If append succeeded, try to write packets
        size_t num_packets = fdp.ConsumeIntegralInRange<size_t>(1, 2);
        write_packets_to_dumper(dumper, tstamp_precision, num_packets, fdp);
        
        pcap_dump_flush(dumper);
        pcap_dump_close(dumper);
    }
}

// Test error paths for all dump operations
static void test_error_paths(pcap_t* pcap, const std::string& filename, 
                             u_int tstamp_precision, FuzzedDataProvider& fdp) {
    // Test with NULL parameters
    pcap_dumper_t* dumper1 = pcap_dump_open(nullptr, filename.c_str());
    pcap_dumper_t* dumper2 = pcap_dump_open_append(nullptr, filename.c_str());
    
    // Test with empty filename
    pcap_dumper_t* dumper3 = pcap_dump_open(pcap, "");
    pcap_dumper_t* dumper4 = pcap_dump_open_append(pcap, "");
    
    // Test pcap_dump_fopen with NULL file
    pcap_dumper_t* dumper5 = pcap_dump_fopen(pcap, nullptr);
    
    // Clean up if any succeeded (unlikely)
    if (dumper1 != nullptr) pcap_dump_close(dumper1);
    if (dumper2 != nullptr) pcap_dump_close(dumper2);
    if (dumper3 != nullptr) pcap_dump_close(dumper3);
    if (dumper4 != nullptr) pcap_dump_close(dumper4);
    if (dumper5 != nullptr) pcap_dump_close(dumper5);
    
    // Test pcap_dump with NULL dumper
    struct pcap_pkthdr hdr;
    create_packet_header(&hdr, tstamp_precision, fdp);
    uint8_t dummy_data[16] = {0};
    pcap_dump(nullptr, &hdr, dummy_data);
    
    // Test pcap_dump_flush with NULL dumper
    pcap_dump_flush(nullptr);
    
    // Test pcap_dump_close with NULL dumper (should be safe)
    pcap_dump_close(nullptr);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Need sufficient input for configurations and packet data
    if (size < 128) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);
    
    // Consume test scenario selection
    uint8_t scenario = fdp.ConsumeIntegral<uint8_t>() % 5;
    
    // Consume configuration parameters
    int linktype = fdp.ConsumeIntegralInRange<int>(0, 255);
    int snaplen = fdp.ConsumeIntegralInRange<int>(68, MAX_PACKET_SIZE);
    u_int tstamp_precision = fdp.ConsumeBool() ? PCAP_TSTAMP_PRECISION_MICRO : PCAP_TSTAMP_PRECISION_NANO;
    
    // Create a temporary file for testing
    std::string filename = create_temp_file("append_");
    if (filename.empty()) {
        return 0;
    }
    
    pcap_t* pcap = nullptr;
    
    // Create pcap handle for testing
    pcap = pcap_open_dead(linktype, snaplen);
    if (pcap == nullptr) {
        unlink(filename.c_str());
        return 0;
    }
    
    switch (scenario) {
        case 0:  // Test append to non-existent file
            test_append_to_nonexistent(pcap, filename, tstamp_precision, fdp);
            break;
            
        case 1:  // Test append to empty file
            test_append_to_empty(pcap, filename, tstamp_precision, fdp);
            break;
            
        case 2:  // Test append to corrupted files with different magic numbers
            test_append_to_corrupted(pcap, filename, tstamp_precision, fdp);
            break;
            
        case 3:  // Mixed operations with error handling
        {
            // First create a valid file
            pcap_dumper_t* dumper = pcap_dump_open(pcap, filename.c_str());
            if (dumper != nullptr) {
                write_packets_to_dumper(dumper, tstamp_precision, 2, fdp);
                pcap_dump_flush(dumper);
                pcap_dump_close(dumper);
            }
            
            // Then append to it
            dumper = pcap_dump_open_append(pcap, filename.c_str());
            if (dumper != nullptr) {
                write_packets_to_dumper(dumper, tstamp_precision, 2, fdp);
                
                // Test pcap_dump_file and pcap_dump_ftell
                FILE* dump_file = pcap_dump_file(dumper);
                long ftell_result = pcap_dump_ftell(dumper);
                int64_t ftell64_result = pcap_dump_ftell64(dumper);
                
                pcap_dump_flush(dumper);
                pcap_dump_close(dumper);
            }
            
            break;
        }
        
        case 4:  // Comprehensive error path testing
            test_error_paths(pcap, filename, tstamp_precision, fdp);
            break;
    }
    
    // Cleanup
    if (pcap != nullptr) {
        pcap_close(pcap);
    }
    
    // Remove temporary file
    unlink(filename.c_str());
    
    return 0;
}
