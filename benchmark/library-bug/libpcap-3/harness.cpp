#include <fuzzer/FuzzedDataProvider.h>
#include <pcap/pcap.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 16) {
        return 0;  // Minimum size for meaningful testing
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Consume configuration parameters from fuzzer input
    int linktype = fdp.ConsumeIntegralInRange<int>(0, 255);  // Link type
    int snaplen = fdp.ConsumeIntegralInRange<int>(68, 65535);  // Snap length
    bool optimize = fdp.ConsumeBool();  // Optimization flag for BPF compilation
    int netmask = fdp.ConsumeIntegral<uint32_t>();  // Netmask for BPF
    
    // Consume filter string (BPF filter)
    size_t filter_size = fdp.ConsumeIntegralInRange<size_t>(1, 512);
    if (filter_size > fdp.remaining_bytes()) {
        filter_size = fdp.remaining_bytes();
    }
    std::string filter_str = fdp.ConsumeBytesAsString(filter_size);
    // Test 1: BPF filter compilation with pcap_open_dead
    {
        pcap_t* pcap_dead = pcap_open_dead(linktype, snaplen);
        if (pcap_dead == nullptr) {
            return 0;
        }
        
        struct bpf_program fp;
        memset(&fp, 0, sizeof(fp));
        
        // Try to compile the filter
        int compile_result = pcap_compile(pcap_dead, &fp, filter_str.c_str(), optimize ? 1 : 0, netmask);
        
        if (compile_result == 0) {
            // Filter compiled successfully, try to set it
            int setfilter_result = pcap_setfilter(pcap_dead, &fp);
            (void)setfilter_result;  // Result intentionally ignored
            
            // Test pcap_offline_filter if we have packet data
            if (fdp.remaining_bytes() > 20) {
                struct pcap_pkthdr pkthdr;
                size_t packet_size = fdp.ConsumeIntegralInRange<size_t>(0, 1500);
                pkthdr.caplen = packet_size;
                pkthdr.len = fdp.ConsumeIntegralInRange<uint32_t>(pkthdr.caplen, 1500);
                
                std::vector<uint8_t> packet = fdp.ConsumeBytes<uint8_t>(packet_size);
                
                if (!packet.empty()) {
                    int filter_match = pcap_offline_filter(&fp, &pkthdr, packet.data());
                    (void)filter_match;  // Result intentionally ignored
                }
            }
            
            pcap_freecode(&fp);
        } else {
            // Filter compilation failed - test error retrieval
            char* err = pcap_geterr(pcap_dead);
            (void)err;  // Error message intentionally ignored
        }
        
        pcap_close(pcap_dead);
    }
    
    // Test 2: PCAP file parsing (if enough data remains)
    if (fdp.remaining_bytes() > 100) {
        // Create a temporary file for pcap_open_offline
        char filename[] = "/tmp/libpcap_fuzz_XXXXXX";
        int fd = mkstemp(filename);
        if (fd >= 0) {
            // Write remaining data to file
            std::vector<uint8_t> file_data = fdp.ConsumeRemainingBytes<uint8_t>();
            if (write(fd, file_data.data(), file_data.size()) == static_cast<ssize_t>(file_data.size())) {
                close(fd);
                
                char errbuf[PCAP_ERRBUF_SIZE];
                pcap_t* pcap_offline = pcap_open_offline(filename, errbuf);
                
                if (pcap_offline != nullptr) {
                    // Try to read packets
                    struct pcap_pkthdr* header;
                    const u_char* pkt_data;
                    
                    int next_result = pcap_next_ex(pcap_offline, &header, &pkt_data);
                    while (next_result == 1) {
                        // Packet read successfully
                        // Test various pcap functions
                        int datalink = pcap_datalink(pcap_offline);
                        int snapshot = pcap_snapshot(pcap_offline);
                        int is_swapped = pcap_is_swapped(pcap_offline);
                        (void)datalink;
                        (void)snapshot;
                        (void)is_swapped;
                        
                        next_result = pcap_next_ex(pcap_offline, &header, &pkt_data);
                    }
                    
                    // Test pcap_stats
                    struct pcap_stat stats;
                    int stats_result = pcap_stats(pcap_offline, &stats);
                    (void)stats_result;
                    
                    pcap_close(pcap_offline);
                }
            } else {
                close(fd);
            }
            
            unlink(filename);
        }
    }
    
    return 0;
}
