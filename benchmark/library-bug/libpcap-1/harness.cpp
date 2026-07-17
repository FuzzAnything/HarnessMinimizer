#include <fuzzer/FuzzedDataProvider.h>
#include <pcap/pcap.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <cerrno>

// Fuzzing harness for libpcap savefile reading and dump writing.
// This harness tests:
// 1. pcap_open_offline - open a pcap savefile from a temporary file.
// 2. pcap_next_ex - read packets from the savefile.
// 3. pcap_dump_open - open a dump file for writing.
// 4. pcap_dump - write each packet to the dump file.
// 5. pcap_dump_close - close the dump file.
// 6. pcap_close - close the pcap handle.
// The fuzzer input is used as the content of a temporary pcap file.
// This harness is distinct from harness_000 (BPF compilation and filtering)
// and harness_001 (standalone BPF compilation and debugging).

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Need at least some data to create a file.
    if (size < 1) {
        return 0;
    }

    // Create a temporary input file for the pcap data.
    char in_filename[] = "/tmp/libpcap_fuzz_in_XXXXXX";
    int in_fd = mkstemp(in_filename);
    if (in_fd < 0) {
        return 0;
    }
    // Write the entire fuzzer input to the file.
    if (write(in_fd, data, size) != static_cast<ssize_t>(size)) {
        close(in_fd);
        unlink(in_filename);
        return 0;
    }
    close(in_fd);

    // Open the savefile.
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(in_filename, errbuf);
    if (pcap == nullptr) {
        unlink(in_filename);
        return 0;
    }

    // Create a temporary output file for dumping.
    char out_filename[] = "/tmp/libpcap_fuzz_out_XXXXXX";
    int out_fd = mkstemp(out_filename);
    if (out_fd < 0) {
        pcap_close(pcap);
        unlink(in_filename);
        return 0;
    }
    close(out_fd);

    // Open the dump file.
    pcap_dumper_t *dumper = pcap_dump_open(pcap, out_filename);
    if (dumper == nullptr) {
        pcap_close(pcap);
        unlink(in_filename);
        unlink(out_filename);
        return 0;
    }

    // Read packets and dump them, up to a limit to avoid infinite loops.
    const int max_packets = 100;
    int packet_count = 0;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    int ret;
    while ((ret = pcap_next_ex(pcap, &header, &pkt_data)) == 1 && packet_count < max_packets) {
        pcap_dump((u_char *)dumper, header, pkt_data);
        packet_count++;
    }

    // Close the dump file and the pcap handle.
    pcap_dump_close(dumper);
    pcap_close(pcap);

    // Remove temporary files.
    unlink(in_filename);
    unlink(out_filename);

    return 0;
}
