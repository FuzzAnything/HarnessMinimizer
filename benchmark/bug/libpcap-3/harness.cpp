// This fuzz driver is generated for library libpcap, aiming to fuzz the following functions:
// pcap_geterr at pcap.c:3549:1 in pcap.h
// pcap_freecode at gencode.c:1290:1 in pcap.h
// pcap_close at pcap.c:4177:1 in pcap.h
// pcap_statustostr at pcap.c:3654:1 in pcap.h
// pcap_statustostr at pcap.c:3654:1 in pcap.h
// pcap_open_live at pcap.c:2749:1 in pcap.h
// pcap_close at pcap.c:4177:1 in pcap.h
// pcap_geterr at pcap.c:3549:1 in pcap.h
// pcap_fileno at pcap.c:3522:1 in pcap.h
// pcap_compile at gencode.c:1105:1 in pcap.h
// pcap_geterr at pcap.c:3549:1 in pcap.h
// pcap_setfilter at pcap.c:3807:1 in pcap.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "pcap/pcap.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

static void dummy_cleanup(pcap_t *pcap, struct bpf_program *fp) {
    if (fp != NULL && fp->bf_insns != NULL) {
        pcap_freecode(fp);
    }
    if (pcap != NULL) {
        pcap_close(pcap);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // First two pcap_statustostr and pcap_geterr calls (without pcap_t)
    if (Size > 0) {
        int status1 = (int)Data[0] - 128; // Map to possible negative error codes
        const char *str1 = pcap_statustostr(status1);
        (void)str1; // Use result to avoid unused variable warning
    }
    
    // These will be NULL initially - pcap_geterr requires valid pcap_t
    // We'll call them properly after we have a pcap_t handle
    
    // Second pcap_statustostr
    if (Size > 1) {
        int status2 = (int)Data[1 % Size] - 128;
        const char *str2 = pcap_statustostr(status2);
        (void)str2;
    }
    
    // Now create a pcap_t handle for the remaining functions
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *device = "any"; // Common device name that might work
    int snapshot_len = 65535;
    int promisc = 0;
    int timeout_ms = 1000;
    
    pcap_t *pcap = pcap_open_live(device, snapshot_len, promisc, timeout_ms, errbuf);
    if (pcap == NULL) {
        // If pcap_open_live fails, we can't proceed with most functions
        // But we should still call pcap_close on NULL is safe (does nothing)
        pcap_close(pcap);
        return 0;
    }
    
    // Now we have a pcap_t, call pcap_geterr (first real call with valid handle)
    char *err1 = pcap_geterr(pcap);
    (void)err1;
    
    // Call pcap_fileno
    int fd = pcap_fileno(pcap);
    (void)fd; // Use result
    
    // Prepare for pcap_compile
    struct bpf_program fp;
    memset(&fp, 0, sizeof(fp));
    
    // Use fuzz data as filter string if available
    const char *filter_str = "";
    char *filter_buf = NULL;
    
    if (Size > 0) {
        // Allocate buffer for null-terminated filter string
        filter_buf = (char *)malloc(Size + 1);
        if (filter_buf != NULL) {
            memcpy(filter_buf, Data, Size);
            filter_buf[Size] = '\0';
            filter_str = filter_buf;
        }
    }
    
    int optimize = 0;
    bpf_u_int32 netmask = 0xffffff00; // Typical netmask
    
    int compile_result = pcap_compile(pcap, &fp, filter_str, optimize, netmask);
    
    // Free filter buffer if allocated
    if (filter_buf != NULL) {
        free(filter_buf);
    }
    
    // Get error after compile
    char *err2 = pcap_geterr(pcap);
    (void)err2;
    
    // Only try to set filter if compilation succeeded
    if (compile_result == 0) {
        int setfilter_result = pcap_setfilter(pcap, &fp);
        (void)setfilter_result;
        
        // Get error after setfilter
        char *err3 = pcap_geterr(pcap);
        (void)err3;
    }
    
    // Cleanup
    dummy_cleanup(pcap, &fp);
    
    return 0;
}
