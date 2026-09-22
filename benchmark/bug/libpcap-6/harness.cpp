// This fuzz driver is generated for library libpcap, aiming to fuzz the following functions:
// pcap_bufsize at pcap.c:3487:1 in pcap.h
// pcap_create at pcap.c:2242:1 in pcap.h
// pcap_activate at pcap.c:2695:1 in pcap.h
// pcap_set_snaplen at pcap.c:2535:1 in pcap.h
// pcap_set_tstamp_precision at pcap.c:2640:1 in pcap.h
// pcap_snapshot at pcap.c:3455:1 in pcap.h
// pcap_bufsize at pcap.c:3487:1 in pcap.h
// pcap_close at pcap.c:4177:1 in pcap.h
// pcap_close at pcap.c:4177:1 in pcap.h
// pcap_open_live at pcap.c:2749:1 in pcap.h
// pcap_snapshot at pcap.c:3455:1 in pcap.h
// pcap_bufsize at pcap.c:3487:1 in pcap.h
// pcap_close at pcap.c:4177:1 in pcap.h
// pcap_create at pcap.c:2242:1 in pcap.h
// pcap_set_snaplen at pcap.c:2535:1 in pcap.h
// pcap_set_tstamp_precision at pcap.c:2640:1 in pcap.h
// pcap_activate at pcap.c:2695:1 in pcap.h
// pcap_snapshot at pcap.c:3455:1 in pcap.h
// pcap_bufsize at pcap.c:3487:1 in pcap.h
// pcap_close at pcap.c:4177:1 in pcap.h
// pcap_close at pcap.c:4177:1 in pcap.h
// pcap_set_snaplen at pcap.c:2535:1 in pcap.h
// pcap_set_tstamp_precision at pcap.c:2640:1 in pcap.h
// pcap_activate at pcap.c:2695:1 in pcap.h
// pcap_snapshot at pcap.c:3455:1 in pcap.h
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

static void dummy_cleanup(pcap_t *pcap) {
    if (pcap) {
        pcap_close(pcap);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Create dummy file for potential offline reading (not used in these APIs but good to have)
    int fd = open("./dummy_file", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        if (Size > 0) {
            write(fd, Data, Size > 1024 ? 1024 : Size);
        }
        close(fd);
    }

    // Initialize error buffer
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof(errbuf));

    // Test pcap_open_live with various inputs
    const char *devices[] = {"lo", "eth0", "any", "wlan0", NULL};
    for (int i = 0; devices[i] != NULL && i < 4; i++) {
        // Use fuzzer data to parameterize the call
        int snaplen = Size > 0 ? (Data[0] % 65535) + 1 : 65535;
        int promisc = Size > 1 ? Data[1] % 2 : 0;
        int timeout = Size > 2 ? (Data[2] % 1000) : 100;
        
        pcap_t *pcap = pcap_open_live(devices[i], snaplen, promisc, timeout, errbuf);
        if (pcap) {
            // Test pcap_snapshot on active handle
            int snap = pcap_snapshot(pcap);
            (void)snap; // Use result to avoid unused variable warning
            
            // Test pcap_bufsize on active handle
            int buf = pcap_bufsize(pcap);
            (void)buf;
            
            pcap_close(pcap);
        }
    }

    // Test pcap_create + pcap_set_snaplen + pcap_set_tstamp_precision + pcap_activate
    pcap_t *pcap = pcap_create("lo", errbuf);
    if (pcap) {
        // Set parameters using fuzzer data
        if (Size > 3) {
            int set_snaplen = pcap_set_snaplen(pcap, Data[3] % 65535);
            (void)set_snaplen;
        }
        
        if (Size > 4) {
            int precision = Data[4] % 3; // 0=PCAP_TSTAMP_PRECISION_MICRO, 1=PCAP_TSTAMP_PRECISION_NANO, 2=other
            int set_precision = pcap_set_tstamp_precision(pcap, precision);
            (void)set_precision;
        }
        
        // Activate the handle
        int activate_ret = pcap_activate(pcap);
        if (activate_ret == 0) {
            // Test pcap_snapshot on successfully activated handle
            int snap = pcap_snapshot(pcap);
            (void)snap;
            
            // Test pcap_bufsize on active handle
            int buf = pcap_bufsize(pcap);
            (void)buf;
        } else if (activate_ret < 0) {
            // On activation failure, close as instructed
            pcap_close(pcap);
            pcap = NULL;
        }
    }
    
    // Cleanup if handle still exists
    if (pcap) {
        pcap_close(pcap);
    }

    // Test edge cases with invalid/null handles
    if (Size > 5 && (Data[5] % 2 == 0)) {
        // Try to call functions with NULL handle
        pcap_t *null_pcap = NULL;
        (void)pcap_set_snaplen(null_pcap, 100);
        (void)pcap_set_tstamp_precision(null_pcap, PCAP_TSTAMP_PRECISION_MICRO);
        (void)pcap_activate(null_pcap);
        (void)pcap_snapshot(null_pcap);
        (void)pcap_bufsize(null_pcap);
    }

    // Test with already activated handle
    if (Size > 6) {
        pcap_t *pcap2 = pcap_create("any", errbuf);
        if (pcap2) {
            if (pcap_activate(pcap2) == 0) {
                // Try to set parameters on already active handle (should fail)
                (void)pcap_set_snaplen(pcap2, 500);
                (void)pcap_set_tstamp_precision(pcap2, PCAP_TSTAMP_PRECISION_NANO);
                
                // These should work
                (void)pcap_snapshot(pcap2);
                (void)pcap_bufsize(pcap2);
            }
            pcap_close(pcap2);
        }
    }

    // Clean up dummy file
    unlink("./dummy_file");
    
    return 0;
}
