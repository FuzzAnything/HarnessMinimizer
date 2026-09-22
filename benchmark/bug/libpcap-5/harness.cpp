// This fuzz driver is generated for library libpcap, aiming to fuzz the following functions:
// pcap_findalldevs_ex at pcap.c:4623:1 in pcap.h
// pcap_freealldevs at pcap.c:1414:1 in pcap.h
// pcap_lookupdev at pcap.c:1471:1 in pcap.h
// pcap_findalldevs at pcap.c:672:1 in pcap.h
// pcap_freealldevs at pcap.c:1414:1 in pcap.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "pcap/pcap.h"
#include "pcap/namedb.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

static void test_pcap_ether_aton(const uint8_t *data, size_t size) {
    if (size == 0) return;
    
    // Create null-terminated string from fuzzer input
    size_t str_len = size < 100 ? size : 100;
    char *str = (char *)malloc(str_len + 1);
    if (!str) return;
    
    memcpy(str, data, str_len);
    str[str_len] = '\0';
    
    u_char *result = pcap_ether_aton(str);
    if (result) {
        free(result);
    }
    
    free(str);
}

static void test_pcap_lookupdev(const uint8_t *data, size_t size) {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = pcap_lookupdev(errbuf);
    (void)dev; // Mark as used to avoid compiler warning
}

static void test_pcap_next_etherent(const uint8_t *data, size_t size) {
    FILE *fp = fopen("./dummy_file", "wb");
    if (!fp) return;
    
    fwrite(data, 1, size, fp);
    fclose(fp);
    
    fp = fopen("./dummy_file", "rb");
    if (!fp) return;
    
    struct pcap_etherent *ent;
    while ((ent = pcap_next_etherent(fp)) != NULL) {
        // Do nothing, just parse entries
    }
    
    fclose(fp);
}

static void test_pcap_ether_hostton(const uint8_t *data, size_t size) {
    if (size == 0) return;
    
    size_t str_len = size < 100 ? size : 100;
    char *hostname = (char *)malloc(str_len + 1);
    if (!hostname) return;
    
    memcpy(hostname, data, str_len);
    hostname[str_len] = '\0';
    
    u_char *result = pcap_ether_hostton(hostname);
    if (result) {
        free(result);
    }
    
    free(hostname);
}

static void test_pcap_findalldevs(const uint8_t *data, size_t size) {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    int result = pcap_findalldevs(&alldevs, errbuf);
    if (result == 0) {
        pcap_freealldevs(alldevs);
    }
}

static void test_pcap_findalldevs_ex(const uint8_t *data, size_t size) {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_rmtauth auth;
    
    // Initialize auth structure with fuzzer data
    auth.type = size > 0 ? data[0] % 3 : 0;
    
    // Initialize strings to NULL first
    auth.username = NULL;
    auth.password = NULL;
    
    if (size > 1) {
        size_t user_len = (size - 1) < 50 ? (size - 1) : 50;
        if (user_len > 0) {
            auth.username = (char *)malloc(user_len + 1);
            if (auth.username) {
                memcpy(auth.username, data + 1, user_len);
                auth.username[user_len] = '\0';
            }
        }
        
        if (size > 51) {
            size_t pass_len = (size - 51) < 50 ? (size - 51) : 50;
            if (pass_len > 0) {
                auth.password = (char *)malloc(pass_len + 1);
                if (auth.password) {
                    memcpy(auth.password, data + 51, pass_len);
                    auth.password[pass_len] = '\0';
                }
            }
        }
    }
    
    // Try different source types - ensure they are valid non-empty strings
    const char *sources[] = {"rpcap://", "file://", "any", NULL};
    
    for (int i = 0; sources[i] != NULL; i++) {
        // Check if source string is valid and non-empty
        if (sources[i] && sources[i][0] != '\0') {
            // Create a modifiable copy of the source string
            size_t source_len = strlen(sources[i]);
            char *source_copy = (char *)malloc(source_len + 3); // Extra space for potential modifications
            if (!source_copy) continue;
            
            strcpy(source_copy, sources[i]);
            
            int result = pcap_findalldevs_ex(source_copy, &auth, &alldevs, errbuf);
            if (result == 0) {
                pcap_freealldevs(alldevs);
            }
            
            free(source_copy);
        }
    }
    
    if (auth.username) free(auth.username);
    if (auth.password) free(auth.password);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    
    // Use first byte to select which function to test
    unsigned char selector = data[0];
    
    switch (selector % 6) {
        case 0:
            test_pcap_ether_aton(data + 1, size > 1 ? size - 1 : 0);
            break;
        case 1:
            test_pcap_lookupdev(data + 1, size > 1 ? size - 1 : 0);
            break;
        case 2:
            test_pcap_next_etherent(data + 1, size > 1 ? size - 1 : 0);
            break;
        case 3:
            test_pcap_ether_hostton(data + 1, size > 1 ? size - 1 : 0);
            break;
        case 4:
            test_pcap_findalldevs(data + 1, size > 1 ? size - 1 : 0);
            break;
        case 5:
            test_pcap_findalldevs_ex(data + 1, size > 1 ? size - 1 : 0);
            break;
    }
    
    return 0;
}
