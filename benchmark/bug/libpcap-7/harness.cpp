// This fuzz driver is generated for library libpcap, aiming to fuzz the following functions:
// pcap_close at pcap.c:4177:1 in pcap.h
// pcap_findalldevs_ex at pcap.c:4623:1 in pcap.h
// pcap_findalldevs_ex at pcap.c:4623:1 in pcap.h
// pcap_findalldevs_ex at pcap.c:4623:1 in pcap.h
// pcap_freealldevs at pcap.c:1414:1 in pcap.h
// pcap_findalldevs at pcap.c:672:1 in pcap.h
// pcap_parsesrcstr at pcap.c:2235:1 in pcap.h
// pcap_createsrcstr at pcap.c:2121:1 in pcap.h
// pcap_open at pcap.c:4949:1 in pcap.h
// pcap_close at pcap.c:4177:1 in pcap.h
// pcap_open at pcap.c:4949:1 in pcap.h
// pcap_close at pcap.c:4177:1 in pcap.h
// pcap_open at pcap.c:4949:1 in pcap.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "pcap/pcap.h"
#include "pcap/namedb.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>

#define ERRBUFSIZE 256
#define HOSTSIZE 256
#define PORTSIZE 16
#define NAMESIZE 256
#define SOURCESIZE 256

static void cleanup_addrinfo(struct addrinfo *ai) {
    if (ai != NULL) {
        freeaddrinfo(ai);
    }
}

static void cleanup_devs(pcap_if_t *alldevs) {
    if (alldevs != NULL) {
        pcap_freealldevs(alldevs);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Create a null-terminated string from fuzzer input
    char *input_str = static_cast<char *>(malloc(Size + 1));
    if (input_str == NULL) {
        return 0;
    }
    memcpy(input_str, Data, Size);
    input_str[Size] = '\0';

    // 1. Test pcap_nametoaddrinfo
    struct addrinfo *ai = pcap_nametoaddrinfo(input_str);
    cleanup_addrinfo(ai);

    // 2. Test pcap_findalldevs
    pcap_if_t *alldevs = NULL;
    char errbuf1[ERRBUFSIZE];
    int ret1 = pcap_findalldevs(&alldevs, errbuf1);
    if (ret1 != -1) {
        cleanup_devs(alldevs);
        alldevs = NULL;
    }

    // 3. Test pcap_parsesrcstr
    int type = 0;
    char host[HOSTSIZE];
    char port[PORTSIZE];
    char name[NAMESIZE];
    char errbuf2[ERRBUFSIZE];
    int ret2 = pcap_parsesrcstr(input_str, &type, host, port, name, errbuf2);

    // 4. Test pcap_createsrcstr
    char source[SOURCESIZE];
    char errbuf3[ERRBUFSIZE];
    
    // Use parsed values or create new ones
    const char *test_host = (ret2 == 0 && host[0] != '\0') ? host : "example.com";
    const char *test_port = (ret2 == 0 && port[0] != '\0') ? port : "80";
    const char *test_name = (ret2 == 0 && name[0] != '\0') ? name : "eth0";
    int test_type = (ret2 == 0) ? type : PCAP_SRC_IFREMOTE;
    
    int ret3 = pcap_createsrcstr(source, test_type, test_host, test_port, test_name, errbuf3);

    // 5. Test pcap_open with various scenarios
    char errbuf4[ERRBUFSIZE];
    pcap_t *pcap_handle = NULL;
    
    // Try with the created source string
    if (ret3 == 0) {
        pcap_handle = pcap_open(source, 65535, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf4);
        if (pcap_handle != NULL) {
            pcap_close(pcap_handle);
            pcap_handle = NULL;
        }
    }
    
    // Try with "any" device
    pcap_handle = pcap_open("any", 65535, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf4);
    if (pcap_handle != NULL) {
        pcap_close(pcap_handle);
        pcap_handle = NULL;
    }
    
    // Try with the original input as source
    pcap_handle = pcap_open(input_str, 65535, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf4);
    if (pcap_handle != NULL) {
        pcap_close(pcap_handle);
        pcap_handle = NULL;
    }

    // 6. Test pcap_findalldevs_ex
    char errbuf5[ERRBUFSIZE];
    pcap_if_t *alldevs_ex = NULL;
    
    // Try with local source
    int ret6_local = pcap_findalldevs_ex("rpcap://", NULL, &alldevs_ex, errbuf5);
    if (ret6_local != -1) {
        cleanup_devs(alldevs_ex);
        alldevs_ex = NULL;
    }
    
    // Try with the created source string
    if (ret3 == 0) {
        int ret6_remote = pcap_findalldevs_ex(source, NULL, &alldevs_ex, errbuf5);
        if (ret6_remote != -1) {
            cleanup_devs(alldevs_ex);
            alldevs_ex = NULL;
        }
    }
    
    // Try with the original input as source
    int ret6_input = pcap_findalldevs_ex(input_str, NULL, &alldevs_ex, errbuf5);
    if (ret6_input != -1) {
        cleanup_devs(alldevs_ex);
        alldevs_ex = NULL;
    }

    free(input_str);
    return 0;
}
