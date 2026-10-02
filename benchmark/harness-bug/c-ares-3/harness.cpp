// This fuzz driver is generated for library cares, aiming to fuzz the following functions:
// ares_parse_srv_reply at ares_parse_srv_reply.c:30:5 in ares.h
// ares_free_string at ares_free_string.c:30:6 in ares.h
// ares_free_string at ares_free_string.c:30:6 in ares.h
// ares_free_data at ares_data.c:46:6 in ares.h
// ares_free_string at ares_free_string.c:30:6 in ares.h
// ares_free_data at ares_data.c:46:6 in ares.h
// ares_free_string at ares_free_string.c:30:6 in ares.h
// ares_free_string at ares_free_string.c:30:6 in ares.h
// ares_free_string at ares_free_string.c:30:6 in ares.h
// ares_free_string at ares_free_string.c:30:6 in ares.h
// ares_free_data at ares_data.c:46:6 in ares.h
// ares_free_string at ares_free_string.c:30:6 in ares.h
// ares_free_data at ares_data.c:46:6 in ares.h
// ares_free_string at ares_free_string.c:30:6 in ares.h
// ares_free_data at ares_data.c:46:6 in ares.h
// ares_parse_soa_reply at ares_parse_soa_reply.c:30:5 in ares.h
// ares_parse_uri_reply at ares_parse_uri_reply.c:30:5 in ares.h
// ares_parse_naptr_reply at ares_parse_naptr_reply.c:29:5 in ares.h
// ares_parse_mx_reply at ares_parse_mx_reply.c:30:5 in ares.h
// ares_parse_ptr_reply at ares_parse_ptr_reply.c:186:5 in ares.h
// ares_free_hostent at ares_free_hostent.c:33:6 in ares.h
// ares_parse_ptr_reply at ares_parse_ptr_reply.c:186:5 in ares.h
// ares_free_hostent at ares_free_hostent.c:33:6 in ares.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "ares.h"

static void free_soa_reply(struct ares_soa_reply *soa) {
    if (soa) {
        ares_free_string(soa->nsname);
        ares_free_string(soa->hostmaster);
        ares_free_data(soa);
    }
}

static void free_uri_reply(struct ares_uri_reply *uri) {
    while (uri) {
        struct ares_uri_reply *next = uri->next;
        ares_free_string(uri->uri);
        ares_free_data(uri);
        uri = next;
    }
}

static void free_naptr_reply(struct ares_naptr_reply *naptr) {
    while (naptr) {
        struct ares_naptr_reply *next = naptr->next;
        ares_free_string(naptr->flags);
        ares_free_string(naptr->service);
        ares_free_string(naptr->regexp);
        ares_free_string(naptr->replacement);
        ares_free_data(naptr);
        naptr = next;
    }
}

static void free_mx_reply(struct ares_mx_reply *mx) {
    while (mx) {
        struct ares_mx_reply *next = mx->next;
        ares_free_string(mx->host);
        ares_free_data(mx);
        mx = next;
    }
}

static void free_srv_reply(struct ares_srv_reply *srv) {
    while (srv) {
        struct ares_srv_reply *next = srv->next;
        ares_free_string(srv->host);
        ares_free_data(srv);
        srv = next;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // Test ares_parse_soa_reply
    struct ares_soa_reply *soa_out = NULL;
    ares_parse_soa_reply(Data, (int)Size, &soa_out);
    free_soa_reply(soa_out);

    // Test ares_parse_uri_reply
    struct ares_uri_reply *uri_out = NULL;
    ares_parse_uri_reply(Data, (int)Size, &uri_out);
    free_uri_reply(uri_out);

    // Test ares_parse_naptr_reply
    struct ares_naptr_reply *naptr_out = NULL;
    ares_parse_naptr_reply(Data, (int)Size, &naptr_out);
    free_naptr_reply(naptr_out);

    // Test ares_parse_mx_reply
    struct ares_mx_reply *mx_out = NULL;
    ares_parse_mx_reply(Data, (int)Size, &mx_out);
    free_mx_reply(mx_out);

    // Test ares_parse_ptr_reply
    struct hostent *host_out = NULL;
    // Create dummy address data for testing
    unsigned char dummy_addr4[4] = {192, 168, 1, 1};
    unsigned char dummy_addr6[16] = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
                                     0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34};
    
    // Test with IPv4
    ares_parse_ptr_reply(Data, (int)Size, dummy_addr4, 4, AF_INET, &host_out);
    if (host_out) {
        ares_free_hostent(host_out);
    }
    
    // Test with IPv6
    ares_parse_ptr_reply(Data, (int)Size, dummy_addr6, 16, AF_INET6, &host_out);
    if (host_out) {
        ares_free_hostent(host_out);
    }

    // Test ares_parse_srv_reply
    struct ares_srv_reply *srv_out = NULL;
    ares_parse_srv_reply(Data, (int)Size, &srv_out);
    free_srv_reply(srv_out);

    return 0;
}
