// This fuzz driver is generated for library cares, aiming to fuzz the following functions:
// ares_parse_txt_reply_ext at ares_parse_txt_reply.c:136:5 in ares.h
// ares_parse_caa_reply at ares_parse_caa_reply.c:30:5 in ares.h
// ares_expand_string at ares_expand_string.c:93:5 in ares.h
// ares_parse_ns_reply at ares_parse_ns_reply.c:39:5 in ares.h
// ares_free_hostent at ares_free_hostent.c:33:6 in ares.h
// ares_parse_a_reply at ares_parse_a_reply.c:48:5 in ares.h
// ares_free_hostent at ares_free_hostent.c:33:6 in ares.h
// ares_parse_aaaa_reply at ares_parse_aaaa_reply.c:51:5 in ares.h
// ares_free_hostent at ares_free_hostent.c:33:6 in ares.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "ares.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void free_txt_ext(struct ares_txt_ext *txt) {
    while (txt) {
        struct ares_txt_ext *next = txt->next;
        free(txt->txt);
        free(txt);
        txt = next;
    }
}

static void free_caa_reply(struct ares_caa_reply *caa) {
    while (caa) {
        struct ares_caa_reply *next = caa->next;
        free(caa->property);
        free(caa->value);
        free(caa);
        caa = next;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;
    
    int alen = (int)Size;
    if (alen < 0) return 0;
    
    // Fuzz ares_parse_txt_reply_ext
    {
        struct ares_txt_ext *txt_out = NULL;
        int ret = ares_parse_txt_reply_ext(Data, alen, &txt_out);
        (void)ret;
        free_txt_ext(txt_out);
    }
    
    // Fuzz ares_parse_caa_reply
    {
        struct ares_caa_reply *caa_out = NULL;
        int ret = ares_parse_caa_reply(Data, alen, &caa_out);
        (void)ret;
        free_caa_reply(caa_out);
    }
    
    // Fuzz ares_expand_string
    {
        unsigned char *s = NULL;
        long enclen = 0;
        int ret = ares_expand_string(Data, Data, alen, &s, &enclen);
        (void)ret;
        if (s) free(s);
    }
    
    // Fuzz ares_parse_ns_reply
    {
        struct hostent *host = NULL;
        int ret = ares_parse_ns_reply(Data, alen, &host);
        (void)ret;
        if (host) ares_free_hostent(host);
    }
    
    // Fuzz ares_parse_a_reply
    {
        struct hostent *host = NULL;
        struct ares_addrttl *addrttls = NULL;
        int naddrttls = 0;
        int ret = ares_parse_a_reply(Data, alen, &host, addrttls, &naddrttls);
        (void)ret;
        if (host) ares_free_hostent(host);
        if (addrttls) free(addrttls);
    }
    
    // Fuzz ares_parse_aaaa_reply
    {
        struct hostent *host = NULL;
        struct ares_addr6ttl *addrttls = NULL;
        int naddrttls = 0;
        int ret = ares_parse_aaaa_reply(Data, alen, &host, addrttls, &naddrttls);
        (void)ret;
        if (host) ares_free_hostent(host);
        if (addrttls) free(addrttls);
    }
    
    return 0;
}
