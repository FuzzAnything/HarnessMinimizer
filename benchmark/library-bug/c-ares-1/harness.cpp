/* MIT License
 *
 * Copyright (c) The c-ares project and its contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stddef.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <cstring>
#include <sys/select.h>

#include "ares.h"
#include <fuzzer/FuzzedDataProvider.h>

/* Harness 007: Socket management and configuration APIs
 * Primary targets: Socket management APIs (160+ undiscovered branches)
 * 
 * Target APIs:
 * - ares_getsock - 22 undiscovered branches (legacy socket state query)
 * - ares_fds - 20 undiscovered branches (legacy file descriptor set)
 * - ares_set_socket_functions - 16 undiscovered branches (custom socket function configuration)
 * - ares_set_socket_configure_callback - 4 undiscovered branches
 * - ares_set_pending_write_cb - 4 undiscovered branches
 * - ares_set_socket_callback - 2 undiscovered branches
 * - ares_set_sortlist - 21 undiscovered branches (DNS sortlist configuration)
 * - ares_set_local_dev, ares_set_local_ip4, ares_set_local_ip6 - 2 branches each (local interface binding)
 * - ares_queue_wait_empty - 14 undiscovered branches (thread synchronization)
 * 
 * Required helper APIs:
 * - ares_library_init (Global initialization)
 * - ares_init_options (Channel initialization)
 * - ares_query / ares_search (Create active connections for socket inspection)
 * - ares_destroy (Cleanup)
 * - ares_library_cleanup (Global cleanup)
 * 
 * Follows the complete socket management lifecycle:
 * Library init → Channel creation → Configuration → Query execution → Socket inspection → Cleanup
 */

// Custom socket functions for ares_set_socket_functions
static ares_socket_t custom_asocket(int domain, int type, int protocol, void *user_data) {
    // Return invalid socket to simulate failure case
    return ARES_SOCKET_BAD;
}

static int custom_aclose(ares_socket_t sock, void *user_data) {
    // Always fail
    return -1;
}

static int custom_aconnect(ares_socket_t sock, const struct sockaddr *addr, 
                          ares_socklen_t len, void *user_data) {
    // Always fail
    return -1;
}

static ares_ssize_t custom_arecvfrom(ares_socket_t sock, void *buf, size_t len, int flags,
                                    struct sockaddr *from, ares_socklen_t *fromlen, void *user_data) {
    // Return 0 to simulate no data
    return 0;
}

static ares_ssize_t custom_asendv(ares_socket_t sock, const struct iovec *iov, int iovcnt, void *user_data) {
    // Return 0 to simulate no data sent
    return 0;
}

// Socket configure callback for ares_set_socket_configure_callback
static int socket_configure_callback(ares_socket_t sock, int type, void *user_data) {
    // Empty callback for testing
    return 0;
}
// Pending write callback for ares_set_pending_write_cb  
static void pending_write_callback(void *data) {
    // Empty callback for testing
}

// Socket create callback for ares_set_socket_callback
static int socket_create_callback(ares_socket_t socket_fd, int type, void *data) {
    // Empty callback for testing
    return 0;
}

// Dummy query callback for ares_query() and ares_search()
static void dummy_query_callback(void *arg, int status, int timeouts, const unsigned char *abuf, int alen) {
    // Empty callback - queries won't complete due to custom socket functions failing
}

// Dummy DNS record callback for ares_query_dnsrec()
static void dummy_dnsrec_callback(void *arg, ares_status_t status, size_t timeouts, const ares_dns_record_t *dnsrec) {
    // Empty callback
    if (dnsrec) {
        ares_dns_record_destroy((ares_dns_record_t *)dnsrec);  // Cast away const for destruction
    }
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check for basic operations
    if (size < 64) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);

    // Step 1: Global library initialization
    ares_library_init(ARES_LIB_INIT_ALL);

    // Step 2: Channel creation with options
    // Consume fixed-size parameters first
    int optmask = fdp.ConsumeIntegral<int>();
    
    ares_channel_t *channel = NULL;
    ares_options options;
    memset(&options, 0, sizeof(options));
    
    // Set some options based on fuzzer input
    options.flags = fdp.ConsumeIntegral<int>();
    options.timeout = fdp.ConsumeIntegral<int>();
    options.tries = fdp.ConsumeIntegral<int>();
    options.ndots = fdp.ConsumeIntegral<int>();
    options.udp_port = fdp.ConsumeIntegral<unsigned short>();
    options.tcp_port = fdp.ConsumeIntegral<unsigned short>();
    
    int status = ares_init_options(&channel, &options, optmask);
    
    if (status != ARES_SUCCESS || channel == NULL) {
        ares_library_cleanup();
        return 0;
    }

    // Step 3: Configuration APIs
    // 3.1: Set sortlist (DNS server sorting preferences)
    std::string sortlist_str = fdp.ConsumeRandomLengthString(256);
    ares_set_sortlist(channel, sortlist_str.c_str());
    
    // 3.2: Set local interface binding
    // Consume IP addresses and device name from fuzzer input
    uint32_t local_ip4 = fdp.ConsumeIntegral<uint32_t>();
    unsigned char local_ip6[16];
    for (int i = 0; i < 16; i++) {
        local_ip6[i] = fdp.ConsumeIntegral<unsigned char>();
    }
    std::string local_dev = fdp.ConsumeRandomLengthString(64);
    
    ares_set_local_ip4(channel, local_ip4);
    ares_set_local_ip6(channel, local_ip6);
    ares_set_local_dev(channel, local_dev.c_str());
    
    // 3.3: Set custom socket functions
    struct ares_socket_functions socket_funcs;
    socket_funcs.asocket = custom_asocket;
    socket_funcs.aclose = custom_aclose;
    socket_funcs.aconnect = custom_aconnect;
    socket_funcs.arecvfrom = custom_arecvfrom;
    socket_funcs.asendv = custom_asendv;
    
    void *user_data = NULL;  // No user data needed for this harness
    ares_set_socket_functions(channel, &socket_funcs, user_data);
    
    // 3.4: Set socket callbacks
    ares_set_socket_configure_callback(channel, socket_configure_callback, user_data);
    ares_set_pending_write_cb(channel, pending_write_callback, user_data);
    ares_set_socket_callback(channel, socket_create_callback, user_data);
    // Step 4: Query execution to create active connections
    // This is necessary for ares_getsock and ares_fds to return meaningful results
    std::string query_name = fdp.ConsumeRandomLengthString(253); // Max DNS name length
    int query_dnsclass = fdp.ConsumeIntegralInRange<int>(1, 255);
    int query_type = fdp.ConsumeIntegralInRange<int>(1, 65);
    // Launch async queries (they won't complete due to custom socket functions returning errors,
    // but they'll create internal state for socket inspection)
    // Option 1: Use deprecated APIs with dummy callback
    ares_query(channel, query_name.c_str(), query_dnsclass, query_type, dummy_query_callback, NULL);
    ares_search(channel, query_name.c_str(), query_dnsclass, query_type, dummy_query_callback, NULL);
    
    // Option 2: Use newer ares_query_dnsrec() API with dummy callback (alternative approach)
    // unsigned short qid;
    // ares_query_dnsrec(channel, query_name.c_str(), ARES_CLASS_IN, ARES_REC_TYPE_A, 
    //                  dummy_dnsrec_callback, NULL, &qid);
    const int max_socks = 16;
    ares_socket_t socks[max_socks];
    int numsocks = ares_getsock(channel, socks, max_socks);
    
    // 5.2: ares_fds - get file descriptor sets for select()
    fd_set read_fds, write_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    
    int nfds = ares_fds(channel, &read_fds, &write_fds);
    
    // 5.3: ares_timeout - get timeout for select()
    struct timeval maxtv;
    struct timeval tv;
    memset(&maxtv, 0, sizeof(maxtv));
    memset(&tv, 0, sizeof(tv));
    
    struct timeval *timeout_ptr = ares_timeout(channel, &maxtv, &tv);
    
    // 5.4: ares_queue_wait_empty - wait for pending operations to complete
    // Note: This will likely timeout immediately due to custom socket functions failing
    int timeout_ms = fdp.ConsumeIntegralInRange<int>(-1, 1000);
    ares_queue_wait_empty(channel, timeout_ms);
    // Step 6: Cleanup
    ares_destroy(channel);
    ares_library_cleanup();

    return 0;
}
