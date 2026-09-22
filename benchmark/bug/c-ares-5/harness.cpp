// This fuzz driver is generated for library cares, aiming to fuzz the following functions:
// ares_free_data at ares_data.c:46:6 in ares.h
// ares_free_data at ares_data.c:46:6 in ares.h
// ares_init at ares_init.c:67:5 in ares.h
// ares_set_servers_ports_csv at ares_update_servers.c:1309:5 in ares.h
// ares_set_servers_csv at ares_update_servers.c:1304:5 in ares.h
// ares_get_servers at ares_update_servers.c:1109:5 in ares.h
// ares_get_servers_ports at ares_update_servers.c:1164:5 in ares.h
// ares_set_servers at ares_update_servers.c:1221:5 in ares.h
// ares_set_servers_ports at ares_update_servers.c:1245:5 in ares.h
// ares_destroy at ares_destroy.c:32:6 in ares.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "ares.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void free_ares_addr_node(struct ares_addr_node *node) {
    while (node) {
        struct ares_addr_node *next = node->next;
        ares_free_data(node);
        node = next;
    }
}

static void free_ares_addr_port_node(struct ares_addr_port_node *node) {
    while (node) {
        struct ares_addr_port_node *next = node->next;
        ares_free_data(node);
        node = next;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // Create null-terminated string from fuzzer input
    char *input_str = (char *)malloc(Size + 1);
    if (!input_str) {
        return 0;
    }
    memcpy(input_str, Data, Size);
    input_str[Size] = '\0';

    // Initialize channel
    ares_channel_t *channel = NULL;
    int status = ares_init(&channel);
    if (status != ARES_SUCCESS) {
        free(input_str);
        return 0;
    }

    // Test ares_set_servers_ports_csv
    ares_set_servers_ports_csv(channel, input_str);

    // Test ares_set_servers_csv
    ares_set_servers_csv(channel, input_str);

    // Test ares_get_servers (deprecated)
    struct ares_addr_node *servers = NULL;
    ares_get_servers(channel, &servers);
    if (servers) {
        free_ares_addr_node(servers);
    }

    // Test ares_get_servers_ports (deprecated)
    struct ares_addr_port_node *servers_ports = NULL;
    ares_get_servers_ports(channel, &servers_ports);
    if (servers_ports) {
        free_ares_addr_port_node(servers_ports);
    }

    // Test ares_set_servers (deprecated) with simple node
    struct ares_addr_node *node = (struct ares_addr_node *)malloc(sizeof(struct ares_addr_node));
    if (node) {
        node->next = NULL;
        node->family = AF_INET;
        node->addr.addr4.s_addr = htonl(0x7f000001); // 127.0.0.1
        ares_set_servers(channel, node);
        free(node);
    }

    // Test ares_set_servers_ports (deprecated) with simple node
    struct ares_addr_port_node *port_node = (struct ares_addr_port_node *)malloc(sizeof(struct ares_addr_port_node));
    if (port_node) {
        port_node->next = NULL;
        port_node->family = AF_INET;
        port_node->addr.addr4.s_addr = htonl(0x7f000001); // 127.0.0.1
        port_node->udp_port = 53;
        port_node->tcp_port = 53;
        ares_set_servers_ports(channel, port_node);
        free(port_node);
    }

    // Cleanup
    ares_destroy(channel);
    free(input_str);
    
    return 0;
}
