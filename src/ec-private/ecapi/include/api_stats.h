#ifndef API_STATS_H
#define API_STATS_H

#include <stdint.h>
#include <stdbool.h>
#include "api_consts.h"

#define IF_LOCATION_SIZE 16
#define IF_NAME_SIZE 32

typedef struct {
    uint32_t collisions;
    uint64_t multicast ;
    uint64_t rx_bytes;
    uint32_t rx_dropped;
    uint32_t rx_errors;
    uint64_t rx_packets;
    uint64_t tx_bytes;
    uint32_t tx_dropped;
    uint32_t tx_errors;
    uint64_t tx_packets;
} counters_t;

typedef struct {
    char location[IF_LOCATION_SIZE];
    char name[IF_NAME_SIZE];
    uint32_t uptime;
    uint32_t speed_dpx_status;
    counters_t counters;
} interface_t;

int get_ethernet_count(int *eth_count);
int get_ethernet_stats(interface_t *eths, int eth_count);
int get_vlans(uint16_t **vlans, int *vlan_count);

#endif
