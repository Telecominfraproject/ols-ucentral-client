#ifndef API_CONFIG_H
#define API_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    DPX_HALF = 0,
    DPX_FULL,
} duplex_t;

typedef enum {
    M_NONE = 1,
    M_SFP_FORCED_1000 = 7,
    M_SFP_FORCED_10G = 8,
} media_t;

typedef enum {
    VL_NONE = 0,
    VL_TAGGED,
    VL_UNTAGGED,
    VL_FORBIDDEN
} vlan_membership_t;

void *open_config_transaction();
void commit_config_transaction(void *tr);

void add_eth_speed(void *tr, uint16_t eth_num, uint32_t speed, duplex_t duplex);
void add_eth_media(void *tr, uint16_t eth_num, media_t media);

void add_l2_vlan(void *tr, uint16_t vlan_id, 
    uint16_t *tagged_members,    // NULL terminated array / NULL if not required
    uint16_t *un_tagged_members, // NULL terminated array / NULL if not required
    uint16_t *forbidden_members, // NULL terminated array / NULL if not required
    uint16_t *pvid_ports // NULL terminated array / NULL if not required
    );



#endif
