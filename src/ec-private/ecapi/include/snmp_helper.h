#ifndef SNMP_HELPER_H
#define SNMP_HELPER_H

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include "oid_define.h"

int snmph_session_start(void);
void snmph_session_close(void);

int snmph_get(const oid *req_oid, size_t req_oid_len, struct snmp_pdu **response);
int snmph_get_argstr(const char *oid_str, struct snmp_pdu **response);
int snmph_get_single_string(const oid *req_oid, size_t req_oid_len, char *buf, int buf_len);
int snmph_get_bulk(const oid *req_oid, size_t req_oid_len, int max, struct snmp_pdu **response);
int snmph_set(const char *oid_str, char type, char *value);
int snmph_set_array(const char *oid_str, char type, const u_char *value, size_t len);
int snmph_walk(const char *oid_str, void *buf, int *num);

enum snmp_walk_node {
  SNMP_WALK_NODE_NONE,
  SNMP_WALK_NODE_VLAN_STATUS,
  SNMP_WALK_NODE_POE_PORT_ENABLE,
};

#endif
