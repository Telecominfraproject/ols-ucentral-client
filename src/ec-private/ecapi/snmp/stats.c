#include <sys_adpt.h>

#include "api_device.h"
#include "api_stats.h"

#include "snmp_helper.h"

#include "if-mib/ifTable/ifTable_constants.h"

const static oid O_IF_COUNT[]       = { 1, 3, 6, 1, 2, 1, 2, 1, 0 };
const static oid O_IF_TYPE[]        = { 1, 3, 6, 1, 2, 1, 2, 2, 1, 3 };
// const static oid O_IF_LAST_CHANGE[] = { 1, 3, 6, 1, 2, 1, 2, 2, 1, 9 };
const static oid O_IF_UPTIME[]      = { SYS_ADPT_PRIVATEMIB_OID, 1, 2, 1, 1, 19 };
const static oid O_SPEED_DPX_STATUS[] = { SYS_ADPT_PRIVATEMIB_OID, 1, 2, 1, 1, 8 };
const static oid OID_IF_NAME[]      = { SYS_ADPT_PRIVATEMIB_OID, 1, 2, 1, 1, 2 };

const static oid O_IF_RX_BYTES_64[]     = { 1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6 };
const static oid O_IF_RX_DISCARD_PKTS[] = { 1, 3, 6, 1, 2, 1, 2, 2, 1, 13 };
const static oid O_IF_RX_ERROR_PKTS[]   = { 1, 3, 6, 1, 2, 1, 2, 2, 1, 14 };
const static oid O_IF_RX_U_PKTS_64[]    = { 1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 7 }; // Unicast packets
const static oid O_IF_RX_MUL_PKTS_64[]  = { 1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 8 }; // Multicast packets
const static oid O_IF_RX_BR_PKTS_64[]   = { 1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 9 };

const static oid O_IF_TX_BYTES_64[]     = { 1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 10 };
const static oid O_IF_TX_DISCARD_PKTS[] = { 1, 3, 6, 1, 2, 1, 2, 2, 1, 19 };
const static oid O_IF_TX_ERROR_PKTS[]   = { 1, 3, 6, 1, 2, 1, 2, 2, 1, 20 };
const static oid O_IF_TX_U_PKTS_64[]    = { 1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 11 }; // Unicast packets
const static oid O_IF_TX_MUL_PKTS_64[]  = { 1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 12 }; // Multicast packets
const static oid O_IF_TX_BR_PKTS_64[]   = { 1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 13 };

int get_ethernet_count(int *eth_count) {
    struct snmp_pdu *response;

    // printf("Try to retrieve IF count...\n");

    int status = snmph_get(O_IF_COUNT, OID_LENGTH(O_IF_COUNT), &response);

    // printf("Retrieved: %d\n", status);

    if (status != STAT_SUCCESS) {
        // printf("Could not retrieve interfaces count\n");
        return status;
    }
    
    // printf("Interfaces: %ld\n", response->variables->val.integer[0]);
    long int max_if = response->variables->val.integer[0];

    snmp_free_pdu(response);

    struct variable_list *vars;

    status = snmph_get_bulk(O_IF_TYPE, OID_LENGTH(O_IF_TYPE), max_if, &response);

    if (status != STAT_SUCCESS) {
        // printf("Could not retrieve types\n");
        return STATUS_ERROR;
    }

    *eth_count = 0;

    for(vars = response->variables; vars; vars = vars->next_variable) {
        // print_variable(vars->name, vars->name_length, vars);
        
        if (vars->val.integer[0] == IANAIFTYPE_ETHERNETCSMACD) {
            (*eth_count)++;
        } else {
            break;
        }
    }

    snmp_free_pdu(response);

    return STATUS_SUCCESS;
}

static int fill_ethernet_stats_32(const oid *req_oid, size_t req_oid_len, int max, uint32_t *val, bool aggregate) {
    struct snmp_pdu *response;
    struct variable_list *vars;
    int status = snmph_get_bulk(req_oid, req_oid_len, max, &response);
    
    if (status != STATUS_SUCCESS) return status;

    uint32_t *addr = val;
    uint32_t local_val = 0;

    int i = 0;
    
    for(vars = response->variables; vars; vars = vars->next_variable) {
        memcpy(&local_val, &vars->val.integer[0], sizeof(uint32_t));

        addr = (uint32_t *) ((char *) val + (sizeof(interface_t) * (i++)));

        if (aggregate) {
            *addr += local_val;
        } else {
            *addr = local_val;
        }
        // addr = (uint32_t *) ((char *) addr + sizeof(interface_t));
    }

    snmp_free_pdu(response);
    return STATUS_SUCCESS;
}

static int fill_ethernet_stats_64(const oid *req_oid, size_t req_oid_len, int max, uint64_t *val, bool aggregate) {
    struct snmp_pdu *response;
    struct variable_list *vars;
    int status = snmph_get_bulk(req_oid, req_oid_len, max, &response);

    if (status != STATUS_SUCCESS) return status;

    uint64_t *addr = val;
    uint64_t local_val = 0;

    int i = 0;

    for(vars = response->variables; vars; vars = vars->next_variable) {
#ifdef ENDIANNESS_ADJUST
        memcpy(&local_val, &vars->val.counter64[0].low, sizeof(uint64_t));
#else
        memcpy(&local_val, &vars->val.counter64[0], sizeof(uint64_t));
#endif
        addr = (uint64_t *) ((char *) val + (sizeof(interface_t) * (i++)));
        if (aggregate) {
            *addr += local_val;
        } else {
            *addr = local_val;
        }
        // addr = (uint64_t *) ((char *) addr + sizeof(interface_t));
    }

    snmp_free_pdu(response);

    return STATUS_SUCCESS;
}

int get_ethernet_stats(interface_t *eths, int eth_count) {
    uint32_t uptime;

    if (dev_get_uptime(&uptime) != STATUS_SUCCESS) return STATUS_ERROR;
    /***************** Interface uptime *****************/
    if (fill_ethernet_stats_32(O_IF_UPTIME, OID_LENGTH(O_IF_UPTIME), eth_count, &eths[0].uptime, false) != STATUS_SUCCESS) return STATUS_ERROR;
    if (fill_ethernet_stats_32(O_SPEED_DPX_STATUS, OID_LENGTH(O_SPEED_DPX_STATUS), eth_count, &eths[0].speed_dpx_status, false) != STATUS_SUCCESS) return STATUS_ERROR;

    int i;

    for (i = 0; i < eth_count; i++) {
        if (eths[i].uptime) {
            eths[i].uptime /= 100;// uptime - (eths[i].uptime / 100);
        }

        snprintf(eths[i].location, IF_LOCATION_SIZE, "%d", i);
    }

    struct snmp_pdu *response;
    struct variable_list *vars;
    int status = snmph_get_bulk(OID_IF_NAME, OID_LENGTH(OID_IF_NAME), eth_count, &response);

    if (status != STATUS_SUCCESS) return status;

    i = 0;
    for(vars = response->variables; vars || i < eth_count; vars = vars->next_variable) {
        strncpy(eths[i].name, (char *)vars->val.string, IF_NAME_SIZE > vars->val_len ? vars->val_len : IF_NAME_SIZE);
        i++;
    }

    snmp_free_pdu(response);
    
    /***************** Bytes (octets) *****************/
    if (fill_ethernet_stats_64(O_IF_RX_BYTES_64, OID_LENGTH(O_IF_RX_BYTES_64), eth_count, &eths[0].counters.rx_bytes, false) != STATUS_SUCCESS) return STATUS_ERROR;
    if (fill_ethernet_stats_64(O_IF_TX_BYTES_64, OID_LENGTH(O_IF_TX_BYTES_64), eth_count, &eths[0].counters.tx_bytes, false) != STATUS_SUCCESS) return STATUS_ERROR;

    /***************** Packets *****************/
    if (fill_ethernet_stats_64(O_IF_RX_MUL_PKTS_64, OID_LENGTH(O_IF_RX_MUL_PKTS_64), eth_count, &eths[0].counters.rx_packets, false) != STATUS_SUCCESS) return STATUS_ERROR;
    if (fill_ethernet_stats_64(O_IF_TX_MUL_PKTS_64, OID_LENGTH(O_IF_TX_MUL_PKTS_64), eth_count, &eths[0].counters.tx_packets, false) != STATUS_SUCCESS) return STATUS_ERROR;

    // "Multicast is the sum of rx+tx multicast packets"
    for (i = 0; i < eth_count; i++) {
        eths[i].counters.multicast = eths[i].counters.rx_packets + eths[i].counters.tx_packets;
    }

    // All packets is a sum (aggregate == true) of unicast, multicast and broadcast packets
    if (fill_ethernet_stats_64(O_IF_RX_U_PKTS_64, OID_LENGTH(O_IF_RX_U_PKTS_64), eth_count, &eths[0].counters.rx_packets, true) != STATUS_SUCCESS) return STATUS_ERROR;
    if (fill_ethernet_stats_64(O_IF_RX_BR_PKTS_64, OID_LENGTH(O_IF_RX_BR_PKTS_64), eth_count, &eths[0].counters.rx_packets, true) != STATUS_SUCCESS) return STATUS_ERROR;

    if (fill_ethernet_stats_64(O_IF_TX_U_PKTS_64, OID_LENGTH(O_IF_TX_U_PKTS_64), eth_count, &eths[0].counters.tx_packets, true) != STATUS_SUCCESS) return STATUS_ERROR;
    if (fill_ethernet_stats_64(O_IF_TX_BR_PKTS_64, OID_LENGTH(O_IF_TX_BR_PKTS_64), eth_count, &eths[0].counters.tx_packets, true) != STATUS_SUCCESS) return STATUS_ERROR;


    /***************** Errors *****************/
    if (fill_ethernet_stats_32(O_IF_RX_ERROR_PKTS, OID_LENGTH(O_IF_RX_ERROR_PKTS), eth_count, &eths[0].counters.rx_errors, false) != STATUS_SUCCESS) return STATUS_ERROR;
    if (fill_ethernet_stats_32(O_IF_TX_ERROR_PKTS, OID_LENGTH(O_IF_TX_ERROR_PKTS), eth_count, &eths[0].counters.tx_errors, false) != STATUS_SUCCESS) return STATUS_ERROR;
    
    /***************** Dropped *****************/
    if (fill_ethernet_stats_32(O_IF_RX_DISCARD_PKTS, OID_LENGTH(O_IF_RX_DISCARD_PKTS), eth_count, &eths[0].counters.rx_dropped, false) != STATUS_SUCCESS) return STATUS_ERROR;
    if (fill_ethernet_stats_32(O_IF_TX_DISCARD_PKTS, OID_LENGTH(O_IF_TX_DISCARD_PKTS), eth_count, &eths[0].counters.tx_dropped, false) != STATUS_SUCCESS) return STATUS_ERROR;
    
    return STATUS_SUCCESS;
}

int get_vlans(uint16_t **vlans, int *vlan_count) {
    struct snmp_pdu *response;
    struct variable_list *vars;

    // printf("Try to retrieve IF count...\n");

    int status = snmph_get(O_IF_COUNT, OID_LENGTH(O_IF_COUNT), &response);

    // printf("Retrieved: %d\n", status);

    if (status != STAT_SUCCESS) {
        printf("Could not retrieve interfaces count\n");
        return status;
    }
    
    // printf("Interfaces: %ld\n", response->variables->val.integer[0]);
    long int max_if = response->variables->val.integer[0];

    status = snmph_get_bulk(O_IF_TYPE, OID_LENGTH(O_IF_TYPE), max_if, &response);

    if (status != STAT_SUCCESS) {
        // printf("VLANS: could not retrieve types\n");
        return STATUS_ERROR;
    }

    *vlan_count = 0;

    for(vars = response->variables; vars; vars = vars->next_variable) {
        // print_variable(vars->name, vars->name_length, vars);
        
        if (vars->val.integer[0] == IANAIFTYPE_L2VLAN || vars->val.integer[0] == IANAIFTYPE_L3IPVLAN) {
            // printf("Found VLAN: %d\n", (int) vars->name[vars->name_length - 1]);
            (*vlan_count)++;
        }
    }

    (*vlans) = malloc(sizeof(uint16_t) * (*vlan_count));
    
    int i = 0;

    for(vars = response->variables; vars; vars = vars->next_variable) {
        // print_variable(vars->name, vars->name_length, vars);
        
        if (vars->val.integer[0] == IANAIFTYPE_L2VLAN || vars->val.integer[0] == IANAIFTYPE_L3IPVLAN) {
            (*vlans)[i++] = (uint16_t) ((int) vars->name[vars->name_length - 1] - 1000);
        }
    }

    return STATUS_SUCCESS;
}
