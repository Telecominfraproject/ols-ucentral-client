#include <sys_adpt.h>

#include "api_device.h"
#include "snmp_helper.h"

int dev_get_main_mac(char *mac, int mac_len) {
    int status = snmph_get_single_string(O_MAIN_MAC, OID_LENGTH(O_MAIN_MAC), mac, mac_len);

    if (status != STAT_SUCCESS) {
        return status;
    }

    int i = 0, j = 2;

    for (i = 3; i < 17; i += 3) {
        mac[j++] = mac[i];
        mac[j++] = mac[i + 1];
    }

    mac[12] = 0;

    char *c;
    
    for (c = mac; *c; c++) {
        if (*c >= 'A' && *c <= 'Z') {
            *c += 32;
        }
    }

    return STAT_SUCCESS;
}


int dev_get_serial(char *serial, int serial_len) {
    return snmph_get_single_string(O_SERIAL, OID_LENGTH(O_SERIAL), serial, serial_len);
}

int dev_get_fw_version(char *fw, int fw_len) {
    return snmph_get_single_string(O_OPCODE_VERSION, OID_LENGTH(O_OPCODE_VERSION), fw, fw_len);
}

int dev_get_uptime(uint32_t *up) {
    struct snmp_pdu *response = NULL;
    int status = snmph_get(O_SYS_UPTIME, OID_LENGTH(O_SYS_UPTIME), &response);

    if (status != STATUS_SUCCESS) return status;


    *up = (uint32_t) (response->variables->val.integer[0] / 100 + 0.5);
    snmp_free_pdu(response);
    return STATUS_SUCCESS;
}

int dev_get_vlan_list(int *vlan_arr, int *num) {
    int status;
    
    status = snmph_walk(O_STR_VLAN_STATUS, vlan_arr, num);

    return status;
}

int dev_get_vlan_mask_len(int *len) {
    char oidstr[MAX_OID_LEN];
    struct snmp_pdu *response;

    sprintf(oidstr, "%s.%d", O_STR_VLAN_EGRESS, 1);
    int status = snmph_get_argstr(oidstr, &response);

    if (status != STAT_SUCCESS) {
        fprintf(stderr, "Could not retrieve vlan mask length.\n");
        return status;
    }
    
    *len = response->variables->val_len;

    return STATUS_SUCCESS;
}

int dev_get_poe_port_num(int *num) {
    int status;

    status = snmph_walk(O_STR_POE_PORT_ENABLE, 0, num);

    return status;
}

int dev_get_port_capabilities_val_len(int *len) {
    int status;
    struct snmp_pdu *response = NULL;

    status = snmph_get(O_PORT_CPAPBILITIES, OID_LENGTH(O_PORT_CPAPBILITIES), &response);
    if (status == STATUS_SUCCESS)
        *len = response->variables->val_len;
    snmp_free_pdu(response);  
    return status;
}
