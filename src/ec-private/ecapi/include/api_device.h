#ifndef API_DEVICEID_H
#define API_DEVICEID_H

#include <stdint.h>
#include "api_consts.h"

int dev_get_main_mac(char *mac, int mac_len);
int dev_get_serial(char *serial, int serial_len);
int dev_get_fw_version(char *fw, int fw_len);
int dev_get_uptime(uint32_t *up);
int dev_get_vlan_list(int *vlan_arr, int *num);
int dev_get_vlan_mask_len(int *len);
int dev_get_poe_port_num(int *num);
int dev_get_port_capabilities_val_len(int *len);
#endif
