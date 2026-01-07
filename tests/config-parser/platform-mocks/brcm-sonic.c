/*
 * Platform Mock: Broadcom SONiC (brcm-sonic)
 *
 * This file provides mock implementations of the gNMI/gNOI APIs
 * used by the brcm-sonic platform. These mocks allow integration
 * testing of the platform code without requiring actual hardware
 * or gNMI server connection.
 *
 * Mock Strategy:
 * - All functions return success (0) by default
 * - Logs function calls for debugging
 * - No actual hardware interaction
 *
 * ITERATIVE DEVELOPMENT:
 * Start with minimal mocks and add more as linker reports undefined references.
 */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

/* Platform includes */
#include <time.h>
#include "gnma/gnma_common.h"
#include "ucentral.h"

/* ============================================================================
 * MOCK CONFIGURATION
 * ============================================================================
 * These constants control the mock behavior to simulate realistic hardware
 */

/* Number of ports to simulate (matches ECS4150-54P/54T hardware) */
#define MOCK_NUM_PORTS 54

/* ============================================================================
 * GLOBAL VARIABLES (from ucentral-client.c)
 * ============================================================================
 * These are needed by proto.c but not provided by platform library
 */

struct client_config client = {
	.redirector_file = "/tmp/test",
	.redirector_file_dbg = "/tmp/test",
	.ols_client_version_file = "/tmp/test",
	.ols_schema_version_file = "/tmp/test",
	.server = "test.example.com",
	.port = 443,
	.path = "/",
	.serial = "TEST123456",
	.CN = "test",
	.firmware = "1.0.0",
	.devid = "00000000-0000-0000-0000-000000000000",
	.selfsigned = 0,
	.debug = 0
};
time_t conn_time = 0;
struct plat_metrics_cfg ucentral_metrics = {0};

/* ============================================================================
 * FEATURE STATUS MOCKS
 * ============================================================================
 * The platform checks feature initialization status. Mock all features as OK.
 */

#define FEAT_CORE 0
#define FEAT_AAA  1
#define FEATSTS_OK 0

int featsts[10] = {FEATSTS_OK, FEATSTS_OK, FEATSTS_OK}; /* All features OK */

/* ============================================================================
 * FUNCTION MOCKS
 * ============================================================================
 * Add mock functions here as the linker reports undefined references.
 * See tests/ADDING_NEW_PLATFORM.md for guidance.
 */

/*
 * When you get linker errors like:
 *   undefined reference to `gnma_some_function'
 *
 * Add a mock implementation like this:
 *
 * int gnma_some_function(parameters...)
 * {
 *     fprintf(stderr, "[MOCK:brcm-sonic] gnma_some_function(...)\n");
 *     return GNMA_OK;  // or 0 for success
 * }
 *
 * Then rebuild and check for more undefined references.
 * Iterate until the build succeeds.
 */

/* VLAN Management Mocks */
int gnma_vlan_list_get(BITMAP_DECLARE(vlans, GNMA_MAX_VLANS))
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_vlan_list_get()\n");
	/* Return empty VLAN list (all zeros) */
	memset(vlans, 0, BITS_TO_UINT32(GNMA_MAX_VLANS) * sizeof(uint32_t));
	return 0; /* Success */
}

int gnma_vlan_remove(uint16_t vid)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_vlan_remove(vid=%u)\n", vid);
	return 0; /* Success */
}

int gnma_vlan_member_bmap_get(struct gnma_vlan_member_bmap *vlan_mbr)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_vlan_member_bmap_get()\n");
	/* Return empty member bitmap */
	memset(vlan_mbr, 0, sizeof(*vlan_mbr));
	return 0; /* Success */
}

struct gnma_change *gnma_change_create(void)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_change_create()\n");
	/* Return a dummy non-NULL pointer */
	return (struct gnma_change *)0x1; /* Mock handle */
}

int gnma_vlan_create(struct gnma_change *c, uint16_t vid)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_vlan_create(vid=%u)\n", vid);
	(void)c;
	return 0; /* Success */
}

int gnma_change_exec(struct gnma_change *c)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_change_exec()\n");
	(void)c;
	return 0; /* Success */
}

/* STP Mocks */
int gnma_stp_mode_set(gnma_stp_mode_t mode, struct gnma_stp_attr *attr)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_stp_mode_set(mode=%d)\n", mode);
	(void)attr;
	return 0;
}

int gnma_stp_vid_set(uint16_t vid, struct gnma_stp_attr *attr)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_stp_vid_set(vid=%u)\n", vid);
	(void)attr;
	return 0;
}

/* 802.1X Mocks */
int gnma_port_ieee8021x_pae_mode_set(struct gnma_port_key *port_key, bool is_authenticator)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_port_ieee8021x_pae_mode_set(is_authenticator=%d)\n", is_authenticator);
	(void)port_key;
	return 0;
}

int gnma_port_ieee8021x_port_ctrl_set(struct gnma_port_key *port_key, gnma_8021x_port_ctrl_mode_t mode)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_port_ieee8021x_port_ctrl_set(mode=%d)\n", mode);
	(void)port_key;
	return 0;
}

int gnma_port_ieee8021x_port_host_mode_set(struct gnma_port_key *port_key, gnma_8021x_port_host_mode_t mode)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_port_ieee8021x_port_host_mode_set(mode=%d)\n", mode);
	(void)port_key;
	return 0;
}

int gnma_port_ieee8021x_guest_vlan_set(struct gnma_port_key *port_key, uint16_t vid)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_port_ieee8021x_guest_vlan_set(vlan=%u)\n", vid);
	(void)port_key;
	return 0;
}

int gnma_port_ieee8021x_unauthorized_vlan_set(struct gnma_port_key *port_key, uint16_t vid)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_port_ieee8021x_unauthorized_vlan_set(vlan=%u)\n", vid);
	(void)port_key;
	return 0;
}

int gnma_ieee8021x_system_auth_control_set(bool is_enabled)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_ieee8021x_system_auth_control_set(enabled=%d)\n", is_enabled);
	return 0;
}

int gnma_ieee8021x_das_dac_host_remove(struct gnma_das_dac_host_key *key)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_ieee8021x_das_dac_host_remove()\n");
	(void)key;
	return 0;
}

int gnma_ieee8021x_das_dac_host_add(struct gnma_das_dac_host_key *key, const char *passkey)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_ieee8021x_das_dac_host_add()\n");
	(void)key;
	(void)passkey;
	return 0;
}

/* PoE Mocks */
int gnma_poe_port_detection_mode_set(struct gnma_port_key *port_key, gnma_poe_port_detection_mode_t mode)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_poe_port_detection_mode_set(mode=%d)\n", mode);
	(void)port_key;
	return 0;
}

int gnma_poe_port_priority_set(struct gnma_port_key *port_key, gnma_poe_port_priority_t priority)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_poe_port_priority_set(priority=%d)\n", priority);
	(void)port_key;
	return 0;
}

int gnma_poe_port_power_limit_set(struct gnma_port_key *port_key, bool user_defined, uint32_t power_limit)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_poe_port_power_limit_set(user_defined=%d, limit=%u)\n",
	        user_defined, power_limit);
	(void)port_key;
	return 0;
}

int gnma_poe_port_admin_mode_set(struct gnma_port_key *port_key, bool enabled)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_poe_port_admin_mode_set(enabled=%d)\n", enabled);
	(void)port_key;
	return 0;
}

int gnma_poe_port_reset(struct gnma_port_key *port_key)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_poe_port_reset()\n");
	(void)port_key;
	return 0;
}

int gnma_poe_power_mgmt_set(gnma_poe_power_mgmt_mode_t mode)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_poe_power_mgmt_set(mode=%d)\n", mode);
	return 0;
}

int gnma_poe_usage_threshold_set(uint8_t threshold)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_poe_usage_threshold_set(threshold=%u)\n", threshold);
	return 0;
}

/* Routing Mocks */
int gnma_route_remove(uint16_t vr_id, struct gnma_ip_prefix *prefix)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_route_remove(vr_id=%u)\n", vr_id);
	(void)prefix;
	return 0;
}

int gnma_route_create(uint16_t vr_id, struct gnma_ip_prefix *prefix, struct gnma_route_attrs *attr)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_route_create(vr_id=%u)\n", vr_id);
	(void)prefix;
	(void)attr;
	return 0;
}

/* RADIUS Mocks */
int gnma_radius_host_remove(struct gnma_radius_host_key *key)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_radius_host_remove()\n");
	(void)key;
	return 0;
}

int gnma_radius_host_add(struct gnma_radius_host_key *key, const char *passkey,
                         uint16_t auth_port, uint8_t prio)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_radius_host_add(port=%u, prio=%u)\n",
	        auth_port, prio);
	(void)key;
	(void)passkey;
	return 0;
}

/* System Mocks */
int gnma_system_password_set(char *password)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_system_password_set()\n");
	(void)password; /* Don't log passwords */
	return 0;
}

int gnma_techsupport_start(char *res_path)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_techsupport_start()\n");
	(void)res_path;
	return 0;
}

/* Configuration Management Mocks */
int gnma_config_restore(void)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_config_restore()\n");
	return 0;
}

int gnma_factory_default(void)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_factory_default()\n");
	return 0;
}

int gnma_metadata_get(struct gnma_metadata *md)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_metadata_get()\n");
	(void)md;
	return 0;
}

/* Firmware Upgrade Mocks */
int gnma_image_install(char *uri)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_image_install(uri=%s)\n", uri);
	return 0;
}

int gnma_image_install_status(uint16_t *buf_size, char *buf)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_image_install_status()\n");
	(void)buf_size;
	(void)buf;
	return 0;
}

int gnma_image_running_name_get(char *str, size_t str_max_len)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_image_running_name_get()\n");
	(void)str;
	(void)str_max_len;
	return 0;
}

int gnma_rebootcause_get(char *buf, size_t buf_size)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_rebootcause_get()\n");
	(void)buf;
	(void)buf_size;
	return 0;
}

/* Subscription/Telemetry Mocks */
int gnma_subscribe(void **handle, const struct gnma_subscribe_callbacks *callbacks)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_subscribe()\n");
	(void)handle;
	(void)callbacks;
	return 0;
}

void gnma_unsubscribe(void **handle)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_unsubscribe()\n");
	(void)handle;
}

/* Syslog Mocks */
int gnma_syslog_cfg_clear(void)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_syslog_cfg_clear()\n");
	return 0;
}

int gnma_syslog_cfg_set(struct gnma_syslog_cfg *cfg, int count)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_syslog_cfg_set(count=%d)\n", count);
	(void)cfg;
	return 0;
}

/* VLAN/RIF Mocks */
int gnma_vlan_erif_attr_pref_list_get(uint16_t vid, uint16_t *list_size, struct gnma_ip_prefix *prefix_list)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_vlan_erif_attr_pref_list_get(vid=%u)\n", vid);
	(void)list_size;
	(void)prefix_list;
	return 0;
}

int gnma_vlan_erif_attr_pref_delete(uint16_t vid, struct gnma_ip_prefix *pref)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_vlan_erif_attr_pref_delete(vid=%u)\n", vid);
	(void)pref;
	return 0;
}

int gnma_vlan_erif_attr_pref_update(uint16_t vid, uint16_t list_size, struct gnma_ip_prefix *pref)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_vlan_erif_attr_pref_update(vid=%u, list_size=%u)\n",
	        vid, list_size);
	(void)pref;
	return 0;
}

/* DHCP Relay Mocks */
int gnma_vlan_dhcp_relay_server_remove(uint16_t vid, struct gnma_ip *ip)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_vlan_dhcp_relay_server_remove(vid=%u)\n", vid);
	(void)ip;
	return 0;
}

int gnma_vlan_dhcp_relay_server_add(uint16_t vid, struct gnma_ip *ip)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_vlan_dhcp_relay_server_add(vid=%u)\n", vid);
	(void)ip;
	return 0;
}

int gnma_vlan_dhcp_relay_max_hop_cnt_set(uint16_t vid, uint8_t max_hop)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_vlan_dhcp_relay_max_hop_cnt_set(vid=%u, max_hop=%u)\n",
	        vid, max_hop);
	return 0;
}

int gnma_vlan_dhcp_relay_policy_action_set(uint16_t vid, gnma_dhcp_relay_policy_action_type_t act)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_vlan_dhcp_relay_policy_action_set(vid=%u, action=%d)\n",
	        vid, act);
	return 0;
}

int gnma_vlan_dhcp_relay_ciruit_id_set(uint16_t vid, gnma_dhcp_relay_circuit_id_t id)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_vlan_dhcp_relay_ciruit_id_set(vid=%u, id=%d)\n",
	        vid, id);
	return 0;
}

/* IGMP Snooping Mocks */
int gnma_igmp_snooping_set(uint16_t vid, struct gnma_igmp_snoop_attr *attr)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_igmp_snooping_set(vid=%u)\n", vid);
	(void)attr;
	return 0;
}

int gnma_igmp_static_groups_set(uint16_t vid, size_t num_groups, struct gnma_igmp_static_group_attr *groups)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_igmp_static_groups_set(vid=%u, num_groups=%zu)\n",
	        vid, num_groups);
	(void)groups;
	return 0;
}

/* Port L2 RIF Mocks */
int gnma_portl2_erif_attr_pref_delete(struct gnma_port_key *port_key, struct gnma_ip_prefix *pref)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_portl2_erif_attr_pref_delete()\n");
	(void)port_key;
	(void)pref;
	return 0;
}

int gnma_portl2_erif_attr_pref_update(struct gnma_port_key *port_key, uint16_t list_size, struct gnma_ip_prefix *pref)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_portl2_erif_attr_pref_update(list_size=%u)\n",
	        list_size);
	(void)port_key;
	(void)pref;
	return 0;
}

/* Port List Mocks */
/**
 * gnma_port_list_get - Get list of available ports (dynamic mock)
 * @list_size: [in/out] Buffer size on input, actual port count on output
 * @port_key_list: [out] Array to fill with port information
 *
 * This mock simulates the real gNMI API behavior:
 * 1. If buffer is too small: Returns GNMA_ERR_OVERFLOW, sets *list_size to required size
 * 2. If buffer is sufficient: Fills port_key_list with port names, returns 0
 *
 * This allows the platform code to query the number of ports dynamically:
 *   uint16_t size = 1;
 *   gnma_port_list_get(&size, &dummy);  // Returns GNMA_ERR_OVERFLOW, size=54
 *   array = malloc(size * sizeof(*array));
 *   gnma_port_list_get(&size, array);   // Returns 0, fills array
 */
int gnma_port_list_get(uint16_t *list_size, struct gnma_port_key *port_key_list)
{
	uint16_t requested_size = list_size ? *list_size : 0;
	uint16_t actual_ports = MOCK_NUM_PORTS;
	uint16_t i;

	fprintf(stderr, "[MOCK:brcm-sonic] gnma_port_list_get(requested=%u, actual=%u)\n",
	        requested_size, actual_ports);

	/* Always return the actual number of ports available */
	if (list_size) {
		*list_size = actual_ports;
	}

	/* If buffer is too small, return overflow error */
	if (requested_size < actual_ports) {
		fprintf(stderr, "[MOCK:brcm-sonic]   -> GNMA_ERR_OVERFLOW (need %u slots)\n", actual_ports);
		return GNMA_ERR_OVERFLOW;
	}

	/* Fill in port names like Ethernet0, Ethernet1, ..., Ethernet53 */
	if (port_key_list) {
		for (i = 0; i < actual_ports; i++) {
			snprintf(port_key_list[i].name, sizeof(port_key_list[i].name), "Ethernet%u", i);
		}
		fprintf(stderr, "[MOCK:brcm-sonic]   -> SUCCESS (filled %u ports)\n", actual_ports);
	}

	return 0;
}

/* IP Interface Mocks */
int gnma_ip_iface_addr_get(struct gnma_vlan_ip_t *address_list, size_t *list_size)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_ip_iface_addr_get()\n");
	(void)address_list;
	(void)list_size;
	return 0;
}

/* MAC Address Table Mocks */
int gnma_mac_address_list_get(size_t *list_size, struct gnma_fdb_entry *list)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_mac_address_list_get()\n");
	(void)list_size;
	(void)list;
	return 0;
}

/* 802.1X Stats Mocks */
int gnma_iee8021x_das_dac_global_stats_get(uint32_t num_of_counters,
                                             gnma_ieee8021x_das_dac_stat_type_t *counter_ids,
                                             uint64_t *counters)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_iee8021x_das_dac_global_stats_get(num_counters=%u)\n",
	        num_of_counters);
	(void)counter_ids;
	(void)counters;
	return 0;
}

/* Dynamic Route Mocks */
int gnma_dyn_route_list_get(size_t *list_size, struct gnma_ip_prefix *prefix_list, struct gnma_route_attrs *attr_list)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_dyn_route_list_get()\n");
	(void)list_size;
	(void)prefix_list;
	(void)attr_list;
	return 0;
}

/* Neighbor Mocks */
int gnma_nei_addr_get(struct gnma_port_key *iface, struct in_addr *ip, char *mac, size_t buf_size)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_nei_addr_get()\n");
	(void)iface;
	(void)ip;
	(void)mac;
	(void)buf_size;
	return 0;
}

/* Change Management Mocks */
void gnma_change_destory(struct gnma_change *c)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_change_destory()\n");
	(void)c;
}

/* STP Port Mocks */
int gnma_stp_ports_enable(uint32_t list_size, struct gnma_port_key *ports_list)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_stp_ports_enable(list_size=%u)\n", list_size);
	(void)ports_list;
	return 0;
}

/* GET Functions for Telemetry/State */
int gnma_poe_port_list_get(uint16_t *list_size, struct gnma_port_key *port_key_arr)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_poe_port_list_get()\n");
	if (list_size) *list_size = 0;
	(void)port_key_arr;
	return 0;
}

int gnma_poe_port_admin_mode_get(struct gnma_port_key *port_key, bool *enabled)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_poe_port_admin_mode_get()\n");
	(void)port_key;
	if (enabled) *enabled = false;
	return 0;
}

int gnma_poe_port_detection_mode_get(struct gnma_port_key *port_key, gnma_poe_port_detection_mode_t *mode)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_poe_port_detection_mode_get()\n");
	(void)port_key;
	(void)mode;
	return 0;
}

int gnma_poe_port_power_limit_get(struct gnma_port_key *port_key, bool *user_defined, uint32_t *power_limit)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_poe_port_power_limit_get()\n");
	(void)port_key;
	(void)user_defined;
	(void)power_limit;
	return 0;
}

int gnma_poe_port_priority_get(struct gnma_port_key *port_key, gnma_poe_port_priority_t *priority)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_poe_port_priority_get()\n");
	(void)port_key;
	(void)priority;
	return 0;
}

int gnma_poe_power_mgmt_get(gnma_poe_power_mgmt_mode_t *mode)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_poe_power_mgmt_get()\n");
	(void)mode;
	return 0;
}

int gnma_poe_usage_threshold_get(uint8_t *power_threshold)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_poe_usage_threshold_get()\n");
	(void)power_threshold;
	return 0;
}

int gnma_radius_hosts_list_get(size_t *list_size, struct gnma_radius_host_key *key_arr)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_radius_hosts_list_get()\n");
	if (list_size) *list_size = 0;
	(void)key_arr;
	return 0;
}

int gnma_portl2_erif_attr_pref_list_get(struct gnma_port_key *port_key, uint16_t *list_size, struct gnma_ip_prefix *prefix_list)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_portl2_erif_attr_pref_list_get()\n");
	(void)port_key;
	if (list_size) *list_size = 0;
	(void)prefix_list;
	return 0;
}

int gnma_port_ieee8021x_pae_mode_get(struct gnma_port_key *port_key, bool *is_authenticator)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_port_ieee8021x_pae_mode_get()\n");
	(void)port_key;
	(void)is_authenticator;
	return 0;
}

int gnma_port_ieee8021x_port_ctrl_get(struct gnma_port_key *port_key, gnma_8021x_port_ctrl_mode_t *mode)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_port_ieee8021x_port_ctrl_get()\n");
	(void)port_key;
	(void)mode;
	return 0;
}

int gnma_port_ieee8021x_port_host_mode_get(struct gnma_port_key *port_key, gnma_8021x_port_host_mode_t *mode)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_port_ieee8021x_port_host_mode_get()\n");
	(void)port_key;
	(void)mode;
	return 0;
}

int gnma_port_ieee8021x_guest_vlan_get(struct gnma_port_key *port_key, uint16_t *vid)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_port_ieee8021x_guest_vlan_get()\n");
	(void)port_key;
	(void)vid;
	return 0;
}

int gnma_port_ieee8021x_unauthorized_vlan_get(struct gnma_port_key *port_key, uint16_t *vid)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_port_ieee8021x_unauthorized_vlan_get()\n");
	(void)port_key;
	(void)vid;
	return 0;
}

int gnma_ieee8021x_das_dac_hosts_list_get(size_t *list_size, struct gnma_das_dac_host_key *das_dac_keys_arr)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_ieee8021x_das_dac_hosts_list_get()\n");
	if (list_size) *list_size = 0;
	(void)das_dac_keys_arr;
	return 0;
}

int gnma_ieee8021x_system_auth_control_get(bool *is_enabled)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_ieee8021x_system_auth_control_get()\n");
	if (is_enabled) *is_enabled = false;
	return 0;
}

int gnma_ieee8021x_das_bounce_port_ignore_get(bool *enabled)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_ieee8021x_das_bounce_port_ignore_get()\n");
	if (enabled) *enabled = false;
	return 0;
}

int gnma_ieee8021x_system_auth_clients_get(char *buf, size_t buf_size)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_ieee8021x_system_auth_clients_get()\n");
	(void)buf;
	(void)buf_size;
	return 0;
}

int gnma_port_lldp_peer_info_get(struct gnma_port_key *port_key, char *buf, size_t buf_size)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_port_lldp_peer_info_get()\n");
	(void)port_key;
	(void)buf;
	(void)buf_size;
	return 0;
}

int gnma_igmp_iface_groups_get(struct gnma_port_key *iface, char *buf, size_t *buf_size)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_igmp_iface_groups_get()\n");
	(void)iface;
	(void)buf;
	(void)buf_size;
	return 0;
}

int gnma_poe_port_state_get(struct gnma_port_key *port_key, char *buf, size_t buf_size)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_poe_port_state_get()\n");
	(void)port_key;
	(void)buf;
	(void)buf_size;
	return 0;
}

int gnma_poe_state_get(char *buf, size_t buf_size)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_poe_state_get()\n");
	(void)buf;
	(void)buf_size;
	return 0;
}

int gnma_vlan_member_remove(struct gnma_change *c, uint16_t vid, struct gnma_port_key *port_key)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_vlan_member_remove(vid=%u)\n", vid);
	(void)c;
	(void)port_key;
	return 0;
}

int gnma_vlan_member_create(struct gnma_change *c, uint16_t vid, struct gnma_port_key *port_key, bool tagged)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_vlan_member_create(vid=%u, tagged=%d)\n", vid, tagged);
	(void)c;
	(void)port_key;
	return 0;
}

int gnma_reboot(void)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_reboot()\n");
	return 0;
}

int gnma_config_save(void)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_config_save()\n");
	return 0;
}

/* ============================================================================
 * ADDITIONAL MOCK FUNCTIONS (Added for complete platform testing)
 * ============================================================================ */

int gnma_switch_create(void)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_switch_create()\n");
	return 0;
}

int gnma_port_admin_state_set(struct gnma_port_key *port_key, bool up)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_port_admin_state_set(up=%d)\n", up);
	(void)port_key;
	return 0;
}

int gnma_port_speed_set(struct gnma_port_key *port_key, const char *speed)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_port_speed_set(speed=%s)\n", speed ? speed : "NULL");
	(void)port_key;
	return 0;
}

int gnma_port_duplex_set(struct gnma_port_key *port_key, bool full_duplex)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_port_duplex_set(full_duplex=%d)\n", full_duplex);
	(void)port_key;
	return 0;
}

int gnma_port_speed_get(struct gnma_port_key *port_key, char *speed, size_t speed_size)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_port_speed_get()\n");
	(void)port_key;
	if (speed && speed_size > 0) {
		snprintf(speed, speed_size, "1000");
	}
	return 0;
}

int gnma_port_duplex_get(struct gnma_port_key *port_key, bool *full_duplex)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_port_duplex_get()\n");
	(void)port_key;
	if (full_duplex) {
		*full_duplex = true;
	}
	return 0;
}

int gnma_port_oper_status_get(struct gnma_port_key *port_key, bool *is_up)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_port_oper_status_get()\n");
	(void)port_key;
	if (is_up) {
		*is_up = true;
	}
	return 0;
}

int gnma_port_stats_get(struct gnma_port_key *port_key,
			uint32_t num_of_counters,
			gnma_port_stat_type_t *counter_ids,
			uint64_t *counters)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_port_stats_get(num_of_counters=%u)\n", num_of_counters);
	(void)port_key;
	(void)counter_ids;
	if (counters) {
		for (uint32_t i = 0; i < num_of_counters; i++) {
			counters[i] = 0;
		}
	}
	return 0;
}

int gnma_route_list_get(uint16_t vr_id, uint32_t *list_size,
			struct gnma_ip_prefix *prefix_list,
			struct gnma_route_attrs *attr_list)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_route_list_get(vr_id=%u)\n", vr_id);
	(void)prefix_list;
	(void)attr_list;
	if (list_size) {
		*list_size = 0;
	}
	return 0;
}

int gnma_stp_mode_get(gnma_stp_mode_t *mode, struct gnma_stp_attr *attr)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_stp_mode_get()\n");
	if (mode) {
		*mode = GNMA_STP_MODE_RPVST;
	}
	(void)attr;
	return 0;
}

int gnma_stp_vid_bulk_get(struct gnma_stp_attr *list, ssize_t size)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_stp_vid_bulk_get(size=%ld)\n", (long)size);
	(void)list;
	return 0;
}

int gnma_vlan_dhcp_relay_server_list_get(uint16_t vid, size_t *list_size,
					  struct gnma_ip *ip_list)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_vlan_dhcp_relay_server_list_get(vid=%u)\n", vid);
	(void)ip_list;
	if (list_size) {
		*list_size = 0;
	}
	return 0;
}

int gnma_vlan_dhcp_relay_ciruit_id_get(uint16_t vid, gnma_dhcp_relay_circuit_id_t *id)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_vlan_dhcp_relay_ciruit_id_get(vid=%u)\n", vid);
	if (id) {
		memset(id, 0, sizeof(*id));
	}
	return 0;
}

int gnma_vlan_dhcp_relay_policy_action_get(uint16_t vid, gnma_dhcp_relay_policy_action_type_t *action)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_vlan_dhcp_relay_policy_action_get(vid=%u)\n", vid);
	if (action) {
		*action = 0;
	}
	return 0;
}

int gnma_vlan_dhcp_relay_max_hop_cnt_get(uint16_t vid, uint8_t *max_hop_cnt)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_vlan_dhcp_relay_max_hop_cnt_get(vid=%u)\n", vid);
	if (max_hop_cnt) {
		*max_hop_cnt = 10;
	}
	return 0;
}

int gnma_ieee8021x_das_disable_port_ignore_get(bool *disable_port_ignore)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_ieee8021x_das_disable_port_ignore_get()\n");
	if (disable_port_ignore) {
		*disable_port_ignore = false;
	}
	return 0;
}

int gnma_ieee8021x_das_ignore_server_key_get(bool *ignore_server_key)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_ieee8021x_das_ignore_server_key_get()\n");
	if (ignore_server_key) {
		*ignore_server_key = false;
	}
	return 0;
}

int gnma_ieee8021x_das_ignore_session_key_get(bool *ignore_session_key)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_ieee8021x_das_ignore_session_key_get()\n");
	if (ignore_session_key) {
		*ignore_session_key = false;
	}
	return 0;
}

int gnma_ieee8021x_das_auth_type_key_get(gnma_das_auth_type_t *auth_type)
{
	fprintf(stderr, "[MOCK:brcm-sonic] gnma_ieee8021x_das_auth_type_key_get()\n");
	if (auth_type) {
		*auth_type = 0;
	}
	return 0;
}
