#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>
#include <bitmap.h>

#define GNMA_RADIUS_CFG_HOSTNAME_STR_MAX_LEN (64)
#define GNMA_RADIUS_CFG_PASSKEY_STR_MAX_LEN (64)

#define GNMA_OK 0
#define GNMA_ERR_COMMON -1
#define GNMA_ERR_OVERFLOW -2

#define GNMA_PORT_KEY_LEN 32
#define GNMA_METADATA_STR_MAX_LEN (96)

#define GNMA_MAX_PORT_ID 256
#define GNMA_MAX_VLANS 4096

struct gnma_change;

struct gnma_port_key {
	char name[GNMA_PORT_KEY_LEN];
};

struct gnma_radius_host_key {
	char hostname[GNMA_RADIUS_CFG_HOSTNAME_STR_MAX_LEN];
};

struct gnma_das_dac_host_key {
	char hostname[GNMA_RADIUS_CFG_HOSTNAME_STR_MAX_LEN];
};

typedef enum _gnma_das_auth_type_t {
	GNMA_802_1X_DAS_AUTH_TYPE_ANY,
	GNMA_802_1X_DAS_AUTH_TYPE_ALL,
	GNMA_802_1X_DAS_AUTH_TYPE_SESSION_KEY,
} gnma_das_auth_type_t;

struct gnma_metadata {
	char platform[GNMA_METADATA_STR_MAX_LEN];
	char hwsku[GNMA_METADATA_STR_MAX_LEN];
	char mac[GNMA_METADATA_STR_MAX_LEN];
};

struct gnma_syslog_cfg {
	const char *ipaddress;
	int32_t remote_port;
	const char *severity;
	const char *message_type;
	const char *src_intf;
	const char *vrf_name;
};

typedef enum _gnma_port_stat_type_t {
	GNMA_PORT_STAT_IN_OCTETS,		/* SAI_PORT_STAT_IF_IN_OCTETS */
	GNMA_PORT_STAT_IN_DISCARDS,		/* SAI_PORT_STAT_IF_IN_DISCARDS */
	GNMA_PORT_STAT_IN_ERRORS,		/* SAI_PORT_STAT_IF_IN_ERRORS */
	GNMA_PORT_STAT_IN_BCAST_PKTS,		/* SAI_PORT_STAT_IF_IN_BROADCAST_PKTS */
	GNMA_PORT_STAT_IN_MCAST_PKTS,		/* SAI_PORT_STAT_IF_IN_MULTICAST_PKTS */
	GNMA_PORT_STAT_IN_UCAST_PKTS,		/* SAI_PORT_STAT_IF_IN_UCAST_PKTS */

	GNMA_PORT_STAT_OUT_OCTETS,		/* SAI_PORT_STAT_IF_IN_OCTETS */
	GNMA_PORT_STAT_OUT_DISCARDS,		/* SAI_PORT_STAT_IF_IN_DISCARDS */
	GNMA_PORT_STAT_OUT_ERRORS,		/* SAI_PORT_STAT_IF_IN_ERRORS */
	GNMA_PORT_STAT_OUT_BCAST_PKTS,		/* SAI_PORT_STAT_IF_IN_BROADCAST_PKTS */
	GNMA_PORT_STAT_OUT_MCAST_PKTS,		/* SAI_PORT_STAT_IF_IN_MULTICAST_PKTS */
	GNMA_PORT_STAT_OUT_UCAST_PKTS,		/* SAI_PORT_STAT_IF_IN_UCAST_PKTS */

} gnma_port_stat_type_t;

typedef enum _gnma_ieee8021x_das_dac_stat_type_t {
	GNMA_IEEE8021X_DAS_DAC_STAT_IN_COA_PKTS,
	GNMA_IEEE8021X_DAS_DAC_STAT_OUT_COA_ACK_PKTS,
	GNMA_IEEE8021X_DAS_DAC_STAT_OUT_COA_NAK_PKTS,
	GNMA_IEEE8021X_DAS_DAC_STAT_IN_COA_IGNORED_PKTS,
	GNMA_IEEE8021X_DAS_DAC_STAT_IN_COA_WRONG_ATTR_PKTS,
	GNMA_IEEE8021X_DAS_DAC_STAT_IN_COA_WRONG_ATTR_VALUE_PKTS,
	GNMA_IEEE8021X_DAS_DAC_STAT_IN_COA_WRONG_SESSION_CONTEXT_PKTS,
	GNMA_IEEE8021X_DAS_DAC_STAT_IN_COA_ADMINISTRATIVELY_PROHIBITED_REQ_PKTS,
} gnma_ieee8021x_das_dac_stat_type_t;

struct gnma_alarm {
	const char *id;
	const char *resource;
	const char *text;
	uint64_t time_created;
	const char *type_id;
	int severity;
	int acknowledged;
	uint64_t acknowledge_time;
};

struct gnma_ip {
	sa_family_t v;
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} u;
};

struct gnma_ip_prefix {
	struct gnma_ip ip;
	int prefix_len;
};

#define GNMA_IP_PREF_IS_EQ(T, D) ({ \
	struct gnma_ip_prefix _p0 = (T), _p1 = (D); \
	bool _ret; \
 \
	_ret = true; \
 \
	if (_p0.prefix_len != _p1.prefix_len) \
		_ret = false; \
 \
	if (_p0.ip.v != _p1.ip.v) \
		_ret = false; \
 \
	if (_p0.ip.v == AF_INET) { \
		if (memcmp(&_p0.ip.u.v4, &_p1.ip.u.v4, 4)) \
			_ret = false; \
	} \
 \
	if (_p0.ip.v == AF_INET6) { \
		if (memcmp(&_p0.ip.u.v6, &_p1.ip.u.v6, 16)) \
			_ret = false; \
	} \
_ret;})

struct gnma_route_attrs {
	enum {
		/* CONNECTED is not supported by SAI. Instead this is TRAP
		 * and handled by control plane
		 */
		/* On HW this could be routing lookup + prefix 32 lookup */
		GNMA_ROUTE_TYPE_CONNECTED,
		GNMA_ROUTE_TYPE_NEXTHOP,
		GNMA_ROUTE_TYPE_BLACKHOLE
	} type;
	union {
		struct {
			/* We could specify port + vid
			 * Or just vid (if underlayer support FDB lookup after
			 * routing)
			 */
			uint16_t vid;
			/* struct gnma_port_key port; */
			/* NOTE: that each port specification could be
			 * vlan with one port
			 */
		} connected;
		struct {
			uint16_t vid;
			struct in_addr gw;
		} nexthop;
	};
};

typedef enum _gnma_dhcp_relay_policy_action_type_t {
	GNMA_DHCP_RELAY_POLICY_ACTION_DISCARD,
	GNMA_DHCP_RELAY_POLICY_ACTION_APPEND,
	GNMA_DHCP_RELAY_POLICY_ACTION_REPLACE,
} gnma_dhcp_relay_policy_action_type_t;

typedef enum _gnma_dhcp_relay_circuit_id_t {
	GNMA_DHCP_RELAY_CIRCUIT_ID_H_P,
	GNMA_DHCP_RELAY_CIRCUIT_ID_I,
	GNMA_DHCP_RELAY_CIRCUIT_ID_P,
} gnma_dhcp_relay_circuit_id_t;

typedef enum _gnma_poe_port_detection_mode_t {
	GNMA_POE_PORT_DETECTION_MODE_2PT_DOT3AF_E,
	GNMA_POE_PORT_DETECTION_MODE_2PT_DOT3AF_LEG_E,
	GNMA_POE_PORT_DETECTION_MODE_4PT_DOT3AF_E,
	GNMA_POE_PORT_DETECTION_MODE_4PT_DOT3AF_LEG_E,
	GNMA_POE_PORT_DETECTION_MODE_DOT3BT_E,
	GNMA_POE_PORT_DETECTION_MODE_DOT3BT_LEG_E,
	GNMA_POE_PORT_DETECTION_MODE_LEG_E
} gnma_poe_port_detection_mode_t;

typedef enum _gnma_poe_port_priority_t {
	GNMA_POE_PORT_PRIORITY_LOW_E,
	GNMA_POE_PORT_PRIORITY_MEDIUM_E,
	GNMA_POE_PORT_PRIORITY_HIGH_E,
	GNMA_POE_PORT_PRIORITY_CRITICAL_E,
} gnma_poe_port_priority_t;

typedef enum _gnma_poe_power_mgmt_mode_t {
	GNMA_POE_POWER_MGMT_CLASS_E,
	GNMA_POE_POWER_MGMT_DYNAMIC_E,
	GNMA_POE_POWER_MGMT_DYNAMIC_PRIORITY_E,
	GNMA_POE_POWER_MGMT_STATIC_E,
	GNMA_POE_POWER_MGMT_STATIC_PRIORITY_E,
} gnma_poe_power_mgmt_mode_t;

typedef enum _gnma_stp_mode_t {
	GNMA_STP_MODE_NONE,
	GNMA_STP_MODE_RPVST,
	GNMA_STP_MODE_PVST,
	GNMA_STP_MODE_MST
} gnma_stp_mode_t;

struct gnma_stp_attr {
	uint16_t forward_delay;
	uint16_t hello_time;
	uint16_t max_age;
	uint16_t priority;
	bool enabled;
};

struct gnma_stp_port_cfg {
	struct gnma_port_key port; /* KEY */
	uint16_t instance; /* KEY. unused, or vid on pvst or instance on mst */
	uint16_t prio;
	bool enabled;
};

#define gnma_stp_attr_cmp(A, B) ((A)->enabled == (B)->enabled && \
				 (A)->forward_delay == (B)->forward_delay && \
				 (A)->hello_time == (B)->hello_time && \
				 (A)->max_age == (B)->max_age && \
				 (A)->priority == (B)->priority)

typedef void (*gnma_alarm_cb)(struct gnma_alarm *, void *);

struct gnma_linkstatus {
	int64_t timestamp; /* nanosecs */
	const char *ifname;
	int up;
};

typedef void (*gnma_linkstatus_cb)(struct gnma_linkstatus *, void *);

struct gnma_poe_linkstatus {
	int64_t timestamp; /* nanosecs */
	const char *ifname;
	char status[32];
};

typedef void (*gnma_poe_linkstatus_cb)(struct gnma_poe_linkstatus *, void *);

struct gnma_poe_link_faultcode {
	int64_t timestamp; /* nanosecs */
	const char *ifname;
	char faultcode[32];
};

typedef void (*gnma_poe_link_faultcode_cb)(struct gnma_poe_link_faultcode *, void *);

struct gnma_subscribe_callbacks {
	gnma_alarm_cb alarm_cb;
	void *alarm_data;
	gnma_linkstatus_cb linkstatus_cb;
	void *linkstatus_data;
	gnma_poe_linkstatus_cb poe_linkstatus_cb;
	void *poe_linkstatus_data;
	gnma_poe_link_faultcode_cb poe_link_faultcode_cb;
	void *poe_link_faultcode_data;
};

typedef enum _gnma_8021x_port_ctrl_mode_t {
	GNMA_8021X_PORT_CTRL_MODE_FORCE_AUTHORIZED,
	GNMA_8021X_PORT_CTRL_MODE_FORCE_UNAUTHORIZED,
	GNMA_8021X_PORT_CTRL_MODE_AUTO,
} gnma_8021x_port_ctrl_mode_t;

typedef enum _gnma_8021x_port_host_mode_t {
	GNMA_8021X_PORT_HOST_MODE_MULTI_AUTH,
	GNMA_8021X_PORT_HOST_MODE_MULTI_DOMAIN,
	GNMA_8021X_PORT_HOST_MODE_MULTI_HOST,
	GNMA_8021X_PORT_HOST_MODE_SINGLE_HOST,
} gnma_8021x_port_host_mode_t;

struct gnma_vlan_member_bmap {
	struct {
		BITMAP_DECLARE(port_member, GNMA_MAX_PORT_ID);
		BITMAP_DECLARE(port_tagged, GNMA_MAX_PORT_ID);
	} vlan[GNMA_MAX_VLANS];
};

typedef enum _gnma_fdb_entry_type_t {
	GNMA_FDB_ENTRY_TYPE_STATIC,
	GNMA_FDB_ENTRY_TYPE_DYNAMIC,
} gnma_fdb_entry_type_t;

struct gnma_fdb_entry {
	struct gnma_port_key port;
	gnma_fdb_entry_type_t type;
	int vid;
	char mac[18];
};

typedef enum _gnma_igmp_version_t {
	GNMA_IGMP_VERSION_NA = 0,
	GNMA_IGMP_VERSION_1 = 1,
	GNMA_IGMP_VERSION_2 = 2,
	GNMA_IGMP_VERSION_3 = 3
} gnma_igmp_version_t;

struct gnma_igmp_snoop_attr {
	bool enabled;
	bool querier_enabled;
	bool fast_leave_enabled;
	uint32_t query_interval;
	uint32_t last_member_query_interval;
	uint32_t max_response_time;
	gnma_igmp_version_t version;
};

struct gnma_igmp_static_group_attr {
	struct in_addr address;
	size_t num_ports;
	struct gnma_port_key *egress_ports;
};

int gnma_switch_create(/* TODO id */ /* TODO: attr (adr, login, psw) */);
int gnma_port_admin_state_set(struct gnma_port_key *port_key, bool up);
int gnma_port_speed_set(struct gnma_port_key *port_key, const char *speed);
int gnma_port_duplex_set(struct gnma_port_key *port_key, bool full_duplex);
int gnma_port_ieee8021x_pae_mode_set(struct gnma_port_key *port_key,
				     bool is_authenticator);
int gnma_port_ieee8021x_port_ctrl_set(struct gnma_port_key *port_key,
				      gnma_8021x_port_ctrl_mode_t mode);
int gnma_port_ieee8021x_port_host_mode_set(struct gnma_port_key *port_key,
					   gnma_8021x_port_host_mode_t mode);
int gnma_port_ieee8021x_guest_vlan_set(struct gnma_port_key *port_key,
				       uint16_t vid);
int gnma_port_ieee8021x_unauthorized_vlan_set(struct gnma_port_key *port_key,
					      uint16_t vid);
int gnma_port_oper_status_get(struct gnma_port_key *port_key, bool *is_up);
int gnma_port_speed_get(struct gnma_port_key *port_key, char *speed,
			size_t str_len);
int gnma_port_duplex_get(struct gnma_port_key *port_key,
			 bool *is_full_duplex);
int gnma_port_ieee8021x_pae_mode_get(struct gnma_port_key *port_key,
				     bool *is_authenticator);
int gnma_port_ieee8021x_port_ctrl_get(struct gnma_port_key *port_key,
				      gnma_8021x_port_ctrl_mode_t *mode);
int gnma_port_ieee8021x_port_host_mode_get(struct gnma_port_key *port_key,
					   gnma_8021x_port_host_mode_t *mode);
int gnma_port_ieee8021x_guest_vlan_get(struct gnma_port_key *port_key,
				       uint16_t *vid);
int gnma_port_ieee8021x_unauthorized_vlan_get(struct gnma_port_key *port_key,
					      uint16_t *vid);
int gnma_port_stats_get(struct gnma_port_key *port_key,
			uint32_t num_of_counters,
			gnma_port_stat_type_t *counter_ids,
			uint64_t *counters);
int gnma_port_lldp_peer_info_get(struct gnma_port_key *port_key, char *buf,
				 size_t buf_size);

int gnma_poe_power_mgmt_set(gnma_poe_power_mgmt_mode_t mode);
int gnma_poe_power_mgmt_get(gnma_poe_power_mgmt_mode_t *mode);
int gnma_poe_usage_threshold_set(uint8_t power_threshold);
int gnma_poe_usage_threshold_get(uint8_t *power_threshold);
int gnma_poe_state_get(char *buf, size_t buf_size);
int gnma_poe_port_admin_mode_set(struct gnma_port_key *port_key, bool enabled);
int gnma_poe_port_admin_mode_get(struct gnma_port_key *port_key, bool *enabled);
int gnma_poe_port_detection_mode_set(struct gnma_port_key *port_key,
				     gnma_poe_port_detection_mode_t mode);
int gnma_poe_port_detection_mode_get(struct gnma_port_key *port_key,
				     gnma_poe_port_detection_mode_t *mode);
int gnma_poe_port_power_limit_set(struct gnma_port_key *port_key,
				  bool user_defined, uint32_t power_limit);
int gnma_poe_port_power_limit_get(struct gnma_port_key *port_key,
				  bool *user_defined, uint32_t *power_limit);
int gnma_poe_port_priority_set(struct gnma_port_key *port_key,
			       gnma_poe_port_priority_t priority);
int gnma_poe_port_priority_get(struct gnma_port_key *port_key,
			       gnma_poe_port_priority_t *priority);
int gnma_poe_port_reset(struct gnma_port_key *port_key);
int gnma_poe_port_list_get(uint16_t *list_size,
			   struct gnma_port_key *port_key_arr);
int gnma_poe_port_state_get(struct gnma_port_key *port_key, char *buf,
			    size_t buf_size);
int gnma_vlan_create(struct gnma_change *c, uint16_t vid);
int gnma_vlan_remove(uint16_t vid);
int gnma_vlan_member_create(struct gnma_change *, uint16_t vid,
			    struct gnma_port_key *port_key, bool tagged);
int gnma_vlan_member_remove(struct gnma_change *, uint16_t vid,
			    struct gnma_port_key *port_key);
int gnma_vlan_member_bmap_get(struct gnma_vlan_member_bmap *);
int gnma_vlan_list_get(BITMAP_DECLARE(, GNMA_MAX_VLANS));
int gnma_reboot(void);
int gnma_config_save(void);
int gnma_config_restore(void);
int gnma_port_list_get(uint16_t *list_size, struct gnma_port_key *port_key_list);
int gnma_factory_default(void);
int gnma_image_install(char *uri);
int gnma_image_install_status(uint16_t *buf_size, char *buf);
int gnma_image_running_name_get(char *str, size_t str_max_len);
int gnma_metadata_get(struct gnma_metadata *md);
int gnma_rebootcause_get(char *buf, size_t buf_size);

int gnma_subscribe(void **handle, const struct gnma_subscribe_callbacks *);
void gnma_unsubscribe(void **handle);

int gnma_syslog_cfg_clear(void);
int gnma_syslog_cfg_set(struct gnma_syslog_cfg *cfg, int count);


int gnma_vlan_erif_attr_pref_list_get(uint16_t vid,
				      uint16_t *list_size,
				      struct gnma_ip_prefix *prefix_list);
int gnma_vlan_erif_attr_pref_update(uint16_t vid, uint16_t list_size,
				   struct gnma_ip_prefix *pref);
int gnma_vlan_erif_attr_pref_delete(uint16_t vid, struct gnma_ip_prefix *pref);

int gnma_portl2_erif_attr_pref_list_get(struct gnma_port_key *port_key,
					uint16_t *list_size,
					struct gnma_ip_prefix *prefix_list);
int gnma_portl2_erif_attr_pref_update(struct gnma_port_key *port_key,
				      uint16_t list_size,
				      struct gnma_ip_prefix *pref);
int gnma_portl2_erif_attr_pref_delete(struct gnma_port_key *port_key,
				      struct gnma_ip_prefix *pref);

int gnma_vlan_dhcp_relay_server_add(uint16_t vid, struct gnma_ip *ip);
int gnma_vlan_dhcp_relay_server_remove(uint16_t vid, struct gnma_ip *ip);
int gnma_vlan_dhcp_relay_server_list_get(uint16_t vid, size_t *list_size,
					 struct gnma_ip *ip_list);
int gnma_vlan_dhcp_relay_ciruit_id_set(uint16_t vid,
				       gnma_dhcp_relay_circuit_id_t id);
int gnma_vlan_dhcp_relay_ciruit_id_get(uint16_t vid,
				       gnma_dhcp_relay_circuit_id_t *id);
int gnma_vlan_dhcp_relay_policy_action_set(uint16_t vid,
					   gnma_dhcp_relay_policy_action_type_t act);
int gnma_vlan_dhcp_relay_policy_action_get(uint16_t vid,
					   gnma_dhcp_relay_policy_action_type_t *act);
int gnma_vlan_dhcp_relay_max_hop_cnt_set(uint16_t vid, uint8_t max_hop_cnt);
int gnma_vlan_dhcp_relay_max_hop_cnt_get(uint16_t vid, uint8_t *max_hop_cnt);
int gnma_route_create(uint16_t vr_id /* 0 - default */,
		      struct gnma_ip_prefix *prefix,
		      struct gnma_route_attrs *attr);
int gnma_route_remove(uint16_t vr_id /* 0 - default */,
		      struct gnma_ip_prefix *prefix /* key */);
int gnma_route_list_get(uint16_t vr_id, uint32_t *list_size,
			struct gnma_ip_prefix *prefix_list,
			struct gnma_route_attrs *attr_list);

int gnma_stp_mode_set(gnma_stp_mode_t mode, struct gnma_stp_attr *attr);
int gnma_stp_mode_get(gnma_stp_mode_t *mode, struct gnma_stp_attr *attr);

int gnma_stp_port_set(uint32_t list_size, struct gnma_stp_port_cfg *ports_list);
int gnma_stp_ports_enable(uint32_t list_size, struct gnma_port_key *ports_list);

int gnma_stp_instance_set(uint16_t instance, uint16_t prio,
			  uint32_t list_size, uint16_t *vid_list);

int gnma_stp_vids_enable(uint32_t list_size, uint16_t *vid_list);
int gnma_stp_vids_enable_all(void);
int gnma_stp_vid_set(uint16_t vid, struct gnma_stp_attr *attr);
int gnma_stp_vid_bulk_get(struct gnma_stp_attr *list, ssize_t size);

int gnma_ieee8021x_system_auth_control_set(bool is_enabled);
int gnma_ieee8021x_system_auth_control_get(bool *is_enabled);
int gnma_ieee8021x_system_auth_clients_get(char *buf, size_t buf_size);
int gnma_ieee8021x_das_bounce_port_ignore_set(bool bounce_port_ignore);
int gnma_ieee8021x_das_bounce_port_ignore_get(bool *bounce_port_ignore);
int gnma_ieee8021x_das_disable_port_ignore_set(bool disable_port_ignore);
int gnma_ieee8021x_das_disable_port_ignore_get(bool *disable_port_ignore);
int gnma_ieee8021x_das_ignore_server_key_set(bool ignore_server_key);
int gnma_ieee8021x_das_ignore_server_key_get(bool *ignore_server_key);
int gnma_ieee8021x_das_ignore_session_key_set(bool ignore_session_key);
int gnma_ieee8021x_das_ignore_session_key_get(bool *ignore_session_key);
int gnma_ieee8021x_das_auth_type_key_set(gnma_das_auth_type_t auth_type);
int gnma_ieee8021x_das_auth_type_key_get(gnma_das_auth_type_t *auth_type);
int gnma_ieee8021x_das_dac_hosts_list_get(size_t *list_size,
					  struct gnma_das_dac_host_key *das_dac_keys_arr);
int gnma_ieee8021x_das_dac_host_add(struct gnma_das_dac_host_key *key,
				    const char *passkey);
int gnma_ieee8021x_das_dac_host_remove(struct gnma_das_dac_host_key *key);
int
gnma_iee8021x_das_dac_global_stats_get(uint32_t num_of_counters,
				       gnma_ieee8021x_das_dac_stat_type_t *counter_ids,
				       uint64_t *counters);

int gnma_radius_hosts_list_get(size_t *list_size,
			       struct gnma_radius_host_key *hosts_list);
int gnma_radius_host_add(struct gnma_radius_host_key *key, const char *passkey,
			 uint16_t auth_port, uint8_t prio);
int gnma_radius_host_remove(struct gnma_radius_host_key *key);
int gnma_mac_address_list_get(size_t *list_size, struct gnma_fdb_entry *list);
int gnma_system_password_set(char *password);
int gnma_igmp_snooping_set(uint16_t vid, struct gnma_igmp_snoop_attr *attr);
int gnma_igmp_static_groups_set(uint16_t vid, size_t num_groups,
				struct gnma_igmp_static_group_attr *groups);

int gnma_igmp_iface_groups_get(struct gnma_port_key *iface,
			       char *buf, size_t *buf_size);

struct gnma_change *gnma_change_create(void);
void gnma_change_destory(struct gnma_change *);
int gnma_change_exec(struct gnma_change *);

int gnma_techsupport_start(char *res_path);
