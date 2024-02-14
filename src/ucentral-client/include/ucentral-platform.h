#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <stdbool.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "bitmap.h"
#include "router-utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UC_CONFIG_DEFAULT_ID (0)

#define FIRST_VLAN (1)
#define MAX_VLANS (4096)
/* TBD: get num of ports from platform, e.g gnmi / noi?? */
#define MAX_NUM_OF_PORTS (100)

#define PORT_MAX_NAME_LEN (32)
#define RTTY_CFG_FIELD_STR_MAX_LEN (64)
#define PLATFORM_INFO_STR_MAX_LEN (96)
#define SYSLOG_CFG_FIELD_STR_MAX_LEN (64)
#define RADIUS_CFG_HOSTNAME_STR_MAX_LEN (64)
#define RADIUS_CFG_PASSKEY_STR_MAX_LEN (64)
#define RADIUS_CFG_DEFAULT_PORT (1812)
#define RADIUS_CFG_DEFAULT_PRIO (1)
#define HEALTHCHEK_MESSAGE_MAX_COUNT (10)
#define HEALTHCHEK_MESSAGE_MAX_LEN (100)
#define PLATFORM_MAC_STR_SIZE (18)
#define METRICS_WIRED_CLIENTS_MAX_NUM (2000)

/*
 * TODO(vb) likely we need to parse interfaces in proto to understand
 *          select regex. but proto should undestand format, actual values like
 *          "Ethernet" should be opaque.
 */
#define PID_TO_NAME(p, name) sprintf(name, "Ethernet%hu", p)
#define NAME_TO_PID(p, name) sscanf((name), "Ethernet%hu", (p))
#define VLAN_TO_NAME(v, name) sprintf((name), "Vlan%hu", (v))

struct plat_vlan_memberlist;
struct plat_port_vlan;
struct plat_port;
struct plat_rtty_cfg;
struct plat_ports_list;
struct plat_port_counters;
struct plat_port_lldp_peer_info;
struct plat_alarm;

enum plat_ieee8021x_port_control_mode {
	PLAT_802_1X_PORT_CONTROL_FORCE_AUTHORIZED,
	PLAT_802_1X_PORT_CONTROL_FORCE_UNAUTHORIZED,
	PLAT_802_1X_PORT_CONTROL_AUTO
};

enum plat_ieee8021x_port_host_mode {
	PLAT_802_1X_PORT_HOST_MODE_MULTI_AUTH,
	PLAT_802_1X_PORT_HOST_MODE_MULTI_DOMAIN,
	PLAT_802_1X_PORT_HOST_MODE_MULTI_HOST,
	PLAT_802_1X_PORT_HOST_MODE_SINGLE_HOST,
};

enum plat_ieee8021x_das_auth_type {
	PLAT_802_1X_DAS_AUTH_TYPE_ANY,
	PLAT_802_1X_DAS_AUTH_TYPE_ALL,
	PLAT_802_1X_DAS_AUTH_TYPE_SESSION_KEY,
};

enum plat_igmp_version {
	PLAT_IGMP_VERSION_1,
	PLAT_IGMP_VERSION_2,
	PLAT_IGMP_VERSION_3
};

#define UCENTRAL_PORT_LLDP_PEER_INFO_MAX_MGMT_IPS (2)
/* Interface LLDP peer's data, as defined in interface.lldp.yml*/
struct plat_port_lldp_peer_info {
	/* The device capabilities that our neighbour is announcing. */
	struct {
		bool is_bridge;
		bool is_router;
		bool is_wlan_ap;
		bool is_station;
	} capabilities;
	/* The chassis name that our neighbour is announcing */
	char name[64];
	/* The chassis MAC that our neighbour is announcing */
	char mac[PLATFORM_MAC_STR_SIZE];
	/* The chassis description that our neighbour is announcing */
	char description[512];
	/* The management IPs that our neighbour is announcing */
	char mgmt_ips[UCENTRAL_PORT_LLDP_PEER_INFO_MAX_MGMT_IPS][INET6_ADDRSTRLEN];
	/* The physical network port that we see this neighbour on */
	char port[PORT_MAX_NAME_LEN];
};

/* PSE's POE state data, as defined in unit.poe */
struct plat_poe_state {
	uint64_t max_power_budget;
	uint64_t power_threshold;
	uint64_t power_consumed;
	char power_status[32];
};

/* Interface POE port's state data, as defined in link-state.upstream.poe */
struct plat_poe_port_state {
	char status[32];
	char fault_status[32];
	char output_voltage[32];
	char temperature[32];
	uint32_t output_power;
	uint32_t output_current;
	uint8_t class_requested;
	uint8_t class_assigned;
	struct {
		uint64_t overload;
		uint64_t shorted;
		uint64_t power_denied;
		uint64_t absent;
		uint64_t invalid_signature;
	} counters;
};

struct plat_ieee8021x_authenticated_client_info {
	char auth_method[32];
	char mac_addr[PLATFORM_MAC_STR_SIZE];
	size_t session_time;
	char username[64];
	char vlan_type[32];
	uint16_t vid;
};

/* Interface IEEE802.1X port's state data, as defined in link-state.upstream.ieee8021x */
struct plat_ieee8021x_port_info {
	struct plat_ieee8021x_authenticated_client_info *client_arr;
	size_t arr_len;
};

struct plat_port_counters {
	uint64_t collisions;
	uint64_t multicast;
	uint64_t rx_bytes;
	uint64_t rx_dropped;
	uint64_t rx_error;
	uint64_t rx_packets;
	uint64_t tx_bytes;
	uint64_t tx_dropped;
	uint64_t tx_error;
	uint64_t tx_packets;
};

struct plat_ports_list {
	struct plat_ports_list *next;
	char name[PORT_MAX_NAME_LEN];
};

struct plat_port {
	char name[PORT_MAX_NAME_LEN];
	uint32_t speed;
	uint16_t fp_id;
	uint8_t duplex;
	uint8_t state;
	/* If set, none of the above should get configured, but rather simple
	 * <reset> invoked:
	 *   - removed from every vlan;
	 *   - set to disabled state;
	 *   - MAC reset;
	 */
	uint8_t reset;
	struct {
		bool is_admin_mode_up;
		bool do_reset;
		char detection_mode[32];
		bool is_detection_mode_set;
		uint32_t power_limit;
		bool is_power_limit_set;
		char priority[32];
		bool is_priority_set;
	} poe;
	struct {
		uint16_t auth_fail_vid;
		uint16_t guest_vid;
		enum plat_ieee8021x_port_control_mode control_mode;
		enum plat_ieee8021x_port_host_mode host_mode;
		bool is_authenticator;
	} ieee8021x;
};

#define UCENTRAL_LIST_PUSH_MEMBER(head, member)		\
	({						\
		if (!*(head)) {				\
			*(head) = (member);		\
			(member)->next = NULL;		\
		} else {				\
			(member)->next = *(head);	\
			*(head) = (member);		\
		}					\
			(member);			\
	})

#define UCENTRAL_LIST_FOR_EACH_MEMBER(pos, head)	\
	for ((pos) = *(head); (pos); (pos) = (pos)->next)

#define UCENTRAL_VLAN_MEMBER_NAME_EXIST(cname, head) \
	({bool res = false; \
	struct plat_vlan_memberlist *_pos; \
	UCENTRAL_LIST_FOR_EACH_MEMBER(_pos, (head)) { \
		if (!strcmp((cname), (_pos)->port.name)) { \
			res = true; \
			break; \
		} \
	} \
	(res);})

#define UCENTRAL_VLAN_EXIST(vlan_id, head) \
	({bool res = false; \
	struct plat_vlans_list *_pos; \
	UCENTRAL_LIST_FOR_EACH_MEMBER((_pos), (head)) { \
		if ((vlan_id) == (_pos)->vid) { \
			res = true; \
			break; \
		} \
	} \
	(res);})

#define UCENTRAL_LIST_DESTROY_SAFE(head, member_node)			\
	do {								\
		typeof(member_node) tmp_node = NULL;			\
		UCENTRAL_LIST_FOR_EACH_MEMBER((member_node), (head)) {	\
			/* 'safely' delete every 'previous' node */	\
			if (tmp_node)					\
				free(tmp_node);				\
									\
			tmp_node = (member_node);			\
		}							\
		/* Since we are deleting only <previous> entries, and	\
		 * thus never proceeded to <next> node			\
		 * (bc. list's ended), delete <previous> element	\
		 * by hand.						\
		 */							\
		if (tmp_node)						\
			free(tmp_node);					\
	} while (0)

struct plat_ipv4 {
	struct in_addr subnet;
	int subnet_len;
	bool exist;
};

struct plat_dhcp {
	struct {
		struct in_addr server_address;
		char circ_id[16];
		bool enabled;
	} relay;
};

struct plat_port_l2 {
	struct plat_ipv4 ipv4;
};

struct plat_igmp {
	bool exist;
	bool snooping_enabled;
	bool querier_enabled;
	bool fast_leave_enabled;
	uint32_t query_interval;
	uint32_t last_member_query_interval;
	uint32_t max_response_time;
	enum plat_igmp_version version;
	size_t num_groups;
	struct {
		struct in_addr addr;
		struct plat_ports_list *egress_ports_list;
	} *groups;
};

struct plat_port_vlan {
	struct plat_vlan_memberlist *members_list_head;
	struct plat_ipv4 ipv4;
	struct plat_dhcp dhcp;
	struct plat_igmp igmp;
	uint16_t id;
	uint16_t mstp_instance;
};

struct plat_vlans_list {
	struct plat_vlans_list *next;
	uint16_t vid;
};

struct plat_vlan_memberlist {
	struct {
		char name[PORT_MAX_NAME_LEN];
		uint16_t fp_id;
	} port;
	bool tagged;
	struct plat_vlan_memberlist *next;
};

struct plat_syslog_cfg {
	int32_t port;
	int32_t size;
	int32_t priority;
	int is_tcp;
	char host[SYSLOG_CFG_FIELD_STR_MAX_LEN];
};

struct plat_enabled_service_cfg {
	struct {
		bool enabled;
	} ssh;
	struct telnet {
		bool enabled;
	} telnet;
	struct {
		bool enabled;
	} http;
};

struct plat_rtty_cfg {
	char id[RTTY_CFG_FIELD_STR_MAX_LEN];
	char passwd[RTTY_CFG_FIELD_STR_MAX_LEN];
	char serial[RTTY_CFG_FIELD_STR_MAX_LEN];
	char server[RTTY_CFG_FIELD_STR_MAX_LEN];
	char token[RTTY_CFG_FIELD_STR_MAX_LEN];
	char user[RTTY_CFG_FIELD_STR_MAX_LEN];
	uint16_t port;
	uint16_t timeout;
};

struct plat_platform_info {
	char platform[PLATFORM_INFO_STR_MAX_LEN];
	char hwsku[PLATFORM_INFO_STR_MAX_LEN];
	char mac[PLATFORM_INFO_STR_MAX_LEN];
};

struct plat_alarm {
	const char *id;
	const char *resource;
	const char *text;
	uint64_t time_created;
	const char *type_id;
	int severity;
	int acknowledged;
	uint64_t acknowledge_time;
};

struct plat_metrics_cfg {
	struct {
		int enabled;
		size_t interval;
	} telemetry;
	struct {
		int enabled;
		size_t interval;
	} healthcheck;
	struct {
		int enabled;
		int lldp_enabled;
		int clients_enabled;
		size_t interval;
		unsigned max_mac_count;
		/* IE GET max length. Should be enoug. */
		char public_ip_lookup[2048];
	} state;
};

struct plat_unit_poe_cfg {
	char power_mgmt[32];
	bool is_power_mgmt_set;
	uint8_t usage_threshold;
	bool is_usage_threshold_set;
};

struct plat_unit_system_cfg {
	char password[64];
	bool password_changed;
};

struct plat_unit {
	struct plat_unit_poe_cfg poe;
	struct plat_unit_system_cfg system;
};

enum plat_stp_mode {
	PLAT_STP_MODE_NONE,
	PLAT_STP_MODE_STP,
	PLAT_STP_MODE_RST,
	PLAT_STP_MODE_MST,
	PLAT_STP_MODE_PVST,
	PLAT_STP_MODE_RPVST
};

struct plat_stp_instance_cfg {
	bool enabled;
	uint16_t forward_delay;
	uint16_t hello_time;
	uint16_t max_age;
	uint16_t priority;
};

struct plat_radius_host {
	char hostname[RADIUS_CFG_HOSTNAME_STR_MAX_LEN];
	char passkey[RADIUS_CFG_PASSKEY_STR_MAX_LEN];
	uint16_t auth_port;
	uint8_t priority;
};

struct plat_radius_hosts_list {
	struct plat_radius_hosts_list *next;
	struct plat_radius_host host;
};

struct plat_ieee8021x_dac_host {
	char hostname[RADIUS_CFG_HOSTNAME_STR_MAX_LEN];
	char passkey[RADIUS_CFG_PASSKEY_STR_MAX_LEN];
};

struct plat_ieee8021x_dac_list {
	struct plat_ieee8021x_dac_list *next;
	struct plat_ieee8021x_dac_host host;
};

struct plat_port_isolation_session_ports {
	struct plat_ports_list *ports_list;
};

struct plat_port_isolation_session {
	uint64_t id;
	struct plat_port_isolation_session_ports uplink;
	struct plat_port_isolation_session_ports downlink;
};

struct plat_port_isolation_cfg {
	struct plat_port_isolation_session *sessions;
	size_t sessions_num;
};

struct plat_cfg {
	struct plat_unit unit;
	/* Alloc all ports, but access them only if bit is set. */
	struct plat_port ports[MAX_NUM_OF_PORTS];
	BITMAP_DECLARE(ports_to_cfg, MAX_NUM_OF_PORTS);
	struct plat_port_vlan vlans[MAX_VLANS];
	BITMAP_DECLARE(vlans_to_cfg, MAX_VLANS);
	struct plat_metrics_cfg metrics;
	struct plat_syslog_cfg *log_cfg;
	struct plat_enabled_service_cfg enabled_services_cfg;
	/* Port's interfaces (provide l2 iface w/o bridge caps) */
	struct plat_port_l2 portsl2[MAX_NUM_OF_PORTS];
	struct ucentral_router router;
	int log_cfg_cnt;
	uint8_t stp_mode /* enum plat_stp_mode */;
	/* Instance zero is for global instance (like common values in rstp) */
	struct plat_stp_instance_cfg stp_instances[MAX_VLANS];
	struct plat_radius_hosts_list *radius_hosts_list;
	struct {
		bool is_auth_ctrl_enabled;
		bool bounce_port_ignore;
		bool disable_port_ignore;
		bool ignore_server_key;
		bool ignore_session_key;
		char server_key[RADIUS_CFG_PASSKEY_STR_MAX_LEN];
		enum plat_ieee8021x_das_auth_type das_auth_type;
		struct plat_ieee8021x_dac_list *das_dac_list;
	} ieee8021x;
	struct plat_port_isolation_cfg port_isolation_cfg;
};

struct plat_learned_mac_addr {
	char port[PORT_MAX_NAME_LEN];
	int vid;
	char mac[PLATFORM_MAC_STR_SIZE];
};

typedef void (*plat_alarm_cb)(struct plat_alarm *);

struct plat_linkstatus {
	int64_t timestamp; /* seconds */
	const char *ifname;
	int up;
};

typedef void (*plat_linkstatus_cb)(struct plat_linkstatus *);

enum plat_poe_linkstatus_value {
	PLAT_POE_LINKSTATUS_DISABLED,
	PLAT_POE_LINKSTATUS_SEARCHING,
	PLAT_POE_LINKSTATUS_DELIVERING_POWER,
	PLAT_POE_LINKSTATUS_OVERLOAD,
	PLAT_POE_LINKSTATUS_FAULT,
};

struct plat_poe_linkstatus {
	int64_t timestamp; /* seconds */
	const char *ifname;
	enum plat_poe_linkstatus_value status;
};

typedef void (*plat_poe_linkstatus_cb)(struct plat_poe_linkstatus *);

enum plat_poe_link_faultcode_value {
	PLAT_POE_LINK_FAULTCODE_NO_ERROR,
	PLAT_POE_LINK_FAULTCODE_OVLO,
	PLAT_POE_LINK_FAULTCODE_MPS_ABSENT,
	PLAT_POE_LINK_FAULTCODE_SHORT,
	PLAT_POE_LINK_FAULTCODE_OVERLOAD,
	PLAT_POE_LINK_FAULTCODE_POWER_DENIED,
	PLAT_POE_LINK_FAULTCODE_THERMAL_SHUTDOWN,
	PLAT_POE_LINK_FAULTCODE_STARTUP_FAILURE,
	PLAT_POE_LINK_FAULTCODE_UVLO,
	PLAT_POE_LINK_FAULTCODE_HW_PIN_DISABLE,
	PLAT_POE_LINK_FAULTCODE_PORT_UNDEFINED,
	PLAT_POE_LINK_FAULTCODE_INTERNAL_HW_FAULT,
	PLAT_POE_LINK_FAULTCODE_USER_SETTING,
	PLAT_POE_LINK_FAULTCODE_NON_STANDARD_PD,
	PLAT_POE_LINK_FAULTCODE_UNDERLOAD,
	PLAT_POE_LINK_FAULTCODE_PWR_BUDGET_EXCEEDED,
	PLAT_POE_LINK_FAULTCODE_OOR_CAPACITOR_VALUE,
	PLAT_POE_LINK_FAULTCODE_CLASS_ERROR,
};

struct plat_poe_link_faultcode {
	int64_t timestamp; /* seconds */
	const char *ifname;
	enum plat_poe_link_faultcode_value faultcode;
};

typedef void (*plat_poe_link_faultcode_cb)(struct plat_poe_link_faultcode *);

struct plat_run_script_result;
typedef void (*plat_run_script_cb)(int err, struct plat_run_script_result *,
				   void *ctx);

enum {
	UCENTRAL_PORT_SPEED_10_E,
	UCENTRAL_PORT_SPEED_100_E,
	UCENTRAL_PORT_SPEED_1000_E,
	UCENTRAL_PORT_SPEED_2500_E,
	UCENTRAL_PORT_SPEED_5000_E,
	UCENTRAL_PORT_SPEED_10000_E,
	UCENTRAL_PORT_SPEED_25000_E,
	UCENTRAL_PORT_SPEED_40000_E,
	UCENTRAL_PORT_SPEED_100000_E,
};

enum {
	UCENTRAL_PORT_DUPLEX_HALF_E,
	UCENTRAL_PORT_DUPLEX_FULL_E,
};

enum {
	UCENTRAL_PORT_DISABLED_E,
	UCENTRAL_PORT_ENABLED_E,
};

enum {
	UCENTRAL_VLAN_1Q_TAG_UNTAGGED_E,
	UCENTRAL_VLAN_1Q_TAG_TAGGED_E,
};

enum upgrade_status {
	UCENTRAL_UPGRADE_STATE_IDLE,
	UCENTRAL_UPGRADE_STATE_DOWNLOAD,
	UCENTRAL_UPGRADE_STATE_INSTALL,
	UCENTRAL_UPGRADE_STATE_FAIL,
	UCENTRAL_UPGRADE_STATE_SUCCESS
};

enum {
	PLAT_REBOOT_CAUSE_REBOOT_CMD,
	PLAT_REBOOT_CAUSE_POWERLOSS,
	PLAT_REBOOT_CAUSE_CRASH,
	PLAT_REBOOT_CAUSE_UNAVAILABLE,
};

enum sfp_form_factor {
	UCENTRAL_SFP_FORM_FACTOR_NA = 0,

	UCENTRAL_SFP_FORM_FACTOR_SFP,
	UCENTRAL_SFP_FORM_FACTOR_SFP_PLUS,
	UCENTRAL_SFP_FORM_FACTOR_SFP_28,
	UCENTRAL_SFP_FORM_FACTOR_SFP_DD,
	UCENTRAL_SFP_FORM_FACTOR_QSFP,
	UCENTRAL_SFP_FORM_FACTOR_QSFP_PLUS,
	UCENTRAL_SFP_FORM_FACTOR_QSFP_28,
	UCENTRAL_SFP_FORM_FACTOR_QSFP_DD
};

enum sfp_link_mode {
	UCENTRAL_SFP_LINK_MODE_NA = 0,

	UCENTRAL_SFP_LINK_MODE_1000_X,
	UCENTRAL_SFP_LINK_MODE_2500_X,
	UCENTRAL_SFP_LINK_MODE_4000_SR,
	UCENTRAL_SFP_LINK_MODE_10G_SR,
	UCENTRAL_SFP_LINK_MODE_25G_SR,
	UCENTRAL_SFP_LINK_MODE_40G_SR,
	UCENTRAL_SFP_LINK_MODE_50G_SR,
	UCENTRAL_SFP_LINK_MODE_100G_SR,
};

struct plat_port_transceiver_info {
	char vendor_name[64];
	char part_number[64];
	char serial_number[64];
	char revision[64];
	enum sfp_form_factor form_factor;
	enum sfp_link_mode *supported_link_modes;
	size_t num_supported_link_modes;
	float temperature;
	float tx_optical_power;
	float rx_optical_power;
	float max_module_power;
};

struct plat_port_info {
	struct plat_port_counters stats;
	struct plat_port_lldp_peer_info lldp_peer_info;
	struct plat_ieee8021x_port_info ieee8021x_info;
	struct plat_port_transceiver_info transceiver_info;
	uint32_t uptime;
	uint32_t speed;
	uint8_t carrier_up;
	uint8_t duplex;
	uint8_t has_lldp_peer_info;
	uint8_t has_transceiver_info;
	char name[PORT_MAX_NAME_LEN];
};

struct plat_system_info {
	uint64_t localtime; /* epoch */
	uint64_t uptime; /* epoch */
	uint64_t ram_buffered; /* bytes */
	uint64_t ram_cached;
	uint64_t ram_free;
	uint64_t ram_total;
	double load_average[3]; /* 1, 5, 15 minutes load average */
};

struct plat_iee8021x_coa_counters {
	uint64_t coa_req_received;
	uint64_t coa_ack_sent;
	uint64_t coa_nak_sent;
	uint64_t coa_ignored;
	uint64_t coa_wrong_attr;
	uint64_t coa_wrong_attr_value;
	uint64_t coa_wrong_session_context;
	uint64_t coa_administratively_prohibited_req;
};

struct plat_state_info {
	struct plat_poe_state poe_state;
	struct plat_poe_port_state poe_ports_state[MAX_NUM_OF_PORTS];
	BITMAP_DECLARE(poe_ports_bmap, MAX_NUM_OF_PORTS);

	struct plat_port_info *port_info;
	int port_info_count;
	struct plat_port_vlan *vlan_info;
	size_t vlan_info_count;
	struct plat_learned_mac_addr *learned_mac_list;
	size_t learned_mac_list_size;

	struct plat_system_info system_info;
	struct plat_iee8021x_coa_counters ieee8021x_global_coa_counters;
};

struct plat_upgrade_info {
	int operation;
	int percentage;
};

struct plat_health_info {
	int sanity; /* 0 - device is dead, 100 - everything is great */
	char msg[HEALTHCHEK_MESSAGE_MAX_COUNT][HEALTHCHEK_MESSAGE_MAX_LEN];
};

struct plat_reboot_cause {
	int cause;
	uint64_t ts;
	char desc[128];
};

struct plat_event_callbacks {
	plat_alarm_cb alarm_cb;
	plat_linkstatus_cb linkstatus_cb;
	plat_poe_linkstatus_cb poe_linkstatus_cb;
	plat_poe_link_faultcode_cb poe_link_faultcode_cb;
};

struct plat_run_script_result {
	const char *stdout_string;
	size_t stdout_string_len;
	int exit_status;
	int timeout_exceeded;
};

struct plat_run_script {
	const char *type;
	const char *script_base64;
	plat_run_script_cb cb;
	void *ctx;
	int64_t timeout;
};

int plat_init(void);
int plat_info_get(struct plat_platform_info *info);

/* Platform independent mid-layer OS related functions definitions */
int plat_reboot(void);
int plat_config_apply(struct plat_cfg *cfg, uint32_t id);
int plat_config_save(uint64_t id);
int plat_config_restore(void);
int plat_metrics_save(const struct plat_metrics_cfg *cfg);
int plat_metrics_restore(struct plat_metrics_cfg *cfg);
int plat_saved_config_id_get(uint64_t *id);
void plat_config_destroy(struct plat_cfg *cfg);
int plat_factory_default(void);
int plat_rtty(struct plat_rtty_cfg *rtty_cfg);
int plat_upgrade(char *uri, char *signature);

/* TODO(vb) is going to be removed with moving to async */
/* Logging functions. Obtain messages from lower layers. */
/* free() must be called for returned string */
char *plat_log_pop(void);
void plat_log_flush(void);
/* free() must be called for returned string */
char *plat_log_pop_concatenate(void);

int plat_event_subscribe(const struct plat_event_callbacks *cbs);
void plat_event_unsubscribe(void);

void plat_health_poll(void (*cb)(struct plat_health_info *), int period_sec);
void plat_health_poll_stop(void);
void plat_telemetry_poll(void (*cb)(struct plat_state_info *state), int period_sec);
void plat_telemetry_poll_stop(void);
void plat_state_poll(void (*cb)(struct plat_state_info *state), int period_sec);
void plat_state_poll_stop(void);
void plat_upgrade_poll(int (*cb)(struct plat_upgrade_info *), int period_sec);
void plat_upgrade_poll_stop(void);

int plat_run_script(struct plat_run_script *);

/* TODO(vb) refactoring: this API will be removed */
/* Platform independent mid-layer PORT related functions definitions */
int plat_port_list_get(uint16_t list_size, struct plat_ports_list *ports);
int plat_port_num_get(uint16_t *num_of_active_ports);
int plat_running_img_name_get(char *str, size_t str_max_len);
int plat_revision_get(char *str, size_t str_max_len);
int
plat_reboot_cause_get(struct plat_reboot_cause *cause);

int plat_diagnostic(char *res_path);

#ifdef __cplusplus
}
#endif
