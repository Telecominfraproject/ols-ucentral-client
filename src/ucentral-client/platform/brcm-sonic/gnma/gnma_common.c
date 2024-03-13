#define _GNU_SOURCE /* asprintf */

#include <inttypes.h>

#include <gnma_common.h>
#include <netlink_common.h>
#include <gnmi/gnmi_c_connector.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <cjson/cJSON.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <errno.h>

#define DEFAULT_TIMEOUT_US 90 * 1000000

#define ARRAY_LENGTH(array) (sizeof((array))/sizeof((array)[0]))
#define ZFREE(p)           \
	do {               \
		free((p)); \
		(p) = 0;   \
	} while (0)

struct subscribe_gnmi_ctx {
	struct gnmi_subscribe *subscribe;
	struct gnma_subscribe_callbacks cbs;
};

extern void (*main_log_cb)(const char *);

static void *main_switch;

static const char *strnonull(const char *s)
{
	return s ? s : "";
}

cJSON *__gnma_parse_cfg_file(char *path)
{
	struct stat fd_stat;
	cJSON *json = NULL;
	void *mem;
	int ret;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		goto err_open;

	ret = fstat(fd, &fd_stat);
	if (ret)
		goto err_stat;

	mem = mmap(NULL, fd_stat.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED)
		goto err_map;

	json = cJSON_ParseWithLength(mem, fd_stat.st_size);

	munmap(mem, fd_stat.st_size);
err_map:
err_stat:
	close(fd);
err_open:
	return json;
}

int gnma_switch_create(/* TODO id */ /* TODO: attr (adr, login, psw) */)
{
	char login_buf[64], passwd_buf[64], srv_buf[64];
	char *var, *srv, *login, *passwd;
	cJSON *gnma_cfg = 0;

	gnma_cfg = __gnma_parse_cfg_file("/etc/gnma/gnma.conf");
	login = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(gnma_cfg, "auth_login"));
	passwd = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(gnma_cfg, "auth_passwd"));

	srv = "127.0.0.1:8080";
	if ((var = getenv("UC_GNMI_SERVER"))) {
		snprintf(srv_buf, sizeof srv_buf, "%s", var);
		srv = srv_buf;
	}
	if ((var = getenv("UC_GNMI_LOGIN"))) {
		snprintf(login_buf, sizeof login_buf, "%s", var);
		login = login_buf;
	}
	if ((var = getenv("UC_GNMI_PASSWD"))) {
		snprintf(passwd_buf, sizeof passwd_buf, "%s", var);
		passwd = passwd_buf;
	}

	if (!login || !passwd)
		return GNMA_ERR_COMMON;

	main_switch = gnmi_session_create(srv, login, passwd);
	if (!main_switch)
		return GNMA_ERR_COMMON; /* ERRNO */

	return 0;
}

static int gnmi_json_object_set(void *s, const char *path, cJSON *val,
				int64_t timeout_us)
{
	char *rendered;
	int ret;

	rendered = cJSON_PrintUnformatted(val);
	if (!rendered)
		return -1;

	ret = gnmi_jsoni_set(s, path, rendered, timeout_us);
	free(rendered);

	return ret;
}

static int gnmi_setrq_add_object_update(struct gnmi_setrq *rq, char *path,
					cJSON *val)
{
	char *rendered;
	int ret;

	rendered = cJSON_PrintUnformatted(val);
	if (!rendered)
		return -1;

	ret = gnmi_setrq_add_jsoni_update(rq, path, rendered);
	free(rendered);

	return ret;
}

int gnma_port_admin_state_set(struct gnma_port_key *port_key, bool up)
{
	int ret;
	cJSON *root;
	cJSON *val;
	char *path;


	ret = asprintf(&path,
		       "/openconfig-interfaces:interfaces/interface[name=%s]/config",
		       port_key->name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	root = cJSON_CreateObject();
	if (!root) {
		ret = GNMA_ERR_COMMON;
		goto err_root_alloc;
	}

	val = cJSON_AddObjectToObject(root, "openconfig-interfaces:config");
	if (!val) {
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	if (!cJSON_AddBoolToObject(val, "enabled", up)) {
		ret = GNMA_ERR_COMMON;
		goto err_val_set;
	}

	ret = gnmi_json_object_set(main_switch, path, root, DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_req_fail;
	}

	ret = 0;
err_req_fail:
err_val_set:
err_val_alloc:
	cJSON_Delete(root);
err_root_alloc:
	free(path);
err_path_alloc:
	return ret;
}

int gnma_port_speed_set(struct gnma_port_key *port_key, const char *speed)
{
	cJSON *root;
	cJSON *val;
	cJSON *arr;
	char *path;
	int ret;

	ret = asprintf(&path, "/sonic-port:sonic-port/PORT/PORT_LIST[ifname=%s]",
		       port_key->name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	root = cJSON_CreateObject();
	if (!root) {
		ret = GNMA_ERR_COMMON;
		goto err_root_alloc;
	}

	arr = cJSON_AddArrayToObject(root, "sonic-port:PORT_LIST");
	if (!arr) {
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	val = cJSON_CreateObject();
	if (!val) {
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	if (!cJSON_AddItemToArray(arr, val)) {
		cJSON_Delete(val);
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	if (!cJSON_AddStringToObject(val, "ifname", port_key->name)) {
		ret = GNMA_ERR_COMMON;
		goto err_val_set;
	}

	if (!cJSON_AddStringToObject(val, "speed", speed)) {
		ret = GNMA_ERR_COMMON;
		goto err_val_set;
	}

	ret = gnmi_json_object_set(main_switch, path, root, DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_req_fail;
	}

	ret = 0;
err_req_fail:
err_val_set:
err_val_alloc:
	cJSON_Delete(root);
err_root_alloc:
	free(path);
err_path_alloc:
	return ret;
}

int gnma_port_duplex_set(struct gnma_port_key *port_key, bool full_duplex)
{
	(void)port_key;
	(void)full_duplex;
	/* sonic:port doesn't have DUPLEX setting, nor setting it via sonic-cli
	 * does anything.
	 */
	return 0;
}

int gnma_port_ieee8021x_pae_mode_set(struct gnma_port_key *port_key,
				     bool is_authenticator)
{
	cJSON *root;
	cJSON *val;
	char *path;
	int ret;

	ret = asprintf(&path,
		       "/openconfig-authmgr:authmgr/authmgr-port-config/interface[name=%s]/config/port-pae-role",
		       port_key->name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	root = cJSON_CreateObject();
	if (!root) {
		ret = GNMA_ERR_COMMON;
		goto err_root_alloc;
	}

	val = cJSON_AddStringToObject(root, "openconfig-authmgr:port-pae-role",
				      is_authenticator
				      ? "AUTHENTICATOR"
				      : "NONE");
	if (!val) {
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	ret = gnmi_json_object_set(main_switch, path, root, DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_req_fail;
	}

	ret = 0;
err_req_fail:
err_val_alloc:
	cJSON_Delete(root);
err_root_alloc:
	free(path);
err_path_alloc:
	return ret;
}

int gnma_port_ieee8021x_port_ctrl_set(struct gnma_port_key *port_key,
				      gnma_8021x_port_ctrl_mode_t mode)
{
	const char *str_mode;
	cJSON *root;
	cJSON *val;
	char *path;
	int ret;

	switch (mode) {
		case GNMA_8021X_PORT_CTRL_MODE_FORCE_AUTHORIZED:
			str_mode = "FORCE_AUTHORIZED";
			break;
		case GNMA_8021X_PORT_CTRL_MODE_FORCE_UNAUTHORIZED:
			str_mode = "FORCE_UNAUTHORIZED";
			break;
		case GNMA_8021X_PORT_CTRL_MODE_AUTO:
			str_mode = "AUTO";
			break;
	}

	ret = asprintf(&path,
		       "/openconfig-authmgr:authmgr/authmgr-port-config/interface[name=%s]/config/port-control-mode",
		       port_key->name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	root = cJSON_CreateObject();
	if (!root) {
		ret = GNMA_ERR_COMMON;
		goto err_root_alloc;
	}

	val = cJSON_AddStringToObject(root, "openconfig-authmgr:port-control-mode",
				      str_mode);
	if (!val) {
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	ret = gnmi_json_object_set(main_switch, path, root, DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_req_fail;
	}

	ret = 0;
err_req_fail:
err_val_alloc:
	cJSON_Delete(root);
err_root_alloc:
	free(path);
err_path_alloc:
	return ret;
}

int gnma_port_ieee8021x_port_host_mode_set(struct gnma_port_key *port_key,
					   gnma_8021x_port_host_mode_t mode)
{
	const char *str_mode;
	cJSON *root;
	cJSON *val;
	char *path;
	int ret;

	switch (mode) {
		case GNMA_8021X_PORT_HOST_MODE_MULTI_AUTH:
			str_mode = "MULTI_AUTH";
			break;
		case GNMA_8021X_PORT_HOST_MODE_MULTI_DOMAIN:
			str_mode = "MULTI_DOMAIN";
			break;
		case GNMA_8021X_PORT_HOST_MODE_MULTI_HOST:
			str_mode = "MULTI_HOST";
			break;
		case GNMA_8021X_PORT_HOST_MODE_SINGLE_HOST:
			str_mode = "SINGLE_HOST";
			break;
		default: return -1;
	}

	ret = asprintf(&path,
		       "/openconfig-authmgr:authmgr/authmgr-port-config/interface[name=%s]/config/host-control-mode",
		       port_key->name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	root = cJSON_CreateObject();
	if (!root) {
		ret = GNMA_ERR_COMMON;
		goto err_root_alloc;
	}

	val = cJSON_AddStringToObject(root, "openconfig-authmgr:host-control-mode",
				      str_mode);
	if (!val) {
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	ret = gnmi_json_object_set(main_switch, path, root, DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_req_fail;
	}

	ret = 0;
err_req_fail:
err_val_alloc:
	cJSON_Delete(root);
err_root_alloc:
	free(path);
err_path_alloc:
	return ret;
}

int gnma_port_ieee8021x_guest_vlan_set(struct gnma_port_key *port_key,
				       uint16_t vid)
{
	cJSON *root;
	cJSON *val;
	char *path;
	int ret;

	ret = asprintf(&path,
		       "/openconfig-authmgr:authmgr/authmgr-port-config/interface[name=%s]/config/guest-vlan-id",
		       port_key->name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	root = cJSON_CreateObject();
	if (!root) {
		ret = GNMA_ERR_COMMON;
		goto err_root_alloc;
	}

	val = cJSON_AddNumberToObject(root, "openconfig-authmgr:guest-vlan-id",
				      vid);
	if (!val) {
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	ret = gnmi_json_object_set(main_switch, path, root, DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_req_fail;
	}

	ret = 0;
err_req_fail:
err_val_alloc:
	cJSON_Delete(root);
err_root_alloc:
	free(path);
err_path_alloc:
	return ret;
}

int gnma_port_ieee8021x_unauthorized_vlan_set(struct gnma_port_key *port_key,
					      uint16_t vid)
{
	cJSON *root;
	cJSON *val;
	char *path;
	int ret;

	ret = asprintf(&path,
		       "/openconfig-authmgr:authmgr/authmgr-port-config/interface[name=%s]/config/auth-fail-vlan-id",
		       port_key->name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	root = cJSON_CreateObject();
	if (!root) {
		ret = GNMA_ERR_COMMON;
		goto err_root_alloc;
	}

	val = cJSON_AddNumberToObject(root, "openconfig-authmgr:auth-fail-vlan-id",
				      vid);
	if (!val) {
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	ret = gnmi_json_object_set(main_switch, path, root, DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_req_fail;
	}

	ret = 0;
err_req_fail:
err_val_alloc:
	cJSON_Delete(root);
err_root_alloc:
	free(path);
err_path_alloc:
	return ret;
}

static const char *
gnma_port_stats_type_to_string(gnma_port_stat_type_t counter_id)
{
	static struct {
		gnma_port_stat_type_t enu_value;
		const char *str_value;
	} stats_enum_to_str[] = {
		{ .enu_value = GNMA_PORT_STAT_IN_OCTETS, .str_value = "in-octets"},
		{ .enu_value = GNMA_PORT_STAT_IN_DISCARDS, .str_value = "in-discards"},
		{ .enu_value = GNMA_PORT_STAT_IN_ERRORS, .str_value = "in-errors"},
		{ .enu_value = GNMA_PORT_STAT_IN_BCAST_PKTS, .str_value = "in-broadcast-pkts"},
		{ .enu_value = GNMA_PORT_STAT_IN_MCAST_PKTS, .str_value = "in-multicast-pkts"},
		{ .enu_value = GNMA_PORT_STAT_IN_UCAST_PKTS, .str_value = "in-unicast-pkts"},
		{ .enu_value = GNMA_PORT_STAT_OUT_OCTETS, .str_value = "out-octets"},
		{ .enu_value = GNMA_PORT_STAT_OUT_DISCARDS, .str_value = "out-discards"},
		{ .enu_value = GNMA_PORT_STAT_OUT_ERRORS, .str_value = "out-errors"},
		{ .enu_value = GNMA_PORT_STAT_OUT_BCAST_PKTS, .str_value = "out-broadcast-pkts"},
		{ .enu_value = GNMA_PORT_STAT_OUT_MCAST_PKTS, .str_value = "out-multicast-pkts"},
		{ .enu_value = GNMA_PORT_STAT_OUT_UCAST_PKTS, .str_value = "out-unicast-pkts"},
	};
	size_t i;

	for (i = 0; i < ARRAY_LENGTH(stats_enum_to_str); ++i)
		if (counter_id == stats_enum_to_str[i].enu_value)
			return stats_enum_to_str[i].str_value;

	return NULL;
}

int gnma_port_oper_status_get(struct gnma_port_key *port_key, bool *is_up)
{
	cJSON *parsed_res, *oper;
	char *buf = NULL;
	char *gpath;
	int ret;

	ret = asprintf(&gpath,
		       "/openconfig-interfaces:interfaces/interface[name=%s]/openconfig-if-ethernet:ethernet/state/openconfig-interfaces-ext:reason",
		       port_key->name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	oper = cJSON_GetObjectItemCaseSensitive(parsed_res, "openconfig-interfaces-ext:reason");
	if (!oper || !cJSON_GetStringValue(oper))
		goto err_gnmi_get_obj;

	*is_up = (strcmp(cJSON_GetStringValue(oper), "OPER_UP") == 0);

err_gnmi_get_obj:
	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_port_speed_get(struct gnma_port_key *port_key, char *speed,
			size_t str_len)
{
	cJSON *parsed_res, *port_speed;
	char *buf = NULL;
	char *gpath;
	int ret;

	ret = asprintf(&gpath, "/sonic-port:sonic-port/PORT/PORT_LIST[ifname=%s]/speed",
		       port_key->name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	port_speed = cJSON_GetObjectItemCaseSensitive(parsed_res, "sonic-port:speed");
	if (!port_speed || !cJSON_GetStringValue(port_speed))
		goto err_gnmi_get_obj;

	strncpy(speed, cJSON_GetStringValue(port_speed), str_len);

err_gnmi_get_obj:
	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_port_duplex_get(struct gnma_port_key *port_key,
			 bool *is_full_duplex)
{
	(void)port_key;

	/* sonic:port doesn't have DUPLEX setting, nor setting it via sonic-cli
	 * does anything - always <FULL duplex>
	 */
	*is_full_duplex = true;

	return 0;
}

int gnma_port_ieee8021x_pae_mode_get(struct gnma_port_key *port_key,
				     bool *is_authenticator)
{
	cJSON *parsed_res, *port_role;
	char *buf = NULL;
	char *gpath;
	int ret;

	ret = asprintf(&gpath,
		       "/openconfig-authmgr:authmgr/authmgr-port-config/interface[name=%s]/state/port-pae-role",
		       port_key->name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	port_role = cJSON_GetObjectItemCaseSensitive(parsed_res, "openconfig-authmgr:port-pae-role");
	if (!port_role || !cJSON_GetStringValue(port_role))
		goto err_gnmi_get_obj;

	if (strcmp(cJSON_GetStringValue(port_role), "AUTHENTICATOR") == 0)
		*is_authenticator = true;
	else
		*is_authenticator = false;

err_gnmi_get_obj:
	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_port_ieee8021x_port_host_mode_get(struct gnma_port_key *port_key,
					   gnma_8021x_port_host_mode_t *mode)
{
	cJSON *parsed_res, *host_mode;
	char *buf = NULL;
	char *gpath;
	int ret;

	ret = asprintf(&gpath,
		       "/openconfig-authmgr:authmgr/authmgr-port-config/interface[name=%s]/state/host-control-mode",
		       port_key->name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	host_mode = cJSON_GetObjectItemCaseSensitive(parsed_res, "openconfig-authmgr:host-control-mode");
	if (!host_mode || !cJSON_GetStringValue(host_mode))
		goto err_gnmi_get_obj;

	if (strcmp(cJSON_GetStringValue(host_mode), "MULTI_AUTH") == 0)
		*mode = GNMA_8021X_PORT_HOST_MODE_MULTI_AUTH;
	else if (strcmp(cJSON_GetStringValue(host_mode), "MULTI_DOMAIN") == 0)
		*mode = GNMA_8021X_PORT_HOST_MODE_MULTI_DOMAIN;
	else if (strcmp(cJSON_GetStringValue(host_mode), "MULTI_HOST") == 0)
		*mode = GNMA_8021X_PORT_HOST_MODE_MULTI_HOST;
	else if (strcmp(cJSON_GetStringValue(host_mode), "SINGLE_HOST") == 0)
		*mode = GNMA_8021X_PORT_HOST_MODE_SINGLE_HOST;
	else {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get_obj;
	}

err_gnmi_get_obj:
	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_port_ieee8021x_port_ctrl_get(struct gnma_port_key *port_key,
				      gnma_8021x_port_ctrl_mode_t *mode)
{
	cJSON *parsed_res, *port_mode;
	char *buf = NULL;
	char *gpath;
	int ret;

	ret = asprintf(&gpath,
		       "/openconfig-authmgr:authmgr/authmgr-port-config/interface[name=%s]/state/port-control-mode",
		       port_key->name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	port_mode = cJSON_GetObjectItemCaseSensitive(parsed_res, "openconfig-authmgr:port-control-mode");
	if (!port_mode || !cJSON_GetStringValue(port_mode))
		goto err_gnmi_get_obj;

	if (strcmp(cJSON_GetStringValue(port_mode), "FORCE_AUTHORIZED") == 0)
		*mode = GNMA_8021X_PORT_CTRL_MODE_FORCE_AUTHORIZED;
	else if (strcmp(cJSON_GetStringValue(port_mode), "FORCE_UNAUTHORIZED") == 0)
		*mode = GNMA_8021X_PORT_CTRL_MODE_FORCE_UNAUTHORIZED;
	else
		*mode = GNMA_8021X_PORT_CTRL_MODE_AUTO;

err_gnmi_get_obj:
	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_port_ieee8021x_guest_vlan_get(struct gnma_port_key *port_key,
				       uint16_t *vid)
{
	cJSON *parsed_res, *guest_vlan_id;
	char *buf = NULL;
	char *gpath;
	int ret;

	ret = asprintf(&gpath,
		       "/openconfig-authmgr:authmgr/authmgr-port-config/interface[name=%s]/state/guest-vlan-id",
		       port_key->name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	guest_vlan_id = cJSON_GetObjectItemCaseSensitive(parsed_res, "openconfig-authmgr:guest-vlan-id");
	if (!guest_vlan_id || !cJSON_IsNumber(guest_vlan_id))
		goto err_gnmi_get_obj;

	*vid = (uint16_t)cJSON_GetNumberValue(guest_vlan_id);

err_gnmi_get_obj:
	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_port_ieee8021x_unauthorized_vlan_get(struct gnma_port_key *port_key,
					      uint16_t *vid)
{
	cJSON *parsed_res, *fail_vlan_id;
	char *buf = NULL;
	char *gpath;
	int ret;

	ret = asprintf(&gpath,
		       "/openconfig-authmgr:authmgr/authmgr-port-config/interface[name=%s]/state/auth-fail-vlan-id",
		       port_key->name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	fail_vlan_id = cJSON_GetObjectItemCaseSensitive(parsed_res, "openconfig-authmgr:auth-fail-vlan-id");
	if (!fail_vlan_id || !cJSON_IsNumber(fail_vlan_id))
		goto err_gnmi_get_obj;

	*vid = (uint16_t)cJSON_GetNumberValue(fail_vlan_id);

err_gnmi_get_obj:
	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_port_stats_get(struct gnma_port_key *port_key,
			uint32_t num_of_counters,
			gnma_port_stat_type_t *counter_ids,
			uint64_t *counters)
{
	cJSON *parsed_res, *iface_counters, *counter;
	const char *counter_string;
	char *gpath;
	int ret;
	size_t i;
	char *buf = 0;

	ret = asprintf(&gpath, "/openconfig-interfaces:interfaces/interface[name=%s]/state/counters",
		       port_key->name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	memset(counters, 0, sizeof(*counters) * num_of_counters);

	iface_counters =
		cJSON_GetObjectItemCaseSensitive(parsed_res,
						 "openconfig-interfaces:counters");
	if (!iface_counters || !cJSON_IsObject(iface_counters)) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get_obj;
	}

	for (i = 0; i < num_of_counters; ++i) {
		counter_string = gnma_port_stats_type_to_string(counter_ids[i]);
		counter = cJSON_GetObjectItemCaseSensitive(iface_counters,
							   counter_string);
		if (counter && cJSON_IsString(counter))
			counters[i] = strtoull(cJSON_GetStringValue(counter),
					       NULL, 10);
	}

err_gnmi_get_obj:
	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_port_lldp_peer_info_get(struct gnma_port_key *port_key, char *buf,
				 size_t buf_size)
{
	cJSON *parsed_res, *lldp_neigh;
	char *gpath;
	int ret;

	ret = asprintf(&gpath,
		       "/openconfig-lldp:lldp/interfaces/interface[name=%s]/neighbors/neighbor[id=%s]",
		       port_key->name, port_key->name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get(main_switch, &gpath[0], buf, buf_size,
			     DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	lldp_neigh = cJSON_GetObjectItemCaseSensitive(parsed_res, "openconfig-lldp:neighbor");
	if (!lldp_neigh || !cJSON_IsArray(lldp_neigh) || !cJSON_GetArraySize(lldp_neigh)) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get_obj;
	}

	ret = !cJSON_PrintPreallocated(cJSON_GetArrayItem(lldp_neigh, 0), buf, buf_size - 1, false);

err_gnmi_get_obj:
	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_poe_power_mgmt_set(gnma_poe_power_mgmt_mode_t mode)
{
	const char *str;
	cJSON *root;
	cJSON *arr;
	char *path;
	int ret;

	switch(mode) {
		case GNMA_POE_POWER_MGMT_CLASS_E:
			str = "CLASS";
			break;
		case GNMA_POE_POWER_MGMT_DYNAMIC_E:
			str = "DYNAMIC";
			break;
		case GNMA_POE_POWER_MGMT_DYNAMIC_PRIORITY_E:
			str = "DYNAMIC_PRI";
			break;
		case GNMA_POE_POWER_MGMT_STATIC_E:
			str = "STATIC";
			break;
		case GNMA_POE_POWER_MGMT_STATIC_PRIORITY_E:
			str = "STATIC_PRI";
			break;
		default:
			return GNMA_ERR_COMMON;
	}

	ret = asprintf(&path, "/sonic-poe:sonic-poe/POE/POE_LIST[id=GLOBAL]/power_management_model");
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	root = cJSON_CreateObject();
	if (!root) {
		ret = GNMA_ERR_COMMON;
		goto err_root_alloc;
	}

	arr = cJSON_AddStringToObject(root, "sonic-poe:power_management_model",
				      str);
	if (!arr) {
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	ret = gnmi_json_object_set(main_switch, path, root, DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_req_fail;
	}

	ret = 0;
err_req_fail:
err_val_alloc:
	cJSON_Delete(root);
err_root_alloc:
	free(path);
err_path_alloc:
	return ret;
}

int gnma_poe_power_mgmt_get(gnma_poe_power_mgmt_mode_t *mode)
{
	cJSON *parsed_res, *power_mgmt_mode;
	char *buf = NULL;
	const char *str;
	char *gpath;
	int ret;

	ret = asprintf(&gpath, "/sonic-poe:sonic-poe/POE/POE_LIST[id=GLOBAL]/power_management_model");
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	power_mgmt_mode =
		cJSON_GetObjectItemCaseSensitive(parsed_res,
						 "sonic-poe:power_management_model");
	if (!power_mgmt_mode || !cJSON_GetStringValue(power_mgmt_mode))
		goto err_gnmi_get_obj;

	str = cJSON_GetStringValue(power_mgmt_mode);

	ret = 0;

	if (!strcmp(str, "CLASS"))
		*mode = GNMA_POE_POWER_MGMT_CLASS_E;
	else if (!strcmp(str, "DYNAMIC"))
		*mode = GNMA_POE_POWER_MGMT_DYNAMIC_E;
	else if (!strcmp(str, "DYNAMIC_PRI"))
		*mode = GNMA_POE_POWER_MGMT_DYNAMIC_PRIORITY_E;
	else if (!strcmp(str, "STATIC"))
		*mode = GNMA_POE_POWER_MGMT_STATIC_E;
	else if (!strcmp(str, "STATIC_PRI"))
		*mode = GNMA_POE_POWER_MGMT_STATIC_PRIORITY_E;
	else
		ret = GNMA_ERR_COMMON;

err_gnmi_get_obj:
	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_poe_usage_threshold_set(uint8_t power_threshold)
{
	char *gpath;
	cJSON *root;
	cJSON *val;
	cJSON *arr;
	int ret;

	ret = asprintf(&gpath, "/sonic-poe:sonic-poe/POE/POE_LIST[id=GLOBAL]");
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	root = cJSON_CreateObject();
	if (!root) {
		ret = GNMA_ERR_COMMON;
		goto err_root_alloc;
	}

	arr = cJSON_AddArrayToObject(root, "sonic-poe:POE_LIST");
	if (!arr) {
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	val = cJSON_CreateObject();
	if (!val) {
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	if (!cJSON_AddItemToArray(arr, val)) {
		cJSON_Delete(val);
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	if (!cJSON_AddStringToObject(val, "id", "GLOBAL")) {
		ret = GNMA_ERR_COMMON;
		goto err_val_set;
	}

	if (!cJSON_AddNumberToObject(val, "power_usage_threshold",
				     power_threshold)) {
		ret = GNMA_ERR_COMMON;
		goto err_val_set;
	}

	ret = gnmi_json_object_set(main_switch, gpath, root,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_req_fail;
	}

	ret = 0;
err_req_fail:
err_val_set:
err_val_alloc:
	cJSON_Delete(root);
err_root_alloc:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_poe_usage_threshold_get(uint8_t *power_threshold)
{
	cJSON *parsed_res, *power_usage_threshold;
	char *buf = NULL;
	char *gpath;
	int ret;

	ret = asprintf(&gpath, "/sonic-poe:sonic-poe/POE/POE_LIST[id=GLOBAL]/power_usage_threshold");
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	power_usage_threshold =
		cJSON_GetObjectItemCaseSensitive(parsed_res,
						 "sonic-poe:power_usage_threshold");
	if (!power_usage_threshold || !cJSON_IsNumber(power_usage_threshold))
		goto err_gnmi_get_obj;

	ret = 0;
	*power_threshold = (uint8_t)cJSON_GetNumberValue(power_usage_threshold);

err_gnmi_get_obj:
	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_poe_state_get(char *buf, size_t buf_size)
{
	cJSON *parsed_res, *state;
	char *gpath;
	int ret;

	ret = asprintf(&gpath, "/openconfig-poe:poe/global/state/");
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get(main_switch, &gpath[0], buf, buf_size,
			     DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	state = cJSON_GetObjectItemCaseSensitive(parsed_res, "openconfig-poe:state");
	if (!state) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get_obj;
	}

	ret = !cJSON_PrintPreallocated(state, buf, buf_size - 1, false);

err_gnmi_get_obj:
	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_poe_port_admin_mode_set(struct gnma_port_key *port_key, bool enabled)
{
	cJSON *root;
	char *gpath;
	int ret;

	/* <Admin mode> of POE. Setting it UP/DOWN doesn't alter port's MAC
	 * admin state.
	 */
	ret = asprintf(&gpath, "/sonic-poe:sonic-poe/POE_PORT/POE_PORT_LIST[ifname=%s]/admin_mode",
		       port_key->name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	root = cJSON_CreateObject();
	if (!root) {
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	if (!cJSON_AddBoolToObject(root, "sonic-poe:admin_mode",
				   enabled)) {
		ret = GNMA_ERR_COMMON;
		goto err_val_set;
	}

	ret = gnmi_json_object_set(main_switch, gpath, root,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_req_fail;
	}

	ret = 0;
err_req_fail:
err_val_set:
err_val_alloc:
	cJSON_Delete(root);
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_poe_port_admin_mode_get(struct gnma_port_key *port_key, bool *enabled)
{
	cJSON *parsed_res, *is_up;
	char *buf = NULL;
	char *gpath;
	int ret;

	ret = asprintf(&gpath, "/sonic-poe:sonic-poe/POE_PORT/POE_PORT_LIST[ifname=%s]/admin_mode",
		       port_key->name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	is_up = cJSON_GetObjectItemCaseSensitive(parsed_res,
						 "sonic-poe:admin_mode");
	if (!is_up || !cJSON_IsBool(is_up))
		goto err_gnmi_get_obj;

	ret = 0;

	*enabled = cJSON_IsTrue(is_up);

err_gnmi_get_obj:
	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_poe_port_detection_mode_set(struct gnma_port_key *port_key,
				     gnma_poe_port_detection_mode_t mode)
{
	const char *str;
	cJSON *root;
	char *gpath;
	int ret;

	switch(mode) {
		case GNMA_POE_PORT_DETECTION_MODE_2PT_DOT3AF_E:
			str = "TWO_PT_DOT3AF";
			break;
		case GNMA_POE_PORT_DETECTION_MODE_2PT_DOT3AF_LEG_E:
			str = "TWO_PT_DOT3AF_LEG";
			break;
		case GNMA_POE_PORT_DETECTION_MODE_4PT_DOT3AF_E:
			str = "FOUR_PT_DOT3AF";
			break;
		case GNMA_POE_PORT_DETECTION_MODE_4PT_DOT3AF_LEG_E:
			str = "FOUR_PT_DOT3AF_LEG";
			break;
		case GNMA_POE_PORT_DETECTION_MODE_DOT3BT_E:
			str = "DOT3BT";
			break;
		case GNMA_POE_PORT_DETECTION_MODE_DOT3BT_LEG_E:
			str = "DOT3BT_LEG";
			break;
		case GNMA_POE_PORT_DETECTION_MODE_LEG_E:
			str = "LEGACY";
			break;
		default:
			return GNMA_ERR_COMMON;
	}

	ret = asprintf(&gpath, "/sonic-poe:sonic-poe/POE_PORT/POE_PORT_LIST[ifname=%s]/detection_mode",
		       port_key->name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	root = cJSON_CreateObject();
	if (!root) {
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	if (!cJSON_AddStringToObject(root, "sonic-poe:detection_mode",
				     str)) {
		ret = GNMA_ERR_COMMON;
		goto err_val_set;
	}

	ret = gnmi_json_object_set(main_switch, gpath, root,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_req_fail;
	}

	ret = 0;
err_req_fail:
err_val_set:
err_val_alloc:
	cJSON_Delete(root);
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_poe_port_detection_mode_get(struct gnma_port_key *port_key,
				     gnma_poe_port_detection_mode_t *mode)
{
	cJSON *parsed_res, *detection_mode;
	char *buf = NULL;
	const char *str;
	char *gpath;
	int ret;

	ret = asprintf(&gpath, "/sonic-poe:sonic-poe/POE_PORT/POE_PORT_LIST[ifname=%s]/detection_mode",
		       port_key->name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	detection_mode =
		cJSON_GetObjectItemCaseSensitive(parsed_res,
						 "sonic-poe:detection_mode");
	if (!detection_mode || !cJSON_GetStringValue(detection_mode))
		goto err_gnmi_get_obj;

	str = cJSON_GetStringValue(detection_mode);

	ret = 0;

	if (!strcmp(str, "TWO_PT_DOT3AF"))
		*mode = GNMA_POE_PORT_DETECTION_MODE_2PT_DOT3AF_E;
	else if (!strcmp(str, "TWO_PT_DOT3AF_LEG"))
		*mode = GNMA_POE_PORT_DETECTION_MODE_2PT_DOT3AF_LEG_E;
	else if (!strcmp(str, "FOUR_PT_DOT3AF"))
		*mode = GNMA_POE_PORT_DETECTION_MODE_4PT_DOT3AF_E;
	else if (!strcmp(str, "FOUR_PT_DOT3AF_LEG"))
		*mode = GNMA_POE_PORT_DETECTION_MODE_4PT_DOT3AF_LEG_E;
	else if (!strcmp(str, "DOT3BT"))
		*mode = GNMA_POE_PORT_DETECTION_MODE_DOT3BT_E;
	else if (!strcmp(str, "DOT3BT_LEG"))
		*mode = GNMA_POE_PORT_DETECTION_MODE_DOT3BT_LEG_E;
	else if (!strcmp(str, "LEGACY"))
		*mode = GNMA_POE_PORT_DETECTION_MODE_LEG_E;
	else
		ret = GNMA_ERR_COMMON;

err_gnmi_get_obj:
	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_poe_port_power_limit_set(struct gnma_port_key *port_key,
				  bool user_defined, uint32_t power_limit)
{
	const char *str;
	char *gpath;
	cJSON *root;
	cJSON *val;
	cJSON *arr;
	int ret;

	if (user_defined)
		str = "USER";
	else
		str = "CLASS_BASED";

	ret = asprintf(&gpath, "/sonic-poe:sonic-poe/POE_PORT/POE_PORT_LIST[ifname=%s]",
		       port_key->name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	root = cJSON_CreateObject();
	if (!root) {
		ret = GNMA_ERR_COMMON;
		goto err_root_alloc;
	}

	arr = cJSON_AddArrayToObject(root, "sonic-poe:POE_PORT_LIST");
	if (!arr) {
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	val = cJSON_CreateObject();
	if (!val) {
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	if (!cJSON_AddItemToArray(arr, val)) {
		cJSON_Delete(val);
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	if (!cJSON_AddStringToObject(val, "power_limit_type", str)) {
		ret = GNMA_ERR_COMMON;
		goto err_val_set;
	}

	if (!cJSON_AddStringToObject(val, "ifname", port_key->name)) {
		ret = GNMA_ERR_COMMON;
		goto err_val_set;
	}

	/* Setting power_limit without specifying power_limit_type to user
	 * defined makes no sense, so set power_limit only when
	 * mode is user defined.
	 */
	if (user_defined) {
		if (!cJSON_AddNumberToObject(val, "power_limit", power_limit)) {
			ret = GNMA_ERR_COMMON;
			goto err_val_set;
		}
	}

	ret = gnmi_json_object_set(main_switch, gpath, root,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_req_fail;
	}

	ret = 0;
err_req_fail:
err_val_set:
err_val_alloc:
	cJSON_Delete(root);
err_root_alloc:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_poe_port_power_limit_get(struct gnma_port_key *port_key,
				  bool *user_defined, uint32_t *power_limit)
{
	cJSON *parsed_res;
	cJSON *limit_type;
	char *buf = NULL;
	const char *str;
	cJSON *limit;
	char *gpath;
	cJSON *port;
	cJSON *arr;
	int ret;

	ret = asprintf(&gpath, "/sonic-poe:sonic-poe/POE_PORT/POE_PORT_LIST[ifname=%s]",
		       port_key->name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	arr = cJSON_GetObjectItemCaseSensitive(parsed_res,
					       "sonic-poe:POE_PORT_LIST");
	if (!arr || !cJSON_IsArray(arr))
		goto err_gnmi_get_obj;

	port = cJSON_GetArrayItem(arr, 0);
	if (!port || !cJSON_IsObject(port))
		goto err_gnmi_get_obj;

	limit_type = cJSON_GetObjectItemCaseSensitive(port, "power_limit_type");
	limit = cJSON_GetObjectItemCaseSensitive(port, "power_limit");
	if (!cJSON_GetStringValue(limit_type) ||
	    !limit || !cJSON_IsNumber(limit))
		goto err_gnmi_get_obj;

	str = cJSON_GetStringValue(limit_type);
	if (!strcmp(str, "CLASS_BASED")) {
		*user_defined = false;
		*power_limit = 0;
	} else {
		*user_defined = true;
		*power_limit = (uint32_t)cJSON_GetNumberValue(limit);
	}

	ret = 0;
err_gnmi_get_obj:
	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_poe_port_priority_set(struct gnma_port_key *port_key,
			       gnma_poe_port_priority_t priority)
{
	const char *str;
	cJSON *root;
	char *gpath;
	int ret;

	switch(priority) {
		case GNMA_POE_PORT_PRIORITY_LOW_E:
			str = "LOW";
			break;
		case GNMA_POE_PORT_PRIORITY_MEDIUM_E:
			str = "MEDIUM";
			break;
		case GNMA_POE_PORT_PRIORITY_HIGH_E:
			str = "HIGH";
			break;
		case GNMA_POE_PORT_PRIORITY_CRITICAL_E:
			str = "CRITICAL";
			break;
		default:
			return GNMA_ERR_COMMON;
	}

	ret = asprintf(&gpath, "/sonic-poe:sonic-poe/POE_PORT/POE_PORT_LIST[ifname=%s]/priority",
		       port_key->name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	root = cJSON_CreateObject();
	if (!root) {
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	if (!cJSON_AddStringToObject(root, "sonic-poe:priority",
				     str)) {
		ret = GNMA_ERR_COMMON;
		goto err_val_set;
	}

	ret = gnmi_json_object_set(main_switch, gpath, root,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_req_fail;
	}

	ret = 0;
err_req_fail:
err_val_set:
err_val_alloc:
	cJSON_Delete(root);
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_poe_port_priority_get(struct gnma_port_key *port_key,
			       gnma_poe_port_priority_t *priority)
{
	cJSON *parsed_res, *port_priority;
	char *buf = NULL;
	const char *str;
	char *gpath;
	int ret;

	ret = asprintf(&gpath, "/sonic-poe:sonic-poe/POE_PORT/POE_PORT_LIST[ifname=%s]/priority",
		       port_key->name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	port_priority =
		cJSON_GetObjectItemCaseSensitive(parsed_res,
						 "sonic-poe:priority");
	if (!port_priority || !cJSON_GetStringValue(port_priority))
		goto err_gnmi_get_obj;

	str = cJSON_GetStringValue(port_priority);

	ret = 0;

	if (!strcmp(str, "LOW"))
		*priority = GNMA_POE_PORT_PRIORITY_LOW_E;
	else if (!strcmp(str, "MEDIUM"))
		*priority = GNMA_POE_PORT_PRIORITY_MEDIUM_E;
	else if (!strcmp(str, "HIGH"))
		*priority = GNMA_POE_PORT_PRIORITY_HIGH_E;
	else if (!strcmp(str, "CRITICAL"))
		*priority = GNMA_POE_PORT_PRIORITY_CRITICAL_E;
	else
		ret = GNMA_ERR_COMMON;

err_gnmi_get_obj:
	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_poe_port_reset(struct gnma_port_key *port_key)
{
	return gnmi_gnoi_poe_port_reset(main_switch, port_key->name,
					DEFAULT_TIMEOUT_US);
}

/* SAI_SWITCH_ATTR_??_POE_???_PORT_LIST */
int gnma_poe_port_list_get(uint16_t *list_size,
			   struct gnma_port_key *port_key_arr)
{
	cJSON *parsed_res, *ports_arr, *iter;
	uint16_t name_len;
	uint16_t ports_num;
	char *port_name;
	char *gpath;
	char *buf = 0;
	int ret;

	ret = asprintf(&gpath, "/sonic-poe:sonic-poe/POE_PORT/POE_PORT_LIST");
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	ports_arr = cJSON_GetObjectItemCaseSensitive(parsed_res, "sonic-poe:POE_PORT_LIST");
	if (!ports_arr || !cJSON_IsArray(ports_arr)) {
		ret = 0;
		*list_size = 0;
		goto err_gnmi_check_arr;
	}

	ports_num = 0;
	cJSON_ArrayForEach(iter, ports_arr) {
		port_name = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(iter, "ifname"));
		if (!port_name) {
			ret = GNMA_ERR_COMMON;
			goto err_result_fill;
		}

		name_len = strlen(port_name);
		if (name_len >= GNMA_PORT_KEY_LEN) {
			ret = GNMA_ERR_COMMON;
			goto err_result_fill;
		}

		if (ports_num < *list_size)
			memcpy(port_key_arr[ports_num].name,
			       port_name, name_len + 1);

		ports_num++;
	}

	if (cJSON_GetArraySize(ports_arr) > *list_size) {
		*list_size = cJSON_GetArraySize(ports_arr);
		ret = GNMA_ERR_OVERFLOW;
		goto err_result_fill;
	}

	*list_size = cJSON_GetArraySize(ports_arr);

	ret = 0;

err_result_fill:
err_gnmi_check_arr:
	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_poe_port_state_get(struct gnma_port_key *port_key, char *buf,
			    size_t buf_size)
{
	cJSON *parsed_res, *state;
	char *gpath;
	int ret;

	ret = asprintf(&gpath,
		       "/openconfig-interfaces:interfaces/interface[name=%s]/openconfig-if-ethernet:ethernet/openconfig-if-poe:poe/state",
		       port_key->name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get(main_switch, &gpath[0], buf, buf_size,
			     DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	state = cJSON_GetObjectItemCaseSensitive(parsed_res, "openconfig-if-poe:state");
	if (!state) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get_obj;
	}

	ret = !cJSON_PrintPreallocated(state, buf, buf_size - 1, false);

err_gnmi_get_obj:
	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_vlan_remove(uint16_t vid) /* TODO: ret oid */
{
	char vlan_name[32];
	int ret;
	char *path;

	sprintf(&vlan_name[0], "Vlan%u", vid);
	ret = asprintf(&path, "/sonic-vlan:sonic-vlan/VLAN/VLAN_LIST[name=%s]",
			vlan_name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_del(main_switch, path, DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_req_fail;
	}

	ret = 0;
err_req_fail:
	free(path);
err_path_alloc:
	return ret;
}

int gnma_vlan_create(struct gnma_change *c, uint16_t vid) /* TODO: ret oid */
{
	char vlan_name[32];
	int ret;
	cJSON *root;
	cJSON *val, *arr;
	char *path;


	ret = asprintf(&path, "/sonic-vlan:sonic-vlan/VLAN/VLAN_LIST");
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	root = cJSON_CreateObject();
	if (!root) {
		ret = GNMA_ERR_COMMON;
		goto err_root_alloc;
	}

	arr = cJSON_AddArrayToObject(root, "sonic-vlan:VLAN_LIST");
	if (!arr) {
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	val = cJSON_CreateObject();
	if (!val) {
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	if (!cJSON_AddItemToArray(arr, val)) {
		cJSON_Delete(val);
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	if (!cJSON_AddNumberToObject(val, "vlanid", vid)) {
		ret = GNMA_ERR_COMMON;
		goto err_val_set;
	}

	sprintf(&vlan_name[0], "Vlan%u", vid);
	if (!cJSON_AddStringToObject(val, "name", &vlan_name[0])) {
		ret = GNMA_ERR_COMMON;
		goto err_val_set;
	}

	ret = gnmi_setrq_add_object_update((struct gnmi_setrq *)c, path, root);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_req_fail;
	}

	ret = 0;
err_req_fail:
err_val_set:
err_val_alloc:
	cJSON_Delete(root);
err_root_alloc:
	free(path);
err_path_alloc:
	return ret;
}

int gnma_vlan_member_remove(struct gnma_change *c, uint16_t vid,
			    struct gnma_port_key *port_key)
{
	char vlan_name[32];
	int ret;
	char *path;

	sprintf(&vlan_name[0], "Vlan%u", vid);
	ret = asprintf(&path, "/sonic-vlan:sonic-vlan/VLAN_MEMBER/VLAN_MEMBER_LIST[name=%s][ifname=%s]",
			&vlan_name[0], port_key->name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_setrq_add_delete((struct gnmi_setrq *)c, path);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_req_fail;
	}

	ret = 0;
err_req_fail:
	free(path);
err_path_alloc:
	return ret;
}

int gnma_vlan_member_create(struct gnma_change *c, uint16_t vid,
			    struct gnma_port_key *port_key, bool tagged)
{
	char vlan_name[32];
	int ret;
	cJSON *root;
	cJSON *val, *arr;
	char *path;


	ret = asprintf(&path, "/sonic-vlan:sonic-vlan/VLAN_MEMBER/VLAN_MEMBER_LIST");
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	root = cJSON_CreateObject();
	if (!root) {
		ret = GNMA_ERR_COMMON;
		goto err_root_alloc;
	}

	arr = cJSON_AddArrayToObject(root, "sonic-vlan:VLAN_MEMBER_LIST");
	if (!arr) {
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	val = cJSON_CreateObject();
	if (!val) {
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	if (!cJSON_AddItemToArray(arr, val)) {
		cJSON_Delete(val);
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	sprintf(&vlan_name[0], "Vlan%u", vid);
	if (!cJSON_AddStringToObject(val, "name", &vlan_name[0])) {
		ret = GNMA_ERR_COMMON;
		goto err_val_set;
	}

	if (!cJSON_AddStringToObject(val, "ifname", port_key->name)) {
		ret = GNMA_ERR_COMMON;
		goto err_val_set;
	}

	if (!cJSON_AddStringToObject(val, "tagging_mode",
				     tagged ? "tagged" : "untagged")) {
		ret = GNMA_ERR_COMMON;
		goto err_val_set;
	}

	ret = gnmi_setrq_add_object_update((struct gnmi_setrq *)c, path, root);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_req_fail;
	}

	ret = 0;
err_req_fail:
err_val_set:
err_val_alloc:
	cJSON_Delete(root);
err_root_alloc:
	free(path);
err_path_alloc:
	return ret;
}

/* SAI_VLAN_ATTR_MEMBER_LIST */
int gnma_vlan_member_bmap_get(struct gnma_vlan_member_bmap *vlan_mbr)
{
	cJSON *members_arr, *member, *tagged;
	char *vlan_name, *member_name;
	uint16_t vid, pid;
	char path[] = "/sonic-vlan:sonic-vlan/VLAN_MEMBER/VLAN_MEMBER_LIST";
	char *buf = 0;
	cJSON *parsed_res = 0;
	int ret = GNMA_ERR_COMMON;

	if (gnmi_jsoni_get_alloc(main_switch, path, &buf, 0,
				 DEFAULT_TIMEOUT_US)) {
		return GNMA_ERR_COMMON;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		goto out;
	}

	members_arr = cJSON_GetObjectItemCaseSensitive(parsed_res, "sonic-vlan:VLAN_MEMBER_LIST");
	if (!members_arr || !cJSON_IsArray(members_arr)) {
		ret = 0;
		goto out;
	}

	cJSON_ArrayForEach(member, members_arr) {
		vlan_name = cJSON_GetStringValue(
			cJSON_GetObjectItemCaseSensitive(member, "name"));
		if (!vlan_name) {
			goto out;
		}

		if (sscanf(vlan_name, "Vlan%" SCNu16, &vid) < 1) {
			continue;
		}

		member_name = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(member, "ifname"));
		if (!member_name) {
			goto out;
		}

		tagged = cJSON_GetObjectItemCaseSensitive(member,
							  "tagging_mode");
		if (!tagged || !cJSON_IsString(tagged)) {
			goto out;
		}

		if (sscanf(member_name, "Ethernet%" SCNu16, &pid) < 1) {
			continue;
		}

		if (vid >= ARRAY_LENGTH(vlan_mbr->vlan)) {
			goto out;
		}

		if (pid >= BITMAP_BITSIZE(vlan_mbr->vlan[vid].port_member)) {
			goto out;
		}

		BITMAP_SET_BIT(vlan_mbr->vlan[vid].port_member, pid);
		if (!strcmp(cJSON_GetStringValue(tagged), "tagged"))
			BITMAP_SET_BIT(vlan_mbr->vlan[vid].port_tagged, pid);
	}

	ret = 0;
out:
	cJSON_Delete(parsed_res);
	return ret;
}

/* SAI_SWITCH_ATTR_VLAN_LIST ??? */
int gnma_vlan_list_get(BITMAP_DECLARE(vlans, GNMA_MAX_VLANS))
{
	cJSON *vlan_arr, *vlan;
	char gpath[64];
	uint16_t vid;
	char *buf = 0;
	cJSON *parsed_res = 0;
	int ret = GNMA_ERR_COMMON;

	sprintf(&gpath[0], "/sonic-vlan:sonic-vlan/VLAN/VLAN_LIST");

	if (gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				 DEFAULT_TIMEOUT_US)) {
		return GNMA_ERR_COMMON;
	}
	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res)
		goto err;

	/* It is OK, when vlan_arr = NULL. Means arr is empty. */
	/* So, just check, if item is returned as another type (str, num) */
	vlan_arr = cJSON_GetObjectItemCaseSensitive(parsed_res, "sonic-vlan:VLAN_LIST");
	if (vlan_arr && !cJSON_IsArray(vlan_arr))
		goto err;

	cJSON_ArrayForEach(vlan, vlan_arr) {
		vid = cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(vlan, "vlanid"));
		if (vid < GNMA_MAX_VLANS)
			BITMAP_SET_BIT(vlans, vid);
	}

	ret = 0;
err:
	cJSON_Delete(parsed_res);
	return ret;
}

int gnma_reboot(void)
{
	return gnmi_gnoi_system_reboot(main_switch, DEFAULT_TIMEOUT_US);
}

/* SAI_? */
int gnma_config_save(void)
{
	/* NOTE: for this direction gnoi (bcm) returns:
	* {"output":{"status":1,"status_detail":"open /mnt/tmp/replace: no such file or directory"}}
	* But config_db.json updated
	*/
	return gnmi_gnoi_sonic_copy_replace(main_switch,
					    "running-configuration",
					    "startup-configuration",
					    DEFAULT_TIMEOUT_US);
}

/* SAI_? */
int gnma_config_restore(void)
{
	return gnmi_gnoi_sonic_copy_replace(main_switch,
					    "startup-configuration",
					    "running-configuration",
					    DEFAULT_TIMEOUT_US);
}

/* SAI_SWITCH_ATTR_PORT_LIST */
int gnma_port_list_get(uint16_t *list_size, struct gnma_port_key *port_key_list) /* switch/session id ? */
{
	cJSON *parsed_res, *ports_arr, *iter;
	int ret;
	uint16_t name_len;
	uint16_t ports_num;
	char *port_name;
	char gpath[256];
	char *buf = 0;

	memset(port_key_list, 0, (*list_size) * sizeof(*port_key_list));
	sprintf(&gpath[0], "/sonic-port:sonic-port/PORT/PORT_LIST");

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	ports_arr = cJSON_GetObjectItemCaseSensitive(parsed_res, "sonic-port:PORT_LIST");
	if (!ports_arr || !cJSON_IsArray(ports_arr)) {
		ret = 0;
		*list_size = 0;
		goto err_gnmi_check_arr;
	}

	ports_num = 0;
	cJSON_ArrayForEach(iter, ports_arr) {
		port_name = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(iter, "ifname"));
		if (!port_name) {
			ret = GNMA_ERR_COMMON;
			goto err_result_fill;
		}

		name_len = strlen(port_name);
		if (name_len >= GNMA_PORT_KEY_LEN) {
			ret = GNMA_ERR_COMMON;
			goto err_result_fill;
		}

		if (ports_num < *list_size)
			memcpy(port_key_list[ports_num].name,
				port_name, name_len + 1);

		ports_num++;
	}

	if (ports_num > *list_size) {
		ret = GNMA_ERR_OVERFLOW;
		*list_size = ports_num;
		goto err_result_fill;
	} else {
		*list_size = ports_num;
	}

	ret = 0;

err_result_fill:
err_gnmi_check_arr:
	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	return ret;
}

/* SAI_? */
int gnma_factory_default(void)
{
	int ret;
	ret = gnmi_gnoi_sonic_cfg_erase_boot(main_switch, DEFAULT_TIMEOUT_US);
	if (ret)
		return GNMA_ERR_COMMON;

	ret = gnmi_gnoi_system_reboot(main_switch, DEFAULT_TIMEOUT_US);
	if (ret) {
		/* Something went wrong. Try to restore state. */
		ret = gnmi_gnoi_sonic_cfg_erase_boot_cancel(main_switch,
							    DEFAULT_TIMEOUT_US);
		if (ret)
			main_log_cb("Another error occured, during state restore");

		return GNMA_ERR_COMMON;
	}

	return 0;
}

/* SAI_? */
int gnma_image_install(char *uri)
{
	int ret;
	ret = gnmi_gnoi_image_install(main_switch, uri, DEFAULT_TIMEOUT_US);
	if (ret)
		return GNMA_ERR_COMMON;

	return 0;
}

/* SAI_? */
/* gnma (sai) api to obtain status is not defined.
 * So use json buffer to prevent additional type convert on gnma layer.
 */
/*  TODO: define structure or content of json (or left as is for POC) */
int gnma_image_install_status(uint16_t *buf_size, char *buf)
{
	int ret;

	ret = gnmi_gnoi_upgrade_status(main_switch, buf, *buf_size,
				       DEFAULT_TIMEOUT_US);

	if (ret)
		return GNMA_ERR_COMMON;

	/* TODO: handle buffer overflow (like lists) */

	return 0;
}

int gnma_image_running_name_get(char *str, size_t str_max_len)
{
	cJSON *parsed_res, *img_global_list, *iter, *current_img = NULL;
	char gpath[256];
	int ret;
	char *buf = 0;

	sprintf(&gpath[0],
		"/sonic-image-management:sonic-image-management/IMAGE_GLOBAL/IMAGE_GLOBAL_LIST");

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	img_global_list = cJSON_GetObjectItemCaseSensitive(parsed_res,
					       "sonic-image-management:IMAGE_GLOBAL_LIST");
	if (!img_global_list || !cJSON_IsArray(img_global_list)) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get_obj;
	}

	cJSON_ArrayForEach(iter, img_global_list) {
		current_img = cJSON_GetObjectItemCaseSensitive(iter, "current");
		if (current_img)
			strncpy(str, cJSON_GetStringValue(current_img),
				str_max_len);
	}

	if (!current_img)
		ret = GNMA_ERR_COMMON;
	else
		ret = 0;

err_gnmi_get_obj:
	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	return ret;
}

int gnma_metadata_get(struct gnma_metadata *md)
{
	/* TODO(vb):
	 * to work even with an invalid "type" value, currently getting tree one by
	 * one. subject to change
	 */
	static char path_mac[] =
		"/sonic-device-metadata:sonic-device-metadata/DEVICE_METADATA/DEVICE_METADATA_LIST[name=localhost]/mac";
	static char path_hwsku[] =
		"/sonic-device-metadata:sonic-device-metadata/DEVICE_METADATA/DEVICE_METADATA_LIST[name=localhost]/hwsku";
	static char path_platform[] =
		"/sonic-device-metadata:sonic-device-metadata/DEVICE_METADATA/DEVICE_METADATA_LIST[name=localhost]/platform";
	char *buf = 0;
	cJSON *root_mac = 0, *root_hwsku = 0, *root_platform = 0, *val = 0;
	int ret = GNMA_ERR_COMMON;

	if (gnmi_jsoni_get_alloc(main_switch, path_mac, &buf, 0,
				 DEFAULT_TIMEOUT_US)) {
		goto err;
	}
	root_mac = cJSON_Parse(buf);
	ZFREE(buf);

	if (gnmi_jsoni_get_alloc(main_switch, path_hwsku, &buf, 0,
				 DEFAULT_TIMEOUT_US)) {
		goto err;
	}
	root_hwsku = cJSON_Parse(buf);
	ZFREE(buf);

	if (gnmi_jsoni_get_alloc(main_switch, path_platform, &buf, 0,
				 DEFAULT_TIMEOUT_US)) {
		goto err;
	}
	root_platform = cJSON_Parse(buf);
	ZFREE(buf);

	val = cJSON_GetObjectItemCaseSensitive(
		root_platform, "sonic-device-metadata:platform");
	if (!cJSON_IsString(val))
		goto err;
	snprintf(md->hwsku, sizeof md->hwsku, "%s", cJSON_GetStringValue(val));

	val = cJSON_GetObjectItemCaseSensitive(root_hwsku,
					       "sonic-device-metadata:hwsku");
	if (!cJSON_IsString(val))
		goto err;
	snprintf(md->platform, sizeof md->platform, "%s",
		 cJSON_GetStringValue(val));

	val = cJSON_GetObjectItemCaseSensitive(root_mac,
					       "sonic-device-metadata:mac");
	if (!cJSON_IsString(val))
		goto err;
	snprintf(md->mac, sizeof md->mac, "%s", cJSON_GetStringValue(val));

	ret = 0;
err:
	cJSON_Delete(root_platform);
	cJSON_Delete(root_hwsku);
	cJSON_Delete(root_mac);
	return ret;
}

int gnma_rebootcause_get(char *buf, size_t buf_size)
{
	cJSON *parsed_res, *reboot_cause;
	char *gpath;
	int ret;

	ret = asprintf(&gpath,
		       "/openconfig-system:system/openconfig-system-ext:infra/state/reboot-cause");
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get(main_switch, &gpath[0], buf, buf_size,
			     DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	reboot_cause = cJSON_GetObjectItemCaseSensitive(parsed_res, "openconfig-system-ext:reboot-cause");
	if (!cJSON_GetStringValue(reboot_cause)) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get_obj;
	}

	ret = !cJSON_PrintPreallocated(parsed_res, buf, buf_size - 1, false);

err_gnmi_get_obj:
	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

static int severity_str2int(const char *s)
{
	if (!s)
		return -1;

	if (!strcmp("CRITICAL", s))
		return 0;
	if (!strcmp("MAJOR", s))
		return 1;
	if (!strcmp("MINOR", s))
		return 2;
	if (!strcmp("WARNING", s))
		return 3;
	if (!strcmp("INFORMATIONAL", s))
		return 4;

	return -1;
}

static void alarm_gnmi_cb(const struct gnmi_subscribe_response *r,
			  gnma_alarm_cb cb, void *cb_data)
{
	int i;
	int severity;
	const char *ids[1] = { 0 };
	struct gnma_alarm a = {
		.id = "",
		.resource = "",
		.text = "",
		.type_id = "",
	};

	if (r->update.prefix.elem_size < 3 ||
	    r->update.prefix.elem[2].key_size != 1 ||
	    strcmp(strnonull(r->update.prefix.elem[2].key[0].key), "id")) {
		return;
	}

	a.id = r->update.prefix.elem[2].key[0].value;
	if (!strcmp(a.id, ""))
		return;

	for (i = 0; i < r->update.update_size; ++i) {
		int plen;
		const struct gnmi_path_elem *p;
		if (!r->update.update[i].has_path ||
		    !r->update.update[i].has_value) {
			continue;
		}

		/* TODO(vb) beautify */

		p = r->update.update[i].path.elem;
		plen = r->update.update[i].path.elem_size;

		if (strcmp(p[0].name, "state") || plen < 2) {
			continue;
		}

		if (!strcmp(p[1].name, "text")) {
			if (r->update.update[i].val.type !=
			    GNMI_TYPED_VALUE_STRING) {
				GNMI_C_CONNECTOR_DEBUG_LOG(
					"r->update.update[%d](text).val.type(%d) != GNMI_TYPED_VALUE_STRING",
					i, r->update.update[i].val.type);
			}
			a.text = strnonull(r->update.update[i].val.v.str);
			continue;
		}

		if (!strcmp(p[1].name, "resource")) {
			if (r->update.update[i].val.type !=
			    GNMI_TYPED_VALUE_STRING) {
				GNMI_C_CONNECTOR_DEBUG_LOG(
					"r->update.update[%d](resource).val.type(%d) != GNMI_TYPED_VALUE_STRING",
					i, r->update.update[i].val.type);
			}
			a.resource = strnonull(r->update.update[i].val.v.str);
			continue;
		}

		if (!strcmp(p[1].name, "type-id")) {
			if (r->update.update[i].val.type !=
			    GNMI_TYPED_VALUE_STRING) {
				GNMI_C_CONNECTOR_DEBUG_LOG(
					"r->update.update[%d](type-id).val.type(%d) != GNMI_TYPED_VALUE_STRING",
					i, r->update.update[i].val.type);
				continue;
			}
			a.type_id = strnonull(r->update.update[i].val.v.str);
			continue;
		}

		if (!strcmp(p[1].name, "severity")) {
			if (r->update.update[i].val.type !=
			    GNMI_TYPED_VALUE_STRING) {
				GNMI_C_CONNECTOR_DEBUG_LOG(
					"r->update.update[%d](severity).val.type(%d) != GNMI_TYPED_VALUE_STRING",
					i, r->update.update[i].val.type);
				continue;
			}
			severity =
				severity_str2int(r->update.update[i].val.v.str);
			if (severity >= 0) {
				/* TODO(vb) if not? */
				a.severity = severity;
			}
			continue;
		}

		if (!strcmp(p[1].name, "acknowledged")) {
			if (r->update.update[i].val.type !=
			    GNMI_TYPED_VALUE_BOOL) {
				GNMI_C_CONNECTOR_DEBUG_LOG(
					"r->update.update[%d](acknowledged).val.type(%d) != GNMI_TYPED_VALUE_BOOL",
					i, r->update.update[i].val.type);
				continue;
			}
			a.acknowledged = !!r->update.update[i].val.v.boolean;
			continue;
		}

		if (!strcmp(p[1].name, "acknowledge-time")) {
			if (r->update.update[i].val.type !=
			    GNMI_TYPED_VALUE_UINT) {
				GNMI_C_CONNECTOR_DEBUG_LOG(
					"r->update.update[%d](acknowledged-time).val.type(%d) != GNMI_TYPED_VALUE_UINT",
					i, r->update.update[i].val.type);
				continue;
			}
			a.acknowledge_time = r->update.update[i].val.v.u64;
			continue;
		}

		if (!strcmp(p[1].name, "time-created")) {
			if (r->update.update[i].val.type !=
			    GNMI_TYPED_VALUE_UINT) {
				GNMI_C_CONNECTOR_DEBUG_LOG(
					"r->update.update[%d](time-created).val.type(%d) != GNMI_TYPED_VALUE_UINT",
					i, r->update.update[i].val.type);
				continue;
			}
			a.time_created = r->update.update[i].val.v.u64;
		}
	}

	if (a.acknowledged) {
		return;
	}

	if (cb)
		cb(&a, cb_data);

	ids[0] = a.id;
	gnmi_gnoi_sonic_alarm_acknowledge(main_switch, ids, 1,
					  DEFAULT_TIMEOUT_US);
}

static void linkstatus_gnmi_cb(const struct gnmi_subscribe_response *r,
			       gnma_linkstatus_cb cb, void *cb_data)
{
	struct gnma_linkstatus s = { 0 };

	if (!r) {
		GNMI_C_CONNECTOR_DEBUG_LOG("exit");
		return;
	}

	if (r->update.prefix.elem[1].key_size <= 0) {
		GNMI_C_CONNECTOR_DEBUG_LOG(
			"r->update.prefix.elem[1].key_size <= 0");
		return;
	}

	if (r->update.update_size <= 0) {
		GNMI_C_CONNECTOR_DEBUG_LOG("r->update.update_size <= 0");
		return;
	}

	if (!r->update.update[0].has_value) {
		GNMI_C_CONNECTOR_DEBUG_LOG("!r->update.update[0].has_value");
		return;
	}

	if (r->update.update[0].val.type != GNMI_TYPED_VALUE_STRING) {
		GNMI_C_CONNECTOR_DEBUG_LOG(
			"r->update.update[0].val.type != GNMI_TYPED_VALUE_STRING");
		return;
	}

	s.timestamp = r->update.timestamp;
	s.ifname = r->update.prefix.elem[1].key[0].value;

	if (strncmp("Ethernet", s.ifname, sizeof "Ethernet" - 1)) {
		return;
	}

	if (!strcmp("DOWN", r->update.update[0].val.v.str)) {
		s.up = 0;
	} else if (!strcmp("UP", r->update.update[0].val.v.str)) {
		s.up = 1;
	} else {
		GNMI_C_CONNECTOR_DEBUG_LOG("invalid status value: %s",
					   r->update.update[0].val.v.str);
		return;
	}

	if (cb)
		cb(&s, cb_data);
}

static void poe_linkstatus_gnmi_cb(const struct gnmi_subscribe_response *r,
				   gnma_poe_linkstatus_cb cb, void *cb_data)
{
	struct gnma_poe_linkstatus s = { 0 };

	if (!r) {
		GNMI_C_CONNECTOR_DEBUG_LOG("exit");
		return;
	}

	if (r->update.prefix.elem[1].key_size <= 0) {
		GNMI_C_CONNECTOR_DEBUG_LOG(
			"r->update.prefix.elem[1].key_size <= 0");
		return;
	}

	if (r->update.update_size <= 0) {
		GNMI_C_CONNECTOR_DEBUG_LOG("r->update.update_size <= 0");
		return;
	}

	if (!r->update.update[0].has_value) {
		GNMI_C_CONNECTOR_DEBUG_LOG("!r->update.update[0].has_value");
		return;
	}

	if (r->update.update[0].val.type != GNMI_TYPED_VALUE_STRING) {
		GNMI_C_CONNECTOR_DEBUG_LOG(
			"r->update.update[0].val.type != GNMI_TYPED_VALUE_STRING");
		return;
	}

	s.timestamp = r->update.timestamp;
	s.ifname = r->update.prefix.elem[1].key[0].value;

	if (strncmp("Ethernet", s.ifname, sizeof "Ethernet" - 1)) {
		return;
	}

	strncpy(s.status, r->update.update[0].val.v.str,
		sizeof s.status - 1);

	if (cb)
		cb(&s, cb_data);
}

static void poe_link_faultcode_gnmi_cb(const struct gnmi_subscribe_response *r,
				       gnma_poe_link_faultcode_cb cb, void *cb_data)
{
	struct gnma_poe_link_faultcode s = { 0 };

	if (!r) {
		GNMI_C_CONNECTOR_DEBUG_LOG("exit");
		return;
	}

	if (r->update.prefix.elem[1].key_size <= 0) {
		GNMI_C_CONNECTOR_DEBUG_LOG(
				"r->update.prefix.elem[1].key_size <= 0");
		return;
	}

	if (r->update.update_size <= 0) {
		GNMI_C_CONNECTOR_DEBUG_LOG("r->update.update_size <= 0");
		return;
	}

	if (!r->update.update[0].has_value) {
		GNMI_C_CONNECTOR_DEBUG_LOG("!r->update.update[0].has_value");
		return;
	}

	if (r->update.update[0].val.type != GNMI_TYPED_VALUE_STRING) {
		GNMI_C_CONNECTOR_DEBUG_LOG(
			"r->update.update[0].val.type != GNMI_TYPED_VALUE_STRING");
		return;
	}

	s.timestamp = r->update.timestamp;
	s.ifname = r->update.prefix.elem[1].key[0].value;

	if (strncmp("Ethernet", s.ifname, sizeof "Ethernet" - 1)) {
		return;
	}

	strncpy(s.faultcode, r->update.update[0].val.v.str,
		sizeof s.faultcode - 1);

	if (cb)
		cb(&s, cb_data);
}

static void subscribe_gnmi_cb(const struct gnmi_subscribe_response *r,
			      void *data)
{
	struct subscribe_gnmi_ctx *ctx = data;

	if (!r) {
		GNMI_C_CONNECTOR_DEBUG_LOG("exit");
		return;
	}

	if (r->has_sync_response) {
		GNMI_C_CONNECTOR_DEBUG_LOG("r->has_sync_response");
	} else {
		GNMI_C_CONNECTOR_DEBUG_LOG("!r->has_sync_response");
	}

	if (!r->has_update) {
		GNMI_C_CONNECTOR_DEBUG_LOG("!r->has_update");
		return;
	}

	if (r->update.prefix.elem_size <= 1) {
		GNMI_C_CONNECTOR_DEBUG_LOG("r->update.prefix.elem_size <= 1");
		return;
	}

	if (!strcmp(r->update.prefix.elem[1].name, "alarms")) {
		alarm_gnmi_cb(r, ctx->cbs.alarm_cb, ctx->cbs.alarm_data);
	} else if (!strcmp(r->update.prefix.elem[1].name, "interface")) {
		if (r->update.prefix.elem_size <= 2) {
			GNMI_C_CONNECTOR_DEBUG_LOG("r->update.prefix.elem_size <= 2");
			return;
		}

		if (!strcmp(r->update.prefix.elem[2].name, "state")) {
			linkstatus_gnmi_cb(r, ctx->cbs.linkstatus_cb,
					   ctx->cbs.linkstatus_data);
			return;
		}

		if (r->update.update_size <= 0) {
			GNMI_C_CONNECTOR_DEBUG_LOG("r->update.update_size <= 0");
			return;
		}

		if (r->update.update[0].path.elem_size <= 0) {
			GNMI_C_CONNECTOR_DEBUG_LOG("r->update.update[0].path.elem_size <= 0");
			return;
		}

		if (!strcmp(r->update.update[0].path.elem[0].name, "status")) {
			poe_linkstatus_gnmi_cb(r, ctx->cbs.poe_linkstatus_cb,
					       ctx->cbs.poe_linkstatus_data);
		} else if (!strcmp(r->update.update[0].path.elem[0].name, "fault-code")) {
			poe_link_faultcode_gnmi_cb(r, ctx->cbs.poe_link_faultcode_cb,
					 	   ctx->cbs.poe_link_faultcode_data);
		}
	}
}

int gnma_subscribe(void **handle, const struct gnma_subscribe_callbacks *cbs)
{
	struct subscribe_gnmi_ctx *ctx = malloc(sizeof *ctx);
	if (!ctx) {
		return -1;
	}
	*ctx = (struct subscribe_gnmi_ctx){ 0 };

	ctx->cbs = *cbs;
	ctx->subscribe = gnmi_subscribe_create(GNMI_SUBSCRIBE_METHOD_STREAM, 0);
	if (!ctx->subscribe) {
		goto err;
	}

	if (gnmi_subscribe_add(ctx->subscribe,
			       "/openconfig-system:system/alarms/alarm",
			       GNMI_SUBSCRIBE_MODE_ON_CHANGE)) {
		goto err;
	}

	if (gnmi_subscribe_add(
		    ctx->subscribe,
		    "/openconfig-interfaces:interfaces/interface[name=*]/state/oper-status",
		    GNMI_SUBSCRIBE_MODE_ON_CHANGE)) {
		goto err;
	}

	if (gnmi_subscribe_add(
		    ctx->subscribe,
		    "/openconfig-interfaces:interfaces/interface[name=*]/openconfig-if-ethernet:ethernet/openconfig-if-poe:poe/state/openconfig-if-poe-ext:status",
		    GNMI_SUBSCRIBE_MODE_ON_CHANGE)) {
		goto err;
	}

	if (gnmi_subscribe_add(
		    ctx->subscribe,
		    "/openconfig-interfaces:interfaces/interface[name=*]/openconfig-if-ethernet:ethernet/openconfig-if-poe:poe/state/openconfig-if-poe-ext:fault-code",
		    GNMI_SUBSCRIBE_MODE_ON_CHANGE)) {
		goto err;
	}

	if (gnmi_subscribe_start(ctx->subscribe, main_switch, subscribe_gnmi_cb,
				 ctx)) {
		goto err;
	}

	*handle = ctx;
	return 0;

err:
	gnmi_subscribe_destroy(ctx->subscribe);
	free(ctx);
	return -1;
}

void gnma_unsubscribe(void **handle)
{
	if (handle && *handle) {
		struct subscribe_gnmi_ctx *ctx = *handle;
		gnmi_subscribe_destroy(ctx->subscribe);
		free(ctx);
		*handle = 0;
	}
}

int gnma_syslog_cfg_clear(void)
{
	static char path[] =
		"/sonic-system-logging:sonic-system-logging/SYSLOG_SERVER/SYSLOG_SERVER_LIST";

	return gnmi_jsoni_del(main_switch, path, DEFAULT_TIMEOUT_US) ?
			     GNMA_ERR_COMMON :
			     0;
}

int gnma_syslog_cfg_set(struct gnma_syslog_cfg *cfg, int count)
{
	static char path[] =
		"/sonic-system-logging:sonic-system-logging/SYSLOG_SERVER/SYSLOG_SERVER_LIST";
	int i;
	cJSON *root = 0, *val = 0, *arr = 0;
	int ret = GNMA_ERR_COMMON;

	root = cJSON_CreateObject();
	if (!root)
		goto err;

	arr = cJSON_AddArrayToObject(root,
				     "sonic-system-logging:SYSLOG_SERVER_LIST");
	if (!arr)
		goto err;

	for (i = 0; i < count; ++i) {
		struct gnma_syslog_cfg *c = &cfg[i];

		val = cJSON_CreateObject();
		if (!val)
			goto err;

		if (!cJSON_AddItemToArray(arr, val)) {
			cJSON_Delete(val);
			goto err;
		}

		if (!cJSON_AddStringToObject(val, "ipaddress", c->ipaddress)) {
			goto err;
		}

		if (c->remote_port >= 0 &&
		    !cJSON_AddNumberToObject(val, "remote-port",
					     c->remote_port)) {
			goto err;
		}

		if (c->severity &&
		    !cJSON_AddStringToObject(val, "severity", c->severity)) {
			goto err;
		}

		if (c->message_type &&
		    !cJSON_AddStringToObject(val, "message-type",
					     c->message_type)) {
			goto err;
		}

		if (c->src_intf &&
		    !cJSON_AddStringToObject(val, "src_intf", c->src_intf)) {
			goto err;
		}

		if (c->vrf_name &&
		    !cJSON_AddStringToObject(val, "vrf_name", c->vrf_name)) {
			goto err;
		}
	}

	if (!gnmi_json_object_set(main_switch, path, root, DEFAULT_TIMEOUT_US))
		ret = 0;

err:
	cJSON_Delete(root);
	return ret;
}

/* Do I need to fetch whole list ? */
/* Or it is enough to get only interfaces list ? */
/*  Get rif by vlan key ? > Will be easier to handle pervlan cfg. */
/* See: create_vlan_member in sai is separate function. But you can fetch
 * list as vlan_attr. So it is applicapble to create_rif as seprate function.
 * But fetch as switch_attr or vlan_attr */
/* This is not pure rif so name it erif (extended/wIP rif) */
/* Also it is defined with IP addresses (not with MAC) */
int gnma_vlan_erif_attr_pref_list_get(uint16_t vid,
				      uint16_t *list_size,
				      struct gnma_ip_prefix *prefix_list)
{
	cJSON *parsed = NULL, *item_arr, *item, *item_iter;
	struct in_addr in_addr_buf;
	int in_addr_len_buf;
	uint16_t addr_num;
	char *gbuf = NULL;
	int ret, err = 0;
	char gpath[256];
	char *addr_str;

	memset(prefix_list, 0, (*list_size) * sizeof(*prefix_list));

	sprintf(&gpath[0],
		"/openconfig-interfaces:interfaces/interface[name=Vlan%u]/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/addresses",
		vid);
	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &gbuf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		err = GNMA_ERR_COMMON;
		goto out;
	}

	parsed = cJSON_Parse(gbuf);
	if (!parsed) {
		err = GNMA_ERR_COMMON;
		goto out;
	}

	item = cJSON_GetObjectItemCaseSensitive(parsed, "openconfig-if-ip:addresses");
	item_arr = cJSON_GetObjectItemCaseSensitive(item, "address");
	if (!item_arr) {
		*list_size = 0;
		goto out;
	}

	addr_num = 0;
	cJSON_ArrayForEach(item_iter, item_arr) {
		item = cJSON_GetObjectItemCaseSensitive(item_iter, "config");
		addr_str = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(item, "ip"));
		if (!addr_str)
			continue;

		if (inet_pton(AF_INET, addr_str, &in_addr_buf) != 1)
			continue;

		in_addr_len_buf = cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(item, "prefix-length"));
		if (in_addr_len_buf > 32 || in_addr_len_buf < 0)
			continue;

		if (addr_num < *list_size) {
			prefix_list[addr_num].prefix_len = in_addr_len_buf;
			prefix_list[addr_num].ip.v = AF_INET;
			prefix_list[addr_num].ip.u.v4 = in_addr_buf;
		}

		addr_num++;
	}

	if (addr_num > *list_size)
		err = GNMA_ERR_OVERFLOW;

	*list_size = addr_num;

out:
	cJSON_Delete(parsed);
	ZFREE(gbuf);
	return err;
}

/* Problem is that pure (and SAI) rif has no IP. But seems, that
 * openconfig defines this ability as additiona feature (unnumbered).
 * So for now we pass IP address for rif.
 * Also note, that IP address on interface is used mostly not for routing,
 * but for different services, like dhcp, bgp, etc... */
/* create SAI_OBJECT_TYPE_ROUTER_INTERFACE (SAI_ROUTER_INTERFACE_TYPE_VLAN) */
/* "update" gnmi operation is do changes on index of addresses array
 * So, there is more scenarios with delete needed, than expected
 */
/* I need rif create to be able to link from routes? */
/*  I need rif list. As well as vlan list */
/* This will be used  */

/* Request: set 2 addresses
 * if you has 3 addresses: will be updated only 2 from begin/end.
 * One of them will be unchanged.
 * if you has 1 address: will add address and update existed.
 */
/* So, this is mixed set/add function */
int gnma_vlan_erif_attr_pref_update(uint16_t vid, uint16_t list_size,
				   struct gnma_ip_prefix *pref)
{
	cJSON *root = NULL, *obj, *arr;
	int err = GNMA_ERR_COMMON, i;
	char addrbuf[64];
	char gpath[256];

	sprintf(&gpath[0], "/openconfig-interfaces:interfaces/interface[name=Vlan%u]/openconfig-vlan:routed-vlan", vid);

	root = cJSON_CreateObject();
	if (!root)
		goto out;

	/* This is safe to check only last state of obj:
	 * cJSON_AddObjectToObject(NULL) == NULL
	 */
	obj = cJSON_AddObjectToObject(root, "openconfig-interfaces:routed-vlan");
	obj = cJSON_AddObjectToObject(obj, "openconfig-if-ip:ipv4");
	obj = cJSON_AddObjectToObject(obj, "addresses");
	arr = cJSON_AddArrayToObject(obj, "address");
	if (!arr)
		goto out;

	for (i = 0; i < list_size; i++) {
		obj = cJSON_CreateObject();
		if (!cJSON_AddItemToArray(arr, obj)) {
			cJSON_Delete(obj); /* Bcs root is not referenced */
			goto out;
		}

		/* v6 is not supported for now */
		if (pref[i].ip.v != AF_INET)
			goto out;

		if (!inet_ntop(AF_INET, &pref[i].ip.u.v4,
			       &addrbuf[0], sizeof(addrbuf)))
			goto out;

		if (!cJSON_AddStringToObject(obj, "ip", &addrbuf[0]))
			goto out;

		obj = cJSON_AddObjectToObject(obj, "config");

		if (!cJSON_AddStringToObject(obj, "ip", &addrbuf[0]))
			goto out;

		if (!cJSON_AddNumberToObject(obj, "prefix-length",
					     pref[i].prefix_len))
			goto out;
	}

	if (gnmi_json_object_set(main_switch, gpath, root, DEFAULT_TIMEOUT_US))
		goto out;

	err = 0;
out:
	cJSON_Delete(root);
	return err;
}

int gnma_vlan_erif_attr_pref_delete(uint16_t vid, struct gnma_ip_prefix *pref)
{
	char addrbuf[64];
	char gpath[256];

	/* v6 is not supported for now */
	if (pref->ip.v != AF_INET)
		return GNMA_ERR_COMMON;

	if (!inet_ntop(AF_INET, &pref->ip.u.v4, &addrbuf[0], sizeof(addrbuf)))
		return GNMA_ERR_COMMON;

	sprintf(&gpath[0], "/openconfig-interfaces:interfaces/interface[name=Vlan%u]/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/addresses/address[ip=%s]",
		vid, &addrbuf[0]);

	if (gnmi_jsoni_del(main_switch, gpath, DEFAULT_TIMEOUT_US))
		return GNMA_ERR_COMMON;

	return 0;
}

/* This is not pure rif so name it erif (extended/wIP rif) */
/* Also it is defined with IP addresses (not with MAC) */
int gnma_portl2_erif_attr_pref_list_get(struct gnma_port_key *port_key,
					uint16_t *list_size,
					struct gnma_ip_prefix *prefix_list)
{
	cJSON *parsed = NULL, *item_arr, *item, *item_iter;
	struct in_addr in_addr_buf;
	int in_addr_len_buf;
	uint16_t addr_num;
	char *gbuf = NULL;
	int ret, err = 0;
	char gpath[256];
	char *addr_str;

	memset(prefix_list, 0, (*list_size) * sizeof(*prefix_list));

	sprintf(&gpath[0],
		"/openconfig-interfaces:interfaces/interface[name=%s]/subinterfaces/subinterface[index=0]/openconfig-if-ip:ipv4/addresses",
		port_key->name);
	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &gbuf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		err = GNMA_ERR_COMMON;
		goto out;
	}

	parsed = cJSON_Parse(gbuf);
	if (!parsed) {
		err = GNMA_ERR_COMMON;
		goto out;
	}

	item = cJSON_GetObjectItemCaseSensitive(parsed, "openconfig-if-ip:addresses");
	item_arr = cJSON_GetObjectItemCaseSensitive(item, "address");
	addr_num = 0;
	cJSON_ArrayForEach(item_iter, item_arr) {
		item = cJSON_GetObjectItemCaseSensitive(item_iter, "config");
		addr_str = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(item, "ip"));
		if (!addr_str)
			continue;

		if (inet_pton(AF_INET, addr_str, &in_addr_buf) != 1)
			continue;

		in_addr_len_buf = cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(item, "prefix-length"));
		if (in_addr_len_buf > 32 || in_addr_len_buf < 0)
			continue;

		if (addr_num < *list_size) {
			prefix_list[addr_num].prefix_len = in_addr_len_buf;
			prefix_list[addr_num].ip.v = AF_INET;
			prefix_list[addr_num].ip.u.v4 = in_addr_buf;
		}

		addr_num++;
	}

	if (addr_num > *list_size)
		err = GNMA_ERR_OVERFLOW;

	*list_size = addr_num;

out:
	cJSON_Delete(parsed);
	ZFREE(gbuf);
	return err;
}

int gnma_portl2_erif_attr_pref_update(struct gnma_port_key *port_key,
				      uint16_t list_size,
				      struct gnma_ip_prefix *pref)
{
	cJSON *root = NULL, *obj, *arr;
	int err = GNMA_ERR_COMMON, i;
	char addrbuf[64];
	char gpath[256];

	sprintf(&gpath[0], "/openconfig-interfaces:interfaces/interface[name=%s]/subinterfaces/subinterface",
		port_key->name);

	root = cJSON_CreateObject();
	if (!root)
		goto out;

	/* This is safe to check only last state of obj:
	 * cJSON_AddObjectToObject(NULL) == NULL
	 */
	arr = cJSON_AddArrayToObject(root, "openconfig-interfaces:subinterface");
	obj = cJSON_CreateObject();
	if (!cJSON_AddItemToArray(arr, obj)) {
		cJSON_Delete(obj);
		goto out;
	}

	if (!cJSON_AddNumberToObject(obj, "index", 0))
		goto out;

	obj = cJSON_AddObjectToObject(obj, "openconfig-if-ip:ipv4");
	obj = cJSON_AddObjectToObject(obj, "addresses");
	arr = cJSON_AddArrayToObject(obj, "address");
	if (!arr)
		goto out;

	for (i = 0; i < list_size; i++) {
		obj = cJSON_CreateObject();
		if (!cJSON_AddItemToArray(arr, obj)) {
			cJSON_Delete(obj); /* Bcs root is not referenced */
			goto out;
		}

		/* v6 is not supported for now */
		if (pref[i].ip.v != AF_INET)
			goto out;

		if (!inet_ntop(AF_INET, &pref[i].ip.u.v4,
			       &addrbuf[0], sizeof(addrbuf)))
			goto out;

		if (!cJSON_AddStringToObject(obj, "ip", &addrbuf[0]))
			goto out;

		obj = cJSON_AddObjectToObject(obj, "config");

		if (!cJSON_AddStringToObject(obj, "ip", &addrbuf[0]))
			goto out;

		if (!cJSON_AddNumberToObject(obj, "prefix-length",
					     pref[i].prefix_len))
			goto out;
	}

	if (gnmi_json_object_set(main_switch, gpath, root, DEFAULT_TIMEOUT_US))
		goto out;

	err = 0;
out:
	cJSON_Delete(root);
	return err;
}

int gnma_portl2_erif_attr_pref_delete(struct gnma_port_key *port_key,
				      struct gnma_ip_prefix *pref)
{
	char addrbuf[64];
	char gpath[256];

	/* v6 is not supported for now */
	if (pref->ip.v != AF_INET)
		return GNMA_ERR_COMMON;

	if (!inet_ntop(AF_INET, &pref->ip.u.v4, &addrbuf[0], sizeof(addrbuf)))
		return GNMA_ERR_COMMON;

	sprintf(&gpath[0], "/openconfig-interfaces:interfaces/interface[name=%s]/subinterfaces/subinterface[index=0]/openconfig-if-ip:ipv4/addresses/address[ip=%s]",
		port_key->name, &addrbuf[0]);

	if (gnmi_jsoni_del(main_switch, gpath, DEFAULT_TIMEOUT_US))
		return GNMA_ERR_COMMON;

	return 0;
}

int gnma_vlan_dhcp_relay_server_add(uint16_t vid, struct gnma_ip *ip)
{
	cJSON *root = NULL, *val, *arr;
	char addrbuf[INET_ADDRSTRLEN];
	char vlan_name[32];
	char *gpath;
	int ret;

	if (!inet_ntop(AF_INET, &ip->u.v4,
		       &addrbuf[0], sizeof(addrbuf)))
		return GNMA_ERR_COMMON;

	sprintf(&vlan_name[0], "Vlan%u", vid);
	ret = asprintf(&gpath,
		       "/openconfig-relay-agent:relay-agent/dhcp/interfaces/interface[id=%s]/config/helper-address",
			&vlan_name[0]);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	root = cJSON_CreateObject();
	if (!root)
		goto err_root_alloc;

	arr = cJSON_AddArrayToObject(root, "openconfig-relay-agent:helper-address");
	if (!arr) {
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	val = cJSON_CreateString(&addrbuf[0]);
	if (!val) {
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	if (!cJSON_AddItemToArray(arr, val)) {
		cJSON_Delete(val);
		ret = GNMA_ERR_COMMON;
		goto err_val_set;
	}

	if (gnmi_json_object_set(main_switch, gpath, root, DEFAULT_TIMEOUT_US))
		goto err_req_fail;

	ret = 0;

err_req_fail:
err_val_set:
err_val_alloc:
	cJSON_Delete(root);
err_root_alloc:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_vlan_dhcp_relay_server_remove(uint16_t vid, struct gnma_ip *ip)
{
	char addrbuf[INET_ADDRSTRLEN];
	char vlan_name[32];
	char *gpath;
	int ret;

	if (!inet_ntop(AF_INET, &ip->u.v4,
		       &addrbuf[0], sizeof(addrbuf)))
		return GNMA_ERR_COMMON;

	sprintf(&vlan_name[0], "Vlan%u", vid);
	ret = asprintf(&gpath,
		       "/openconfig-relay-agent:relay-agent/dhcp/interfaces/interface[id=%s]/config/helper-address[helper-address=%s]",
		       &vlan_name[0], &addrbuf[0]);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_del(main_switch, gpath, DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_req_fail;
	}

	ret = 0;
err_req_fail:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_vlan_dhcp_relay_server_list_get(uint16_t vid, size_t *list_size,
					 struct gnma_ip *ip_list)
{
	cJSON *parsed_res, *addr_arr, *addr;
	char vlan_name[32];
	uint16_t arr_len;
	char *buf = 0;
	char *gpath;
	int ret;

	sprintf(&vlan_name[0], "Vlan%u", vid);
	ret = asprintf(&gpath,
		       "/openconfig-relay-agent:relay-agent/dhcp/interfaces/interface[id=%s]/config/helper-address",
		       vlan_name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	addr_arr = cJSON_GetObjectItemCaseSensitive(parsed_res, "openconfig-relay-agent:helper-address");
	if (!addr_arr || !cJSON_IsArray(addr_arr)) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_check_arr;
	}

	arr_len = 0;
	cJSON_ArrayForEach(addr, addr_arr)
		arr_len++;

	if (arr_len > *list_size) {
		ret = GNMA_ERR_OVERFLOW;
		*list_size = arr_len;
		goto err_overflow;
	}

	memset(ip_list, 0, sizeof(*ip_list) * (*list_size));

	*list_size = 0;
	cJSON_ArrayForEach(addr, addr_arr) {
		/* Ipv4 only. v6 is stored in another dhcpv6 endpoint. */
		inet_pton(AF_INET, cJSON_GetStringValue(addr),
			  &ip_list[*list_size].u.v4);
		(*list_size)++;
	}

	ret = 0;

err_overflow:
err_gnmi_check_arr:
	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_vlan_dhcp_relay_ciruit_id_set(uint16_t vid,
				       gnma_dhcp_relay_circuit_id_t id)
{
	/* "/openconfig-relay-agent:relay-agent/dhcp/interfaces/interface[id=%s]/agent-information-option/config/circuit-id" */
	/* json_ietf_val: "{\"openconfig-relay-agent:circuit-id\":\"%p\"}" */
	const char *circ_id;
	cJSON *root = NULL;
	char vlan_name[32];
	char *gpath;
	int ret;

	switch(id) {
		case GNMA_DHCP_RELAY_CIRCUIT_ID_H_P:
			circ_id = "%h:%p";
			break;
		case GNMA_DHCP_RELAY_CIRCUIT_ID_I:
			circ_id = "%i";
			break;
		case GNMA_DHCP_RELAY_CIRCUIT_ID_P:
			circ_id = "%p";
			break;
		default:
			return GNMA_ERR_COMMON;
	}

	sprintf(&vlan_name[0], "Vlan%u", vid);
	ret = asprintf(&gpath,
		       "/openconfig-relay-agent:relay-agent/dhcp/interfaces/interface[id=%s]/agent-information-option/config/circuit-id",
			&vlan_name[0]);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	root = cJSON_CreateObject();
	if (!root)
		goto err_root_alloc;

	if (!cJSON_AddStringToObject(root, "openconfig-relay-agent:circuit-id", circ_id)) {
		ret = GNMA_ERR_COMMON;
		goto err_val_set;
	}

	if (gnmi_json_object_set(main_switch, gpath, root, DEFAULT_TIMEOUT_US))
		goto err_req_fail;

	ret = 0;

err_req_fail:
err_val_set:
	cJSON_Delete(root);
err_root_alloc:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_vlan_dhcp_relay_ciruit_id_get(uint16_t vid,
				       gnma_dhcp_relay_circuit_id_t *id)
{
	cJSON *parsed_res, *circ_id;
	const char *circ_id_str;
	char vlan_name[32];
	char *buf = 0;
	char *gpath;
	int ret;

	sprintf(&vlan_name[0], "Vlan%u", vid);
	ret = asprintf(&gpath,
		       "/openconfig-relay-agent:relay-agent/dhcp/interfaces/interface[id=%s]/agent-information-option/config/circuit-id",
		       vlan_name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	circ_id = cJSON_GetObjectItemCaseSensitive(parsed_res, "openconfig-relay-agent:circuit-id");
	if (!circ_id || !cJSON_IsString(circ_id)) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_check_val;
	}

	circ_id_str = cJSON_GetStringValue(circ_id);
	if (!circ_id_str) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_check_str;
	}

	if (!strcmp(circ_id_str, "%h:%p"))
		*id = GNMA_DHCP_RELAY_CIRCUIT_ID_H_P;
	else if (!strcmp(circ_id_str, "%u"))
		*id = GNMA_DHCP_RELAY_CIRCUIT_ID_I;
	else if (!strcmp(circ_id_str, "%p"))
		*id = GNMA_DHCP_RELAY_CIRCUIT_ID_P;
	else {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_check_str;
	}

	ret = 0;

err_gnmi_check_str:
err_gnmi_check_val:
	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_vlan_dhcp_relay_policy_action_set(uint16_t vid,
					   gnma_dhcp_relay_policy_action_type_t act)
{
	/* "/openconfig-relay-agent:relay-agent/dhcp/interfaces/interface[id=%s]/config/openconfig-relay-agent-ext:policy-action" */
	/* "{"openconfig-relay-agent-ext:policy-action":"REPLACE"}" */

	const char *policy_action;
	cJSON *root = NULL;
	char vlan_name[32];
	char *gpath;
	int ret;

	switch(act) {
		case GNMA_DHCP_RELAY_POLICY_ACTION_DISCARD:
			policy_action = "DISCARD";
			break;
		case GNMA_DHCP_RELAY_POLICY_ACTION_APPEND:
			policy_action = "APPEND";
			break;
		case GNMA_DHCP_RELAY_POLICY_ACTION_REPLACE:
			policy_action = "REPLACE";
			break;
		default:
			return GNMA_ERR_COMMON;
	}

	sprintf(&vlan_name[0], "Vlan%u", vid);
	ret = asprintf(&gpath,
		       "/openconfig-relay-agent:relay-agent/dhcp/interfaces/interface[id=%s]/config/openconfig-relay-agent-ext:policy-action",
			&vlan_name[0]);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	root = cJSON_CreateObject();
	if (!root)
		goto err_root_alloc;

	if (!cJSON_AddStringToObject(root,
				     "openconfig-relay-agent-ext:policy-action", policy_action)) {
		ret = GNMA_ERR_COMMON;
		goto err_val_set;
	}

	if (gnmi_json_object_set(main_switch, gpath, root, DEFAULT_TIMEOUT_US))
		goto err_req_fail;

	ret = 0;

err_req_fail:
err_val_set:
	cJSON_Delete(root);
err_root_alloc:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_vlan_dhcp_relay_policy_action_get(uint16_t vid,
					   gnma_dhcp_relay_policy_action_type_t *act)
{
	cJSON *parsed_res, *policy_act;
	const char *policy_act_str;
	char vlan_name[32];
	char *buf = 0;
	char *gpath;
	int ret;

	sprintf(&vlan_name[0], "Vlan%u", vid);
	ret = asprintf(&gpath,
		       "/openconfig-relay-agent:relay-agent/dhcp/interfaces/interface[id=%s]/config/openconfig-relay-agent-ext:policy-action",
		       vlan_name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	policy_act = cJSON_GetObjectItemCaseSensitive(parsed_res, "openconfig-relay-agent-ext:policy-action");
	if (!policy_act || !cJSON_IsString(policy_act)) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_check_val;
	}

	policy_act_str = cJSON_GetStringValue(policy_act);
	if (!policy_act_str) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_check_str;
	}

	if (!strcmp(policy_act_str, "DISCARD"))
		*act = GNMA_DHCP_RELAY_POLICY_ACTION_DISCARD;
	else if (!strcmp(policy_act_str, "APPEND"))
		*act = GNMA_DHCP_RELAY_POLICY_ACTION_APPEND;
	else if (!strcmp(policy_act_str, "REPLACE"))
		*act = GNMA_DHCP_RELAY_POLICY_ACTION_REPLACE;
	else {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_check_str;
	}

	ret = 0;

err_gnmi_check_str:
err_gnmi_check_val:
	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_vlan_dhcp_relay_max_hop_cnt_set(uint16_t vid, uint8_t max_hop_cnt)
{
	/* "/openconfig-relay-agent:relay-agent/dhcp/interfaces/interface[id=%s]/config/openconfig-relay-agent-ext:max-hop-count" */
	/* "{"openconfig-relay-agent-ext:max-hop-count":10}" */
	cJSON *root = NULL;
	char vlan_name[32];
	char *gpath;
	int ret;

	sprintf(&vlan_name[0], "Vlan%u", vid);
	ret = asprintf(&gpath,
		       "/openconfig-relay-agent:relay-agent/dhcp/interfaces/interface[id=%s]/config/openconfig-relay-agent-ext:max-hop-count",
			&vlan_name[0]);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	root = cJSON_CreateObject();
	if (!root)
		goto err_root_alloc;

	if (!cJSON_AddNumberToObject(root,
				     "openconfig-relay-agent-ext:max-hop-count", max_hop_cnt)) {
		ret = GNMA_ERR_COMMON;
		goto err_val_set;
	}

	if (gnmi_json_object_set(main_switch, gpath, root, DEFAULT_TIMEOUT_US))
		goto err_req_fail;

	ret = 0;

err_req_fail:
err_val_set:
	cJSON_Delete(root);
err_root_alloc:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_vlan_dhcp_relay_max_hop_cnt_get(uint16_t vid, uint8_t *max_hop_cnt)
{
	cJSON *parsed_res, *hop_cnt;
	char vlan_name[32];
	char *buf = 0;
	char *gpath;
	int ret;

	sprintf(&vlan_name[0], "Vlan%u", vid);
	ret = asprintf(&gpath,
		       "/openconfig-relay-agent:relay-agent/dhcp/interfaces/interface[id=%s]/config/openconfig-relay-agent-ext:max-hop-count",
		       vlan_name);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	hop_cnt = cJSON_GetObjectItemCaseSensitive(parsed_res, "openconfig-relay-agent-ext:max-hop-count");
	if (!hop_cnt || !cJSON_IsNumber(hop_cnt)) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_check_val;
	}

	*max_hop_cnt = cJSON_GetNumberValue(hop_cnt);

	ret = 0;

err_gnmi_check_val:
	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}


/* sai_create_route_entry_fn
 * sai_remove_route_entry_fn
 * sai_set_route_entry_attribute_fn
 * sai_get_route_entry_attribute_fn
 *
 * sai_bulk_create_route_entry_fn
 * sai_bulk_remove_route_entry_fn
 * sai_bulk_set_route_entry_attribute_fn
 * sai_bulk_get_route_entry_attribute_fn
 * ---------------------------------------
 * SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID
 * SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION
 */
int gnma_route_create(uint16_t vr_id /* 0 - default */,
		      struct gnma_ip_prefix *prefix,
		      struct gnma_route_attrs *attr)
{
	char *gpath = "/sonic-static-route:sonic-static-route/";
	int err = GNMA_ERR_COMMON;
	cJSON *root, *obj, *arr;
	char buf[64];

	if (prefix->ip.v != AF_INET)
		goto out; /* IPv6 not supported */

	/* This is safe to check only last state of obj:
	 * cJSON_AddObjectToObject(NULL) == NULL
	 */
	root = cJSON_CreateObject();
	obj = cJSON_AddObjectToObject(root, "sonic-static-route:sonic-static-route");
	obj = cJSON_AddObjectToObject(obj, "STATIC_ROUTE");
	arr = cJSON_AddArrayToObject(obj, "STATIC_ROUTE_LIST");
	if (!arr)
		goto out;

	obj = cJSON_CreateObject();
	if (!cJSON_AddItemToArray(arr, obj)) {
		cJSON_Delete(obj); /* Bcs root is not referenced */
		goto out;
	}

	memset(&buf[0], 0, sizeof(buf));
	if (inet_ntop(AF_INET, &prefix->ip.u.v4,
		      &buf[0], sizeof(buf)))
		sprintf(&buf[strlen(&buf[0])], "/%d",
			prefix->prefix_len);
	else
		goto out;

	if (!cJSON_AddStringToObject(obj, "prefix", &buf[0]))
		goto out;

	/* TODO vrf */
	if (vr_id || !cJSON_AddStringToObject(obj, "vrf-name", "default"))
		goto out;

	switch (attr->type) {
	case GNMA_ROUTE_TYPE_BLACKHOLE:
		if (!cJSON_AddStringToObject(obj, "blackhole", "true,false"))
			goto out;
		break;
	case GNMA_ROUTE_TYPE_CONNECTED:
		memset(&buf[0], 0, sizeof(buf));
		sprintf(&buf[0], "Vlan%u", attr->connected.vid);
		if (!cJSON_AddStringToObject(obj, "ifname", &buf[0]))
			goto out;
		break;
	case GNMA_ROUTE_TYPE_NEXTHOP:
		memset(&buf[0], 0, sizeof(buf));
		sprintf(&buf[0], "Vlan%u", attr->nexthop.vid);
		if (!cJSON_AddStringToObject(obj, "ifname", &buf[0]))
			goto out;

		memset(&buf[0], 0, sizeof(buf));
		if (!inet_ntop(AF_INET, &attr->nexthop.gw, &buf[0], sizeof(buf)))
			goto out;

		if (!cJSON_AddStringToObject(obj, "nexthop", &buf[0]))
			goto out;
		break;
	default:
		goto out;
	}

	if (gnmi_json_object_set(main_switch, gpath, root, DEFAULT_TIMEOUT_US))
		goto out;

	err = 0;
out:
	cJSON_Delete(root);
	return err;
}

int gnma_route_remove(uint16_t vr_id /* 0 - default */,
		      struct gnma_ip_prefix *prefix /* key */)
{
	char gpath[256], addrbuf[64];
	int err = GNMA_ERR_COMMON;

	if (prefix->ip.v != AF_INET)
		goto out; /* IPv6 not supported */

	if (vr_id)
		goto out;

	memset(&addrbuf[0], 0, sizeof(addrbuf));
	if (inet_ntop(AF_INET, &prefix->ip.u.v4,
		      &addrbuf[0], sizeof(addrbuf)))
		sprintf(&addrbuf[strlen(&addrbuf[0])], "/%d",
			prefix->prefix_len);
	else
		goto out;

	/* 100 - 150 bytes */
	sprintf(&gpath[0],
		"/sonic-static-route:sonic-static-route/STATIC_ROUTE/STATIC_ROUTE_LIST[prefix=%s][vrf-name=default]",
		&addrbuf[0]);

	if (gnmi_jsoni_del(main_switch, gpath, DEFAULT_TIMEOUT_US))
		goto out;

	err = 0;
out:
	return err;
}

/* SAI ? Mix route_list + route_attr */
int gnma_route_list_get(uint16_t vr_id, uint32_t *list_size,
			struct gnma_ip_prefix *prefix_list,
			struct gnma_route_attrs *attr_list)
{
	char *gpath = "/sonic-static-route:sonic-static-route/STATIC_ROUTE/STATIC_ROUTE_LIST";
	cJSON *root, *obj, *arr, *arr_iter;
	struct gnma_route_attrs attrs;
	struct gnma_ip_prefix prefix;
	int ret = GNMA_ERR_COMMON;
	char *buf = NULL;
	uint32_t cnt;

	/* IPv6 not supported. VRF not supported */
	if (vr_id)
		goto out;

	if (gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				 DEFAULT_TIMEOUT_US))
		goto out;

	/* "{\"sonic-static-route:STATIC_ROUTE_LIST\":[{\"blackhole\":\"true\",\"prefix\":\"5.5.5.0/24\",\"vrf-name\":\"default\"}]}" */
	root = cJSON_Parse(buf);
	ZFREE(buf);
	arr = cJSON_GetObjectItemCaseSensitive(root, "sonic-static-route:STATIC_ROUTE_LIST");

	cnt = 0;
	cJSON_ArrayForEach(arr_iter, arr) {
		obj = cJSON_GetObjectItemCaseSensitive(arr_iter, "vrf-name");
		buf = cJSON_GetStringValue(obj);
		if (buf && strcmp("default", buf))
			continue;

		/* Parse prefix */
		obj = cJSON_GetObjectItemCaseSensitive(arr_iter, "prefix");
		buf = cJSON_GetStringValue(obj);
		if (!buf)
			continue;

		prefix.ip.v = AF_INET;
		prefix.prefix_len = inet_net_pton(AF_INET, buf, &prefix.ip.u.v4,
						  sizeof(prefix.ip.u.v4));
		if (prefix.prefix_len == -1)
			continue;

		/* Parse attr */
		if (cJSON_GetObjectItemCaseSensitive(arr_iter, "blackhole")) /* For now only blackhole supported */
			attrs.type = GNMA_ROUTE_TYPE_BLACKHOLE;
		else
			continue;

		/* Fill list */
		if (cnt >= *list_size)
			goto next;

		if (prefix_list)
			prefix_list[cnt] = prefix;

		if (attr_list)
			attr_list[cnt] = attrs;

next:
		cnt++;
	}

	ret = cnt > *list_size ? GNMA_ERR_OVERFLOW : 0;
	*list_size = cnt;
out:
	cJSON_Delete(root);
	return ret;
}

/* This config related to control plane. So, have no analog in SAI */
/* Data plane STP config is only perport state. */
int gnma_stp_mode_set(gnma_stp_mode_t mode, struct gnma_stp_attr *attr)
{
	cJSON *root = NULL, *obj, *arr;
	int err = GNMA_ERR_COMMON, ret;
	char gpath[256];

	/* delete global config since you cannot change the stp mode otherwise */
	gnmi_jsoni_del(main_switch,
		       "/sonic-spanning-tree:sonic-spanning-tree/STP/STP_LIST[keyleaf=GLOBAL]",
		       DEFAULT_TIMEOUT_US);
	if (mode == GNMA_STP_MODE_NONE) {
		err = 0;
		goto out;
	}

	if (!attr)
		goto out; /* For MODE_NONE is not used */

	sprintf(&gpath[0], "/sonic-spanning-tree:sonic-spanning-tree/STP/STP_LIST");

	root = cJSON_CreateObject();
	if (!root)
		goto out;

	arr = cJSON_AddArrayToObject(root, "sonic-spanning-tree:STP_LIST");
	if (!arr)
		goto out;

	obj = cJSON_CreateObject();
	if (!cJSON_AddItemToArray(arr, obj)) {
		cJSON_Delete(obj); /* Bcs root is not referenced */
		goto out;
	}

	ret = 1;
	ret &= !!cJSON_AddNumberToObject(obj, "priority", attr->priority);
	ret &= !!cJSON_AddStringToObject(obj, "keyleaf", "GLOBAL");
	ret &= !!cJSON_AddBoolToObject(obj, "bpdu_filter", false);
	switch (mode) {
	case GNMA_STP_MODE_PVST:
		ret &= !!cJSON_AddStringToObject(obj, "mode", "pvst");
		ret &= !!cJSON_AddBoolToObject(obj, "portfast", false);
		ret &= !!cJSON_AddNumberToObject(obj, "rootguard_timeout", 30);
		break;
	case GNMA_STP_MODE_RPVST:
		ret &= !!cJSON_AddStringToObject(obj, "mode", "rpvst");
		ret &= !!cJSON_AddBoolToObject(obj, "loop_guard", false);
		ret &= !!cJSON_AddNumberToObject(obj, "rootguard_timeout", 30);
		break;
	case GNMA_STP_MODE_MST:
		ret &= !!cJSON_AddStringToObject(obj, "mode", "mst");
		ret &= !!cJSON_AddBoolToObject(obj, "loop_guard", false);
		break;
	default:
		goto out;
	}
	if (!ret)
		goto out;

	if (gnmi_json_object_set(main_switch, gpath, root, DEFAULT_TIMEOUT_US))
		goto out;

	err = 0;
out:
	cJSON_Delete(root);
	return err;
}

int gnma_stp_mode_get(gnma_stp_mode_t *mode, struct gnma_stp_attr *attr)
{
	char *gpath = "/sonic-spanning-tree:sonic-spanning-tree";
	int err = GNMA_ERR_COMMON;
	cJSON *root = NULL, *obj;
	char *buf;

	if (gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				 DEFAULT_TIMEOUT_US))
		goto out;

	root = cJSON_Parse(buf);
	ZFREE(buf);

	obj = cJSON_GetObjectItemCaseSensitive(root, "sonic-spanning-tree:sonic-spanning-tree");
	obj = cJSON_GetObjectItemCaseSensitive(obj, "STP");
	obj = cJSON_GetObjectItemCaseSensitive(obj, "STP_LIST");
	obj = cJSON_GetArrayItem(obj, 0);

	buf = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(obj, "mode"));
	if (!buf) {
		*mode = GNMA_STP_MODE_NONE;
		if (attr)
			memset(attr, 0, sizeof(*attr));
	} else if (!strcmp(buf, "rpvst")) {
		*mode = GNMA_STP_MODE_RPVST;
		if (attr) {
			memset(attr, 0, sizeof(*attr));
			attr->forward_delay =
				cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(obj, "forward_delay"));
			attr->hello_time =
				cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(obj, "hello_time"));
			attr->max_age =
				cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(obj, "max_age"));
			attr->priority =
				cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(obj, "priority"));
		}
	} else if (!strcmp(buf, "pvst")) {
		*mode = GNMA_STP_MODE_PVST;
		if (attr) {
			memset(attr, 0, sizeof(*attr));
			attr->forward_delay =
				cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(obj, "forward_delay"));
			attr->hello_time =
				cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(obj, "hello_time"));
			attr->max_age =
				cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(obj, "max_age"));
			attr->priority =
				cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(obj, "priority"));
		}
	} else {
		goto out;
	}

	err = 0;
out:
	cJSON_Delete(root);
	return err;
}

/* This is control plane config instead os SAI's dataplane STP objcst
 * NOTE: this cfg should be reapplied on each configuration changing of global
 * STP mode. This may looks like overhead. But keep in mind two things:
 *  1. Disabling path faster with implicit port cfg reset instead of explicit
 *  2. We own full device config state. So feel free to assum that if STP
 *     enabled - ports already configured.
 */
int gnma_stp_port_set(uint32_t list_size, struct gnma_stp_port_cfg *ports_list)
{
	cJSON *root = NULL, *obj, *arr;
	int err = GNMA_ERR_COMMON, ret;
	struct gnma_stp_port_cfg *c;
	char gpath[256];
	uint32_t i;

	sprintf(&gpath[0], "/sonic-spanning-tree:sonic-spanning-tree/STP_PORT");

	root = cJSON_CreateObject();
	if (!root)
		goto out;

	obj = cJSON_AddObjectToObject(root, "sonic-spanning-tree:STP_PORT");
	arr = cJSON_AddArrayToObject(obj, "STP_PORT_LIST");
	if (!arr)
		goto out;

	for (i = 0; i < list_size; i++) {
		c = &ports_list[i];
		obj = cJSON_CreateObject();
		if (!cJSON_AddItemToArray(arr, obj)) {
			cJSON_Delete(obj); /* Bcs root is not referenced */
			goto out;
		}

		ret = 1;
		ret &= !!cJSON_AddStringToObject(obj, "ifname", &c->port.name[0]);
		ret &= !!cJSON_AddBoolToObject(obj, "enabled", c->enabled);
		if (!ret)
			goto out;
	}

	if (gnmi_json_object_set(main_switch, gpath, root, DEFAULT_TIMEOUT_US))
		goto out;

	err = 0;
out:
	cJSON_Delete(root);
	return err;
}

/* Similar to gnma_stp_port_set but set default parameters for all ports */
int gnma_stp_ports_enable(uint32_t list_size, struct gnma_port_key *ports_list)
{
	cJSON *root = NULL, *obj, *arr;
	int err = GNMA_ERR_COMMON, ret;
	char gpath[256];
	uint32_t i;

	sprintf(&gpath[0], "/sonic-spanning-tree:sonic-spanning-tree/STP_PORT");

	root = cJSON_CreateObject();
	if (!root)
		goto out;

	obj = cJSON_AddObjectToObject(root, "sonic-spanning-tree:STP_PORT");
	arr = cJSON_AddArrayToObject(obj, "STP_PORT_LIST");
	if (!arr)
		goto out;

	for (i = 0; i < list_size; i++) {
		obj = cJSON_CreateObject();
		if (!cJSON_AddItemToArray(arr, obj)) {
			cJSON_Delete(obj); /* Bcs root is not referenced */
			goto out;
		}

		ret = 1;
		ret &= !!cJSON_AddStringToObject(obj, "ifname",
						 &ports_list[i].name[0]);
		ret &= !!cJSON_AddBoolToObject(obj, "enabled", true);
		if (!ret)
			goto out;
	}

	if (gnmi_json_object_set(main_switch, gpath, root, DEFAULT_TIMEOUT_US))
		goto out;

	err = 0;
out:
	cJSON_Delete(root);
	return err;
}

int gnma_stp_instance_set(uint16_t instance, uint16_t prio,
			  uint32_t list_size, uint16_t *vid_list)
{
	cJSON *root = NULL, *obj, *arr;
	int err = GNMA_ERR_COMMON, ret;
	char gpath[256], vidstr[64];
	uint32_t i;

	sprintf(&gpath[0], "/sonic-spanning-tree:sonic-spanning-tree/STP_MST_INST");

	root = cJSON_CreateObject();
	if (!root)
		goto out;

	obj = cJSON_AddObjectToObject(root, "sonic-spanning-tree:STP_MST_INST");
	arr = cJSON_AddArrayToObject(obj, "STP_MST_INST_LIST");
	if (!arr)
		goto out;

	obj = cJSON_CreateObject();
	if (!cJSON_AddItemToArray(arr, obj)) {
		cJSON_Delete(obj); /* Bcs root is not referenced */
		goto out;
	}

	ret = 1;
	ret &= !!cJSON_AddNumberToObject(obj, "instance", instance);
	ret &= !!cJSON_AddNumberToObject(obj, "bridge_priority", prio);
	if (!ret)
		goto out;

	arr = cJSON_AddArrayToObject(obj, "vlan");
	if (!arr)
		goto out;

	for (i = 0; i < list_size; i++) {
		sprintf(&vidstr[0], "%u", vid_list[i]);
		obj = cJSON_CreateString(&vidstr[0]);
		if (!cJSON_AddItemToArray(arr, obj)) {
			cJSON_Delete(obj); /* Bcs root is not referenced */
			goto out;
		}
	}

	if (gnmi_json_object_set(main_switch, gpath, root, DEFAULT_TIMEOUT_US))
		goto out;

	err = 0;
out:
	cJSON_Delete(root);
	return err;

}

int gnma_stp_vids_set(uint32_t list_size, uint16_t *vid_list, bool enable)
{
	cJSON *root = NULL, *obj, *arr;
	int err = GNMA_ERR_COMMON, ret;
	char gpath[256], vidstr[64];
	uint32_t i;

	sprintf(&gpath[0], "/sonic-spanning-tree:sonic-spanning-tree/STP_VLAN");

	root = cJSON_CreateObject();
	if (!root)
		goto out;

	obj = cJSON_AddObjectToObject(root, "sonic-spanning-tree:STP_VLAN");
	arr = cJSON_AddArrayToObject(obj, "STP_VLAN_LIST");
	if (!arr)
		goto out;

	for (i = 0; i < list_size; i++) {
		obj = cJSON_CreateObject();
		if (!cJSON_AddItemToArray(arr, obj)) {
			cJSON_Delete(obj); /* Bcs root is not referenced */
			goto out;
		}

		ret = 1;
		sprintf(&vidstr[0], "Vlan%u", vid_list[i]);
		ret &= !!cJSON_AddStringToObject(obj, "name", &vidstr[0]);
		ret &= !!cJSON_AddBoolToObject(obj, "enabled", enable);
		if (!ret)
			goto out;
	}

	if (gnmi_json_object_set(main_switch, gpath, root, DEFAULT_TIMEOUT_US))
		goto out;

	err = 0;
out:
	cJSON_Delete(root);
	return err;
}

int gnma_stp_vids_set_all(bool enable)
{
	BITMAP_DECLARE(vlans, GNMA_MAX_VLANS);
	uint16_t vid_list[GNMA_MAX_VLANS];
	size_t i, num_vlans = 0;
	int ret;

	ret = gnma_vlan_list_get(vlans);
	if (ret)
		return ret;

	BITMAP_FOR_EACH_BIT_SET(i, vlans, GNMA_MAX_VLANS) {
		vid_list[num_vlans] = i;
		num_vlans++;
	}

	return gnma_stp_vids_set(num_vlans, vid_list, enable);
}

static int gnma_stp_vid_enable(uint16_t vid, struct gnma_stp_attr *attr)
{
	cJSON *root = NULL, *obj, *arr;
	int err = GNMA_ERR_COMMON, ret;
	char gpath[256], vidstr[64];

	sprintf(&gpath[0], "/sonic-spanning-tree:sonic-spanning-tree/STP_VLAN");

	root = cJSON_CreateObject();
	if (!root)
		goto out;

	obj = cJSON_AddObjectToObject(root, "sonic-spanning-tree:STP_VLAN");
	arr = cJSON_AddArrayToObject(obj, "STP_VLAN_LIST");
	if (!arr)
		goto out;

	obj = cJSON_CreateObject();
	if (!cJSON_AddItemToArray(arr, obj)) {
		cJSON_Delete(obj); /* Bcs root is not referenced */
		goto out;
	}

	ret = 1;
	sprintf(&vidstr[0], "Vlan%u", vid);
	ret &= !!cJSON_AddStringToObject(obj, "name", &vidstr[0]);
	ret &= !!cJSON_AddBoolToObject(obj, "enabled", true);
	ret &= !!cJSON_AddNumberToObject(obj, "priority", attr->priority);
	ret &= !!cJSON_AddNumberToObject(obj, "forward_delay", attr->forward_delay);
	ret &= !!cJSON_AddNumberToObject(obj, "hello_time", attr->hello_time);
	ret &= !!cJSON_AddNumberToObject(obj, "max_age", attr->max_age);
	if (!ret)
		goto out;

	if (gnmi_json_object_set(main_switch, gpath, root, DEFAULT_TIMEOUT_US))
		goto out;

	err = 0;
out:
	cJSON_Delete(root);
	return err;
}

static int gnma_stp_vid_disable(uint16_t vid)
{
	gnma_stp_vids_set(1, &vid, false);
	return 0;
}

int gnma_stp_vid_set(uint16_t vid, struct gnma_stp_attr *attr)
{
	if (attr->enabled)
		return gnma_stp_vid_enable(vid, attr);
	else
		return gnma_stp_vid_disable(vid);
}

int gnma_stp_vid_bulk_get(struct gnma_stp_attr *list, ssize_t size)
{
	char *gpath = "/sonic-spanning-tree:sonic-spanning-tree/STP_VLAN/STP_VLAN_LIST";
	cJSON *root = NULL, *obj, *arr, *iter;
	int err = GNMA_ERR_COMMON, ret;
	unsigned int parsed_vid;
	char *buf;

	memset(list, 0, size * sizeof(*list));

	if (gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				 DEFAULT_TIMEOUT_US))
		goto out;

	root = cJSON_Parse(buf);
	ZFREE(buf);

	arr = cJSON_GetObjectItemCaseSensitive(root, "sonic-spanning-tree:STP_VLAN_LIST");
	cJSON_ArrayForEach(iter, arr) {
		obj = cJSON_GetObjectItemCaseSensitive(iter, "name");
		buf = cJSON_GetStringValue(obj);
		ret = sscanf(buf, "Vlan%u", &parsed_vid);
		if (ret == EOF || parsed_vid >= size)
			goto out;

		list[parsed_vid].enabled = true;

		obj = cJSON_GetObjectItemCaseSensitive(iter, "priority");
		list[parsed_vid].priority = (uint16_t)cJSON_GetNumberValue(obj);
	}

	err = 0;
out:
	cJSON_Delete(root);
	return err;
}

int gnma_ieee8021x_system_auth_control_set(bool is_enabled)
{
	cJSON *root;
	cJSON *val;
	char *path;
	int ret;

	ret = asprintf(&path,
		       "/openconfig-hostapd:hostapd/hostapd-global-config/config/dot1x-system-auth-control");
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	root = cJSON_CreateObject();
	if (!root) {
		ret = GNMA_ERR_COMMON;
		goto err_root_alloc;
	}

	val = cJSON_AddBoolToObject(root, "openconfig-hostapd:dot1x-system-auth-control",
				    is_enabled);
	if (!val) {
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	ret = gnmi_json_object_set(main_switch, path, root, DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_req_fail;
	}

	ret = 0;
err_req_fail:
err_val_alloc:
	cJSON_Delete(root);
err_root_alloc:
	free(path);
err_path_alloc:
	return ret;
}

int gnma_ieee8021x_system_auth_control_get(bool *is_enabled)
{
	cJSON *parsed_res, *auth_ctrl;
	char *buf = NULL;
	char *gpath;
	int ret;

	ret = asprintf(&gpath,
		       "/openconfig-hostapd:hostapd/hostapd-global-config/config/dot1x-system-auth-control");
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	auth_ctrl = cJSON_GetObjectItemCaseSensitive(parsed_res, "openconfig-hostapd:dot1x-system-auth-control");
	*is_enabled = cJSON_IsTrue(auth_ctrl);

	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_ieee8021x_system_auth_clients_get(char *buf, size_t buf_size)
{
	return gnmi_jsoni_get(
		main_switch,
		"/openconfig-authmgr:authmgr/authmgr-authenticated-clients/",
		buf, buf_size, DEFAULT_TIMEOUT_US);
}

int gnma_ieee8021x_das_bounce_port_ignore_set(bool bounce_port_ignore)
{
	char *gpath = "/openconfig-das:das/das-global-config-table/config/ignore-bounce-port";
	int ret = GNMA_ERR_COMMON;
	cJSON *root;

	if (!(root = cJSON_CreateObject()))
		goto err_alloc;

	if (!cJSON_AddBoolToObject(root, "openconfig-das:ignore-bounce-port",
				   bounce_port_ignore))
		goto err_json;

	if (gnmi_json_object_set(main_switch, gpath, root,
				 DEFAULT_TIMEOUT_US))
		goto err_json;

	ret = GNMA_OK;
err_json:
	cJSON_Delete(root);
err_alloc:
	return ret;
}

int gnma_ieee8021x_das_bounce_port_ignore_get(bool *bounce_port_ignore)
{
	cJSON *parsed_res, *bounce_port;
	char *buf = NULL;
	char *gpath;
	int ret;

	ret = asprintf(&gpath,
		       "/openconfig-das:das/das-global-config-table/config/ignore-bounce-port");
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	bounce_port = cJSON_GetObjectItemCaseSensitive(parsed_res, "openconfig-das:ignore-bounce-port");
	*bounce_port_ignore = cJSON_IsTrue(bounce_port);

	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_ieee8021x_das_disable_port_ignore_set(bool disable_port_ignore)
{
	char *gpath = "/openconfig-das:das/das-global-config-table/config/ignore-disable-port";
	int ret = GNMA_ERR_COMMON;
	cJSON *root;

	if (!(root = cJSON_CreateObject()))
		goto err_alloc;

	if (!cJSON_AddBoolToObject(root, "openconfig-das:ignore-disable-port",
				   disable_port_ignore))
		goto err_json;

	if (gnmi_json_object_set(main_switch, gpath, root,
				 DEFAULT_TIMEOUT_US))
		goto err_json;

	ret = GNMA_OK;
err_json:
	cJSON_Delete(root);
err_alloc:
	return ret;
}

int gnma_ieee8021x_das_disable_port_ignore_get(bool *disable_port_ignore)
{
	cJSON *parsed_res, *disable_port;
	char *buf = NULL;
	char *gpath;
	int ret;

	ret = asprintf(&gpath,
		       "/openconfig-das:das/das-global-config-table/config/ignore-disable-port");
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	disable_port = cJSON_GetObjectItemCaseSensitive(parsed_res, "openconfig-das:ignore-disable-port");
	*disable_port_ignore = cJSON_IsTrue(disable_port);

	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_ieee8021x_das_ignore_server_key_set(bool ignore_server_key)
{
	char *gpath = "/openconfig-das:das/das-global-config-table/config/ignore-server-key";
	int ret = GNMA_ERR_COMMON;
	cJSON *root;

	if (!(root = cJSON_CreateObject()))
		goto err_alloc;

	if (!cJSON_AddBoolToObject(root, "openconfig-das:ignore-server-key",
				   ignore_server_key))
		goto err_json;

	if (gnmi_json_object_set(main_switch, gpath, root,
				 DEFAULT_TIMEOUT_US))
		goto err_json;

	ret = GNMA_OK;
err_json:
	cJSON_Delete(root);
err_alloc:
	return ret;
}

int gnma_ieee8021x_das_ignore_server_key_get(bool *ignore_server_key)
{
	cJSON *parsed_res, *server_key;
	char *buf = NULL;
	char *gpath;
	int ret;

	ret = asprintf(&gpath,
		       "/openconfig-das:das/das-global-config-table/config/ignore-server-key");
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	server_key = cJSON_GetObjectItemCaseSensitive(parsed_res, "openconfig-das:ignore-server-key");
	*ignore_server_key = cJSON_IsTrue(server_key);

	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_ieee8021x_das_ignore_session_key_set(bool ignore_session_key)
{
	char *gpath = "/openconfig-das:das/das-global-config-table/config/ignore-session-key";
	int ret = GNMA_ERR_COMMON;
	cJSON *root;

	if (!(root = cJSON_CreateObject()))
		goto err_alloc;

	if (!cJSON_AddBoolToObject(root, "openconfig-das:ignore-session-key",
				   ignore_session_key))
		goto err_json;

	if (gnmi_json_object_set(main_switch, gpath, root,
				 DEFAULT_TIMEOUT_US))
		goto err_json;

	ret = GNMA_OK;
err_json:
	cJSON_Delete(root);
err_alloc:
	return ret;
}

int gnma_ieee8021x_das_ignore_session_key_get(bool *ignore_session_key)
{
	cJSON *parsed_res, *server_key;
	char *buf = NULL;
	char *gpath;
	int ret;

	ret = asprintf(&gpath,
		       "/openconfig-das:das/das-global-config-table/config/ignore-session-key");
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	server_key = cJSON_GetObjectItemCaseSensitive(parsed_res, "openconfig-das:ignore-session-key");
	*ignore_session_key = cJSON_IsTrue(server_key);

	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_ieee8021x_das_auth_type_key_set(gnma_das_auth_type_t auth_type)
{
	char *gpath = "/openconfig-das:das/das-global-config-table/state/das-auth-type";
	int ret = GNMA_ERR_COMMON;
	cJSON *root;

	if (!(root = cJSON_CreateObject()))
		goto err_alloc;

	if (auth_type == GNMA_802_1X_DAS_AUTH_TYPE_ANY) {
		if (!cJSON_AddStringToObject(root, "openconfig-das:das-auth-type", "ANY"))
			goto err_json;
	} else if (auth_type == GNMA_802_1X_DAS_AUTH_TYPE_ALL) {
		if (!cJSON_AddStringToObject(root, "openconfig-das:das-auth-type", "ALL"))
			goto err_json;
	} else if (auth_type == GNMA_802_1X_DAS_AUTH_TYPE_SESSION_KEY) {
		if (!cJSON_AddStringToObject(root, "openconfig-das:das-auth-type", "SESSION_KEY"))
			goto err_json;
	} else {
		goto err_json;
	}

	if (gnmi_json_object_set(main_switch, gpath, root,
				 DEFAULT_TIMEOUT_US))
		goto err_json;

	ret = GNMA_OK;
err_json:
	cJSON_Delete(root);
err_alloc:
	return ret;
}

int gnma_ieee8021x_das_auth_type_key_get(gnma_das_auth_type_t *auth_type)
{
	cJSON *parsed_res, *auth;
	char *buf = NULL;
	char *gpath;
	int ret;

	ret = asprintf(&gpath,
		       "/openconfig-das:das/das-global-config-table/config/das-auth-type");
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	auth = cJSON_GetObjectItemCaseSensitive(parsed_res, "openconfig-das:das-auth-type");
	if (!auth || !cJSON_GetStringValue(auth))
		goto err_gnmi_parse;

	if (!strcmp("ANY", cJSON_GetStringValue(auth)))
		*auth_type = GNMA_802_1X_DAS_AUTH_TYPE_ANY;
	else if (!strcmp("ALL", cJSON_GetStringValue(auth)))
		*auth_type = GNMA_802_1X_DAS_AUTH_TYPE_ALL;
	else if (!strcmp("SESSION_KEY", cJSON_GetStringValue(auth)))
		*auth_type = GNMA_802_1X_DAS_AUTH_TYPE_SESSION_KEY;
	else
		ret = GNMA_ERR_COMMON;

	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_ieee8021x_das_dac_hosts_list_get(size_t *list_size,
					  struct gnma_das_dac_host_key *hosts_list)
{
	cJSON *parsed_res, *host, *hosts_arr, *addr;
	uint16_t arr_len;
	char *buf = 0;
	char *gpath;
	int ret;

	ret = asprintf(&gpath,
		       "/openconfig-das:das/das-client-config-table/das-client-config-table-entry");
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	hosts_arr = cJSON_GetObjectItemCaseSensitive(parsed_res,
						     "openconfig-das:das-client-config-table-entry");

	arr_len = 0;
	cJSON_ArrayForEach(host, hosts_arr)
		arr_len++;

	if (arr_len > *list_size) {
		ret = GNMA_ERR_OVERFLOW;
		*list_size = arr_len;
		goto err_overflow;
	}

	memset(hosts_list, 0, sizeof(*hosts_list) * (*list_size));

	*list_size = 0;
	cJSON_ArrayForEach(host, hosts_arr) {
		addr = cJSON_GetObjectItemCaseSensitive(host, "clientaddress");
		if (!addr) {
			ret = GNMA_ERR_COMMON;
			goto err_gnmi_check_arr;
		}
		strcpy(hosts_list[*list_size].hostname,
		       cJSON_GetStringValue(addr));
		(*list_size)++;
	}

	ret = 0;

err_overflow:
err_gnmi_check_arr:
	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_ieee8021x_das_dac_host_add(struct gnma_das_dac_host_key *key,
				    const char *passkey)
{
	cJSON *server_item;
	cJSON *servers_arr;
	cJSON *config;
	cJSON *root;
	char *path;
	int ret;

	ret = asprintf(&path,
		       "/openconfig-das:das/das-client-config-table/das-client-config-table-entry");
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	/*
	{
	  "openconfig-das:das-client-config-table-entry": [
	    {
	      "clientaddress": "test.com",
	      "config": {
	        "clientaddress": "test.com",
	        "encrypted": false,
	        "server-key": "test"
	      }
	    }
	  ]
	}
	 */
	root = cJSON_CreateObject();
	servers_arr = cJSON_AddArrayToObject(root, "openconfig-das:das-client-config-table-entry");
	server_item = cJSON_CreateObject();
	config = cJSON_AddObjectToObject(server_item, "config");
	if (!cJSON_AddStringToObject(server_item, "clientaddress", key->hostname) ||
	    !cJSON_AddBoolToObject(config, "encrypted", false) ||
	    !cJSON_AddStringToObject(config, "clientaddress", key->hostname) ||
	    !cJSON_AddItemToArray(servers_arr, server_item)) {
		cJSON_Delete(server_item);
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	if (passkey[0] != '\0' && !cJSON_AddStringToObject(config, "server-key", passkey)) {
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	ret = gnmi_json_object_set(main_switch, path, root, DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_req_fail;
	}

	ret = 0;
err_req_fail:
err_val_alloc:
	cJSON_Delete(root);
	free(path);
err_path_alloc:
	return ret;
}

int gnma_ieee8021x_das_dac_host_remove(struct gnma_das_dac_host_key *key)
{
	char *path;
	int ret;

	ret = asprintf(&path,
		       "/openconfig-das:das/das-client-config-table/das-client-config-table-entry[clientaddress=%s]/",
		       key->hostname);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_del(main_switch, path, DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_req_fail;
	}

	ret = 0;
err_req_fail:
	free(path);
err_path_alloc:
	return ret;
}

static const char *
gnma_ieee8021x_das_dac_stats_type_to_string(gnma_ieee8021x_das_dac_stat_type_t counter_id)
{
	static struct {
		gnma_ieee8021x_das_dac_stat_type_t enu_value;
		const char *str_value;
	} stats_enum_to_str[] = {
		{ .enu_value = GNMA_IEEE8021X_DAS_DAC_STAT_IN_COA_PKTS, .str_value = "num_coa_requests_received"},
		{ .enu_value = GNMA_IEEE8021X_DAS_DAC_STAT_OUT_COA_ACK_PKTS, .str_value = "num_coa_ack_responses_sent"},
		{ .enu_value = GNMA_IEEE8021X_DAS_DAC_STAT_OUT_COA_NAK_PKTS, .str_value = "num_coa_nak_responses_sent"},
		{ .enu_value = GNMA_IEEE8021X_DAS_DAC_STAT_IN_COA_IGNORED_PKTS, .str_value = "num_coa_requests_ignored"},
		{ .enu_value = GNMA_IEEE8021X_DAS_DAC_STAT_IN_COA_WRONG_ATTR_PKTS, .str_value = "num_coa_missing_unsupported_attributes_requests"},
		{ .enu_value = GNMA_IEEE8021X_DAS_DAC_STAT_IN_COA_WRONG_ATTR_VALUE_PKTS, .str_value = "num_coa_invalid_attribute_value_requests"},
		{ .enu_value = GNMA_IEEE8021X_DAS_DAC_STAT_IN_COA_WRONG_SESSION_CONTEXT_PKTS, .str_value = "num_coa_session_context_not_found_requests"},
		{ .enu_value = GNMA_IEEE8021X_DAS_DAC_STAT_IN_COA_ADMINISTRATIVELY_PROHIBITED_REQ_PKTS, .str_value = "num_coa_administratively_prohibited_requests"},
	};
	size_t i;

	for (i = 0; i < ARRAY_LENGTH(stats_enum_to_str); ++i)
		if (counter_id == stats_enum_to_str[i].enu_value)
			return stats_enum_to_str[i].str_value;

	return NULL;
}

int
gnma_iee8021x_das_dac_global_stats_get(uint32_t num_of_counters,
				       gnma_ieee8021x_das_dac_stat_type_t *counter_ids,
				       uint64_t *counters)
{
	cJSON *parsed_res, *global_table, *global_counter_table_list, *counter,
	      *counters_arr;
	const char *counter_string;
	char *buf = 0;
	char *gpath;
	size_t i;
	int ret;

	ret = asprintf(&gpath, "/sonic-das:sonic-das/DAS_GLOBAL_COUNTER_TABLE");
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	memset(counters, 0, sizeof(*counters) * num_of_counters);
	/*
	 * Parse the following table type:
	{
	"sonic-das:DAS_GLOBAL_COUNTER_TABLE": {
		"DAS_GLOBAL_COUNTER_TABLE_LIST": [
		{
			"global": "GLOBAL",
			"num_coa_ack_responses_sent": 0,
			"num_coa_administratively_prohibited_requests": 0,
			"num_coa_invalid_attribute_value_requests": 0,
			"num_coa_missing_unsupported_attributes_requests": 0,
			"num_coa_nak_responses_sent": 1,
			"num_coa_requests_ignored": 1,
			"num_coa_requests_received": 1,
			"num_coa_session_context_not_found_requests": 0
		}
		]
	}
	}
	*/

	global_table =
		cJSON_GetObjectItemCaseSensitive(parsed_res,
						 "sonic-das:DAS_GLOBAL_COUNTER_TABLE");
	global_counter_table_list =
		cJSON_GetObjectItemCaseSensitive(global_table,
						 "DAS_GLOBAL_COUNTER_TABLE_LIST");
	counters_arr = cJSON_GetArrayItem(global_counter_table_list, 0);
	if (!cJSON_IsObject(counters_arr)) {
		/* It's okay if these tables do not exists:
		 * no DAC cfg was present, counters - all zero*/
		ret = GNMA_OK;
		goto err_gnmi_get_obj;
	}

	for (i = 0; i < num_of_counters; ++i) {
		counter_string = gnma_ieee8021x_das_dac_stats_type_to_string(counter_ids[i]);
		counter = cJSON_GetObjectItemCaseSensitive(counters_arr,
							   counter_string);
		if (counter && cJSON_IsNumber(counter)) {
			counters[i] = (typeof(counters[i])) cJSON_GetNumberValue(counter);
		}
	}

err_gnmi_get_obj:
	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_radius_hosts_list_get(size_t *list_size,
			       struct gnma_radius_host_key *hosts_list)
{
	cJSON *parsed_res, *hosts_arr, *host, *addr, *servers;
	uint16_t arr_len;
	char *buf = 0;
	char *gpath;
	int ret;

	ret = asprintf(&gpath,
		       "/openconfig-system:system/aaa/server-groups/server-group[name=RADIUS]/servers");
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	parsed_res = cJSON_Parse(buf);
	ZFREE(buf);
	if (!parsed_res) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_parse;
	}

	servers = cJSON_GetObjectItemCaseSensitive(parsed_res, "openconfig-system:servers");
	hosts_arr = cJSON_GetObjectItemCaseSensitive(servers, "server");

	arr_len = 0;
	cJSON_ArrayForEach(host, hosts_arr)
		arr_len++;

	if (arr_len > *list_size) {
		ret = GNMA_ERR_OVERFLOW;
		*list_size = arr_len;
		goto err_overflow;
	}

	memset(hosts_list, 0, sizeof(*hosts_list) * (*list_size));

	*list_size = 0;
	cJSON_ArrayForEach(host, hosts_arr) {
		addr = cJSON_GetObjectItemCaseSensitive(host, "address");
		if (!addr) {
			ret = GNMA_ERR_COMMON;
			goto err_gnmi_check_arr;
		}
		strcpy(hosts_list[*list_size].hostname,
		       cJSON_GetStringValue(addr));
		(*list_size)++;
	}

	ret = 0;

err_overflow:
err_gnmi_check_arr:
	cJSON_Delete(parsed_res);
err_gnmi_parse:
err_gnmi_get:
	free(gpath);
err_path_alloc:
	return ret;
}

int gnma_radius_host_add(struct gnma_radius_host_key *key, const char *passkey,
			 uint16_t auth_port, uint8_t prio)
{
	cJSON *server_item;
	cJSON *servers_arr;
	cJSON *radius_cfg;
	cJSON *servers;
	cJSON *config;
	cJSON *radius;
	cJSON *root;
	char *path;
	int ret;

	ret = asprintf(&path,
		       "/openconfig-system:system/aaa/server-groups/server-group[name=RADIUS]/servers");
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	root = cJSON_CreateObject();
	servers = cJSON_AddObjectToObject(root, "openconfig-system:servers");
	servers_arr = cJSON_AddArrayToObject(servers, "server");
	server_item = cJSON_CreateObject();
	config = cJSON_AddObjectToObject(server_item, "config");
	if (!cJSON_AddStringToObject(server_item, "address", key->hostname) ||
	    !cJSON_AddNumberToObject(config, "priority", prio) ||
	    !cJSON_AddItemToArray(servers_arr, server_item)) {
		cJSON_Delete(server_item);
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	radius = cJSON_AddObjectToObject(server_item, "radius");
	radius_cfg = cJSON_AddObjectToObject(radius, "config");
	if (!radius_cfg) {
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	if (!cJSON_AddNumberToObject(radius_cfg, "auth-port", auth_port) ||
	    !cJSON_AddBoolToObject(radius_cfg, "openconfig-aaa-radius-ext:encrypted", false)) {
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	if (passkey[0] != '\0' && !cJSON_AddStringToObject(radius_cfg, "secret-key", passkey)) {
		ret = GNMA_ERR_COMMON;
		goto err_val_alloc;
	}

	ret = gnmi_json_object_set(main_switch, path, root, DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_req_fail;
	}

	ret = 0;
err_req_fail:
err_val_alloc:
	cJSON_Delete(root);
	free(path);
err_path_alloc:
	return ret;
}

int gnma_radius_host_remove(struct gnma_radius_host_key *key)
{
	char *path;
	int ret;

	ret = asprintf(&path,
		       "/openconfig-das:das/das-client-config-table/das-client-config-table-entry[clientaddress=%s]/",
		       key->hostname);
	if (ret == -1) {
		ret = GNMA_ERR_COMMON;
		goto err_path_alloc;
	}

	ret = gnmi_jsoni_del(main_switch, path, DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_req_fail;
	}

	ret = 0;
err_req_fail:
	free(path);
err_path_alloc:
	return ret;
}

int gnma_system_password_set(char *password)
{
	char *gpath = "/openconfig-system:system/aaa/authentication/users/user[username=admin]/config/password";
	int ret = GNMA_ERR_COMMON;
	cJSON *root;

	if (!(root = cJSON_CreateObject()))
		goto err_alloc;

	if (!cJSON_AddStringToObject(root, "role", "admin"))
		goto err_json;

	if (!cJSON_AddStringToObject(root, "password", password))
		goto err_json;

	if (gnmi_json_object_set(main_switch, gpath, root,
				 DEFAULT_TIMEOUT_US))
		goto err_json;

	ret = GNMA_OK;
err_json:
	cJSON_Delete(root);
err_alloc:
	return ret;
}

struct gnma_change *gnma_change_create(void)
{
	return (struct gnma_change *)gnmi_setrq_create();
}

void gnma_change_destory(struct gnma_change *c)
{
	gnmi_setrq_destroy((struct gnmi_setrq *)c);
}

int gnma_change_exec(struct gnma_change *c)
{
	return gnmi_setrq_execute(main_switch, (struct gnmi_setrq *)c, 0);
}

int gnma_techsupport_start(char *res_path)
{
	int ret;
	ret = gnmi_gnoi_techsupport_start(main_switch, res_path);
	if (ret)
		return GNMA_ERR_COMMON;

	return 0;
}

int gnma_mac_address_list_get(size_t *list_size, struct gnma_fdb_entry *list)
{
	const char *gpath = "/openconfig-network-instance:network-instances/network-instance[name=default]/fdb";
	cJSON *root, *fdb, *state, *entry_list, *entry, *field;
	char *buf = NULL, *port, *mac;
	gnma_fdb_entry_type_t type;
	int vlan, ret, idx = 0;
	size_t num_entries;

	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	/*
	{"openconfig-network-instance:fdb": {
		"mac-table": {"entries": {"entry": [ ... ]}},
		"state": {"dynamic-count": #, "static-count": #}}
	}
	*/
	root = cJSON_Parse(buf);
	ZFREE(buf);
	if (!root) {
		ret = GNMA_ERR_COMMON;
		goto err_gnmi_get;
	}

	ret = GNMA_ERR_COMMON;
	/* get number of entries */
	fdb = cJSON_GetObjectItemCaseSensitive(root, "openconfig-network-instance:fdb");
	state = cJSON_GetObjectItemCaseSensitive(fdb, "state");
	field = cJSON_GetObjectItemCaseSensitive(state, "dynamic-count");
	if (!fdb || !state || !cJSON_IsNumber(field))
		goto err_gnmi_get_obj;
	num_entries = field->valueint;
	field = cJSON_GetObjectItemCaseSensitive(state, "static-count");
	if (!cJSON_IsNumber(field))
		goto err_gnmi_get_obj;
	num_entries += field->valueint;

	/* check that provided buffer is big enough */
	if (*list_size < num_entries) {
		*list_size = num_entries;
		ret = GNMA_ERR_OVERFLOW;
		goto err_gnmi_get_obj;
	}

	/* if fdb is empty there is nothing to do */
	if (num_entries == 0)
		goto err_gnmi_no_entries;

	if (list == NULL)
		goto err_gnmi_get_obj;

	/* parse fdb entries */
	entry_list = cJSON_GetObjectItemCaseSensitive(fdb, "mac-table");
	entry_list = cJSON_GetObjectItemCaseSensitive(entry_list, "entries");
	entry_list = cJSON_GetObjectItemCaseSensitive(entry_list, "entry");
	if (!entry_list)
		goto err_gnmi_get_obj;

	/*
	{"interface": {"interface-ref": {"state": {"interface": "Ethernet#"}}},
	 "state": {"entry-type": "STATIC" | "DYNAMIC",
		   "mac-address": "XX:XX:XX:XX:XX:XX",
		   "vlan": #}
	}
	*/
	cJSON_ArrayForEach(entry, entry_list) {
		if (cJSON_IsInvalid(entry) || cJSON_IsNull(entry))
			goto err_gnmi_get_obj;

		state = cJSON_GetObjectItemCaseSensitive(entry, "state");
		field = cJSON_GetObjectItemCaseSensitive(state, "mac-address");
		if (!state || !cJSON_IsString(field) || !field->valuestring)
			goto err_gnmi_get_obj;
		mac = field->valuestring;

		field = cJSON_GetObjectItemCaseSensitive(state, "vlan");
		if (!cJSON_IsNumber(field))
			goto err_gnmi_get_obj;
		vlan = field->valueint;

		field = cJSON_GetObjectItemCaseSensitive(state, "entry-type");
		if (!cJSON_IsString(field) || !field->valuestring)
			goto err_gnmi_get_obj;
		type = strcmp(field->valuestring, "STATIC") == 0
			? GNMA_FDB_ENTRY_TYPE_STATIC
			: GNMA_FDB_ENTRY_TYPE_DYNAMIC;

		field = cJSON_GetObjectItemCaseSensitive(entry, "interface");
		field = cJSON_GetObjectItemCaseSensitive(field, "interface-ref");
		field = cJSON_GetObjectItemCaseSensitive(field, "state");
		field = cJSON_GetObjectItemCaseSensitive(field, "interface");
		if (!cJSON_IsString(field) || !field->valuestring)
			goto err_gnmi_get_obj;
		port = field->valuestring;

		strncpy(list[idx].port.name, port, sizeof(list[idx].port.name));
		strncpy(list[idx].mac, mac, sizeof(list[idx].mac));
		list[idx].type = type;
		list[idx].vid = vlan;
		idx++;
		*list_size = idx;
	}

err_gnmi_no_entries:
	ret = GNMA_OK;
err_gnmi_get_obj:
	cJSON_Delete(root);  /* only need to free root */
err_gnmi_get:
	return ret;
}

static int __gnma_igmp_disable(uint16_t vid)
{
	char *resource[] = {
		"/openconfig-interfaces:interfaces/interface[name=Vlan%u]/subinterfaces/subinterface[index=0]/openconfig-if-ip:ipv4/openconfig-igmp-ext:igmp",
		"/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping/interfaces/interface[name=Vlan%u]/staticgrps",
		"/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping/interfaces/interface[name=Vlan%u]"
	};
	char gpath[256];
	size_t i;
	int ret;

	for (i = 0; i < ARRAY_LENGTH(resource); i++) {
		ret = snprintf(gpath, sizeof(gpath), resource[i], vid);
		if (ret == -1)
			return GNMA_ERR_COMMON;
		/* ignore return value */
		gnmi_jsoni_del(main_switch, gpath, DEFAULT_TIMEOUT_US);
	}
	return 0;
}

static int __gnma_ip_igmp_set(uint16_t vid, struct gnma_igmp_snoop_attr *attr)
{
	cJSON *root, *config;
	char *gpath;
	int ret;

	ret = asprintf(&gpath,
		       "/openconfig-interfaces:interfaces/interface[name=Vlan%u]/subinterfaces/subinterface[index=0]/openconfig-if-ip:ipv4/openconfig-igmp-ext:igmp",
		       vid);
	if (ret == -1)
		return GNMA_ERR_COMMON;

	ret = GNMA_ERR_COMMON;
	root = cJSON_CreateObject();
	if (!root)
		goto err;

	config = cJSON_AddObjectToObject(root, "openconfig-igmp-ext:igmp");
	config = cJSON_AddObjectToObject(config, "config");
	if (!config)
		goto err;

	if (!cJSON_AddBoolToObject(config, "enabled", attr->querier_enabled))
		goto err;

	if (attr->querier_enabled){
		if (!cJSON_AddNumberToObject(config, "query-interval", attr->query_interval) ||
		    !cJSON_AddNumberToObject(config, "query-max-response-time", attr->max_response_time) ||
		    !cJSON_AddNumberToObject(config, "last-member-query-interval", attr->last_member_query_interval))
			goto err;
		if (attr->version != GNMA_IGMP_VERSION_NA)
			if (!cJSON_AddNumberToObject(config, "version", attr->version))
				goto err;
	}

	ret = gnmi_json_object_set(main_switch, gpath, root, DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err;
	}
err:
	free(gpath);
	return ret;
}

static int __gnma_igmp_root_alloc(uint16_t vid, cJSON **root, cJSON **interface)
{
	cJSON *root_node, *config, *iface_node, *interfaces_list;
	char iface_name[] = "VlanXXXX";

	if (vid >= 4096)  /* sanity */
		return GNMA_ERR_COMMON;

	snprintf(iface_name, sizeof(iface_name), "Vlan%u", vid);

	root_node = cJSON_CreateObject();
	if (!root_node)
		return GNMA_ERR_COMMON;

	interfaces_list = cJSON_AddObjectToObject(root_node, "openconfig-network-instance-deviation:igmp-snooping");
	interfaces_list = cJSON_AddObjectToObject(interfaces_list, "interfaces");
	interfaces_list = cJSON_AddArrayToObject(interfaces_list, "interface");
	if (!interfaces_list)
		goto err;

	iface_node = cJSON_CreateObject();
	if (!iface_node)
		goto err;
	if (!cJSON_AddItemToArray(interfaces_list, iface_node)) {
		cJSON_Delete(iface_node);
		goto err;
	}

	config = cJSON_AddObjectToObject(iface_node, "config");
	if (!config)
		goto err;

	if (!cJSON_AddStringToObject(iface_node, "name", iface_name) ||
	    !cJSON_AddStringToObject(config, "name", iface_name))
		goto err;

	*root = root_node;
	*interface = iface_node;
	return 0;
err:
	cJSON_Delete(root_node);
	*root = NULL;
	*interface = NULL;
	return GNMA_ERR_COMMON;
}

int gnma_igmp_snooping_set(uint16_t vid, struct gnma_igmp_snoop_attr *attr)
{
	char *gpath = "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping";
	bool enabled = attr->enabled || attr->querier_enabled;
	cJSON *root, *config, *interface;
	int ret;

	if (!enabled) {
		/* ignore return value */
		__gnma_igmp_disable(vid);
		return 0;
	}

	ret = __gnma_ip_igmp_set(vid, attr);
	if (ret)
		return ret;

	/* allocates root object which needs to be freed */
	ret = __gnma_igmp_root_alloc(vid, &root, &interface);
	if (ret)
		return ret;

	config = cJSON_GetObjectItemCaseSensitive(interface, "config");
	if (!config) {
		ret = GNMA_ERR_COMMON;
		goto err;
	}

	if (!cJSON_AddBoolToObject(config, "enabled", attr->enabled) ||
	    !cJSON_AddBoolToObject(config, "querier", attr->querier_enabled)) {
		ret = GNMA_ERR_COMMON;
		goto err;
	}

	if (attr->enabled){
		if (!cJSON_AddBoolToObject(config, "fast-leave", attr->fast_leave_enabled))
			goto err;
		if (attr->version != GNMA_IGMP_VERSION_NA)
			if (!cJSON_AddNumberToObject(config, "version", attr->version))
				goto err;
	}

	ret = gnmi_json_object_set(main_switch, gpath, root, DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err;
	}
err:
	cJSON_Delete(root);
	return ret;
}

int gnma_igmp_static_groups_set(uint16_t vid, size_t num_groups,
				struct gnma_igmp_static_group_attr *groups)
{
	char *gpath = "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping";
	cJSON *root, *mcast_groups, *group, *port_list, *port, *interface;
	char ip_addr[] = {"255.255.255.255"};
	size_t grp_idx, port_idx;
	int ret;

	/* allocates root object which needs to be freed */
	ret = __gnma_igmp_root_alloc(vid, &root, &interface);
	if (ret)
		return ret;

	mcast_groups = cJSON_AddObjectToObject(interface, "staticgrps");
	mcast_groups = cJSON_AddArrayToObject(mcast_groups, "static-multicast-group");
	if (!mcast_groups) {
		ret = GNMA_ERR_COMMON;
		goto err;
	}

	for (grp_idx = 0; grp_idx < num_groups; grp_idx++) {
		group = cJSON_CreateObject();
		if (!group) {
			ret = GNMA_ERR_COMMON;
			goto err;
		}
		if (!cJSON_AddItemToArray(mcast_groups, group)) {
			cJSON_Delete(group);
			ret = GNMA_ERR_COMMON;
			goto err;
		}

		if (!inet_ntop(AF_INET, &groups[grp_idx].address.s_addr, ip_addr, sizeof(ip_addr)) ||
		    !cJSON_AddStringToObject(group, "group", ip_addr) ||
		    !cJSON_AddStringToObject(group, "source-addr", "0.0.0.0")) {
			ret = GNMA_ERR_COMMON;
			goto err;
		}

		port_list = cJSON_AddObjectToObject(group, "config");
		port_list = cJSON_AddArrayToObject(port_list, "outgoing-interface");
		if (!port_list) {
			ret = GNMA_ERR_COMMON;
			goto err;
		}
		for (port_idx = 0; port_idx < groups[grp_idx].num_ports; port_idx++) {
			port = cJSON_CreateString(groups[grp_idx].egress_ports[port_idx].name);
			if (!port) {
				ret = GNMA_ERR_COMMON;
				goto err;
			}
			if (!cJSON_AddItemToArray(port_list, port)) {
				cJSON_Delete(port);
				ret = GNMA_ERR_COMMON;
				goto err;
			}
		}
	}

	ret = gnmi_json_object_set(main_switch, gpath, root, DEFAULT_TIMEOUT_US);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto err;
	}
err:
	cJSON_Delete(root);
	return ret;
}

int gnma_igmp_iface_groups_get(struct gnma_port_key *iface,
			       char *out_buf, size_t *out_buf_size)
{
	char *gpath, *buf = NULL;
	cJSON *root, *groups;
	size_t json_len = 0;
	char *json_buf;
	int ret;

	ret = asprintf(&gpath,
		       "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping/interfaces/interface[name=%s]",
		       iface->name);

	if (ret == -1)
		return GNMA_ERR_COMMON;
	ret = gnmi_jsoni_get_alloc(main_switch, &gpath[0], &buf, 0,
				   DEFAULT_TIMEOUT_US);
	ZFREE(gpath);
	if (ret)
		return GNMA_ERR_COMMON;
	root = cJSON_Parse(buf);
	ZFREE(buf);
	if (!root)
		return GNMA_ERR_COMMON;
	ret = GNMA_ERR_COMMON;
	groups = cJSON_GetObjectItemCaseSensitive(root, "openconfig-network-instance-deviation:interface");
	groups = cJSON_GetArrayItem(groups, 0);
	groups = cJSON_GetObjectItemCaseSensitive(groups, "staticgrps");
	groups = cJSON_GetObjectItemCaseSensitive(groups, "static-multicast-group");
	if (cJSON_GetArraySize(groups) == 0) {
		/* No IGMP groups exists. */
		*out_buf_size = 0;
		goto err_gnmi_no_entries;
	}

	json_buf = cJSON_PrintUnformatted(groups);
	if (!json_buf) {
		ret = GNMA_ERR_COMMON;
		goto err_buf_print;
	}

	json_len = strlen(json_buf);
	/* check that provided buffer is large enough */
	if (*out_buf_size < json_len) {
		*out_buf_size = json_len + 1;
		ret = GNMA_ERR_OVERFLOW;
		free(json_buf);
		goto err_gnmi_get_obj;
	}

	memcpy(out_buf, json_buf, *out_buf_size - 1);
	free(json_buf);

err_gnmi_no_entries:
	ret = GNMA_OK;
err_buf_print:
err_gnmi_get_obj:
	cJSON_Delete(root);  /* only need to free root */
	return ret;
}

int gnma_ip_iface_addr_get(struct gnma_vlan_ip_t *address_list, size_t *list_size)
{
	struct nl_vid_addr *list;
	size_t len = 0, i;
	int ret;

	ret = nl_get_ip_list(NULL, &len);
	if (ret && ret != -EOVERFLOW)
		return GNMA_ERR_COMMON;

	if (!address_list || len > *list_size) {
		*list_size = len;
		return GNMA_ERR_OVERFLOW;
	}
	if (len == 0) {
		*list_size = 0;
		return GNMA_OK;
	}

	list = calloc(len, sizeof(*list));
	if (!list)
		return GNMA_ERR_COMMON;

	ret = nl_get_ip_list(list, &len);
	if (ret) {
		ret = GNMA_ERR_COMMON;
		goto out;
	}

	for (i = 0; i < len; i++) {
		address_list[i].vid = list[i].vid;
		address_list[i].prefixlen = list[i].prefixlen;
		address_list[i].address.s_addr = list[i].address;
	}
	ret = GNMA_OK;
out:
	free(list);
	*list_size = len;
	return ret;
}
