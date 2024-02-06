#define _GNU_SOURCE /* asprintf */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>

#include <cjson/cJSON.h>
#include <curl/curl.h>

#define UC_LOG_COMPONENT UC_LOG_COMPONENT_PROTO

#include "ucentral.h"

#define CONFIGURE_STATUS_REJECTED 2
#define CONFIGURE_STATUS_PARTIALLY_APPLIED 1
#define CONFIGURE_STATUS_APPLIED 0

struct blob {
	cJSON *obj;
	char *rendered_string;
};

enum {
	JSONRPC_VER,
	JSONRPC_METHOD,
	JSONRPC_ERROR,
	JSONRPC_PARAMS,
	JSONRPC_ID,
	JSONRPC_RADIUS,
	__JSONRPC_MAX,
};
enum {
	PARAMS_SERIAL,
	PARAMS_UUID,
	PARAMS_COMMAND,
	PARAMS_CONFIG,
	PARAMS_PAYLOAD,
	PARAMS_REJECTED,
	PARAMS_COMPRESS,
	PARAMS_FACTORY_KEEP_REDIRECTOR,
	PARAMS_TELEMETRY_INTERVAL,
	PARAMS_TELEMETRY_TYPES,
	__PARAMS_MAX,
};


static char *password;

static time_t uuid_active;
static time_t uuid_latest;

static bool state_compress = true;

static uc_send_msg_cb send_msg_cb;
static uc_send_connect_msg_cb send_connect_msg_cb;

#define PORT_ID_SELECT_ALL_PORTS (255)
struct proto_script_ctx {
	uint64_t id;
	char *uri;
};

void proto_cb_register_uc_send_msg(uc_send_msg_cb cb)
{
	send_msg_cb = cb;
}

void proto_cb_register_uc_connect_msg_send(uc_send_connect_msg_cb cb)
{
	send_connect_msg_cb = cb;
}

static cJSON *jobj_u64_set(cJSON *dst, const char *name, uint64_t u)
{
	char b[32] = { 0 };
	snprintf(b, sizeof b, "%" PRIu64, u);
	return cJSON_AddRawToObject(dst, name, b);
}

static const char *jobj_str_get(const cJSON *obj, const char *name)
{
	return cJSON_GetStringValue(
		cJSON_GetObjectItemCaseSensitive(obj, name));
}

static int proto_port_duplex_to_num(const char *str, uint8_t *duplex)
{
	/* TBD: optimize (move out from hdr? */
	static struct {
		const char *str;
		uint8_t duplex;
	} arr[] = {
		{ .str = "full", .duplex = UCENTRAL_PORT_DUPLEX_FULL_E },
		{ .str = "half", .duplex = UCENTRAL_PORT_DUPLEX_HALF_E }
	};
	size_t i;

	for (i = 0; i < sizeof(arr) / sizeof(arr[0]); ++i) {
		if (!strcmp(str, arr[i].str)) {
			*duplex = arr[i].duplex;
			return 0;
		}
	}

	return 1;
}

static int proto_port_speed_to_num(double val, uint32_t *speed)
{
	/* TBD: optimize (move out from hdr? */
	static struct {
		double val;
		uint32_t speed;
	} arr[] = {
		{ .val = 10, .speed = UCENTRAL_PORT_SPEED_10_E },
		{ .val = 100, .speed = UCENTRAL_PORT_SPEED_100_E },
		{ .val = 1000, .speed = UCENTRAL_PORT_SPEED_1000_E },
		{ .val = 2500, .speed = UCENTRAL_PORT_SPEED_2500_E },
		{ .val = 5000, .speed = UCENTRAL_PORT_SPEED_5000_E },
		{ .val = 10000, .speed = UCENTRAL_PORT_SPEED_10000_E },
		{ .val = 25000, .speed = UCENTRAL_PORT_SPEED_25000_E },
		{ .val = 100000, .speed = UCENTRAL_PORT_SPEED_100000_E }
	};
	size_t i;

	for (i = 0; i < sizeof(arr) / sizeof(arr[0]); ++i) {
		if (val == arr[i].val) {
			*speed = arr[i].speed;
			return 0;
		}
	}

	return 1;
}

static int proto_port_state_to_num(bool enabled, uint8_t *state)
{
	*state = enabled ? UCENTRAL_PORT_ENABLED_E : UCENTRAL_PORT_DISABLED_E;

	return 1;
}

static int proto_port_name_to_num(const char *str, uint16_t *p_fp_id)
{
	unsigned int fp_id;
	int ret;

	if (!strcmp(str, "Ethernet*") || !strcmp(str, "eth*")) {
		*p_fp_id = (uint16_t) PORT_ID_SELECT_ALL_PORTS;
		return 0;
	}

	ret = sscanf(str, "Ethernet%u", &fp_id);
	if (ret) {
		*p_fp_id = (uint16_t) fp_id;
		return 0;
	}

	return 1;
}

static int proto_vlan_tagged_to_num(const char *str, uint8_t *tagged)
{
	/* TBD: optimize (move out from hdr? */
	static struct {
		const char *str;
		uint8_t tagged;
	} arr[] = {
		{ .str = "tagged", .tagged = UCENTRAL_VLAN_1Q_TAG_TAGGED_E },
		{ .str = "un-tagged", .tagged = UCENTRAL_VLAN_1Q_TAG_UNTAGGED_E }
	};
	size_t i;

	for (i = 0; i < sizeof(arr) / sizeof(arr[0]); ++i) {
		if (!strcmp(str, arr[i].str)) {
			*tagged = arr[i].tagged;
			return 0;
		}
	}

	return 1;
}

static int proto_stp_mode_to_num(const char *str, uint8_t *stp_mode)
{
	/* TBD: optimize (move out from hdr? */
	static struct {
		const char *str;
		uint8_t mode;
	} arr[] = {
		{ .str = "none", .mode = PLAT_STP_MODE_NONE },
		{ .str = "stp", .mode = PLAT_STP_MODE_STP },
		{ .str = "rstp", .mode = PLAT_STP_MODE_RST },
		{ .str = "mstp", .mode = PLAT_STP_MODE_MST },
		{ .str = "pvstp", .mode = PLAT_STP_MODE_PVST },
		{ .str = "rpvstp", .mode = PLAT_STP_MODE_RPVST }
	};
	size_t i;

	if (!str)
		return 1;

	for (i = 0; i < sizeof(arr) / sizeof(arr[0]); ++i) {
		if (!strcmp(str, arr[i].str)) {
			*stp_mode = arr[i].mode;
			return 0;
		}
	}

	return 1;
}

static pthread_mutex_t __port_list_mtx = PTHREAD_MUTEX_INITIALIZER;
static struct plat_ports_list *__port_list;
static uint16_t __port_list_num;

static int __get_port_list(struct plat_ports_list **ports_list,
			   uint16_t *num_of_active_ports)
{
	struct plat_ports_list *port_node = NULL;
	int ret = 0;
	int i;

	pthread_mutex_lock(&__port_list_mtx);
	if (__port_list) {
		goto skip_access;
	}

	ret = plat_port_num_get(&__port_list_num);
	if (ret) {
		UC_LOG_ERR("Failed to get num of active ports\n");
		goto skip_access;
	}

	for (i = 0; i < __port_list_num; ++i) {
		port_node = calloc(1, sizeof(*port_node));
		if (!port_node) {
			UC_LOG_ERR("Failed alloc port list list\n");
			ret = -ENOMEM;
			goto skip_access; /* TODO remove allocated */
		}
		UCENTRAL_LIST_PUSH_MEMBER(&__port_list, port_node);
	}

	ret = plat_port_list_get(__port_list_num, __port_list);
	if (ret) {
		UC_LOG_ERR("Failed to get platform active ports list\n");
		UCENTRAL_LIST_DESTROY_SAFE(&__port_list, port_node);
		__port_list = NULL;
		goto skip_access;
	}

skip_access:
	*ports_list = __port_list;
	/* Do not return ports number, if list fetching failed */
	*num_of_active_ports = __port_list ? __port_list_num : 0;
	pthread_mutex_unlock(&__port_list_mtx);

	return ret;
}

/* Define period, when ports list on device could be changed */
static void __put_port_list(struct plat_ports_list **ports_list)
{
	/* TODO: could be refcnt
	 * For now just null ptr. Could be used for dbg purposes.
	 * And rev compatibility with list_free (previously implementation)
	 */
	*ports_list = NULL;
}

static cJSON *
proto_new_blob(const char *method)
{
	cJSON *root = cJSON_CreateObject();
	cJSON *params;

	if (!root)
		goto err;

	if (!cJSON_AddStringToObject(root, "jsonrpc", "2.0"))
		goto err;

	if (!cJSON_AddStringToObject(root, "method", method))
		goto err;

	if (!(params = cJSON_AddObjectToObject(root, "params")))
		goto err;

	return root;

err:
	UC_LOG_ERR("JSON obj alloc failed\n");
	cJSON_Delete(root);
	return NULL;
}

static cJSON*
result_new_blob(double id, time_t uuid)
{
	cJSON *root = cJSON_CreateObject();
	cJSON *result;

	if (!root)
		goto err;

	if (!cJSON_AddStringToObject(root, "jsonrpc", "2.0"))
		goto err;

	if (!cJSON_AddNumberToObject(root, "id", id))
		goto err;

	if (!(result = cJSON_AddObjectToObject(root, "result")))
		goto err;

	if (!cJSON_AddStringToObject(result, "serial", client.serial))
		goto err;

	if (!cJSON_AddNumberToObject(result, "uuid", uuid))
		goto err;

	return root;

err:
	UC_LOG_ERR("JSON obj alloc failed\n");
	cJSON_Delete(root);
	return NULL;
}

static void proto_destroy_blob(struct blob *blob)
{
	cJSON_Delete(blob->obj);
	free(blob->rendered_string);

	blob->obj = NULL;
	blob->rendered_string = NULL;
}

static void send_blob(struct blob *blob)
{
	char *msg = cJSON_PrintUnformatted(blob->obj);

	if (!msg) {
		UC_LOG_ERR("cJSON_PrintUnformatted failed");
		return;
	}

	send_msg_cb(msg, strlen(msg));
	free(msg);
}

static void send_connect_blob(struct blob *blob)
{
	char *msg = cJSON_PrintUnformatted(blob->obj);

	if (!msg) {
		UC_LOG_ERR("cJSON_PrintUnformatted failed");
		return;
	}

	send_connect_msg_cb(msg, strlen(msg));
	free(msg);
}

static void proto_send_blob(struct blob *blob)
{
	send_blob(blob);
}

static void result_send_blob(struct blob *blob)
{
	send_blob(blob);
}

void log_send(const char *message, int severity)
{
	struct blob blob = {0};
	cJSON *params;

	blob.obj = proto_new_blob("log");
	if (!blob.obj)
		goto err;

	params = cJSON_GetObjectItemCaseSensitive(blob.obj, "params");
	if (!params)
		goto err;

	if (!cJSON_AddStringToObject(params, "serial", client.serial))
		goto err;

	if (!cJSON_AddStringToObject(params, "log", message))
		goto err;

	if (!cJSON_AddNumberToObject(params, "severity", severity))
		goto err;

	UC_LOG_DBG("xmit log\n");

	proto_send_blob(&blob);
	proto_destroy_blob(&blob);

	return;

err:
	UC_LOG_ERR("JSON obj alloc failed\n");
	proto_destroy_blob(&blob);
}

void
connect_send(void)
{
	/* WIP: TMP hardcode; to be removed*/
	unsigned mac[6];
	struct plat_platform_info pinfo = {0};
	struct plat_metrics_cfg restore_metrics = { 0 };
	struct blob blob = {0};
	uint64_t uuid_buf; /* fixed storage size */
	cJSON *params;
	cJSON *cap;
	int ret;

	blob.obj = proto_new_blob("connect");
	if (!blob.obj)
		goto err;

	params = cJSON_GetObjectItemCaseSensitive(blob.obj, "params");
	if (!params)
		goto err;

	/* Initialize protocol's local uuid_active variable */
	ret = plat_saved_config_id_get(&uuid_buf);
	if (ret)
		uuid_active = 1;
	else
		uuid_active = uuid_buf;

	if (!cJSON_AddStringToObject(params, "serial", client.serial))
		goto err;

	if (!cJSON_AddStringToObject(params, "firmware", client.firmware))
		goto err;

	if (!cJSON_AddNumberToObject(params, "uuid", (double)uuid_active))
		goto err;

	if (password) {
		if (!cJSON_AddStringToObject(params, "password", password))
			goto err;

		memset(password, 0, strlen(password));
		free(password);
		password = NULL;
	}

	cap = cJSON_AddObjectToObject(params, "capabilities");
	if (!cap)
		goto err;

	if (plat_info_get(&pinfo)) {
		UC_LOG_CRIT("failed to get platform info");
	} else {
		if (!cJSON_AddStringToObject(cap, "compatible", pinfo.hwsku))
			goto err;

		if (!cJSON_AddStringToObject(cap, "model", pinfo.platform))
			goto err;
	}

	if (!cJSON_AddStringToObject(cap, "platform", "switch"))
		goto err;

	if (client.serial &&
		  sscanf(client.serial, "%2x%2x%2x%2x%2x%2x",
			  &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
		char label_mac[32];
		snprintf(label_mac, sizeof label_mac,
			 "%02x:%02x:%02x:%02x:%02x:%02x",
			 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		if (!cJSON_AddStringToObject(cap, "label_macaddr", label_mac)) {
			goto err;
		}
	} else {
		UC_LOG_DBG("failed to parse serial as label_macaddr");
	}

	if (!plat_metrics_restore(&restore_metrics)) {
		ucentral_metrics = restore_metrics;
		plat_state_poll_stop();
		plat_health_poll_stop();

		if (ucentral_metrics.state.enabled)
			plat_state_poll(state_send,
					ucentral_metrics.state.interval);

		if (ucentral_metrics.healthcheck.enabled)
			plat_health_poll(health_send,
					 ucentral_metrics.healthcheck.interval);
	}

	UC_LOG_DBG("xmit connect\n");

	send_connect_blob(&blob);
	proto_destroy_blob(&blob);

	return;

err:
	UC_LOG_ERR("JSON obj alloc failed\n");
	proto_destroy_blob(&blob);
}

void event_firmware_upgrade_send(char *operation, int percentage, char *text)
{
	cJSON *params, *data, *events, *event, *payload;
	time_t rawtime_utc = time(NULL);
	struct blob blob = {0};

	blob.obj = proto_new_blob("event");
	if (!blob.obj)
		goto err;

	params = cJSON_GetObjectItemCaseSensitive(blob.obj, "params");
	if (!params)
		goto err;

	if (!cJSON_AddStringToObject(params, "serial", client.serial))
		goto err;

	data = cJSON_AddObjectToObject(params, "data");
	if (!data)
		goto err;

	events = cJSON_AddArrayToObject(data, "event");
	if (!events)
		goto err;

	event = cJSON_CreateObject();
	if (!event)
		goto err;

	if (!cJSON_AddItemToArray(events, cJSON_CreateNumber(rawtime_utc)))
			goto err;

	if (!cJSON_AddItemToArray(events, event)) {
		cJSON_Delete(event);
		goto err;
	}

	if (!cJSON_AddStringToObject(event, "type", "firmware_upgrade_status"))
		goto err;

	payload = cJSON_AddObjectToObject(event, "payload");
	if (!payload)
		goto err;

	if (!cJSON_AddStringToObject(payload, "operation", operation))
		goto err;

	if (percentage >= 0) {
		if (!cJSON_AddNumberToObject(payload, "percentage", percentage))
			goto err;
	}

	if (text && !cJSON_AddStringToObject(payload, "text", text))
		goto err;

	UC_LOG_DBG("xmit upgrade state\n");

	proto_send_blob(&blob);
	proto_destroy_blob(&blob);

	return;

err:
	UC_LOG_ERR("JSON obj alloc failed\n");
	proto_destroy_blob(&blob);
}

void
configure_reply(uint32_t error, const char *text, time_t uuid, double id)
{
	struct blob blob = {0};
	cJSON *status;
	cJSON *res;

	blob.obj = result_new_blob(id ,uuid);
	if (!blob.obj)
		goto err;

	if (!(res = cJSON_GetObjectItemCaseSensitive(blob.obj, "result")))
		goto err;

	if (!(status = cJSON_AddObjectToObject(res, "status")))
		goto err;

	if (!cJSON_AddStringToObject(status, "text", text))
		goto err;

	/*
	 * rejected: TODO
	 */

	if (!cJSON_AddNumberToObject(status, "error", error))
		goto err;

	/*
	if (blob_len(rejected.head)) {
		struct blob_attr *tb[__PARAMS_MAX] = {};

		blobmsg_parse(params_policy, __PARAMS_MAX, tb, blob_data(rejected.head),
			      blob_len(rejected.head));
		if (tb[PARAMS_REJECTED]) {
			r = blobmsg_open_array(&result, "rejected");
			blobmsg_for_each_attr(b, tb[PARAMS_REJECTED], rem)
				blobmsg_add_blob(&result, b);
			blobmsg_close_array(&result, r);
		}
		if (!error)
			error = 1;
	}
	*/

	result_send_blob(&blob);
	proto_destroy_blob(&blob);

	return;
err:
	UC_LOG_ERR("JSON obj alloc failed\n");
	proto_destroy_blob(&blob);
}

/* result_send_error */
static void action_reply(uint32_t error, char *text, uint32_t retcode, uint32_t id)
{
	struct blob blob = {0};
	cJSON *status;
	cJSON *res;

	blob.obj = result_new_blob(id, uuid_active);
	if (!blob.obj)
		goto err;

	if (!(res = cJSON_GetObjectItemCaseSensitive(blob.obj, "result")))
		goto err;

	if (!(status = cJSON_AddObjectToObject(res, "status")))
		goto err;

	if (!cJSON_AddNumberToObject(status, "error", error))
		goto err;

	if (!cJSON_AddStringToObject(status, "text", text))
		goto err;

	if (!cJSON_AddNumberToObject(status, "resultCode", retcode))
		goto err;

	result_send_blob(&blob);
	proto_destroy_blob(&blob);

	return;
err:
	UC_LOG_ERR("JSON obj alloc failed\n");
	proto_destroy_blob(&blob);
}

static void script_reply(uint32_t error, const char *text, uint32_t id)
{
	struct blob blob = {0};
	cJSON *status;
	cJSON *res;

	blob.obj = result_new_blob(id, uuid_active);
	if (!blob.obj)
		goto err;

	if (!(res = cJSON_GetObjectItemCaseSensitive(blob.obj, "result")))
		goto err;

	if (!(status = cJSON_AddObjectToObject(res, "status")))
		goto err;

	if (!cJSON_AddNumberToObject(status, "error", error))
		goto err;

	if (!cJSON_AddStringToObject(status, "result", text))
		goto err;

	result_send_blob(&blob);
	proto_destroy_blob(&blob);

	return;
err:
	UC_LOG_ERR("JSON obj alloc failed\n");
	proto_destroy_blob(&blob);
}

static int
cfg_ethernet_select_ports_parse(cJSON *select_ports,
				uint32_t *ports_bmap,
				size_t *ports_selected_num)
{
	BITMAP_DECLARE(plat_ports_avail, MAX_NUM_OF_PORTS);
	struct plat_ports_list *port_node = NULL;
	struct plat_ports_list *ports = NULL;
	uint16_t num_of_active_ports;
	uint16_t tmp_fp_id;
	cJSON *p;
	int ret;

	ret = __get_port_list(&ports, &num_of_active_ports);
	if (ret) {
		UC_LOG_ERR("Fetch ports list failed\n");
		return -1;
	}

	BITMAP_CLEAR(plat_ports_avail, MAX_NUM_OF_PORTS);
	BITMAP_CLEAR(ports_bmap, MAX_NUM_OF_PORTS);

	*ports_selected_num = 0;

	UCENTRAL_LIST_FOR_EACH_MEMBER(port_node, &ports) {
		uint16_t pid;
		NAME_TO_PID(&pid, port_node->name);
		BITMAP_SET_BIT(plat_ports_avail, pid);
	}

	cJSON_ArrayForEach(p, select_ports) {
		ret = proto_port_name_to_num(cJSON_GetStringValue(p),
					     &tmp_fp_id);
		if (ret) {
			UC_LOG_ERR("Failed to conver port '%s' to num/idx\n",
					cJSON_GetStringValue(p));
			ret = -1;
			goto out;
		}

		/* Wildcard selection == select all ports available in the
		 * platform <get active ports list>.
		 */
		if (tmp_fp_id == PORT_ID_SELECT_ALL_PORTS) {
			UCENTRAL_LIST_FOR_EACH_MEMBER(port_node, &ports) {
				NAME_TO_PID(&tmp_fp_id, port_node->name);
				BITMAP_SET_BIT(ports_bmap, tmp_fp_id);
			}
			*ports_selected_num = num_of_active_ports;
			ret = 0;
			goto out;
		} else {
			/* Test if we <can> configure this port on platform
			 * based on bmap that holds bitmask of present ports
			 * on platform.
			 */
			if (tmp_fp_id >= MAX_NUM_OF_PORTS ||
			    !BITMAP_TEST_BIT(plat_ports_avail, tmp_fp_id)) {
				ret = -1;
				UC_LOG_DBG("<Ethernet%hu> is invalid port idx\n",
					   tmp_fp_id);
				goto out;
			}

			BITMAP_SET_BIT(ports_bmap, tmp_fp_id);
			++(*ports_selected_num);
			continue;
		}
	}

	ret = 0;

out:
	__put_port_list(&ports);
	return ret;
}

static int cfg_ethernet_poe_parse(cJSON *poe,
				  struct plat_port *port)
{
	cJSON *power_limit;
	cJSON *admin_mode;
	cJSON *detection;
	cJSON *priority;
	cJSON *do_reset;

	admin_mode = cJSON_GetObjectItemCaseSensitive(poe, "admin-mode");
	do_reset = cJSON_GetObjectItemCaseSensitive(poe, "do-reset");
	detection = cJSON_GetObjectItemCaseSensitive(poe, "detection");
	power_limit = cJSON_GetObjectItemCaseSensitive(poe, "power-limit");
	priority = cJSON_GetObjectItemCaseSensitive(poe, "priority");

	if (admin_mode && !cJSON_IsBool(admin_mode)) {
		UC_LOG_ERR("poe:admin-mode is invalid, bool expected\n");
		return -1;
	} else if (admin_mode)
		port->poe.is_admin_mode_up = cJSON_IsTrue(admin_mode);

	if (do_reset && !cJSON_IsBool(do_reset)) {
		UC_LOG_ERR("poe:do-reset is invalid, bool expected\n");
		return -1;
	} else if (do_reset)
		port->poe.do_reset = cJSON_IsTrue(do_reset);

	if (detection && !cJSON_GetStringValue(detection)) {
		UC_LOG_ERR("poe:detection is invalid, string expected\n");
		return -1;
	} else if (detection) {
		strcpy(port->poe.detection_mode, cJSON_GetStringValue(detection));
		port->poe.is_detection_mode_set = true;
	}

	if (power_limit && !cJSON_IsNumber(power_limit)) {
		UC_LOG_ERR("poe:power-limit is invalid, number expected\n");
		return -1;
	} else if (power_limit) {
		port->poe.power_limit = (uint32_t)cJSON_GetNumberValue(power_limit);
		port->poe.is_power_limit_set = true;
	}

	if (priority && !cJSON_GetStringValue(priority)) {
		UC_LOG_ERR("poe:priority is invalid, string expected\n");
		return -1;
	} else if (priority) {
		strcpy(port->poe.priority, cJSON_GetStringValue(priority));
		port->poe.is_priority_set = true;
	}

	return 0;
}

static int
cfg_ethernet_ieee8021x_parse(cJSON *ieee8021x, struct plat_port *port)
{
	cJSON *authentication_mode;
	cJSON *is_authenticator;
	cJSON *auth_fail_vid;
	cJSON *guest_vid;
	cJSON *host_mode;

	is_authenticator = cJSON_GetObjectItemCaseSensitive(ieee8021x, "is-authenticator");
	authentication_mode = cJSON_GetObjectItemCaseSensitive(ieee8021x, "authentication-mode");
	host_mode = cJSON_GetObjectItemCaseSensitive(ieee8021x, "host-mode");
	guest_vid = cJSON_GetObjectItemCaseSensitive(ieee8021x, "guest-vlan");
	auth_fail_vid = cJSON_GetObjectItemCaseSensitive(ieee8021x, "unauthenticated-vlan");

	/* Set default values in case if no cfg supplied */
	port->ieee8021x.is_authenticator = false;
	port->ieee8021x.control_mode = PLAT_802_1X_PORT_CONTROL_FORCE_AUTHORIZED;
	port->ieee8021x.host_mode = PLAT_802_1X_PORT_HOST_MODE_MULTI_AUTH;
	/* VID 0 means don't care / do not configure */
	port->ieee8021x.auth_fail_vid = 0;
	port->ieee8021x.guest_vid = 0;

	if (is_authenticator && !cJSON_IsBool(is_authenticator)) {
		UC_LOG_ERR("ieee8021x:is-authenticator is invalid, bool expected");
		return -1;
	} else if (is_authenticator)
		port->ieee8021x.is_authenticator = cJSON_IsTrue(is_authenticator);

	if (authentication_mode && !cJSON_GetStringValue(authentication_mode)) {
		UC_LOG_ERR("ieee8021x:authentication_mode is invalid, string expected");
		return -1;
	} else if (authentication_mode) {
		if (strcmp(cJSON_GetStringValue(authentication_mode), "force-authorized") == 0)
			port->ieee8021x.control_mode = PLAT_802_1X_PORT_CONTROL_FORCE_AUTHORIZED;
		else if (strcmp(cJSON_GetStringValue(authentication_mode), "force-unauthorized") == 0)
			port->ieee8021x.control_mode = PLAT_802_1X_PORT_CONTROL_FORCE_UNAUTHORIZED;
		else if (strcmp(cJSON_GetStringValue(authentication_mode), "auto") == 0)
			port->ieee8021x.control_mode = PLAT_802_1X_PORT_CONTROL_AUTO;
		else {
			UC_LOG_ERR("ieee8021x:authentication_mode has valid type but invalid \"%s\" value",
				   cJSON_GetStringValue(authentication_mode));
			return -1;
		}
	}

	if (host_mode && !cJSON_GetStringValue(host_mode)) {
		UC_LOG_ERR("ieee8021x:host_mode is invalid, string expected");
		return -1;
	} else if (host_mode) {
		if (strcmp(cJSON_GetStringValue(host_mode), "multi-auth") == 0)
			port->ieee8021x.host_mode = PLAT_802_1X_PORT_HOST_MODE_MULTI_AUTH;
		else if (strcmp(cJSON_GetStringValue(host_mode), "multi-domain") == 0)
			port->ieee8021x.host_mode = PLAT_802_1X_PORT_HOST_MODE_MULTI_DOMAIN;
		else if (strcmp(cJSON_GetStringValue(host_mode), "multi-host") == 0)
			port->ieee8021x.host_mode = PLAT_802_1X_PORT_HOST_MODE_MULTI_HOST;
		else if (strcmp(cJSON_GetStringValue(host_mode), "single-host") == 0)
			port->ieee8021x.host_mode = PLAT_802_1X_PORT_HOST_MODE_SINGLE_HOST;
		else {
			UC_LOG_ERR("ieee8021x:host_mode has valid type but invalid \"%s\" value",
				   cJSON_GetStringValue(host_mode));
			return -1;
		}
	}

	if (guest_vid && !cJSON_IsNumber(guest_vid)) {
		UC_LOG_ERR("ieee8021x:guest-vlan is invalid, number expected");
		return -1;
	} else if (guest_vid)
		port->ieee8021x.guest_vid = (uint16_t)cJSON_GetNumberValue(guest_vid);

	if (auth_fail_vid && !cJSON_IsNumber(auth_fail_vid)) {
		UC_LOG_ERR("ieee8021x:unauthenticated-vlan is invalid, number expected");
		return -1;
	} else if (auth_fail_vid)
		port->ieee8021x.auth_fail_vid = (uint16_t)cJSON_GetNumberValue(auth_fail_vid);

	return 0;
}

static int
cfg_ethernet_port_isolation_interface_parse(cJSON *iface,
					    struct plat_port_isolation_session_ports *ports) {
	struct plat_ports_list *port_node = NULL;
	cJSON *iface_list;
	int i;

	iface_list = cJSON_GetObjectItemCaseSensitive(iface, "interface-list");
	if (!iface_list || !cJSON_IsArray(iface_list) ||
	    cJSON_GetArraySize(iface_list) == 0) {
		UC_LOG_ERR("Ethernet obj 'port_isolation:interface-list' is invalid, parse failed\n");
		return -1;
	}

	for (i = 0; i < cJSON_GetArraySize(iface_list); ++i) {
		if (!cJSON_GetStringValue(cJSON_GetArrayItem(iface_list, i))) {
			UC_LOG_ERR("Ethernet obj 'port_isolation:interface-list:%d' has invalid port name, parse failed\n",
				   i);
			return -1;
		}
		port_node = calloc(1, sizeof(*port_node));
		if (!port_node) {
			UC_LOG_ERR("Failed alloc port list list\n");
			return -1;
		}
		strcpy(port_node->name,
		       cJSON_GetStringValue(cJSON_GetArrayItem(iface_list, i)));
		UCENTRAL_LIST_PUSH_MEMBER(&ports->ports_list, port_node);
	}

	return 0;
}

static int
cfg_ethernet_port_isolation_parse(cJSON *ethernet, struct plat_cfg *cfg) {
	cJSON *eth = NULL, *port_isolation, *sessions, *session;
	struct plat_port_isolation_session *session_arr;
	struct plat_ports_list *port_node = NULL;
	int i = 0, j = 0;

	cJSON_ArrayForEach(eth, ethernet) {
		port_isolation = cJSON_GetObjectItemCaseSensitive(eth, "port-isolation");
		if (!port_isolation)
			continue;

		if (!cJSON_IsObject(port_isolation)) {
			UC_LOG_ERR("Ethernet obj holds 'port_isolation' object of wrongful type, parse failed\n");
			return -1;
		}

		sessions = cJSON_GetObjectItemCaseSensitive(port_isolation,
							    "sessions");
		if (!sessions || !cJSON_IsArray(sessions)) {
			UC_LOG_ERR("Ethernet obj holds 'port_isolation:sessions' array of wrongful type (or empty), parse failed\n");
			return -1;
		}

		cJSON_ArrayForEach(session, sessions) {
			cfg->port_isolation_cfg.sessions_num++;
		}
	}

	if (cfg->port_isolation_cfg.sessions_num == 0) {
		return 0;
	}

	session_arr = calloc(cfg->port_isolation_cfg.sessions_num,
			     sizeof(struct plat_port_isolation_session));
	cfg->port_isolation_cfg.sessions = session_arr;

	if (!session_arr) {
		UC_LOG_ERR("Failed to alloc memory for port-isolation-cfg, parse failed\n");
		return -1;
	}

	cJSON_ArrayForEach(eth, ethernet) {
		port_isolation = cJSON_GetObjectItemCaseSensitive(eth, "port-isolation");
		if (!port_isolation)
			continue;

		/*
		 * Highly unlikeable that the object is missing / invalid,
		 * as it was okay prior (parsing above).
		 * But this is still a sanity-check, in case if JSON
		 * got corrupted for some reason.
		 */
		if (!cJSON_IsObject(port_isolation)) {
			UC_LOG_ERR("Ethernet obj holds 'port_isolation' object of wrongful type, parse failed\n");
			return -1;
		}

		sessions = cJSON_GetObjectItemCaseSensitive(port_isolation,
							    "sessions");
		if (!sessions || !cJSON_IsArray(sessions)) {
			UC_LOG_ERR("Ethernet obj holds 'port_isolation:sessions' array of wrongful type (or empty), parse failed\n");
			return -1;
		}

		cJSON_ArrayForEach(session, sessions) {
			cJSON *id, *uplink, *downlink;
			double session_arrid;

			id = cJSON_GetObjectItemCaseSensitive(session, "id");
			if (!id || !cJSON_IsNumber(id)) {
				UC_LOG_ERR("Ethernet obj 'port_isolation:id' is invalid, parse failed\n");
				goto err;
			}

			session_arrid = cJSON_GetNumberValue(id);

			if (i > 0) {
				for (int j = i - 1; j >= 0; --j) {
					if ((double) session_arr[j].id == session_arrid) {
						UC_LOG_ERR("Expected unique 'port_isolation:id', duplicate (%lu) detected, parse failed\n",
							   (uint64_t) session_arrid);
						goto err;
					}
				}
			}

			session_arr[j].id = (uint64_t) session_arrid;

			uplink = cJSON_GetObjectItemCaseSensitive(session,
								  "uplink");
			if (!uplink || !cJSON_IsObject(uplink)) {
				UC_LOG_ERR("Ethernet obj 'port_isolation:uplink' is invalid, parse failed\n");
				goto err;
			}

			downlink = cJSON_GetObjectItemCaseSensitive(session,
								    "downlink");
			if (!downlink || !cJSON_IsObject(downlink)) {
				UC_LOG_ERR("Ethernet obj 'port_isolation:downlink' is invalid, parse failed\n");
				goto err;
			}

			if (cfg_ethernet_port_isolation_interface_parse(uplink,
									&session_arr[j].uplink)) {
				UC_LOG_ERR("Ethernet obj 'port_isolation:uplink' parse failed\n");
				goto err;
			}

			if (cfg_ethernet_port_isolation_interface_parse(downlink,
									&session_arr[j].downlink)) {
				UC_LOG_ERR("Ethernet obj 'port_isolation:downlink' parse failed\n");
				goto err;
			}

			++i;
		}
	}

	return 0;
err:
	for (int j = i; j >= 0; --j) {
		UCENTRAL_LIST_DESTROY_SAFE(&session_arr[j].uplink.ports_list,
					   port_node);
		UCENTRAL_LIST_DESTROY_SAFE(&session_arr[j].downlink.ports_list,
					   port_node);
	}
	cfg->port_isolation_cfg.sessions = 0;
	free(cfg->port_isolation_cfg.sessions);
	return -1;
}

static int cfg_ethernet_parse(cJSON *ethernet, struct plat_cfg *cfg)
{
	cJSON *eth = NULL;
	size_t i;
	int ret;

	cJSON_ArrayForEach(eth, ethernet) {
		BITMAP_DECLARE(tmp_port_bmap, MAX_NUM_OF_PORTS);
		struct plat_port tmp_port = {0};
		size_t ports_selected = 0;
		cJSON *select_ports;
		const char *duplex;
		double speed = 0;
		cJSON *ieee8021x;
		bool enabled;
		cJSON *poe;

		BITMAP_CLEAR(tmp_port_bmap, MAX_NUM_OF_PORTS);

		select_ports = cJSON_GetObjectItemCaseSensitive(eth, "select-ports");
		enabled =
			cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(eth, "enabled"));
		duplex =
			cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(eth, "duplex"));
		speed =
			cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(eth, "speed"));

		if (!duplex || !speed || !select_ports) {
			UC_LOG_ERR("Ethernet obj doesn't hold duplex, speed or select-ports fields, parse failed\n");
			return -1;
		}

		poe = cJSON_GetObjectItemCaseSensitive(eth, "poe");
		if (poe && !cJSON_IsObject(poe)) {
			UC_LOG_ERR("Ethernet obj holds 'poe' object of wrongful type, parse failed\n");
			return -1;
		} else if (poe) {
			ret = cfg_ethernet_poe_parse(poe, &tmp_port);
			if (ret) {
				UC_LOG_ERR("Ethernet 'poe' object parse failed\n");
				return -1;
			}
		}

		ieee8021x = cJSON_GetObjectItemCaseSensitive(eth, "ieee8021x");
		if (ieee8021x && !cJSON_IsObject(ieee8021x)) {
			UC_LOG_ERR("Ethernet obj holds 'ieee8021x' object of wrongful type, parse failed\n");
			return -1;
		} else if (ieee8021x) {
			ret = cfg_ethernet_ieee8021x_parse(ieee8021x, &tmp_port);
			if (ret) {
				UC_LOG_ERR("Ethernet 'ieee8021x' object parse failed\n");
				return -1;
			}
		}

		proto_port_duplex_to_num(duplex, &tmp_port.duplex);
		proto_port_state_to_num(enabled, &tmp_port.state);
		proto_port_speed_to_num(speed, &tmp_port.speed);

		ret = cfg_ethernet_select_ports_parse(select_ports,
						      tmp_port_bmap,
						      &ports_selected);
		if (ret || ports_selected == 0) {
			UC_LOG_ERR("'select-ports' obj doesn't hold enough ifaces or is empty, parse failed\n");
			return -1;
		}

		BITMAP_FOR_EACH_BIT_SET(i, tmp_port_bmap, MAX_NUM_OF_PORTS) {
			char port_name[32];

			PID_TO_NAME((uint16_t)i, port_name);
			strcpy(tmp_port.name, port_name);
			tmp_port.fp_id = i;

			memcpy(&cfg->ports[i], &tmp_port, sizeof(tmp_port));
			BITMAP_SET_BIT(cfg->ports_to_cfg, i);
		}
	}

	if (cfg_ethernet_port_isolation_parse(ethernet, cfg)) {
		UC_LOG_ERR("port-isolation config parse faile\n");
		return -1;
	}

	return 0;
}

static uint16_t cfg_interface2vid(cJSON *interface)
{
		cJSON *vlan_id;
		cJSON *vlan;

		vlan = cJSON_GetObjectItemCaseSensitive(interface, "vlan");
		vlan_id = cJSON_GetObjectItemCaseSensitive(vlan, "id");

		if (!cJSON_GetNumberValue(vlan_id) ||
		    cJSON_GetNumberValue(vlan_id) >= MAX_VLANS) {
			UC_LOG_ERR("found 'vlan', but 'id' (vlan-id) seems to be invalud (%u), parse failed\n",
				   (uint16_t)cJSON_GetNumberValue(vlan_id));
			return MAX_VLANS;
		}

		return (uint16_t)cJSON_GetNumberValue(vlan_id);
}

static int cfg_port_interface_parse(cJSON *interface, struct plat_cfg *cfg)
{
	size_t i;
	int ret;

	BITMAP_DECLARE(tmp_port_bmap, MAX_NUM_OF_PORTS);
	size_t ports_selected = 0;
	char *ipv4_subnet_str;
	cJSON *select_ports;
	cJSON *ethernet;
	cJSON *ipv4;
	cJSON *eth;

	/* Ignore interface with l2 type: vlan */
	if (cJSON_GetObjectItemCaseSensitive(interface, "vlan"))
		return -1;

	ethernet = cJSON_GetObjectItemCaseSensitive(interface, "ethernet");
	if (cJSON_GetArraySize(ethernet) != 1)
		return -1;

	eth = cJSON_GetArrayItem(ethernet, 0);
	select_ports = cJSON_GetObjectItem(eth, "select-ports");
	ret = cfg_ethernet_select_ports_parse(select_ports,
					      tmp_port_bmap,
					      &ports_selected);
	if (ret || ports_selected != 1) {
		UC_LOG_ERR("'select-ports' obj doesn't hold enough ifaces or is empty, parse failed\n");
		return -1;
	}

	i = BITMAP_FIND_FIRST_BIT_SET(tmp_port_bmap, MAX_NUM_OF_PORTS);
	ipv4 = cJSON_GetObjectItemCaseSensitive(interface, "ipv4");
	if (ipv4) {
		/*  TODO addressing */
		ipv4_subnet_str = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(ipv4, "subnet"));
		if (!ipv4_subnet_str)
			return 0; /* In case of old config */

		memset(&cfg->portsl2[i].ipv4.subnet, 0,
		       sizeof(cfg->portsl2[i].ipv4.subnet));
		cfg->portsl2[i].ipv4.subnet_len =
			inet_net_pton(AF_INET, ipv4_subnet_str,
				      &cfg->portsl2[i].ipv4.subnet,
				      sizeof(cfg->portsl2[i].ipv4.subnet));
		if (cfg->portsl2[i].ipv4.subnet_len == -1) {
			UC_LOG_ERR("Subnet parsing failed");
			return -1;
		}

		cfg->portsl2[i].ipv4.exist = true;
	}

	return 0;
}

static int cfg_vlan_interface_parse(cJSON *interface, struct plat_cfg *cfg)
{
	size_t i;
	int ret;

	struct plat_vlan_memberlist *memberlist_node = NULL;
	BITMAP_DECLARE(tmp_port_bmap, MAX_NUM_OF_PORTS);
	char *dhcp_relay_circ_id_str;
	size_t ports_selected = 0;
	char *dhcp_relay_srv_str;
	char *ipv4_subnet_str;
	cJSON *select_ports;
	cJSON *ipv4_subnet;
	cJSON *vlan_tag;
	cJSON *ethernet;
	uint8_t tagged;
	uint16_t vid;
	cJSON *ipv4;
	cJSON *dhcp;
	cJSON *eth;

	/* Ignore interface with l2 type: not vlan */
	if (!cJSON_GetObjectItemCaseSensitive(interface, "vlan"))
		return -1;

	BITMAP_CLEAR(tmp_port_bmap, MAX_NUM_OF_PORTS);

	vid = cfg_interface2vid(interface);
	if (vid == MAX_VLANS)
		return -1;

	BITMAP_SET_BIT(cfg->vlans_to_cfg, vid);

	ethernet = cJSON_GetObjectItemCaseSensitive(interface, "ethernet");
	cJSON_ArrayForEach(eth, ethernet) {
		select_ports = cJSON_GetObjectItem(eth, "select-ports");

		ret = cfg_ethernet_select_ports_parse(select_ports,
						      tmp_port_bmap,
						      &ports_selected);
		if (ret || ports_selected == 0) {
			UC_LOG_ERR("'select-ports' obj doesn't hold enough ifaces or is empty, parse failed\n");
			return -1;
		}

		vlan_tag = cJSON_GetObjectItemCaseSensitive(eth, "vlan-tag");

		ret = proto_vlan_tagged_to_num(cJSON_GetStringValue(vlan_tag),
					       &tagged);
		if (ret) {
			UC_LOG_ERR("Ethernet doesn't hold 'vlan-tag' field, parse failed\n");
			return -1;
		}

		BITMAP_FOR_EACH_BIT_SET(i, tmp_port_bmap, MAX_NUM_OF_PORTS) {
			char port_name[PORT_MAX_NAME_LEN];

			memberlist_node = calloc(1, sizeof(*memberlist_node));
			if (!memberlist_node) {
				UC_LOG_ERR("Can't alloc vlan memberlist_node, parse failed\n");
				return -1;
			}

			PID_TO_NAME((uint16_t)i, port_name);
			strcpy(memberlist_node->port.name, port_name);
			memberlist_node->port.fp_id = i;
			memberlist_node->tagged =
				(tagged == UCENTRAL_VLAN_1Q_TAG_TAGGED_E);

			UCENTRAL_LIST_PUSH_MEMBER(&cfg->vlans[vid].members_list_head,
						  memberlist_node);
		}
	}

	cfg->vlans[vid].ipv4.exist = false;
	cfg->vlans[vid].dhcp.relay.enabled = false;
	ipv4 = cJSON_GetObjectItemCaseSensitive(interface, "ipv4");
	dhcp = cJSON_GetObjectItemCaseSensitive(ipv4, "dhcp");
	if (ipv4) {
		/*  TODO addressing */
		ipv4_subnet_str = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(ipv4, "subnet"));
		if (!ipv4_subnet_str)
			goto skip_subnet_old; /* In case of old config */

		memset(&cfg->vlans[vid].ipv4.subnet, 0,
		       sizeof(cfg->vlans[vid].ipv4.subnet));
		cfg->vlans[vid].ipv4.subnet_len =
			inet_net_pton(AF_INET, ipv4_subnet_str,
				      &cfg->vlans[vid].ipv4.subnet,
				      sizeof(cfg->vlans[vid].ipv4.subnet));
		if (cfg->vlans[vid].ipv4.subnet_len == -1) {
			UC_LOG_ERR("Subnet parsing failed");
			return -1;
		}

		cfg->vlans[vid].ipv4.exist = true;
skip_subnet_old:

		ipv4_subnet = cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(ipv4, "subnet"), 0);
		if (!ipv4_subnet)
			goto skip_subnet;

		ipv4_subnet_str = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(ipv4_subnet, "prefix"));
		if (!ipv4_subnet_str)
			goto skip_subnet;

		memset(&cfg->vlans[vid].ipv4.subnet, 0,
		       sizeof(cfg->vlans[vid].ipv4.subnet));
		cfg->vlans[vid].ipv4.subnet_len =
			inet_net_pton(AF_INET, ipv4_subnet_str,
				      &cfg->vlans[vid].ipv4.subnet,
				      sizeof(cfg->vlans[vid].ipv4.subnet));
		if (cfg->vlans[vid].ipv4.subnet_len == -1) {
			UC_LOG_ERR("Subnet parsing failed");
			return -1;
		}
		cfg->vlans[vid].ipv4.exist = true;
skip_subnet:

		if (!dhcp)
			return 0;

		dhcp_relay_srv_str = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(dhcp, "relay-server"));
		dhcp_relay_circ_id_str = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(dhcp, "circuit-id-format"));
		if (!dhcp_relay_srv_str || !dhcp_relay_circ_id_str ||
		    inet_net_pton(AF_INET, dhcp_relay_srv_str,
				  &cfg->vlans[vid].dhcp.relay.server_address,
				  4) <= 0) {
			UC_LOG_ERR("DHCP-relay cfg is incomplete or missing: 'relay-server' and 'circuit-id-format' strings required");
			UC_LOG_DBG("%s %s 0x%08X", dhcp_relay_srv_str, dhcp_relay_circ_id_str, cfg->vlans[vid].dhcp.relay.server_address.s_addr);
			return -1;
		}

		if (!strcmp(dhcp_relay_circ_id_str, "{VLAN-ID}"))
			strcpy(cfg->vlans[vid].dhcp.relay.circ_id, "%p");
		else if (!strcmp(dhcp_relay_circ_id_str, "{Interface}"))
			strcpy(cfg->vlans[vid].dhcp.relay.circ_id, "%i");
		else
			strcpy(cfg->vlans[vid].dhcp.relay.circ_id, "%h:%p");

		cfg->vlans[vid].dhcp.relay.enabled = true;
	}

	return 0;
}

static int cfg_interfaces_parse(cJSON *interfaces, struct plat_cfg *cfg)
{
	cJSON *interface;

	cJSON_ArrayForEach(interface, interfaces) {
		if (!cfg_vlan_interface_parse(interface,cfg))
			continue;

		if (!cfg_port_interface_parse(interface,cfg))
			continue;

		return -1;
	}

	return 0;
}

static int cfg_service_log_parse(cJSON *s, struct plat_syslog_cfg *l)
{
	int ret = -1;
	cJSON *port = cJSON_GetObjectItemCaseSensitive(s, "port");
	cJSON *priority = cJSON_GetObjectItemCaseSensitive(s, "priority");
	cJSON *size = cJSON_GetObjectItemCaseSensitive(s, "size");
	cJSON *host = cJSON_GetObjectItemCaseSensitive(s, "host");
	cJSON *proto = cJSON_GetObjectItemCaseSensitive(s, "proto");

	/* TODO(vb): proper double to int conv handling */
	if (!cJSON_IsNumber(port)) {
		UC_LOG_DBG("services.log.port must be a number");
		goto err;
	}
	l->port = cJSON_GetNumberValue(port);

	l->priority = 7;
	if (priority) {
		if (!cJSON_IsNumber(priority)) {
			UC_LOG_DBG("services.log.priority must be a number");
			goto err;
		}
		l->priority = cJSON_GetNumberValue(priority);
	}

	l->size = 1000;
	if (size) {
		if (!cJSON_IsNumber(size)) {
			UC_LOG_DBG("services.log.priority must be a number");
			goto err;
		}
		l->size = cJSON_GetNumberValue(size);
	}

	if (proto) {
		if (!cJSON_IsString(proto)) {
			UC_LOG_DBG("services.log.proto must be a string");
			goto err;
		}

		if (!strcmp("udp", cJSON_GetStringValue(proto)))
			l->is_tcp = 0;
		else if (!strcmp("tcp", cJSON_GetStringValue(proto)))
			l->is_tcp = 1;
		else {
			UC_LOG_DBG("services.log.proto invalid value '%s'",
				   cJSON_GetStringValue(proto));
			goto err;
		}
	}

	if (host) {
		if (!cJSON_IsString(host)) {
			UC_LOG_DBG("services.log.host must be a string");
			goto err;
		}
		snprintf(l->host, sizeof l->host, "%s",
			 cJSON_GetStringValue(host));
	}

	ret = 0;
err:
	return ret;
}

static int cfg_services_parse(cJSON *services, struct plat_cfg *cfg)
{
	cJSON *s, *item;

	/* TODO(vb) clarify multiple log servers */
	s = cJSON_GetObjectItemCaseSensitive(services, "log");
	if (s) {
		if (cJSON_IsObject(s)) {
			cfg->log_cfg = malloc(sizeof *cfg->log_cfg);
			if (!cfg->log_cfg) {
				UC_LOG_ERR("malloc failed");
				return -1;
			}
			*cfg->log_cfg = (struct plat_syslog_cfg){ 0 };
			if (cfg_service_log_parse(s, cfg->log_cfg))
				return -1;
			cfg->log_cfg_cnt = 1;
		} else if (cJSON_IsArray(s)) {
			if (cJSON_GetArraySize(s)) {
				cfg->log_cfg = malloc(cJSON_GetArraySize(s) *
						      sizeof *cfg->log_cfg);
				if (!cfg->log_cfg) {
					UC_LOG_ERR("malloc failed");
					return -1;
				}
			}
			cJSON_ArrayForEach(item, s)
			{
				struct plat_syslog_cfg *l =
					&cfg->log_cfg[cfg->log_cfg_cnt];
				*l = (struct plat_syslog_cfg){ 0 };
				if (cfg_service_log_parse(item, l)) {
					return -1;
				}
				++cfg->log_cfg_cnt;
			}
		} else {
			UC_LOG_ERR("services.log must be an object");
			return -1;
		}
	}

	/* Set default values in case if no cfg supplied */
	cfg->enabled_services_cfg.ssh.enabled = false;
	cfg->enabled_services_cfg.telnet.enabled = false;
	cfg->enabled_services_cfg.http.enabled = false;

	s = cJSON_GetObjectItemCaseSensitive(services, "ssh");
	if (s) {
		if (!cJSON_IsObject(s)) {
			UC_LOG_ERR("Unexpected type of services:ssh: Object expected");
			return -1;
		}

		cJSON *enable = cJSON_GetObjectItemCaseSensitive(s, "enable");
		if (enable && !cJSON_IsBool(enable)) {
			UC_LOG_ERR("Unexpected type of services:ssh:enable: Boolean expected");
			return -1;
		}

		cfg->enabled_services_cfg.ssh.enabled = cJSON_IsTrue(enable);
	}

	s = cJSON_GetObjectItemCaseSensitive(services, "telnet");
	if (s) {
		if (!cJSON_IsObject(s)) {
			UC_LOG_ERR("Unexpected type of services:telnet: Object expected");
			return -1;
		}

		cJSON *enable = cJSON_GetObjectItemCaseSensitive(s, "enable");
		if (enable && !cJSON_IsBool(enable)) {
			UC_LOG_ERR("Unexpected type of services:telnet:enable: Boolean expected");
			return -1;
		}

		cfg->enabled_services_cfg.telnet.enabled = cJSON_IsTrue(enable);
	}

	s = cJSON_GetObjectItemCaseSensitive(services, "http");
	if (s) {
		if (!cJSON_IsObject(s)) {
			UC_LOG_ERR("Unexpected type of services:http: Object expected");
			return -1;
		}

		cJSON *enable = cJSON_GetObjectItemCaseSensitive(s, "enable");
		if (enable && !cJSON_IsBool(enable)) {
			UC_LOG_ERR("Unexpected type of services:http:enable: Boolean expected");
			return -1;
		}

		cfg->enabled_services_cfg.http.enabled = cJSON_IsTrue(enable);
	}

	return 0;
}

static int cfg_switch_ieee8021x_parse(cJSON *sw, struct plat_cfg *cfg)
{
	cJSON *ieee8021x, *auth_ctrl_enabled, *radius, *iter;

	ieee8021x = cJSON_GetObjectItemCaseSensitive(sw, "ieee8021x");
	if (!ieee8021x)
		return 0;

	if (ieee8021x && !cJSON_IsObject(ieee8021x)) {
		UC_LOG_ERR("Unexpected type of switch:ieee8021x: Object expected");
		return -1;
	}

	auth_ctrl_enabled = cJSON_GetObjectItemCaseSensitive(ieee8021x, "auth-control-enable");
	/* It's safe to check against NULL cJSON obj.
	 * In case if option is missing - defaulting to 'false' is OK for us.
	 */
	cfg->ieee8021x_is_auth_ctrl_enabled = cJSON_IsTrue(auth_ctrl_enabled);
	radius = cJSON_GetObjectItemCaseSensitive(ieee8021x, "radius");

	if (radius && !cJSON_IsArray(radius)) {
		UC_LOG_ERR("Unexpected type of switch:ieee8021x:radius: Array expected");
		return -1;
	}

	cJSON_ArrayForEach(iter, radius) {
		struct plat_radius_hosts_list *hosts_node = NULL;
		struct plat_radius_host tmp_host = {0};
		cJSON *host, *port, *key, *prio;

		if (!cJSON_IsObject(iter)) {
			UC_LOG_ERR("Unexpected type of switch:ieee8021x:radius:<element>: Object expected");
			return -1;
		}

		host = cJSON_GetObjectItemCaseSensitive(iter, "server-host");
		port = cJSON_GetObjectItemCaseSensitive(iter, "server-authentication-port");
		key = cJSON_GetObjectItemCaseSensitive(iter, "server-key");
		prio = cJSON_GetObjectItemCaseSensitive(iter, "server-priority");

		if (!host || !cJSON_GetStringValue(host)) {
			UC_LOG_ERR("Cannot add radius host without address!");
			return -1;
		} else
			strncpy(tmp_host.hostname, cJSON_GetStringValue(host),
				sizeof(tmp_host.hostname) - 1);

		if (!port || !cJSON_GetNumberValue(port)) {
			UC_LOG_INFO("<%s> radius host doesn't hold port value, defaulting to %d",
				    cJSON_GetStringValue(host), RADIUS_CFG_DEFAULT_PORT);
			tmp_host.auth_port = RADIUS_CFG_DEFAULT_PORT;
		} else
			tmp_host.auth_port = cJSON_GetNumberValue(port);

		/* RADIUS host conf without shared key is a valid / supported
		 * config.
		 */
		if (!key || !cJSON_GetStringValue(key)) {
			UC_LOG_INFO("<%s> radius host passkey field is omitted / not configured",
				    cJSON_GetStringValue(host));
		} else
			strncpy(tmp_host.passkey, cJSON_GetStringValue(key),
				sizeof(tmp_host.passkey) - 1);

		if (!prio || !cJSON_GetNumberValue(prio)) {
			UC_LOG_INFO("<%s> radius host doesn't hold prio value, defaulting to %d",
				    cJSON_GetStringValue(host), RADIUS_CFG_DEFAULT_PRIO);
			tmp_host.priority = RADIUS_CFG_DEFAULT_PRIO;
		} else
			tmp_host.priority = cJSON_GetNumberValue(port);

		hosts_node = calloc(1, sizeof(*hosts_node));
		if (!hosts_node) {
			UC_LOG_ERR("Can't alloc radius hosts node, parse failed\n");
			return -1;
		}

		memcpy(&hosts_node->host, &tmp_host, sizeof(tmp_host));

		UCENTRAL_LIST_PUSH_MEMBER(&cfg->radius_hosts_list,
					  hosts_node);
	}

	return 0;
}

static int cfg_switch_parse(cJSON *root, struct plat_cfg *cfg)
{
	BITMAP_DECLARE(instances_parsed, MAX_VLANS);
	int id, prio, fwd, hello, age;
	cJSON *sw, *obj, *iter, *arr;
	bool enabled;
	int ret;

	/* TODO mstp */

	sw = cJSON_GetObjectItemCaseSensitive(root, "switch");
	ret = cfg_switch_ieee8021x_parse(sw, cfg);
	if (ret) {
		UC_LOG_ERR("Switch ieee8021x parse failed.");
		return -1;
	}

	obj = cJSON_GetObjectItemCaseSensitive(sw, "loop-detection");
	iter = cJSON_GetObjectItemCaseSensitive(obj, "protocol");
	if (!iter)
		cfg->stp_mode = PLAT_STP_MODE_NONE;
	else
		if (proto_stp_mode_to_num(cJSON_GetStringValue(iter), &cfg->stp_mode))
			return -1;

	/* Initialize default instance values */
	for (id = 0; id < MAX_VLANS; id++) {
		cfg->stp_instances[id].enabled = false;
		cfg->stp_instances[id].forward_delay = 15;
		cfg->stp_instances[id].hello_time = 2;
		cfg->stp_instances[id].max_age = 20;
		cfg->stp_instances[id].priority = 20;
	}

	arr = cJSON_GetObjectItemCaseSensitive(obj, "instances");
	BITMAP_CLEAR(instances_parsed, MAX_VLANS);
	cJSON_ArrayForEach(iter, arr) {
		obj = cJSON_GetObjectItemCaseSensitive(iter, "id");
		id = !obj ? 0 : cJSON_GetNumberValue(obj);
		if (id < 0 || id >= MAX_VLANS)
			return -1;

		obj = cJSON_GetObjectItemCaseSensitive(iter, "priority");
		prio = !obj ? cfg->stp_instances[id].priority : cJSON_GetNumberValue(obj);

		obj = cJSON_GetObjectItemCaseSensitive(iter, "forward_delay");
		fwd = !obj ? cfg->stp_instances[id].forward_delay : cJSON_GetNumberValue(obj);

		obj = cJSON_GetObjectItemCaseSensitive(iter, "hello_time");
		hello = !obj ? cfg->stp_instances[id].hello_time : cJSON_GetNumberValue(obj);

		obj = cJSON_GetObjectItemCaseSensitive(iter, "max_age");
		age = !obj ? cfg->stp_instances[id].max_age : cJSON_GetNumberValue(obj);

		obj = cJSON_GetObjectItemCaseSensitive(iter, "enabled");
		enabled = !obj ? cfg->stp_instances[id].enabled : cJSON_IsTrue(obj);

		if (BITMAP_TEST_BIT(instances_parsed, id)) {
			UC_LOG_ERR("STP instance %d: duplicate config occured", id);
			return -1;
		}
		BITMAP_SET_BIT(instances_parsed, id);

		cfg->stp_instances[id].enabled = enabled;
		cfg->stp_instances[id].forward_delay = fwd;
		cfg->stp_instances[id].hello_time = hello;
		cfg->stp_instances[id].max_age = age;
		cfg->stp_instances[id].priority = prio;
	}

	return 0;
}

/* TODO also will parse vrf */
static int route_prefix_obj2node_key(cJSON *obj,
				     struct ucentral_router_fib_node *node)
{
	char *addr_str;
	cJSON *tobj;

	tobj = cJSON_GetObjectItemCaseSensitive(obj, "prefix");
	addr_str = cJSON_GetStringValue(tobj);
	if (!addr_str)
		return -1;

	node->key.prefix_len =
		inet_net_pton(AF_INET, addr_str, &node->key.prefix,
			      sizeof(node->key.prefix));
	if (node->key.prefix_len == -1)
		return -1;

	return 0;
}

/* return number of parsed elements */
static int cfg_process_prefixes(cJSON *root, struct ucentral_router *router)
{
	cJSON *ipv4_blackhole, *ipv4_unreachable, *gateway, *broadcast,
	      *interfaces, *interface, *ipv4, *nh, *globals, *iter;
	struct ucentral_router_fib_node node;
	char *addr_str = NULL;
	int index = 0;
	uint16_t vid;

	globals = cJSON_GetObjectItem(root, "globals");

	ipv4_blackhole = cJSON_GetObjectItem(globals, "ipv4-blackhole");
	cJSON_ArrayForEach(iter, ipv4_blackhole) {
		index++;
		if (!router)
			continue;

		if (route_prefix_obj2node_key(iter, &node))
			return -1;

		node.info.type = UCENTRAL_ROUTE_BLACKHOLE;
		ucentral_router_fib_db_append(router, &node);
	}

	ipv4_unreachable = cJSON_GetObjectItem(globals, "ipv4-unreachable");
	cJSON_ArrayForEach(iter, ipv4_unreachable) {
		index++;
		if (!router)
			continue;

		if (route_prefix_obj2node_key(iter, &node))
			return -1;

		node.info.type = UCENTRAL_ROUTE_UNREACHABLE;
		ucentral_router_fib_db_append(router, &node);
	}

	interfaces = cJSON_GetObjectItem(root, "interfaces");
	cJSON_ArrayForEach(interface, interfaces) {
		vid = cfg_interface2vid(interface);
		if (vid == MAX_VLANS)
			continue;

		ipv4 = cJSON_GetObjectItem(interface, "ipv4");

		gateway = cJSON_GetObjectItem(ipv4, "gateway");
		cJSON_ArrayForEach(iter, gateway) {
			index++;
			if (!router)
				continue;

			if (route_prefix_obj2node_key(iter, &node))
				return -1;

			node.info.type = UCENTRAL_ROUTE_NH;
			node.info.nh.vid = vid;

			nh = cJSON_GetObjectItemCaseSensitive(iter, "nexthop");
			addr_str = cJSON_GetStringValue(nh);
			if (!addr_str ||
			    inet_pton(AF_INET, addr_str, &node.info.nh.gw) != 1)
				return -1;

			ucentral_router_fib_db_append(router, &node);
		}

		broadcast = cJSON_GetObjectItem(ipv4, "broadcast");
		cJSON_ArrayForEach(iter, broadcast) {
			index++;
			if (!router)
				continue;

			if (route_prefix_obj2node_key(iter, &node))
				return -1;

			node.info.type = UCENTRAL_ROUTE_BROADCAST;
			node.info.broadcast.vid = vid;
			ucentral_router_fib_db_append(router, &node);
		}
	}

	return index;
}

/* This fetch all routes */
static int cfg_router_parse(cJSON *root, struct plat_cfg *cfg)
{
	int num, ret;

	num = cfg_process_prefixes(root, NULL);
	if (num == -1)
		return -1;

	ret = ucentral_router_fib_db_alloc(&cfg->router, num);
	if (ret)
		return ret;

	num = cfg_process_prefixes(root, &cfg->router);
	if (num == -1)
		return -1;

	return 0;
}

static int cfg_metrics_parse(cJSON *metrics, struct plat_cfg *cfg)
{
	/* statistics == <state> evt;
	 * health == <healthcheck> evt;
	 */
	cJSON *statistics_types;
	cJSON *statistics_type;
	cJSON *max_mac_count;
	cJSON *statistics;
	cJSON *interval;
	cJSON *health;

	memset(&cfg->metrics, 0, sizeof(cfg->metrics));

	statistics = cJSON_GetObjectItemCaseSensitive(metrics, "statistics");
	interval = cJSON_GetObjectItemCaseSensitive(statistics, "interval");
	statistics_types = cJSON_GetObjectItemCaseSensitive(statistics, "types");
	max_mac_count = cJSON_GetObjectItemCaseSensitive(statistics, "wired-clients-max-num");  /* optional */
	if (!statistics || !interval || !statistics_types)
		goto skip_statistics_parse;

	cJSON_ArrayForEach(statistics_type, statistics_types) {
		if (!cJSON_GetStringValue(statistics_type)) {
			UC_LOG_ERR("Unexpected type of <statistics>:<type>: Object expected");
			continue;
		}

		if (!strcmp(cJSON_GetStringValue(statistics_type), "clients"))
			cfg->metrics.state.clients_enabled = true;

		if (!strcmp(cJSON_GetStringValue(statistics_type), "lldp"))
			cfg->metrics.state.lldp_enabled = true;
	}

	/* Interval >0 == enabled. */
	cfg->metrics.state.interval = (size_t)cJSON_GetNumberValue(interval);
	cfg->metrics.state.enabled = (bool)cJSON_GetNumberValue(interval);

	if (cJSON_IsNumber(max_mac_count))  /** TODO: validate number */
		cfg->metrics.state.max_mac_count = (unsigned)cJSON_GetNumberValue(max_mac_count);
	else
		cfg->metrics.state.max_mac_count = METRICS_WIRED_CLIENTS_MAX_NUM;

	if (cfg->metrics.state.enabled && !cfg->metrics.state.lldp_enabled &&
	    cfg->metrics.state.clients_enabled) {
		UC_LOG_ERR("Received statistics cfg with interval, but no type specified. Defaulting to <disable> state event");
		log_send("<configure>:<metrics> holds invalid data, <state> event disabled",
			 LOG_ERR);
		memset(&cfg->metrics.state, 0, sizeof(cfg->metrics.state));
		goto skip_statistics_parse;
	}

skip_statistics_parse:
	health = cJSON_GetObjectItemCaseSensitive(metrics, "health");
	interval = cJSON_GetObjectItemCaseSensitive(health, "interval");
	if (!health || !interval)
		goto skip_health_parse;

	cfg->metrics.healthcheck.interval = (size_t)cJSON_GetNumberValue(interval);
	cfg->metrics.healthcheck.enabled = (bool)cJSON_GetNumberValue(interval);

skip_health_parse:
	return 0;
}

static int cfg_unit_parse(cJSON *unit, struct plat_cfg *cfg)
{
	cJSON *usage_threshold;
	cJSON *power_mgmt;
	cJSON *password;
	cJSON *poe;

	if ((poe = cJSON_GetObjectItemCaseSensitive(unit, "poe"))) {
		power_mgmt = cJSON_GetObjectItemCaseSensitive(poe, "power-management");
		usage_threshold = cJSON_GetObjectItemCaseSensitive(poe, "usage-threshold");

		if (cJSON_GetStringValue(power_mgmt)) {
			strcpy(cfg->unit.poe.power_mgmt, cJSON_GetStringValue(power_mgmt));
			cfg->unit.poe.is_power_mgmt_set = true;
		}

		if (cJSON_IsNumber(usage_threshold)) {
			cfg->unit.poe.usage_threshold =
				(uint8_t)cJSON_GetNumberValue(usage_threshold);
			cfg->unit.poe.is_usage_threshold_set = true;
		}
	}

	if ((password = cJSON_GetObjectItemCaseSensitive(unit, "system-password"))) {
		strncpy(cfg->unit.system.password, password->valuestring,
			sizeof(cfg->unit.system.password));
		cfg->unit.system.password_changed = true;
	}

	return 0;
}

static struct plat_cfg * cfg_parse(cJSON *config)
{
	struct plat_ports_list *port_node = NULL;
	struct plat_ports_list *ports = NULL;
	struct plat_cfg *cfg = NULL;
	uint16_t num_of_active_ports;
	size_t num_of_vlans_cfg = 0;
	size_t num_of_eths_cfg = 0;
	cJSON *interfaces = NULL;
	cJSON *interface = NULL;
	cJSON *ethernet = NULL;
	char *public_ip_lookup;
	cJSON *metrics = NULL;
	cJSON *services = NULL;
	cJSON *unit = NULL;
	cJSON *eth = NULL;
	size_t i;
	int ret;

	ethernet = cJSON_GetObjectItemCaseSensitive(config, "ethernet");
	if (!ethernet || !cJSON_IsArray(ethernet))
		goto err;

	interfaces = cJSON_GetObjectItemCaseSensitive(config, "interfaces");
	if (!interfaces || !cJSON_IsArray(interfaces))
		goto err;

	services = cJSON_GetObjectItemCaseSensitive(config, "services");
	if (services && !cJSON_IsObject(services))
		goto err;

	/* It's OK for metrics to be missing. It's not expected for metrics
	 * to have any other type rather than <object>.
	 */
	metrics = cJSON_GetObjectItemCaseSensitive(config, "metrics");
	if (metrics && !cJSON_IsObject(metrics))
		goto err;

	unit = cJSON_GetObjectItemCaseSensitive(config, "unit");
	if (unit && !cJSON_IsObject(unit))
		goto err;

	cJSON_ArrayForEach(eth, ethernet)
		num_of_eths_cfg++;

	cJSON_ArrayForEach(interface, interfaces)
		num_of_vlans_cfg++;

	UC_LOG_DBG("Num of nested requested cfg changes: vlans: %lu, eth: %lu\n",
		   num_of_vlans_cfg, num_of_eths_cfg);

	cfg = calloc(1, sizeof(*cfg));
	if (!cfg) {
		UC_LOG_ERR("Failed to alloc CFG struct, parse failed\n");
		return NULL;
	}

	/* Make sure we fill in ID and name for all ports:
	 * in case if ports are not selected (not specified in
	 * <ethernet>:<select_ports>, force <reset> of the given port
	 * (negative case), to do so at least ID and name should be filled in.
	 */
	ret = __get_port_list(&ports, &num_of_active_ports);
	if (ret) {
		UC_LOG_ERR("Fetch ports list failed\n");
		free(cfg);
		return NULL;
	}
	UCENTRAL_LIST_FOR_EACH_MEMBER(port_node, &ports) {
		uint16_t pid;

		NAME_TO_PID(&pid, port_node->name);
		strcpy(cfg->ports[pid].name, port_node->name);
		cfg->ports[pid].fp_id = pid;
		BITMAP_SET_BIT(cfg->ports_to_cfg, pid);
	}
	__put_port_list(&ports);

	for (i = FIRST_VLAN; i < MAX_VLANS; ++i)
		cfg->vlans[i].id = i;

	/* First step of parsing: iterate over each port in
	 * ethernet: select-ports section to determine which port's state
	 * should be altered;
	 */
	if (cfg_ethernet_parse(ethernet, cfg)) {
		UC_LOG_ERR("Failed parse 'ethernet', parse failed\n");
		goto err_parse;
	}

	/* Second step of parsing: determine which vlans are configured and
	 * associate vlans:port map, e.g. which ports should be added to
	 * what vlans.
	 *
	 * At this stage update (populate) each vlan's port member list.
	 */
	if (cfg_interfaces_parse(interfaces, cfg)) {
		UC_LOG_ERR("Failed parse 'interfaces', parse failed\n");
		goto err_parse;
	}

	if (cfg_switch_parse(config, cfg)) {
		UC_LOG_ERR("Failed parse switch config\n");
		goto err_parse;
	}

	/* Parse metrics data configuration: which <events> (healthcheck / state
	 * should be enabled) and what data should be sent (for example:
	 * should <state> hold LLDP peers info as well?). Configure
	 * requested timeouts and start sending events (if any).
	 *
	 * In case if <metrics> is not present in configure request,
	 * it's still okay to zero-out all metrics, as timeout == 0
	 * means also <disabled>. Also, it's not expected to have
	 * any <telemetry> events pending by this stage, as GW
	 * can't expect any <telemetry> events and do <configure>
	 * in parallel.
	 */
	if (metrics && cfg_metrics_parse(metrics, cfg)) {
		UC_LOG_ERR("Failed parse 'metrics', parse failed\n");
		goto err_parse;
	} else if (!metrics) {
		memset(&cfg->metrics, 0, sizeof(cfg->metrics));
	}

	if (services && cfg_services_parse(services, cfg)) {
		UC_LOG_ERR("Failed parse 'services', parse failed\n");
		goto err_parse;
	}

	if (unit && cfg_unit_parse(unit, cfg)) {
		UC_LOG_ERR("Failed parse 'unit', parse failed\n");
		goto err_parse;
	}

	/* We could do config segment based parsing or feature based
	 *  - if we decide to do segment based - than router parsing logic will
	 * be spreaded on two functions (globals, interfaces).
	 *  - on other hand we has feature based parsing. So, if router
	 *  supported on our device - it will parsed with only one function
	 */
	if (cfg_router_parse(config, cfg)) {
		UC_LOG_ERR("Failed parse router\n");
		goto err_parse;
	}

	public_ip_lookup =
		cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(config, "public_ip_lookup"));
	strcpy(&cfg->metrics.state.public_ip_lookup[0],
	       public_ip_lookup ? public_ip_lookup : "");

	return cfg;

err_parse:
	/* TODO: free all ports->vlans as well */
	free(cfg->log_cfg);
	free(cfg);
	return NULL;

err:
	UC_LOG_ERR("JSON config parse failed\n");
	return NULL;
}

static void
configure_handle(cJSON **rpc)
{
	static struct plat_cfg *plat_cfg;
	cJSON *tb[__PARAMS_MAX] = {0};
	char *log_msg;
	double id = 0;
	int ret = 0;

	tb[PARAMS_SERIAL] =
		cJSON_GetObjectItemCaseSensitive(rpc[JSONRPC_PARAMS], "serial");
	tb[PARAMS_UUID] =
		cJSON_GetObjectItemCaseSensitive(rpc[JSONRPC_PARAMS], "uuid");
	tb[PARAMS_COMMAND] =
		cJSON_GetObjectItemCaseSensitive(rpc[JSONRPC_PARAMS], "command");
	tb[PARAMS_CONFIG] =
		cJSON_GetObjectItemCaseSensitive(rpc[JSONRPC_PARAMS], "config");
	tb[PARAMS_PAYLOAD] =
		cJSON_GetObjectItemCaseSensitive(rpc[JSONRPC_PARAMS], "payload");
	tb[PARAMS_REJECTED] =
		cJSON_GetObjectItemCaseSensitive(rpc[JSONRPC_PARAMS], "rejected");
	tb[PARAMS_COMPRESS] =
		cJSON_GetObjectItemCaseSensitive(rpc[JSONRPC_PARAMS], "compress");

	if (rpc[JSONRPC_ID])
		id = cJSON_GetNumberValue(rpc[JSONRPC_ID]);

	if (!tb[PARAMS_UUID] || !tb[PARAMS_SERIAL] || !tb[PARAMS_CONFIG]) {
		UC_LOG_ERR("configure message is missing parameters\n");
		configure_reply(CONFIGURE_STATUS_REJECTED, "invalid parameters", 0, id);
		return;
	}

	if (tb[PARAMS_COMPRESS]) {
		if (cJSON_IsBool(tb[PARAMS_COMPRESS]))
			state_compress = cJSON_IsTrue(tb[PARAMS_COMPRESS]);
		else {
			/* TODO: handle? */
			;
		}
	}

	uuid_latest = cJSON_GetNumberValue(tb[PARAMS_UUID]);

	plat_cfg = cfg_parse(tb[PARAMS_CONFIG]);
	if (!plat_cfg) {
		UC_LOG_ERR("configure parse failed");
		configure_reply(CONFIGURE_STATUS_REJECTED,
				"Configure parse failed", 0, id);
		return;
	}

	plat_log_flush();
	ret = plat_config_apply(plat_cfg, id);
	if (ret) {
		UC_LOG_ERR("Config apply failed. Trying to restore.\n");
		plat_config_restore();
		goto err_apply;
	} else {
		/* TODO(vb) try to reconnect to the could before replying (callback?) */
		uuid_active = uuid_latest;
		plat_config_save(uuid_active);
		plat_metrics_save(&plat_cfg->metrics);
	}

	if (plat_cfg->unit.system.password_changed)
		deviceupdate_send(plat_cfg->unit.system.password);

	/* Apply metrics config. We got parsed cfg->metrics and now we need
	 * to copy all data to ucentral_metrics struct to read from
	 * periodic handlers. So ensure, that no periodic in progress and
	 * than update global struct.
	 * Also note, that plat_state_poll calls periodic_destroy. So it is
	 * OK to stop all explicity.
	 */
	plat_state_poll_stop();
	plat_health_poll_stop();
	plat_telemetry_poll_stop();
	memcpy(&ucentral_metrics, &plat_cfg->metrics, sizeof(ucentral_metrics));

	if (ucentral_metrics.state.enabled)
		plat_state_poll(state_send, ucentral_metrics.state.interval);

	if (ucentral_metrics.healthcheck.enabled)
		plat_health_poll(health_send,
				 ucentral_metrics.healthcheck.interval);

	if (ucentral_metrics.telemetry.enabled)
		plat_telemetry_poll(telemetry_send,
				    ucentral_metrics.telemetry.interval);

err_apply:
	plat_config_destroy(plat_cfg);

	free(plat_cfg->log_cfg);
	free(plat_cfg);

	log_msg = plat_log_pop_concatenate();
	configure_reply((ret ? CONFIGURE_STATUS_REJECTED :
				     CONFIGURE_STATUS_APPLIED),
			log_msg ? log_msg : "", uuid_latest, id);
	free(log_msg);

	UC_LOG_DBG("Applied %010lu. Active %010lu.\n", uuid_latest, uuid_active);
}

static void
reboot_handle(cJSON **rpc)
{
	cJSON *tb[__PARAMS_MAX] = {0};
	double id = 0;

	tb[PARAMS_SERIAL] =
		cJSON_GetObjectItemCaseSensitive(rpc[JSONRPC_PARAMS], "serial");

	if (rpc[JSONRPC_ID])
		id = cJSON_GetNumberValue(rpc[JSONRPC_ID]);

	if (!tb[PARAMS_SERIAL]) {
		UC_LOG_ERR("reboot message is missing parameters\n");
		action_reply(1, "invalid parameters", 1, id);
		return;
	}

	if (plat_reboot()) {
		UC_LOG_ERR("reboot failed\n");
		action_reply(1, "reboot failed", 1, id);
		return;
	}

	action_reply(0, "Reboot requested successfully", 0, id);
	UC_LOG_DBG("Reboot OK\n");
}

static void
factory_handle(cJSON **rpc)
{
	cJSON *tb[__PARAMS_MAX] = {0};
	double id = 0;

	tb[PARAMS_SERIAL] =
		cJSON_GetObjectItemCaseSensitive(rpc[JSONRPC_PARAMS], "serial");
	/* Currently unused; rework needed for <redirector parse>/ save logic */
	tb[PARAMS_FACTORY_KEEP_REDIRECTOR] =
		cJSON_GetObjectItemCaseSensitive(rpc[JSONRPC_PARAMS],
						 "keep_redirectory");

	if (rpc[JSONRPC_ID])
		id = cJSON_GetNumberValue(rpc[JSONRPC_ID]);

	if (!tb[PARAMS_SERIAL]) {
		UC_LOG_ERR("factory message is missing parameters\n");
		action_reply(1, "invalid parameters", 1, id);
		return;
	}

	if (plat_factory_default()) {
		UC_LOG_ERR("factory failed\n");
		action_reply(1, "factory failed", 1, id);
		return;
	}

	action_reply(0, "factory requested successfully", 0, id);
	UC_LOG_DBG("factory OK\n");
}

static void
ping_handle(cJSON **rpc)
{
	struct blob blob = {0};
	cJSON *status;
	double id = 0;
	cJSON *res;

	UC_LOG_DBG("Ping received\n");

	if (rpc[JSONRPC_ID])
		id = cJSON_GetNumberValue(rpc[JSONRPC_ID]);

	blob.obj = result_new_blob(id, uuid_active);

	if (!(res = cJSON_GetObjectItemCaseSensitive(blob.obj, "result")))
		goto err;

	if (!(status = cJSON_AddObjectToObject(res, "status")))
		goto err;

	if (!cJSON_AddStringToObject(status, "text", "Success"))
		goto err;

	if (!cJSON_AddNumberToObject(status, "error", 0))
		goto err;

	result_send_blob(&blob);
	proto_destroy_blob(&blob);

	return;
err:
	UC_LOG_ERR("JSON obj alloc failed\n");
	proto_destroy_blob(&blob);
}

static struct plat_rtty_cfg * rtty_parse(cJSON *rtty_params)
{
	struct plat_rtty_cfg *rtty_cfg = NULL;
	cJSON *timeout;
	cJSON *passwd;
	cJSON *serial;
	cJSON *server;
	cJSON *token;
	cJSON *port;
	cJSON *user;
	cJSON *id;

	if (!(serial = cJSON_GetObjectItemCaseSensitive(rtty_params, "serial")))
		goto err;

	if (!(token = cJSON_GetObjectItemCaseSensitive(rtty_params, "token")))
		goto err;

	if (!(id = cJSON_GetObjectItemCaseSensitive(rtty_params, "id")))
		goto err;

	if (!(server = cJSON_GetObjectItemCaseSensitive(rtty_params, "server")))
		goto err;

	if (!(port = cJSON_GetObjectItemCaseSensitive(rtty_params, "port")))
		goto err;

	if (!(user = cJSON_GetObjectItemCaseSensitive(rtty_params, "user")))
		goto err;

	if (!(timeout = cJSON_GetObjectItemCaseSensitive(rtty_params,
							 "timeout")))
		goto err;

	if (!(passwd = cJSON_GetObjectItemCaseSensitive(rtty_params,
							"password")))
		goto err;

	rtty_cfg = calloc(1, sizeof(*rtty_cfg));
	if (!rtty_cfg) {
		UC_LOG_ERR("Failed to alloc rtty conf struct\n");
		return NULL;
	}

	strcpy(rtty_cfg->id, cJSON_GetStringValue(id));
	strcpy(rtty_cfg->passwd, cJSON_GetStringValue(passwd));
	strcpy(rtty_cfg->serial, cJSON_GetStringValue(serial));
	strcpy(rtty_cfg->server, cJSON_GetStringValue(server));
	strcpy(rtty_cfg->token, cJSON_GetStringValue(token));
	strcpy(rtty_cfg->user, cJSON_GetStringValue(user));
	rtty_cfg->port = (uint16_t)cJSON_GetNumberValue(port);
	rtty_cfg->timeout = (uint16_t)cJSON_GetNumberValue(timeout);

	return rtty_cfg;

err:
	UC_LOG_ERR("Failed to parse RTTY params\n");
	return NULL;
}

static void
rtty_handle(cJSON **rpc)
{
	struct plat_rtty_cfg *rtty_cfg = NULL;
	struct blob blob = {0};
	cJSON *status;
	double id = 0;
	cJSON *res;

	UC_LOG_DBG("RTTY request received\n");

	if (rpc[JSONRPC_ID])
		id = cJSON_GetNumberValue(rpc[JSONRPC_ID]);

	blob.obj = result_new_blob(id, uuid_active);

	if (!(res = cJSON_GetObjectItemCaseSensitive(blob.obj, "result")))
		goto err;

	if (!(status = cJSON_AddObjectToObject(res, "status")))
		goto err;

	if (!cJSON_AddStringToObject(status, "text", "Success"))
		goto err;

	if (!cJSON_AddNumberToObject(status, "error", 0))
		goto err;

	rtty_cfg = rtty_parse(rpc[JSONRPC_PARAMS]);
	if (!rtty_cfg) {
		UC_LOG_ERR("RTTY command parse failed\n");
		action_reply(1, "RTTY cmd parse failed", 1, id);
		proto_destroy_blob(&blob);
		return;
	}

	if (plat_rtty(rtty_cfg)) {
		UC_LOG_ERR("RTTY command execution failed\n");
		action_reply(1, "RTTY cmd execution failed", 1, id);
		proto_destroy_blob(&blob);
		return;
	}

	result_send_blob(&blob);
	proto_destroy_blob(&blob);

	return;
err:
	UC_LOG_ERR("JSON obj alloc failed\n");
	proto_destroy_blob(&blob);
}

int upgrade_status_send(struct plat_upgrade_info *upgrade)
{
	static enum upgrade_status last_operation = 0;

	/* Handle namin as part of defined proto */
	switch (upgrade->operation) {
	case UCENTRAL_UPGRADE_STATE_IDLE:
		event_firmware_upgrade_send("idle", -1 /* unused */, NULL);
		last_operation = upgrade->operation;
		break;
	case UCENTRAL_UPGRADE_STATE_DOWNLOAD:
		event_firmware_upgrade_send("download", upgrade->percentage,
					    NULL);
		last_operation = upgrade->operation;
		break;
	case UCENTRAL_UPGRADE_STATE_INSTALL:
		event_firmware_upgrade_send("install", -1 /* unused */, NULL);
		last_operation = upgrade->operation;
		break;
	case UCENTRAL_UPGRADE_STATE_FAIL:
		event_firmware_upgrade_send("fail", -1 /* unused */, NULL);
		last_operation = upgrade->operation;
		return 1;
	case UCENTRAL_UPGRADE_STATE_SUCCESS:
		if (last_operation == UCENTRAL_UPGRADE_STATE_DOWNLOAD)
			event_firmware_upgrade_send("install", -1 /* unused */, NULL);

		event_firmware_upgrade_send("success", -1 /* unused */, NULL);
		UC_LOG_DBG("upgrade OK\n");
		/* once instalation finished - reboot device */
		if (plat_reboot())
			UC_LOG_ERR("reboot failed\n");

		return 1;
	default:
		UC_LOG_ERR("Got unsupported upgrade state (%d)\n",
			   upgrade->operation);
		break; /* UNSUPPORTED state */
	}

	return 0;
}

static void
upgrade_handle(cJSON **rpc)
{
	cJSON *serial, *uri, *sign;
	char *parsed_uri;
	double id = 0;

	if (rpc[JSONRPC_ID])
		id = cJSON_GetNumberValue(rpc[JSONRPC_ID]);

	serial = cJSON_GetObjectItemCaseSensitive(rpc[JSONRPC_PARAMS], "serial");
	if (!serial) {
		UC_LOG_ERR("upgrade message is missing serial\n");
		action_reply(1, "invalid parameters", 1, id);
		return;
	}

	/* TODO keep_redirector */
#if 0
	cJSON_GetObjectItemCaseSensitive(rpc[JSONRPC_PARAMS],
					 "keep_redirector");
#endif

	uri = cJSON_GetObjectItemCaseSensitive(rpc[JSONRPC_PARAMS], "uri");
	if (!uri) {
		UC_LOG_ERR("upgrade message is missing uri\n");
		action_reply(1, "invalid parameters", 1, id);
		return;
	}

	parsed_uri = cJSON_GetStringValue(uri);
	if (!parsed_uri) {
		UC_LOG_ERR("upgrade message has invalid uril\n");
		action_reply(1, "invalid parameters", 1, id);
		return;
	}

	sign = cJSON_GetObjectItemCaseSensitive(rpc[JSONRPC_PARAMS], "FWsignature");
	if (plat_upgrade(parsed_uri,
			 sign ? cJSON_GetStringValue(sign) : NULL)) {
		UC_LOG_ERR("upgrade failed\n");
		action_reply(1, "upgrade failed", 1, id);
		return;
	}

	action_reply(0, "upgrade requested successfully", 0, id);

	/* Poll upgrade state - start periodical. */
	plat_upgrade_poll(upgrade_status_send, 1);
}

static void
telemetry_handle(cJSON **rpc)
{
	cJSON *tb[__PARAMS_MAX] = {0};
	double interval = 0;
	double id = 0;

	tb[PARAMS_SERIAL] =
		cJSON_GetObjectItemCaseSensitive(rpc[JSONRPC_PARAMS], "serial");
	tb[PARAMS_TELEMETRY_INTERVAL] =
		cJSON_GetObjectItemCaseSensitive(rpc[JSONRPC_PARAMS], "interval");
	/* TBD: parse any other <telemetry> types (currently only STATE
	 * is supported)
	 */
	tb[PARAMS_TELEMETRY_TYPES] =
		cJSON_GetObjectItemCaseSensitive(rpc[JSONRPC_PARAMS], "types");

	if (rpc[JSONRPC_ID])
		id = cJSON_GetNumberValue(rpc[JSONRPC_ID]);

	if (tb[PARAMS_TELEMETRY_INTERVAL])
		interval = cJSON_GetNumberValue(tb[PARAMS_TELEMETRY_INTERVAL]);

	if (!tb[PARAMS_SERIAL] || (interval && !tb[PARAMS_TELEMETRY_TYPES])) {
		UC_LOG_ERR("Telemetry message is missing parameters\n");
		action_reply(1, "invalid parameters", 1, id);
		return;
	}

	plat_telemetry_poll_stop();

	ucentral_metrics.telemetry.interval = (size_t)interval;
	/* Interval 0 == disable telemetry streaming */
	ucentral_metrics.telemetry.enabled = (bool)interval;

	if (ucentral_metrics.telemetry.enabled) {
		plat_telemetry_poll(telemetry_send,
				    ucentral_metrics.telemetry.interval);
	}

	action_reply(0, "Telemetry configure requested successfully", 0, id);
	UC_LOG_DBG("Telemetry configure OK\n");
}

static int curl_upload_diagnostic_form(const char *url, const char *file_path)
{
    struct curl_httppost *post = NULL, *last = NULL;
    CURLcode res;
    int ret = 0;
    CURL *curl;

    curl = curl_easy_init();
    if(curl) {
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_formadd(&post,
		     &last,
		     CURLFORM_COPYNAME, "name",
		     CURLFORM_COPYCONTENTS, client.serial,
		     CURLFORM_END);
	curl_formadd(&post,
		     &last,
		     CURLFORM_COPYNAME, "data",
		     CURLFORM_FILE, file_path,
		     CURLFORM_END);
	curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);
	res = curl_easy_perform(curl);

	if(res != CURLE_OK) {
		ret = -1;
		UC_LOG_ERR("Uploading diagnostic failed. URL=%s FILE=%s res=%d \n",
			   url, file_path, res);
	}

	curl_easy_cleanup(curl);
	curl_formfree(post);
    }

    return ret;
}

static int curl_upload_form(char *url, const void *buf)
{
	CURLcode res;
	CURL *curl;
	curl_mimepart *part;
	curl_mime *multipart = 0;
	int rc = -1;

	curl = curl_easy_init();
	if (!curl)
		return -1;

	multipart = curl_mime_init(curl);
	if (!multipart)
		goto exit;

	if (!(part = curl_mime_addpart(multipart)))
		goto exit;
	curl_mime_name(part, "name");
	curl_mime_data(part, client.serial, CURL_ZERO_TERMINATED);

	if (!(part = curl_mime_addpart(multipart)))
		goto exit;
	curl_mime_name(part, "data");
	curl_mime_filename(part, "output.txt");
	curl_mime_type(part, "application/octet-stream");
	curl_mime_data(part, buf, CURL_ZERO_TERMINATED);

	curl_easy_setopt(curl, CURLOPT_MIMEPOST, multipart);
	curl_easy_setopt(curl, CURLOPT_URL, url);

	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		UC_LOG_ERR("Uploading script output failed. URL=%s res=%d \n",
			   url, res);
		goto exit;
	}

	rc = 0;
exit:
	curl_mime_free(multipart);
	curl_easy_cleanup(curl);

	return rc;
}

static void script_result_cb(int err, struct plat_run_script_result *sres,
			     void *ctx)
{
	uint32_t e;
	const char *result;
	struct proto_script_ctx *c = ctx;

	if (err) {
		action_reply(1, "failed to execute script", 1, c->id);
		goto exit;
	}

	e = (sres->timeout_exceeded ? 255 : sres->exit_status);
	result = sres->stdout_string;
	if (c->uri) {
		if (sres->timeout_exceeded)
			result = "timed out";
		else if (sres->exit_status)
			result = "error";
		else
			result = "done";
	}

	if (c->uri && curl_upload_form(c->uri, sres->stdout_string)) {
		UC_LOG_ERR("upload failed");
	}

	script_reply(e, result, (int32_t)c->id);

exit:
	free(c->uri);
	free(c);
}

static void script_plat_handle(const char *script, const char *type,
			       const char *uri, const int64_t *timeout,
			       double id)
{
	struct plat_run_script p = { 0 };
	struct proto_script_ctx *c = 0;
	if (!(c = malloc(sizeof(struct proto_script_ctx))))
		return;

	*c = (struct proto_script_ctx){ .id = id };
	if (uri)
		c->uri = strdup(uri);

	p.ctx = c;
	p.cb = script_result_cb;
	p.timeout = timeout ? *timeout : (int64_t)30;
	p.type = type;
	p.script_base64 = script;

	if (plat_run_script(&p)) {
		free(c->uri);
		free(c);
		UC_LOG_ERR("plat_run_script failed");
		action_reply(1, "failed to start execution", 1, id);
		return;
	}

	if (c->uri)
		script_reply(0, "pending", id);
}

static void script_handle(cJSON **rpc)
{
	int64_t t;
	const char *script, *serial, *type, *uri_str;
	cJSON *timeout, *uri;
	double id = 0;

	serial = jobj_str_get(rpc[JSONRPC_PARAMS], "serial");
	script = jobj_str_get(rpc[JSONRPC_PARAMS], "script");
	type = jobj_str_get(rpc[JSONRPC_PARAMS], "type");
	timeout = cJSON_GetObjectItemCaseSensitive(rpc[JSONRPC_PARAMS], "timeout");
	uri = cJSON_GetObjectItemCaseSensitive(rpc[JSONRPC_PARAMS], "uri");

	if (rpc[JSONRPC_ID])
		id = cJSON_GetNumberValue(rpc[JSONRPC_ID]);

	if (!serial || !type || (timeout && !cJSON_IsNumber(timeout)) ||
	    (uri && !cJSON_IsString(uri))) {
		action_reply(1, "invalid parameters", 1, id);
		return;
	}
	uri_str = cJSON_GetStringValue(uri);
	t = cJSON_GetNumberValue(timeout);

	if (!strcmp("diagnostic", type)) {
		char file_path[PATH_MAX + 1];
		if (!uri_str) {
			UC_LOG_ERR("script message missing 'uri' parameter");
			return;
		}

		script_reply(0, "pending", id);
		UC_LOG_DBG("Script requested OK (pending. Waiting for plat to execute)\n");

		memset(&file_path[0], 0, sizeof(file_path));
		if (plat_diagnostic(&file_path[0])) {
			UC_LOG_ERR("Script failed\n");
			script_reply(1, "fail", id);
			return;
		}

		/* Poll upgrade state - start periodical. */
		while (access(file_path, F_OK))
			sleep(1);

		/* Send file to server */
		if (curl_upload_diagnostic_form(uri_str, file_path)) {
			UC_LOG_ERR("Upload failed\n");
			script_reply(1, "fail", id);
			return;
		}
		script_reply(0, "done", id);
		return;
	}

	if (!script) {
		action_reply(1, "invalid parameters", 1, id);
		return;
	}
	script_plat_handle(script, type, uri_str, timeout ? &t : 0, id);
}

static void
generic_handle(cJSON **rpc)
{
	struct blob blob = {0};
	const char *method;
	cJSON *status;
	double id = 0;
	cJSON *res;

	if (rpc[JSONRPC_ID])
		id = cJSON_GetNumberValue(rpc[JSONRPC_ID]);

	if (rpc[JSONRPC_METHOD])
		method = cJSON_GetStringValue(rpc[JSONRPC_METHOD]);

	UC_LOG_DBG("'%s' received, not implemented...using generic handler\n", method);

	blob.obj = result_new_blob(id, uuid_active);

	if (!(res = cJSON_GetObjectItemCaseSensitive(blob.obj, "result")))
		goto err;

	if (!(status = cJSON_AddObjectToObject(res, "status")))
		goto err;

	if (!cJSON_AddStringToObject(status, "text", "Success"))
		goto err;

	if (!cJSON_AddNumberToObject(status, "error", 0))
		goto err;

	result_send_blob(&blob);
	proto_destroy_blob(&blob);

	return;
err:
	UC_LOG_ERR("JSON obj alloc failed\n");
	proto_destroy_blob(&blob);
}

void ping_send(void)
{
	struct blob blob = {0};
	cJSON *params;

	blob.obj = proto_new_blob("ping");
	if (!blob.obj)
		goto err;

	params = cJSON_GetObjectItemCaseSensitive(blob.obj, "params");
	if (!params)
		goto err;

	if (!cJSON_AddStringToObject(params, "serial", client.serial))
		goto err;

	if (uuid_active != uuid_latest) {
		if (!cJSON_AddNumberToObject(params, "uuid",
					     (double)uuid_active))
			goto err;
		if (!cJSON_AddNumberToObject(params, "uuid",
					     (double)uuid_latest))
			goto err;
	} else {
		if (!cJSON_AddNumberToObject(params, "uuid",
					     (double)uuid_latest))
			goto err;
	}
	UC_LOG_DBG("xmit ping\n");

	proto_send_blob(&blob);
	proto_destroy_blob(&blob);

	return;

err:
	UC_LOG_ERR("JSON obj alloc failed\n");
	proto_destroy_blob(&blob);
}

void health_send(struct plat_health_info *health)
{
	int i;
	struct blob blob = {0};
	cJSON *params;
	cJSON *data;
	cJSON *messages;

	blob.obj = proto_new_blob("healthcheck");
	if (!blob.obj)
		goto err;

	params = cJSON_GetObjectItemCaseSensitive(blob.obj, "params");
	if (!params)
		goto err;

	if (!cJSON_AddStringToObject(params, "serial", client.serial))
		goto err;

	if (!cJSON_AddNumberToObject(params, "uuid", (double)uuid_active))
		goto err;

	if (!cJSON_AddNumberToObject(params, "sanity", (double)health->sanity))
		goto err;

	data = cJSON_AddObjectToObject(params, "data");
	if (!data)
		goto err;

	messages = cJSON_AddArrayToObject(data, "messages");
	for (i = 0; i < HEALTHCHEK_MESSAGE_MAX_COUNT; ++i) {
		cJSON *msg;

		if (!strlen(health->msg[i]))
			continue;

		msg = cJSON_CreateString(health->msg[i]);
		if (!cJSON_AddItemToArray(messages, msg)) {
			cJSON_Delete(msg);
			goto err;
		}
	}
	UC_LOG_DBG("xmit healthcheck \n");

	proto_send_blob(&blob);
	proto_destroy_blob(&blob);

	return;

err:
	UC_LOG_ERR("JSON obj alloc failed\n");
	proto_destroy_blob(&blob);
}

static int state_fill_interface_ipv4(cJSON *ipv4, struct plat_port_info *info)
{
	(void)ipv4;
	(void)info;
	/* TBD */
#if 0
	const char *ipv4_addresses_arr[] = { "192.168.1.228/24" };

	if (!cJSON_AddStringToObject(ipv4, "dhcp_server", "192.168.1.1"))
		goto err;

	if (!cJSON_AddNumberToObject(ipv4, "leasetime", (double)86400))
		goto err;

	ipv4_addresses = cJSON_CreateStringArray(ipv4_addresses_arr, 1);
	if (!ipv4_addresses)
		goto err;

	if (!cJSON_AddItemToObject(ipv4, "addresses", ipv4_addresses))
		goto err;
#endif
	return 0;
}

static int state_fill_interface_dns_servers(cJSON *dns_servers,
					    struct plat_port_info *port_info)
{
	(void)dns_servers;
	(void)port_info;

	/* TBD */
#if 0
	const char *dns_servers_arr[] = { "192.168.1.1" };

	if (!cJSON_AddItemToArray(dns_servers,
				  cJSON_CreateString(dns_servers_arr[0])))
		goto err;
#endif
	return 0;
}

static int state_fill_interface_clients(cJSON *clients,
					struct plat_port_info *port_info)
{
	(void)clients;
	(void)port_info;
	/* TBD */
	return 0;
}

static int state_fill_interface_counters(cJSON *counters,
					 struct plat_port_counters *stats)
{
	/* Fill-in created "counters" obj */
	if (!cJSON_AddNumberToObject(counters, "collisions", stats->collisions))
		goto err;

	if (!cJSON_AddNumberToObject(counters, "multicast", stats->multicast))
		goto err;

	if (!cJSON_AddNumberToObject(counters, "rx_bytes", stats->rx_bytes))
		goto err;

	if (!cJSON_AddNumberToObject(counters, "rx_dropped", stats->rx_dropped))
		goto err;

	if (!cJSON_AddNumberToObject(counters, "rx_error", stats->rx_error))
		goto err;

	if (!cJSON_AddNumberToObject(counters, "rx_packets", stats->rx_packets))
		goto err;

	if (!cJSON_AddNumberToObject(counters, "tx_bytes", stats->tx_bytes))
		goto err;

	if (!cJSON_AddNumberToObject(counters, "tx_dropped", stats->tx_dropped))
		goto err;

	if (!cJSON_AddNumberToObject(counters, "tx_error", stats->tx_error))
		goto err;

	if (!cJSON_AddNumberToObject(counters, "tx_packets", stats->tx_packets))
		goto err;

	return 0;

err:
	return -1;
}

static int state_fill_interfaces_data(cJSON *interfaces,
				      struct plat_state_info *state)
{
	cJSON *dns_servers;
	cJSON *interface;
	cJSON *counters;
	cJSON *clients;
	cJSON *ipv4;
	int ret;
	int i;

	/* For each port fill in:
	 *  - clients
	 *  - counters
	 *  - dns_servers
	 *  - ipv4
	 */
	for (i = 0; i < state->port_info_count; ++i) {
		interface = cJSON_CreateObject();
		if (!interface)
			goto err;

		if (!cJSON_AddItemToArray(interfaces, interface))
			goto err;

		clients = cJSON_AddArrayToObject(interface, "clients");
		if (!clients)
			goto err;

		counters = cJSON_AddObjectToObject(interface, "counters");
		if (!counters)
			goto err;

		dns_servers = cJSON_AddArrayToObject(interface, "dns_servers");
		if (!dns_servers)
			goto err;

		ipv4 = cJSON_AddObjectToObject(interface, "ipv4");
		if (!ipv4)
			goto err;

		ret = state_fill_interface_clients(clients,
						   &state->port_info[i]);
		if (ret)
			goto err;

		ret = state_fill_interface_counters(counters,
						    &state->port_info[i].stats);
		if (ret)
			goto err;

		ret = state_fill_interface_dns_servers(dns_servers,
						       &state->port_info[i]);
		if (ret)
			goto err;

		ret = state_fill_interface_ipv4(ipv4, &state->port_info[i]);
		if (ret)
			goto err;

		if (!cJSON_AddStringToObject(interface, "name",
					     state->port_info[i].name)) {
			goto err;
		}

		/* TBD: find out (?) proper <location> */
		{
			char location[] = { "/interfaces/XXXX" };
			uint16_t pid;

			NAME_TO_PID(&pid, state->port_info[i].name);
			sprintf(location, "/interfaces/%hu", pid);

			if (!cJSON_AddStringToObject(interface, "location",
						     location))
				goto err;
		}

		if (!jobj_u64_set(interface, "uptime",
				  state->system_info.uptime))
			goto err;
	}

	return 0;
err:
	return -1;
}

static int
state_fill_link_state_poe_data(cJSON *port,
			       struct plat_poe_port_state *poe_port_state)
{
	cJSON *counters;
	cJSON *poe;

	poe = cJSON_AddObjectToObject(port, "poe");
	if (!poe)
		goto err;

	counters = cJSON_AddObjectToObject(poe, "counters");
	if (!counters)
		goto err;

	if (!cJSON_AddNumberToObject(poe, "class-requested",
				     poe_port_state->class_requested))
		goto err;

	if (!cJSON_AddNumberToObject(poe, "class-assigned",
				     poe_port_state->class_assigned))
		goto err;

	if (!cJSON_AddNumberToObject(poe, "output-power",
				     poe_port_state->output_power))
		goto err;

	if (!cJSON_AddNumberToObject(poe, "output-current",
				     poe_port_state->output_current))
		goto err;

	if (!cJSON_AddStringToObject(poe, "output-voltage",
				     poe_port_state->output_voltage))
		goto err;

	if (!cJSON_AddStringToObject(poe, "temp",
				     poe_port_state->temperature))
		goto err;

	if (!cJSON_AddStringToObject(poe, "status",
				     poe_port_state->status))
		goto err;

	if (!cJSON_AddStringToObject(poe, "fault-status",
				     poe_port_state->fault_status))
		goto err;

	if (!cJSON_AddNumberToObject(counters, "overload",
				     poe_port_state->counters.overload))
		goto err;

	if (!cJSON_AddNumberToObject(counters, "short",
				     poe_port_state->counters.shorted))
		goto err;

	if (!cJSON_AddNumberToObject(counters, "power-denied",
				     poe_port_state->counters.power_denied))
		goto err;

	if (!cJSON_AddNumberToObject(counters, "absent",
				     poe_port_state->counters.absent))
		goto err;

	if (!cJSON_AddNumberToObject(counters, "invalid-signature",
				     poe_port_state->counters.invalid_signature))
		goto err;

	return 0;

err:
	return -1;
}

static int
state_fill_link_state_ieee8021x_data(cJSON *port,
				     struct plat_port_info *port_info)
{
	struct plat_ieee8021x_port_info *ieee8021x_port_info;
	cJSON *root, *clients, *client;
	size_t i;

	ieee8021x_port_info = &port_info->ieee8021x_info;

	if (!ieee8021x_port_info->arr_len ||
	    !ieee8021x_port_info->client_arr)
		return 0;

	root = cJSON_AddObjectToObject(port, "ieee8021x");
	clients = cJSON_AddArrayToObject(root, "authenticated-clients");
	if (!root || !clients)
		goto err;

	for (i = 0; i < ieee8021x_port_info->arr_len; ++i) {
		struct plat_ieee8021x_authenticated_client_info *info;

		client = cJSON_CreateObject();
		if (!client)
			goto err;

		info = &ieee8021x_port_info->client_arr[i];

		if (!cJSON_AddItemToArray(clients, client)) {
			cJSON_Delete(client);
			goto err;
		}

		if (!cJSON_AddStringToObject(client, "authenticated-method",
					     info->auth_method))
			goto err;

		if (!cJSON_AddStringToObject(client, "mac-address",
					     info->mac_addr))
			goto err;

		if (!cJSON_AddNumberToObject(client, "session-time",
					     info->session_time))
			goto err;

		if (!cJSON_AddStringToObject(client, "username",
					     info->username))
			goto err;

		if (!cJSON_AddStringToObject(client, "vlan-type",
					     info->vlan_type))
			goto err;

		if (!cJSON_AddNumberToObject(client, "vlan-id",
					     info->vid))
			goto err;
	}

	return 0;
err:
	cJSON_Delete(root);
	return -1;
}


static int state_fill_link_state_data(cJSON *link_state,
				      struct plat_state_info *state)
{
	cJSON *counters_obj = NULL;
	cJSON *link_upstream;
	uint16_t pid = 0;
	cJSON *port;
	int i;

	link_upstream = cJSON_AddObjectToObject(link_state,
						"upstream");
	if (!link_upstream)
		goto err;

	for (i = 0; i < state->port_info_count; ++i) {
		NAME_TO_PID(&pid, state->port_info[i].name);

		port = cJSON_AddObjectToObject(link_upstream,
					       state->port_info[i].name);
		counters_obj = cJSON_AddObjectToObject(port, "counters");
		if (!port || !counters_obj)
			goto err;

		if (state_fill_interface_counters(counters_obj,
						  &state->port_info[i].stats)) {
			goto err;
		}
		if (!cJSON_AddBoolToObject(port, "carrier",
					   state->port_info[i].carrier_up))
			goto err;

		/* If port is down - don't fill speed and duplex.
		 * We still care about PoE for example, since
		 * lower could be because of some issues on PoE level.
		 */
		if (!state->port_info[i].carrier_up)
			goto skip_portattr_fill;

		if (!cJSON_AddNumberToObject(port, "speed",
					     state->port_info[i].speed))
			goto err;

		if (!cJSON_AddStringToObject(
			    port, "duplex",
			    state->port_info[i].duplex ? "full" : "half"))
			goto err;

		if (state_fill_link_state_ieee8021x_data(port,
							 &state->port_info[i]))
			goto err;

skip_portattr_fill:
		/* Skip this port if it doesn't have any PoE functionality */
		if (!BITMAP_TEST_BIT(state->poe_ports_bmap, pid))
			continue;

		if (state_fill_link_state_poe_data(
			    port, &state->poe_ports_state[pid]))
			goto err;
	}

	return 0;

err:
	return -1;
}

static int state_fill_lldp_peers(cJSON *lldp_peers,
				 struct plat_state_info *state)
{
	struct plat_port_lldp_peer_info *peer_info;
	cJSON *lldp_peers_downstream;
	cJSON *lldp_peers_upstream;
	cJSON *capabilities;
	cJSON *mgmt_ips;
	cJSON *port;
	cJSON *info;
	int pi, i;

	lldp_peers_downstream = cJSON_AddObjectToObject(lldp_peers,
							"downstream");
	lldp_peers_upstream = cJSON_AddObjectToObject(lldp_peers,
						      "upstream");
	if (!lldp_peers_upstream || !lldp_peers_downstream)
		goto err;

	for (pi = 0; pi < state->port_info_count; ++pi) {
		if (!state->port_info[pi].has_lldp_peer_info) {
			continue;
		}
		peer_info = &state->port_info[pi].lldp_peer_info;
		port = cJSON_AddArrayToObject(lldp_peers_upstream,
					      state->port_info[pi].name);

		info = cJSON_CreateObject();
		if (!port || !info || !cJSON_AddItemToArray(port, info))
			goto err;

		capabilities = cJSON_AddArrayToObject(info, "capability");
		if (!capabilities)
			goto err;

		if (peer_info->capabilities.is_bridge)
			if (!cJSON_AddItemToArray(capabilities,
						  cJSON_CreateString("Bridge")))
			goto err;

		if (peer_info->capabilities.is_router)
			if (!cJSON_AddItemToArray(capabilities,
						  cJSON_CreateString("Router")))
			goto err;

		if (peer_info->capabilities.is_wlan_ap)
			if (!cJSON_AddItemToArray(capabilities,
						  cJSON_CreateString("Wlan")))
			goto err;

		if (peer_info->capabilities.is_station)
			if (!cJSON_AddItemToArray(capabilities,
						  cJSON_CreateString("Station")))
			goto err;

		if (!cJSON_AddStringToObject(info, "description", peer_info->description))
			goto err;

		if (!cJSON_AddStringToObject(info, "mac", peer_info->mac))
			goto err;

		if (!cJSON_AddStringToObject(info, "name", peer_info->name))
			goto err;

		if (!cJSON_AddStringToObject(info, "port", peer_info->port))
			goto err;

		/* If parsing LLDP output didn't feel even one mgmt IPs,
		 * we can safely skip filling-out mgmt ips and proceed to
		 * next iface.
		 */
		if (peer_info->mgmt_ips[0][0] == '\0')
			continue;

		mgmt_ips = cJSON_AddArrayToObject(info, "management_ips");
		if (!mgmt_ips)
			goto err;

		for (i = 0; i < UCENTRAL_PORT_LLDP_PEER_INFO_MAX_MGMT_IPS; ++i) {
			if (peer_info->mgmt_ips[i][0] == '\0')
				break;

			if (!cJSON_AddItemToArray(mgmt_ips,
						  cJSON_CreateString(&peer_info->mgmt_ips[i][0])))
				goto err;
		}
	}

	return 0;

err:
	return -1;
}

static int
state_fill_unit_poe_data(cJSON *poe, struct plat_poe_state *poe_state_info)
{

	if (!jobj_u64_set(poe, "max-power-budget",
			  poe_state_info->max_power_budget))
		goto err;

	if (!jobj_u64_set(poe, "power-consumed",
			  poe_state_info->power_consumed))
		goto err;

	if (!jobj_u64_set(poe, "power-threshold",
			  poe_state_info->power_threshold))
		goto err;

	if (!cJSON_AddStringToObject(poe, "power-status",
				     poe_state_info->power_status))
		goto err;

	return 0;
err:
	return -1;
}

static int state_fill_unit_data(cJSON *unit, struct plat_state_info *state)
{
	cJSON *loadArr;
	cJSON *memory;
	cJSON *poe;

	loadArr = cJSON_CreateDoubleArray(state->system_info.load_average, 3);
	if (!loadArr)
		goto err;

	if (!cJSON_AddItemToObject(unit, "load", loadArr))
		goto err;

	if (!jobj_u64_set(unit, "localtime", state->system_info.localtime)) {
		goto err;
	}

	memory = cJSON_AddObjectToObject(unit, "memory");
	if (!memory)
		goto err;

	if (!jobj_u64_set(memory, "buffered", state->system_info.ram_buffered))
		goto err;
	if (!jobj_u64_set(memory, "cached", state->system_info.ram_cached))
		goto err;
	if (!jobj_u64_set(memory, "free", state->system_info.ram_free))
		goto err;
	if (!jobj_u64_set(memory, "total", state->system_info.ram_total))
		goto err;
	if (!jobj_u64_set(unit, "uptime", state->system_info.uptime)) {
		goto err;
	}

	poe = cJSON_AddObjectToObject(unit, "poe");
	if (!poe || state_fill_unit_poe_data(poe, &state->poe_state))
		goto err;

	return 0;

err:
	return -1;
}

static size_t
state_fill_pub_ip_curl_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    char *buffer = (char *)userdata;
    size_t total_size = size * nmemb;

    if (total_size >= 256)
	return 0;

    memcpy(buffer, ptr, total_size);
    buffer[total_size] = '\0';

    return total_size;
}

static int state_fill_public_ip(cJSON *state)
{
	CURL *curl_handle;
	char pub_ip[256];
	CURLcode res;
	int ret = 0;

	memset(&pub_ip[0], 0, sizeof(pub_ip));

	/* If addr is empty - do not obtain IP */
	if (!ucentral_metrics.state.public_ip_lookup[0])
		return 0;

	curl_handle = curl_easy_init();
	if (!curl_handle)
		return -1;

	/* TODO guard data of metrics_cfg of config reqs */
	curl_easy_setopt(curl_handle, CURLOPT_URL,
			 &ucentral_metrics.state.public_ip_lookup[0]);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, state_fill_pub_ip_curl_cb);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &pub_ip[0]);
	res = curl_easy_perform(curl_handle);
	if (res != CURLE_OK) {
		ret = -1;
	} else {
		if (!cJSON_AddStringToObject(state, "public_ip", &pub_ip[0]))
			ret = -1;
	}

	curl_easy_cleanup(curl_handle);
	return ret;
}

static int state_fill_mac_addr_list_data(cJSON *root,
					 struct plat_state_info *state)
{
	struct plat_learned_mac_addr *learned_entry;
	cJSON *port, *vid, *mac;
	size_t i, num_elem;
	char vid_key[6];
	bool overflow;

	overflow = ((state->learned_mac_list_size > ucentral_metrics.state.max_mac_count) ||
		    (ucentral_metrics.state.max_mac_count == 0));
	num_elem = overflow ? ucentral_metrics.state.max_mac_count
			    : state->learned_mac_list_size;

	if (!cJSON_AddBoolToObject(root, "overflow", overflow))
		goto err;

	for (i = 0; i < num_elem; i++) {
		learned_entry = &state->learned_mac_list[i];
		if (!(port = cJSON_GetObjectItemCaseSensitive(root, learned_entry->port)))
			if (!(port = cJSON_AddObjectToObject(root, learned_entry->port)))
				goto err;

		snprintf(vid_key, sizeof(vid_key), "%u", learned_entry->vid);
		if (!(vid = cJSON_GetObjectItemCaseSensitive(port, vid_key)))
			if (!(vid = cJSON_AddArrayToObject(port, vid_key)))
				goto err;

		if (!(mac = cJSON_CreateString(learned_entry->mac)))
			goto err;
		if (!cJSON_AddItemToArray(vid, mac)) {
			/**
			 * element created but still not attached to
			 * anything, so we have to delete it ourselves
			 */
			cJSON_Delete(mac);
			goto err;
		}
	}
	return 0;
err:
	return -1;
}

static int state_fill(cJSON *state, struct plat_state_info *plat_state_info)
{
	cJSON *mac_forwarding_table;
	cJSON *link_state;
	cJSON *lldp_peers;
	cJSON *interfaces;
	cJSON *unit;

	 /* TBD: handle clients_enabled set to false once actual clients
	  * fetching is implemented.
	  */
	interfaces = cJSON_AddArrayToObject(state, "interfaces");
	if (!interfaces) {
		UC_LOG_ERR("cJSON failed");
		goto err;
	}
	if (state_fill_interfaces_data(interfaces, plat_state_info)) {
		UC_LOG_ERR("state_fill_interfaces_data failed");
		goto err;
	}
	link_state = cJSON_AddObjectToObject(state, "link-state");
	if (!link_state ||
	    state_fill_link_state_data(link_state, plat_state_info)) {
		UC_LOG_ERR("!link_state(%p) || state_fill_link_state_data",
			   (void *)link_state);
		goto err;
	}
	if (ucentral_metrics.state.enabled &&
	    ucentral_metrics.state.lldp_enabled) {
		lldp_peers = cJSON_AddObjectToObject(state, "lldp-peers");
		if (!lldp_peers) {
			UC_LOG_ERR("cJSON failed");
			goto err;
		}
		if (state_fill_lldp_peers(lldp_peers, plat_state_info)) {
			UC_LOG_ERR("state_fill_lldp_peers failed");
			goto err;
		}
	}

	if (ucentral_metrics.state.enabled &&
	    ucentral_metrics.state.clients_enabled) {
		mac_forwarding_table = cJSON_AddObjectToObject(state, "mac-forwarding-table");
		if (!mac_forwarding_table ||
		    state_fill_mac_addr_list_data(mac_forwarding_table, plat_state_info)) {
			UC_LOG_ERR("!mac_forwarding_table(%p) || state_fill_mac_addr_list_data",
				(void *)mac_forwarding_table);
			goto err;
		}
	}

	unit = cJSON_AddObjectToObject(state, "unit");
	if (!unit || state_fill_unit_data(unit, plat_state_info)) {
		UC_LOG_ERR("!unit(%p) || state_fill_unit_data", (void *)unit);
		goto err;
	}
	if (state_fill_public_ip(state)) {
		UC_LOG_ERR("state_fill_public_ip failed");
		goto err;
	}
	if (!cJSON_AddNumberToObject(state, "version", (double)1)) {
		UC_LOG_ERR("cJSON failed");
		goto err;
	}
	return 0;

err:
	return -1;
}

void state_send(struct plat_state_info *plat_state_info)
{
	struct blob blob = {0};
	cJSON *params;
	cJSON *state;

	blob.obj = proto_new_blob("state");
	if (!blob.obj)
		goto err;

	params = cJSON_GetObjectItemCaseSensitive(blob.obj, "params");
	if (!params)
		goto err;

	if (!cJSON_AddStringToObject(params, "serial", client.serial))
		goto err;

	if (!cJSON_AddNumberToObject(params, "uuid", (double)uuid_latest))
		goto err;

	state = cJSON_AddObjectToObject(params, "state");
	if (!state)
		goto err;

	if (state_fill(state, plat_state_info)) {
		UC_LOG_ERR("state_fill failed");
		goto err;
	}
	UC_LOG_DBG("xmit state\n");

	proto_send_blob(&blob);
	proto_destroy_blob(&blob);

	return;

err:
	UC_LOG_ERR("failed to collect state");
	proto_destroy_blob(&blob);
}

void deviceupdate_send(const char *updated_pass)
{
	struct blob blob = {0};
	cJSON *params;

	if (!updated_pass)
		return;

	blob.obj = proto_new_blob("deviceupdate");
	if (!blob.obj)
		return;

	params = cJSON_GetObjectItemCaseSensitive(blob.obj, "params");
	if (!params)
		goto out;

	if (!cJSON_AddStringToObject(params, "serial", client.serial))
		goto out;

	if (!cJSON_AddStringToObject(params, "currentPassword", updated_pass))
		goto out;

	UC_LOG_DBG("xmit deviceupdate \n");

	proto_send_blob(&blob);
out:
	proto_destroy_blob(&blob);
}

void telemetry_send(struct plat_state_info *plat_state_info)
{
	time_t curr_time = time(NULL);
	struct blob blob = {0};
	cJSON *state_root;
	cJSON *state_arr;
	cJSON *arr_obj;
	cJSON *params;
	cJSON *state;
	cJSON *data;

	blob.obj = proto_new_blob("telemetry");
	if (!blob.obj)
		goto err;

	params = cJSON_GetObjectItemCaseSensitive(blob.obj, "params");
	if (!params)
		goto err;

	if (!cJSON_AddStringToObject(params, "serial", client.serial))
		goto err;

	if (!(data = cJSON_AddObjectToObject(params, "data")))
		goto err;

	/* For some reason schema and actual telemetry differ: APs treat
	 * <data:state> as array of arrays. The inner array consits of:
	 *  [0] timestamp
	 *  [1] actual <state> object
	 * Mimic AP behavior for now.
	 *
	 * Typical AP telemetry format:
	 * "data":{"state":[[1676464490,{"uuid":1675778738,"serial":"xxx","state":{"unit":{"memory":
	 */
	if (!(state_root = cJSON_AddArrayToObject(data, "state")))
		goto err;

	if (!(state_arr = cJSON_CreateArray()))
		goto err;

	if (!(arr_obj = cJSON_CreateObject()))
		goto err;

	if (!cJSON_AddItemToArray(state_root, state_arr))
		goto err;

	if (!cJSON_AddItemToObject(data, "timestamp", cJSON_CreateNumber(curr_time)))
		goto err;

	/* Once the whole <skeleton> is ready, fill all the necessary object
	 * with actual data.
	 */
	if (!cJSON_AddNumberToObject(arr_obj, "uuid", (double)uuid_latest))
		goto err;

	if (!cJSON_AddStringToObject(arr_obj, "serial", client.serial))
		goto err;

	if (!(state = cJSON_AddObjectToObject(arr_obj, "state")))
		goto err;

	if (state_fill(state, plat_state_info))
		goto err;

	if (!cJSON_AddItemToArray(state_arr, cJSON_CreateNumber(curr_time)))
		goto err;

	if (!cJSON_AddItemToArray(state_arr, arr_obj))
		goto err;

	UC_LOG_DBG("xmit telemetry\n");

	proto_send_blob(&blob);
	proto_destroy_blob(&blob);

	return;

err:
	UC_LOG_ERR("JSON obj alloc failed\n");
	proto_destroy_blob(&blob);
}

static void
proto_handle_blob(struct blob *blob)
{
	cJSON *rpc[__JSONRPC_MAX] = {0};
	char *method;

	rpc[JSONRPC_VER] =
		cJSON_GetObjectItemCaseSensitive(blob->obj, "jsonrpc");
	rpc[JSONRPC_METHOD]  =
		cJSON_GetObjectItemCaseSensitive(blob->obj, "method");
	rpc[JSONRPC_ERROR] =
		cJSON_GetObjectItemCaseSensitive(blob->obj, "error");
	rpc[JSONRPC_PARAMS] =
		cJSON_GetObjectItemCaseSensitive(blob->obj, "params");
	rpc[JSONRPC_ID] =
		cJSON_GetObjectItemCaseSensitive(blob->obj, "id");
	rpc[JSONRPC_RADIUS] =
		cJSON_GetObjectItemCaseSensitive(blob->obj, "radius");

	if (!rpc[JSONRPC_VER] || (!rpc[JSONRPC_METHOD] && !rpc[JSONRPC_ERROR]) ||
	    (rpc[JSONRPC_METHOD] && !rpc[JSONRPC_PARAMS]) ||
	    strcmp(cJSON_GetStringValue(rpc[JSONRPC_VER]), "2.0")) {
		log_send("received invalid jsonrpc call", LOG_ERR);
		return;
	}

	if (rpc[JSONRPC_METHOD]) {
		method = cJSON_GetStringValue(rpc[JSONRPC_METHOD]);

		if (!strcmp(method, "configure"))
			configure_handle(rpc);
		else if (!strcmp(method, "ping"))
			ping_handle(rpc);
		else if (!strcmp(method, "reboot"))
			reboot_handle(rpc);
		else if (!strcmp(method, "factory"))
			factory_handle(rpc);
		else if (!strcmp(method, "rtty"))
			rtty_handle(rpc);
		else if (!strcmp(method, "upgrade"))
			upgrade_handle(rpc);
		else if (!strcmp(method, "telemetry"))
			telemetry_handle(rpc);
		else if (!strcmp(method, "script"))
			script_handle(rpc);
		else
			generic_handle(rpc);
	}
}

void proto_handle(cJSON *cmd)
{
	struct blob blob = {0};

	blob.obj = cmd;
	blob.rendered_string = cJSON_PrintUnformatted(blob.obj);
	UC_LOG_DBG("Got cmd:\n'%s'\n", blob.rendered_string
		? blob.rendered_string
		: NULL);

	proto_handle_blob(&blob);
	free(blob.rendered_string);
}

static void alarm_plat_cb(struct plat_alarm *a)
{
	char buf[32];
	struct blob blob = { 0 };
	cJSON *params = 0, *data = 0;

	UC_LOG_DBG("a->id=%s", a->id);
	UC_LOG_DBG("a->type_id=%s", a->type_id);
	UC_LOG_DBG("a->severity=%d", a->severity);
	UC_LOG_DBG("a->text=%s", a->text);

	blob.obj = proto_new_blob("alarm");
	if (!blob.obj)
		return;

	params = cJSON_GetObjectItemCaseSensitive(blob.obj, "params");
	if (!params)
		goto err;

	if (!cJSON_AddStringToObject(params, "serial", client.serial))
		goto err;

	data = cJSON_AddObjectToObject(params, "data");
	if (!data)
		goto err;

	if (!cJSON_AddStringToObject(data, "id", a->id))
		goto err;

	if (!cJSON_AddStringToObject(data, "resource", a->resource))
		goto err;

	if (!cJSON_AddStringToObject(data, "text", a->text))
		goto err;

	snprintf(buf, sizeof buf, "%ju", (uintmax_t)a->time_created);
	if (!cJSON_AddStringToObject(data, "time_created", buf))
		goto err;

	if (!cJSON_AddStringToObject(data, "type_id", a->type_id))
		goto err;

	snprintf(buf, sizeof buf, "%ju", (uintmax_t)a->severity);
	if (!cJSON_AddStringToObject(data, "severity", buf))
		goto err;

	proto_send_blob(&blob);
err:
	proto_destroy_blob(&blob);
}

static void linkstatus_plat_cb(struct plat_linkstatus *s)
{
	char ts[32];
	struct blob blob = { 0 };
	cJSON *params = 0, *data = 0, *events = 0, *event = 0, *timestamp = 0,
	      *payload = 0;

	UC_LOG_DBG("s->timestamp=%" PRIi64 "", s->timestamp);
	UC_LOG_DBG("s->ifname=%s", s->ifname);
	UC_LOG_DBG("s->up=%d", s->up);

	blob.obj = proto_new_blob("event");
	if (!blob.obj)
		return;

	params = cJSON_GetObjectItemCaseSensitive(blob.obj, "params");
	if (!params)
		goto err;

	if (!cJSON_AddStringToObject(params, "serial", client.serial))
		goto err;

	data = cJSON_AddObjectToObject(params, "data");
	if (!data)
		goto err;

	if (!(events = cJSON_AddArrayToObject(data, "event")))
		goto err;

	snprintf(ts, sizeof ts, "%" PRIi64, s->timestamp);
	if (!(timestamp = cJSON_CreateRaw(ts)))
		goto err;

	if (!cJSON_AddItemToArray(events, timestamp)) {
		cJSON_Delete(timestamp);
		goto err;
	}

	if (!(event = cJSON_CreateObject()))
		goto err;

	if (!cJSON_AddItemToArray(events, event)) {
		cJSON_Delete(event);
		goto err;
	}

	if (s->up) {
		if (!cJSON_AddStringToObject(event, "type", "wired.carrier-up"))
			goto err;
	} else {
		if (!cJSON_AddStringToObject(event, "type",
					     "wired.carrier-down"))
			goto err;
	}

	if (!(payload = cJSON_AddObjectToObject(event, "payload"))) {
		goto err;
	}

	if (!cJSON_AddStringToObject(payload, "name", s->ifname)) {
		goto err;
	}

	proto_send_blob(&blob);
err:
	proto_destroy_blob(&blob);
}

static void poe_linkstatus_plat_cb(struct plat_poe_linkstatus *s)
{
	char ts[32];
	struct blob blob = { 0 };
	cJSON *params = 0, *data = 0, *events = 0, *event = 0, *timestamp = 0,
	      *payload = 0;

	blob.obj = proto_new_blob("event");
	if (!blob.obj)
		return;

	params = cJSON_GetObjectItemCaseSensitive(blob.obj, "params");
	if (!params)
		goto err;

	if (!cJSON_AddStringToObject(params, "serial", client.serial))
		goto err;

	data = cJSON_AddObjectToObject(params, "data");
	if (!data)
		goto err;

	if (!(events = cJSON_AddArrayToObject(data, "event")))
		goto err;

	snprintf(ts, sizeof ts, "%" PRIi64, s->timestamp);
	if (!(timestamp = cJSON_CreateRaw(ts)))
		goto err;

	if (!cJSON_AddItemToArray(events, timestamp)) {
		cJSON_Delete(timestamp);
		goto err;
	}

	if (!(event = cJSON_CreateObject()))
		goto err;

	if (!cJSON_AddItemToArray(events, event)) {
		cJSON_Delete(event);
		goto err;
	}

	switch (s->status) {
	case PLAT_POE_LINKSTATUS_DISABLED:
		if (!cJSON_AddStringToObject(event, "type", "wired.poe.status.disabled"))
			goto err;
		break;
	case PLAT_POE_LINKSTATUS_SEARCHING:
		if (!cJSON_AddStringToObject(event, "type", "wired.poe.status.searching"))
			goto err;
		break;
	case PLAT_POE_LINKSTATUS_DELIVERING_POWER:
		if (!cJSON_AddStringToObject(event, "type", "wired.poe.status.delivering_power"))
			goto err;
		break;
	case PLAT_POE_LINKSTATUS_OVERLOAD:
		if (!cJSON_AddStringToObject(event, "type", "wired.poe.status.overload"))
			goto err;
		break;
	case PLAT_POE_LINKSTATUS_FAULT:
		if (!cJSON_AddStringToObject(event, "type", "wired.poe.status.fault"))
			goto err;
		break;
	}

	if (!(payload = cJSON_AddObjectToObject(event, "payload"))) {
		goto err;
	}

	if (!cJSON_AddStringToObject(payload, "name", s->ifname)) {
		goto err;
	}

	proto_send_blob(&blob);
err:
	proto_destroy_blob(&blob);
}

static void poe_link_faultcode_plat_cb(struct plat_poe_link_faultcode *s)
{
	char ts[32];
	struct blob blob = { 0 };
	cJSON *params = 0, *data = 0, *events = 0, *event = 0, *timestamp = 0,
	      *payload = 0;

	blob.obj = proto_new_blob("event");
	if (!blob.obj)
		return;

	params = cJSON_GetObjectItemCaseSensitive(blob.obj, "params");
	if (!params)
		goto err;

	if (!cJSON_AddStringToObject(params, "serial", client.serial))
		goto err;

	data = cJSON_AddObjectToObject(params, "data");
	if (!data)
		goto err;

	if (!(events = cJSON_AddArrayToObject(data, "event")))
		goto err;

	snprintf(ts, sizeof ts, "%" PRIi64, s->timestamp);
	if (!(timestamp = cJSON_CreateRaw(ts)))
		goto err;

	if (!cJSON_AddItemToArray(events, timestamp)) {
		cJSON_Delete(timestamp);
		goto err;
	}

	if (!(event = cJSON_CreateObject()))
		goto err;

	if (!cJSON_AddItemToArray(events, event)) {
		cJSON_Delete(event);
		goto err;
	}

	switch (s->faultcode) {
	case PLAT_POE_LINK_FAULTCODE_OVLO:
		if (!cJSON_AddStringToObject(event, "type", "wired.poe.fault.ovlo"))
			goto err;
		break;
	case PLAT_POE_LINK_FAULTCODE_MPS_ABSENT:
		if (!cJSON_AddStringToObject(event, "type", "wired.poe.fault.mps_absent"))
			goto err;
		break;
	case PLAT_POE_LINK_FAULTCODE_SHORT:
		if (!cJSON_AddStringToObject(event, "type", "wired.poe.fault.short"))
			goto err;
		break;
	case PLAT_POE_LINK_FAULTCODE_OVERLOAD:
		if (!cJSON_AddStringToObject(event, "type", "wired.poe.fault.overload"))
			goto err;
		break;
	case PLAT_POE_LINK_FAULTCODE_POWER_DENIED:
		if (!cJSON_AddStringToObject(event, "type", "wired.poe.fault.power_denied"))
			goto err;
		break;
	case PLAT_POE_LINK_FAULTCODE_THERMAL_SHUTDOWN:
		if (!cJSON_AddStringToObject(event, "type", "wired.poe.fault.thermal_shutdown"))
			goto err;
		break;
	case PLAT_POE_LINK_FAULTCODE_STARTUP_FAILURE:
		if (!cJSON_AddStringToObject(event, "type", "wired.poe.fault.startup_failure"))
			goto err;
		break;
	case PLAT_POE_LINK_FAULTCODE_UVLO:
		if (!cJSON_AddStringToObject(event, "type", "wired.poe.fault.uvlo"))
			goto err;
		break;
	case PLAT_POE_LINK_FAULTCODE_HW_PIN_DISABLE:
		if (!cJSON_AddStringToObject(event, "type", "wired.poe.fault.hw_pin_disable"))
			goto err;
		break;
	case PLAT_POE_LINK_FAULTCODE_PORT_UNDEFINED:
		if (!cJSON_AddStringToObject(event, "type", "wired.poe.fault.port_undefined"))
			goto err;
		break;
	case PLAT_POE_LINK_FAULTCODE_INTERNAL_HW_FAULT:
		if (!cJSON_AddStringToObject(event, "type", "wired.poe.fault.internal_hw_fault"))
			goto err;
		break;
	case PLAT_POE_LINK_FAULTCODE_USER_SETTING:
		if (!cJSON_AddStringToObject(event, "type", "wired.poe.fault.user_setting"))
			goto err;
		break;
	case PLAT_POE_LINK_FAULTCODE_NON_STANDARD_PD:
		if (!cJSON_AddStringToObject(event, "type", "wired.poe.fault.non_standard_pd"))
			goto err;
		break;
	case PLAT_POE_LINK_FAULTCODE_UNDERLOAD:
		if (!cJSON_AddStringToObject(event, "type", "wired.poe.fault.underload"))
			goto err;
		break;
	case PLAT_POE_LINK_FAULTCODE_PWR_BUDGET_EXCEEDED:
		if (!cJSON_AddStringToObject(event, "type", "wired.poe.fault.pwr_budget_exceeded"))
			goto err;
		break;
	case PLAT_POE_LINK_FAULTCODE_OOR_CAPACITOR_VALUE:
		if (!cJSON_AddStringToObject(event, "type", "wired.poe.fault.oor_capacitor_value"))
			goto err;
		break;
	case PLAT_POE_LINK_FAULTCODE_CLASS_ERROR:
		if (!cJSON_AddStringToObject(event, "type", "wired.poe.fault.class_error"))
			goto err;
		break;
	default: goto err;
	}

	if (!(payload = cJSON_AddObjectToObject(event, "payload"))) {
		goto err;
	}

	if (!cJSON_AddStringToObject(payload, "name", s->ifname)) {
		goto err;
	}

	proto_send_blob(&blob);
err:
	proto_destroy_blob(&blob);
}

void device_rebootcause_send(void)
{
	struct blob blob = { 0 };
	cJSON *params = 0, *data = 0, *events = 0, *event = 0, *timestamp = 0,
	      *payload;
	struct plat_reboot_cause cause = {0};
	char ts[32];
	int ret;

	UC_LOG_DBG("xmit rebootcause\n");
	ret = plat_reboot_cause_get(&cause);
	UC_LOG_DBG("rebootcause rc %d, cause %d\n", ret, cause.cause);
	if (ret)
		return;

	blob.obj = proto_new_blob("event");
	if (!blob.obj)
		return;

	params = cJSON_GetObjectItemCaseSensitive(blob.obj, "params");
	if (!params)
		goto err;

	if (!cJSON_AddStringToObject(params, "serial", client.serial))
		goto err;

	data = cJSON_AddObjectToObject(params, "data");
	if (!data)
		goto err;

	if (!(events = cJSON_AddArrayToObject(data, "event")))
		goto err;

	snprintf(ts, sizeof ts, "%" PRIi64, cause.ts);
	if (!(timestamp = cJSON_CreateRaw(ts)))
		goto err;

	if (!cJSON_AddItemToArray(events, timestamp)) {
		cJSON_Delete(timestamp);
		goto err;
	}

	if (!(event = cJSON_CreateObject()))
		goto err;

	if (!cJSON_AddItemToArray(events, event)) {
		cJSON_Delete(event);
		goto err;
	}

	switch (cause.cause) {
	case PLAT_REBOOT_CAUSE_REBOOT_CMD:
		if (!cJSON_AddStringToObject(event, "type", "device.reboot"))
			goto err;
		break;
	case PLAT_REBOOT_CAUSE_POWERLOSS:
		if (!cJSON_AddStringToObject(event, "type", "device.powerloss"))
			goto err;
		break;
	case PLAT_REBOOT_CAUSE_CRASH:
		if (!cJSON_AddStringToObject(event, "type", "device.crash"))
			goto err;
		break;
	case PLAT_REBOOT_CAUSE_UNAVAILABLE:
		if (!cJSON_AddStringToObject(event, "type", "device.reboot-cause-unavailable"))
			goto err;
		break;
	default: goto err;
	}

	if (!(payload = cJSON_AddObjectToObject(event, "payload"))) {
		goto err;
	}

	if (!cJSON_AddStringToObject(payload, "description", cause.desc)) {
		goto err;
	}

	proto_send_blob(&blob);
err:
	proto_destroy_blob(&blob);
}

void proto_start(void)
{
	plat_event_subscribe(&(struct plat_event_callbacks){
		.alarm_cb = alarm_plat_cb,
		.linkstatus_cb = linkstatus_plat_cb,
		.poe_linkstatus_cb = poe_linkstatus_plat_cb,
		.poe_link_faultcode_cb = poe_link_faultcode_plat_cb,
	});
}

void proto_stop(void)
{
	plat_event_unsubscribe();
	plat_state_poll_stop();
	plat_health_poll_stop();
	plat_telemetry_poll_stop();
	plat_upgrade_poll_stop();
}
