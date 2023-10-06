/* SPDX-License-Identifier: BSD-3-Clause */
#ifdef __cplusplus
extern "C" {
#endif

#include <syslog.h>

#define GNMI_C_CONNECTOR_DEBUG_LOG(FMT, ...)                       \
	syslog(LOG_DEBUG, "GNMI: %s:%d: " FMT, __func__, __LINE__, \
	       ##__VA_ARGS__)

#define GNMI_C_CONNECTOR_PRETTY_LOG(FMT, ...)                                 \
	syslog(LOG_DEBUG, "GNMI: %s:%d: " FMT, __PRETTY_FUNCTION__, __LINE__, \
	       ##__VA_ARGS__)

struct gnmi_status {
	int ok;
	int error_code;
	char msg[1024];
};

struct gnmi_typed_value {
	enum {
		GNMI_TYPED_VALUE_NOT_SET = 0,
		GNMI_TYPED_VALUE_STRING = 1,
		GNMI_TYPED_VALUE_INT = 2,
		GNMI_TYPED_VALUE_UINT = 3,
		GNMI_TYPED_VALUE_BOOL = 4,
		GNMI_TYPED_VALUE_BYTES = 5,
		GNMI_TYPED_VALUE_FLOAT = 6,
		GNMI_TYPED_VALUE_DECIMAL = 7,
		GNMI_TYPED_VALUE_LEAFLIST = 8,
		GNMI_TYPED_VALUE_ANY = 9,
		GNMI_TYPED_VALUE_JSON = 10,
		GNMI_TYPED_VALUE_JSONIETF = 11,
		GNMI_TYPED_VALUE_ASCII = 12,
		GNMI_TYPED_VALUE_PROTOBYTES = 13,
	} type;

	union {
		uint64_t u64;
		const char *str;
		int boolean;
	} v;
};

enum gnmi_subscribe_method {
	GNMI_SUBSCRIBE_METHOD_STREAM,
	GNMI_SUBSCRIBE_METHOD_POLL,
	GNMI_SUBSCRIBE_METHOD_ONCE,
};

enum gnmi_subscribe_mode {
	GNMI_SUBSCRIBE_MODE_TARGET_DEFINED,
	GNMI_SUBSCRIBE_MODE_ON_CHANGE,
	GNMI_SUBSCRIBE_MODE_SAMPLE,
};

struct gnmi_path_elem_key {
	const char *key;
	const char *value;
};

struct gnmi_path_elem {
	const char *name;
	int key_size;
	const struct gnmi_path_elem_key *key;
};

struct gnmi_path {
	const char *origin;
	const struct gnmi_path_elem *elem;
	int elem_size;
};

void gnmi_path_dump(const struct gnmi_path *p);

struct gnmi_subscribe_update {
	int has_path;
	int has_value;
	struct gnmi_path path;
	struct gnmi_typed_value val;
};

struct gnmi_notification {
	int64_t timestamp;
	struct gnmi_path prefix;
	int has_prefix;
	const char *alias;
	struct gnmi_subscribe_update *update;
	int update_size;
};

struct gnmi_subscribe_response {
	struct gnmi_notification update;
	int has_update;
	int has_sync_response;
	int sync_response;
};

struct gnmi_alarm {
	const char *id;
	const char *resource;
	const char *text;
	uint64_t time_created;
	const char *type_id;
	int severity;
	int acknowledged;
	uint64_t acknowledge_time;
};

struct gnmi_gnoi_sonic_alarm_show_request {
	enum {
		GNMI_GNOI_SONIC_ALARM_SHOW_REQUEST_FILTER_NOT_SET,
		GNMI_GNOI_SONIC_ALARM_SHOW_REQUEST_FILTER_ID_RANGE,
	} filter;

	union {
		struct {
			const char *begin;
			const char *end;
		} id;
	} v;
};

struct gnmi_gnoi_sonic_alarm_show_response {
	int32_t status;
	size_t count;
	struct gnmi_alarm alarm[];
};

struct gnmi_subscribe;

typedef void (*gnmi_subscribe_cb)(const struct gnmi_subscribe_response *,
				  void *data);

struct gnmi_session;
struct gnmi_session *gnmi_session_create(char *host,
					 char *username, char *password);
int gnmi_jsoni_set(struct gnmi_session *gs, const char *path, char *req,
		   int64_t timeout_us);
int gnmi_jsoni_get(struct gnmi_session *gs, const char *path, char *res,
		   size_t res_size, int64_t timeout_us);
int gnmi_jsoni_get_alloc(struct gnmi_session *gs, const char *path, char **res,
			 size_t *len, int64_t timeout_us);
int gnmi_jsoni_del(struct gnmi_session *gs, const char *path,
		   int64_t timeout_us);
int gnmi_jsoni_replace(struct gnmi_session *gs, const char *path, char *req,
		       int64_t timeout_us);
int gnmi_gnoi_system_reboot(struct gnmi_session *gs, int64_t timeout_us);
int gnmi_gnoi_sonic_copy_merge(struct gnmi_session *gs, char *src, char *dst,
			       int64_t timeout_us);
int gnmi_gnoi_sonic_copy_overwrite(struct gnmi_session *gs, char *src,
				   char *dst, int64_t timeout_us);
int gnmi_gnoi_sonic_copy_replace(struct gnmi_session *gs, char *src, char *dst,
				 int64_t timeout_us);
int gnmi_gnoi_sonic_cfg_erase_boot(struct gnmi_session *gs, int64_t timeout_us);
int gnmi_gnoi_sonic_cfg_erase_boot_cancel(struct gnmi_session *gs,
					  int64_t timeout_us);
int gnmi_gnoi_image_install(struct gnmi_session *gs, const char *uri,
			    int64_t timeout_us);
int gnmi_gnoi_upgrade_status(struct gnmi_session *gs, char *res,
			     size_t res_size, int64_t timeout_us);
int gnmi_gnoi_sonic_alarm_acknowledge(struct gnmi_session *gs, const char **id,
				      size_t count, int64_t timeout_us);
int gnmi_gnoi_sonic_alarm_show(
	struct gnmi_session *gs,
	const struct gnmi_gnoi_sonic_alarm_show_request *request,
	struct gnmi_gnoi_sonic_alarm_show_response **response,
	int64_t timeout_us);
void gnmi_gnoi_sonic_alarm_show_response_free(
	struct gnmi_gnoi_sonic_alarm_show_response **response);

int gnmi_gnoi_poe_port_reset(struct gnmi_session *gs, const char *port,
			     int64_t timeout_us);

struct gnmi_subscribe *gnmi_subscribe_create(enum gnmi_subscribe_method method,
					     int updates_only);
int gnmi_subscribe_add(struct gnmi_subscribe *s, const char *path,
		       enum gnmi_subscribe_mode mode);
int gnmi_subscribe_start(struct gnmi_subscribe *s, struct gnmi_session *gs,
			 gnmi_subscribe_cb cb, void *data);
void gnmi_subscribe_stop(struct gnmi_subscribe *s);
void gnmi_subscribe_destroy(struct gnmi_subscribe *s);

struct gnmi_setrq;

struct gnmi_setrq *gnmi_setrq_create(void);
void gnmi_setrq_destroy(struct gnmi_setrq *rq);
int gnmi_setrq_add_jsoni_update(struct gnmi_setrq *rq, const char *path,
				const char *req);
int gnmi_setrq_add_jsoni_replace(struct gnmi_setrq *rq, const char *path,
				 const char *req);
int gnmi_setrq_add_delete(struct gnmi_setrq *rq, const char *path);
int gnmi_setrq_execute(struct gnmi_session *gs, const struct gnmi_setrq *rq,
		       struct gnmi_status *sts);
int gnmi_gnoi_techsupport_start(struct gnmi_session *gs, char *res_path);

#ifdef __cplusplus
}
#endif
