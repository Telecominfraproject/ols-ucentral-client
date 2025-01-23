/* SPDX-License-Identifier: BSD-3-Clause */
#include <stdbool.h>

#include <fcntl.h>

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <glob.h>
#include <libgen.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <libwebsockets.h>
#include <cjson/cJSON.h>

#include <ucentral-platform.h>
#include "ucentral-log.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ARRAY_LENGTH(array) (sizeof((array))/sizeof((array)[0]))

#define UCENTRAL_CONFIG	"/etc/ucentral/"
#define UCENTRAL_STATE	"/tmp/ucentral.state"
#define UCENTRAL_TMP	"/tmp/ucentral.cfg"
#define UCENTRAL_LATEST	"/etc/ucentral/ucentral.active"

/* It's expected that dev-id format is the following:
 * 11111111-1111-1111-1111-111111111111
 * and the max size of such string is 36 symbols.
 */
#define UCENTRAL_DEVID_F_MAX_LEN	(36)

struct client_config {
	const char *redirector_file;
	const char *redirector_file_dbg;
	const char *ols_client_version_file;
	const char *ols_schema_version_file;
	const char *server;
	int16_t port;
	const char *path;
	const char *serial;
	char CN[64];
	char firmware[64];
	char devid[UCENTRAL_DEVID_F_MAX_LEN + 1];
	int selfsigned;
	int debug;
};

typedef void (*uc_send_msg_cb)(const char *msg, size_t len);
typedef void (*uc_send_connect_msg_cb)(const char *msg, size_t len);

extern struct client_config client;
extern time_t conn_time;
extern struct plat_metrics_cfg ucentral_metrics;

/* proto.c */
void proto_handle(char *cmd);
void proto_cb_register_uc_send_msg(uc_send_msg_cb cb);
void proto_cb_register_uc_connect_msg_send(uc_send_connect_msg_cb cb);
void connect_send(void);
void ping_send(void);
void health_send(struct plat_health_info *);
void state_send(struct plat_state_info *plat_state_info);
void deviceupdate_send(const char *updated_pass);
void device_rebootcause_send(void);
void telemetry_send(struct plat_state_info *plat_state_info);
void log_send(const char *message, int severity);
void proto_start(void);
void proto_stop(void);
int upgrade_status_send(struct plat_upgrade_info *);

#ifdef __cplusplus
}
#endif
