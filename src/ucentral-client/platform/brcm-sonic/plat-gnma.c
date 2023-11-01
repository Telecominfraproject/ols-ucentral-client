#define _GNU_SOURCE /* asprintf */
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <sys/sysinfo.h>
#include <sys/mman.h>

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <poll.h>
#include <signal.h>

#include <curl/curl.h>

#include <ucentral-platform.h>
#define UC_LOG_COMPONENT UC_LOG_COMPONENT_PLAT
#include <ucentral-log.h>
#include <base64.h>

#include "gnma/gnma_common.h"
#include "plat-revision.h"

#include <cjson/cJSON.h>

#define SCRIPT_UID (1996)
#define SCRIPT_OUTLEN (512 * 1024)
#define SCRIPT_ARGMAX (32)
#define SCRIPT_TOKLEN (512)

#define ZFREE(p)           \
	do {               \
		free((p)); \
		(p) = 0;   \
	} while (0)

#define RTTY_SESS_MAX (10)

static int plat_state_get(struct plat_state_info *state);
static void plat_state_deinit(struct plat_state_info *state);
static int plat_port_speed_get(uint16_t fp_p_id, uint32_t *speed);
static int plat_port_duplex_get(uint16_t fp_p_id, bool *is_full_duplex);
static int plat_port_oper_status_get(uint16_t fp_p_id, bool *is_up);
static int plat_port_stats_get(uint16_t fp_p_id,
			       struct plat_port_counters *stats);
static int
plat_port_lldp_peer_info_get(uint16_t fp_p_id,
			     struct plat_port_lldp_peer_info *peer_info);
static int plat_upgrade_state(int *operation, int *percentage);
static int
plat_poe_port_state_get(uint16_t pid,
			struct plat_poe_port_state *state);
static int
plat_poe_state_get(struct plat_poe_state *state);
static int plat_port_speed_set(uint16_t fp_p_id, uint32_t speed);
static int plat_port_duplex_set(uint16_t fp_p_id, uint32_t duplex);
static int plat_port_admin_state_set(uint16_t fp_p_id, uint8_t state);
static int plat_vlan_rif_set(uint16_t vid, struct plat_ipv4 *ipv4);
int plat_vlan_memberlist_set(struct gnma_change *c,
			     struct gnma_vlan_member_bmap *vlan_mbr,
			     struct plat_port_vlan *vlan);
static int plat_vlan_list_set(BITMAP_DECLARE(, GNMA_MAX_VLANS));
static int plat_syslog_set(struct plat_syslog_cfg *log_cfg, int count);
static int
plat_ieee8021x_system_auth_clients_get(uint16_t port_id,
				       char **buf, size_t *buf_size,
				       struct plat_ieee8021x_port_info *state);

#define CFG_LOG_CRIT(...)                     \
	do {                                  \
		UC_LOG_CRIT(__VA_ARGS__);     \
		plat_log_printf(__VA_ARGS__); \
	} while (0)

#define ARRAY_LENGTH(array) (sizeof((array))/sizeof((array)[0]))

#define SPEED_TO_STR(p, str)						\
	({								\
		int rc = 0;						\
		switch (p) {						\
			case UCENTRAL_PORT_SPEED_10_E:			\
				strcpy(str, "10");			\
				break;					\
			case UCENTRAL_PORT_SPEED_100_E:			\
				strcpy(str, "100");			\
				break;					\
			case UCENTRAL_PORT_SPEED_1000_E:		\
				strcpy(str, "1000");			\
				break;					\
			case UCENTRAL_PORT_SPEED_2500_E:		\
				strcpy(str, "2500");			\
				break;					\
			case UCENTRAL_PORT_SPEED_5000_E:		\
				strcpy(str, "5000");			\
				break;					\
			case UCENTRAL_PORT_SPEED_10000_E:		\
				strcpy(str, "10000");			\
				break;					\
			case UCENTRAL_PORT_SPEED_25000_E:		\
				strcpy(str, "25000");			\
				break;					\
			case UCENTRAL_PORT_SPEED_40000_E:		\
				strcpy(str, "40000");			\
				break;					\
			case UCENTRAL_PORT_SPEED_100000_E:		\
				strcpy(str, "100000");			\
				break;					\
			default:					\
				rc = 1;					\
				break;					\
		}							\
		(rc);							\
	})
#define STR_TO_SPEED(p, str)						\
	({								\
		int rc = 0;						\
		rc = sscanf((str), "%u", (p));				\
	 	(rc);							\
	})

#define PLAT_RADIUS_HOST_EXISTS_IN_CFG(_host, head) \
	({bool res = false; \
	struct plat_radius_hosts_list *_pos; \
	UCENTRAL_LIST_FOR_EACH_MEMBER((_pos), (head)) { \
		if (strcmp((_host), ((_pos)->host.hostname)) == 0) { \
			res = true; \
			break; \
		} \
	} \
	(res);})

/* For now, let's define abs max buf size as:
 * 1024 (bytes) per client, 10 clients total at max for 100 ports;
 * Bare minimum client info has ~600B size (raw json).
 */
#define PLAT_IEEE8021X_AUT_CLIENTS_BUF_SIZE (1024 * 10 * 100)

enum {
	FEAT_CORE,
	FEAT_POE,
	FEAT_AAA,
	FEAT_MAX
};

enum {
	FEATSTS_FAIL = -1,
	FEATSTS_NONE = 0,
	FEATSTS_OK,
	FEATSTS_MAX
};

static int featsts[FEAT_MAX];

struct plat_cb_ctx {
	void (*cb)();
	void *data;
};

struct plat_telemetry_cb_ctx {
	void (*cb)(struct plat_state_info *);
	void *data;
};

struct plat_upgrade_cb_ctx {
	int (*cb)();
	void *data;
};

struct periodic {
	pthread_t t;
	int (*cb)(void *);
	void *data;
	uint64_t delay_usec;
	uint64_t period_usec;
	pthread_mutex_t mtx;
	pthread_cond_t cv;
	int stop;
};

struct poe_port {
	struct plat_poe_port_state state;
	struct gnma_port_key key;
	bool is_admin_mode_up;
	gnma_poe_port_detection_mode_t detection_mode;
	uint32_t power_limit;
	bool is_power_limit_user_defined;
	gnma_poe_port_priority_t priority;
};

/* Password is obfuscated and key changes all the time.
 * So cache only actual hosts (ip / hostname), and do a single
 * GNMI request to add host (with all parameters - passkey, port etc) upon
 * every cfg reqest.
 */
struct radius_host {
	struct gnma_radius_host_key key;
};

struct port {
	struct gnma_port_key key;
	struct {
		gnma_8021x_port_ctrl_mode_t control_mode;
		gnma_8021x_port_host_mode_t host_mode;
		uint16_t auth_fail_vid;
		uint16_t guest_vid;
		bool is_authenticator;
	} ieee8021x;
};

/* Schema doesn't support policy action and maxhop cfg,
 * so whenever define default values and use whenever (if) needed.
 */
#define PLAT_DHCP_RELAY_DEFAULT_POLICY_ACT (GNMA_DHCP_RELAY_POLICY_ACTION_REPLACE)
#define PLAT_DHCP_RELAY_DEFAULT_MAXHOP_CNT (10)
#define PLAT_DHCP_RELAY_MAX_SERVERS (1)
struct plat_state {
	struct {
		struct port array[MAX_NUM_OF_PORTS];
		BITMAP_DECLARE(ports_bmap, MAX_NUM_OF_PORTS);
	} ports;
	struct {
		struct {
			gnma_dhcp_relay_policy_action_type_t policy_act;
			gnma_dhcp_relay_circuit_id_t circ_id;
			uint8_t max_hop_cnt;
			struct gnma_ip helper_addresses[PLAT_DHCP_RELAY_MAX_SERVERS];
			bool enabled;
		} dhcp_relay;
	} vlans[GNMA_MAX_VLANS];
	struct {
		gnma_poe_power_mgmt_mode_t power_mgmt;
		uint8_t usage_threshold;
		/* Alloc all ports, but access them only if bit is set. */
		struct poe_port ports[MAX_NUM_OF_PORTS];
		BITMAP_DECLARE(ports_bmap, MAX_NUM_OF_PORTS);
	} poe;
	struct {
		bool is_auth_control_enabled;
	} ieee8021x;
	struct {
		struct gnma_radius_host_key *hosts_keys_arr;
		size_t hosts_keys_arr_size;
	} radius;
	struct ucentral_router router;
	gnma_stp_mode_t stp_mode;
	struct gnma_stp_attr stp_mode_attr;
	struct gnma_stp_attr stp_vlan_attr[GNMA_MAX_VLANS];
	/* TODO: max num per iface */
	struct plat_ipv4 portsl2_rif_ipv4[MAX_NUM_OF_PORTS];
} plat_state;

#define plat_log_ringbuf_size 64
static char *plat_log_ringbuf[plat_log_ringbuf_size];
static size_t plat_log_ringbuf_rp = 0;
static size_t plat_log_ringbuf_wp = 0;

static const char *cfgid_path = "/var/lib/ucentral/saved_config_id";
static const char *cfgmetrics_path = "/var/lib/ucentral/saved_cfg_metrics";

static void *subscribe_hdl;
static struct plat_event_callbacks events_cbs;

static struct periodic *health_periodic;
static struct periodic *telemetry_periodic;
static struct periodic *state_periodic;
static struct periodic *upgrade_periodic;

#define IMG_DL_FILE_PATH "/var/lib/ucentral/img"
#define IMG_DL_PIPE_PATH "/var/lib/ucentral/upgrade_pipe"
#define IMG_DL_DEB_FILE_SIGNATURE "\x21\x3C\x61\x72\x63\x68\x3E"
static struct img_dl_task {
	bool active;
	bool downloaded_full_img;
	CURL *curl;
	pthread_t t;
	FILE *fp;
	uint8_t percentage;
	uint8_t upgrade_state;
} img_dl_task;

static struct script_ctx {
	pthread_t tid;
	int is_tid_valid;
	plat_run_script_cb cb;
	void *ctx;
	int t;
	char *script_buf;
	size_t script_bufsz;
	char *outbuf;
} script_ctx;

static pthread_mutex_t script_mtx = PTHREAD_MUTEX_INITIALIZER;
static int script_count;

static int script_lock_aquire(void)
{
	int rc = -1;
	if (!pthread_mutex_lock(&script_mtx)) {
		if (!script_count) {
			++script_count;
			rc = 0;
		}
		pthread_mutex_unlock(&script_mtx);
	}
	return rc;
}

static void script_lock_release(void)
{
	if (!pthread_mutex_lock(&script_mtx)) {
		if (script_count)
			--script_count;
		pthread_mutex_unlock(&script_mtx);
	}
}

/* free() must be called for returned string */
char *plat_log_pop(void)
{
	char *msg = plat_log_ringbuf[plat_log_ringbuf_rp];

	if (msg) {
		plat_log_ringbuf[plat_log_ringbuf_rp] = NULL;

		plat_log_ringbuf_rp++;
		plat_log_ringbuf_rp %= plat_log_ringbuf_size;

		return msg;
	}

	return NULL;
}

void plat_log_flush(void)
{
	char *msg;
	for (msg = plat_log_pop(); msg; msg = plat_log_pop())
		free(msg);
}

/* free() must be called for returned string */
char *plat_log_pop_concatenate(void)
{
	char *res_prev, *res, *msg;
	int ret;

	res = calloc(1, 1);
	if (!res)
		return NULL;

	for (msg = plat_log_pop(), res_prev = res;
	     msg; msg = plat_log_pop(), res_prev = res) {
		ret = asprintf(&res, "%s%s\n", res, msg);
		free(msg);
		free(res_prev);

		if (ret == -1)
			return NULL;
	}

	return res;
}

static void __plat_log_push(char *msg)
{
	char *old_msg;

	plat_log_ringbuf_wp++;
	plat_log_ringbuf_wp %= plat_log_ringbuf_size;

	if (plat_log_ringbuf_wp == plat_log_ringbuf_rp) {
		old_msg = plat_log_pop();
		free(old_msg);
	}

	plat_log_ringbuf[plat_log_ringbuf_wp] = msg;
}

static void plat_log_printf(const char *fmt, ...)
{
	char *new_msg;
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vasprintf(&new_msg, fmt, ap);
	va_end(ap);
	if (ret == -1 || !new_msg)
		return;

	__plat_log_push(new_msg);
}

static void plat_log_push(const char *msg)
{
	plat_log_printf("%s", msg);
}

static int fdsetcmd(int fd, int getcmd, int setcmd, int is_set, int fl)
{
	int flag = fcntl(fd, getcmd);

	if (flag < 0 ||
	    fcntl(fd, setcmd, is_set ? (flag | fl) : (flag & ~(fl))))
		return -1;

	return 0;
}

static pid_t spawnp(const char *path, char *av[], char *env[],
		    const sigset_t *sigset, int uid, int gid, int *ifd,
		    int *ofd, int set_flag)
{
	int e;
	pid_t pid;
	int in, out;
	int pin[2] = { -1, -1 }, pout[2] = { -1, -1 };

	if (!ifd) {
		in = -1;
	} else if (*ifd < 0) {
		if (pipe(pin))
			goto err;
		in = pin[0];
		if (set_flag && fdsetcmd(pin[1], F_GETFL, F_SETFL, 1, set_flag))
			goto err;
	} else {
		in = *ifd;
	}

	if (!ofd) {
		out = -1;
	}
	if (*ofd < 0) {
		if (pipe(pout))
			goto err;
		out = pout[1];
		if (set_flag &&
		    fdsetcmd(pout[0], F_GETFL, F_SETFL, 1, set_flag))
			goto err;
	} else {
		out = *ofd;
	}

	pid = fork();
	if (pid < 0)
		goto err;

	if (!pid) {
		if ((in >= 0 && dup2(in, 0) < 0) ||
		    (out >= 0 && dup2(out, 1) < 0)) {
			_exit(1);
		}

		if (sigset && sigprocmask(SIG_SETMASK, sigset, 0)) {
			_exit(1);
		}

		if (in > 0)
			close(in);
		if (out >= 0 && out != 1)
			close(out);

		close(pin[1]);
		close(pout[0]);

		/*
         * TODO(vb) closefrom(3)
         */
		if (gid >= 0 && setgid(gid)) {
			_exit(1);
		}
		if (uid >= 0 && setuid(uid)) {
			_exit(1);
		}
		if (env) {
			execvpe(path, av, env);
		} else {
			execvp(path, av);
		}
		_exit(1);
	}

	e = errno;
	close(pin[0]);
	if (ifd && *ifd < 0)
		*ifd = pin[1];

	close(pout[1]);
	if (ofd && *ofd < 0)
		*ofd = pout[0];
	errno = e;

	return pid;

err:
	e = errno;
	close(pin[0]);
	close(pout[1]);
	close(pin[0]);
	close(pout[1]);
	errno = e;
	return -1;
}

struct timespec sub_timespec(const struct timespec *a, const struct timespec *b)
{
	struct timespec d = {
		.tv_sec = a->tv_sec - b->tv_sec,
		.tv_nsec = a->tv_nsec - b->tv_nsec,
	};
	if (d.tv_nsec < 0) {
		--d.tv_sec;
		d.tv_nsec += 1000000000L;
	}
	return d;
}

void (*main_log_cb)(const char *) = plat_log_push;

static int plat_poe_port_num_get(uint16_t *num_of_active_poe_ports)
{
	struct gnma_port_key port_key_list = {0};
	uint16_t list_size = 1;
	int ret;

	ret = gnma_poe_port_list_get(&list_size, &port_key_list);
	if (ret && ret != GNMA_ERR_OVERFLOW) {
		*num_of_active_poe_ports = 0;
		return ret;
	}

	*num_of_active_poe_ports = list_size;

	return 0;
}

static int plat_state_poe_init()
{
	struct gnma_port_key *poe_ports_arr = NULL;
	uint16_t poe_port_arr_size = 0;
	struct poe_port *port;
	uint16_t pid;
	int ret;
	int i;

	ret = plat_poe_port_num_get(&poe_port_arr_size);
	if (ret) {
		UC_LOG_DBG("plat_poe_port_num_get");
		goto err;
	}

	poe_ports_arr = calloc(poe_port_arr_size, sizeof(*poe_ports_arr));
	if (!poe_ports_arr)
		goto err;

	ret = gnma_poe_port_list_get(&poe_port_arr_size, poe_ports_arr);
	if (ret) {
		UC_LOG_DBG("gnma_poe_port_list_get");
		goto err;
	}

	for (i = 0; i < poe_port_arr_size; ++i) {
		NAME_TO_PID(&pid, poe_ports_arr[i].name);
		BITMAP_SET_BIT(plat_state.poe.ports_bmap, pid);

		port = &plat_state.poe.ports[pid];

		strcpy(port->key.name, poe_ports_arr[i].name);

		ret = gnma_poe_port_admin_mode_get(&port->key,
						   &port->is_admin_mode_up);
		if (ret) {
			UC_LOG_ERR("gnma_poe_port_admin_mode_get");
			goto err;
		}

		ret = gnma_poe_port_detection_mode_get(&port->key,
						       &port->detection_mode);
		if (ret) {
			UC_LOG_ERR("gnma_poe_port_detection_mode_get");
			goto err;
		}

		ret = gnma_poe_port_power_limit_get(&port->key,
						    &port->is_power_limit_user_defined,
						    &port->power_limit);
		if (ret) {
			UC_LOG_ERR("gnma_poe_port_power_limit_get");
			goto err;
		}

		ret = gnma_poe_port_priority_get(&port->key,
						 &port->priority);
		if (ret) {
			UC_LOG_ERR("gnma_poe_port_priority_get");
			goto err;
		}
	}

	ret = gnma_poe_power_mgmt_get(&plat_state.poe.power_mgmt);
	if (ret) {
		UC_LOG_ERR("gnma_poe_power_mgmt_get");
		goto err;
	}
	ret = gnma_poe_usage_threshold_get(&plat_state.poe.usage_threshold);
	if (ret) {
		UC_LOG_ERR("gnma_poe_usage_threshold_get");
		goto err;
	}

	ret = 0;

err:
	free(poe_ports_arr);
	return ret;
}

static int plat_state_radius_init()
{
	int ret;

	free(plat_state.radius.hosts_keys_arr);
	plat_state.radius.hosts_keys_arr = NULL;
	plat_state.radius.hosts_keys_arr_size = 0;

	ret = gnma_radius_hosts_list_get(&plat_state.radius.hosts_keys_arr_size,
					 NULL);
	if (ret && ret != GNMA_ERR_OVERFLOW) {
		UC_LOG_CRIT("gnma_radius_hosts_list_get failed");
		plat_state.radius.hosts_keys_arr_size = 0;
		return ret;
	}

	/* No RADIUS hosts configured, no need to update cache. */
	if (0 == plat_state.radius.hosts_keys_arr_size)
		return 0;

	plat_state.radius.hosts_keys_arr =
		calloc(plat_state.radius.hosts_keys_arr_size,
		       sizeof(*plat_state.radius.hosts_keys_arr));
	if (!plat_state.radius.hosts_keys_arr) {
		ret = -ENOMEM;
		goto err;
	}

	ret = gnma_radius_hosts_list_get(&plat_state.radius.hosts_keys_arr_size,
					 plat_state.radius.hosts_keys_arr);
	if (ret) {
		UC_LOG_CRIT("gnma_radius_hosts_list_get failed");
		goto err;
	}
	return 0;

err:
	free(plat_state.radius.hosts_keys_arr);
	plat_state.radius.hosts_keys_arr = NULL;
	plat_state.radius.hosts_keys_arr_size = 0;
	return ret;
}

static void router_fib_key2gnma_prefix(struct ucentral_router_fib_key *uk,
				       struct gnma_ip_prefix *gp)
{
	gp->ip.v = AF_INET;
	gp->ip.u.v4 = uk->prefix;
	gp->prefix_len = uk->prefix_len;
}

static void gnma_prefix2router_fib_key(struct gnma_ip_prefix *gp,
				       struct ucentral_router_fib_key *uk)
{
	/* TODO ipv6 ? */
	uk->prefix = gp->ip.u.v4;
	uk->prefix_len = gp->prefix_len;
}

static int router_fib_info2gnma_attr(struct ucentral_router_fib_info *ui,
				     struct gnma_route_attrs *ga)
{
	switch (ui->type) {
	case UCENTRAL_ROUTE_BLACKHOLE:
		ga->type = GNMA_ROUTE_TYPE_BLACKHOLE;
		break;
	case UCENTRAL_ROUTE_CONNECTED:
		ga->type = GNMA_ROUTE_TYPE_CONNECTED;
		ga->connected.vid = ui->connected.vid;
		break;
	case UCENTRAL_ROUTE_NH:
		ga->type = GNMA_ROUTE_TYPE_NEXTHOP;
		ga->nexthop.vid = ui->nh.vid;
		ga->nexthop.gw = ui->nh.gw;
		break;
	default:
		return -1;
	}

	return 0;
}

static int gnma_attr2router_fib_info(struct gnma_route_attrs *ga,
				     struct ucentral_router_fib_info *ui)
{
	switch (ga->type) {
	case GNMA_ROUTE_TYPE_BLACKHOLE:
		ui->type = UCENTRAL_ROUTE_BLACKHOLE;
		break;
	case GNMA_ROUTE_TYPE_CONNECTED:
		ui->type = UCENTRAL_ROUTE_CONNECTED;
		ui->connected.vid = ga->connected.vid;
		break;
	case GNMA_ROUTE_TYPE_NEXTHOP:
		ui->type = UCENTRAL_ROUTE_NH;
		ui->nh.vid = ga->nexthop.vid;
		ui->nh.gw = ga->nexthop.gw;
		break;
	default:
		return -1;
	}

	return 0;
}

static int plat_state_portsl2_init()
{
	struct gnma_port_key *plist = NULL;
	uint16_t pcount = 0, list_size;
	struct gnma_ip_prefix prefix;
	uint16_t pid;
	int err = -1;
	int i;

	if (plat_port_num_get(&pcount)) {
		UC_LOG_ERR("plat_port_num_get failed");
		goto err;
	}

	plist = calloc(pcount, sizeof(*plist));
	if (!plist)
		goto err;

	if (gnma_port_list_get(&pcount, plist)) {
		UC_LOG_ERR("gnma_port_list_get failed");
		goto err;
	}

	/* TODO generic ports iterator... Cache ? */
	for (i = 0; i < pcount; i++) {
		list_size = 1; /* TODO */
		/* plat_state initialized with zeroes */
		if (gnma_portl2_erif_attr_pref_list_get(&plist[i], &list_size,
							&prefix)) {
			UC_LOG_ERR("gnma_port_list_get failed");
			goto err;
		}

		if (list_size && prefix.ip.v == AF_INET) {
			NAME_TO_PID(&pid, plist[i].name);
			plat_state.portsl2_rif_ipv4[pid].subnet_len = prefix.prefix_len;
			memcpy(&plat_state.portsl2_rif_ipv4[pid].subnet,
			       &prefix.ip.u.v4, sizeof(prefix.ip.u.v4));
			plat_state.portsl2_rif_ipv4[pid].exist = true;
		}
	}

	err = 0;
err:
	free(plist);
	return err;
}

static int plat_state_port_ieee8021x_init(struct port *port)
{
	int ret;

	ret = gnma_port_ieee8021x_pae_mode_get(
		&port->key, &port->ieee8021x.is_authenticator);
	if (ret) {
		UC_LOG_ERR("<%s> gnma_port_ieee8021x_pae_mode_get failed",
			   port->key.name);
		return -1;
	}

	ret = gnma_port_ieee8021x_port_ctrl_get(&port->key,
						&port->ieee8021x.control_mode);
	if (ret) {
		UC_LOG_ERR("<%s> gnma_port_ieee8021x_port_ctrl_get failed",
			   port->key.name);
		return -1;
	}

	ret = gnma_port_ieee8021x_port_host_mode_get(
		&port->key, &port->ieee8021x.host_mode);
	if (ret) {
		UC_LOG_ERR("<%s> gnma_port_ieee8021x_port_host_mode_get failed",
			   port->key.name);
		return -1;
	}

	ret = gnma_port_ieee8021x_guest_vlan_get(&port->key,
						 &port->ieee8021x.guest_vid);
	if (ret) {
		UC_LOG_ERR("<%s> gnma_port_ieee8021x_guest_vlan_get failed",
			   port->key.name);
		return -1;
	}

	ret = gnma_port_ieee8021x_unauthorized_vlan_get(
		&port->key, &port->ieee8021x.auth_fail_vid);
	if (ret) {
		UC_LOG_ERR(
			"<%s> gnma_port_ieee8021x_unauthorized_vlan_get failed",
			port->key.name);
		return -1;
	}

	return ret;
}

static int plat_state_ports_init()
{
	struct gnma_port_key *port_key_list;
	uint16_t port_list_num;
	struct port *port;
	uint16_t port_id;
	int ret;
	int i;

	ret = plat_port_num_get(&port_list_num);
	if (ret) {
		UC_LOG_ERR("Failed to get num of active ports");
		return ret;
	}

	port_key_list = calloc(port_list_num, sizeof(*port_key_list));
	if (!port_key_list) {
		ret = -ENOMEM;
		goto err;
	}

	ret = gnma_port_list_get(&port_list_num, port_key_list);
	if (ret && ret != GNMA_ERR_OVERFLOW) {
		UC_LOG_ERR("Port list get failed");
		goto err;
	}

	for (i = 0; i < port_list_num; ++i) {
		NAME_TO_PID(&port_id, port_key_list[i].name);
		BITMAP_SET_BIT(plat_state.ports.ports_bmap, port_id);

		port = &plat_state.ports.array[port_id];

		memcpy(&port->key, &port_key_list[i],
		       sizeof(port_key_list[i]));

		if (plat_state_port_ieee8021x_init(port)) {
			UC_LOG_ERR("plat_state_port_ieee8021x_init failed");
			featsts[FEAT_AAA] = FEATSTS_FAIL;
		}
	}

	free(port_key_list);
	return 0;
err:
	free(port_key_list);
	BITMAP_CLEAR(plat_state.ports.ports_bmap, MAX_NUM_OF_PORTS);
	return ret;
}

static int plat_state_init()
{
	BITMAP_DECLARE(vlans, GNMA_MAX_VLANS);
	size_t arr_size = PLAT_DHCP_RELAY_MAX_SERVERS;
	struct gnma_route_attrs *attrs_list = NULL;
	struct gnma_ip_prefix *prefix_list = NULL;
	uint32_t prefix_list_size = 0, prefix_iter;
	struct ucentral_router_fib_node node;
	uint16_t vid;
	int ret = 0;
	size_t i;

	memset(&plat_state, 0, sizeof(plat_state));
	memset(&featsts, 0, sizeof featsts);

	featsts[FEAT_CORE] = FEATSTS_FAIL;

	ret = gnma_ieee8021x_system_auth_control_get(&plat_state.ieee8021x.is_auth_control_enabled);
	if (ret) {
		UC_LOG_CRIT("gnma_ieee8021x_system_auth_control_get failed");
		featsts[FEAT_AAA] = FEATSTS_FAIL;
	}

	ret = plat_state_ports_init();
	if (ret) {
		UC_LOG_CRIT("plat_state_ports_init failed");
		goto err;
	}

	BITMAP_CLEAR(vlans, GNMA_MAX_VLANS);
	ret = gnma_vlan_list_get(vlans);
	if (ret) {
		UC_LOG_CRIT("gnma_vlan_list_get");
		goto err;
	}

	ret = gnma_stp_mode_get(&plat_state.stp_mode, &plat_state.stp_mode_attr);
	if (ret) {
		UC_LOG_CRIT("gnma_stp_mode_get");
		goto err;
	}

	ret = gnma_stp_vid_bulk_get(&plat_state.stp_vlan_attr[0],
				    GNMA_MAX_VLANS);
	if (ret) {
		UC_LOG_CRIT("gnma_stp_vid_bulk_get");
		goto err;
	}

	BITMAP_FOR_EACH_BIT_SET(i, vlans, GNMA_MAX_VLANS)
	{
		/* It's possible that relay is not configured on this vlan.
		 * Ignore and proceed to next.
		 */
		vid = (uint16_t)i;
		ret = gnma_vlan_dhcp_relay_server_list_get(vid, &arr_size,
							   &plat_state.vlans[vid].dhcp_relay.helper_addresses[0]);
		if (ret)
			continue;

		ret = gnma_vlan_dhcp_relay_ciruit_id_get(vid,
							 &plat_state.vlans[vid].dhcp_relay.circ_id);
		if (ret) {
			UC_LOG_CRIT("gnma_vlan_dhcp_relay_ciruit_id_get");
			goto err;
		}

		ret = gnma_vlan_dhcp_relay_policy_action_get(vid,
							     &plat_state.vlans[vid].dhcp_relay.policy_act);
		if (ret) {
			UC_LOG_CRIT("gnma_vlan_dhcp_relay_policy_action_get");
			goto err;
		}

		ret = gnma_vlan_dhcp_relay_max_hop_cnt_get(vid,
							   &plat_state.vlans[vid].dhcp_relay.max_hop_cnt);
		if (ret) {
			UC_LOG_CRIT("gnma_vlan_dhcp_relay_max_hop_cnt_get");
			goto err;
		}

		plat_state.vlans[vid].dhcp_relay.enabled = true;
	}

	if (plat_state_poe_init()) {
		UC_LOG_CRIT("plat_state_poe_init");
		featsts[FEAT_POE] = FEATSTS_FAIL;
	}

	if (plat_state_portsl2_init()) {
		UC_LOG_CRIT("plat_state_portsl2_init");
		goto err;
	}

	ret = gnma_route_list_get(0, &prefix_list_size,
				  prefix_list, attrs_list);
	if (ret && ret != GNMA_ERR_OVERFLOW) {
		UC_LOG_CRIT("gnma_route_list_get");
		goto err;
	}

	prefix_list = calloc(prefix_list_size, sizeof(prefix_list[0]));
	attrs_list = calloc(prefix_list_size, sizeof(attrs_list[0]));
	if (!prefix_list || !attrs_list) {
		goto err;
	}

	ret = gnma_route_list_get(0, &prefix_list_size,
				  prefix_list, attrs_list);
	if (ret) {
		UC_LOG_CRIT("gnma_route_list_get");
		goto err;
	}

	/* TODO ECMP */
	ucentral_router_fib_db_free(&plat_state.router);
	ret = ucentral_router_fib_db_alloc(&plat_state.router, prefix_list_size);
	if (ret) {
		UC_LOG_CRIT("ucentral_router_fib_db_alloc");
		goto err;
	}

	for (prefix_iter = 0; prefix_iter < prefix_list_size; prefix_iter++) {
		gnma_prefix2router_fib_key(&prefix_list[prefix_iter], &node.key);
		ret = gnma_attr2router_fib_info(&attrs_list[prefix_iter], &node.info);
		if (ret) {
			UC_LOG_CRIT("gnma_attr2router_fib_info");
			goto err;
		}

		ret = ucentral_router_fib_db_append(&plat_state.router, &node);
		if (ret) {
			UC_LOG_CRIT("ucentral_router_fib_db_append");
			goto err;
		}
	}

	ret = plat_state_radius_init();
	if (ret) {
		UC_LOG_CRIT("plat_state_radius_init failed");
		featsts[FEAT_AAA] = FEATSTS_FAIL;
	}

	if (featsts[FEAT_AAA] == FEATSTS_FAIL) {
		UC_LOG_CRIT("AAA feature failed to initialize");
	} else {
		featsts[FEAT_AAA] = FEATSTS_OK;
	}

	if (featsts[FEAT_POE] == FEATSTS_FAIL) {
		UC_LOG_CRIT("POE feature failed to initialize");
	} else {
		featsts[FEAT_POE] = FEATSTS_OK;
	}

	featsts[FEAT_CORE] = FEATSTS_OK;
err:
	free (prefix_list);
	free (attrs_list);

	for (i = 0; i < FEAT_MAX; ++i) {
		if (featsts[i] != FEATSTS_OK) {
			return -1;
		}
	}

	return 0;
}

int plat_init(void)
{
	if (gnma_switch_create()) {
		UC_LOG_CRIT("gnma_switch_create failed");
		return -1;
	}

	if (plat_state_init()) {
		UC_LOG_CRIT("plat_state_init failed");
		return -1;
	}

	return 0;
}

static void *periodic_thread(void *args)
{
	int rc;
	struct periodic *p = args;
	uint64_t timeout = p->delay_usec;
	struct timespec now = { 0 };
	struct timespec deadline = { 0 };
	int stop = 0;

	UC_LOG_DBG("enter");
	while (1) {
		rc = 0;
		pthread_mutex_lock(&p->mtx);
		/* TODO(vb) monotonic clock wrap-up? check how that is handled in
		 *			FUTEX_WAIT. */
		clock_gettime(CLOCK_MONOTONIC, &now);

		/* TODO(vb) overflows? */
		deadline.tv_sec = now.tv_sec + (timeout / 1000000);
		deadline.tv_nsec = now.tv_nsec + (timeout % 1000000) * 1000;
		if (deadline.tv_nsec >= 1000000000) {
			/* normalize */
			deadline.tv_sec += 1;
			deadline.tv_nsec -= 1000000000;
		}
		while (!p->stop && !rc) {
			rc = pthread_cond_timedwait(&p->cv, &p->mtx, &deadline);
		}
		stop = p->stop;
		pthread_mutex_unlock(&p->mtx);

		if (stop)
			break;

		if (rc != ETIMEDOUT) {
			UC_LOG_ERR("pthread_cond_timedwait rc=%d", rc);
			break;
		}

		/* If cb returned nonzero value - it signalizes the periodic
		 * subsystem that this thread should exit.
		 */
		if (p->cb)
			if (p->cb(p->data))
				break;

		timeout = p->period_usec;
	}
	UC_LOG_DBG("exit");
	return 0;
}

static int periodic_create(struct periodic **periodic, uint64_t delay_usec,
			   uint64_t period_usec, int (*cb)(void *), void *data)
{
	pthread_condattr_t cvattr;
	struct periodic *p = 0;
	int ret = -1;

	if (!periodic)
		return -1;

	if (!(p = malloc(sizeof *p))) {
		UC_LOG_DBG("malloc failed: %s", strerror(errno));
		return -1;
	}
	*p = (struct periodic){
		.cb = cb,
		.data = data,
		.period_usec = period_usec,
		.delay_usec = delay_usec,
	};
	pthread_condattr_init(&cvattr);
	if (pthread_condattr_setclock(&cvattr, CLOCK_MONOTONIC)) {
		UC_LOG_DBG("pthread_condattr_setclock: %s", strerror(errno));
		goto err;
	}
	if (pthread_cond_init(&p->cv, &cvattr)) {
		UC_LOG_DBG("pthread_cond_init: %s", strerror(errno));
		goto err;
	}
	pthread_mutex_init(&p->mtx, 0);
	if (pthread_create(&p->t, 0, periodic_thread, p)) {
		UC_LOG_DBG("pthread_create failed: %s", strerror(errno));
		pthread_cond_destroy(&p->cv);
		pthread_mutex_destroy(&p->mtx);
		goto err;
	}

	*periodic = p;
	p = 0;
	ret = 0;
err:
	pthread_condattr_destroy(&cvattr);
	free(p);
	return ret;
}

static void periodic_destroy(struct periodic **p)
{
	if (!p || !*p)
		return;
	pthread_mutex_lock(&(*p)->mtx);
	(*p)->stop = 1;
	pthread_mutex_unlock(&(*p)->mtx);
	pthread_cond_broadcast(&(*p)->cv);
	pthread_join((*p)->t, 0);
	pthread_cond_destroy(&(*p)->cv);
	pthread_mutex_destroy(&(*p)->mtx);
	free(*p);
	*p = 0;
}

static int health_periodic_cb(void *data)
{
	struct plat_cb_ctx *ctx = data;
	void (*cb)(struct plat_health_info *) = ctx->cb;
	struct plat_health_info health = {
		.sanity = 100,
	};

	if (featsts[FEAT_CORE] != FEATSTS_OK) {
		health.sanity = 0;
		snprintf(health.msg[2], sizeof health.msg[2],
			 "the core features are not initialized");

	} else {
		if (featsts[FEAT_AAA] != FEATSTS_OK) {
			health.sanity = 50;
			snprintf(health.msg[0], sizeof health.msg[0],
				 "the 8021X feature is not initialized");
		}

		if (featsts[FEAT_POE] != FEATSTS_OK) {
			health.sanity = 50;
			snprintf(health.msg[1], sizeof health.msg[1],
				 "the POE feature is not initialized");
		}
	}

	if (cb)
		cb(&health);

	return 0;
}

void plat_health_poll(void (*cb)(struct plat_health_info *), int period_sec)
{
	static struct plat_cb_ctx ctx;
	periodic_destroy(&health_periodic);
	ctx = (struct plat_cb_ctx){
		.cb = (void (*)())cb,
	};
	periodic_create(&health_periodic, 0, period_sec * 1000000,
			health_periodic_cb, &ctx);
}

void plat_health_poll_stop(void)
{
	periodic_destroy(&health_periodic);
}

static int telemetry_periodic_cb(void *data)
{
	struct plat_telemetry_cb_ctx *ctx = data;
	void (*cb)(struct plat_state_info *) = ctx->cb;
	struct plat_state_info state = {0};

	if (plat_state_get(&state)) {
		return 0;
	}

	if (cb)
		cb(&state);

	plat_state_deinit(&state);

	return 0;
}

void plat_telemetry_poll(void (*cb)(struct plat_state_info *), int period_sec)
{
	static struct plat_telemetry_cb_ctx ctx;
	periodic_destroy(&telemetry_periodic);
	ctx = (struct plat_telemetry_cb_ctx){
		.cb = cb,
	};
	periodic_create(&telemetry_periodic, 0, period_sec * 1000000,
			telemetry_periodic_cb, &ctx);
}

void plat_telemetry_poll_stop(void)
{
	periodic_destroy(&telemetry_periodic);
}

static int state_periodic_cb(void *data)
{
	struct plat_telemetry_cb_ctx *ctx = data;
	void (*cb)(struct plat_state_info *) = ctx->cb;
	struct plat_state_info state = {0};

	if (plat_state_get(&state)) {
		return 0;
	}

	if (cb)
		cb(&state);

	plat_state_deinit(&state);

	return 0;
}

void plat_state_poll(void (*cb)(struct plat_state_info *), int period_sec)
{
	static struct plat_telemetry_cb_ctx ctx;
	periodic_destroy(&state_periodic);
	ctx = (struct plat_telemetry_cb_ctx){
		.cb = (void (*)(struct plat_state_info *))cb,
	};
	periodic_create(&state_periodic, 0, period_sec * 1000000,
			state_periodic_cb, &ctx);
}

void plat_state_poll_stop(void)
{
	periodic_destroy(&state_periodic);
}

static int upgrade_periodic_cb(void *data)
{
	struct plat_upgrade_cb_ctx *ctx = data;
	int (*cb)(struct plat_upgrade_info *) = ctx->cb;
	struct plat_upgrade_info upgrade = { 0 };

	if (plat_upgrade_state(&upgrade.operation, &upgrade.percentage))
		return 0;

	if (cb)
		if (cb(&upgrade))
			return -1;

	return 0;
}

void plat_upgrade_poll(int (*cb)(struct plat_upgrade_info *), int period_sec)
{
	static struct plat_upgrade_cb_ctx ctx;
	periodic_destroy(&upgrade_periodic);
	ctx = (struct plat_upgrade_cb_ctx){
		.cb = (int (*)())cb,
	};
	periodic_create(&upgrade_periodic, 0, period_sec * 1000000,
			upgrade_periodic_cb, &ctx);
}

void plat_upgrade_poll_stop(void)
{
	periodic_destroy(&upgrade_periodic);
}

int plat_port_admin_state_set(uint16_t fp_p_id, uint8_t state)
{
	struct gnma_port_key gnma_port;

	PID_TO_NAME(fp_p_id, gnma_port.name);

	gnma_port_admin_state_set(&gnma_port, state == UCENTRAL_PORT_ENABLED_E ? true : false);
	return 0;
}

int plat_port_speed_set(uint16_t fp_p_id, uint32_t speed)
{
	struct gnma_port_key gnma_port;
	char speed_str[32] = {0};

	PID_TO_NAME(fp_p_id, gnma_port.name);
	if (SPEED_TO_STR(speed, speed_str))
		return -1;

	gnma_port_speed_set(&gnma_port, speed_str);

	return 0;
}

int plat_port_duplex_set(uint16_t fp_p_id, uint32_t duplex)
{
	struct gnma_port_key gnma_port;

	PID_TO_NAME(fp_p_id, gnma_port.name);

	gnma_port_duplex_set(&gnma_port,
			     duplex == UCENTRAL_PORT_DUPLEX_FULL_E
			     ? true
			     : false);

	return 0;
}

int plat_port_speed_get(uint16_t fp_p_id, uint32_t *speed)
{
	struct gnma_port_key gnma_port;
	char speed_str[8] = {0};
	int ret;

	PID_TO_NAME(fp_p_id, gnma_port.name);

	ret = gnma_port_speed_get(&gnma_port, speed_str, sizeof(speed_str));
	if (ret)
		return ret;

	STR_TO_SPEED(speed, speed_str);
	return 0;
}

int plat_port_duplex_get(uint16_t fp_p_id, bool *is_full_duplex)
{
	struct gnma_port_key gnma_port;

	PID_TO_NAME(fp_p_id, gnma_port.name);

	return gnma_port_duplex_get(&gnma_port, is_full_duplex);
}

int plat_port_oper_status_get(uint16_t fp_p_id, bool *is_up)
{
	struct gnma_port_key gnma_port;

	PID_TO_NAME(fp_p_id, gnma_port.name);

	return gnma_port_oper_status_get(&gnma_port, is_up);
}

int plat_port_num_get(uint16_t *num_of_active_ports)
{
	struct gnma_port_key port_key_list = {0};
	uint16_t list_size = 1;
	int ret;

	/* It is NOT safe to not pass prt to list (e.g. NULL), as underlying
	 * function might memset this <object> ptr. C standard explicitly states
	 * that memsset(0, 0, 0) (where dst is NULL) is UB.
	 * Pass at least <one> object (port_key_list), but pass size <zero>
	 * (list_size).
	 */
	ret = gnma_port_list_get(&list_size, &port_key_list);
	if (ret && ret != GNMA_ERR_OVERFLOW) {
		*num_of_active_ports = 0;
		return ret;
	}

	*num_of_active_ports = list_size;

	return 0;
}

int plat_port_list_get(uint16_t list_size,
		       struct plat_ports_list *ports)
{
	struct plat_ports_list *port_node;
	struct gnma_port_key *port_key_list;
	int i = 0;
	int ret;

	port_key_list = calloc(list_size, sizeof(*port_key_list));
	if (!port_key_list)
		return -ENOMEM;

	ret = gnma_port_list_get(&list_size, port_key_list);
	if (ret && ret != GNMA_ERR_OVERFLOW)
		return ret;

	UCENTRAL_LIST_FOR_EACH_MEMBER(port_node, &ports)
		strcpy(port_node->name, port_key_list[i++].name);

	free(port_key_list);
	return 0;
}

int plat_port_stats_get(uint16_t fp_p_id, struct plat_port_counters *stats)
{
	gnma_port_stat_type_t stat_types[] = {
		GNMA_PORT_STAT_IN_OCTETS,
		GNMA_PORT_STAT_IN_DISCARDS,
		GNMA_PORT_STAT_IN_ERRORS,
		GNMA_PORT_STAT_IN_BCAST_PKTS,
		GNMA_PORT_STAT_IN_MCAST_PKTS,
		GNMA_PORT_STAT_IN_UCAST_PKTS,
		GNMA_PORT_STAT_OUT_OCTETS,
		GNMA_PORT_STAT_OUT_DISCARDS,
		GNMA_PORT_STAT_OUT_ERRORS,
		GNMA_PORT_STAT_OUT_BCAST_PKTS,
		GNMA_PORT_STAT_OUT_MCAST_PKTS,
		GNMA_PORT_STAT_OUT_UCAST_PKTS
	};
	uint64_t counters[ARRAY_LENGTH(stat_types)];
	struct gnma_port_key gnma_port;

#define ARR_FIND_VALUE_IDX(A, len, value)				\
	({								\
		size_t it = 0;						\
		for ((it) = 0; (it) < (len); (++it)) {			\
			if ((A)[it] == (value))				\
				break;					\
		}							\
		(it);							\
	})

	PID_TO_NAME(fp_p_id, gnma_port.name);

	if (gnma_port_stats_get(&gnma_port, ARRAY_LENGTH(stat_types),
				&stat_types[0], &counters[0]))
		return -EINVAL;

	/* TBD: find out where to get (not present in openconfig yml)
	 * <collisions>, and what is <mukticast> exactly
	 * (rx? tx? both?? packets or octets? L2? L3?)
	 */
	stats->collisions = 0;
	stats->multicast = 0;

	stats->rx_bytes =
		counters[ARR_FIND_VALUE_IDX(stat_types, ARRAY_LENGTH(stat_types),
					    GNMA_PORT_STAT_IN_OCTETS)];
	stats->rx_dropped =
		counters[ARR_FIND_VALUE_IDX(stat_types, ARRAY_LENGTH(stat_types),
					    GNMA_PORT_STAT_IN_DISCARDS)];
	stats->rx_error =
		counters[ARR_FIND_VALUE_IDX(stat_types, ARRAY_LENGTH(stat_types),
					    GNMA_PORT_STAT_IN_ERRORS)];

	/* Packets is sum of UC + MC + BC */
	stats->rx_packets =
		counters[ARR_FIND_VALUE_IDX(stat_types, ARRAY_LENGTH(stat_types),
					    GNMA_PORT_STAT_IN_UCAST_PKTS)];
	stats->rx_packets +=
		counters[ARR_FIND_VALUE_IDX(stat_types, ARRAY_LENGTH(stat_types),
					    GNMA_PORT_STAT_IN_MCAST_PKTS)];
	stats->rx_packets +=
		counters[ARR_FIND_VALUE_IDX(stat_types, ARRAY_LENGTH(stat_types),
					    GNMA_PORT_STAT_IN_BCAST_PKTS)];

	stats->tx_bytes =
		counters[ARR_FIND_VALUE_IDX(stat_types, ARRAY_LENGTH(stat_types),
					    GNMA_PORT_STAT_OUT_OCTETS)];
	stats->tx_dropped =
		counters[ARR_FIND_VALUE_IDX(stat_types, ARRAY_LENGTH(stat_types),
					    GNMA_PORT_STAT_OUT_DISCARDS)];
	stats->tx_error =
		counters[ARR_FIND_VALUE_IDX(stat_types, ARRAY_LENGTH(stat_types),
					    GNMA_PORT_STAT_OUT_ERRORS)];

	/* Packets is sum of UC + MC + BC */
	stats->tx_packets =
		counters[ARR_FIND_VALUE_IDX(stat_types, ARRAY_LENGTH(stat_types),
					    GNMA_PORT_STAT_OUT_UCAST_PKTS)];
	stats->tx_packets +=
		counters[ARR_FIND_VALUE_IDX(stat_types, ARRAY_LENGTH(stat_types),
					    GNMA_PORT_STAT_OUT_MCAST_PKTS)];
	stats->tx_packets +=
		counters[ARR_FIND_VALUE_IDX(stat_types, ARRAY_LENGTH(stat_types),
					    GNMA_PORT_STAT_OUT_BCAST_PKTS)];
#undef ARR_FIND_VALUE_IDX

	return 0;
}

static int
__lldp_peer_info_buf_parse(char *buf, size_t buf_size,
			   struct plat_port_lldp_peer_info *peer_info)
{
	cJSON *system_description;
	cJSON *mgmt_address;
	cJSON *capabilities;
	cJSON *system_name;
	cJSON *capability;
	cJSON *chassis_id;
	cJSON *state;
	cJSON *lldp;
	cJSON *it;
	cJSON *id;
	char *p;
	int ret;
	int i;

	lldp = cJSON_ParseWithLength(buf, buf_size);
	if (!lldp)
		goto err;

	state = cJSON_GetObjectItemCaseSensitive(lldp, "state");
	capabilities = cJSON_GetObjectItemCaseSensitive(lldp, "capabilities");
	capability = cJSON_GetObjectItemCaseSensitive(capabilities, "capability");
	if (!state || !capabilities || !capability || !cJSON_IsArray(capability))
		goto err;

	cJSON_ArrayForEach(it, capability) {
		cJSON *name, *enabled;

		name = cJSON_GetObjectItemCaseSensitive(it, "name");
		enabled =
			cJSON_GetObjectItemCaseSensitive(
					cJSON_GetObjectItemCaseSensitive(it, "state"),
					"enabled");

		if (!name || !enabled || !cJSON_GetStringValue(name) ||
		    !cJSON_IsBool(enabled))
			goto err;

		if (!strcmp(cJSON_GetStringValue(name), "openconfig-lldp-types:MAC_BRIDGE"))
			peer_info->capabilities.is_bridge = cJSON_IsTrue(enabled);
		else if (!strcmp(cJSON_GetStringValue(name), "openconfig-lldp-types:ROUTER"))
			peer_info->capabilities.is_router = cJSON_IsTrue(enabled);
		else if (!strcmp(cJSON_GetStringValue(name), "openconfig-lldp-types:WLAN_ACCESS_POINT"))
			peer_info->capabilities.is_wlan_ap = cJSON_IsTrue(enabled);
		else if (!strcmp(cJSON_GetStringValue(name), "openconfig-lldp-types:STATION_ONLY"))
			peer_info->capabilities.is_wlan_ap = cJSON_IsTrue(enabled);
	}

	system_description = cJSON_GetObjectItemCaseSensitive(state, "system-description");
	mgmt_address = cJSON_GetObjectItemCaseSensitive(state, "management-address");
	system_name = cJSON_GetObjectItemCaseSensitive(state, "system-name");
	chassis_id = cJSON_GetObjectItemCaseSensitive(state, "chassis-id");
	if (!system_description || !mgmt_address || !system_name || !chassis_id ||
	    !cJSON_GetStringValue(system_description) ||
	    !cJSON_GetStringValue(mgmt_address) ||
	    !cJSON_GetStringValue(system_name) ||
	    !cJSON_GetStringValue(chassis_id))
		goto err;

	strcpy(peer_info->name, cJSON_GetStringValue(system_name));
	strcpy(peer_info->description,
	       cJSON_GetStringValue(system_description));
	strcpy(peer_info->mac, cJSON_GetStringValue(chassis_id));

	/* management-address meant to be an array of string, however it's
	 * actually one long string with ',' delims.
	 * In order to process it correctly do the following things:
	 *  1. Split string into chunk delimmed by ','/'EOF'
	 *  2. Try to <parse> the string into saddr to verify IP is valid.
	 *  3. Copy found string to string in peer_info (since step 2 didn't fail,
	 *     IP addrs is OK and can be explicitly copied).
	 */
	p = strtok(cJSON_GetStringValue(mgmt_address), ",");
	for (i = 0; i < UCENTRAL_PORT_LLDP_PEER_INFO_MAX_MGMT_IPS && p; ++i) {
		unsigned char addr_buf[sizeof(struct in6_addr)] = {0};

		ret = inet_pton(AF_INET, p, addr_buf);
		if (ret) {
			ret = inet_pton(AF_INET6, p, addr_buf);
			if (ret)
				goto err;
		}

		strncpy(peer_info->mgmt_ips[i], p, INET6_ADDRSTRLEN);

		p = strtok(NULL, ",");
	}

	id = cJSON_GetObjectItemCaseSensitive(lldp, "id");
	if (!id || !cJSON_GetStringValue(id))
		goto err;

	strcpy(peer_info->port, cJSON_GetStringValue(id));

	cJSON_Delete(lldp);
	return 0;

err:
	cJSON_Delete(lldp);
	return -1;
}

static int
__ieee8021x_auth_clients_parse(uint16_t port_id,
			       char *buf, size_t buf_size,
			       struct plat_ieee8021x_port_info *state)
{
	cJSON *root, *clients, *it, *cl_state, *name, *auth_clients;
	struct gnma_port_key gnma_port = {0};
	size_t arr_len = 0;
	int i = 0;

	PID_TO_NAME(port_id, gnma_port.name);

	root = cJSON_ParseWithLength(buf, buf_size);
	if (!root)
		goto err;

	auth_clients = cJSON_GetObjectItemCaseSensitive(root,
							"openconfig-authmgr:authmgr-authenticated-clients");
	clients = cJSON_GetObjectItemCaseSensitive(auth_clients, "authenticated-client");

	cJSON_ArrayForEach(it, clients) {
		cl_state = cJSON_GetObjectItemCaseSensitive(it, "state");
		name = cJSON_GetObjectItemCaseSensitive(cl_state, "name");
		if (!cJSON_GetStringValue(name)) {
			UC_LOG_ERR("cJSON_GetStringValue(%s) fail %s\n", gnma_port.name, cJSON_GetStringValue(name));
			goto err;
		}

		/* We're iterating over every client;
		 * Count only if it's client of current port.
		 */
		if (strcmp(gnma_port.name, cJSON_GetStringValue(name)) == 0)
			arr_len++;
	}

	if (!arr_len)
		goto err;

	state->client_arr = calloc(arr_len, sizeof(*state->client_arr) * arr_len);
	if (!state->client_arr) {
		UC_LOG_ERR("calloc is zero\n");
		goto err;
	}

	state->arr_len = arr_len;

	cJSON_ArrayForEach(it, clients) {
		cJSON *auth_method, *mac, *session_time, *username, *vlan_type, *vid;
		struct plat_ieee8021x_authenticated_client_info *info;

		name = cJSON_GetObjectItemCaseSensitive(it, "name");
		if (!cJSON_GetStringValue(name))
			goto err;

		/* We're iterating over every client;
		 * Skip clients of other ports.
		 */
		if (strcmp(gnma_port.name, cJSON_GetStringValue(name)) != 0)
			continue;

		cl_state = cJSON_GetObjectItemCaseSensitive(it, "state");

		info = &state->client_arr[i];

		auth_method = cJSON_GetObjectItemCaseSensitive(cl_state, "authenticated-method");
		mac = cJSON_GetObjectItemCaseSensitive(cl_state, "macaddress");
		session_time = cJSON_GetObjectItemCaseSensitive(cl_state, "session-time");
		username = cJSON_GetObjectItemCaseSensitive(cl_state, "user-name");
		vlan_type = cJSON_GetObjectItemCaseSensitive(cl_state, "vlan-type");
		vid = cJSON_GetObjectItemCaseSensitive(cl_state, "vlan-id");

		if (!cJSON_GetStringValue(auth_method))
			goto err;

		strncpy(info->auth_method, cJSON_GetStringValue(auth_method),
			sizeof(info->auth_method) - 1);

		if (!cJSON_GetStringValue(mac))
			goto err;

		strncpy(info->mac_addr, cJSON_GetStringValue(mac),
			sizeof(info->mac_addr) - 1);

		info->session_time = (size_t)cJSON_GetNumberValue(session_time);

		if (!cJSON_GetStringValue(username))
			goto err;

		strncpy(info->username, cJSON_GetStringValue(username),
			sizeof(info->username) - 1);

		if (!cJSON_GetStringValue(vlan_type))
			goto err;

		strncpy(info->vlan_type, cJSON_GetStringValue(vlan_type),
			sizeof(info->vlan_type) - 1);

		info->vid = (uint16_t)cJSON_GetNumberValue(vid);

		++i;
	}

	cJSON_Delete(root);
	return 0;
err:
	cJSON_Delete(root);
	free(state->client_arr);
	state->client_arr = NULL;
	state->arr_len = 0;
	return -1;
}

static int
plat_ieee8021x_system_auth_clients_get(uint16_t port_id,
				       char **buf, size_t *buf_size,
				       struct plat_ieee8021x_port_info *state)
{
	int ret;

	if (!*buf) {
		*buf = calloc(1, PLAT_IEEE8021X_AUT_CLIENTS_BUF_SIZE);
		if (!buf)
			return -ENOMEM;
		*buf_size = PLAT_IEEE8021X_AUT_CLIENTS_BUF_SIZE;

		ret = gnma_ieee8021x_system_auth_clients_get(*buf, *buf_size);
		if (ret) {
			free(*buf);
			*buf = NULL;
			*buf_size = 0;
			return ret;
		}
	}

	return __ieee8021x_auth_clients_parse(port_id, *buf, *buf_size, state);
}

int plat_port_lldp_peer_info_get(uint16_t fp_p_id,
				 struct plat_port_lldp_peer_info *peer_info)
{
	struct gnma_port_key gnma_port = {0};
	const size_t buf_size = 4096;
	char *buf;
	int ret;

	PID_TO_NAME(fp_p_id, gnma_port.name);

	buf = calloc(1, buf_size);
	if (!buf)
		return -ENOMEM;

	ret = gnma_port_lldp_peer_info_get(&gnma_port, buf, buf_size);
	if (ret)
		goto err;

	ret = __lldp_peer_info_buf_parse(buf, buf_size, peer_info);

err:
	free(buf);
	return ret;
}

static int
__poe_port_state_buf_parse(char *buf, size_t buf_size,
			   struct plat_poe_port_state *port_state)
{
	cJSON *class_requested;
	cJSON *class_assigned;
	cJSON *output_current;
	cJSON *output_voltage;
	cJSON *output_power;
	cJSON *fault_status;
	cJSON *temperature;
	cJSON *counters;
	cJSON *state;
	cJSON *status;

	state = cJSON_ParseWithLength(buf, buf_size);
	if (!state)
		goto err;

	counters = cJSON_GetObjectItemCaseSensitive(state, "openconfig-if-poe-ext:counters");
	if (!counters || !cJSON_IsObject(counters))
		goto err;

	port_state->counters.absent =
		cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(counters, "absent-counter"));
	port_state->counters.shorted =
		cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(counters, "short-counter"));
	port_state->counters.overload =
		cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(counters, "overload-counter"));
	port_state->counters.power_denied =
		cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(counters, "power-denied-counter"));
	port_state->counters.invalid_signature =
		cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(counters, "invalid-signature-counter"));

	class_requested =
		cJSON_GetObjectItemCaseSensitive(state, "openconfig-if-poe-ext:power-class-requested");
	class_assigned =
		cJSON_GetObjectItemCaseSensitive(state, "power-class");
	/* It's okay if these are NULL, means PSE has no Powered Device
	 * (or link is down).
	 */
	if (!class_requested || !cJSON_IsNumber(class_requested))
		port_state->class_requested = 0;
	else
		port_state->class_requested = cJSON_GetNumberValue(class_requested);

	if (!class_assigned || !cJSON_IsNumber(class_assigned))
		port_state->class_assigned = 0;
	else
		port_state->class_assigned = cJSON_GetNumberValue(class_assigned);

	output_power =
		cJSON_GetObjectItemCaseSensitive(state, "power-used");
	output_current =
		cJSON_GetObjectItemCaseSensitive(state, "openconfig-if-poe-ext:output-current");
	output_voltage =
		cJSON_GetObjectItemCaseSensitive(state, "openconfig-if-poe-ext:output-voltage");
	if (!cJSON_GetStringValue(output_power) ||
	    !cJSON_IsNumber(output_current) ||
	    !cJSON_GetStringValue(output_voltage))
		goto err;

	if (1 != sscanf(cJSON_GetStringValue(output_power),
			"%" SCNu32,
			&port_state->output_power))
		goto err;
	port_state->output_current = cJSON_GetNumberValue(output_current);
	strcpy(port_state->output_voltage,
	       cJSON_GetStringValue(output_voltage));

	temperature =
		cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(state, "openconfig-if-poe-ext:diagnostics"),
						 "temperature");
	if (!cJSON_GetStringValue(temperature))
		goto err;

	strcpy(port_state->temperature, cJSON_GetStringValue(temperature));

	status = cJSON_GetObjectItemCaseSensitive(state, "openconfig-if-poe-ext:status");
	fault_status = cJSON_GetObjectItemCaseSensitive(state, "openconfig-if-poe-ext:fault-code");
	if (!cJSON_GetStringValue(status) || !cJSON_GetStringValue(fault_status))
		goto err;

	strcpy(port_state->status, cJSON_GetStringValue(status));
	strcpy(port_state->fault_status, cJSON_GetStringValue(fault_status));

	cJSON_Delete(state);
	return 0;

err:
	cJSON_Delete(state);
	return -1;
}

static int
plat_poe_port_state_get(uint16_t pid,
			struct plat_poe_port_state *state)
{
	struct gnma_port_key gnma_port = {0};
	const size_t buf_size = 4096;
	char *buf;
	int ret;

	PID_TO_NAME(pid, gnma_port.name);

	buf = calloc(1, buf_size);
	if (!buf)
		return -ENOMEM;

	ret = gnma_poe_port_state_get(&gnma_port, buf, buf_size);
	if (ret)
		goto err;

	ret = __poe_port_state_buf_parse(buf, buf_size, state);

err:
	free(buf);
	return ret;
}

static int
__poe_state_buf_parse(char *buf, size_t buf_size,
		      struct plat_poe_state *poe_state)
{
	cJSON *status;
	cJSON *state;

	state = cJSON_ParseWithLength(buf, buf_size);
	if (!state)
		goto err;

	poe_state->max_power_budget =
		cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(state, "max-power-budget"));
	poe_state->power_threshold =
		cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(state, "power-threshold"));
	poe_state->power_consumed =
		cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(state, "power-consumption"));

	status = cJSON_GetObjectItemCaseSensitive(state, "pse-oper-status");
	if (!cJSON_GetStringValue(status))
		goto err;

	strcpy(poe_state->power_status, cJSON_GetStringValue(status));


	cJSON_Delete(state);
	return 0;

err:
	cJSON_Delete(state);
	return -1;
}

static int
plat_poe_state_get(struct plat_poe_state *state)
{
	const size_t buf_size = 4096;
	char *buf;
	int ret;

	buf = calloc(1, buf_size);
	if (!buf)
		return -ENOMEM;

	ret = gnma_poe_state_get(buf, buf_size);
	if (ret)
		goto err;

	ret = __poe_state_buf_parse(buf, buf_size, state);

err:
	free(buf);
	return ret;
}

/* NOTE: In case of error this function left partial config */
int plat_vlan_list_set(BITMAP_DECLARE(vlans_to_cfg, GNMA_MAX_VLANS))
{
	BITMAP_DECLARE(vlans, GNMA_MAX_VLANS);
	uint16_t vid;
	size_t i;
	struct plat_ipv4 ipv4 = {.exist = false};
	int ret = 0;

	BITMAP_CLEAR(vlans, GNMA_MAX_VLANS);
	ret = gnma_vlan_list_get(vlans);
	if (ret)
		goto err;

	BITMAP_FOR_EACH_BIT_SET(i, vlans, GNMA_MAX_VLANS)
	{
		vid = (uint16_t)i;
		if (BITMAP_TEST_BIT(vlans_to_cfg, vid))
			continue;
		UC_LOG_DBG("Removing vid <%" PRIu16
			   "> (not in cfg, present on system)\n",
			   vid);

		/* TODO should it be part of gnma vlan_del ? */
		/* Let it fail,
         * to prevent additional rif existence check req
         */
		ret = plat_vlan_rif_set(vid, &ipv4);
		if (ret)
			goto err;
		ret = gnma_vlan_remove(vid);
		if (ret)
			goto err;
	}

	/* We skip creating (for every all_vlans_arr), because it created
	 * imlicity by plat_vlan_memberlist_set
	 */
err:
	return ret;
}

int plat_vlan_memberlist_set(struct gnma_change *c,
			     struct gnma_vlan_member_bmap *vlan_mbr,
			     struct plat_port_vlan *vlan)
{
	BITMAP_DECLARE(vlan_port_member, MAX_NUM_OF_PORTS);
	BITMAP_DECLARE(vlan_port_tagged, MAX_NUM_OF_PORTS);
	uint16_t pid;
	size_t i;
	struct gnma_port_key gnma_port;
	struct plat_vlan_memberlist *pv;
	uint32_t tagged;
	int ret = 0;

	ret = gnma_vlan_create(c, vlan->id);
	if (ret)
		return -1;

	BITMAP_CLEAR(vlan_port_member, MAX_NUM_OF_PORTS);
	BITMAP_CLEAR(vlan_port_tagged, MAX_NUM_OF_PORTS);
	for (pv = vlan->members_list_head; pv; pv = pv->next) {
		if (NAME_TO_PID(&pid, pv->port.name) < 1) {
			UC_LOG_ERR("Invalid port name: '%s'", pv->port.name);
			return -1;
		}
		BITMAP_SET_BIT(vlan_port_member, pid);
		if (pv->tagged)
			BITMAP_SET_BIT(vlan_port_tagged, pid);
	}

	/* Delete already configured members that are not present in the new config */
	BITMAP_FOR_EACH_BIT_SET(i, vlan_mbr->vlan[vlan->id].port_member,
				MAX_NUM_OF_PORTS)
	{
		if (!BITMAP_TEST_BIT(vlan_port_member, i)) {
			PID_TO_NAME((uint16_t)i, gnma_port.name);
			UC_LOG_DBG("Removing vlan <%u>: member <%s>\n",
				   vlan->id, gnma_port.name);
			gnma_vlan_member_remove(c, vlan->id, &gnma_port);
		}
	}

	/* Configure vlan members from the new config */
	BITMAP_FOR_EACH_BIT_SET(i, vlan_port_member, MAX_NUM_OF_PORTS)
	{
		tagged = BITMAP_TEST_BIT(vlan_port_tagged, i);

		if (BITMAP_TEST_BIT(vlan_mbr->vlan[vlan->id].port_member, i) &&
		    tagged ==
			    BITMAP_TEST_BIT(
				    vlan_mbr->vlan[vlan->id].port_tagged, i)) {
			continue;
		}

		PID_TO_NAME((uint16_t)i, gnma_port.name);
		UC_LOG_DBG(
			"Configuring vlan <%u>: member <%s>, fp_id <%zu>, tagged <%d>\n",
			vlan->id, gnma_port.name, i, tagged);
		ret = gnma_vlan_member_create(c, vlan->id, &gnma_port, tagged);
		if (ret) {
			return -1;
		}
	}

	return ret;
}

int plat_reboot(void)
{
	return gnma_reboot();
}

static int __plat_config_id_store(uint64_t id)
{
	FILE *cfgid_file = NULL;
	int err = 0;
	int ret;

	cfgid_file = fopen(cfgid_path, "w");
	if (!cfgid_file) {
		err = -1;
		goto out;
	}

	ret = fprintf(cfgid_file, "%lu", id);
	if (ret < 0) {
		err = -1;
		goto out;
	}

out:
	if (cfgid_file)
		fclose(cfgid_file);

	return err;
}

static int __plat_config_id_load(uint64_t *id)
{
	FILE *cfgid_file = NULL;
	int err = 0;
	int ret;

	*id = 0;

	cfgid_file = fopen(cfgid_path, "r");
	if (!cfgid_file) {
		err = -1;
		goto out;
	}

	ret = fscanf(cfgid_file, "%lu", id);
	if (ret == EOF || !ret) {
		err = -1;
		goto out;
	}

out:
	if (cfgid_file)
		fclose(cfgid_file);

	return err;
}

/* Save applied config to be restored after reboot */
int plat_config_save(uint64_t id)
{
	int err;

	err = gnma_config_save();
	if (err)
		return err;

	__plat_config_id_store(id);

	return 0;
}

int plat_config_restore(void)
{
	int ret;

	ret = gnma_config_restore();
	if (ret)
		return ret;

	/* Restore internal state/cache of plat objects. */
	return plat_state_init();
}

/* Get id of saved config.
 * Describe, what will be restored during plat_config_restore()
 */
/* NOTE: gnma is not supported such things as config id. So, we can add logic
 * to read store config id in plat layer, as defined by design.
 * This layer knows about /var/run directory as well as about gnma restrictions
 */
int plat_saved_config_id_get(uint64_t *id)
{
	return __plat_config_id_load(id);
}

int plat_factory_default(void)
{
	return gnma_factory_default();
}

int plat_rtty(struct plat_rtty_cfg *rtty_cfg)
{
	static pid_t child[RTTY_SESS_MAX];
	int n, i, e;

	/* wait the dead children */
	for (i = 0; i < RTTY_SESS_MAX;) {
		n = 0;
		if (child[i] > 0) {
		  while ((n = waitpid(child[i], 0, WNOHANG)) < 0 && errno == EINTR);
		}
		if (n <= 0) {
			++i;
		} else {
			if (RTTY_SESS_MAX > 1)
			  memmove(&child[i], &child[i+1], (RTTY_SESS_MAX-i-1)*sizeof(pid_t));
			child[RTTY_SESS_MAX - 1] = -1;
		}
	}

	/* find a place for a new session */
	for (i = 0; i < RTTY_SESS_MAX && child[i] > 0; ++i);

	/* if there are RTTY_SESS_MAX sessions, kill the oldest */
	if (i == RTTY_SESS_MAX) {
		if (child[0] <= 0) {
		   UC_LOG_CRIT("child[0]==%jd", (intmax_t)child[0]);
		} else {
		  if (kill(child[0], SIGKILL)) {
			UC_LOG_CRIT("kill failed: %s", strerror(errno));
		  } else {
			while ((n = waitpid(child[0], 0, 0)) < 0 && errno == EINTR);
			if (n < 0)
				UC_LOG_CRIT("waitpid failed: %s", strerror(errno));
		  }
		  if (RTTY_SESS_MAX > 1)
			memmove(&child[0], &child[1], (RTTY_SESS_MAX - 1) * sizeof(pid_t));
		}
		i = RTTY_SESS_MAX - 1;
	}
	child[i] = fork();

	if (!child[i]) {
		char argv[][128] = {
			"--id=",
			"--host=",
			"--port=",
			"--token="
			};

		setsid();
		strcat(argv[0], rtty_cfg->id);
		strcat(argv[1], rtty_cfg->server);
		sprintf(argv[2], "--port=%u", rtty_cfg->port);
		strcat(argv[3], rtty_cfg->token);
		execl("/usr/local/bin/rtty", "rtty", argv[0], argv[1], argv[2], argv[3], "-d Edgecore Switch device", "-v", "-s", NULL);
		e = errno;
		UC_LOG_DBG("execv failed %d\n", e);

		/* If we got to this line, that means execl failed, and
		 * currently, due to simple design (fork/exec), it's impossible
		 * to notify  <main> process, that forked child failed to execl.
		 * TBD: notify about execl fail.
		 */
		_exit(e);
	}

	if (child[i] < (pid_t)0) {
		return -1;
	}

	return 0;
}

int plat_info_get(struct plat_platform_info *info)
{
	struct gnma_metadata md = {0};

	if (gnma_metadata_get(&md)) {
		return -1;
	}

	*info = (struct plat_platform_info){0};
	snprintf(info->platform, sizeof info->platform, "%s", md.platform);
	snprintf(info->hwsku, sizeof info->hwsku, "%s", md.hwsku);
	snprintf(info->mac, sizeof info->mac, "%s", md.mac);

	return 0;
}

static int
img_dl_progress_cb(void *ptr, double dltotal, double dlnow, double ultotal,
		   double ulnow)
{
	struct img_dl_task *tsk = (struct img_dl_task *)ptr;

	(void)(ultotal);
	(void)(ulnow);

	tsk->percentage = (uint8_t) (dlnow / dltotal * 100);

	return 0;
}

static int img_dl_get_type(struct img_dl_task *tsk)
{
	const size_t len = sizeof IMG_DL_DEB_FILE_SIGNATURE - 1;
	void *buf;
	int ret;
	int fd;

	fd = open(IMG_DL_FILE_PATH, O_RDONLY);
	if (fd < 0) {
		UC_LOG_ERR("IMG dl completed, but couldn't open it for type detection");
		return -1;
	}

	/* All we care is whether it's a deb or not, hence mmap only signature
	 * length.
	 */
	buf = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
	if (buf == MAP_FAILED) {
		UC_LOG_ERR("IMG dl completed, but couldn't open it for type detection");
		ret = -1;
		goto err;
	}

	tsk->downloaded_full_img =
		(bool)memcmp(buf, IMG_DL_DEB_FILE_SIGNATURE, len);
	ret = 0;

	UC_LOG_DBG("Downloaded img (is_full_img %d)", tsk->downloaded_full_img);
	UC_LOG_DBG("Img hdr (64): %" PRIu64, *(uint64_t *)buf);

err:
	if (buf)
		munmap(buf, len);
	close(fd);
	return ret;
}

static int img_dl_start_partial_upgrade(char *uri)
{
	char buf[256];
	char *bufpt;
	size_t size;
	int ret;
	int fd;

	strcpy(buf, "upgrade ");
	strcat(buf, uri);

	bufpt = buf;

	size = strlen(buf);

	fd = open(IMG_DL_PIPE_PATH, O_RDWR);
	if (fd < 0) {
		UC_LOG_ERR("partial upgrade pipe open failed");
		return -1;
	}

	UC_LOG_DBG("Issuing upgrade cmd: \'%s\'", buf);

	/* Send 'upgrade' cmd to script through pipe;
	 * Cover partial-write case.
	 * TBD: verify script can actually install this package
	 * (e.g. integrity kept intact, checksums are fine etc).
	 */
	while (size != 0) {
		ret = write(fd, bufpt, size);
		if (ret < 0) {
			UC_LOG_ERR("Write to upgrade pipe failed");
			goto err;
		}

		bufpt += ret;
		size -= ret;
	}

	close(fd);
	return 0;
err:
	close(fd);
	return -1;
}

static void *img_dl_entrypoint(void *args)
{
	struct img_dl_task *tsk = (struct img_dl_task *)args;
	CURLcode res;

	res = curl_easy_perform(tsk->curl);

	fclose(tsk->fp);
	curl_easy_cleanup(tsk->curl);

	if (res != CURLE_OK || img_dl_get_type(tsk)) {
		goto err;
	}

	if (!tsk->downloaded_full_img) {
		if (img_dl_start_partial_upgrade(IMG_DL_FILE_PATH))
			goto err;
		tsk->upgrade_state = UCENTRAL_UPGRADE_STATE_SUCCESS;
	} else {
		char f_uri[256];

		strcpy(f_uri, "file://");
		strcat(f_uri, IMG_DL_FILE_PATH);
		if (gnma_image_install(f_uri))
			goto err;
		tsk->upgrade_state = UCENTRAL_UPGRADE_STATE_INSTALL;
		tsk->percentage = 0;
		tsk->active = false;
	}

	return 0;
err:
	tsk->upgrade_state = UCENTRAL_UPGRADE_STATE_FAIL;
	tsk->percentage = 0;
	UC_LOG_ERR("IMG DL fail or failed to define downloaded img type");
	return 0;
}

static int plat_img_dl_start(char *uri, char *signature)
{
	/* TODO */
	if (signature)
		UC_LOG_DBG("Signature check is not implemented!\n");

	memset(&img_dl_task, 0, sizeof(img_dl_task));

	img_dl_task.upgrade_state = UCENTRAL_UPGRADE_STATE_DOWNLOAD;
	img_dl_task.active = true;

	img_dl_task.fp = fopen(IMG_DL_FILE_PATH, "w+");
	if (!img_dl_task.fp) {
		UC_LOG_ERR("Failed to open '%s' for img dl!", IMG_DL_FILE_PATH);
		return -1;
	}

	img_dl_task.curl = curl_easy_init();
	if (!img_dl_task.curl) {
		UC_LOG_ERR("curl_easy_init failed!");
		goto err;
	}

	curl_easy_setopt(img_dl_task.curl, CURLOPT_URL, uri);
	curl_easy_setopt(img_dl_task.curl, CURLOPT_NOPROGRESS, 0);
	curl_easy_setopt(img_dl_task.curl, CURLOPT_PROGRESSFUNCTION, img_dl_progress_cb);
	curl_easy_setopt(img_dl_task.curl, CURLOPT_PROGRESSDATA, &img_dl_task);
	curl_easy_setopt(img_dl_task.curl, CURLOPT_WRITEDATA, (void *)img_dl_task.fp);

	if (pthread_create(&img_dl_task.t, 0, img_dl_entrypoint, &img_dl_task)) {
		UC_LOG_DBG("pthread_create failed: %s", strerror(errno));
		goto err;
	}

	/* thread will cleanup everything by itself. Clean only in case of
	 * err here.
	 */
	return 0;

err:
	if (img_dl_task.curl)
		curl_easy_cleanup(img_dl_task.curl);
	if (img_dl_task.fp)
		fclose(img_dl_task.fp);

	return -1;
}

int plat_upgrade(char *uri, char *signature)
{
	/* TODO */
	if (signature)
		UC_LOG_DBG("Signature check is not implemented!\n");

	return plat_img_dl_start(uri, signature);
}

static int __plat_upgrade_state_gnmi(int *operation, int *percentage)
{
	char buf[256];
	uint16_t buf_size = sizeof(buf);
	cJSON *json, *json_item;
	char *state_name;
	int parsed_percentage;

	if (gnma_image_install_status(&buf_size, &buf[0]))
		return -1;

	json = cJSON_Parse(buf);
	json_item = cJSON_GetObjectItemCaseSensitive(json, "global_state");
	if (!json_item)
		goto err_parse;
	state_name = cJSON_GetStringValue(json_item);

	json_item = cJSON_GetObjectItemCaseSensitive(json, "percentage");
	if (!json_item)
		goto err_parse;
	parsed_percentage = cJSON_GetNumberValue(json_item);

	*operation = UCENTRAL_UPGRADE_STATE_IDLE;
	*percentage = 0;
	if (!strcmp(state_name, "GLOBAL_STATE_FAILED")) {
		*operation = UCENTRAL_UPGRADE_STATE_FAIL;
	} else if (!strcmp(state_name, "GLOBAL_STATE_DOWNLOAD")) {
		*operation = UCENTRAL_UPGRADE_STATE_DOWNLOAD;
		*percentage = parsed_percentage;
	} else if (!strcmp(state_name, "GLOBAL_STATE_INSTALL")) {
		*operation = UCENTRAL_UPGRADE_STATE_INSTALL;
	} else if (!strcmp(state_name, "GLOBAL_STATE_SUCCESS")) {
		*operation = UCENTRAL_UPGRADE_STATE_SUCCESS;
	}

	cJSON_Delete(json);
	return 0;

err_parse:
	/* TODO single retpath */
	cJSON_Delete(json);
	return -1;
}

static int plat_upgrade_state(int *operation, int *percentage)
{
	/*  */
	if (img_dl_task.active) {
		*percentage = img_dl_task.percentage;
		*operation = img_dl_task.upgrade_state;
		return 0;
	} else
		return __plat_upgrade_state_gnmi(operation, percentage);
}

int plat_running_img_name_get(char *str, size_t str_max_len)
{
	return gnma_image_running_name_get(str, str_max_len);
}

int plat_revision_get(char *str, size_t str_max_len)
{
	snprintf(str, str_max_len, PLATFORM_REVISION);
	return 0;
}

static int
__reboot_cause_buf_parse(char *buf, size_t buf_size,
			 struct plat_reboot_cause *cause)
{
	struct sysinfo sys_info = { 0 };
	time_t localtime = time(0);
	cJSON *json, *json_cause;
	char *cause_str;

	sysinfo(&sys_info);

	json = cJSON_ParseWithLength(buf, buf_size);
	json_cause = cJSON_GetObjectItemCaseSensitive(json, "openconfig-system-ext:reboot-cause");
	if (!(cause_str = cJSON_GetStringValue(json_cause)))
		goto err_parse;

	/* Some of reboot causes might not have TS set, hence calculate it
	 * manually: a tricky way to do so is simply substract uptime from
	 * localtime.
	 * The only downside is that TS is approximated and not exact,
	 * however if system gives no other option to get TS from powerloss,
	 * it's an OK way to calculate it this way.
	 */
	cause->ts = (uint64_t)localtime - (uint64_t)sys_info.uptime;

	/* Upon powerloss no cause is saved, hence Unknown == powerloss.
	 * In case if reboot is issued, cause will be explicitly set to reboot;
	 * And in case of crash any other value or 'kdump issued' will be set.
	 */
	if (strstr(cause_str, "not yet available")) {
		UC_LOG_ERR("uCentral SW failed to fetch reboot cause string");
		cause->cause = PLAT_REBOOT_CAUSE_UNAVAILABLE;
		strncpy(cause->desc,
			"uCentral SW failed to fetch reboot cause string (not available)",
			sizeof cause->desc - 1);
	} else if (strstr(cause_str, "Unknown")) {
		cause->cause = PLAT_REBOOT_CAUSE_POWERLOSS;
		strncpy(cause->desc,
			"Powerloss detected.",
			sizeof cause->desc - 1);
	} else if (strstr(cause_str, "reboot")) {
		cause->cause = PLAT_REBOOT_CAUSE_REBOOT_CMD;
		strncpy(cause->desc,
			"Reboot command's been executed.",
			sizeof cause->desc - 1);
	} else {
		strncpy(cause->desc,
			"Device's (kernel) crashed (kernelpanic caused device to reboot).",
			sizeof cause->desc - 1);
		cause->cause = PLAT_REBOOT_CAUSE_CRASH;
	}

	cJSON_Delete(json);
	return 0;

err_parse:
	cJSON_Delete(json);
	return -1;
}

int
plat_reboot_cause_get(struct plat_reboot_cause *cause)
{
	const size_t buf_size = 4096;
	char *buf;
	int ret;

	buf = calloc(1, buf_size);
	if (!buf)
		return -ENOMEM;

	ret = gnma_rebootcause_get(buf, buf_size);
	if (ret)
		goto err;

	ret = __reboot_cause_buf_parse(buf, buf_size, cause);

err:
	free(buf);
	return ret;
}

static void alarm_gnma_cb(struct gnma_alarm *ga, void *data)
{
	struct plat_event_callbacks *ctx = data;
	struct plat_alarm a = {
		.id = ga->id,
		.resource = ga->resource,
		.text = ga->text,
		.time_created = ga->time_created,
		.type_id = ga->type_id,
		.severity = ga->severity,
		.acknowledged = ga->acknowledged,
		.acknowledge_time = ga->acknowledge_time,
	};

	if (ctx->alarm_cb) {
		ctx->alarm_cb(&a);
	}
}

static void linkstatus_gnma_cb(struct gnma_linkstatus *s, void *data)
{
	struct plat_event_callbacks *ctx = data;
	struct plat_linkstatus ucs = {
		.timestamp = s->timestamp / 1000000000,
		.ifname = s->ifname,
		.up = s->up,
	};

	if (ctx->linkstatus_cb)
		ctx->linkstatus_cb(&ucs);
}

static void poe_linkstatus_gnma_cb(struct gnma_poe_linkstatus *s, void *data)
{
	struct plat_event_callbacks *ctx = data;
	struct plat_poe_linkstatus ucs = {
		.timestamp = s->timestamp / 1000000000,
		.ifname = s->ifname,
	};

	if (!strcmp("DISABLED", s->status))
		ucs.status = PLAT_POE_LINKSTATUS_DISABLED;
	else if (!strcmp("SEARCHING", s->status))
		ucs.status = PLAT_POE_LINKSTATUS_SEARCHING;
	else if (!strcmp("DELIVERING_POWER", s->status))
		ucs.status = PLAT_POE_LINKSTATUS_DELIVERING_POWER;
	else if (!strcmp("OVERLOAD", s->status))
		ucs.status = PLAT_POE_LINKSTATUS_OVERLOAD;
	else if (!strcmp("OTHER_FAULT", s->status))
		ucs.status = PLAT_POE_LINKSTATUS_FAULT;
	else
		return;

	if (ctx->poe_linkstatus_cb)
		ctx->poe_linkstatus_cb(&ucs);
}

static void poe_link_faultcode_gnma_cb(struct gnma_poe_link_faultcode *s, void *data)
{
	struct plat_event_callbacks *ctx = data;
	struct plat_poe_link_faultcode ucs = {
		.timestamp = s->timestamp / 1000000000,
		.ifname = s->ifname,
	};

	if (!strcmp("NO_ERROR", s->faultcode))
		/* We're interested only in actual fault codes, but sonic alerts
		 * us also whenever fault-code is 'back-to-normal'. So we explicitly
		 * ignore the given NO_ERROR code.
		 * However, if two sequential OVERLOAD events happen, for example,
		 * we still send BOTH events, as these are two discrete unique
		 * events that happened to the device.
		 */
		return;
	else if (!strcmp("OVLO", s->faultcode))
		ucs.faultcode = PLAT_POE_LINK_FAULTCODE_OVLO;
	else if (!strcmp("MPS_ABSENT", s->faultcode))
		ucs.faultcode = PLAT_POE_LINK_FAULTCODE_MPS_ABSENT;
	else if (!strcmp("SHORT", s->faultcode))
		ucs.faultcode = PLAT_POE_LINK_FAULTCODE_SHORT;
	else if (!strcmp("OVERLOAD", s->faultcode))
		ucs.faultcode = PLAT_POE_LINK_FAULTCODE_OVERLOAD;
	else if (!strcmp("POWER_DENIED", s->faultcode))
		ucs.faultcode = PLAT_POE_LINK_FAULTCODE_POWER_DENIED;
	else if (!strcmp("THERMAL_SHUTDOWN", s->faultcode))
		ucs.faultcode = PLAT_POE_LINK_FAULTCODE_THERMAL_SHUTDOWN;
	else if (!strcmp("STARTUP_FAILURE", s->faultcode))
		ucs.faultcode = PLAT_POE_LINK_FAULTCODE_STARTUP_FAILURE;
	else if (!strcmp("UVLO", s->faultcode))
		ucs.faultcode = PLAT_POE_LINK_FAULTCODE_UVLO;
	else if (!strcmp("HW_PIN_DISABLE", s->faultcode))
		ucs.faultcode = PLAT_POE_LINK_FAULTCODE_HW_PIN_DISABLE;
	else if (!strcmp("PORT_UNDEFINED", s->faultcode))
		ucs.faultcode = PLAT_POE_LINK_FAULTCODE_PORT_UNDEFINED;
	else if (!strcmp("INTERNAL_HW_FAULT", s->faultcode))
		ucs.faultcode = PLAT_POE_LINK_FAULTCODE_INTERNAL_HW_FAULT;
	else if (!strcmp("USER_SETTING", s->faultcode))
		ucs.faultcode = PLAT_POE_LINK_FAULTCODE_USER_SETTING;
	else if (!strcmp("NON_STANDARD_PD", s->faultcode))
		ucs.faultcode = PLAT_POE_LINK_FAULTCODE_NON_STANDARD_PD;
	else if (!strcmp("UNDERLOAD", s->faultcode))
		ucs.faultcode = PLAT_POE_LINK_FAULTCODE_UNDERLOAD;
	else if (!strcmp("PWR_BUDGET_EXCEEDED", s->faultcode))
		ucs.faultcode = PLAT_POE_LINK_FAULTCODE_PWR_BUDGET_EXCEEDED;
	else if (!strcmp("OOR_CAPACITOR_VALUE", s->faultcode))
		ucs.faultcode = PLAT_POE_LINK_FAULTCODE_OOR_CAPACITOR_VALUE;
	else if (!strcmp("CLASS_ERROR", s->faultcode))
		ucs.faultcode = PLAT_POE_LINK_FAULTCODE_CLASS_ERROR;
	else
		return;

	if (ctx->poe_link_faultcode_cb)
		ctx->poe_link_faultcode_cb(&ucs);
}

int plat_event_subscribe(const struct plat_event_callbacks *cbs)
{
	if (subscribe_hdl) {
		UC_LOG_DBG("already subscribed");
		return -1;
	}

	events_cbs = *cbs;

	return gnma_subscribe(&subscribe_hdl,
			      &(struct gnma_subscribe_callbacks){
				      .alarm_cb = alarm_gnma_cb,
				      .alarm_data = &events_cbs,
				      .linkstatus_cb = linkstatus_gnma_cb,
				      .linkstatus_data = &events_cbs,
				      .poe_linkstatus_cb = poe_linkstatus_gnma_cb,
				      .poe_linkstatus_data = &events_cbs,
				      .poe_link_faultcode_cb = poe_link_faultcode_gnma_cb,
				      .poe_link_faultcode_data = &events_cbs,
			      });
}

void plat_event_unsubscribe(void)
{
	gnma_unsubscribe(&subscribe_hdl);
	events_cbs = (struct plat_event_callbacks){ 0 };
}

int plat_syslog_set(struct plat_syslog_cfg *cfg, int count)
{
	static const char *const prio2str[8] = { "emerg", "alert",   "crit",
						 "error", "warning", "notice",
						 "info",  "debug" };
	int i;
	struct gnma_syslog_cfg *gnma_cfg = 0;
	int ret = -1;

	gnma_cfg = malloc(count * sizeof *gnma_cfg);
	if (!gnma_cfg) {
		UC_LOG_ERR("malloc failed");
		return -1;
	}

	for (i = 0; i < count; ++i) {
		if (cfg[i].priority < 0 || cfg[i].priority > 7) {
			UC_LOG_ERR("severity must be in range 0-7");
			goto err;
		}

		gnma_cfg[i] = (struct gnma_syslog_cfg){
			.ipaddress = cfg[i].host,
			.remote_port = cfg[i].port,
			.severity = prio2str[cfg[i].priority],
		};
	}

	if (gnma_syslog_cfg_clear()) {
		UC_LOG_ERR("failed clearing previous syslog configuration");
		goto err;
	}
	ret = gnma_syslog_cfg_set(gnma_cfg, count);

err:
	free(gnma_cfg);
	return ret;
}

/* NOTE: In case of error this function left partial config */
int plat_vlan_rif_set(uint16_t vid, struct plat_ipv4 *ipv4)
{
	struct gnma_ip_prefix pref, pref_old;
	uint16_t list_size;
	int i;

	pref.prefix_len = ipv4->subnet_len;
	pref.ip.v = AF_INET;
	memcpy(&pref.ip.u.v4, &ipv4->subnet, sizeof(pref.ip.u.v4));

	list_size = 1;
	/* TODO support more than one. So handle overflow */
	if (gnma_vlan_erif_attr_pref_list_get(vid, &list_size, &pref_old))
		return -1;

	/* Both update / delete require no upper (dhcp) cfg.
	 * Remove dhcp-relay cfg, and restore it, only in case
	 * if RIF was updated, not deleted (changed pref for example).
	 */
	for (i = 0; i < PLAT_DHCP_RELAY_MAX_SERVERS; ++i) {
		if (!plat_state.vlans[vid].dhcp_relay.enabled)
			continue;
		if (gnma_vlan_dhcp_relay_server_remove(
					vid,
					&plat_state.vlans[vid].dhcp_relay.helper_addresses[i]))
			return -1;
	}

	if (list_size > 0 && !ipv4->exist) {
		/* Force DHCP cache/state flush (delete), as at this point no
		 * dhcp cfg for this vlan exists, and it won't be 'restored'
		 * in this function.
		 */
		plat_state.vlans[vid].dhcp_relay.enabled = false;
		memset(&plat_state.vlans[vid].dhcp_relay.helper_addresses[0], 0,
		       sizeof(plat_state.vlans[vid].dhcp_relay.helper_addresses));

		if (gnma_vlan_erif_attr_pref_delete(vid, &pref_old))
			return -1;
	}

	if (ipv4->exist &&
	    (list_size == 0 || !GNMA_IP_PREF_IS_EQ(pref, pref_old))) {
		/* Update works as expected for prefixes less than 2 */
		/* TODO handle comparing for mt 1 cases ! */
		if (gnma_vlan_erif_attr_pref_update(vid, 1, &pref))
			return -1;

		/* Restore DHCP-relay conf */
		for (i = 0; i < PLAT_DHCP_RELAY_MAX_SERVERS; ++i) {
			if (!plat_state.vlans[vid].dhcp_relay.enabled)
				continue;
			if (gnma_vlan_dhcp_relay_server_add(
						vid,
						&plat_state.vlans[vid].dhcp_relay.helper_addresses[i]))
				return -1;
		}
	}

	return 0;
}

/* NOTE: In case of error this function left partial config */
int plat_portl2_rif_set(uint16_t fp_p_id, struct plat_ipv4 *ipv4)
{
	struct plat_ipv4 *sipv4 = &plat_state.portsl2_rif_ipv4[fp_p_id];
	struct gnma_port_key gnma_port;
	struct gnma_ip_prefix pref;

	PID_TO_NAME(fp_p_id, gnma_port.name);

	if (sipv4->exist && !ipv4->exist) {
		pref.prefix_len = ipv4->subnet_len;
		pref.ip.v = AF_INET;
		memcpy(&pref.ip.u.v4, &sipv4->subnet, sizeof(pref.ip.u.v4));
		if (gnma_portl2_erif_attr_pref_delete(&gnma_port, &pref))
			return -1;
	}

	if (ipv4->exist &&
	    (sipv4->subnet_len != ipv4->subnet_len ||
	     sipv4->subnet.s_addr != ipv4->subnet.s_addr)) {
		pref.prefix_len = ipv4->subnet_len;
		pref.ip.v = AF_INET;
		memcpy(&pref.ip.u.v4, &ipv4->subnet, sizeof(pref.ip.u.v4));
		/* Update works as expected for prefixes less than 2 */
		/* TODO handle comparing for mt 1 cases ! */
		if (gnma_portl2_erif_attr_pref_update(&gnma_port, 1, &pref))
			return -1;
	}

	memcpy(sipv4, ipv4, sizeof(*ipv4));
	return 0;
}

static void plat_state_deinit(struct plat_state_info *state)
{
	free(state->port_info);
	*state = (struct plat_state_info){ 0 };
}

static int plat_port_info_get(struct plat_port_info **port_info, int *count)
{
	size_t ieee8021x_buf_size = 0;
	char *ieee8021x_buf = NULL;
	int rc;
	size_t i = 0;
	uint16_t pcount = 0;
	struct plat_port_info *pinfo = 0;
	struct gnma_port_key *plist = 0;
	int ret = -1;

	/* TODO(vb) beautify &c */
	if (plat_port_num_get(&pcount)) {
		UC_LOG_DBG("plat_port_num_get failed");
		goto err;
	}

	if (!(plist = malloc(sizeof *plist * pcount))) {
		goto err;
	}
	rc = gnma_port_list_get(&pcount, plist);
	if (rc && rc != GNMA_ERR_OVERFLOW) {
		UC_LOG_DBG("gnma_port_list_get failed");
		goto err;
	}

	if (!(pinfo = malloc(sizeof *pinfo * pcount))) {
		goto err;
	}

	for (i = 0; i < pcount; ++i) {
		uint16_t pid;
		bool is_up, is_full_duplex;

		NAME_TO_PID(&pid, plist[i].name);

		pinfo[i] = (struct plat_port_info){ 0 };
		snprintf(pinfo[i].name, PORT_MAX_NAME_LEN, "%s", plist[i].name);
		if (plat_port_speed_get(pid, &pinfo[i].speed)) {
			UC_LOG_DBG("plat_port_speed_get failed");
			goto err;
		}
		if (plat_port_duplex_get(pid, &is_full_duplex)) {
			UC_LOG_DBG("plat_port_duplex_get failed");
			goto err;
		}
		pinfo[i].duplex = is_full_duplex;
		if (plat_port_oper_status_get(pid, &is_up)) {
			UC_LOG_DBG("plat_port_oper_status_get failed");
			goto err;
		}
		pinfo[i].carrier_up = is_up;
		if (plat_port_stats_get(pid, &pinfo[i].stats)) {
			UC_LOG_DBG("plat_port_stats_get failed");
			goto err;
		}

		if (!plat_port_lldp_peer_info_get(pid,
						  &pinfo[i].lldp_peer_info)) {
			pinfo[i].has_lldp_peer_info = 1;
		}

		plat_ieee8021x_system_auth_clients_get(pid,
						       &ieee8021x_buf,
						       &ieee8021x_buf_size,
						       &pinfo[i].ieee8021x_info);
	}

	*port_info = pinfo;
	*count = pcount;
	pinfo = 0;
	ret = 0;
err:
	free(pinfo);
	free(plist);
	free(ieee8021x_buf);
	if (ret)
		UC_LOG_DBG("failed");
	return ret;
}

static int get_meminfo_cached_kib(uint64_t *cached)
{
	size_t n;
	char *line = 0;
	int found = 0;
	FILE *f = fopen("/proc/meminfo", "r");
	if (!f)
		return -1;

	while (getline(&line, &n, f) >= 0) {
		if (sscanf(line, "Cached:%" SCNu64, cached) == 1) {
			found = 1;
			break;
		}
	}

	free(line);
	fclose(f);
	return found ? 0 : 1;
}

static int plat_system_info_get(struct plat_system_info *info)
{
	uint64_t cached = 0;
	struct sysinfo sys_info = { 0 };
	double loadArray[3] = { 0 };
	time_t localtime = time(0);

	sysinfo(&sys_info);

	get_meminfo_cached_kib(&cached);

	getloadavg(loadArray, 3);
	loadArray[0] /= 100;
	loadArray[1] /= 100;
	loadArray[2] /= 100;

	*info = (struct plat_system_info){ 0 };
	info->localtime = (uint64_t)localtime;
	info->uptime = (uint64_t)sys_info.uptime;
	info->ram_buffered = sys_info.bufferram * sys_info.mem_unit;
	info->ram_cached = cached * 1024;
	info->ram_free =
		(sys_info.freeram + sys_info.freeswap) * sys_info.mem_unit;
	info->ram_total = sys_info.totalram * sys_info.mem_unit;
	memcpy(info->load_average, loadArray, sizeof info->load_average);

	return 0;
}

static int plat_state_get(struct plat_state_info *state)
{
	size_t i;

	plat_poe_state_get(&state->poe_state);

	BITMAP_FOR_EACH_BIT_SET(i, plat_state.poe.ports_bmap, MAX_NUM_OF_PORTS)
	{
		plat_poe_port_state_get(i, &state->poe_ports_state[i]);
		BITMAP_SET_BIT(state->poe_ports_bmap, i);
	}

	if (plat_system_info_get(&state->system_info))
		return -1;

	if (plat_port_info_get(&state->port_info, &state->port_info_count))
		return -1;

	return 0;
}

static int config_vlan_ipv4_apply(struct plat_cfg *cfg)
{
	size_t i;
	int ret;

	BITMAP_FOR_EACH_BIT_SET(i, cfg->vlans_to_cfg, MAX_VLANS) {
		UC_LOG_DBG("Configuring vlan ip <%u>\n", (uint16_t)i);
		ret = plat_vlan_rif_set(cfg->vlans[i].id, &cfg->vlans[i].ipv4);
		if (ret) {
			UC_LOG_DBG("Failed to set VLAN rif.\n");
			return ret;
		}
	}

	return 0;
}

static int config_portl2_ipv4_apply(struct plat_cfg *cfg)
{
	size_t i;
	int ret;

	BITMAP_FOR_EACH_BIT_SET(i, cfg->ports_to_cfg, MAX_NUM_OF_PORTS) {
		UC_LOG_DBG("Configuring port ip <%u>\n", (uint16_t)i);
		/* If port is not in cfg - ipv4.exist == false */
		ret = plat_portl2_rif_set(i, &cfg->portsl2[i].ipv4);
		if (ret) {
			UC_LOG_DBG("Failed to set portl2 rif.\n");
			return ret;
		}
	}

	return 0;
}

static int config_vlan_dhcp_relay_apply(struct plat_cfg *cfg)
{
	gnma_dhcp_relay_circuit_id_t circ_id;
	struct gnma_ip ip;
	size_t i;
	int ret;

	/* Clear previous cfg: delete disabled relay-addresses, or
	 * delete relay-addresses if they've been changed.
	 */
	BITMAP_FOR_EACH_BIT_SET(i, cfg->vlans_to_cfg, MAX_VLANS)
	{
		/* Iterate only over configured vlans. */
		if (!plat_state.vlans[i].dhcp_relay.enabled)
			continue;

		/* If relay was enabled prior, and new cfg wants to disabled it -
		 * remove relay address from this iface.
		 * Also, remove relay helper address in case if both previous
		 * and new CFG enable dhcp-relay, but the helper-address's changed.
		 * New address will be added below.
		 *
		 * Since schema only able to configure one (first) server,
		 * remove server at idx 0.
		 */
		if ((!cfg->vlans[i].dhcp.relay.enabled &&
		    plat_state.vlans[i].dhcp_relay.enabled) ||
		    (plat_state.vlans[i].dhcp_relay.enabled &&
		     cfg->vlans[i].dhcp.relay.enabled &&
		     memcmp(&plat_state.vlans[i].dhcp_relay.helper_addresses[0].u.v4.s_addr,
			    &cfg->vlans[i].dhcp.relay.server_address.s_addr,
			    sizeof(cfg->vlans[i].dhcp.relay.server_address.s_addr)))) {

			UC_LOG_DBG("Vid <%u> removing %s \n",
				   (uint16_t)i,
				   inet_ntoa(plat_state.vlans[i].dhcp_relay.helper_addresses[0].u.v4));
			if (gnma_vlan_dhcp_relay_server_remove(i,
							       &plat_state.vlans[i].dhcp_relay.helper_addresses[0]))
				return -1;

			plat_state.vlans[i].dhcp_relay.enabled = false;
			memset(&plat_state.vlans[i].dhcp_relay.helper_addresses[0].u.v4.s_addr, 0,
			       sizeof(plat_state.vlans[i].dhcp_relay.helper_addresses[0].u.v4.s_addr));
		}
	}

	BITMAP_FOR_EACH_BIT_SET(i, cfg->vlans_to_cfg, MAX_VLANS)
	{
		/* Iterate only over vlans to-be-configured. */
		if (!cfg->vlans[i].dhcp.relay.enabled)
			continue;

		UC_LOG_DBG("Configuring vlan dhcp-relay <%u>\n", (uint16_t)i);
		UC_LOG_DBG("adding dhcp-relay helper addr <%s>\n",
			   inet_ntoa(cfg->vlans[i].dhcp.relay.server_address));

		memcpy(&ip.u.v4.s_addr,
		       &cfg->vlans[i].dhcp.relay.server_address.s_addr,
		       sizeof(ip.u.v4.s_addr));

		ret = gnma_vlan_dhcp_relay_server_add(i, &ip);
		if (ret) {
			UC_LOG_DBG("Failed to set VLAN dhcp-relay server.\n");
			return ret;
		}

		/* Schema only able to configure one (first) server,
		 * so copy just-configured addr at idx 0.
		 */
		memcpy(&plat_state.vlans[i].dhcp_relay.helper_addresses[0].u.v4.s_addr,
		       &ip.u.v4.s_addr, sizeof(ip.u.v4.s_addr));

		if (plat_state.vlans[i].dhcp_relay.max_hop_cnt != PLAT_DHCP_RELAY_DEFAULT_MAXHOP_CNT) {
			ret = gnma_vlan_dhcp_relay_max_hop_cnt_set(i, PLAT_DHCP_RELAY_DEFAULT_MAXHOP_CNT);
			if (ret) {
				UC_LOG_DBG("Failed to set VLAN dhcp-relay max hop to default value\n");
				return ret;
			}
			plat_state.vlans[i].dhcp_relay.max_hop_cnt =
				PLAT_DHCP_RELAY_DEFAULT_MAXHOP_CNT;
		}
		if (plat_state.vlans[i].dhcp_relay.policy_act != PLAT_DHCP_RELAY_DEFAULT_POLICY_ACT) {
			ret = gnma_vlan_dhcp_relay_policy_action_set(i, PLAT_DHCP_RELAY_DEFAULT_POLICY_ACT);
			if (ret) {
				UC_LOG_DBG("Failed to set VLAN dhcp-relay policy action to default value\n");
				return ret;
			}
			plat_state.vlans[i].dhcp_relay.policy_act =
				PLAT_DHCP_RELAY_DEFAULT_POLICY_ACT;
		}

		if (!strcmp(cfg->vlans[i].dhcp.relay.circ_id, "%u"))
			circ_id = GNMA_DHCP_RELAY_CIRCUIT_ID_I;
		else if (!strcmp(cfg->vlans[i].dhcp.relay.circ_id, "%p"))
			circ_id = GNMA_DHCP_RELAY_CIRCUIT_ID_P;
		else
			circ_id = GNMA_DHCP_RELAY_CIRCUIT_ID_H_P;

		if (plat_state.vlans[i].dhcp_relay.circ_id != circ_id) {
			ret = gnma_vlan_dhcp_relay_ciruit_id_set(i, circ_id);
			if (ret) {
				UC_LOG_DBG("Failed to set VLAN dhcp-relay circuit id format\n");
				return ret;
			}
			plat_state.vlans[i].dhcp_relay.circ_id = circ_id;
		}

		plat_state.vlans[i].dhcp_relay.enabled = true;
	}

	return 0;
}

static int config_vlan_apply(struct plat_cfg *cfg)
{
	struct gnma_change *c = 0;
	struct gnma_vlan_member_bmap *vlan_mbr = 0;
	int ret = 0;
	size_t i;

	/* Handle <negative> case: if there are configured VLANs on system that
	 * are not present in CFG - remove the missing VLANs firsts
	 */
	ret = plat_vlan_list_set(cfg->vlans_to_cfg);
	if (ret) {
		UC_LOG_DBG("Failed to set VLANs list.\n");
		goto err;
	}

	if (!(vlan_mbr = calloc(1, sizeof *vlan_mbr))) {
		UC_LOG_ERR("ENOMEM");
		ret = -1;
		goto err;
	}

	if ((ret = gnma_vlan_member_bmap_get(vlan_mbr))) {
		UC_LOG_ERR("gnma_vlan_member_bmap_get");
		goto err;
	}

	/* Handle <positive> case: setting vlan's member list;
	 * If vlan doesn't exist - it's being created upon member set call
	 */
	if (!(c = gnma_change_create())) {
		UC_LOG_ERR("gnma_change_create failed");
		ret = -1;
		goto err;
	}

	BITMAP_FOR_EACH_BIT_SET(i, cfg->vlans_to_cfg, GNMA_MAX_VLANS)
	{
		UC_LOG_DBG("Configuring vlan <%u>\n", (uint16_t)i);
		ret = plat_vlan_memberlist_set(c, vlan_mbr, &cfg->vlans[i]);
		if (ret) {
			UC_LOG_DBG("Failed to set VLAN members list.\n");
			goto err;
		}
	}
	ZFREE(vlan_mbr);

	if ((ret = gnma_change_exec(c)))
		UC_LOG_ERR("gnma_change_exec failed");

err:
	ZFREE(vlan_mbr);
	gnma_change_destory(c);

	return ret ? -1 : 0;
}

static int config_stp_apply_ports_enable_all(void)
{
	struct gnma_port_key *plist = NULL;
	uint16_t pcount = 0;
	int err = -1;
	int ret;

	if (plat_port_num_get(&pcount)) {
		UC_LOG_ERR("plat_port_num_get failed");
		goto err;
	}

	if (!(plist = malloc(sizeof *plist * pcount))) {
		goto err;
	}

	ret = gnma_port_list_get(&pcount, plist);
	if (ret && ret != GNMA_ERR_OVERFLOW) {
		UC_LOG_ERR("gnma_port_list_get failed");
		goto err;
	}

	ret = gnma_stp_ports_enable(pcount, plist);
	if (ret) {
		UC_LOG_ERR("gnma_stp_ports_enable failed");
		goto err;
	}

	err = 0;
err:
	free(plist);
	return err;
}

static int config_stp_apply(struct plat_cfg *cfg)
{
	struct gnma_stp_attr attr;
	int ret, i;

	switch (cfg->stp_mode) {
	case PLAT_STP_MODE_NONE:
		if (plat_state.stp_mode == GNMA_STP_MODE_NONE)
			break;

		/* This will clear all per port/vlan stp entries */
		ret = gnma_stp_mode_set(GNMA_STP_MODE_NONE, NULL);
		if (ret) {
			UC_LOG_ERR("Failed to disable STP.\n");
			return ret;
		}

		plat_state.stp_mode = GNMA_STP_MODE_NONE;
		memset(&plat_state.stp_vlan_attr[0], 0, sizeof(plat_state.stp_vlan_attr));
		break;
	case PLAT_STP_MODE_RPVST:
		/* Config mode */
		memset(&attr, 0, sizeof(attr));
		if (plat_state.stp_mode != GNMA_STP_MODE_RPVST ||
		    !gnma_stp_attr_cmp(&attr, &plat_state.stp_mode_attr)) {
			ret = gnma_stp_mode_set(GNMA_STP_MODE_RPVST, &attr);
			if (ret) {
				UC_LOG_ERR("Failed to set STP mode.\n");
				return ret;
			}

			/* Once mode enabled - create entries for all ports */
			ret = config_stp_apply_ports_enable_all();
			if (ret) {
				UC_LOG_ERR("Failed to set STP on ports.\n");
				return ret;
			}

			plat_state.stp_mode = GNMA_STP_MODE_RPVST;
			plat_state.stp_mode_attr = attr;
		}

		/* Config vlans */
		memset(&attr, 0, sizeof(attr));
		for (i = FIRST_VLAN; i < MAX_VLANS; i++) {
			attr.enabled = cfg->stp_instances[i].enabled;
			attr.priority = cfg->stp_instances[i].priority;
			attr.forward_delay = cfg->stp_instances[i].forward_delay;
			attr.hello_time = cfg->stp_instances[i].hello_time;
			attr.max_age = cfg->stp_instances[i].max_age;

			if (!plat_state.stp_vlan_attr[i].enabled && !attr.enabled) {
				continue;
			}

			if (gnma_stp_attr_cmp(&attr, &plat_state.stp_vlan_attr[i]))
				continue;

			UC_LOG_DBG(
				"set vlan=%d attr.enabled=%d attr.priority=%d "
				"attr.forward_delay=%d attr.hello_time=%d "
				"attr.max_age=%d state.enabled=%d state.priority=%d "
				"state.forward_delay=%d state.hello_time=%d "
				"state.max_age=%d ",
				i, attr.enabled, attr.priority, attr.forward_delay,
				attr.hello_time, attr.max_age,
				plat_state.stp_vlan_attr[i].enabled,
				plat_state.stp_vlan_attr[i].priority,
				plat_state.stp_vlan_attr[i].forward_delay,
				plat_state.stp_vlan_attr[i].hello_time,
				plat_state.stp_vlan_attr[i].max_age);

			ret = gnma_stp_vid_set(i, &attr);
			if (ret) {
				UC_LOG_ERR("Failed to set STP on vlan");
				return ret;
			}

			plat_state.stp_vlan_attr[i] = attr;
		}

		break;
	default:
		UC_LOG_ERR("Unsupported STP mode.\n");
		return -1;
	}

	return 0;
}

static int config_metrics_apply(struct plat_cfg *cfg)
{
    /* TODO(vb) */

	UC_LOG_DBG("Metrics cfg:\n");
	UC_LOG_DBG("healthcheck: enabled <%d>, interval <%zu>\n",
		   cfg->metrics.healthcheck.enabled,
		   cfg->metrics.healthcheck.interval);

	UC_LOG_DBG(
		"state: enabled <%d>, interval <%zu>, lldp_enabled <%d>, clients_enabled <%d>\n",
		cfg->metrics.state.enabled, cfg->metrics.state.interval,
		cfg->metrics.state.lldp_enabled, cfg->metrics.state.clients_enabled);

	return 0;
}

static void __poe_port_detection_mode_str2num(const char *str,
					      gnma_poe_port_detection_mode_t *mode)
{
	if (!strcmp(str, "2pt-dot3af"))
		*mode = GNMA_POE_PORT_DETECTION_MODE_2PT_DOT3AF_E;
	else if (!strcmp(str, "2pt-dot3af+legacy"))
		*mode = GNMA_POE_PORT_DETECTION_MODE_2PT_DOT3AF_LEG_E;
	else if (!strcmp(str, "4pt-dot3af"))
		*mode = GNMA_POE_PORT_DETECTION_MODE_4PT_DOT3AF_E;
	else if (!strcmp(str, "4pt-dot3af+legacy"))
		*mode = GNMA_POE_PORT_DETECTION_MODE_4PT_DOT3AF_LEG_E;
	else if (!strcmp(str, "dot3bt"))
		*mode = GNMA_POE_PORT_DETECTION_MODE_DOT3BT_E;
	else if (!strcmp(str, "dot3bt+legacy"))
		*mode = GNMA_POE_PORT_DETECTION_MODE_DOT3BT_LEG_E;
	else if (!strcmp(str, "legacy"))
		*mode = GNMA_POE_PORT_DETECTION_MODE_LEG_E;
	else
		/* In case if unsupported supplied - use a default one */
		*mode = GNMA_POE_PORT_DETECTION_MODE_4PT_DOT3AF_E;
}

static void __poe_port_priority_mode_str2num(const char *str,
					     gnma_poe_port_priority_t *priority)
{
	if (!strcmp(str, "low"))
		*priority = GNMA_POE_PORT_PRIORITY_LOW_E;
	else if (!strcmp(str, "medium"))
		*priority = GNMA_POE_PORT_PRIORITY_MEDIUM_E;
	else if (!strcmp(str, "high"))
		*priority = GNMA_POE_PORT_PRIORITY_HIGH_E;
	else if (!strcmp(str, "critical"))
		*priority = GNMA_POE_PORT_PRIORITY_CRITICAL_E;
	else
		*priority = GNMA_POE_PORT_PRIORITY_LOW_E;
}

static void __poe_power_mgmt_str2num(const char *str,
				     gnma_poe_power_mgmt_mode_t *mgmt_mode)
{
	if (!strcmp(str, "class"))
		*mgmt_mode = GNMA_POE_POWER_MGMT_CLASS_E;
	else if (!strcmp(str, "dynamic"))
		*mgmt_mode = GNMA_POE_POWER_MGMT_DYNAMIC_E;
	else if (!strcmp(str, "dynamic-priority"))
		*mgmt_mode = GNMA_POE_POWER_MGMT_DYNAMIC_PRIORITY_E;
	else if (!strcmp(str, "static"))
		*mgmt_mode = GNMA_POE_POWER_MGMT_STATIC_E;
	else if (!strcmp(str, "static-priority"))
		*mgmt_mode = GNMA_POE_POWER_MGMT_STATIC_PRIORITY_E;
	else
		*mgmt_mode = GNMA_POE_POWER_MGMT_CLASS_E;
}

static int
config_port_ieee8021x_apply(uint16_t port_id, struct plat_port *port_cfg)
{
	struct port *cached_port = &plat_state.ports.array[port_id];
	gnma_8021x_port_ctrl_mode_t ctrl_mode;
	gnma_8021x_port_host_mode_t host_mode;
	struct gnma_port_key gnma_port = {0};
	int ret;

	PID_TO_NAME(port_id, gnma_port.name);

	if (cached_port->ieee8021x.is_authenticator != port_cfg->ieee8021x.is_authenticator) {
		UC_LOG_DBG("configuring port .1x pae mode to %s",
			   port_cfg->ieee8021x.is_authenticator
			   ? "authenticator"
			   : "none");
		ret = gnma_port_ieee8021x_pae_mode_set(&gnma_port, port_cfg->ieee8021x.is_authenticator);
		if (ret)
			return ret;
	}

	switch (port_cfg->ieee8021x.control_mode) {
		case PLAT_802_1X_PORT_CONTROL_FORCE_AUTHORIZED:
			ctrl_mode = GNMA_8021X_PORT_CTRL_MODE_FORCE_AUTHORIZED;
			break;
		case PLAT_802_1X_PORT_CONTROL_FORCE_UNAUTHORIZED:
			ctrl_mode = GNMA_8021X_PORT_CTRL_MODE_FORCE_UNAUTHORIZED;
			break;
		case PLAT_802_1X_PORT_CONTROL_AUTO:
			ctrl_mode = GNMA_8021X_PORT_CTRL_MODE_AUTO;
			break;
		default: break;
	}

	if (cached_port->ieee8021x.control_mode != ctrl_mode) {
		ret = gnma_port_ieee8021x_port_ctrl_set(&gnma_port, ctrl_mode);
		UC_LOG_DBG("configuring port .1x pae mode from %d to %d",
			   cached_port->ieee8021x.control_mode,
			   ctrl_mode);
		if (ret)
			return ret;
	}

	switch (port_cfg->ieee8021x.host_mode) {
		case PLAT_802_1X_PORT_HOST_MODE_MULTI_AUTH:
			host_mode = GNMA_8021X_PORT_HOST_MODE_MULTI_AUTH;
			break;
		case PLAT_802_1X_PORT_HOST_MODE_MULTI_DOMAIN:
			host_mode = GNMA_8021X_PORT_HOST_MODE_MULTI_DOMAIN;
			break;
		case PLAT_802_1X_PORT_HOST_MODE_MULTI_HOST:
			host_mode = GNMA_8021X_PORT_HOST_MODE_MULTI_HOST;
			break;
		case PLAT_802_1X_PORT_HOST_MODE_SINGLE_HOST:
			host_mode = GNMA_8021X_PORT_HOST_MODE_SINGLE_HOST;
			break;
		default: break;
	}

	if (cached_port->ieee8021x.host_mode != host_mode) {
		ret = gnma_port_ieee8021x_port_host_mode_set(&gnma_port, host_mode);
		UC_LOG_DBG("configuring port .1x host mode from %d to %d",
			   cached_port->ieee8021x.host_mode,
			   host_mode);
		if (ret)
			return ret;
	}

	if (cached_port->ieee8021x.guest_vid != port_cfg->ieee8021x.guest_vid) {
		UC_LOG_DBG("configuring port .1x guest vid from %d to %d",
			   cached_port->ieee8021x.guest_vid, port_cfg->ieee8021x.guest_vid);
		ret = gnma_port_ieee8021x_guest_vlan_set(&gnma_port, port_cfg->ieee8021x.guest_vid);
		if (ret)
			return ret;
	}

	if (cached_port->ieee8021x.auth_fail_vid != port_cfg->ieee8021x.auth_fail_vid) {
		UC_LOG_DBG("configuring port .1x fail vid from %d to %d",
			   cached_port->ieee8021x.auth_fail_vid, port_cfg->ieee8021x.auth_fail_vid);
		ret = gnma_port_ieee8021x_unauthorized_vlan_set(&gnma_port,
								port_cfg->ieee8021x.auth_fail_vid);
		if (ret)
			return ret;
	}

	cached_port->ieee8021x.is_authenticator =
		port_cfg->ieee8021x.is_authenticator;
	cached_port->ieee8021x.control_mode = ctrl_mode;
	cached_port->ieee8021x.guest_vid = port_cfg->ieee8021x.guest_vid;
	cached_port->ieee8021x.auth_fail_vid = port_cfg->ieee8021x.auth_fail_vid;
	cached_port->ieee8021x.host_mode = port_cfg->ieee8021x.host_mode;

	return 0;
}

static int config_poe_port_apply(uint16_t pid,
				 struct plat_port *port_cfg)
{
	struct poe_port *poe_port = &plat_state.poe.ports[pid];
	bool is_power_limit_user_defined = false;
	uint32_t power_limit = 0;
	int ret;

	if (port_cfg->poe.is_detection_mode_set) {
		gnma_poe_port_detection_mode_t mode;

		__poe_port_detection_mode_str2num(port_cfg->poe.detection_mode, &mode);

		if (poe_port->detection_mode != mode) {
			UC_LOG_DBG("configuring poe port detection_mode <%d> to <%d>\n",
				   poe_port->detection_mode, mode);
			ret = gnma_poe_port_detection_mode_set(&poe_port->key,
							       mode);
			if (ret)
				return -1;
			poe_port->detection_mode = mode;
		}
	}

	if (port_cfg->poe.is_priority_set) {
		gnma_poe_port_priority_t priority;

		__poe_port_priority_mode_str2num(port_cfg->poe.priority, &priority);

		if (poe_port->priority != priority) {
			UC_LOG_DBG("configuring poe port priority <%d> to <%d>\n",
				   poe_port->priority, priority);
			ret = gnma_poe_port_priority_set(&poe_port->key,
							 priority);
			if (ret) {
				UC_LOG_ERR("gnma_poe_port_priority_set failed");
				return -1;
			}
			poe_port->priority = priority;
		}
	}

	/* In case if power_limit is omitted, it means that user doesn't
	 * care about actual power limit, and relies the selection choice
	 * on the power delivering unit - power limit is unlimited,
	 * and power limit type is set to 'Class based' (e.g. NOT user defined).
	 * This implies an explicit limit_set.
	 *
	 * Setting limit type to 'User defined' with power limit '0' is also
	 * technically a valid configuration, hence all these cases should
	 * be explicitly handled as in if-clauses below.
	 */
	if (port_cfg->poe.is_power_limit_set) {
		power_limit = port_cfg->poe.power_limit;
		is_power_limit_user_defined = true;
	}
	if (poe_port->power_limit != power_limit ||
	    poe_port->is_power_limit_user_defined != is_power_limit_user_defined) {
		UC_LOG_DBG("configuring poe port power limit <%d,%d> to <%d,%d>\n",
			   poe_port->is_power_limit_user_defined, poe_port->power_limit,
			   is_power_limit_user_defined, power_limit);
		ret = gnma_poe_port_power_limit_set(&poe_port->key,
						    is_power_limit_user_defined,
						    power_limit);

		if (ret) {
			UC_LOG_ERR("gnma_poe_port_power_limit_set failed");
			return -1;
		}
		poe_port->is_power_limit_user_defined = is_power_limit_user_defined;
		poe_port->power_limit = power_limit;
	}

	if (poe_port->is_admin_mode_up != port_cfg->poe.is_admin_mode_up) {
		UC_LOG_DBG("configuring poe port admin mode <%d> to <%d>\n",
			   poe_port->is_admin_mode_up, port_cfg->poe.is_admin_mode_up);
		ret = gnma_poe_port_admin_mode_set(&poe_port->key,
						   port_cfg->poe.is_admin_mode_up);
		if (ret) {
			UC_LOG_ERR("gnma_poe_port_admin_mode_set failed");
			return -1;
		}
		poe_port->is_admin_mode_up = port_cfg->poe.is_admin_mode_up;
	}

	if (port_cfg->poe.do_reset) {
		UC_LOG_DBG("issuing poe port reset\n");
		ret = gnma_poe_port_reset(&poe_port->key);
		if (ret) {
			UC_LOG_ERR("gnma_poe_port_reset failed");
			return -1;
		}
	}

	return 0;
}

/* Do diff + copy to cache + free old cache */
/* CFG and cache is different structs. Not depend on each other. */
static int config_router_apply(struct plat_cfg *cfg)
{
	struct ucentral_router newr, oldr;
	struct gnma_route_attrs gattr;
	struct gnma_ip_prefix gpref;
	ssize_t oi, ni;
	int ret, diff;

	oldr = plat_state.router;
	ret = ucentral_router_fib_db_copy(&cfg->router, &newr);
	if (ret)
		return ret;

	if (!newr.sorted)
		ucentral_router_fib_db_sort(&newr);
	if (!oldr.sorted)
		ucentral_router_fib_db_sort(&oldr);

	for_router_db_diff(&newr, &oldr, ni, oi, diff) {
		diff = router_db_diff_get(&newr, &oldr, ni, oi);

		if (diff_case_upd(diff)) {
			if (!ucentral_router_fib_info_cmp(&router_db_get(&newr, ni)->info,
							  &router_db_get(&oldr, oi)->info))
				continue;

			router_fib_key2gnma_prefix(&router_db_get(&newr, ni)->key, &gpref);
			gnma_route_remove(0, &gpref);
			ret = router_fib_info2gnma_attr(&router_db_get(&newr, ni)->info,
							&gattr);
			if (ret)
				return -1;

			ret = gnma_route_create(0, &gpref, &gattr);
			if (ret)
				return -1;
		}

		if (diff_case_del(diff)) {
			router_fib_key2gnma_prefix(&router_db_get(&oldr, oi)->key,
						   &gpref);
			gnma_route_remove(0, &gpref);
		}

		if (diff_case_add(diff)) {
			router_fib_key2gnma_prefix(&router_db_get(&newr, ni)->key, &gpref);

			ret = router_fib_info2gnma_attr(&router_db_get(&newr, ni)->info,
							&gattr);
			if (ret)
				return -1;

			ret = gnma_route_create(0, &gpref, &gattr);
			if (ret)
				return -1;
		}
	}

	ucentral_router_fib_db_free(&oldr);
	plat_state.router = newr;

	return 0;
}

static int plat_radius_hosts_list_set(struct plat_radius_hosts_list *hosts)
{
	struct plat_radius_hosts_list *iter;
	bool cache_changed = false;
	int ret = 0;
	size_t i;

	/* Check cache and remove any host that is not present in
	 * requested CFG (same as for VLAN: if not present in cfg = to
	 * be removed).
	 */
	for (i = 0; i < plat_state.radius.hosts_keys_arr_size; ++i) {
		if (!PLAT_RADIUS_HOST_EXISTS_IN_CFG(plat_state.radius.hosts_keys_arr[i].hostname, &hosts)) {
			UC_LOG_DBG("Removing RADIUS server <%s> (not in cfg, present on system)\n",
				   plat_state.radius.hosts_keys_arr[i].hostname);
			ret = gnma_radius_host_remove(&plat_state.radius.hosts_keys_arr[i]);
			if (ret)
				return ret;
			cache_changed = true;
		} else {
			/* Special case, when host exists in cache and new CFG omitted password:
			 * - remove previous entry
			 * - recreate it without specifying password.
			 * Either way SONIC treats this host as if password is set
			 * explicitly, and might result in false-obfuscations of
			 * EAP exchange between RADIUS and switch.
			 */
			UCENTRAL_LIST_FOR_EACH_MEMBER(iter, &hosts) {
				if (strcmp(plat_state.radius.hosts_keys_arr[i].hostname,
					   iter->host.hostname) == 0 &&
				    iter->host.passkey[0] == '\0') {
					ret = gnma_radius_host_remove(&plat_state.radius.hosts_keys_arr[i]);
					if (ret) {
						UC_LOG_DBG("Failed to remove RADIUS host <%s> (new CFG pass is empty, tried to delete))\n",
							   plat_state.radius.hosts_keys_arr[i].hostname);
						return ret;
					}
					cache_changed = true;
					break;
				}
			}
		}
	}

	/* Add any new hosts that are present in requested CFG. */
	UCENTRAL_LIST_FOR_EACH_MEMBER(iter, &hosts) {
		struct gnma_radius_host_key key;

		strcpy(key.hostname, iter->host.hostname);

		ret = gnma_radius_host_add(&key, iter->host.passkey,
					   iter->host.auth_port,
					   iter->host.priority);
		if (ret)
			return ret;
		cache_changed = true;
	}

	/* Reinit RADIUS hosts cache. */
	if (cache_changed)
		plat_state_radius_init();

	return 0;
}

static int config_unit_apply(struct plat_cfg *cfg)
{
	gnma_poe_power_mgmt_mode_t mgmt_mode;
	int ret;

	__poe_power_mgmt_str2num(cfg->unit.poe.power_mgmt, &mgmt_mode);

	if (cfg->unit.poe.is_power_mgmt_set &&
	    plat_state.poe.power_mgmt != mgmt_mode) {
		UC_LOG_DBG("Configuring unit.poe power mgmt mode <%d> to <%d>\n",
			   plat_state.poe.power_mgmt, mgmt_mode);
		ret = gnma_poe_power_mgmt_set(mgmt_mode);
		if (ret)
			return ret;
		plat_state.poe.power_mgmt = mgmt_mode;
	}

	if (cfg->unit.poe.is_usage_threshold_set &&
	    plat_state.poe.usage_threshold != cfg->unit.poe.usage_threshold) {
		UC_LOG_DBG("Configuring unit.poe usage threshold <%d> to <%d>\n",
			   plat_state.poe.usage_threshold, cfg->unit.poe.usage_threshold);
		ret = gnma_poe_usage_threshold_set(cfg->unit.poe.usage_threshold);
		if (ret)
			return ret;
		plat_state.poe.usage_threshold = cfg->unit.poe.usage_threshold;
	}

	return 0;
}

static int plat_port_config_apply(struct plat_cfg *cfg)
{
	size_t i;
	int ret;
	int is_8021x_reported = 0, is_poe_reported = 0;

	BITMAP_FOR_EACH_BIT_SET(i, cfg->ports_to_cfg, MAX_NUM_OF_PORTS) {
		UC_LOG_DBG("Configuring port <%s>: speed <%d> duplex <%d> state <%d>\n",
				cfg->ports[i].name, cfg->ports[i].speed,
				cfg->ports[i].duplex, cfg->ports[i].state);
		ret = plat_port_admin_state_set(i, cfg->ports[i].state);
		if (cfg->ports[i].state) {
			ret |= plat_port_speed_set(i, cfg->ports[i].speed);
			ret |= plat_port_duplex_set(i, cfg->ports[i].duplex);
		}

		if (ret)
			return -1;

		if (featsts[FEAT_AAA] == FEATSTS_OK) {
			if (config_port_ieee8021x_apply(i, &cfg->ports[i]))
				return -1;
		} else if (!is_8021x_reported) {
			CFG_LOG_CRIT(
				"AAA feature is not initialized, skipping configuration");
			is_8021x_reported = 1;
		}

		if (!BITMAP_TEST_BIT(plat_state.poe.ports_bmap, i))
			continue;

		if (featsts[FEAT_POE] == FEATSTS_OK) {
			if (config_poe_port_apply(i, &cfg->ports[i]))
				return -1;
		} else if (!is_poe_reported) {
			CFG_LOG_CRIT(
				"POE feature is not initialized, skipping configuration");
			is_poe_reported = 1;
		}
	}

	return 0;
}

static int config_ieee8021x_apply(struct plat_cfg *cfg)
{
	int ret;

	if (cfg->ieee8021x_is_auth_ctrl_enabled != plat_state.ieee8021x.is_auth_control_enabled) {
		UC_LOG_DBG("802.1x: changing global auth ctrl state from %d to %d",
			   plat_state.ieee8021x.is_auth_control_enabled,
			   cfg->ieee8021x_is_auth_ctrl_enabled);
		ret = gnma_ieee8021x_system_auth_control_set(cfg->ieee8021x_is_auth_ctrl_enabled);
		if (ret) {
			UC_LOG_DBG("802.1x: Failed to set global auth ctrl state.");
			return ret;
		}
		plat_state.ieee8021x.is_auth_control_enabled = cfg->ieee8021x_is_auth_ctrl_enabled;
	}

	ret = plat_radius_hosts_list_set(cfg->radius_hosts_list);
	if (ret) {
		UC_LOG_DBG("802.1x: Failed to set RADIUS hosts list.");
		return ret;
	}

	return 0;
}

int plat_config_apply(struct plat_cfg *cfg, uint32_t id)
{
	int ret;

	(void)id;

	if (featsts[FEAT_CORE] != FEATSTS_OK) {
		CFG_LOG_CRIT(
			"core features are not initialized, the system is not stable");
	}

	ret = config_vlan_apply(cfg);
	if (ret)
		return -1;

	ret = plat_port_config_apply(cfg);
	if (ret)
		return -1;

	ret = config_unit_apply(cfg);
	if (ret)
		return -1;

	ret = config_stp_apply(cfg);
	if (ret)
		return -1;

	ret = config_vlan_ipv4_apply(cfg);
	if (ret)
		return -1;

	ret = config_portl2_ipv4_apply(cfg);
	if (ret)
		return -1;

	ret = config_vlan_dhcp_relay_apply(cfg);
	if (ret)
		return -1;

	ret = config_metrics_apply(cfg);
	if (ret)
		return -1;

	ret = config_router_apply(cfg);
	if (ret)
		return -1;

	if (featsts[FEAT_AAA] == FEATSTS_OK) {
		if (config_ieee8021x_apply(cfg))
			return -1;
	} else {
		CFG_LOG_CRIT(
			"AAA feature is not initialized, skipping configuration");
	}

	plat_syslog_set(cfg->log_cfg, cfg->log_cfg_cnt);

	return 0;
}

void plat_config_destroy(struct plat_cfg *cfg)
{
	struct plat_vlan_memberlist *member_node = NULL;
	struct plat_radius_hosts_list *hosts_node = NULL;
	size_t i;

	if (!cfg)
		return; /* like free() */

	ucentral_router_fib_db_free(&cfg->router);

	/* TODO: do better */
	BITMAP_FOR_EACH_BIT_SET(i, cfg->vlans_to_cfg, GNMA_MAX_VLANS)
	{
		UCENTRAL_LIST_DESTROY_SAFE(&cfg->vlans[i].members_list_head,
					   member_node);

		cfg->vlans[i].members_list_head = NULL;
	}

	UCENTRAL_LIST_DESTROY_SAFE(&cfg->radius_hosts_list,
			hosts_node);
}

/* TODO(vb) 1. will be hidden in plat 2. this approach does not survive
 * upgrade. also it does not seem telemetry provide storage services, but need
 * to double-check later */
int plat_metrics_save(const struct plat_metrics_cfg *cfg)
{
	FILE *cfg_file = 0;

	if (!cfg)
		return -1;

	cfg_file = fopen(cfgmetrics_path, "w+");
	if (!cfg_file)
		return -1;

	fprintf(cfg_file, "%d\n", !!cfg->healthcheck.enabled);
	fprintf(cfg_file, "%zu\n", cfg->healthcheck.interval);
	fprintf(cfg_file, "%d\n", !!cfg->state.enabled);
	fprintf(cfg_file, "%d\n", !!cfg->state.lldp_enabled);
	fprintf(cfg_file, "%d\n", !!cfg->state.clients_enabled);
	fprintf(cfg_file, "%zu\n", cfg->state.interval);
	fprintf(cfg_file, "%s\n", cfg->state.public_ip_lookup);

	fclose(cfg_file);
	return 0;
}

int plat_metrics_restore(struct plat_metrics_cfg *cfg)
{
	size_t len;
	FILE *cfg_file = 0;

	if (!cfg)
		return -1;

	cfg_file = fopen(cfgmetrics_path, "r");
	if (!cfg_file)
		return -1;

	if (fscanf(cfg_file, "%d", &cfg->healthcheck.enabled) != 1 ||
	    fscanf(cfg_file, "%zu", &cfg->healthcheck.interval) != 1 ||
	    fscanf(cfg_file, "%d", &cfg->state.enabled) != 1 ||
	    fscanf(cfg_file, "%d", &cfg->state.lldp_enabled) != 1 ||
	    fscanf(cfg_file, "%d", &cfg->state.clients_enabled) != 1 ||
	    fscanf(cfg_file, "%zu", &cfg->state.interval) != 1 ||
	    !fgets(cfg->state.public_ip_lookup,
		   sizeof cfg->state.public_ip_lookup, cfg_file)) {
		fclose(cfg_file);
		return -1;
	}

	len = strlen(cfg->state.public_ip_lookup);
	if (len && cfg->state.public_ip_lookup[len - 1] == '\n')
		cfg->state.public_ip_lookup[len - 1] = 0;

	fclose(cfg_file);
	return 0;
}

int plat_diagnostic(char *res_path)
{
	if (gnma_techsupport_start(res_path))
		return -1;

	return 0;
}

static size_t simple_wordexp(const char **s, char *out, size_t outsz,
			     size_t *toklen, int *delim)
{
	int ch; /* current char */
	int esc = 0; /* escape */
	int q = 0; /* quote char */
	size_t tl = 0, oi = 0; /* token length, output iterator */

	while (**s == ' ' || **s == '\n' || **s == '\t' || **s == '\v' ||
	       **s == '\r' || **s == '\f') {
		++*s;
	}

	for (ch = **s; **s; ch = *++*s) {
		if (!esc && ch == '\\') {
			esc = 1;
		} else if (esc) {
			if (q && q != ch) {
				if (oi < outsz)
					out[oi++] = '\\';
				++tl;
			}
			if (oi < outsz)
				out[oi++] = ch;
			++tl;
			esc = 0;
		} else if (q) {
			if (ch == q) {
				q = 0;
			} else {
				if (oi < outsz)
					out[oi++] = ch;
				++tl;
			}
		} else {
			if (ch == '"' || ch == '\'') {
				q = ch;
			} else {
				if (ch == ' ' || ch == '\n' || ch == '\t' ||
				    ch == '\v' || ch == '\r' || ch == '\f') {
					++*s;
					break;
				} else {
					if (oi < outsz)
						out[oi++] = ch;
					++tl;
				}
			}
		}
	}

	if (toklen)
		*toklen = tl;

	if (delim)
		*delim = ch;

	return oi;
}

static void *script_runner(void *p)
{
	static __thread char *arg[SCRIPT_ARGMAX];
	static __thread char token[SCRIPT_ARGMAX][SCRIPT_TOKLEN];
	sigset_t sigset;
	const char *script;
	int timeout, i, n, wstatus = 0;
	struct plat_run_script_result res = {0};
	struct timespec run = {0}, now = {0}, start = {0};
	ssize_t ri = 0, bi = 0;
	pid_t pid = -1;
	int fd = -1, rc = 0;
	int exit_status = 0;
	struct script_ctx *ctx = p;

	memset(&sigset, 0, sizeof sigset);
	if (sigemptyset(&sigset)) {
		UC_LOG_CRIT("sigemptyset failed");
	}

	if (clock_gettime(CLOCK_MONOTONIC, &start)) {
		UC_LOG_CRIT("clock_gettime(CLOCK_MONOTONIC): %s", strerror(errno));
		rc = -1;
		goto exit;
	}

	script = script_ctx.script_buf;
	for (i = 0; *script && !exit_status && bi < SCRIPT_OUTLEN - 1 && !rc; ++i) {
		size_t sz;
		int argc;
		int ignore = 0, delim = 0;

		for (argc = 0; argc < SCRIPT_ARGMAX && *script && delim != '\n';
		     ++argc) {
			sz = simple_wordexp(&script, token[argc], SCRIPT_TOKLEN,
					    0, &delim);
			if (ignore) /* continue to parse */
				continue;
			if (sz == SCRIPT_TOKLEN) {
				UC_LOG_ERR("the token is too long, ignoring the whole line");
				ignore = 1;
				continue;
			}
			token[argc][sz] = 0;
			arg[argc] = token[argc];
		}

		if (ignore || argc < 1 || argc >= SCRIPT_ARGMAX)
			continue;

		arg[argc] = 0;
		if (strcmp(arg[0], "ping") &&
            strcmp(arg[0], "nslookup") &&
		    strcmp(arg[0], "traceroute")) {
			continue;
		}

		/* TODO(vb) add cleaned up env */
		pid = spawnp(arg[0], arg, 0, &sigset, -1, -1, 0, &fd, O_NONBLOCK);
		if (pid < 0) {
			UC_LOG_ERR("failed to spawn %s: %s", arg[0], strerror(errno));
			rc = -1;
			break;
		}

		while (1) {
			struct pollfd pfd = { fd, POLLIN, 0 };

			if (clock_gettime(CLOCK_MONOTONIC, &now)) {
				UC_LOG_CRIT(
					"clock_gettime(CLOCK_MONOTONIC): %s",
					strerror(errno));
				rc = -1;
				goto child_finish;
			}

			run = sub_timespec(&now, &start);
			if (run.tv_sec < 0) {
				rc = -1;
				UC_LOG_CRIT("now is behind start");
				goto child_finish;
			}
			timeout = (ctx->t - run.tv_sec);
			timeout = timeout < 0 ? 0 :
						      (timeout * 1000 + run.tv_nsec / 1000000L);

			n = poll(&pfd, 1, timeout);
			if (n < 0) {
				if (errno == EINTR)
					continue;
				UC_LOG_CRIT("poll failed: %s", strerror(errno));
				rc = -1;
				break;
			}
			if (n == 0) {
				res.timeout_exceeded = 1;
				break;
			}

			if (pfd.revents & POLLIN) {
				while (1) {
					ri = read(pfd.fd, &script_ctx.outbuf[bi],
                              SCRIPT_OUTLEN - bi - 1);

					if (ri < 0) {
						if (errno == EINTR)
							continue;
						if (errno == EWOULDBLOCK || errno == EAGAIN)
							break;
						UC_LOG_CRIT("read failed: %s", strerror(errno));
						rc = -1;
						goto child_finish;
					}

					if (ri == 0)
						goto child_finish;

					bi += ri;
					if (bi >= SCRIPT_OUTLEN - 1) /* TODO(vb) chunked upload? move to callback */
						goto child_finish;
				}
			}

			if (pfd.revents & POLLHUP) {
				break;
			}
		}

child_finish:
		close(fd);
		fd = -1;

		/* TODO(vb) put into pid namesapce if expanding functionality */
		if (kill(pid, SIGKILL)) {
			UC_LOG_CRIT("kill failed: %s", strerror(errno));
		}

		while (1) {
			while ((n = waitpid(pid, &wstatus, 0)) < 0 && errno == EINTR);
			if (n <= 0)
				break;
			if (WIFEXITED(wstatus)) {
				exit_status = WEXITSTATUS(wstatus);
				break;
			}
			if (WIFSIGNALED(wstatus)) {
				exit_status = 128 + WTERMSIG(wstatus);
				break;
			}
		}
	}

exit:
	free(script_ctx.script_buf);

	script_ctx.outbuf[bi] = 0;
	res.exit_status = exit_status;
	res.stdout_string = script_ctx.outbuf;
	res.stdout_string_len = bi;

	if (ctx->cb)
		ctx->cb(rc, &res, ctx->ctx);

	free(script_ctx.outbuf);
	script_lock_release();

	return 0;
}

int plat_run_script(struct plat_run_script *p)
{
	size_t len;

	if (strcmp(p->type, "shell")) {
		UC_LOG_ERR("only type 'shell' script is supported");
		return -1;
	}

	if (p->timeout > INT_MAX) {
		UC_LOG_ERR("invalid timeout");
		return -1;
	}

	if (script_lock_aquire()) {
		UC_LOG_ERR("max 1 script at a time");
		return -1;
	}

	if (script_ctx.is_tid_valid) {
		if (pthread_join(script_ctx.tid, 0)) {
			UC_LOG_CRIT("pthread_join: %s", strerror(errno));
		}
	}
	script_ctx = (struct script_ctx){
		.cb = p->cb,
		.ctx = p->ctx,
	};
	script_ctx.t = p->timeout;

	len = strlen(p->script_base64);
	if (!(script_ctx.script_buf =
		      calloc(1, BASE64_DECODE_OUT_SIZE(len) + 1))) {
		goto exit;
	}
	script_ctx.script_bufsz = base64_decode(p->script_base64, len,
						(void *)script_ctx.script_buf);
	if (!script_ctx.script_bufsz) {
		UC_LOG_ERR("failed to decode base64 script text");
		goto exit;
	}

	if (!(script_ctx.outbuf = malloc(SCRIPT_OUTLEN)))
		goto exit;

	if (pthread_create(&script_ctx.tid, 0, script_runner, &script_ctx)) {
		UC_LOG_ERR("pthread_create: %s", strerror(errno));
		goto exit;
	}

	script_ctx.is_tid_valid = 1;
exit:
	if (!script_ctx.is_tid_valid) {
		free(script_ctx.script_buf);
		free(script_ctx.outbuf);
		script_lock_release();
		return -1;
	}
	return 0;
}
