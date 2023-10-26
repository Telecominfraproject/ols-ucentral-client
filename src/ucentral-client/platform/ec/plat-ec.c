#include <stdio.h>
#include <ucentral-platform.h>
#include <ucentral-log.h>
#include <errno.h>
#include <sys/sysinfo.h>
#include <ctype.h>
#include <pthread.h>

#include "snmp_helper.h"
#include "api_device.h"
#include "api_stats.h"

#define print_err(...) fprintf(stderr, __VA_ARGS__)

#define SPEED_DPX_NUM 14
struct port_speed_duplex{
	int speed;
	int duplex;
}port_speed_duplex_st[SPEED_DPX_NUM] = {
	{0, 0},    // 0
	{0, 0},    // 1
	{10, 0},   // 2
	{10, 1},   // 3
	{100, 0},  // 4
	{100, 1},  // 5
	{1000, 0}, // 6
	{1000, 1}, // 7
	{10000, 0},// 8
	{10000, 1},// 9
	{0, 0},    // 10
	{0, 0},    // 11
	{0, 0},    // 12
	{2500, 1}  // 13
};

static int plat_state_get(struct plat_state_info *state);
static void plat_state_deinit(struct plat_state_info *state);

struct plat_cb_ctx {
	void (*cb)();
	void *data;
};

struct plat_telemetry_cb_ctx {
	void (*cb)(struct plat_state_info *);
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

#define UNUSED_PARAM(param) (void)((param))

#define CFG_NAME "ucentral.cfg"
#define OID_JOIN(buf, oid_str, num)  snprintf(buf, MAX_OID_LEN, "%s.%d", oid_str, num)
#define REDIRECTOR_FILE "/etc/ucentral/redirector.json"
#define MAX_FILE_PATH_SIZE 64
#define MAX_CMD_SIZE 512

static struct periodic *health_periodic;
static struct periodic *state_periodic;
static struct periodic *telemetry_periodic;
static interface_t *ethernet_cache = NULL;
uint32_t poe_port_num;

static int health_periodic_cb(void *data)
{
	struct plat_cb_ctx *ctx = data;
	void (*cb)(struct plat_health_info *) = ctx->cb;
	struct plat_health_info health = {
		.sanity = 100,
	};

	struct sysinfo info = { 0 };
	sysinfo(&info);
	uint32_t used_memory = (uint32_t) (100.0 - ((double)info.freeram / (double) info.totalram * 100.0) + 0.5);
	snprintf(health.msg[0], sizeof health.msg[0], "memory:%d", used_memory);

	if (cb)
		cb(&health);

	return 0;
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

static void plat_state_deinit(struct plat_state_info *state)
{
	free(state->port_info);
	*state = (struct plat_state_info){ 0 };
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
	time_t localtime = time(0);
	int i;

	sysinfo(&sys_info);
	
	get_meminfo_cached_kib(&cached);

	*info = (struct plat_system_info){ 0 };
	info->localtime = (uint64_t)localtime;
	info->uptime = (uint64_t)sys_info.uptime;
	info->ram_buffered = sys_info.bufferram * sys_info.mem_unit;
	info->ram_cached = cached * 1024;
	info->ram_free =
		(sys_info.freeram + sys_info.freeswap) * sys_info.mem_unit;
	info->ram_total = sys_info.totalram * sys_info.mem_unit;

	float f_load = 1.f / (1 << SI_LOAD_SHIFT);
	for (i = 0; i < 3; i++) {
		info->load_average[i] = sys_info.loads[i] * f_load / 100;
	}

	return 0;
}

static int plat_port_info_get(struct plat_port_info **port_info, int *count)
{
	int rc;
	size_t i = 0;
	uint16_t pcount = 0;
	struct plat_port_info *pinfo = 0;
	int ret = -1;
	int status;

	/* TODO(vb) beautify &c */
	if (plat_port_num_get(&pcount)) {
		UC_LOG_DBG("plat_port_num_get failed");
		goto err;
	}

	if (!(pinfo = malloc(sizeof *pinfo * pcount))) {
		goto err;
	}

	interface_t *ethernets = calloc(pcount, sizeof(interface_t));

	if (ethernets == NULL) {
		print_err("ucentral-client: no memory for ethernet stats\n");
		goto err;
	}

	status = get_ethernet_stats(ethernets, pcount);
	if (status != STATUS_SUCCESS) {
		goto err;
	}

	if (ethernet_cache == NULL) {
		ethernet_cache = calloc(pcount, sizeof(interface_t));
		memcpy(ethernet_cache, ethernets, pcount * sizeof(interface_t));
	}


	for (i = 0; i < pcount; ++i) {
		uint16_t pid;

		pinfo[i] = (struct plat_port_info){ 0 };
		snprintf(pinfo[i].name, PORT_MAX_NAME_LEN, "%s%d", "Ethernet", i);
		
		//pinfo[i].uptime = ethernets[i].uptime;
		if(ethernets[i].uptime != 0)
			pinfo[i].carrier_up = 1;
		else
			pinfo[i].carrier_up = 0;
		status = ethernets[i].speed_dpx_status;
		if(status > 0 && status < SPEED_DPX_NUM){
			pinfo[i].speed = port_speed_duplex_st[status].speed;
			pinfo[i].duplex = port_speed_duplex_st[status].duplex;
		}
		
		pinfo[i].stats.collisions = ethernets[i].counters.collisions - ethernet_cache[i].counters.collisions;
		pinfo[i].stats.multicast = ethernets[i].counters.multicast  - ethernet_cache[i].counters.multicast;
		pinfo[i].stats.rx_bytes = ethernets[i].counters.rx_bytes   - ethernet_cache[i].counters.rx_bytes;
		pinfo[i].stats.rx_dropped = ethernets[i].counters.rx_dropped - ethernet_cache[i].counters.rx_dropped;
		pinfo[i].stats.rx_error = ethernets[i].counters.rx_errors  - ethernet_cache[i].counters.rx_errors;
		pinfo[i].stats.rx_packets = ethernets[i].counters.rx_packets - ethernet_cache[i].counters.rx_packets;
		pinfo[i].stats.tx_bytes = ethernets[i].counters.tx_bytes   - ethernet_cache[i].counters.tx_bytes;
		pinfo[i].stats.tx_dropped = ethernets[i].counters.tx_dropped - ethernet_cache[i].counters.tx_dropped;
		pinfo[i].stats.tx_error = ethernets[i].counters.tx_errors  - ethernet_cache[i].counters.tx_errors;
		pinfo[i].stats.tx_packets = ethernets[i].counters.tx_packets - ethernet_cache[i].counters.tx_packets;
		
	}
	memcpy(ethernet_cache, ethernets, pcount * sizeof(interface_t));
	
	*port_info = pinfo;
	*count = pcount;
	pinfo = 0;
	ret = 0;
err:
	free(pinfo);
	free(ethernets);

	if (ret)
		UC_LOG_DBG("failed");
	return ret;
}

static int plat_state_get(struct plat_state_info *state)
{
	if (plat_system_info_get(&state->system_info))
		return -1;

	if (plat_port_info_get(&state->port_info, &state->port_info_count))
		return -1;

	return 0;
}

void clean_stats()
{
	if (ethernet_cache) {
		free(ethernet_cache);
	}
}

int port_bitmap_adjust(int port_in)
{
	int port_out = port_in;

	if (port_in <= 31)
	{
		port_out = 31 - port_in;
	}
	else if (port_in>=32 && port_in<64)
	{
		port_out = 63 + 32 - port_in;
	}
	else if (port_in>=64 && port_in<96)
	{
		port_out = 95 + 64 - port_in;
	}
	else
	{
		UC_LOG_ERR("Not support more than 96 ports.");
		return port_out;
	}
	return port_out;
}

void endianness_adjust(uint32_t *bitmaptb, int len)
{
	int i;

	for (i=0; i<len; i++)
	{
		u_char *tmp_arr = (u_char*)&bitmaptb[i];
		u_char tmp_val;

		tmp_val = tmp_arr[0];
		tmp_arr[0] = tmp_arr[3];
		tmp_arr[3] = tmp_val;

		tmp_val = tmp_arr[1];
		tmp_arr[1] = tmp_arr[2];
		tmp_arr[2] = tmp_val;
	}
}

int plat_init(void)
{
	u_char oidstr[MAX_OID_LEN];

#if 0
	/* check if endianess adjustment is needed. */
	BITMAP_DECLARE(endian_test, 32);
	BITMAP_CLEAR(endian_test, 32);
	BITMAP_SET_BIT(endian_test, 0);
	if (((u_char*)endian_test)[0] & 1)
		printf("ucentral-client: need to adjust endianness");
#endif

	if (STATUS_SUCCESS != dev_get_poe_port_num(&poe_port_num))
	{
		print_err("ucentral-client: get poe port number error!");
		return 1;
	}

	/* default enable SNTP */
	strncpy(oidstr, O_NTP_STATUS, MAX_OID_LEN-1);
	if (0 != snmph_set(oidstr, 'i', "2"))
	{
		print_err("ucentral-client: set NTP error!");
		return 1;
	}
	strncpy(oidstr, O_SNTP_STATUS, MAX_OID_LEN-1);
	if (0 != snmph_set(oidstr, 'i', "1"))
	{
		print_err("ucentral-client: set SNTP error!");
		return 1;
	}
	strncpy(oidstr, O_SNTP_INTERVAL, MAX_OID_LEN-1);
	if (0 != snmph_set(oidstr, 'i', "10800"))
	{
		print_err("ucentral-client: set SNTP Poll Interval error!");
		return 1;
	}
	OID_JOIN(oidstr, O_SNTP_SERVER_TYPE, 1);
#ifdef NOT_SUPPORT_NTP_DOMAIN_NAME
	if (0 != snmph_set(oidstr, 'i', "1"))
#else
	if (0 != snmph_set(oidstr, 'i', "16"))
#endif
	{
		print_err("ucentral-client: set SNTP server type error!");
		return 1;
	}
	OID_JOIN(oidstr, O_SNTP_SERVER_ADDR, 1);
#ifdef NOT_SUPPORT_NTP_DOMAIN_NAME
	if (0 != snmph_set(oidstr, 's', "\x8c\x70\x02\xbd"))  // ntp.ntu.edu.tw
#else
	if (0 != snmph_set(oidstr, 's', "tock.stdtime.gov.tw"))
#endif
	{
		print_err("ucentral-client: set SNTP server address error!");
		return 1;
	}
	OID_JOIN(oidstr, O_SNTP_SERVER_TYPE, 2);
#ifdef NOT_SUPPORT_NTP_DOMAIN_NAME
	if (0 != snmph_set(oidstr, 'i', "1"))
#else
	if (0 != snmph_set(oidstr, 'i', "16"))
#endif
	{
		print_err("ucentral-client: set SNTP server type error!");
		return 1;
	}
	OID_JOIN(oidstr, O_SNTP_SERVER_ADDR, 2);
#ifdef NOT_SUPPORT_NTP_DOMAIN_NAME	
	if (0 != snmph_set(oidstr, 's', "\x83\xbc\x03\xdc"))  // ntp0.fau.de
#else
	if (0 != snmph_set(oidstr, 's', "watch.stdtime.gov.tw"))
#endif
	{
		print_err("ucentral-client: set SNTP server address error!");
		return 1;
	}
	OID_JOIN(oidstr, O_SNTP_SERVER_TYPE, 3);
#ifdef NOT_SUPPORT_NTP_DOMAIN_NAME
	if (0 != snmph_set(oidstr, 'i', "1"))
#else
	if (0 != snmph_set(oidstr, 'i', "16"))
#endif
	{
		print_err("ucentral-client: set SNTP server type error!");
		return 1;
	}
	OID_JOIN(oidstr, O_SNTP_SERVER_ADDR, 3);
#ifdef NOT_SUPPORT_NTP_DOMAIN_NAME
	if (0 != snmph_set(oidstr, 's', "\xc1\x4f\xed\x0e"))  // ntp1.nl.net
#else
	if (0 != snmph_set(oidstr, 's', "time.stdtime.gov.tw"))
#endif
	{
		print_err("ucentral-client: set SNTP server address error!");
		return 1;
	}

	return 0;
}

int plat_info_get(struct plat_platform_info *info)
{
	struct snmp_pdu *response = NULL;
	int status, i, len;
	char buf[PLATFORM_INFO_STR_MAX_LEN], company[PLATFORM_INFO_STR_MAX_LEN], *p;
	
	status = snmph_get_argstr(O_DEVICE_MODEL, &response);
	if (status != STATUS_SUCCESS) return status;

	if(response->variables->val_len < PLATFORM_INFO_STR_MAX_LEN)
		len = response->variables->val_len;
	else
		len = PLATFORM_INFO_STR_MAX_LEN-1;
	strncpy(info->platform, response->variables->val.string, len);
	snmp_free_pdu(response);
	memset(buf, 0, PLATFORM_INFO_STR_MAX_LEN);
	strncpy(buf, info->platform, PLATFORM_INFO_STR_MAX_LEN-1);
	p = strstr(buf, "-");
	if(p)
		p[0]='\0';
	for(i=0 ; i<sizeof(buf) ; i++)
		buf[i] = tolower(buf[i]);

	status = snmph_get_argstr(O_DEVICE_COMPANY, &response);
	if (status != STATUS_SUCCESS) return status;
	memset(company, 0, PLATFORM_INFO_STR_MAX_LEN);
	if(response->variables->val_len < PLATFORM_INFO_STR_MAX_LEN)
		len = response->variables->val_len;
	else
		len = PLATFORM_INFO_STR_MAX_LEN-1;
	strncpy(company, (char*)response->variables->val.string, len);
	snprintf(info->hwsku, sizeof(info->hwsku), "%s_%s", company, buf);
	snmp_free_pdu(response);

	return STATUS_SUCCESS;
}

/* Platform independent mid-layer OS related functions definitions */
int plat_reboot(void)
{
	system("(sleep 10; reboot)&");
	return 0;
}

int plat_config_apply(struct plat_cfg *cfg, uint32_t id)
{
#ifdef ENDIANNESS_ADJUST
	const u_char speed_bits_10_half[] = { 7 };
	const u_char speed_bits_10_full[] = { 7, 6 };
	const u_char speed_bits_100_half[] = { 7, 5 };
	const u_char speed_bits_100_full[] = { 7, 6, 5, 4 };
	const u_char speed_bits_1000_full[] = { 7, 6, 5, 4, 2 };
	const u_char speed_bits_2500_full[] = { 7, 6, 5, 4, 2, 23 };
	const u_char speed_bits_10000_full[] = { 0 };
#else
	const u_char speed_bits_10_half[] = { 31 };
	const u_char speed_bits_10_full[] = { 31, 30 };
	const u_char speed_bits_100_half[] = { 31, 29 };
	const u_char speed_bits_100_full[] = { 31, 30, 29, 28 };
	const u_char speed_bits_1000_full[] = { 31, 30, 29, 28, 26 };
	const u_char speed_bits_2500_full[] = { 31, 30, 29, 28, 26, 15 };
	const u_char speed_bits_10000_full[] = { 24 };
#endif

	int i, j, k;
	int port_cnt;
	int val_len = 0;
	int capabilities_bits_num = 0;
	u_char oidstr[MAX_OID_LEN], str[16];

	if (STATUS_SUCCESS != dev_get_port_capabilities_val_len(&val_len))
	{
		print_err("ucentral-client: get port capabilities value length error! \n", j);
		return 1;
	}

	capabilities_bits_num = val_len * BITS_PER_BYTE;
	BITMAP_DECLARE(capabilities, capabilities_bits_num);
  
	if (STATUS_SUCCESS != get_ethernet_count(&port_cnt))
	{
		print_err("ucentral-client: get port number error!\n", j);
		return 1;
	}

	for (i=0,j=1; i < port_cnt; i++,j++) {
		const char *speed_array;
		int arr_size = 0;

		/* reset vlan settings */
		/* set all ports PVIDs to DefaultVlan */
		OID_JOIN(oidstr, O_STR_PVID, j);
		if (0 != snmph_set(oidstr, 'u', "1"))
		{
			print_err("ucentral-client: set DefaultVlan as PVID on port %d error!\n", j);
			return 1;
		}

		/* if port is unset, no need to configure */
		if ((cfg->ports[i].speed == UCENTRAL_PORT_SPEED_NONE) &&
			(cfg->ports[i].duplex == UCENTRAL_PORT_DUPLEX_NONE))
			continue;

		/* apply port configure */
		OID_JOIN(oidstr, O_STR_IF_ADMIN_STATUS, j);
		if (0 != snmph_set(oidstr, 'i', cfg->ports[i].state == UCENTRAL_PORT_DISABLED_E ? "2" : "1"))
		{
			print_err("ucentral-client: shutdown/no-shutdown error on port %d error!\n", j);
			return 1;
		}
		
		BITMAP_CLEAR(capabilities, capabilities_bits_num);

		if (cfg->ports[i].duplex == UCENTRAL_PORT_DUPLEX_HALF_E)
		{
			switch(cfg->ports[i].speed) {
				case UCENTRAL_PORT_SPEED_10_E:
					speed_array = speed_bits_10_half;
					arr_size = sizeof(speed_bits_10_half);
					break;

				case UCENTRAL_PORT_SPEED_100_E:
					speed_array = speed_bits_100_half;
					arr_size = sizeof(speed_bits_100_half);
					break;

				case UCENTRAL_PORT_SPEED_1000_E:
				case UCENTRAL_PORT_SPEED_2500_E:
					print_err("ucentral-client: Not support capabilities 1000/2500 half on port %d!\n", j);
					return 1;

				case UCENTRAL_PORT_SPEED_10000_E:
					print_err("ucentral-client: Not support capabilities 10000 half on port %d!\n", j);
					return 1;

				default:
					break;
			}
		}
		else
		{
			switch (cfg->ports[i].speed) {
				case UCENTRAL_PORT_SPEED_10_E:
					speed_array = speed_bits_10_full;
					arr_size = sizeof(speed_bits_10_full);
					break;

				case UCENTRAL_PORT_SPEED_100_E:
					speed_array = speed_bits_100_full;
					arr_size = sizeof(speed_bits_100_full);
					break;

				case UCENTRAL_PORT_SPEED_1000_E:
					speed_array = speed_bits_1000_full;
					arr_size = sizeof(speed_bits_1000_full);
					break;

				case UCENTRAL_PORT_SPEED_2500_E:
#ifdef NOT_SUPPORT_CAP_2500					
					print_err("ucentral-client: Not support capabilities 2500 on port %d!\n", j);
#else
					speed_array = speed_bits_2500_full;
					arr_size = sizeof(speed_bits_2500_full);
#endif
					break;

				case UCENTRAL_PORT_SPEED_10000_E:	
					if ( j > poe_port_num)
					{
						speed_array = speed_bits_10000_full;
						arr_size = sizeof(speed_bits_10000_full);
					}
					else
					{
						print_err("ucentral-client: Not support capabilities 10000 full on port %d!\n", j);
						return 1;
					}
				default:
					break;
			}
		}

		for (k=0; k<arr_size; k++)
			BITMAP_SET_BIT(capabilities, speed_array[k]);

		if (arr_size)
		{
			OID_JOIN(oidstr, O_STR_PORT_CPAPBILITIES, j);
			if (0 != snmph_set_array(oidstr, 0x4, (u_char*)capabilities, capabilities_bits_num/8))
			{	
				print_err("ucentral-client: set port %d capabilities error!\n", j);
				return 1;
			}
		}

		/* apply poe configure */
		if (i < poe_port_num)
		{
			/* admin_mode: false -> is_admin_mode_up = 0 */
			/* admin_mode: true -> is_admin_mode_up = 1 */
			OID_JOIN(oidstr, O_STR_POE_PORT_ENABLE, j);
			if (0 != snmph_set(oidstr, 'i', cfg->ports[i].poe.is_admin_mode_up == 0 ? "2" : "1"))
			{	
				print_err("ucentral-client: set poe admin-mode error on port %d!\n", j);
				return 1;
			}
			
			OID_JOIN(oidstr, O_STR_POE_MAX_POWER, j);
			snprintf(str, sizeof(str), "%d", cfg->ports[i].poe.power_limit);
			if (0 != snmph_set(oidstr, 'i', str))
			{	
				print_err("ucentral-client: set poe max power error on port %d!\n", j);
				return 1;
			}
		}
	}
	
	/* apply poe usage threshold */ 
	snprintf(str, sizeof(str), "%d", cfg->unit.poe.usage_threshold);
	if (0 != snmph_set(O_STR_POE_USAGE_THRESHOLD, 'i', str))
	{	
		print_err("ucentral-client: set poe usage threshold error!\n");
		return 1;
	}

	int vlan_list[MAX_VLANS];
	int vlan_list_cnt = 0;
	int vlan_mask_cnt = 0;

	memset(vlan_list, 0, MAX_VLANS);
	if (0 != dev_get_vlan_list(vlan_list, &vlan_list_cnt))
	{	
		print_err("ucentral-client: get vlan list error!\n");
		return 1;
	}

	dev_get_vlan_mask_len(&vlan_mask_cnt);
	BITMAP_DECLARE(snmp_port_list_blank, vlan_mask_cnt*BITS_PER_BYTE);
	BITMAP_CLEAR(snmp_port_list_blank, vlan_mask_cnt*BITS_PER_BYTE);

	/* Remove port associations from all VLANs except the DefaultVlan */
	for (i=0; i<vlan_list_cnt; i++)
	{
		if (vlan_list[i] != 1)
		{
			OID_JOIN(oidstr, O_STR_VLAN_EGRESS, vlan_list[i]);
			if (0 != snmph_set_array(oidstr, 0x4, (u_char*)snmp_port_list_blank, vlan_mask_cnt))
			{	
				print_err("ucentral-client: remove all ports egress associations from vlan %d error!\n", vlan_list[i]);
				return 1;
			}

			OID_JOIN(oidstr, O_STR_VLAN_UNTAGGED, vlan_list[i]);
			if (0 != snmph_set_array(oidstr, 0x4, (u_char*)snmp_port_list_blank, vlan_mask_cnt))
			{
				print_err("ucentral-client: remove all ports untagged associations from vlan %d error!\n", vlan_list[i]);
				return 1;
			}

		}
	}

	BITMAP_DECLARE(snmp_port_list, vlan_mask_cnt*BITS_PER_BYTE);
	BITMAP_CLEAR(snmp_port_list, vlan_mask_cnt*BITS_PER_BYTE);

	for (i=0; i<port_cnt; i++)
	{
		if (i <= 31)
		{	
			BITMAP_SET_BIT(snmp_port_list, 31-i);
		}
		else if (i>=32 && i<64)
		{
			BITMAP_SET_BIT(snmp_port_list, 63+32-i);
		}
		else if (i>=64 && i<96)
		{
			BITMAP_SET_BIT(snmp_port_list, 95+64-i);
		}
		else
		{
			UC_LOG_ERR("Not support more than 96 ports.");
			return -1;
		}
	}
	
#ifdef ENDIANNESS_ADJUST
	endianness_adjust(snmp_port_list, BITS_TO_UINT32(vlan_mask_cnt*BITS_PER_BYTE));
#endif
	/* Set all ports as untagged members of the DefaultVlan */
	OID_JOIN(oidstr, O_STR_VLAN_EGRESS, FIRST_VLAN);
	if (0 != snmph_set_array(oidstr, 0x4, (u_char*)snmp_port_list, vlan_mask_cnt))
	{
		print_err("ucentral-client: set all ports as DefaulVlan egress members error!\n");
		return 1;
	}

	OID_JOIN(oidstr, O_STR_VLAN_UNTAGGED, FIRST_VLAN);
	if (0 != snmph_set_array(oidstr, 0x4, (u_char*)snmp_port_list, vlan_mask_cnt))
	{	
		print_err("ucentral-client: set all ports as DefaultVlan untagged members error!\n");
		return 1;
	}

	/* destroy all vlans except DefaultVlan */
	for (i=0; i<vlan_list_cnt ; i++)
	{
		if (vlan_list[i] != FIRST_VLAN)
		{
			OID_JOIN(oidstr, O_STR_VLAN_STATUS, vlan_list[i]);
			if (0 != snmph_set(oidstr, 'i', "6"))  // destroy
			{
				print_err("ucentral-client: destroy vlan %d error!\n", vlan_list[i]);
				return 1;
			}
		}
	}

	/* apply vlan config */
	BITMAP_DECLARE(snmp_port_list_egress, vlan_mask_cnt*BITS_PER_BYTE);	
	BITMAP_DECLARE(snmp_port_list_untagged, vlan_mask_cnt*BITS_PER_BYTE);	
	i=FIRST_VLAN;
	BITMAP_FOR_EACH_BIT_SET(i ,cfg->vlans_to_cfg, MAX_VLANS)
	{
		BITMAP_CLEAR(snmp_port_list_egress, vlan_mask_cnt*BITS_PER_BYTE);
		BITMAP_CLEAR(snmp_port_list_untagged, vlan_mask_cnt*BITS_PER_BYTE);

		if (i!=FIRST_VLAN)
		{
			OID_JOIN(oidstr, O_STR_VLAN_STATUS, i);
			if (0 != snmph_set(oidstr, 'i', "4"))  // createAndGo(4)
			{
				print_err("ucentral-client: create vlan %d error!\n", i);
				return 1;
			}
		}

		OID_JOIN(oidstr, O_STR_VLAN_NAME, i);
		if (0 != snmph_set_array(oidstr, 0x4, (u_char*)cfg->vlans[i].name, strlen(cfg->vlans[i].name)))
		{
			print_err("ucentral-client: set vlan %d name error!\n", i);
			return 1;
		}

		struct plat_vlan_memberlist *memberlist = cfg->vlans[i].members_list_head;
		for (;memberlist; memberlist=memberlist->next)
		{
			BITMAP_SET_BIT(snmp_port_list_egress, port_bitmap_adjust(memberlist->port.fp_id));

			if (memberlist->tagged ? 0:1)
				BITMAP_SET_BIT(snmp_port_list_untagged, port_bitmap_adjust(memberlist->port.fp_id));
		}

#ifdef ENDIANNESS_ADJUST
		endianness_adjust(snmp_port_list_egress, BITS_TO_UINT32(vlan_mask_cnt*BITS_PER_BYTE));
		endianness_adjust(snmp_port_list_untagged, BITS_TO_UINT32(vlan_mask_cnt*BITS_PER_BYTE));
#endif

		OID_JOIN(oidstr, O_STR_VLAN_EGRESS, i);
		if (0 != snmph_set_array(oidstr, 0x4, (u_char*)snmp_port_list_egress, vlan_mask_cnt))
		{
			print_err("ucentral-client: set vlan %d egress members error!\n", i);
			return 1;
		}

		OID_JOIN(oidstr, O_STR_VLAN_UNTAGGED, i);
		if (0 != snmph_set_array(oidstr, 0x4, (u_char*)snmp_port_list_untagged, vlan_mask_cnt))
		{
			print_err("ucentral-client: set vlan %d untagged members error!\n", i);
			return 1;
		}
		
		memberlist = cfg->vlans[i].members_list_head;
		for (;memberlist; memberlist=memberlist->next)
		{
			if (memberlist->pvid)
			{
				OID_JOIN(oidstr, O_STR_PVID, memberlist->port.fp_id + 1);
				snprintf(str, sizeof(str), "%d", i);
				if (0 != snmph_set(oidstr, 'u', str))
				{
					print_err("ucentral-client: set pvid error on port %d!\n", memberlist->port.fp_id + 1);
					return 1;
				}
			}
		}
	}

	return 0;
}

int plat_config_save(uint64_t id)
{
	/* save running_config to ucentral.cfg */
	snmph_set(O_STR_COPY_SRC_TYPE, 'i', "2");  // runningCfg(2)
	snmph_set(O_STR_COPY_DST_TYPE, 'i', "3");  // startupCfg(3)
	snmph_set_array(O_STR_COPY_DST_NAME, 0x4, (u_char*)CFG_NAME, strlen(CFG_NAME));
	snmph_set(O_STR_COPY_FILE_TYPE, 'i', "2");  // config(2)
	snmph_set(O_STR_COPY_ACTION, 'i', "2");  // copy(2)
	
	return 0;
}

int plat_config_restore(void)
{
	return 0;
}

int plat_saved_config_id_get(uint64_t *id)
{
	/*
	 * The config_id is not saved currently, so return 1.
	 */
	return 1;
}

void plat_config_destroy(struct plat_cfg *cfg)
{
	UNUSED_PARAM(cfg);
}

int plat_factory_default(bool keep_redirector)
{
	int status;

	status = snmph_set(O_FACTORY_DEFAULT, 'i', "1");
	if(status == 0){
		if(!keep_redirector)
			system("rm -f " REDIRECTOR_FILE);
		system("(sleep 10; reboot)&");
 	}
	
	return status;
}

int plat_rtty(struct plat_rtty_cfg *rtty_cfg)
{
	UNUSED_PARAM(rtty_cfg);
	return 0;
}

int plat_upgrade(char *uri, char *signature)
{
	char file_path[MAX_FILE_PATH_SIZE], cmd[MAX_CMD_SIZE], *p, *q=NULL;
	int ret;

	p=uri;
	while((p=strstr(p, "/")) != NULL){
		q=p;
		p=p+1;
	}
	if(!q){
		return -1;
	}
	snprintf(file_path, MAX_FILE_PATH_SIZE, "/tmp/%s", q+1);
	snprintf(cmd, MAX_CMD_SIZE, "/usr/sbin/curl -k --connect-timeout 60 -o %s %s", file_path, uri);
	system(cmd);
	ret = snmph_set(O_FW_UPGRADE_MGMT, 'i', "1");
	if(ret == 1)
		ret = STATUS_SUCCESS;

	return ret;
}

char *plat_log_pop(void)
{
	return NULL;
}

void plat_log_flush(void)
{
}

char *plat_log_pop_concatenate(void)
{
	return NULL;
}


int plat_alarm_subscribe(plat_alarm_cb cb)
{
	UNUSED_PARAM(cb);
	return 0;
}

void plat_alarm_unsubscribe(void)
{
}

int plat_linkstatus_subscribe(plat_linkstatus_cb cb)
{
	UNUSED_PARAM(cb);
	return 0;
}

void plat_linkstatus_unsubscribe(void)
{
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

void plat_upgrade_poll(int (*cb)(struct plat_upgrade_info *), int period_sec)
{
	UNUSED_PARAM(period_sec);
	UNUSED_PARAM(cb);
}

void plat_upgrade_poll_stop(void)
{
}

int plat_port_list_get(uint16_t list_size, struct plat_ports_list *ports)
{
	int i=0;
	char buff[128];
	struct plat_ports_list *port_node;

/* if user don't configure ethernet port name, we can't get corresponding snmp information .
   Then it can't generate appropriate port list, it will cause segFault, so hardcode here.
   Start from Ethernet0, Ethernet1 ... and so on
*/
	UCENTRAL_LIST_FOR_EACH_MEMBER(port_node, &ports)
	{
		snprintf(buff, sizeof(buff), "Ethernet%d", i++);
		strcpy(port_node->name, buff);
	}

	return 0;
}

int plat_port_num_get(uint16_t *num_of_active_ports)
{
	int port_cnt;

	get_ethernet_count(&port_cnt);
	*num_of_active_ports = port_cnt;
	return 0;
}

int plat_running_img_name_get(char *str, size_t str_max_len)
{
	char fw[16];

	int status = dev_get_fw_version(fw, sizeof(fw));
	strncpy(str, fw, sizeof(fw));
	return 0;
}

int plat_event_subscribe(const struct plat_event_callbacks *cbs)
{
	
	return 0;
}

void plat_event_unsubscribe(void)
{

}

int
plat_reboot_cause_get(struct plat_reboot_cause *cause)
{
	UNUSED_PARAM(cause);
	return 0;
}

int plat_metrics_restore(struct plat_metrics_cfg *cfg)
{
	UNUSED_PARAM(cfg);
	return 0;
}

int plat_metrics_save(const struct plat_metrics_cfg *cfg)
{
	UNUSED_PARAM(cfg);
	return 0;
}

int plat_run_script(struct plat_run_script *p)
{
	UNUSED_PARAM(p);
	return 0;
}

int plat_diagnostic(char *res_path)
{
	UNUSED_PARAM(res_path);
	return 0;
}

