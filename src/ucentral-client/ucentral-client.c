/* SPDX-License-Identifier: BSD-3-Clause */

#define _GNU_SOURCE /* asprintf */

#define UC_LOG_COMPONENT UC_LOG_COMPONENT_CLIENT

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <curl/curl.h>

#include <cjson/cJSON.h>

#include "ucentral.h"
#include "ucentral-json-parser.h"

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#ifdef PLAT_EC
#include "api_device.h"
#include "api_session.h"
#endif

struct per_vhost_data__minimal {
	struct lws_context *context;
	struct lws_vhost *vhost;
	const struct lws_protocols *protocol;

	lws_sorted_usec_list_t sul;
	struct lws_client_connect_info i;
	struct lws *client_wsi;
};

static struct lws_context *context;

static struct lws *websocket = NULL;
time_t conn_time;

static int conn_successfull;

struct plat_metrics_cfg ucentral_metrics;
static struct uc_json_parser parser;

static int interrupted;
static pthread_t sigthread;
static pthread_mutex_t sigthread_mtx = PTHREAD_MUTEX_INITIALIZER;
static struct lws_context *sigthread_context;

static int
callback_broker(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len);

static const struct
lws_protocols protocols[] = {
	{ "ucentral-broker", callback_broker, 0, 4096 * 1024, 0, NULL, 0},
	{ }
};

struct client_config client = {
#ifdef PLAT_EC
	.redirector_file = "/etc/ucentral/redirector.json",
	.redirector_file_dbg = "/etc/ucentral/firstcontact.hdr",
#else
	.redirector_file = "/tmp/ucentral-redirector.json",
	.redirector_file_dbg = "/tmp/firstcontact.hdr",
#endif
	.server = NULL,
	.port = 15002,
	.path = "/",
	.serial = NULL,
	.CN = {0},
	.firmware = {0},
	.devid = {0},
};

static const char file_cert[] = UCENTRAL_CONFIG "cert.pem";
static const char file_key[] = UCENTRAL_CONFIG "key.pem";

static struct txq {
	struct txq *next;
	size_t len;
	unsigned char data[];
} * txqtail, *txqhead, *txconnect; /* TODO make it ringbuf? */
static pthread_mutex_t txqmtx = PTHREAD_MUTEX_INITIALIZER;

static void txq_free(struct txq *txq)
{
	while (txq) {
		struct txq *n = txq;
		txq = txq->next;
		free(n);
	}
}

static void txq_enqueue(struct txq **msg)
{
	pthread_mutex_lock(&txqmtx);
	if (txqtail) {
		txqtail->next = *msg;
		txqtail = *msg;
	} else {
		txqhead = *msg;
		txqtail = *msg;
	}
	pthread_mutex_unlock(&txqmtx);
	*msg = 0;
}

static struct txq *txq_pull(void)
{
	struct txq *head;

	pthread_mutex_lock(&txqmtx);
	head = txqhead;
	txqhead = 0;
	txqtail = 0;
	pthread_mutex_unlock(&txqmtx);

	return head;
}

static struct txq *txq_connect_pull(void)
{
	struct txq *msg;
	pthread_mutex_lock(&txqmtx);
	msg = txconnect;
	txconnect = 0;
	pthread_mutex_unlock(&txqmtx);
	return msg;
}

static void txq_msg_proto_cb(const char *data, size_t len)
{
	struct txq *msg;
	msg = calloc(1, sizeof *msg + LWS_PRE + len + 1);
	if (!msg) {
		UC_LOG_ERR("malloc failed");
		return;
	}
	msg->next = 0;
	msg->len = LWS_PRE + len;
	memcpy(&msg->data[LWS_PRE], data, len);
	txq_enqueue(&msg);
	if (context)
		lws_cancel_service(context);
}

static void txq_connect_msg_proto_cb(const char *data, size_t len)
{
	struct txq *msg;
	msg = calloc(1, sizeof *msg + LWS_PRE + len + 1);
	if (!msg) {
		UC_LOG_ERR("malloc failed");
		return;
	}
	msg->next = 0;
	msg->len = LWS_PRE + len;
	memcpy(&msg->data[LWS_PRE], data, len);
	pthread_mutex_lock(&txqmtx);
	free(txconnect);
	txconnect = msg;
	pthread_mutex_unlock(&txqmtx);
	if (context)
		lws_cancel_service(context);
}

int ssl_cert_get_common_name(char *cn, size_t size, const char *cert_path)
{
	FILE *fp = fopen(cert_path, "rb");

	OPENSSL_no_config();

	if (!fp)
	{
		UC_LOG_ERR("Failed to open file: %s\n", strerror(errno));
		return errno;
	}
	X509* cert = PEM_read_X509_AUX(fp, NULL, NULL, NULL);
	if (!cert)
	{
		UC_LOG_ERR("Failed to read PEM cert\n");
		return -1;
	}

	X509_NAME_oneline(X509_get_subject_name(cert), cn, size);

	X509_free(cert);

	fclose(fp);
	CONF_modules_unload(1);
	CONF_modules_free();
	return 0;
}

static int
ucentral_redirector_parse(char **gw_host)
{
	size_t json_data_size = 0;
	cJSON *redirector = NULL;
	void *json_data = NULL;
	cJSON *server = NULL;
	struct stat statbuf;
	cJSON *field = NULL;
	cJSON *fields;
	int fd_json;
	int ret;

	fd_json = open(client.redirector_file, O_RDONLY);
	if (fd_json < 0) {
		UC_LOG_ERR("Failed to open '%s' for reading\n",
			   client.redirector_file);
		return fd_json;
	}

	ret = fstat(fd_json, &statbuf);
	if (ret < 0) {
		UC_LOG_ERR("Failed to get '%s' file size\n",
			   client.redirector_file);
		goto err;
	}

	json_data_size = statbuf.st_size;

	json_data = mmap(NULL, json_data_size, PROT_READ, MAP_SHARED,
			 fd_json, 0);
	if (json_data == MAP_FAILED) {
		UC_LOG_ERR("Failed to mmap '%s' file for reading\n",
			   client.redirector_file);
		ret = -EIO;
		goto err;
	}

	redirector = cJSON_ParseWithLength((const char *)json_data,
					   json_data_size);
	if (!redirector) {
		const char *error_ptr = cJSON_GetErrorPtr();

		if (error_ptr)
			UC_LOG_ERR("Redirector str parse failed (%s)\n",
				(const char *)json_data);

		ret = -EINVAL;
		goto err;
	}

	fields = cJSON_GetObjectItem(redirector, "fields");
	if (!cJSON_IsArray(fields)) {
		UC_LOG_ERR("Redirector parse failed: 'fields' array is not found\n");
		ret = -EINVAL;
		goto err;
	}

	cJSON_ArrayForEach(field, fields) {
		cJSON *name;

		name = cJSON_GetObjectItem(field, "name");
		if (!name || name->valuestring == NULL) {
			UC_LOG_ERR("Warning: Redirector parse err: found fields:name value, but it's empty\n");
			continue;
		}

		if (!strcmp("Redirector", name->valuestring)) {
			server = cJSON_GetObjectItem(field, "value");
			break;
		}
	}

	if (!cJSON_IsString(server) || server->valuestring == NULL) {
		UC_LOG_ERR("Redirector parse failed: 'server' key invalid\n");
		ret = -EINVAL;
		goto err;
	}

	*gw_host = strdup(server->valuestring);
	if (!*gw_host) {
		UC_LOG_ERR("Cannot alloc GW host string\n");

		ret = -ENOMEM;
		goto err;
	}

err:
	cJSON_Delete(redirector);

	if (json_data)
		munmap(json_data, json_data_size);

	if (fd_json)
		close(fd_json);

	return ret;
}

void
set_conn_time(void)
{
	struct timespec tp;

	clock_gettime(CLOCK_MONOTONIC, &tp);
	conn_time = tp.tv_sec;
}

static int
get_reconnect_timeout(void)
{
	int ret = 5;
	UC_LOG_INFO("next reconnect in %ds\n", ret);
	return ret * LWS_US_PER_SEC;
}

static void
sul_connect_attempt(struct lws_sorted_usec_list *sul)
{
	struct per_vhost_data__minimal *vhd;

	vhd = lws_container_of(sul, struct per_vhost_data__minimal, sul);

	vhd->i.context = vhd->context;
	vhd->i.port = client.port;
	vhd->i.address = client.server;
	vhd->i.path = client.path;
	vhd->i.host = vhd->i.address;
	vhd->i.origin = vhd->i.address;
	vhd->i.ssl_connection = LCCSCF_USE_SSL | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;

	vhd->i.protocol = "ucentral-broker";
	vhd->i.pwsi = &vhd->client_wsi;

	UC_LOG_INFO("trying to connect '%s':'%u'\n", client.server, client.port);
	if (!lws_client_connect_via_info(&vhd->i)) {
		UC_LOG_INFO("connect failed\n");
		lws_sul_schedule(vhd->context, 0, &vhd->sul,
				 sul_connect_attempt, get_reconnect_timeout());
	}

	UC_LOG_DBG("Connected\n");
}

static void parse_cb(cJSON *j, void *data)
{
	(void)data;
	proto_handle(j);
}

static void parse_error_cb(void *data)
{
	(void)data;
	UC_LOG_ERR("JSON config parse failed");
}

static const char *redirector_host_get(void)
{
	static char url[512];
	char *v = getenv("UC_REDIRECTOR_URL");
	if (v) {
		snprintf(url, sizeof url, "%s", v);
		return url;
	}
#ifndef UCENTRAL_CLIENT_REDIRECTOR_HOST
	return "https://clientauth.one.digicert.com/iot/api/v2/device";
#else
	return UCENTRAL_CLIENT_REDIRECTOR_HOST;
#endif
}

static int gateway_cert_trust(void)
{
	char *v = getenv("UC_GATEWAY_CERT_TRUST");
	return v && *v && strcmp("0", v);
}

static int redirector_cert_trust(void)
{
#ifdef PLAT_EC
  return 1;
#else
	char *v = getenv("UC_REDIRECTOR_CERT_TRUST");
	return v && *v && strcmp("0", v);
#endif
}

static int
callback_broker(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	struct txq *txq = 0, *txq_connect = 0;
	struct per_vhost_data__minimal *vhd =
			(struct per_vhost_data__minimal *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
						 lws_get_protocol(wsi));
	int r = 0;

	switch (reason) {
	case LWS_CALLBACK_OPENSSL_PERFORM_SERVER_CERT_VERIFICATION:
		if (gateway_cert_trust()) {
			X509_STORE_CTX_set_error((X509_STORE_CTX *)user,
						 X509_V_OK);
		}
		break;
	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = (struct per_vhost_data__minimal *)
			lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
						    lws_get_protocol(wsi),
						    sizeof(struct per_vhost_data__minimal));
		vhd->context = lws_get_context(wsi);
		vhd->protocol = lws_get_protocol(wsi);
		vhd->vhost = lws_get_vhost(wsi);

		sul_connect_attempt(&vhd->sul);
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		lws_sul_cancel(&vhd->sul);
		return r;

	case LWS_CALLBACK_ADD_POLL_FD:
	case LWS_CALLBACK_CHANGE_MODE_POLL_FD:
		return 0;

	case LWS_CALLBACK_DEL_POLL_FD:
		return 0;

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		set_conn_time();
		websocket = wsi;
		connect_send();
		conn_successfull = 1;
		uc_json_parser_init(&parser, parse_cb, parse_error_cb, 0);
		lws_callback_on_writable(websocket);
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:
		uc_json_parser_feed(&parser, in, len);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		UC_LOG_ERR("connection error: %s\n",
			   in ? (char *)in : "(null)");
		conn_successfull = 0;

#ifdef __clang_analyzer__
		__attribute__ ((fallthrough));
#endif
	/* fall through */
	case LWS_CALLBACK_CLIENT_CLOSED:
		UC_LOG_INFO("connection closed\n");
		uc_json_parser_uninit(&parser);
		websocket = NULL;
		set_conn_time();
		vhd->client_wsi = NULL;
		lws_sul_schedule(vhd->context, 0, &vhd->sul,
				 sul_connect_attempt, get_reconnect_timeout());
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:
		txq = txq_pull();
		txq_connect = txq_connect_pull();
		if (txq_connect) {
			txq_connect->next = txq;
			txq = txq_connect;
		}
		while (txq) {
			struct txq *m = txq;
			txq = txq->next;
			int plen = (m->len - LWS_PRE < (size_t)INT_MAX) ?
						 (m->len - LWS_PRE) :
						 INT_MAX;

			UC_LOG_DBG("TX:\n'%*s'\n", plen, &m->data[LWS_PRE]);
			if (!websocket) {
				UC_LOG_DBG(
					"attempt to write to a closed socket");
			} else if (lws_write(websocket, &m->data[LWS_PRE],
					     m->len - LWS_PRE,
					     LWS_WRITE_TEXT) < 0) {
				UC_LOG_ERR("failed to send message\n");
			}

			free(m);
		}
		break;

	case LWS_CALLBACK_EVENT_WAIT_CANCELLED:
		if (websocket) {
			lws_callback_on_writable(websocket);
		}
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static int client_config_read(void)
{
	long f_devid_size;
	FILE *f_devid;
	int i;
	const char *file_devid = UCENTRAL_CONFIG "dev-id";

	/* UGLY W/A for now: get MAC from cert's CN */
	if (ssl_cert_get_common_name(client.CN, 63, file_cert)) {
		UC_LOG_ERR("CN read from cert failed");
		return -1;
	}
	client.serial = &client.CN[10];

	/* Make sure MAC in CN is lowercase (either way redirector won't be
	 * happy)
	 */
	for (i = 10; i < 63; ++i)
		client.CN[i] = tolower(client.CN[i]);

	f_devid = fopen(file_devid, "rb");
	if (!f_devid) {
		UC_LOG_ERR("Failed to open devid ('%s') file (%d)", file_devid, errno);
		return -1;
	}

	fseek(f_devid, 0, SEEK_END);
	f_devid_size = ftell(f_devid);
	fseek(f_devid, 0, SEEK_SET);

	if (f_devid_size < UCENTRAL_DEVID_F_MAX_LEN) {
		UC_LOG_ERR("dev-id file suspiciously < than %u.. trying anyway",
			   UCENTRAL_DEVID_F_MAX_LEN);
	}
	else if (f_devid_size >= UCENTRAL_DEVID_F_MAX_LEN)
		f_devid_size = UCENTRAL_DEVID_F_MAX_LEN + 1;

	if (!fread(client.devid, f_devid_size, 1, f_devid)) {
		UC_LOG_ERR("Failed to read devid string to buf (%d)", errno);
		fclose(f_devid);
		return -1;
	}
	client.devid[f_devid_size - 1] = '\0';

	fclose(f_devid);
	return 0;
}

static int firstcontact(void)
{
	const char *redirector_host = redirector_host_get();
	FILE *fp_json;
	char url[256];
	FILE *fp_dbg;
	CURLcode res;
	CURL *curl;

	UC_LOG_INFO("Attempting Firstcontact (%s)\n", redirector_host);

	fp_dbg = fopen(client.redirector_file_dbg, "wb");
	fp_json = fopen(client.redirector_file, "wb");
	if (!fp_json) {
		UC_LOG_ERR("failed to create %s\n", client.redirector_file);
		return errno;
	}

	curl = curl_easy_init();
	if (!curl) {
		fclose(fp_dbg);
		fclose(fp_json);
		UC_LOG_ERR("curl_easy_init failed\n");
		return errno;
	}

	strcpy(url, redirector_host);
	strcat(url, "/");
	strcat(url, client.devid);

	UC_LOG_DBG("Trying redirector URL: '%s'\n", url);

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp_json);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, fp_dbg);
	curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
	curl_easy_setopt(curl, CURLOPT_SSLCERT, file_cert);
	curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PEM");
	curl_easy_setopt(curl, CURLOPT_SSLKEY, file_key);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,
			 (long)!redirector_cert_trust());
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST,
			 (long)!redirector_cert_trust());
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);

	res = curl_easy_perform(curl);
	if (res != CURLE_OK)
		UC_LOG_ERR("Firstcontact failed: curl_easy_perform() failed: %s\n",
			   curl_easy_strerror(res));
	else
		UC_LOG_INFO("Firstcontact success: downloaded first contact data\n");

	curl_easy_cleanup(curl);

	fclose(fp_dbg);
	fclose(fp_json);

	return res != CURLE_OK;
}

static int uc_loop_interrupted_set(int value)
{
	int ret;

	pthread_mutex_lock(&sigthread_mtx);
	ret = interrupted;
	interrupted = value;
	pthread_mutex_unlock(&sigthread_mtx);

	return ret;
}

static int uc_loop_interrupted_get(void)
{
	int ret;

	pthread_mutex_lock(&sigthread_mtx);
	ret = interrupted;
	pthread_mutex_unlock(&sigthread_mtx);

	return ret;
}

static void sigthread_context_set(struct lws_context *c)
{
	pthread_mutex_lock(&sigthread_mtx);
	sigthread_context = c;
	pthread_mutex_unlock(&sigthread_mtx);
}

static struct lws_context *sigthread_context_get(void)
{
	struct lws_context *c;
	pthread_mutex_lock(&sigthread_mtx);
	c = sigthread_context;
	pthread_mutex_unlock(&sigthread_mtx);
	return c;
}

static void init_sigset(sigset_t *set)
{
	sigemptyset(set);
	sigaddset(set, SIGQUIT);
}

static void *sigthread_cb(void *arg)
{
	int s;
	sigset_t set;
	struct lws_context *c;

	(void)arg;

	init_sigset(&set);
	UC_LOG_DBG("enter");

	if (!sigwait(&set, &s)) {
		UC_LOG_DBG("Got signal %d", s);
	}
	uc_loop_interrupted_set(1);
	c = sigthread_context_get();
	if (c)
		lws_cancel_service(c);

	UC_LOG_DBG("exiting");
	return 0;
}

static void sigthread_create(void)
{
	sigset_t set;

	init_sigset(&set);

	if (pthread_sigmask(SIG_BLOCK, &set, 0)) {
		UC_LOG_DBG("pthread_sigmask filed: %s", strerror(errno));
	}

	if (pthread_create(&sigthread, 0, sigthread_cb, 0)) {
		exit(EXIT_FAILURE);
	}
}

int main(void)
{
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_CLIENT;
	int syslogs = LOG_MASK(LOG_EMERG) | LOG_MASK(LOG_ALERT) |
		      LOG_MASK(LOG_CRIT) | LOG_MASK(LOG_ERR) |
		      LOG_MASK(LOG_WARNING) | LOG_MASK(LOG_NOTICE) |
		      LOG_MASK(LOG_INFO);
	struct lws_context_creation_info info = {0};
	bool reboot_reason_sent = false;
	char *gw_host = NULL;
	struct stat st;
	int ret;

#ifdef PLAT_EC
	sleep(50); // wait for system ready
#endif

	sigthread_create(); /* move signal handling to a dedicated thread */

	openlog("ucentral-client", LOG_CONS | LOG_NDELAY | LOG_PERROR, LOG_DAEMON);
	/* TODO for now always enable debug syslog */
	syslogs |= LOG_MASK(LOG_DEBUG);
	setlogmask(syslogs);

	curl_global_init(CURL_GLOBAL_DEFAULT);

	proto_cb_register_uc_send_msg(txq_msg_proto_cb);
	proto_cb_register_uc_connect_msg_send(txq_connect_msg_proto_cb);
	lws_set_log_level(logs, lwsl_emit_syslog);
	uc_log_send_cb_register(log_send);
	uc_log_severity_set(UC_LOG_COMPONENT_PROTO, UC_LOG_SV_ERR);
	uc_log_severity_set(UC_LOG_COMPONENT_CLIENT, UC_LOG_SV_ERR);
	uc_log_severity_set(UC_LOG_COMPONENT_PLAT, UC_LOG_SV_ERR);

#ifdef PLAT_EC
	int status = session_start();

	if (status == STATUS_SUCCESS) {
		UC_LOG_INFO("Successfully connected to SNMP!\n");
	} else {
		UC_LOG_INFO("Could not connect to SNMP!\n");
		exit(EXIT_FAILURE);;
	}
#endif
	
	if (client_config_read()) {
		UC_LOG_CRIT("client_config_read failed");
		exit(EXIT_FAILURE);
	}

	if (plat_init()) {
		UC_LOG_CRIT("Platform initialization failed");
	}

	plat_running_img_name_get(client.firmware, sizeof(client.firmware));

#ifdef PLAT_EC
	FILE *f = fopen(REDIRECTOR_USER_DEFINE_FILE, "r");

	if (f) {
		size_t cnt;
		char redirector_url[256];
		memset(redirector_url, 0, sizeof(redirector_url));

		cnt = fread(redirector_url, 1, sizeof(redirector_url), f);
		fclose(f);
		client.server = redirector_url;
	} else {
		ret = ucentral_redirector_parse(&gw_host);
		if (ret) {
		/* parse failed by present redirector file, try to get redirector file from digicert */
#else
	if ((gw_host = getenv("UC_GATEWAY_ADDRESS"))) {
		gw_host = strdup(gw_host);
	} else {
#endif
		while (1) {
			if (uc_loop_interrupted_get())
				goto exit;
			if (firstcontact()) {
				UC_LOG_INFO(
					"Firstcontact failed; trying again in 30 second...\n");
#ifdef PLAT_EC
				sleep(30);
#else
				sleep(1);
#endif
				continue;
			}

			break;
		}

		/* Workaround for now: if parse failed, use default one */
		ret = ucentral_redirector_parse(&gw_host);
		if (ret) {
			UC_LOG_ERR("Firstcontact json data parse failed: %d\n",
				   ret);
		} else {
			client.server = gw_host;
		}
#ifdef PLAT_EC
		} else {
			client.server = gw_host;
		}
#endif
	}

	memset(&info, 0, sizeof info);

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.client_ssl_cert_filepath = UCENTRAL_CONFIG"cert.pem";
	if (!stat(UCENTRAL_CONFIG"key.pem", &st))
		info.client_ssl_private_key_filepath = UCENTRAL_CONFIG"key.pem";
	info.ssl_ca_filepath = UCENTRAL_CONFIG"cas.pem";
	info.protocols = protocols;
	info.fd_limit_per_thread = 1 + 1 + 1;
        info.connect_timeout_secs = 30;

	set_conn_time();
	context = lws_create_context(&info);
	if (!context) {
		UC_LOG_INFO("failed to start LWS context\n");
		goto exit;
	}
	sigthread_context_set(context);

	proto_start();

	while (!uc_loop_interrupted_get()) {
		lws_service_tsi(context, 0, 0);

		if (conn_successfull) {
			deviceupdate_send();
			if (!reboot_reason_sent) {
				device_rebootcause_send();
				reboot_reason_sent = true;
			}
		}
	}

exit:
	proto_stop();
	txq_free(txq_pull());
	pthread_join(sigthread, 0);
	if (context)
		lws_context_destroy(context);

	free(gw_host);
	curl_global_cleanup();
#ifdef PLAT_EC
	session_close();
	clean_stats();
#endif
	return 0;
}
