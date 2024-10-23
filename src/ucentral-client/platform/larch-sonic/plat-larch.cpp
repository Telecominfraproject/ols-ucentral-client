#include <metrics.hpp>
#include <port.hpp>
#include <route.hpp>
#include <services.hpp>
#include <state.hpp>
#include <stp.hpp>
#include <syslog.hpp>
#include <utils.hpp>
#include <vlan.hpp>

#include <gnmi.grpc.pb.h>
#include <gnmi.pb.h>

#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>
#include <grpc/grpc.h>
#include <nlohmann/json.hpp>
#include <sw/redis++/redis++.h>

#define UC_LOG_COMPONENT UC_LOG_COMPONENT_PLAT
#include <ucentral-log.h>
#include <ucentral-platform.h>
#include <router-utils.h>

#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility> // std::move

#include <sys/types.h>
#include <sys/wait.h>

#define UNUSED_PARAM(param) (void)((param))

#define RTTY_SESS_MAX (10)

using nlohmann::json;

namespace {
const std::string config_id_path = "/var/lib/ucentral/saved_config_id";
}

int plat_init(void)
{
	using namespace larch;

	state = std::make_unique<platform_state>();

	auto verifier = grpc::experimental::ExternalCertificateVerifier::Create<certificate_verifier>();
	grpc::experimental::TlsChannelCredentialsOptions options;
	options.set_verify_server_certs(false);
	options.set_certificate_verifier(verifier);
	options.set_check_call_host(false);
	auto credentials = grpc::experimental::TlsCredentials(options);

	state->channel = grpc::CreateChannel("127.0.0.1:8080", credentials);
	state->gnmi_stub = gnmi::gNMI::NewStub(state->channel);

	// created new channel for gnoi
	state->system_gnoi_stub = gnoi::system::System::NewStub(grpc::CreateChannel("127.0.0.1:8080", credentials));
	state->stub_gnoi_sonic = gnoi::sonic::SonicService::NewStub(grpc::CreateChannel("127.0.0.1:8080", credentials));

	state->telemetry_periodic = std::make_unique<periodic>();
	state->state_periodic = std::make_unique<periodic>();
	state->health_periodic = std::make_unique<periodic>();

	state->redis_asic = std::make_unique<sw::redis::Redis>("tcp://127.0.0.1:6379/1");
	state->redis_counters = std::make_unique<sw::redis::Redis>("tcp://127.0.0.1:6379/2");

	/*
	 * Workaround to fix the issue when ucentral-client starts too early
	 * (before gNMI container or before ports are up)
	 */
	UC_LOG_INFO("Trying to get initial port list...");

	std::vector<port> ports;

	while (true)
	{
		try
		{
			ports = get_port_list();

			if (ports.empty())
			{
				UC_LOG_DBG("Port list is empty");
			}
			else
			{
				break;
			}
		}
		catch (const std::exception &ex)
		{
			UC_LOG_DBG(
			    "Failed to get initial port list: %s",
			    ex.what());
		}

		UC_LOG_DBG("Retrying in 10 seconds...");
		std::this_thread::sleep_for(std::chrono::seconds{10});
	}

	UC_LOG_INFO("Successfully got the port list, continuing platform "
		    "initialization");

	try
	{
		/*
		 * Get the state of interfaces addresses
		 */
		const plat_ipv4 no_address{false};

		for (port &p : get_port_list())
		{
			const auto addresses = get_port_addresses(p);

			state->interfaces_addrs.push_back(
			    addresses.empty() ? no_address : addresses[0]);
		}

		/*
		 * Initialize the router
		 */
		ucentral_router_fib_db_free(&state->router);

		auto routes = get_routes(0);

		if (ucentral_router_fib_db_alloc(&state->router, routes.size())
		    != 0)
		{
			UC_LOG_CRIT("Failed to allocate FIB DB");
			return -1;
		}

		for (auto &node : routes)
		{
			if (ucentral_router_fib_db_append(&state->router, &node)
			    != 0)
			{
				UC_LOG_CRIT("Failed to append entry to FIB DB");
				return -1;
			}
		}
	}
	catch (const std::exception &ex)
	{
		UC_LOG_CRIT("Platform initialization failed: %s", ex.what());
		return -1;
	}

	return 0;
}

int plat_info_get(struct plat_platform_info *info)
{
	using namespace larch;

	try
	{
		const json metadata_json =
		    json::parse(
			gnmi_get("/sonic-device_metadata:sonic-device_metadata/"
				 "DEVICE_METADATA/localhost"))
			.at("sonic-device_metadata:localhost");

		auto copy_from_json =
		    [](const json &obj, char *dest, std::size_t dest_size) {
			    std::strncpy(
				dest,
				obj.template get<std::string>().c_str(),
				dest_size > 0 ? dest_size - 1 : 0);
		    };

		copy_from_json(
		    metadata_json.at("platform"),
		    info->platform,
		    std::size(info->platform));

		copy_from_json(
		    metadata_json.at("hwsku"),
		    info->hwsku,
		    std::size(info->hwsku));

		copy_from_json(
		    metadata_json.at("mac"),
		    info->mac,
		    std::size(info->mac));
	}
	catch (const std::exception &ex)
	{
		UC_LOG_ERR("Failed to get device metadata: %s", ex.what());
		return -1;
	}

	return 0;
}

int plat_reboot(void)
{
	grpc::Status status;
	gnoi::system::RebootResponse gres;
	gnoi::system::RebootRequest greq;

	grpc::ClientContext context;
	status = (larch::state->system_gnoi_stub)->Reboot(&context, greq, &gres);

	if (!status.ok()) {
		UC_LOG_ERR("Request failed");
		UC_LOG_ERR("Code: %d", status.error_code());
		return 1;
	}
	return 0;
}

int plat_config_apply(struct plat_cfg *cfg, uint32_t id)
{
	using namespace larch;

	UNUSED_PARAM(id);

	try
	{
		apply_vlan_config(cfg);
		apply_port_config(cfg);
		apply_route_config(cfg);
		apply_stp_config(cfg);
		apply_services_config(cfg);
		apply_vlan_ipv4_config(cfg);
		/* apply_syslog_config() call must always be the last one */
		apply_syslog_config(cfg->log_cfg, cfg->log_cfg_cnt);
	}
	catch (const std::exception &ex)
	{
		UC_LOG_ERR("Failed to apply config: %s", ex.what());
		return -1;
	}

	return 0;
}

int plat_config_save(uint64_t id)
{
	// TO-DO: actually save the config, not only config id

	std::ofstream os{config_id_path};

	if (!os)
	{
		UC_LOG_ERR(
		    "Failed to save config id - can't open the file: %s",
		    std::strerror(errno));
		return -1;
	}

	os << id << std::endl;

	return 0;
}

int plat_config_restore(void)
{
	return 0;
}

int plat_metrics_save(const struct plat_metrics_cfg *cfg)
{
	try
	{
		larch::save_metrics_config(cfg);
	}
	catch (const std::exception &ex)
	{
		UC_LOG_ERR("Failed to save metrics config: %s", ex.what());
		return -1;
	}

	return 0;
}

int plat_metrics_restore(struct plat_metrics_cfg *cfg)
{
	try
	{
		larch::load_metrics_config(cfg);
	}
	catch (const std::exception &ex)
	{
		UC_LOG_ERR("Failed to load metrics config: %s", ex.what());
		return -1;
	}

	return 0;
}

int plat_saved_config_id_get(uint64_t *id)
{
	std::ifstream is{config_id_path};

	if (!is)
	{
		UC_LOG_ERR(
		    "Failed to get saved config id - can't open the file: %s",
		    std::strerror(errno));
		return -1;
	}

	is >> *id;

	if (!is.good())
	{
		UC_LOG_ERR("Failed to get saved config id - read failed");
		return -1;
	}

	return 0;
}

void plat_config_destroy(struct plat_cfg *cfg)
{
	UNUSED_PARAM(cfg);
}

int plat_factory_default(void)
{
	return 0;
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
		execl("/usr/local/bin/rtty", "rtty", argv[0], argv[1], argv[2], argv[3], "-d Larch Switch device", "-v", "-s", NULL);
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

int plat_upgrade(char *uri, char *signature)
{
	UNUSED_PARAM(signature);
	UNUSED_PARAM(uri);
	return 0;
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

int plat_event_subscribe(const struct plat_event_callbacks *cbs)
{
	UNUSED_PARAM(cbs);
	return 0;
}

void plat_event_unsubscribe(void)
{
}

void plat_health_poll(void (*cb)(struct plat_health_info *), int period_sec)
{
	using namespace larch;

	try
	{
		state->health_periodic->stop();
		state->health_periodic->start(
		    [cb] {
			    plat_health_info health_info{100};
			    cb(&health_info);
		    },
		    std::chrono::seconds{period_sec});
	}
	catch (const std::exception &ex)
	{
		UC_LOG_ERR("Failed to start health poll: %s", ex.what());
	}
}

void plat_health_poll_stop(void)
{
	using namespace larch;

	try
	{
		state->health_periodic->stop();
	}
	catch (const std::exception &ex)
	{
		UC_LOG_ERR("Failed to stop health poll: %s", ex.what());
	}
}

void plat_telemetry_poll(void (*cb)(struct plat_state_info *), int period_sec)
{
	using namespace larch;

	try
	{
		state->telemetry_periodic->stop();
		state->telemetry_periodic->start(
		    [cb] {
			    auto [state_info, data] = get_state_info();
			    cb(&state_info);
		    },
		    std::chrono::seconds{period_sec});
	}
	catch (const std::exception &ex)
	{
		UC_LOG_ERR("Failed to start telemetry poll: %s", ex.what());
	}
}

void plat_telemetry_poll_stop(void)
{
	using namespace larch;

	try
	{
		state->telemetry_periodic->stop();
	}
	catch (const std::exception &ex)
	{
		UC_LOG_ERR("Failed to stop telemetry poll: %s", ex.what());
	}
}

void plat_state_poll(void (*cb)(struct plat_state_info *), int period_sec)
{
	using namespace larch;

	try
	{
		state->state_periodic->stop();
		state->state_periodic->start(
		    [cb] {
			    auto [state_info, data] = get_state_info();
			    cb(&state_info);
		    },
		    std::chrono::seconds{period_sec});
	}
	catch (const std::exception &ex)
	{
		UC_LOG_ERR("Failed to start state poll: %s", ex.what());
	}
}

void plat_state_poll_stop(void)
{
	using namespace larch;

	try
	{
		state->state_periodic->stop();
	}
	catch (const std::exception &ex)
	{
		UC_LOG_ERR("Failed to stop state poll: %s", ex.what());
	}
}

void plat_upgrade_poll(int (*cb)(struct plat_upgrade_info *), int period_sec)
{
	UNUSED_PARAM(period_sec);
	UNUSED_PARAM(cb);
}

void plat_upgrade_poll_stop(void)
{
}

int plat_run_script(struct plat_run_script *)
{
	return 0;
}

int plat_port_list_get(uint16_t list_size, struct plat_ports_list *ports)
{
	try
	{
		const auto port_list = larch::get_port_list();

		if (port_list.size() < list_size)
		{
			UC_LOG_ERR(
			    "Too much ports requested (requested %hu, while "
			    "only %zu available)",
			    list_size,
			    port_list.size());
			return -1;
		}

		auto it = port_list.cbegin();
		for (plat_ports_list *node = ports; node; node = node->next)
		{
			std::strncpy(
			    node->name,
			    it++->name.c_str(),
			    sizeof(node->name) - 1);
		}
	}
	catch (const std::exception &ex)
	{
		UC_LOG_ERR("Failed to get list of ports: %s", ex.what());
		return -1;
	}

	return 0;
}

int plat_port_num_get(uint16_t *num_of_active_ports)
{
	try
	{
		*num_of_active_ports = larch::get_port_list().size();
	}
	catch (const std::exception &ex)
	{
		UC_LOG_ERR("Failed to get count of ports: %s", ex.what());
		return -1;
	}

	return 0;
}

int plat_running_img_name_get(char *str, size_t str_max_len)
{
	UNUSED_PARAM(str_max_len);
	UNUSED_PARAM(str);
	return 0;
}

int plat_revision_get(char *str, size_t str_max_len)
{
	UNUSED_PARAM(str_max_len);
	UNUSED_PARAM(str);
	return 0;
}

int plat_reboot_cause_get(struct plat_reboot_cause *cause)
{
	UNUSED_PARAM(cause);
	return 0;
}

int plat_diagnostic(char *res_path)
{
	UNUSED_PARAM(res_path);
	return 0;
}
