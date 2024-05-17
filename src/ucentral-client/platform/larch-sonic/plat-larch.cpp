#include <state.hpp>
#include <utils.hpp>
#include <vlan.hpp>

#include <gnmi.grpc.pb.h>
#include <gnmi.pb.h>

#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>
#include <grpc/grpc.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#define UC_LOG_COMPONENT UC_LOG_COMPONENT_PLAT
#include <ucentral-log.h>
#include <ucentral-platform.h>

#include <cstdlib>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility> // std::move

#define UNUSED_PARAM(param) (void)((param))

using nlohmann::json;

namespace {
const std::string api_address = "http://127.0.0.1:8090";
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

	state->channel = grpc::CreateChannel("127.0.0.1:8080", std::move(credentials));
	state->gnmi_stub = gnmi::gNMI::NewStub(state->channel);

	return 0;
}

int plat_info_get(struct plat_platform_info *info)
{
	using namespace larch;

	httplib::Client client{api_address};

	auto result = client.Get("/v1/config/devicemetadata");

	if (!verify_response(result))
		return -1;

	const json response = json::parse(result->body, nullptr, false);

	if (response.is_discarded())
		return -1;

	*info = {};

	auto copy_from_json = [](const json &obj, char *dest, std::size_t dest_size) {
		std::strncpy(
			dest,
			obj.template get<std::string>().c_str(),
			dest_size > 0 ? dest_size - 1 : 0);
	};

	copy_from_json(response["platform"], info->platform, std::size(info->platform));
	copy_from_json(response["hwsku"], info->hwsku, std::size(info->hwsku));
	copy_from_json(response["mac_address"], info->mac, std::size(info->mac));

	return 0;
}

int plat_reboot(void)
{
	std::system("reboot");
	return 0;
}

int plat_config_apply(struct plat_cfg *cfg, uint32_t id)
{
	using namespace larch;

	UNUSED_PARAM(id);

	try
	{
		apply_vlan_config(cfg);
	}
	catch (const std::exception &ex)
	{
		UC_LOG_ERR("Failed to apply config: %s", ex.what());
	}

	return 0;
}

int plat_config_save(uint64_t id)
{
	UNUSED_PARAM(id);
	return 0;
}

int plat_config_restore(void)
{
	return 0;
}

int plat_metrics_save(const struct plat_metrics_cfg *cfg)
{
	UNUSED_PARAM(cfg);
	return 0;
}

int plat_metrics_restore(struct plat_metrics_cfg *cfg)
{
	UNUSED_PARAM(cfg);
	return 0;
}

int plat_saved_config_id_get(uint64_t *id)
{
	UNUSED_PARAM(id);
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
	UNUSED_PARAM(rtty_cfg);
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
	UNUSED_PARAM(period_sec);
	UNUSED_PARAM(cb);
}

void plat_health_poll_stop(void)
{
}

void plat_telemetry_poll(void (*cb)(struct plat_state_info *), int period_sec)
{
	UNUSED_PARAM(period_sec);
	UNUSED_PARAM(cb);
}

void plat_telemetry_poll_stop(void)
{
}

void plat_state_poll(void (*cb)(struct plat_state_info *), int period_sec)
{
	UNUSED_PARAM(period_sec);
	UNUSED_PARAM(cb);
}

void plat_state_poll_stop(void)
{
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
	UNUSED_PARAM(ports);
	UNUSED_PARAM(list_size);
	return 0;
}

int plat_port_num_get(uint16_t *num_of_active_ports)
{
	UNUSED_PARAM(num_of_active_ports);
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
