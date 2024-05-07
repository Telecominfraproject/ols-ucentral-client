#include <utils.hpp>

#include <gnmi.grpc.pb.h>
#include <gnmi.pb.h>

#include <grpc++/alarm.h>
#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>
#include <grpc/grpc.h>
#include <libs/httplib.h>
#include <libs/json.hpp>

#include <ucentral-log.h>
#include <ucentral-platform.h>

#include <cstring>
#include <functional> // std::function
#include <iostream>
#include <memory>
#include <string>
#include <utility> // std::move
#include <optional>

#define UNUSED_PARAM(param) (void)((param))

using nlohmann::json;

struct platform_state {
	std::shared_ptr<grpc::ChannelInterface> channel;
	std::unique_ptr<gnmi::gNMI::Stub> gnmi_stub;
};

/**
 * Verifier that marks all the certificates as valid.
*/
class certificate_verifier
    : public grpc::experimental::ExternalCertificateVerifier {
 public:
  bool Verify(grpc::experimental::TlsCustomVerificationCheckRequest* request,
              std::function<void(grpc::Status)> callback,
              grpc::Status* sync_status) override {
	  (void)request;
	  (void)callback;
	  *sync_status = grpc::Status(grpc::StatusCode::OK, "");
	  return true;
  }

  void Cancel(grpc::experimental::TlsCustomVerificationCheckRequest*) override {
  }
};

namespace {
const std::string api_address = "http://127.0.0.1:8090";

thread_local std::unique_ptr<platform_state> state;

std::optional<std::string> gnmi_get(const std::string &yang_path)
{
	gnmi::GetRequest greq;
	greq.set_encoding(gnmi::JSON_IETF);

	convert_yang_path_to_proto(yang_path, greq.add_path());

	grpc::ClientContext context;
	gnmi::GetResponse gres;
	const grpc::Status status = state->gnmi_stub->Get(&context, greq, &gres);

	if (!status.ok())
	{
		std::cerr << "Get operation wasn't successful: " << status.error_message()
				  << "; error code " << status.error_code() << std::endl;
		return {};
	}

	if (gres.notification_size() != 1)
	{
		std::cerr << "Unsupported notification size" << std::endl;
		return {};
	}

	gnmi::Notification notification = gres.notification(0);
	if (notification.update_size() != 1)
	{
		std::cerr << "Unsupported update size" << std::endl;
		return {};
	}

	gnmi::Update update = notification.update(0);
	if (!update.has_val())
	{
		std::cerr << "Empty value" << std::endl;
		return {};
	}

	gnmi::TypedValue value = update.val();
	if (!value.has_json_ietf_val())
	{
		std::cerr << "Empty JSON value" << std::endl;
		return {};
	}

	return value.json_ietf_val();
}
}

int plat_init(void)
{
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
	return 0;
}

int plat_config_apply(struct plat_cfg *cfg, uint32_t id)
{
	UNUSED_PARAM(cfg);
	UNUSED_PARAM(id);
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
