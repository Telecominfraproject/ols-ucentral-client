#include <syslog.h>
#include <string.h>
#include <thread>
#include <vector>
#include <chrono>
#include <list>
#include <string>
#include <utility> // std::move
#include <gnmi_c_connector.h>

#include <jsoncpp/json/json.h>

#include <grpc/grpc.h>
#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>
#include <grpc++/alarm.h>

#include "gnmi.grpc.pb.h"
#include "gnmi.pb.h"
#include "system.grpc.pb.h"
#include "system.pb.h"
#include "openconfig_file_mgmt_private.grpc.pb.h"
#include "openconfig_file_mgmt_private.pb.h"
#include "sonic_config_mgmt.grpc.pb.h"
#include "sonic_config_mgmt.pb.h"
#include "sonic_alarm.pb.h"
#include "sonic_alarm.grpc.pb.h"
#include "sonic_gnoi.pb.h"
#include "sonic_gnoi.grpc.pb.h"
#include "sonic_alarm.grpc.pb.h"
#include "openconfig_image_management.grpc.pb.h"
#include "openconfig_image_management.pb.h"
#include "os.grpc.pb.h"
#include "os.pb.h"
#include "openconfig_poe.pb.h"
#include "openconfig_poe.grpc.pb.h"

using namespace std::chrono_literals;
using namespace std::chrono;

extern "C" {
	extern void (*main_log_cb)(const char *);
}

static void set_deadline_after_us(grpc::ClientContext &c, int64_t us)
{
	if (0 >= us) {
		c.set_deadline(system_clock::now() + microseconds{ us });
	}
}

static int convertYangPath2ProtoPath(const char *yangPath, ::gnmi::Path *path)
{
	std::string str{yangPath};

	std::string::size_type pos{};
	std::vector<std::string> elements;

	while ((pos = str.find('/')) != std::string::npos)
	{
		std::string elem{str.substr(0, pos)};

		if (!elem.empty())
			elements.push_back(std::move(elem));

		str.erase(0, pos + 1);
	}

	// Add the last part of split string
	elements.push_back(str);

	std::string &first_element = elements[0];
	const auto colon_pos = first_element.find(':');

	if (colon_pos != std::string::npos)
	{
		path->set_origin(first_element.substr(0, colon_pos));
		first_element.erase(0, colon_pos + 1);
	}

	for (const auto &elem : elements)
	{
		::gnmi::PathElem *path_elem = path->add_elem();
		path_elem->set_name(elem);
	}

	return 1;
}

class SyncCertificateVerifier
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

struct Token {
	std::string token;
	std::string type;
	int64_t expires_in;
	int err;
};

static Token sonic_jwt_authenticate(gnoi::sonic::SonicService::Stub *stub,
				    const char *username, const char *password,
				    int64_t timeout_us)
{
	grpc::ClientContext context;
	grpc::Status status;
	gnoi::sonic::AuthenticateRequest rq;
	gnoi::sonic::AuthenticateResponse resp;
	Token result{};

	rq.set_username(username);
	rq.set_password(password);

	set_deadline_after_us(context, timeout_us);

	status = stub->Authenticate(&context, rq, &resp);
	if (!status.ok()) {
		GNMI_C_CONNECTOR_DEBUG_LOG("Request failed");
		GNMI_C_CONNECTOR_DEBUG_LOG("Code: %d", status.error_code());
		main_log_cb(status.error_message().c_str());
		result.err = 1;
		return result;
	}

	if (!resp.has_token()) {
		GNMI_C_CONNECTOR_DEBUG_LOG(
			"Request failed, response does not have token");
		GNMI_C_CONNECTOR_DEBUG_LOG("Code: %d", status.error_code());
		main_log_cb(status.error_message().c_str());
		result.err = 1;
		return result;
	}

	result.token = move(resp.mutable_token()->access_token());
	result.type = move(resp.mutable_token()->type());
	result.expires_in = resp.token().expires_in();

	GNMI_C_CONNECTOR_DEBUG_LOG("Access token %s", result.token.c_str());
	return result;
}

struct gnmi_session {
	std::unique_ptr<gnmi::gNMI::Stub> *stub;
	std::unique_ptr<gnoi::system::System::Stub> *stub_gnoi_system;
	std::unique_ptr<gnoi::OpenconfigFileMgmtPrivate::OpenconfigFileMgmtPrivateService::Stub> *stub_gnoi_openconfig_file_mgmt_priv;
	std::unique_ptr<gnoi::SonicConfigMgmt::SonicConfigMgmtService::Stub> *stub_gnoi_sonic_cfg_mgmt;
	std::unique_ptr<gnoi::OpenconfigImageManagement::OpenconfigImageManagementService::Stub> *stub_gnoi_openconfig_img_mgmt;
	std::unique_ptr<gnoi::os::OS::Stub> *stub_gnoi_os;
	std::unique_ptr<gnoi::SonicAlarm::SonicAlarmService::Stub>
		*stub_gnoi_sonic_alarm;
	std::unique_ptr<gnoi::sonic::SonicService::Stub> *stub_gnoi_sonic;
	std::unique_ptr<gnoi::OpenconfigPoe::OpenconfigPoeService::Stub>
		*stub_gnoi_openconfig_poe;
	std::string *host;
	std::string *username;
	std::string *password;
	std::shared_ptr< ::grpc::ChannelInterface> channel;
	int64_t auth_timeout_us;
};

struct gnmi_session *gnmi_session_create(char *host,
					 char *username, char *password)
{
	struct gnmi_session *gs;
	auto verifier = grpc::experimental::ExternalCertificateVerifier::Create<SyncCertificateVerifier>();
	grpc::experimental::TlsChannelCredentialsOptions options;
	options.set_verify_server_certs(false);
	options.set_certificate_verifier(verifier);
	options.set_check_call_host(false);
	auto credentials = grpc::experimental::TlsCredentials(options);

	gs = new gnmi_session{};
	gs->auth_timeout_us = 10 * 1000000; /* 10 seconds */
	gs->host = new std::string(host);
	gs->username = new std::string(username);
	gs->password = new std::string(password);
	gs->stub = new std::unique_ptr<gnmi::gNMI::Stub>();
	gs->stub_gnoi_system = new std::unique_ptr<gnoi::system::System::Stub>();
	gs->stub_gnoi_openconfig_file_mgmt_priv = new std::unique_ptr<gnoi::OpenconfigFileMgmtPrivate::OpenconfigFileMgmtPrivateService::Stub>();
	gs->stub_gnoi_openconfig_img_mgmt = new std::unique_ptr<gnoi::OpenconfigImageManagement::OpenconfigImageManagementService::Stub>();
	gs->stub_gnoi_sonic_cfg_mgmt = new std::unique_ptr<gnoi::SonicConfigMgmt::SonicConfigMgmtService::Stub>();
	gs->stub_gnoi_os = new std::unique_ptr<gnoi::os::OS::Stub>();
	gs->stub_gnoi_sonic_alarm =
		new std::unique_ptr<gnoi::SonicAlarm::SonicAlarmService::Stub>();
	gs->stub_gnoi_sonic =
		new std::unique_ptr<gnoi::sonic::SonicService::Stub>();
	gs->stub_gnoi_openconfig_poe =
		new std::unique_ptr<gnoi::OpenconfigPoe::OpenconfigPoeService::Stub>();

	gs->channel = grpc::CreateChannel(*gs->host, credentials);
	*gs->stub = gnmi::gNMI::NewStub(gs->channel);
	*gs->stub_gnoi_system =
		gnoi::system::System::NewStub(grpc::CreateChannel(*gs->host, credentials));
	*gs->stub_gnoi_openconfig_file_mgmt_priv =
		gnoi::OpenconfigFileMgmtPrivate::OpenconfigFileMgmtPrivateService::NewStub(grpc::CreateChannel(*gs->host, credentials));
	*gs->stub_gnoi_sonic_cfg_mgmt =
		gnoi::SonicConfigMgmt::SonicConfigMgmtService::NewStub(grpc::CreateChannel(*gs->host, credentials));
	*gs->stub_gnoi_openconfig_img_mgmt =
		gnoi::OpenconfigImageManagement::OpenconfigImageManagementService::NewStub(grpc::CreateChannel(*gs->host, credentials));
	*gs->stub_gnoi_os =
		gnoi::os::OS::NewStub(grpc::CreateChannel(*gs->host, credentials));
	*gs->stub_gnoi_sonic_alarm =
		gnoi::SonicAlarm::SonicAlarmService::NewStub(
			grpc::CreateChannel(*gs->host, credentials));
	*gs->stub_gnoi_sonic = gnoi::sonic::SonicService::NewStub(
		grpc::CreateChannel(*gs->host, credentials));
	*gs->stub_gnoi_openconfig_poe = gnoi::OpenconfigPoe::OpenconfigPoeService::NewStub(
		grpc::CreateChannel(*gs->host, credentials));

	return gs;
}

static thread_local std::string g_token;

template <class F>
static ::grpc::Status invoke_with_token(gnmi_session *gs, F &&f)
{
	::grpc::Status status{ ::grpc::StatusCode::UNAUTHENTICATED,
			       "failed to obtain a token" };

	if (!g_token.empty()) {
		status = f(g_token);
		if (status.error_code() != ::grpc::StatusCode::UNAUTHENTICATED)
			return status;
	}

	auto t = sonic_jwt_authenticate((*gs->stub_gnoi_sonic).get(),
					(*gs->username).c_str(),
					(*gs->password).c_str(),
					gs->auth_timeout_us);
	if (t.err)
		return status;

	g_token = move(t.token);
	return f(g_token);
}

struct gnmi_setrq {
	::gnmi::SetRequest req;
};

gnmi_setrq *gnmi_setrq_create(void)
{
	return new gnmi_setrq{};
}

void gnmi_setrq_destroy(gnmi_setrq *rq)
{
	delete rq;
}

int gnmi_setrq_add_jsoni_update(gnmi_setrq *rq, const char *path,
				const char *req)
{
	::gnmi::Update *upd = rq->req.add_update();
	if (!upd)
		return -1;
	convertYangPath2ProtoPath(path, upd->mutable_path());
	upd->mutable_val()->set_json_ietf_val(req);
	return 0;
}

int gnmi_setrq_add_jsoni_replace(gnmi_setrq *rq, const char *path,
				 const char *req)
{
	::gnmi::Update *upd = rq->req.add_replace();
	if (!upd)
		return -1;
	convertYangPath2ProtoPath(path, upd->mutable_path());
	upd->mutable_val()->set_json_ietf_val(req);
	return 0;
}

int gnmi_setrq_add_delete(gnmi_setrq *rq, const char *path)
{
	::gnmi::Path *del = rq->req.add_delete_();
	if (!del)
		return -1;
	convertYangPath2ProtoPath(path, del);
	return 0;
}

int gnmi_setrq_execute(gnmi_session *gs, const gnmi_setrq *rq,
		       struct gnmi_status *sts)
{
	::grpc::Status status;
	::grpc::ClientContext context;
	::gnmi::SetResponse res;

	status = invoke_with_token(gs, [&](const std::string &token) {
		::grpc::ClientContext context;
		context.AddMetadata("access_token", token);
		return (*gs->stub)->Set(&context, rq->req, &res);
	});

	if (sts) {
		sts->ok = status.ok();
		sts->error_code = status.error_code();
		snprintf(sts->msg, sizeof sts->msg, "%s",
			 status.error_message().c_str());
	}

	return 0;
}

int gnmi_gnoi_techsupport_start(struct gnmi_session *gs, char *res_path)
{
	gnoi::sonic::TechsupportResponse gres;
	gnoi::sonic::TechsupportRequest greq;
	grpc::Status status;
	int path_len;

	status = invoke_with_token(gs, [&](const std::string &token) {
		grpc::ClientContext context;
		context.AddMetadata("access_token", token);
		return (*gs->stub_gnoi_sonic)
			->ShowTechsupport(&context, greq, &gres);
	});
	if (!status.ok()) {
		GNMI_C_CONNECTOR_DEBUG_LOG("Request failed");
		GNMI_C_CONNECTOR_DEBUG_LOG("Code: %d", status.error_code());
		main_log_cb(gres.output().status_detail().c_str());
		return -1;
	}

	path_len = gres.output().output_filename().length();
	if (path_len > PATH_MAX) {
		GNMI_C_CONNECTOR_DEBUG_LOG("Path length is too big (%d)", path_len);
		return -1;
	}

	memcpy(res_path, gres.output().output_filename().c_str(), path_len);
	res_path[path_len] = 0;

	return gres.output().status();
}

static int gnmi_jsoni_get_internal(struct gnmi_session *gs, const char *path,
				   ::gnmi::TypedValue &val, int64_t timeout_us)
{
	int notification_size, update_size;
	::gnmi::Notification notif;
	::gnmi::Update upd;
	::gnmi::Path* gpath;
	::gnmi::GetRequest greq;
	::gnmi::GetResponse gres;
	::grpc::Status status;

	greq.set_encoding(::gnmi::JSON_IETF);
	gpath = greq.add_path();
	convertYangPath2ProtoPath(path, gpath);

	::grpc::ClientContext context;
	set_deadline_after_us(context, timeout_us);
	status = (*gs->stub)->Get(&context, greq, &gres);

	/*
	 * We don't have the implementation of JWT authentication, so disable it

	status = invoke_with_token(gs, [&](const std::string &token) {
		::grpc::ClientContext context;
		context.AddMetadata("access_token", token);
		set_deadline_after_us(context, timeout_us);
		return (*gs->stub)->Get(&context, greq, &gres);
	});
	 */

	if (!status.ok()) {
		GNMI_C_CONNECTOR_DEBUG_LOG("Request failed");
		GNMI_C_CONNECTOR_DEBUG_LOG("Code: %d", status.error_code());
		main_log_cb(status.error_message().c_str());
		return -1;
	}

	notification_size = gres.notification_size();
	if (notification_size != 1) {
		GNMI_C_CONNECTOR_DEBUG_LOG("Unsupported notification size");
		return -1;
	}

	notif = gres.notification(0);
	update_size = notif.update_size();
	if (update_size != 1) {
		GNMI_C_CONNECTOR_DEBUG_LOG("Unsupported update size");
		return -1;
	}

	upd = notif.update(0);
	if (!upd.has_val()) {
		GNMI_C_CONNECTOR_DEBUG_LOG("Empty val");
		return -1;
	}

	val = upd.val();
	if (!val.has_json_ietf_val()) {
		GNMI_C_CONNECTOR_DEBUG_LOG("Empty json val");
		return -1;
	}

	return 0;
}

int gnmi_jsoni_get(struct gnmi_session *gs, const char *path, char *res,
		   size_t res_size, int64_t timeout_us)
{
	::gnmi::TypedValue val;

	int rc = gnmi_jsoni_get_internal(gs, path, val, timeout_us);
	if (rc) {
		return -1;
	}

	if (!(res_size > val.json_ietf_val().length())) {
		GNMI_C_CONNECTOR_DEBUG_LOG("Buffer overflow");
		return -1;
	}

	memset(res, 0, res_size);
	memcpy(res, val.json_ietf_val().c_str(), val.json_ietf_val().length());

	return 0;
}

int gnmi_jsoni_get_alloc(struct gnmi_session *gs, const char *path, char **res,
			 size_t *len, int64_t timeout_us)
{
	int rc;
	char *buf;
	::gnmi::TypedValue val;

	if (!res) {
		return -1;
	}

	rc = gnmi_jsoni_get_internal(gs, path, val, timeout_us);
	if (rc) {
		return -1;
	}

	if (!(buf = (char *)calloc(1, val.json_ietf_val().length() + 1))) {
		GNMI_C_CONNECTOR_DEBUG_LOG("malloc");
		return -1;
	}

	memcpy(buf, val.json_ietf_val().c_str(), val.json_ietf_val().length());

	*res = buf;
	if (len) {
		*len = val.json_ietf_val().length();
	}

	return 0;
}

int gnmi_jsoni_set(struct gnmi_session *gs, const char *path, char *req,
		   int64_t timeout_us)
{
	::gnmi::SetResponse gres;
	::gnmi::SetRequest greq;
	::gnmi::Update* upd;
	::grpc::Status status;

	upd = greq.add_update();
	convertYangPath2ProtoPath(path, upd->mutable_path());
	upd->mutable_val()->set_json_ietf_val(std::string(req));

	status = invoke_with_token(gs, [&](const std::string &token) {
		::grpc::ClientContext context;
		context.AddMetadata("access_token", token);
		set_deadline_after_us(context, timeout_us);
		return (*gs->stub)->Set(&context, greq, &gres);
	});
	if (!status.ok()) {
		GNMI_C_CONNECTOR_DEBUG_LOG("Request failed");
		GNMI_C_CONNECTOR_DEBUG_LOG("Code: %d", status.error_code());
		main_log_cb(status.error_message().c_str());
		return -1;
	}

	return 0;
}

int gnmi_jsoni_del(struct gnmi_session *gs, const char *path,
		   int64_t timeout_us)
{
	::gnmi::SetResponse gres;
	::gnmi::SetRequest greq;
	::gnmi::Path *del_gpath;
	::grpc::Status status;

	del_gpath = greq.add_delete_();
	convertYangPath2ProtoPath(path, del_gpath);

	status = invoke_with_token(gs, [&](const std::string &token) {
		::grpc::ClientContext context;
		context.AddMetadata("access_token", token);
		set_deadline_after_us(context, timeout_us);
		return (*gs->stub)->Set(&context, greq, &gres);
	});
	if (!status.ok()) {
		GNMI_C_CONNECTOR_DEBUG_LOG("Request failed");
		GNMI_C_CONNECTOR_DEBUG_LOG("Code: %d", status.error_code());
		main_log_cb(status.error_message().c_str());
		return -1;
	}

	return 0;
}

int gnmi_jsoni_replace(struct gnmi_session *gs, const char *path, char *req,
		       int64_t timeout_us)
{
	::gnmi::SetResponse gres;
	::gnmi::SetRequest greq;
	::gnmi::Update* upd;
	::grpc::Status status;

	upd = greq.add_replace();
	convertYangPath2ProtoPath(path, upd->mutable_path());
	upd->mutable_val()->set_json_ietf_val(std::string(req));

	status = invoke_with_token(gs, [&](const std::string &token) {
		::grpc::ClientContext context;
		context.AddMetadata("access_token", token);
		set_deadline_after_us(context, timeout_us);
		return (*gs->stub)->Set(&context, greq, &gres);
	});

	if (!status.ok()) {
		GNMI_C_CONNECTOR_DEBUG_LOG("Request failed");
		GNMI_C_CONNECTOR_DEBUG_LOG("Code: %d", status.error_code());
		main_log_cb(status.error_message().c_str());
		return -1;
	}

	return 0;
}

int gnmi_gnoi_system_reboot(struct gnmi_session *gs, int64_t timeout_us)
{
	grpc::Status status;
	gnoi::system::RebootResponse gres;
	gnoi::system::RebootRequest greq;

	status = invoke_with_token(gs, [&](const std::string &token) {
		grpc::ClientContext context;
		context.AddMetadata("access_token", token);
		set_deadline_after_us(context, timeout_us);
		return (*gs->stub_gnoi_system)->Reboot(&context, greq, &gres);
	});
	if (!status.ok()) {
		GNMI_C_CONNECTOR_DEBUG_LOG("Request failed");
		GNMI_C_CONNECTOR_DEBUG_LOG("Code: %d", status.error_code());
		main_log_cb(status.error_message().c_str());
		return -1;
	}

	return 0;
}

static int __gnmi_gnoi_sonic_copy(
	struct gnmi_session *gs, char *src, char *dst,
	gnoi::OpenconfigFileMgmtPrivate::CopyRequest_Input_Copy_config_option mode,
	int64_t timeout_us)
{
	grpc::Status status;
	gnoi::OpenconfigFileMgmtPrivate::CopyResponse gres;
	gnoi::OpenconfigFileMgmtPrivate::CopyRequest greq;

	greq.mutable_input()->set_source(src);
	greq.mutable_input()->set_destination(dst);
	greq.mutable_input()->set_copy_config_option(mode);

	status = invoke_with_token(gs, [&](const std::string &token) {
		grpc::ClientContext context;
		context.AddMetadata("access_token", token);
		set_deadline_after_us(context, timeout_us);
		return (*gs->stub_gnoi_openconfig_file_mgmt_priv)
			->Copy(&context, greq, &gres);
	});
	if (!status.ok()) {
		GNMI_C_CONNECTOR_DEBUG_LOG("Request failed");
		GNMI_C_CONNECTOR_DEBUG_LOG("Code: %d", status.error_code());
		main_log_cb(gres.output().status_detail().c_str());
		return -1;
	}

	return 0;
}

int gnmi_gnoi_sonic_copy_merge(struct gnmi_session *gs, char *src, char *dst,
			       int64_t timeout_us)
{
	return __gnmi_gnoi_sonic_copy(
		gs, src, dst,
		gnoi::OpenconfigFileMgmtPrivate::
			CopyRequest_Input_Copy_config_option_MERGE,
		timeout_us);
}

int gnmi_gnoi_sonic_copy_overwrite(struct gnmi_session *gs, char *src,
				   char *dst, int64_t timeout_us)
{
	return __gnmi_gnoi_sonic_copy(
		gs, src, dst,
		gnoi::OpenconfigFileMgmtPrivate::
			CopyRequest_Input_Copy_config_option_OVERWRITE,
		timeout_us);
}

int gnmi_gnoi_sonic_copy_replace(struct gnmi_session *gs, char *src, char *dst,
				 int64_t timeout_us)
{
	return __gnmi_gnoi_sonic_copy(
		gs, src, dst,
		gnoi::OpenconfigFileMgmtPrivate::
			CopyRequest_Input_Copy_config_option_REPLACE,
		timeout_us);
}

static int __gnmi_gnoi_sonic_cfg_subcmd(struct gnmi_session *gs,
					const char *subcmd, int64_t timeout_us)
{
	grpc::Status status;
	gnoi::SonicConfigMgmt::WriteEraseResponse gres;
	gnoi::SonicConfigMgmt::WriteEraseRequest greq;

	greq.mutable_input()->set_subcmd(subcmd);

	status = invoke_with_token(gs, [&](const std::string &token) {
		grpc::ClientContext context;
		context.AddMetadata("access_token", token);
		set_deadline_after_us(context, timeout_us);
		return (*gs->stub_gnoi_sonic_cfg_mgmt)
			->WriteErase(&context, greq, &gres);
	});
	if (!status.ok()) {
		GNMI_C_CONNECTOR_DEBUG_LOG("Request failed");
		GNMI_C_CONNECTOR_DEBUG_LOG("Code: %d", status.error_code());
		main_log_cb(gres.output().status_detail().c_str());
		return -1;
	}

	return 0;
}

int gnmi_gnoi_sonic_cfg_erase_boot(struct gnmi_session *gs, int64_t timeout_us)
{
	return __gnmi_gnoi_sonic_cfg_subcmd(gs, "op_write_erase_boot",
					    timeout_us);
}

int gnmi_gnoi_sonic_cfg_erase_boot_cancel(struct gnmi_session *gs,
					  int64_t timeout_us)
{
	return __gnmi_gnoi_sonic_cfg_subcmd(gs, "op_no_write_erase",
					    timeout_us);
}

int gnmi_gnoi_image_install(struct gnmi_session *gs, const char *uri,
			    int64_t timeout_us)
{
	grpc::Status status;
	gnoi::OpenconfigImageManagement::ImageInstallResponse gres;
	gnoi::OpenconfigImageManagement::ImageInstallRequest greq;

	greq.mutable_input()->set_image_name(uri);

	status = invoke_with_token(gs, [&](const std::string &token) {
		grpc::ClientContext context;
		context.AddMetadata("access_token", token);
		set_deadline_after_us(context, timeout_us);
		return (*gs->stub_gnoi_openconfig_img_mgmt)
			->ImageInstall(&context, greq, &gres);
	});
	if (!status.ok()) {
		GNMI_C_CONNECTOR_DEBUG_LOG("Request failed");
		GNMI_C_CONNECTOR_DEBUG_LOG("Code: %d", status.error_code());
		main_log_cb(gres.output().status_detail().c_str());
		return -1;
	}

	return 0;
}

/* gnma (sai) api to obtain status is not defined.
 * So use json buffer to prevent additional type convert on gnma layer.
 */
int gnmi_gnoi_upgrade_status(struct gnmi_session *gs, char *res,
			     size_t res_size, int64_t timeout_us)
{
	grpc::Status status;
	gnoi::os::UpgradeStatusResponse gres;
	gnoi::os::UpgradeStatusRequest greq;
	Json::Value json_res;
	std::string rendered_json;
	Json::FastWriter fastWriter;

	status = invoke_with_token(gs, [&](const std::string &token) {
		grpc::ClientContext context;
		context.AddMetadata("access_token", token);
		set_deadline_after_us(context, timeout_us);
		return (*gs->stub_gnoi_os)
			->GetUpgradeStatus(&context, greq, &gres);
	});
	if (!status.ok()) {
		GNMI_C_CONNECTOR_DEBUG_LOG("Request failed");
		GNMI_C_CONNECTOR_DEBUG_LOG("Code: %d", status.error_code());
		return -1;
	}

	json_res["global_state"] = gnoi::os::UpgradeStatusResponse::Global_state_Name(gres.global_state());
	json_res["percentage"] = 0;
	if (gres.global_state() == gnoi::os::UpgradeStatusResponse_Global_state_GLOBAL_STATE_DOWNLOAD)
		if (gres.has_transfer_status())
			json_res["percentage"] = gres.transfer_status().file_progress();

	rendered_json = fastWriter.write(json_res);
	if (!(res_size > rendered_json.length())) {
		GNMI_C_CONNECTOR_DEBUG_LOG("Buffer overflow");
		return -1;
	}

	memset(res, 0, res_size);
	memcpy(res, rendered_json.c_str(), rendered_json.length());

	return 0;
}

static int gnmi2connector_typed_value(gnmi_typed_value &dst,
				      const ::gnmi::TypedValue &src)
{
	switch (src.value_case()) {
	case ::gnmi::TypedValue::kUintVal:
		dst.type = gnmi_typed_value::GNMI_TYPED_VALUE_UINT;
		dst.v.u64 = src.uint_val();
		break;
	case ::gnmi::TypedValue::kJsonIetfVal:
		dst.type = gnmi_typed_value::GNMI_TYPED_VALUE_JSONIETF;
		dst.v.str = src.json_ietf_val().c_str();
		break;
	case ::gnmi::TypedValue::kStringVal:
		dst.type = gnmi_typed_value::GNMI_TYPED_VALUE_STRING;
		dst.v.str = src.string_val().c_str();
		break;
	case ::gnmi::TypedValue::kBoolVal:
		dst.type = gnmi_typed_value::GNMI_TYPED_VALUE_BOOL;
		dst.v.boolean = src.bool_val();
		break;
	/* TODO not handled: */
	case ::gnmi::TypedValue::kBytesVal:
	case ::gnmi::TypedValue::kFloatVal:
	case ::gnmi::TypedValue::kDecimalVal:
	case ::gnmi::TypedValue::kLeaflistVal:
	case ::gnmi::TypedValue::kAnyVal:
	case ::gnmi::TypedValue::kJsonVal:
	case ::gnmi::TypedValue::kAsciiVal:
	case ::gnmi::TypedValue::kProtoBytes:
	default:
		GNMI_C_CONNECTOR_DEBUG_LOG("type not supprted %d",
					   (int)src.value_case());
		return -1;
	}
	return 0;
}

struct container_path {
	std::vector<gnmi_path_elem> elem;
	std::list<std::vector<gnmi_path_elem_key> > key;
	std::list<std::string> str;
};

static void gnmi2connector_path(gnmi_path *dst, container_path &container,
				const ::gnmi::Path &src)
{
	int ie, ik;

	if (!src.elem_size())
		return;

	container.elem.assign(src.elem_size(), gnmi_path_elem{});

	for (ie = 0; ie < src.elem_size(); ++ie) {
		auto &e = src.elem(ie);
		container.str.emplace_back(e.name());
		container.elem[ie].name = container.str.back().c_str();
		if (!e.key_size()) {
			continue;
		}
		container.key.emplace_back(e.key_size(), gnmi_path_elem_key{});
		auto &key = container.key.back();
		container.elem[ie].key_size = e.key_size();
		container.elem[ie].key = key.data();
		ik = 0;
		for (auto &kv : e.key()) {
			container.str.emplace_back(kv.first);
			key[ik].key = container.str.back().c_str();
			container.str.emplace_back(kv.second);
			key[ik].value = container.str.back().c_str();
			++ik;
		}
	}
	container.str.emplace_back(src.origin());
	dst->origin = container.str.back().c_str();

	dst->elem = container.elem.data();
	dst->elem_size = container.elem.size();
}

/*
 * TODO(vb) make concept
 * RpcT:
 *  typedef ResponseType
 *  typedef RequestType
 *  prepare_call(ClientContext *, CompletionQueue *) -> ClientAsyncReaderWriter<RequestType, ResponseType>
 *  request() -> RequestType
 *  channel() -> ChannelInterface *
 *  on_read(ResponseType) -> bool   //
 *  on_finish(::grpc::Status) -> bool // false==reconnect
 *  on_exit(void) -> void // clean-up client resources etc
 */
struct RpcStreamReader final {
	template <class RpcT>
	void start(std::unique_ptr<RpcT> rpc, std::string name = "<unnamed>")
	{
		cq = std::unique_ptr< ::grpc::CompletionQueue>{
			new ::grpc::CompletionQueue{}
		};

		th = std::thread(
			[&](std::unique_ptr<RpcT> rpc, std::string name) {
				thread_cb(*rpc, name);
			},
			move(rpc), move(name));
	}

	void stop()
	{
		if (!cq)
			return;
		::grpc::Alarm().Set(cq.get(), gpr_time_0(GPR_CLOCK_MONOTONIC),
				    (void *)CTL_SHUTDOWN);
		th.join();
		cq = nullptr;
	}

    private:
	enum : uintptr_t {
		CTL_TAG_BEGIN = 1,
		CTL_SHUTDOWN,
		CTL_TAG_END,

		STATE_TAG_BEGIN,
		STATE_CHANGE,
		STATE_TAG_END,

		STREAM_TAG_BEGIN,
		STREAM_START_CALL,
		STREAM_READ,
		STREAM_WRITE,
		STREAM_WRITES_DONE,
		STREAM_FINISH,
		STREAM_TAG_END,
	};

	template <class RpcT> void thread_cb(RpcT &rpc, std::string name)
	{
		bool stop = 0;

		GNMI_C_CONNECTOR_DEBUG_LOG("%s: enter", name.c_str());

		while (!stop) {
			GNMI_C_CONNECTOR_DEBUG_LOG("%s: start", name.c_str());
			::grpc::ClientContext context;
			void *tag;
			bool ok;
			typename RpcT::ResponseType resp;
			::grpc::Status status;

			auto stream = rpc.prepare_call(&context, cq.get());
			rpc.channel()->GetState(1);
			rpc.channel()->NotifyOnStateChange(
				GRPC_CHANNEL_IDLE,
				gpr_inf_future(GPR_CLOCK_MONOTONIC), cq.get(),
				(void *)STATE_CHANGE);

			while (cq->Next(&tag, &ok)) {
				uintptr_t t = reinterpret_cast<uintptr_t>(tag);

				if (t == CTL_SHUTDOWN) {
					GNMI_C_CONNECTOR_DEBUG_LOG(
						"%s: CTL_SHUTDOWN",
						name.c_str());
					stop = 1;
					break;
				}

				if (!ok && STREAM_TAG_BEGIN < t &&
				    t < STREAM_TAG_END) {
					GNMI_C_CONNECTOR_DEBUG_LOG(
						"%s: !ok", name.c_str());
					stream->Finish(&status,
						       (void *)STREAM_FINISH);
					continue;
				}

				if (t == STREAM_FINISH) {
					GNMI_C_CONNECTOR_DEBUG_LOG(
						"STREAM_FINISH, status %d",
						status.error_code());
					stop |= rpc.on_finish(status);
					break;
				}

				if (t == STATE_CHANGE) {
					auto state = rpc.channel()->GetState(1);
					GNMI_C_CONNECTOR_DEBUG_LOG(
						"state change: %d", (int)state);
					if (state == GRPC_CHANNEL_SHUTDOWN) {
						stop = 1;
						break;
					}

					if (state != GRPC_CHANNEL_READY) {
						rpc.channel()->NotifyOnStateChange(
							state,
							gpr_inf_future(
								GPR_CLOCK_MONOTONIC),
							cq.get(),
							(void *)STATE_CHANGE);
						continue;
					}

					stream->StartCall(
						(void *)STREAM_START_CALL);
					continue;
				}

				if (t == STREAM_START_CALL) {
					GNMI_C_CONNECTOR_DEBUG_LOG(
						"%s: STREAM_START_CALL",
						name.c_str());
					stream->Write(rpc.request(),
						      (void *)STREAM_WRITE);
					continue;
				}

				if (t == STREAM_WRITE) {
					GNMI_C_CONNECTOR_DEBUG_LOG(
						"%s: STREAM_WRITE",
						name.c_str());
					stream->WritesDone(
						(void *)STREAM_WRITES_DONE);
					continue;
				}

				if (t == STREAM_WRITES_DONE) {
					GNMI_C_CONNECTOR_DEBUG_LOG(
						"%s: STREAM_WRITES_DONE",
						name.c_str());
					GNMI_C_CONNECTOR_DEBUG_LOG(
						"%s: string read",
						name.c_str());
					stream->Read(&resp,
						     (void *)STREAM_READ);
					GNMI_C_CONNECTOR_DEBUG_LOG(
						"%s: ending read",
						name.c_str());
					continue;
				}

				if (t == STREAM_READ) {
					GNMI_C_CONNECTOR_DEBUG_LOG(
						"%s: STREAM_READ",
						name.c_str());
					if (rpc.on_read(resp)) {
						GNMI_C_CONNECTOR_DEBUG_LOG(
							"%s: read: cancelling",
							name.c_str());
						context.TryCancel();
						continue;
					}

					stream->Read(&resp,
						     (void *)STREAM_READ);
					continue;
				}
			}

			if (stop) {
				GNMI_C_CONNECTOR_DEBUG_LOG(
					"%s: shutting CQ down", name.c_str());
				cq->Shutdown();
			}

			/*
			 * 1) we MUST to drain after Shutdown and before CQ destruction
			 * 2) we need to drain before reuse
			 *	NOTE at this point there are no producers
			 */
			GNMI_C_CONNECTOR_DEBUG_LOG("%s: draining CQ",
						   name.c_str());
			while (cq->AsyncNext(&tag, &ok,
					     gpr_time_0(GPR_CLOCK_MONOTONIC)) ==
			       ::grpc::CompletionQueue::GOT_EVENT)
				;
		}

		GNMI_C_CONNECTOR_DEBUG_LOG("%s: exit", name.c_str());
		rpc.on_exit();
	}

	std::thread th{};
	std::unique_ptr< ::grpc::CompletionQueue> cq;
};

struct RpcGnmiSubscribe final {
	using RequestType = ::gnmi::SubscribeRequest;
	using ResponseType = ::gnmi::SubscribeResponse;

	RpcGnmiSubscribe(gnmi::gNMI::Stub *stub,
			 std::shared_ptr< ::grpc::ChannelInterface> chan,
			 std::string username, std::string password,
			 RequestType rq, gnmi_subscribe_cb cb, void *data)
		: stub{ stub }
		, chan{ chan }
		, username{ move(username) }
		, password{ move(password) }
		, cb{ cb }
		, data{ data }
		, rq{ rq }
	{
	}

	std::unique_ptr<
		::grpc::ClientAsyncReaderWriter<RequestType, ResponseType> >
	prepare_call(::grpc::ClientContext *context,
		     ::grpc::CompletionQueue *cq)
	{
		context->AddMetadata("username", username);
		context->AddMetadata("password", password);
		return stub->PrepareAsyncSubscribe(context, cq);
	}

	::grpc::ChannelInterface *channel()
	{
		return chan.get();
	}

	const RequestType &request()
	{
		return rq;
	}

	bool on_read(ResponseType &resp)
	{
		gnmi_subscribe_response r = {};
		std::vector<gnmi_subscribe_update> update;
		std::list<container_path> path_store;

		GNMI_C_CONNECTOR_DEBUG_LOG("new response");

		if (resp.has_sync_response()) {
			GNMI_C_CONNECTOR_DEBUG_LOG("resp.has_sync_response()");
			if (cb) {
				r.has_sync_response = 1;
				r.sync_response = resp.sync_response();
			}
		}

		if (resp.has_update()) {
			const ::gnmi::Notification &notif = resp.update();

			GNMI_C_CONNECTOR_DEBUG_LOG("resp.has_update() %d",
						   notif.update_size());

			r.update.timestamp = notif.timestamp();
			if (notif.has_prefix()) {
				path_store.emplace_back();
				gnmi2connector_path(&r.update.prefix,
						    path_store.back(),
						    notif.prefix());
				r.update.has_prefix = 1;
			}

			r.update.alias = notif.alias().c_str();
			update.reserve(notif.update_size());
			for (int i = 0; i < notif.update_size(); ++i) {
				const ::gnmi::Update &upd = notif.update(i);
				gnmi_subscribe_update u = {};

				if (upd.has_val()) {
					if (gnmi2connector_typed_value(
						    u.val, upd.val())) {
						GNMI_C_CONNECTOR_DEBUG_LOG(
							"failed to convert value");
						continue;
					}
					u.has_value = 1;
				}
				if (upd.has_path()) {
					path_store.emplace_back();
					gnmi2connector_path(&u.path,
							    path_store.back(),
							    upd.path());
					u.has_path = 1;
				}
				update.emplace_back(u);
			}
			r.update.update = update.data();
			r.update.update_size = update.size();
			r.has_update = 1;
		}

		if (cb)
			cb(&r, data);

		return false;
	}

	bool on_finish(const ::grpc::Status &status)
	{
		return status.error_code() ==
			       ::grpc::StatusCode::UNIMPLEMENTED ||
		       status.error_code() ==
			       ::grpc::StatusCode::INVALID_ARGUMENT ||
		       status.error_code() == ::grpc::StatusCode::UNKNOWN ||
		       status.error_code() == ::grpc::StatusCode::NOT_FOUND ||
		       status.error_code() ==
			       ::grpc::StatusCode::OUT_OF_RANGE ||
		       status.error_code() ==
			       ::grpc::StatusCode::UNAUTHENTICATED;
	}

	void on_exit()
	{
		if (cb)
			cb(0, data);
	}

    private:
	::gnmi::gNMI::Stub *stub{};
	std::shared_ptr< ::grpc::ChannelInterface> chan;
	std::string username;
	std::string password;
	gnmi_subscribe_cb cb{};
	void *data{};
	RequestType rq;
};

struct gnmi_subscribe {
	::gnmi::SubscribeRequest rq;
	std::unique_ptr<RpcStreamReader> rpc;
};

gnmi_subscribe *gnmi_subscribe_create(enum gnmi_subscribe_method method,
				      int updates_only)
{
	std::unique_ptr<gnmi_subscribe> res{ new gnmi_subscribe{} };
	auto &rq = res->rq;

	rq.mutable_subscribe()->set_encoding(::gnmi::JSON_IETF);

	rq.mutable_subscribe()->set_updates_only(!!updates_only);
	if (method == GNMI_SUBSCRIBE_METHOD_STREAM) {
		rq.mutable_subscribe()->set_mode(
			gnmi::SubscriptionList_Mode_STREAM);
	} else if (method == GNMI_SUBSCRIBE_METHOD_POLL) {
		rq.mutable_subscribe()->set_mode(
			gnmi::SubscriptionList_Mode_POLL);
	} else if (method == GNMI_SUBSCRIBE_METHOD_ONCE) {
		rq.mutable_subscribe()->set_mode(
			gnmi::SubscriptionList_Mode_ONCE);
	}

	return res.release();
}

int gnmi_subscribe_add(gnmi_subscribe *subscribe, const char *path,
		       enum gnmi_subscribe_mode mode)
{
	auto s = subscribe->rq.mutable_subscribe()->add_subscription();

	convertYangPath2ProtoPath(path, s->mutable_path());

	if (mode == GNMI_SUBSCRIBE_MODE_TARGET_DEFINED) {
		s->set_mode(gnmi::SubscriptionMode::TARGET_DEFINED);
	} else if (mode == GNMI_SUBSCRIBE_MODE_ON_CHANGE) {
		s->set_mode(gnmi::SubscriptionMode::ON_CHANGE);
	} else if (mode == GNMI_SUBSCRIBE_MODE_SAMPLE) {
		s->set_mode(gnmi::SubscriptionMode::SAMPLE);
	}

	return 0;
}

int gnmi_subscribe_start(gnmi_subscribe *s, gnmi_session *gs,
			 gnmi_subscribe_cb cb, void *data)
{
	gnmi_subscribe_stop(s);
	std::unique_ptr<RpcGnmiSubscribe> subscribe{ new RpcGnmiSubscribe{
		(*gs->stub).get(), gs->channel, *gs->username, *gs->password,
		s->rq, cb, data } };
	std::unique_ptr<RpcStreamReader> streamrpc{ new RpcStreamReader{} };

	streamrpc->start(move(subscribe), "<gnmi-subscription>");
	s->rpc = move(streamrpc);
	return 0;
}

void gnmi_subscribe_stop(gnmi_subscribe *s)
{
	if (s && s->rpc) {
		s->rpc->stop();
		s->rpc = nullptr;
	}
}

void gnmi_subscribe_destroy(gnmi_subscribe *s)
{
	gnmi_subscribe_stop(s);
	delete s;
}

int gnmi_gnoi_sonic_alarm_acknowledge(struct gnmi_session *gs, const char **id,
				      size_t count, int64_t timeout_us)
{
	size_t i;
	grpc::Status status;
	gnoi::SonicAlarm::AcknowledgeAlarmsRequest rq;
	gnoi::SonicAlarm::AcknowledgeAlarmsResponse resp;

	for (i = 0; i < count; ++i) {
		rq.mutable_input()->add_id(id[i]);
	}

	status = invoke_with_token(gs, [&](const std::string &token) {
		grpc::ClientContext context;
		context.AddMetadata("access_token", token);
		set_deadline_after_us(context, timeout_us);
		return (*gs->stub_gnoi_sonic_alarm)
			->AcknowledgeAlarms(&context, rq, &resp);
	});

	if (!status.ok()) {
		GNMI_C_CONNECTOR_DEBUG_LOG("Request failed");
		GNMI_C_CONNECTOR_DEBUG_LOG("Code: %d", status.error_code());
		return -1;
	}

	return 0;
}

int gnmi_gnoi_sonic_alarm_show(
	struct gnmi_session *gs,
	const struct gnmi_gnoi_sonic_alarm_show_request *request,
	struct gnmi_gnoi_sonic_alarm_show_response **response,
	int64_t timeout_us)
{
	size_t count, i;
	grpc::Status status;
	gnoi::SonicAlarm::ShowAlarmsRequest rq;
	gnoi::SonicAlarm::ShowAlarmsResponse resp;
	gnoi::SonicAlarm::ShowAlarmsRequest_Input_Id idopt;
	struct gnmi_gnoi_sonic_alarm_show_response *ret = 0;

	if (request->filter !=
	    gnmi_gnoi_sonic_alarm_show_request::
		    GNMI_GNOI_SONIC_ALARM_SHOW_REQUEST_FILTER_ID_RANGE) {
		GNMI_C_CONNECTOR_DEBUG_LOG("unsupported");
		return -1;
	}

	if (request->v.id.begin)
		*idopt.mutable_begin() = request->v.id.begin;
	if (request->v.id.end)
		*idopt.mutable_end() = request->v.id.end;

	*rq.mutable_input()->mutable_id() = idopt;

	status = invoke_with_token(gs, [&](const std::string &token) {
		grpc::ClientContext context;
		context.AddMetadata("access_token", token);
		set_deadline_after_us(context, timeout_us);
		return (*gs->stub_gnoi_sonic_alarm)
			->ShowAlarms(&context, rq, &resp);
	});

	if (!status.ok()) {
		GNMI_C_CONNECTOR_DEBUG_LOG("Request failed");
		GNMI_C_CONNECTOR_DEBUG_LOG("Code: %d", status.error_code());
		return -1;
	}

	count = 0;
	if (resp.has_output() && resp.output().has_alarm()) {
		count = resp.output().alarm().alarm_list_size();
	}

	ret = (decltype(ret))malloc(sizeof *ret + count * sizeof ret->alarm[0]);
	*ret = gnmi_gnoi_sonic_alarm_show_response{};
	for (i = 0; i < count; ++i) {
		struct gnmi_alarm *a = &ret->alarm[i];
		const auto &ga = resp.output().alarm().alarm_list(i);

		GNMI_C_CONNECTOR_DEBUG_LOG("received inited: %d",
					   ga.IsInitialized());
		GNMI_C_CONNECTOR_DEBUG_LOG("received id: %s", ga.id().c_str());
		GNMI_C_CONNECTOR_DEBUG_LOG("received resource: %s",
					   ga.resource().c_str());
		GNMI_C_CONNECTOR_DEBUG_LOG("received text: %s",
					   ga.text().c_str());
		GNMI_C_CONNECTOR_DEBUG_LOG("received type_id: %s",
					   ga.text().c_str());
		GNMI_C_CONNECTOR_DEBUG_LOG("received severity: %d",
					   (int)ga.severity());
		GNMI_C_CONNECTOR_DEBUG_LOG("received time_created: %ju",
					   (uintmax_t)ga.time_created());
		GNMI_C_CONNECTOR_DEBUG_LOG("received acknowledge_time: %ju",
					   (uintmax_t)ga.acknowledge_time());
		GNMI_C_CONNECTOR_DEBUG_LOG("received acknowledged: %d",
					   ga.acknowledged());

		*a = gnmi_alarm{};
		a->id = strdup(ga.id().c_str());
		a->resource = strdup(ga.resource().c_str());
		a->text = strdup(ga.text().c_str());
		a->type_id = strdup(ga.type_id().c_str());
		a->severity = (int)ga.severity();

		a->time_created = ga.time_created();
		a->acknowledge_time = ga.acknowledge_time();
		a->acknowledged = ga.acknowledged();
	}
	ret->status = resp.output().status();
	ret->count = count;

	*response = ret;
	return 0;
}

void gnmi_gnoi_sonic_alarm_show_response_free(
	struct gnmi_gnoi_sonic_alarm_show_response **response)
{
	size_t i;
	struct gnmi_gnoi_sonic_alarm_show_response *r;

	if (!response || !*response)
		return;

	r = *response;
	for (i = 0; i < r->count; ++i) {
		struct gnmi_alarm *a = &r->alarm[i];
		free((void *)a->type_id);
		free((void *)a->text);
		free((void *)a->resource);
		free((void *)a->id);
	}

	free(r);
	*response = 0;
}

void gnmi_path_dump(const struct gnmi_path *p)
{
	int ie, ik;
	GNMI_C_CONNECTOR_DEBUG_LOG("origin = %s", p->origin);
	for (ie = 0; ie < p->elem_size; ++ie) {
		GNMI_C_CONNECTOR_DEBUG_LOG("elem[%d].name = %s", ie,
					   p->elem[ie].name);
		for (ik = 0; ik < p->elem[ie].key_size; ++ik) {
			GNMI_C_CONNECTOR_DEBUG_LOG("elem[%d].key[%d].key = %s",
						   ie, ik,
						   p->elem[ie].key[ik].key);
			GNMI_C_CONNECTOR_DEBUG_LOG(
				"elem[%d].key[%d].value = %s", ie, ik,
				p->elem[ie].key[ik].value);
		}
	}
}

int gnmi_gnoi_poe_port_reset(struct gnmi_session *gs, const char *port,
			     int64_t timeout_us)
{
	gnoi::OpenconfigPoe::ResetPoeResponse gres;
	gnoi::OpenconfigPoe::ResetPoeRequest greq;
	grpc::Status status;

	greq.mutable_input()->set_interface_name(port);

	status = invoke_with_token(gs, [&](const std::string &token) {
		grpc::ClientContext context;
		context.AddMetadata("access_token", token);
		set_deadline_after_us(context, timeout_us);
		return (*gs->stub_gnoi_openconfig_poe)
			->ResetPoe(&context, greq, &gres);
	});
	if (!status.ok()) {
		GNMI_C_CONNECTOR_DEBUG_LOG("Request failed for %s", greq.mutable_input()->interface_name().c_str());
		GNMI_C_CONNECTOR_DEBUG_LOG("Code: %d", status.error_code());
		main_log_cb(gres.output().status_detail().c_str());
		return -1;
	}

	return 0;
}
