#ifndef LARCH_PLATFORM_UTILS_HPP_
#define LARCH_PLATFORM_UTILS_HPP_

#include <grpcpp/grpcpp.h>
#include <httplib.h>

#include <gnmi.pb.h>

#include <optional>
#include <string>

namespace larch {

bool verify_response(const httplib::Result &result, bool expect_ok = true);

void convert_yang_path_to_proto(std::string yang_path, gnmi::Path *proto_path);

/**
 * @brief Get value by specified path.
 *
 * @return Optional containing the response if operation was successful, nullopt otherwise
 */
std::optional<std::string> gnmi_get(const std::string &yang_path);

/**
 * @brief Set the value by specified path.
 *
 * @return True if operation is successful, false otherwise
 */
bool gnmi_set(const std::string &yang_path, const std::string &json_data);

/**
 * @brief Verifier that marks all the certificates as valid.
 */
class certificate_verifier : public grpc::experimental::ExternalCertificateVerifier {
public:
	bool Verify(
	    grpc::experimental::TlsCustomVerificationCheckRequest *request,
	    std::function<void(grpc::Status)> callback,
	    grpc::Status *sync_status) override
	{
		(void)request;
		(void)callback;
		*sync_status = grpc::Status(grpc::StatusCode::OK, "");
		return true;
	}

	void Cancel(grpc::experimental::TlsCustomVerificationCheckRequest *) override {}
};
}

#endif // !LARCH_PLATFORM_UTILS_HPP_
