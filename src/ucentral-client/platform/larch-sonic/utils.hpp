#ifndef LARCH_PLATFORM_UTILS_HPP_
#define LARCH_PLATFORM_UTILS_HPP_

#include <grpcpp/grpcpp.h>
#include <httplib.h>

#include <gnmi.pb.h>

#include <string>

namespace larch {

bool verify_response(const httplib::Result &result, bool expect_ok = true);

void convert_yang_path_to_proto(std::string yang_path, gnmi::Path *proto_path);

/**
 * @brief Get value by specified path.
 *
 * @throw std::runtime_error If get request wasn't successful
 */
std::string gnmi_get(const std::string &yang_path);

/**
 * @brief Convenience wrapper to set only one entry.
 *
 * @throw std::runtime_error If set request wasn't successful
*/
void gnmi_set(std::string yang_path, std::string json_data);

class gnmi_operation {
public:
	gnmi_operation() = default;

	void add_update(const std::string &yang_path, const std::string &json_data);
	void add_delete(const std::string &yang_path);

	/**
	 * @brief Execute the previously added modifications.
	 *
	 * @throw std::runtime_error If set request wasn't successful
	 */
	void execute();

protected:
	gnmi::SetRequest set_request_;
};

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
