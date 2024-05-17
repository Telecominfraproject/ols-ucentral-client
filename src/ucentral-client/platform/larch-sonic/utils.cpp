#include <state.hpp>
#include <utils.hpp>

#include <gnmi.grpc.pb.h>
#include <gnmi.pb.h>

#include <grpcpp/grpcpp.h>

#include <stdexcept>
#include <string>
#include <utility> // std::move
#include <vector>

namespace larch {

bool verify_response(const httplib::Result &result, bool expect_ok)
{
	if (!result)
		return false;

	if (expect_ok && result->status != 200)
		return false;

	// Check if content type header starts with the specified type
	if (result->get_header_value("Content-Type").rfind("application/json", 0) != 0)
		return false;

	return true;
}

void convert_yang_path_to_proto(std::string yang_path, gnmi::Path *proto_path)
{
	std::string::size_type pos{};
	std::vector<std::string> elements;

	while ((pos = yang_path.find('/')) != std::string::npos)
	{
		std::string elem{yang_path.substr(0, pos)};

		if (!elem.empty())
			elements.push_back(std::move(elem));

		yang_path.erase(0, pos + 1);
	}

	// Add the last part of split string
	elements.push_back(yang_path);

	std::string &first_element = elements[0];
	const auto colon_pos = first_element.find(':');

	if (colon_pos != std::string::npos)
	{
		proto_path->set_origin(first_element.substr(0, colon_pos));
		first_element.erase(0, colon_pos + 1);
	}

	for (const auto &elem : elements)
	{
		gnmi::PathElem *path_elem = proto_path->add_elem();
		path_elem->set_name(elem);
	}
}

std::string gnmi_get(const std::string &yang_path)
{
	gnmi::GetRequest greq;
	greq.set_encoding(gnmi::JSON_IETF);

	convert_yang_path_to_proto(yang_path, greq.add_path());

	grpc::ClientContext context;
	gnmi::GetResponse gres;
	const grpc::Status status = state->gnmi_stub->Get(&context, greq, &gres);

	if (!status.ok())
	{
		throw std::runtime_error{
		    "gNMI get operation wasn't successful: "
		    + status.error_message() + "; error code "
		    + std::to_string(status.error_code())};
	}

	if (gres.notification_size() != 1)
	{
		throw std::runtime_error{"Unsupported notification size"};
	}

	gnmi::Notification notification = gres.notification(0);
	if (notification.update_size() != 1)
	{
		throw std::runtime_error{"Unsupported update size"};
	}

	gnmi::Update update = notification.update(0);
	if (!update.has_val())
	{
		throw std::runtime_error{"Empty value"};
	}

	gnmi::TypedValue value = update.val();
	if (!value.has_json_ietf_val())
	{
		throw std::runtime_error{"Empty JSON value"};
	}

	return value.json_ietf_val();
}

void gnmi_set(std::string yang_path, std::string json_data)
{
	gnmi_operation op;
	op.add_update(yang_path, json_data);
	op.execute();
}

void gnmi_operation::add_update(const std::string &yang_path, const std::string &json_data)
{
	gnmi::Update *update = set_request_.add_update();
	convert_yang_path_to_proto(yang_path, update->mutable_path());
	update->mutable_val()->set_json_ietf_val(json_data);
}

void gnmi_operation::add_delete(const std::string &yang_path)
{
	convert_yang_path_to_proto(yang_path, set_request_.add_delete_());
}

void gnmi_operation::execute()
{
	grpc::ClientContext context;
	gnmi::SetResponse response;

	const grpc::Status status = state->gnmi_stub->Set(&context, set_request_, &response);

	set_request_.Clear();

	if (!status.ok())
	{
		throw std::runtime_error{
		    "gNMI set operation wasn't successful: "
			+ status.error_message() + "; error code "
			+ std::to_string(status.error_code())};
	}
}

}
