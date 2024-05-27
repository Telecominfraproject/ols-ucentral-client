#include <state.hpp>
#include <utils.hpp>

#include <gnmi.grpc.pb.h>
#include <gnmi.pb.h>

#include <grpcpp/grpcpp.h>

#include <map>
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

std::map<std::string, std::string> parse_kv(const std::string &kv_str)
{
	enum class parse_state { open_bracket, close_bracket, key, value };

	parse_state state = parse_state::close_bracket;
	std::map<std::string, std::string> kv;

	std::string key_buf, value_buf;

	for (const char c : kv_str)
	{
		switch (c)
		{
			case '[':
				if (state != parse_state::close_bracket)
					throw std::runtime_error{
					    "Unexpected opening bracket"};

				state = parse_state::open_bracket;
				break;

			case ']':
				if (state != parse_state::value)
					throw std::runtime_error{
					    "Unexpected closing bracket"};

				state = parse_state::close_bracket;

				if (key_buf.empty())
					throw std::runtime_error{"Empty key"};

				if (value_buf.empty())
					throw std::runtime_error{"Empty value"};

				kv.emplace(
				    std::move(key_buf),
				    std::move(value_buf));
				key_buf.clear();
				value_buf.clear();

				break;

			case '=':
				if (state != parse_state::key)
					throw std::runtime_error{
					    "Unexpected equals sign"};

				state = parse_state::value;
				break;

			default:
			{
				if (state == parse_state::open_bracket)
					state = parse_state::key;

				if (state == parse_state::key)
					key_buf.push_back(c);
				else if (state == parse_state::value)
					value_buf.push_back(c);
				else
					throw std::runtime_error{
					    "Unexpected character '"
					    + std::string{c} + "'"};

				break;
			}
		}
	}

	if (state != parse_state::close_bracket)
		throw std::runtime_error{"Couldn't find closing bracket"};

	return kv;
}

void convert_yang_path_to_proto(std::string yang_path, gnmi::Path *proto_path)
{
	struct path_element {
		std::string name;
		std::map<std::string, std::string> kv;
	};

	std::vector<path_element> elements;

	auto process_elem_str = [&elements](std::string elem_str) {
		if (!elem_str.empty())
		{
			const auto open_bracket_pos = elem_str.find('[');

			if (open_bracket_pos == std::string::npos)
			{
				elements.push_back({std::move(elem_str), {}});
			}
			else
			{
				// Parse the key-value part of YANG path
				// (e.g. [Vlan=100][SomeKey=SomeValue]...)
				try
				{
					elements.push_back(
					    {elem_str.substr(
						 0,
						 open_bracket_pos),
					     parse_kv(elem_str.substr(
						 open_bracket_pos))});
				}
				catch (const std::runtime_error &ex)
				{
					using namespace std::string_literals;
					throw std::runtime_error{
					    "Failed to parse key-value part of YANG path: "s
					    + ex.what()};
				}
			}
		}
	};

	std::string::size_type pos{};
	while ((pos = yang_path.find('/')) != std::string::npos)
	{
		process_elem_str(yang_path.substr(0, pos));

		yang_path.erase(0, pos + 1);
	}

	// Process the last part of split string
	process_elem_str(std::move(yang_path));

	std::string &first_element = elements[0].name;
	const auto colon_pos = first_element.find(':');

	if (colon_pos != std::string::npos)
	{
		proto_path->set_origin(first_element.substr(0, colon_pos));
		first_element.erase(0, colon_pos + 1);
	}

	for (const auto &elem : elements)
	{
		gnmi::PathElem *path_elem = proto_path->add_elem();
		path_elem->set_name(elem.name);

		if (!elem.kv.empty())
		{
			auto path_kv = path_elem->mutable_key();

			for (const auto &[key, value] : elem.kv)
				(*path_kv)[key] = value;
		}
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

void gnmi_set(const std::string &yang_path, const std::string &json_data)
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
