#include <utils.hpp>

#include <string>
#include <vector>
#include <utility> // std::move

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
