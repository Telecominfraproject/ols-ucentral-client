#include <utils.hpp>

#include <libs/httplib.h>

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
