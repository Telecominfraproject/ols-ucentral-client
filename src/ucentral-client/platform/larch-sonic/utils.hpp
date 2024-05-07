#ifndef LARCH_PLATFORM_UTILS_HPP_
#define LARCH_PLATFORM_UTILS_HPP_

#include <libs/httplib.h>

bool verify_response(const httplib::Result &result, bool expect_ok = true);

#endif // !LARCH_PLATFORM_UTILS_HPP_
