#ifndef LARCH_PLATFORM_UTILS_HPP_
#define LARCH_PLATFORM_UTILS_HPP_

#include <libs/httplib.h>

#include <gnmi.pb.h>

#include <string>

bool verify_response(const httplib::Result &result, bool expect_ok = true);

void convert_yang_path_to_proto(std::string yang_path, gnmi::Path *proto_path);

#endif // !LARCH_PLATFORM_UTILS_HPP_
