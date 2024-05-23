#ifndef LARCH_PLATFORM_PORT_HPP_
#define LARCH_PLATFORM_PORT_HPP_

#include <ucentral-platform.h>

#include <string>
#include <vector>

namespace larch {

struct port {
	std::string name;
};

std::vector<port> get_port_list();

void apply_port_config(plat_cfg *cfg);

} // namespace larch

#endif // !LARCH_PLATFORM_PORT_HPP_
