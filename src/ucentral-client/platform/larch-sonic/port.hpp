#ifndef LARCH_PLATFORM_PORT_HPP_
#define LARCH_PLATFORM_PORT_HPP_

#include <ucentral-platform.h>

#include <cstddef>
#include <memory>
#include <string>
#include <utility> // std::pair
#include <vector>

namespace larch {

struct port {
	std::string name;
};

std::vector<port> get_port_list();

void apply_port_config(plat_cfg *cfg);

std::pair<std::unique_ptr<plat_port_info[]>, std::size_t> get_port_info();

} // namespace larch

#endif // !LARCH_PLATFORM_PORT_HPP_
