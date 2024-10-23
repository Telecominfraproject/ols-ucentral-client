#ifndef LARCH_PLATFORM_FDB_HPP_
#define LARCH_PLATFORM_FDB_HPP_

#include <ucentral-platform.h>

#include <vector>

namespace larch {

std::vector<plat_learned_mac_addr> get_learned_mac_addrs();

} // namespace larch

#endif // !LARCH_PLATFORM_FDB_HPP_
