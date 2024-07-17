#ifndef LARCH_PLATFORM_ROUTE_HPP_
#define LARCH_PLATFORM_ROUTE_HPP_

#include <router-utils.h>
#include <ucentral-platform.h>

#include <cstdint>
#include <vector>

namespace larch {

void create_route(
    std::uint16_t router_id,
    const ucentral_router_fib_key &fib_key,
    const ucentral_router_fib_info &fib_info);

void remove_route(
    std::uint16_t router_id,
    const ucentral_router_fib_key &fib_key);

std::vector<ucentral_router_fib_node> get_routes(std::uint16_t router_id);

std::vector<plat_gw_address> get_gw_addresses();

void apply_route_config(plat_cfg *cfg);

} // namespace larch

#endif // !LARCH_PLATFORM_ROUTE_HPP_
