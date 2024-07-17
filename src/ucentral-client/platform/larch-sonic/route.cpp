#include <route.hpp>
#include <sai_redis.hpp>
#include <state.hpp>
#include <utils.hpp>

#include <nlohmann/json.hpp>
#include <sw/redis++/redis++.h>

#define UC_LOG_COMPONENT UC_LOG_COMPONENT_PLAT
#include <router-utils.h>
#include <ucentral-log.h>
#include <ucentral-platform.h>

#include <arpa/inet.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator> // std::inserter
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using nlohmann::json;

namespace larch {

static std::string fib_key_to_str(const ucentral_router_fib_key &fib_key)
{
	std::array<char, INET_ADDRSTRLEN + 1> ip_buf{};

	if (!inet_ntop(AF_INET, &fib_key.prefix, ip_buf.data(), ip_buf.size()))
		throw std::runtime_error{
		    "Failed to convert FIB prefix from binary to text form"};

	std::string ip{ip_buf.data()};
	ip += "/" + std::to_string(fib_key.prefix_len);

	return ip;
}

void create_route(
    std::uint16_t router_id,
    const ucentral_router_fib_key &fib_key,
    const ucentral_router_fib_info &fib_info)
{
	// VRF is not supported
	if (router_id != 0)
		return;

	json route_json;

	route_json["prefix"] = fib_key_to_str(fib_key);
	route_json["vrf-name"] = "default";

	switch (fib_info.type)
	{
		case ucentral_router_fib_info::UCENTRAL_ROUTE_BLACKHOLE:
		{
			route_json["blackhole"] = "true,false";
			break;
		}

		case ucentral_router_fib_info::UCENTRAL_ROUTE_CONNECTED:
		{
			route_json["ifname"] =
			    "Vlan" + std::to_string(fib_info.connected.vid);
			break;
		}

		case ucentral_router_fib_info::UCENTRAL_ROUTE_NH:
		{
			route_json["ifname"] =
			    "Vlan" + std::to_string(fib_info.nh.vid);

			std::array<char, INET_ADDRSTRLEN + 1> ip_buf{};

			if (!inet_ntop(
				AF_INET,
				&fib_info.nh.gw,
				ip_buf.data(),
				ip_buf.size()))
			{
				throw std::runtime_error{
				    "Failed to convert gateway address from "
				    "binary to text form"};
			}

			break;
		}

		default:
		{
			return;
		}
	}

	json add_route_json;
	add_route_json["sonic-static-route:sonic-static-route"]["STATIC_ROUTE"]
		      ["STATIC_ROUTE_LIST"] = {route_json};

	gnmi_set(
	    "/sonic-static-route:sonic-static-route/",
	    add_route_json.dump());
}

void remove_route(
    std::uint16_t router_id,
    const ucentral_router_fib_key &fib_key)
{
	// VRF is not supported
	if (router_id != 0)
		return;

	gnmi_operation op;

	op.add_delete(
	    "/sonic-static-route:sonic-static-route/STATIC_ROUTE/"
	    "STATIC_ROUTE_LIST[prefix="
	    + fib_key_to_str(fib_key) + "][vrf-name=default]");

	op.execute();
}

std::vector<ucentral_router_fib_node> get_routes(std::uint16_t router_id)
{
	// VRF is not supported
	if (router_id != 0)
		return {};

	const json static_routes_json =
	    json::parse(gnmi_get("/sonic-static-route:sonic-static-route/"
				 "STATIC_ROUTE/STATIC_ROUTE_LIST"));

	std::vector<ucentral_router_fib_node> routes;

	for (const auto &route_json : static_routes_json.value(
		 "sonic-static-route:STATIC_ROUTE_LIST",
		 json::array()))
	{
		if (route_json.contains("vrf-name")
		    && route_json.at("vrf-name").template get<std::string>()
			   != "default")
		{
			continue;
		}

		if (!route_json.contains("prefix"))
			continue;

		ucentral_router_fib_info fib_info{};

		// For now only blackhole is supported
		if (route_json.contains("blackhole"))
			fib_info.type =
			    ucentral_router_fib_info::UCENTRAL_ROUTE_BLACKHOLE;
		else
			continue;

		ucentral_router_fib_key fib_key{};

		const int ret = inet_net_pton(
		    AF_INET,
		    route_json.at("prefix").template get<std::string>().c_str(),
		    &fib_key.prefix,
		    sizeof(fib_key.prefix));

		if (ret == -1)
			continue;

		fib_key.prefix_len = ret;

		routes.push_back({fib_key, fib_info});
	}

	return routes;
}

struct router_interface {
	std::string mac;
	sai::object_id port_oid;
};

static std::optional<router_interface>
parse_router_interface(const sai::object_id &oid)
{
	router_interface router_if{};

	std::unordered_map<std::string, std::string> entry;

	state->redis_asic->hgetall(
	    "ASIC_STATE:SAI_OBJECT_TYPE_ROUTER_INTERFACE:" + oid,
	    std::inserter(entry, entry.begin()));

	try
	{
		if (entry.at("SAI_ROUTER_INTERFACE_ATTR_TYPE")
		    != "SAI_ROUTER_INTERFACE_TYPE_PORT")
		{
			// Other types are not supported
			return std::nullopt;
		}

		router_if.mac =
		    entry.at("SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS");
		router_if.port_oid =
		    entry.at("SAI_ROUTER_INTERFACE_ATTR_PORT_ID");
	}
	catch (const std::out_of_range &ex)
	{
		return std::nullopt;
	}

	return router_if;
}

std::vector<plat_gw_address> get_gw_addresses()
{
	const auto port_name_mapping = sai::get_port_name_mapping();

	std::vector<plat_gw_address> gw_addresses;

	std::int64_t cursor = 0;
	std::unordered_set<std::string> keys;

	do
	{
		constexpr std::string_view pattern =
		    "ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY:*";

		keys.clear();

		cursor = state->redis_asic->scan(
		    cursor,
		    pattern,
		    std::inserter(keys, keys.begin()));

		for (const auto &key : keys)
		{
			const json route_json =
			    json::parse(key.substr(pattern.size() - 1));

			plat_gw_address gw_addr{};

			// Get IP
			const std::string ip =
			    route_json.at("dest").template get<std::string>();

			if (inet_pton(AF_INET, ip.c_str(), &gw_addr.ip) != 1)
			{
				UC_LOG_ERR(
				    "Failed to parse GW IP address %s",
				    ip.c_str());
				continue;
			}

			std::unordered_map<std::string, std::string> entry;

			state->redis_asic->hgetall(
			    key,
			    std::inserter(entry, entry.begin()));

			const auto router_it =
			    entry.find("SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID");

			if (router_it == entry.cend())
				continue;

			auto router_if_opt =
			    parse_router_interface(router_it->second);

			if (!router_if_opt)
				continue;

			// Get MAC
			std::strncpy(
			    gw_addr.mac,
			    router_if_opt->mac.c_str(),
			    std::size(gw_addr.mac) - 1);

			// Get port name
			const auto port_name_it =
			    port_name_mapping.find(router_if_opt->port_oid);

			if (port_name_it == port_name_mapping.cend())
				continue;

			std::strncpy(
			    gw_addr.port,
			    port_name_it->second.c_str(),
			    std::size(gw_addr.port) - 1);

			gw_addresses.push_back(gw_addr);
		}
	} while (cursor != 0);

	return gw_addresses;
}

void apply_route_config(plat_cfg *cfg)
{
	ucentral_router old_router{}, new_router{};

	// Save the old router
	old_router = state->router;

	// Load new router, this also does the necessary allocations
	if (ucentral_router_fib_db_copy(&cfg->router, &new_router) != 0)
		throw std::runtime_error{"Failed to copy FIB DB"};

	if (!old_router.sorted)
		ucentral_router_fib_db_sort(&old_router);
	if (!new_router.sorted)
		ucentral_router_fib_db_sort(&new_router);

	std::size_t old_idx = 0, new_idx = 0;
	int diff = 0;

	for_router_db_diff(&new_router, &old_router, new_idx, old_idx, diff)
	{
		diff = router_db_diff_get(
		    &new_router,
		    &old_router,
		    new_idx,
		    old_idx);

		if (diff_case_upd(diff))
		{
			if (!ucentral_router_fib_info_cmp(
				&router_db_get(&old_router, old_idx)->info,
				&router_db_get(&new_router, new_idx)->info))
				continue;

			const auto &node = *router_db_get(&new_router, new_idx);

			remove_route(0, node.key);
			create_route(0, node.key, node.info);
		}

		if (diff_case_del(diff))
		{
			remove_route(
			    0,
			    router_db_get(&old_router, old_idx)->key);
		}

		if (diff_case_add(diff))
		{
			const auto &node = *router_db_get(&new_router, new_idx);
			create_route(0, node.key, node.info);
		}
	}

	ucentral_router_fib_db_free(&old_router);
	state->router = new_router;
}

} // namespace larch
