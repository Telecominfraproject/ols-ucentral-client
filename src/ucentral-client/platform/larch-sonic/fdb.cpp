#include <fdb.hpp>
#include <sai_redis.hpp>
#include <state.hpp>

#include <nlohmann/json.hpp>
#include <sw/redis++/redis++.h>

#include <ucentral-platform.h>

#include <cstdint>
#include <cstdio>   // std::snprintf
#include <iterator> // std:inserter
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using nlohmann::json;

namespace larch {

std::vector<plat_learned_mac_addr> get_learned_mac_addrs()
{
	const auto bridge_mapping = sai::get_bridge_port_mapping();
	const auto port_name_mapping = sai::get_port_name_mapping();
	std::unordered_map<sai::object_id, std::uint16_t> vlan_cache;

	std::vector<plat_learned_mac_addr> learned_mac_addrs;

	std::int64_t cursor = 0;
	std::unordered_set<std::string> keys;

	do
	{
		constexpr std::string_view pattern =
		    "ASIC_STATE:SAI_OBJECT_TYPE_FDB_ENTRY:*";

		keys.clear();

		cursor = state->redis_asic->scan(
		    cursor,
		    pattern,
		    std::inserter(keys, keys.begin()));

		for (const auto &key : keys)
		{
			plat_learned_mac_addr learned_entry{};
			std::unordered_map<std::string, std::string> entry;

			// Get port name
			state->redis_asic->hgetall(
			    key,
			    std::inserter(entry, entry.begin()));

			if (entry.at("SAI_FDB_ENTRY_ATTR_TYPE")
			    == "SAI_FDB_ENTRY_TYPE_STATIC")
				continue;

			const auto port_it = bridge_mapping.find(
			    entry.at("SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID")
				.substr(sai::oid_prefix.size()));

			if (port_it == bridge_mapping.cend())
				continue;

			const auto interface_it =
			    port_name_mapping.find(port_it->second);

			const std::string interface_name =
			    (interface_it != port_name_mapping.cend())
				? interface_it->second
				: port_it->second;

			// Get VLAN ID
			std::uint16_t vlan_id{};

			const json fdb_json =
			    json::parse(key.substr(pattern.size() - 1));

			if (fdb_json.contains("vlan"))
			{
				vlan_id = static_cast<std::uint16_t>(std::stoul(
				    fdb_json.at("vlan")
					.template get<std::string>()));
			}
			else
			{
				if (!fdb_json.contains("bvid"))
					continue;

				std::string vlan_oid =
				    fdb_json.at("bvid")
					.template get<std::string>()
					.substr(sai::oid_prefix.size());

				const auto vlan_it = vlan_cache.find(vlan_oid);

				if (vlan_it != vlan_cache.cend())
				{
					// VLAN is found in cache, using it
					vlan_id = vlan_it->second;
				}
				else
				{
					auto vlan_id_opt =
					    sai::get_vlan_by_oid(vlan_oid);

					if (!vlan_id_opt)
						continue;

					vlan_id = *vlan_id_opt;

					vlan_cache.try_emplace(
					    std::move(vlan_oid),
					    std::move(*vlan_id_opt));
				}
			}

			std::snprintf(
			    learned_entry.port,
			    PORT_MAX_NAME_LEN,
			    "%s",
			    interface_name.c_str());

			learned_entry.vid = vlan_id;

			std::snprintf(
			    learned_entry.mac,
			    PLATFORM_MAC_STR_SIZE,
			    "%s",
			    fdb_json.at("mac")
				.template get<std::string>()
				.c_str());

			learned_mac_addrs.push_back(learned_entry);
		}
	} while (cursor != 0);

	return learned_mac_addrs;
}

} // namespace larch
