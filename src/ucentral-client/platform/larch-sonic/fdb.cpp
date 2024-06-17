#include <fdb.hpp>
#include <state.hpp>

#include <nlohmann/json.hpp>
#include <sw/redis++/redis++.h>

#include <ucentral-platform.h>

#include <cstddef>
#include <cstdio>   // std::snprintf
#include <iterator> // std:inserter
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using nlohmann::json;

namespace larch {

constexpr std::string_view oid_prefix = "oid:0x";

/**
 * @brief Get mapping of port object IDs to port IDs.
 */
static std::unordered_map<std::string, std::string> get_port_mapping()
{
	std::unordered_map<std::string, std::string> mapping;

	std::int64_t cursor = 0;
	std::unordered_set<std::string> keys;

	do
	{
		constexpr std::string_view pattern =
		    "ASIC_STATE:SAI_OBJECT_TYPE_BRIDGE_PORT:*";

		// Example key is
		// ASIC_STATE:SAI_OBJECT_TYPE_BRIDGE_PORT:oid:0x3a000000000616
		// and we need to get only the 3a00... part. -1 here is for the
		// trailing '*' at the end of the pattern.
		constexpr std::size_t offset =
		    pattern.size() - 1 + oid_prefix.size();

		state->redis_asic->scan(
		    cursor,
		    pattern,
		    std::inserter(keys, keys.begin()));

		for (const auto &key : keys)
		{
			std::unordered_map<std::string, std::string> entry;

			state->redis_asic->hgetall(
			    key,
			    std::inserter(entry, entry.begin()));

			const auto it =
			    entry.find("SAI_BRIDGE_PORT_ATTR_PORT_ID");

			if (it != entry.cend())
			{
				mapping[key.substr(offset)] =
				    it->second.substr(oid_prefix.size());
			}
		}
	} while (cursor != 0);

	return mapping;
}

/**
 * @brief Get mapping of interface object IDs to interface names.
 */
static std::unordered_map<std::string, std::string> get_interface_mapping()
{
	std::unordered_map<std::string, std::string> entry;

	state->redis_counters->hgetall(
	    "COUNTERS_PORT_NAME_MAP",
	    std::inserter(entry, entry.begin()));

	std::unordered_map<std::string, std::string> mapping;

	for (auto it = entry.cbegin(); it != entry.cend();)
	{
		// TO-DO: validate interface name?
		auto node = entry.extract(it++);

		mapping.try_emplace(
		    std::move(node.mapped()),
		    std::move(node.key()));
	}

	return mapping;
}

/**
 * @brief Get VLAN ID from the bridge VLAN object ID.
 */
static std::optional<std::string> get_vlan_id(const std::string &object_id)
{
	std::int64_t cursor = 0;
	std::unordered_set<std::string> keys;

	const std::string pattern =
	    "ASIC_STATE:SAI_OBJECT_TYPE_VLAN:" + object_id;

	state->redis_asic->scan(
	    cursor,
	    pattern,
	    std::inserter(keys, keys.begin()));

	if (keys.empty())
		throw std::runtime_error{"Failed to get VLAN by object ID"};

	std::unordered_map<std::string, std::string> entry;

	state->redis_asic->hgetall(
	    *keys.begin(),
	    std::inserter(entry, entry.begin()));

	const auto it = entry.find("SAI_VLAN_ATTR_VLAN_ID");

	return it != entry.cend() ? std::make_optional(it->second)
				  : std::nullopt;
}

std::vector<plat_learned_mac_addr> get_learned_mac_addrs()
{
	const auto port_mapping = get_port_mapping();
	const auto interface_mapping = get_interface_mapping();
	std::unordered_map<std::string, std::string> vlan_cache;

	std::vector<plat_learned_mac_addr> learned_mac_addrs;

	std::int64_t cursor = 0;
	std::unordered_set<std::string> keys;

	do
	{
		constexpr std::string_view pattern =
		    "ASIC_STATE:SAI_OBJECT_TYPE_FDB_ENTRY:*";

		state->redis_asic->scan(
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

			const auto port_it = port_mapping.find(
			    entry.at("SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID")
				.substr(oid_prefix.size()));

			if (port_it == port_mapping.cend())
				continue;

			std::string interface_name;

			const auto interface_it =
			    interface_mapping.find(port_it->second);

			interface_name =
			    (interface_it != interface_mapping.cend())
				? interface_it->second
				: port_it->second;

			// Get VLAN ID
			std::string vlan_id;

			const json fdb_json =
			    json::parse(key.substr(pattern.size() - 1));

			if (fdb_json.contains("vlan"))
			{
				vlan_id = fdb_json.at("vlan")
					      .template get<std::string>();
			}
			else
			{
				if (!fdb_json.contains("bvid"))
					continue;

				std::string vlan_object_id =
				    fdb_json.at("bvid")
					.template get<std::string>();

				const auto vlan_it =
				    vlan_cache.find(vlan_object_id);

				if (vlan_it != vlan_cache.cend())
				{
					// VLAN is found in cache, using it
					vlan_id = vlan_it->second;
				}
				else
				{
					auto vlan_id_opt =
					    get_vlan_id(vlan_object_id);

					if (!vlan_id_opt)
						continue;

					vlan_id = *vlan_id_opt;

					vlan_cache.try_emplace(
					    std::move(vlan_object_id),
					    std::move(*vlan_id_opt));
				}
			}

			std::snprintf(
			    learned_entry.port,
			    PORT_MAX_NAME_LEN,
			    "%s",
			    interface_name.c_str());

			learned_entry.vid = std::stoi(vlan_id);

			std::snprintf(
			    learned_entry.mac,
			    PLATFORM_MAC_STR_SIZE,
			    "%s",
			    fdb_json.at("mac").template get<std::string>());

			learned_mac_addrs.push_back(learned_entry);
		}
	} while (cursor != 0);

	return learned_mac_addrs;
}

} // namespace larch
