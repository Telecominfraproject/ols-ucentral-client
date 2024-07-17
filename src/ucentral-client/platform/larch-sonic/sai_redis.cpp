#include <sai_redis.hpp>
#include <state.hpp>

#include <sw/redis++/redis++.h>

#include <cstddef>
#include <cstdint>
#include <iterator> // std::inserter
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace larch::sai {

std::unordered_map<object_id, object_id> get_bridge_port_mapping()
{
	std::unordered_map<object_id, object_id> mapping;

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

		keys.clear();

		cursor = state->redis_asic->scan(
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

std::unordered_map<object_id, std::string> get_port_name_mapping()
{
	std::unordered_map<std::string, std::string> entry;

	state->redis_counters->hgetall(
	    "COUNTERS_PORT_NAME_MAP",
	    std::inserter(entry, entry.begin()));

	state->redis_counters->hgetall(
	    "COUNTERS_LAG_NAME_MAP",
	    std::inserter(entry, entry.begin()));

	std::unordered_map<object_id, std::string> mapping;

	for (auto it = entry.cbegin(); it != entry.cend();)
	{
		// TO-DO: validate interface name?
		auto node = entry.extract(it++);

		mapping.try_emplace(
		    node.mapped().substr(oid_prefix.size()),
		    std::move(node.key()));
	}

	return mapping;
}

std::optional<std::uint16_t> get_vlan_by_oid(const object_id &oid)
{
	std::int64_t cursor = 0;
	std::unordered_set<std::string> keys;

	const std::string pattern =
	    "ASIC_STATE:SAI_OBJECT_TYPE_VLAN:" + std::string{oid_prefix} + oid;

	// There is no guarantee that the necessary key will be found during the
	// first scan, so we need to scan until we find it
	do
	{
		keys.clear();

		cursor = state->redis_asic->scan(
		    cursor,
		    pattern,
		    std::inserter(keys, keys.begin()));

		if (keys.empty())
			continue;

		std::unordered_map<std::string, std::string> entry;

		state->redis_asic->hgetall(
		    *keys.begin(),
		    std::inserter(entry, entry.begin()));

		const auto it = entry.find("SAI_VLAN_ATTR_VLAN_ID");

		if (it == entry.cend())
			return std::nullopt;

		try
		{
			return static_cast<std::uint16_t>(
			    std::stoul(it->second));
		}
		catch (const std::logic_error &)
		{
			throw std::runtime_error{"Failed to parse VLAN ID"};
		}
		{}
	} while (cursor != 0);

	throw std::runtime_error{"Failed to get VLAN by object ID"};
}

} // namespace larch::sai
