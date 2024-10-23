/**
 * @file sai_redis.hpp
 * @brief Commonly used functions to interact with SAI via Redis DB.
 *
 * Note, that object IDs (OIDs) are used without "oid:0x" prefix.
 */

#ifndef LARCH_PLATFORM_SAI_REDIS_HPP_
#define LARCH_PLATFORM_SAI_REDIS_HPP_

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace larch::sai {

using object_id = std::string;

inline constexpr std::string_view oid_prefix = "oid:0x";

/**
 * @brief Get mapping of bridge port OIDs to port OIDs.
 *
 * @return Map with bridge port OID as a key and port OID as a value.
 */
std::unordered_map<object_id, object_id> get_bridge_port_mapping();

/**
 * @brief Get mapping of port OIDs to port names.
 *
 * @return Map with port OID and port name as a value.
 */
std::unordered_map<object_id, std::string> get_port_name_mapping();

/**
 * @brief Get VLAN ID by its OID.
 *
 * @throw std::runtime_error If VLAN can't be found
 */
std::optional<std::uint16_t> get_vlan_by_oid(const object_id &oid);

} // namespace larch::sai

#endif // !LARCH_PLATFORM_SAI_REDIS_HPP_
