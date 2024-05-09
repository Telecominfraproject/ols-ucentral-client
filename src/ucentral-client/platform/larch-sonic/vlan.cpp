#include <vlan.hpp>
#include <utils.hpp>

#include <nlohmann/json.hpp>

#include <ucentral-platform.h>

#include <bitset>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <tuple>
#include <utility> // std::move

using nlohmann::json;

namespace larch {

std::tuple<std::vector<std::bitset<MAX_NUM_OF_PORTS>>, std::vector<std::bitset<MAX_NUM_OF_PORTS>>> get_vlan_membership()
{
    std::vector<std::bitset<MAX_NUM_OF_PORTS>> vlan_membership(MAX_VLANS);
	std::vector<std::bitset<MAX_NUM_OF_PORTS>> vlan_tagged(MAX_VLANS);

    const auto vlan_membership_result = gnmi_get("/sonic-vlan:sonic-vlan/VLAN_MEMBER/VLAN_MEMBER_LIST");

    if (!vlan_membership_result)
        throw std::runtime_error{"Failed to get VLAN membership data via gNMI"};
    
    const json vlan_membership_json = json::parse(*vlan_membership_result, nullptr, false);

    for (const auto entry : vlan_membership_json.at("sonic-vlan:VLAN_MEMBER_LIST"))
    {
        std::uint16_t vlan_id{};
        std::uint16_t port_id{};

        if (NAME_TO_VLAN(&vlan_id, entry.at("name").template get<std::string>().c_str()) < 1)
        {
            throw std::runtime_error{"Failed to parse VLAN ID"};
        }

        if (NAME_TO_PID(&port_id, entry.at("port").template get<std::string>().c_str()) < 1)
        {
            throw std::runtime_error{"Failed to parse port ID"};
        }

        vlan_membership[vlan_id].set(port_id);

        if (entry.at("tagging_mode").template get<std::string>() == "tagged")
            vlan_tagged[vlan_id].set(port_id);
    }

    return {std::move(vlan_membership), std::move(vlan_tagged)};
}

bool apply_vlan_config(struct plat_cfg *cfg)
{
	// Get current VLAN membership data
	

	return true;
}

}
