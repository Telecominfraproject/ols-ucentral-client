#include <vlan.hpp>
#include <utils.hpp>

#include <nlohmann/json.hpp>

#include <ucentral-platform.h>

#include <bitset>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <tuple>
#include <utility> // std::move

using nlohmann::json;

namespace larch {

void delete_nonconfig_vlans(BITMAP_DECLARE(vlans_to_cfg, MAX_VLANS))
{
    const auto vlan_list_result = gnmi_get("/sonic-vlan:sonic-vlan/VLAN/VLAN_LIST");

    if (!vlan_list_result)
        throw std::runtime_error{"Failed to get VLAN list via gNMI"};

    gnmi_operation op;
    const json vlan_list_json = json::parse(*vlan_list_result, nullptr, false);

    for (const auto vlan : vlan_list_json.at("sonic-vlan:VLAN_LIST"))
    {
        const int vlan_id = vlan.at("vlanid").template get<int>();

        if (vlan_id < MAX_VLANS)
        {
            if (BITMAP_TEST_BIT(vlans_to_cfg, vlan_id))
                continue;

            if (vlan_id == FIRST_VLAN)
                continue;

            op.add_delete("/sonic-vlan:sonic-vlan/VLAN/VLAN_LIST[name=Vlan" + std::to_string(vlan_id) + "]");
        }
    }

    if (!op.execute())
        throw std::runtime_error{"Failed to delete VLANs via gNMI"};
}

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

bool apply_vlan_config(plat_cfg *cfg)
{
    // Step 1: delete VLANs that currently exist, but are not present in the supplied config
    delete_nonconfig_vlans(cfg->vlans_to_cfg);

    const auto [vlan_membership, vlan_tagged] = get_vlan_membership();

    gnmi_operation op;

    std::size_t i{};
    BITMAP_FOR_EACH_BIT_SET(i, cfg->vlans_to_cfg, MAX_VLANS)
    {
        const plat_port_vlan *vlan = &cfg->vlans[i];

        // Step 2: create the VLAN
        json vlan_json;
        vlan_json["vlanid"] = vlan->id;
        vlan_json["name"] = "Vlan" + std::to_string(vlan->id);

        json add_vlan_json;
	    add_vlan_json["sonic-vlan:VLAN_LIST"] = {vlan_json};

        op.add_update("/sonic-vlan:sonic-vlan/VLAN/VLAN_LIST", add_vlan_json.dump());

        // Step 3: delete VLAN members that are not in the config
        std::bitset<MAX_NUM_OF_PORTS> vlan_members_config;
        std::bitset<MAX_NUM_OF_PORTS> vlan_tagged_config;

        for (plat_vlan_memberlist *pv = vlan->members_list_head; pv; pv = pv->next)
        {
            std::uint16_t port_id{};

            if (NAME_TO_PID(&port_id, pv->port.name) < 1)
                throw std::runtime_error{"Failed to parse port ID"};

            vlan_members_config.set(port_id);

            if (pv->tagged)
                vlan_tagged_config.set(port_id);
        }

        // Get bits that are set in the first bitset, but not set in the second one
        const auto vlan_members_to_delete = vlan_membership[vlan->id] & ~vlan_members_config;

        for (std::size_t port_id = 0; port_id < vlan_members_to_delete.size(); ++port_id)
        {
            if (vlan_members_to_delete[port_id])
            {
                op.add_delete(
                    "/sonic-vlan:sonic-vlan/VLAN_MEMBER/VLAN_MEMBER_LIST[name=Vlan"
                    + std::to_string(i) + "][port=Ethernet" + std::to_string(port_id) + "]");
            }
        }

        // Step 4: add VLAN members
        for (std::size_t port_id = 0; port_id < vlan_members_config.size(); ++port_id)
        {
            if (!vlan_members_config[port_id])
                continue;

            const bool tagged = vlan_tagged_config.test(port_id);

            // VLAN member is already configured in the same way as in the config, skipping
            if (vlan_membership[vlan->id].test(port_id) && tagged == vlan_tagged[vlan->id].test(port_id))
                continue;

            json vlan_member_json;
            vlan_member_json["name"] = "Vlan" + std::to_string(vlan->id);
            vlan_member_json["port"] = "Ethernet" + std::to_string(port_id);
            vlan_member_json["tagging_mode"] = tagged ? "tagged" : "untagged";

            json add_vlan_member_json;
            add_vlan_member_json["sonic-vlan:VLAN_MEMBER_LIST"] = {vlan_member_json};

            op.add_update("/sonic-vlan:sonic-vlan/VLAN_MEMBER/VLAN_MEMBER_LIST", add_vlan_member_json.dump());
        }
    }

	return op.execute();
}

}
