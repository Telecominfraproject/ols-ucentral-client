#include <igmp.hpp>
#include <utils.hpp>

#include <nlohmann/json.hpp>

#define UC_LOG_COMPONENT UC_LOG_COMPONENT_PLAT
#include <ucentral-log.h>

#include <string>

using nlohmann::json;
using namespace std;

namespace larch {

typedef enum {
    GNMI_IGMP_VERSION_NA = 0,
    GNMI_IGMP_VERSION_1 = 1,
    GNMI_IGMP_VERSION_2 = 2,
    GNMI_IGMP_VERSION_3 = 3
} gnmi_igmp_version_t;

static void disable_igmp_snooping(uint16_t vid)
{
    gnmi_operation op;

    const auto igmp_snooping_list
        = gnmi_get ("/sonic-igmp-snooping:sonic-igmp-snooping/CFG_L2MC_TABLE/"
                    "CFG_L2MC_TABLE_LIST");
    const json igmp_snooping_list_json = json::parse(igmp_snooping_list);

    /* There are no IGMP-snoooping */
    if (!igmp_snooping_list_json.contains("sonic-igmp-snooping:CFG_L2MC_TABLE_LIST"))
        return;

    /* Delete igmp-snooping config for specific VLAN. */
    op.add_delete("/sonic-igmp-snooping:sonic-igmp-snooping/CFG_L2MC_TABLE/CFG_L2MC_TABLE_LIST[vlan-name=Vlan" + to_string(vid) + "]");

    op.execute();
}

static void set_igmp_snooping(uint16_t vid, struct plat_igmp *igmp)
{
    bool enabled = igmp->snooping_enabled || igmp->querier_enabled;
    gnmi_igmp_version_t gnmi_igmp_version = GNMI_IGMP_VERSION_NA;
    gnmi_operation op;

    if (!enabled)
    {
        disable_igmp_snooping(vid);
        return;
    }

    if (igmp->version == PLAT_IGMP_VERSION_1)
        gnmi_igmp_version = GNMI_IGMP_VERSION_1;
    else if (igmp->version == PLAT_IGMP_VERSION_2)
        gnmi_igmp_version = GNMI_IGMP_VERSION_2;
    else if (igmp->version == PLAT_IGMP_VERSION_3)
        gnmi_igmp_version = GNMI_IGMP_VERSION_3;
    else
    {
        UC_LOG_ERR("Failed IGMP version");
        throw std::runtime_error{"Failed IGMP version"};
    }

    /* Config IGMP-snooping */
    json igmp_snooping_list_json;

    igmp_snooping_list_json["vlan-name"] = "Vlan" + to_string(vid);
    igmp_snooping_list_json["enabled"] = igmp->snooping_enabled;
    igmp_snooping_list_json["querier"] = igmp->querier_enabled;

    if (igmp->querier_enabled)
    {
        igmp_snooping_list_json["query-interval"] = igmp->query_interval;
        igmp_snooping_list_json["query-max-response-time"] = igmp->max_response_time;
        igmp_snooping_list_json["last-member-query-interval"] = igmp->last_member_query_interval;
        if (gnmi_igmp_version != GNMI_IGMP_VERSION_NA)
        {
            igmp_snooping_list_json["version"] = igmp->version;
        }
    }

    if (igmp->snooping_enabled) {
        igmp_snooping_list_json["fast-leave"] = igmp->fast_leave_enabled;
    }

    json add_igmp_snooping_list_json;
    add_igmp_snooping_list_json["sonic-igmp-snooping:CFG_L2MC_TABLE_LIST"] = {igmp_snooping_list_json};

    op.add_update("/sonic-igmp-snooping:sonic-igmp-snooping/CFG_L2MC_TABLE/CFG_L2MC_TABLE_LIST", add_igmp_snooping_list_json.dump());

    op.execute();
}

static void set_igmp_static_groups(uint16_t vid, struct plat_igmp *igmp)
{
    struct plat_ports_list *port_node = NULL;
    size_t group_idx;
    gnmi_operation op;

    for (group_idx = 0; group_idx < igmp->num_groups; group_idx++)
    {
        const std::string ip_addr = addr_to_str(igmp->groups[group_idx].addr);

        json igmp_static_group_json;

        igmp_static_group_json["vlan-name"] = "Vlan" + to_string(vid);
        igmp_static_group_json["group-addr"] = ip_addr;

        json out_intf_list_json = json::array();
        UCENTRAL_LIST_FOR_EACH_MEMBER(port_node, &igmp->groups[group_idx].egress_ports_list)
        {
            out_intf_list_json.push_back(port_node->name);
        }
        igmp_static_group_json["out-intf"] = out_intf_list_json;

        json add_igmp_static_group_json;
        add_igmp_static_group_json["sonic-igmp-snooping:CFG_L2MC_STATIC_GROUP_TABLE_LIST"] = {igmp_static_group_json};

        op.add_update("/sonic-igmp-snooping:sonic-igmp-snooping/CFG_L2MC_STATIC_GROUP_TABLE/CFG_L2MC_STATIC_GROUP_TABLE_LIST", add_igmp_static_group_json.dump());
    }

    op.execute();
}

void apply_igmp_config(uint16_t vid, struct plat_igmp *igmp)
{
    set_igmp_snooping(vid, igmp);
    if (igmp->num_groups > 0)
    {
        set_igmp_static_groups(vid, igmp);
    }
}

}
