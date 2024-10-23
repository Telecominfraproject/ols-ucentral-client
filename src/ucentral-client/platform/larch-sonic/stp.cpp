#include <stp.hpp>
#include <utils.hpp>

#include <nlohmann/json.hpp>

#define UC_LOG_COMPONENT UC_LOG_COMPONENT_PLAT
#include <ucentral-log.h>

#include <string>

using nlohmann::json;

namespace larch {

void apply_stp_config(struct plat_cfg *cfg)
{
    std::size_t i = 0;
    gnmi_operation op;

    switch (cfg->stp_mode) {
    case PLAT_STP_MODE_NONE:
    {
        const auto stp_list = gnmi_get("/sonic-spanning-tree:sonic-spanning-tree/STP/STP_LIST");
        const json stp_list_json = json::parse(stp_list);

        /* There are no STPs */
        if (!stp_list_json.contains("sonic-spanning-tree:STP_LIST"))
            return;

        /* This will clear all per port/vlan stp entries */
        /* Delete global config since you cannot change the stp mode otherwise */
        op.add_delete("/sonic-spanning-tree:sonic-spanning-tree/STP/STP_LIST[keyleaf=GLOBAL]");

        break;
    }
    case PLAT_STP_MODE_PVST:
    {
        /* Config mode */
        json stp_cfg_mode_json;

        stp_cfg_mode_json["priority"] = cfg->stp_instances[0].priority;
        stp_cfg_mode_json["keyleaf"] = "GLOBAL";
        stp_cfg_mode_json["bpdu_filter"] = false;
        stp_cfg_mode_json["mode"] = "pvst";
        stp_cfg_mode_json["rootguard_timeout"] = 30;

        json add_stp_cfg_mode_json;
        add_stp_cfg_mode_json["sonic-spanning-tree:STP_LIST"] = {stp_cfg_mode_json};        

        op.add_update("/sonic-spanning-tree:sonic-spanning-tree/STP/STP_LIST", add_stp_cfg_mode_json.dump());

        /* Once mode enabled - create entries for all ports */
        BITMAP_FOR_EACH_BIT_SET(i, cfg->ports_to_cfg, MAX_NUM_OF_PORTS)
        {
            json stp_port_json;

            stp_port_json["ifname"] = "Ethernet" + std::to_string(i);
            stp_port_json["enabled"] = true;

            json add_stp_port_json;
            add_stp_port_json["sonic-spanning-tree:STP_PORT_LIST"] = {stp_port_json};        

            op.add_update("/sonic-spanning-tree:sonic-spanning-tree/STP_PORT/STP_PORT_LIST", add_stp_port_json.dump());
        }

        /* Config vlans */
        for (i = FIRST_VLAN; i < MAX_VLANS; i++) {
            if (!cfg->stp_instances[i].enabled) {
                continue;
            }

            json stp_vlan_json;
            stp_vlan_json["vlanid"] = i;
            stp_vlan_json["name"] = "Vlan" + std::to_string(i);
            stp_vlan_json["enabled"] = cfg->stp_instances[i].enabled;
            stp_vlan_json["priority"] = cfg->stp_instances[i].priority;
            stp_vlan_json["forward_delay"] = cfg->stp_instances[i].forward_delay;
            stp_vlan_json["hello_time"] = cfg->stp_instances[i].hello_time;
            stp_vlan_json["max_age"] = cfg->stp_instances[i].max_age;

            json add_stp_vlan_json;
            add_stp_vlan_json["sonic-spanning-tree:STP_VLAN_LIST"] = {stp_vlan_json};

            UC_LOG_DBG(
                "set vlan=%d state.enabled=%d state.priority=%d "
                "state.forward_delay=%d state.hello_time=%d "
                "state.max_age=%d ",
                i,
                cfg->stp_instances[i].enabled,
                cfg->stp_instances[i].priority,
                cfg->stp_instances[i].forward_delay,
                cfg->stp_instances[i].hello_time,
                cfg->stp_instances[i].max_age);

            op.add_update("/sonic-spanning-tree:sonic-spanning-tree/STP_VLAN/STP_VLAN_LIST", add_stp_vlan_json.dump());
        }
        
        break;
    }
    default:
        throw std::runtime_error{"Failed apply stp config"};
    }

    op.execute();
}

}
