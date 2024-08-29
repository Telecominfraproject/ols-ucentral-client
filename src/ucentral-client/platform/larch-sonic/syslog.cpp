#include <syslog.hpp>
#include <utils.hpp>

#include <nlohmann/json.hpp>

#define UC_LOG_COMPONENT UC_LOG_COMPONENT_PLAT
#include <ucentral-log.h>
#include <ucentral-platform.h>

#include <string>

using nlohmann::json;

namespace larch {

void gnma_syslog_cfg_clear(void)
{
    std::string path = "/sonic-syslog:sonic-syslog/SYSLOG_SERVER/SYSLOG_SERVER_LIST";

    gnmi_operation op;
    op.add_delete(path);
    op.execute();
}

void apply_syslog_config(struct plat_syslog_cfg *cfg, int count)
{
    std::string path = "/sonic-syslog:sonic-syslog/SYSLOG_SERVER/SYSLOG_SERVER_LIST";
    const std::array<std::string, 8> priority2str = {
        "crit",
        "crit",
        "crit",
        "error",
        "warn",
        "notice",
        "info",
        "debug"
        };
    int i;

    gnmi_operation op;

    for (i = 0; i < count; ++i)
    {
        json syslog_cfg_member_json;
        syslog_cfg_member_json["server_address"] = cfg[i].host;
        syslog_cfg_member_json["port"] = cfg[i].port;
        syslog_cfg_member_json["protocol"] = cfg[i].is_tcp ? "tcp" : "udp";
        syslog_cfg_member_json["severity"] = priority2str.at(cfg[i].priority);
        syslog_cfg_member_json["vrf"] = "default";

        json add_syslog_cfg_member_json;
        add_syslog_cfg_member_json["sonic-syslog:SYSLOG_SERVER_LIST"] = {syslog_cfg_member_json};

        op.add_update(path, add_syslog_cfg_member_json.dump());
    }

    gnma_syslog_cfg_clear();
    op.execute();
}

}
