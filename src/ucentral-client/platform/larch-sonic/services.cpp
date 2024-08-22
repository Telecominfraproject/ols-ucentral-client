#include <services.hpp>
#include <utils.hpp>

#include <nlohmann/json.hpp>

#define UC_LOG_COMPONENT UC_LOG_COMPONENT_PLAT
#include <ucentral-log.h>
#include <ucentral-platform.h>

#include <arpa/inet.h>

#include <array>

using nlohmann::json;

namespace larch {

static void apply_ntp_config(const plat_ntp_cfg *ntp_cfg)
{
	if (ntp_cfg->servers)
	{
		json ntp_json;
		json &server_list_json = ntp_json["sonic-ntp:NTP_SERVER_LIST"];
		server_list_json = json::array();

		const plat_ntp_server *it = nullptr;
		UCENTRAL_LIST_FOR_EACH_MEMBER(it, &ntp_cfg->servers)
		{
			std::array<unsigned char, sizeof(in6_addr)> addr_buf{};

			if (inet_pton(AF_INET, it->hostname, addr_buf.data())
				!= 1
			    && inet_pton(
				   AF_INET6,
				   it->hostname,
				   addr_buf.data())
				   != 1)
			{
				UC_LOG_ERR(
				    "Domains are not supported in NTP server "
				    "list, use IP addresses");
				continue;
			}

			json server_json;
			server_json["association_type"] = "server";
			server_json["server_address"] = it->hostname;
			server_json["resolve_as"] = it->hostname;

			server_list_json.push_back(server_json);
		}

		gnmi_set(
		    "/sonic-ntp:sonic-ntp/NTP_SERVER/NTP_SERVER_LIST",
		    ntp_json.dump());
	}
}

void apply_services_config(plat_cfg *cfg)
{
	apply_ntp_config(&cfg->ntp_cfg);
}

} // namespace larch
