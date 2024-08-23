#include <services.hpp>
#include <utils.hpp>

#include <nlohmann/json.hpp>

#define UC_LOG_COMPONENT UC_LOG_COMPONENT_PLAT
#include <ucentral-log.h>
#include <ucentral-platform.h>

#include <arpa/inet.h>

#include <array>
#include <string>
#include <unordered_set>

using nlohmann::json;

namespace larch {

static std::unordered_set<std::string> get_existing_ntp_servers()
{
	const json existing_servers_json = json::parse(
	    gnmi_get("/sonic-ntp:sonic-ntp/NTP_SERVER/NTP_SERVER_LIST"));

	std::unordered_set<std::string> existing_servers;

	if (existing_servers_json.contains("sonic-ntp:NTP_SERVER_LIST"))
	{
		for (const auto &server_json :
		     existing_servers_json.at("sonic-ntp:NTP_SERVER_LIST"))
		{
			if (!server_json.contains("server_address"))
				continue;

			existing_servers.insert(
			    server_json.at("server_address")
				.template get<std::string>());
		}
	}

	return existing_servers;
}

static void apply_ntp_config(const plat_ntp_cfg *ntp_cfg)
{
	if (ntp_cfg->servers)
	{
		gnmi_operation op;

		std::unordered_set<std::string> existing_servers =
		    get_existing_ntp_servers();

		json ntp_json;
		json &server_list_json = ntp_json["sonic-ntp:NTP_SERVER_LIST"];
		server_list_json = json::array();

		const plat_ntp_server *it = nullptr;
		UCENTRAL_LIST_FOR_EACH_MEMBER(it, &ntp_cfg->servers)
		{
			const auto existing_it =
			    existing_servers.find(it->hostname);

			if (existing_it != existing_servers.cend())
			{
				existing_servers.erase(existing_it);
				continue;
			}

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

		op.add_update(
		    "/sonic-ntp:sonic-ntp/NTP_SERVER/NTP_SERVER_LIST",
		    ntp_json.dump());

		for (const auto &server : existing_servers)
		{
			op.add_delete(
			    "/sonic-ntp:sonic-ntp/NTP_SERVER/"
			    "NTP_SERVER_LIST[server_address="
			    + server + "]");
		}

		op.execute();
	}
}

void apply_services_config(plat_cfg *cfg)
{
	apply_ntp_config(&cfg->ntp_cfg);
}

} // namespace larch
