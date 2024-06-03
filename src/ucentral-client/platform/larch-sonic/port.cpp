#include <port.hpp>
#include <utils.hpp>

#include <nlohmann/json.hpp>

#include <bitmap.h>
#define UC_LOG_COMPONENT UC_LOG_COMPONENT_PLAT
#include <ucentral-log.h>
#include <ucentral-platform.h>

#include <cstddef>
#include <cstdint>
#include <cstdio> // std::snprintf, std::sscanf
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility> // std::pair
#include <vector>

using nlohmann::json;

namespace larch {

std::vector<port> get_port_list()
{
	const json port_list_json =
	    json::parse(gnmi_get("/sonic-port:sonic-port/PORT/PORT_LIST"));

	std::vector<port> port_list;

	for (const auto port_json :
	     port_list_json.value("sonic-port:PORT_LIST", json::array()))
	{
		port &p = port_list.emplace_back();
		p.name = port_json.at("name").template get<std::string>();
	}

	return port_list;
}

static bool get_port_oper_status(const std::string &port_name)
{
	const json port_status_json = json::parse(gnmi_get(
	    "/openconfig-interfaces:interfaces/interface[name=" + port_name
	    + "]/state/oper-status"));

	const std::string port_status_str =
	    port_status_json["openconfig-interfaces:oper-status"]
		.template get<std::string>();

	if (port_status_str == "UP")
		return true;
	else if (port_status_str == "DOWN")
		return false;
	else
	{
		UC_LOG_ERR(
		    "Unknown port oper status: %s",
		    port_status_str.c_str());
		throw std::runtime_error{
		    "Unknown oper status: " + port_status_str};
	}
}

static void set_port_admin_state(const std::string &port_name, bool state)
{
	json port_state_json;
	port_state_json["openconfig-interfaces:config"]["enabled"] = state;

	gnmi_set(
	    "/openconfig-interfaces:interfaces/interface[name=" + port_name
		+ "]/config",
	    port_state_json.dump());
}

static std::uint32_t get_port_speed(const std::string &port_name)
{
	const json port_speed_json = json::parse(gnmi_get(
	    "/sonic-port:sonic-port/PORT/PORT_LIST[ifname=" + port_name
	    + "]/speed"));

	const std::string port_speed_str =
	    port_speed_json["sonic-port:speed"].template get<std::string>();

	std::uint32_t port_speed = 0;

	if (std::sscanf(port_speed_str.c_str(), "%u", &port_speed) < 1)
	{
		UC_LOG_ERR("Failed to parse port speed");
		throw std::runtime_error{"Failed to parse port speed"};
	}

	return port_speed;
}

static void set_port_speed(const std::string &port_name, std::uint32_t speed)
{
	auto speed_to_num = [](std::uint32_t speed) -> std::uint32_t {
		switch (speed)
		{
			case UCENTRAL_PORT_SPEED_10_E:
				return 10;
			case UCENTRAL_PORT_SPEED_100_E:
				return 100;
			case UCENTRAL_PORT_SPEED_1000_E:
				return 1000;
			case UCENTRAL_PORT_SPEED_2500_E:
				return 2500;
			case UCENTRAL_PORT_SPEED_5000_E:
				return 5000;
			case UCENTRAL_PORT_SPEED_10000_E:
				return 10000;
			case UCENTRAL_PORT_SPEED_25000_E:
				return 25000;
			case UCENTRAL_PORT_SPEED_40000_E:
				return 40000;
			case UCENTRAL_PORT_SPEED_100000_E:
				return 100000;

			default:
			{
				UC_LOG_ERR("Unknown port speed");
				throw std::runtime_error{"Unknown port speed"};
			}
		}
	};

	json port_speed_json;
	port_speed_json["name"] = port_name;
	port_speed_json["speed"] = speed_to_num(speed);

	json set_port_speed_json;
	set_port_speed_json["sonic-port:PORT_LIST"] = {port_speed_json};

	gnmi_set(
	    "/sonic-port:sonic-port/PORT/PORT_LIST[name=" + port_name + "]",
	    set_port_speed_json.dump());
}

static std::unordered_map<std::string, std::uint64_t>
get_port_counters(const std::string &port_name)
{
	const json port_counters_json = json::parse(gnmi_get(
	    "/openconfig-interfaces:interfaces/interface[name=" + port_name
	    + "]/state/counters"));

	std::unordered_map<std::string, std::uint64_t> counters;

	if (!port_counters_json.contains("openconfig-interfaces:counters"))
		return counters;

	for (const auto &item :
	     port_counters_json["openconfig-interfaces:counters"].items())
	{
		counters[item.key()] =
		    std::stoull(item.value().template get<std::string>());
	}

	return counters;
}

void apply_port_config(plat_cfg *cfg)
{
	std::size_t i = 0;

	BITMAP_FOR_EACH_BIT_SET(i, cfg->ports_to_cfg, MAX_NUM_OF_PORTS)
	{
		const plat_port &port = cfg->ports[i];

		const std::string port_name = "Ethernet" + std::to_string(i);
		const bool state = port.state == UCENTRAL_PORT_ENABLED_E;

		set_port_admin_state(port_name, state);

		if (state)
		{
			set_port_speed(port_name, port.speed);
		}
	}
}

std::pair<std::unique_ptr<plat_port_info[]>, std::size_t> get_port_info()
{
	std::vector<port> ports = get_port_list();

	auto ports_info = std::make_unique<plat_port_info[]>(ports.size());

	for (std::size_t i = 0; i < ports.size(); ++i)
	{
		const std::string &port_name = ports[i].name;
		plat_port_info &port_info = ports_info[i];

		std::snprintf(
		    port_info.name,
		    PORT_MAX_NAME_LEN,
		    "%s",
		    port_name.c_str());

		port_info.speed = get_port_speed(port_name);
		port_info.duplex = true;
		port_info.carrier_up = get_port_oper_status(port_name);

		// Get port counters
		const auto counters = get_port_counters(port_name);

		auto get_counter =
		    [&counters](const std::string &counter) -> std::uint64_t {
			const auto it = counters.find(counter);

			return it != counters.cend() ? it->second : 0;
		};

		auto &stats = port_info.stats;

		stats.collisions = 0;
		stats.multicast = 0;

		stats.rx_bytes = get_counter("in-octets");
		stats.rx_dropped = get_counter("in-discards");
		stats.rx_error = get_counter("in-errors");
		stats.rx_packets = get_counter("in-unicast-pkts")
				   + get_counter("in-multicast-pkts")
				   + get_counter("in-broadcast-pkts");

		stats.tx_bytes = get_counter("out-octets");
		stats.tx_dropped = get_counter("out-discards");
		stats.tx_error = get_counter("out-errors");
		stats.tx_packets = get_counter("out-unicast-pkts")
				   + get_counter("out-multicast-pkts")
				   + get_counter("out-broadcast-pkts");
	}

	return {std::move(ports_info), ports.size()};
}

} // namespace larch
