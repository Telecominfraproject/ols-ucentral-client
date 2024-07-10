#include <port.hpp>
#include <state.hpp>
#include <utils.hpp>

#include <nlohmann/json.hpp>

#include <bitmap.h>
#define UC_LOG_COMPONENT UC_LOG_COMPONENT_PLAT
#include <ucentral-log.h>
#include <ucentral-platform.h>

#include <arpa/inet.h>

#include <algorithm> // std::find_if
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio> // std::snprintf, std::sscanf
#include <cstring>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility> // std::move
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
	std::string port_status_data;

	try
	{
		port_status_data = gnmi_get(
		    "/openconfig-interfaces:interfaces/interface[name="
		    + port_name + "]/state/oper-status");
	}
	catch (const gnmi_exception &ex)
	{
		// For some reason there's no oper-status field in the gNMI
		// response when carrier is down
		return false;
	}

	const json port_status_json = json::parse(port_status_data);

	const std::string port_status_str =
	    port_status_json.at("openconfig-interfaces:oper-status")
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
	    "/sonic-port:sonic-port/PORT/PORT_LIST[name=" + port_name
	    + "]/speed"));

	return port_speed_json["sonic-port:speed"]
	    .template get<std::uint32_t>();
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

static plat_port_lldp_peer_info get_lldp_peer_info(const std::string &port_name)
{
	/*
	 * Actually, more specific YANG path should be used here
	 * (/openconfig-lldp:lldp/interfaces/interface[name=<interface>]/neighbors/neighbor[id=<interface>])
	 * but for some reason gNMI response for this path is empty, so the
	 * workaround is to make more generic request and filter the response
	 * and find necessary data.
	 */
	const json lldp_json = json::parse(gnmi_get(
	    "/openconfig-lldp:lldp/interfaces/interface[name=" + port_name
	    + "]"));

	const auto &neighbors = lldp_json.at("openconfig-lldp:interface")
				    .at(0)
				    .at("neighbors")
				    .at("neighbor");

	const auto neighbor_it = std::find_if(
	    neighbors.cbegin(),
	    neighbors.cend(),
	    [&port_name](const auto &neighbor) {
		    return neighbor.at("id").template get<std::string>()
			   == port_name;
	    });

	if (neighbor_it == neighbors.cend())
	{
		throw std::runtime_error{"Failed to find LLDP neighbor"};
	}

	plat_port_lldp_peer_info peer_info{};

	for (const auto &cap : neighbor_it->at("capabilities").at("capability"))
	{
		const std::string name =
		    cap.at("name").template get<std::string>();

		const bool enabled =
		    cap.at("state").at("enabled").template get<bool>();

		if (name == "openconfig-lldp-types:MAC_BRIDGE")
			peer_info.capabilities.is_bridge = enabled;
		else if (name == "openconfig-lldp-types:ROUTER")
			peer_info.capabilities.is_router = enabled;
		else if (name == "openconfig-lldp-types:WLAN_ACCESS_POINT")
			peer_info.capabilities.is_wlan_ap = enabled;
		else if (name == "openconfig-lldp-types:STATION_ONLY")
			peer_info.capabilities.is_station = enabled;
	}

	const json &state = neighbor_it->at("state");

	std::strncpy(
	    peer_info.name,
	    state.at("system-name").template get<std::string>().c_str(),
	    std::size(peer_info.name) - 1);
	std::strncpy(
	    peer_info.description,
	    state.at("system-description").template get<std::string>().c_str(),
	    std::size(peer_info.description) - 1);
	std::strncpy(
	    peer_info.mac,
	    state.at("chassis-id").template get<std::string>().c_str(),
	    std::size(peer_info.mac) - 1);
	std::strncpy(
	    peer_info.port,
	    neighbor_it->at("id").template get<std::string>().c_str(),
	    std::size(peer_info.port) - 1);

	// Parse management addresses
	const auto addresses = split_string(
	    state.at("management-address").template get<std::string>(),
	    ",");

	for (std::size_t i = 0; i < UCENTRAL_PORT_LLDP_PEER_INFO_MAX_MGMT_IPS;
	     ++i)
	{
		if (i >= addresses.size())
			break;

		const char *address = addresses[i].c_str();

		// Verify that retrieved address is either valid IPv4 or IPv6
		// address. If so - copy it to peer_info.
		bool success = false;
		std::array<unsigned char, sizeof(in6_addr)> addr_buf{};

		if (inet_pton(AF_INET, address, addr_buf.data()) == 1)
			success = true;
		else if (inet_pton(AF_INET6, address, addr_buf.data()) == 1)
			success = true;

		if (success)
			std::strncpy(
			    peer_info.mgmt_ips[i],
			    address,
			    INET6_ADDRSTRLEN);
	}

	return peer_info;
}

std::vector<plat_ipv4> get_port_addresses(const port &p)
{
	// TO-DO: should gnmi_exception be caught (this would mean that there're
	// no addresses assigned to interface)?
	const json addresses_json = json::parse(gnmi_get(
	    "/openconfig-interfaces:interfaces/interface[name=" + p.name
	    + "]/subinterfaces/subinterface[index=0]/openconfig-if-ip:ipv4/"
	      "addresses"));

	if (!addresses_json.contains("openconfig-if-ip:addresses"))
		return {};

	std::vector<plat_ipv4> addresses;

	for (const auto &address_json :
	     addresses_json.at("openconfig-if-ip:addresses")
		 .value("address", json::array()))
	{
		const json &config_json = address_json.at("config");

		const std::string address_str =
		    config_json.at("ip").template get<std::string>();

		plat_ipv4 address{};

		if (inet_pton(AF_INET, address_str.c_str(), &address.subnet)
		    != 1)
		{
			UC_LOG_ERR(
			    "Failed to parse interface IP address: %s",
			    address_str.c_str());
			continue;
		}

		address.subnet_len = config_json.at("prefix-length")
					 .template get<std::int32_t>();

		if (address.subnet_len < 0 || address.subnet_len > 32)
		{
			UC_LOG_ERR(
			    "Incorrect subnet length: %d (address %s)",
			    address.subnet_len,
			    address_str.c_str());
			continue;
		}

		address.exist = true;

		addresses.push_back(std::move(address));
	}

	return addresses;
}

static void
add_port_address(const std::string &port_name, const plat_ipv4 &address)
{
	const std::string addr_str = addr_to_str(address.subnet);

	json address_json;
	address_json["ip"] = addr_str;
	address_json["config"]["ip"] = addr_str;
	address_json["config"]["prefix-length"] = address.subnet_len;

	json port_json;
	port_json["index"] = 0;
	port_json["openconfig-if-ip:ipv4"]["addresses"]["address"] = {
	    address_json};

	json add_port_json;
	add_port_json["openconfig-interfaces:subinterface"] = {port_json};

	gnmi_set(
	    "/openconfig-interfaces:interfaces/interface[name=" + port_name
		+ "]/subinterfaces/subinterface",
	    add_port_json.dump());
}

static void
delete_port_address(const std::string &port_name, const plat_ipv4 &address)
{
	const std::string addr_str = addr_to_str(address.subnet);

	gnmi_operation op;

	op.add_delete(
	    "/openconfig-interfaces:interfaces/interface[name=" + port_name
	    + "]/subinterfaces/subinterface[index=0]/openconfig-if-ip:ipv4/"
	      "addresses/address[ip="
	    + addr_str + "]");

	op.execute();
}

void apply_port_config(plat_cfg *cfg)
{
	std::size_t i = 0;

	BITMAP_FOR_EACH_BIT_SET(i, cfg->ports_to_cfg, MAX_NUM_OF_PORTS)
	{
		const plat_port &port = cfg->ports[i];

		const std::string port_name = "Ethernet" + std::to_string(i);
		const bool admin_state = port.state == UCENTRAL_PORT_ENABLED_E;

		set_port_admin_state(port_name, admin_state);

		if (admin_state)
		{
			set_port_speed(port_name, port.speed);
		}

		/*
		 * Configure the interface address
		 */
		const plat_ipv4 &address = cfg->portsl2[i].ipv4;
		plat_ipv4 &port_addr = state->interfaces_addrs.at(i);

		if (address.exist)
		{
			if (!port_addr.exist
			    || port_addr.subnet.s_addr != address.subnet.s_addr
			    || port_addr.subnet_len != address.subnet_len)
			{
				if (port_addr.exist)
				{
					delete_port_address(
					    port_name,
					    port_addr);
				}

				add_port_address(port_name, address);

				port_addr = address;
			}
		}
		else if (port_addr.exist)
		{
			delete_port_address(port_name, port_addr);

			port_addr = plat_ipv4{false};
		}
	}
}

std::vector<plat_port_info> get_port_info()
{
	std::vector<port> ports = get_port_list();

	std::vector<plat_port_info> ports_info(ports.size());

	std::size_t i = 0;
	for (auto &port_info : ports_info)
	{
		const std::string &port_name = ports[i++].name;

		std::snprintf(
		    port_info.name,
		    PORT_MAX_NAME_LEN,
		    "%s",
		    port_name.c_str());

		port_info.speed = get_port_speed(port_name);
		port_info.duplex = true;
		port_info.carrier_up = get_port_oper_status(port_name);

		// Get port counters
		std::unordered_map<std::string, std::uint64_t> counters;

		try
		{
			counters = get_port_counters(port_name);
		}
		catch (const gnmi_exception &ex)
		{
			UC_LOG_ERR(
			    "Couldn't get counters for port %s: %s",
			    port_name.c_str(),
			    ex.what());
		}

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

		try
		{
			port_info.lldp_peer_info =
			    get_lldp_peer_info(port_name);

			port_info.has_lldp_peer_info = 1;
		}
		catch (const std::exception &ex)
		{
			UC_LOG_DBG(
			    "Couldn't get LLDP peer info: %s",
			    ex.what());
		}
	}

	return ports_info;
}

} // namespace larch
