#include <port.hpp>
#include <utils.hpp>

#include <nlohmann/json.hpp>

#include <bitmap.h>
#define UC_LOG_COMPONENT UC_LOG_COMPONENT_PLAT
#include <ucentral-log.h>
#include <ucentral-platform.h>

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>

using nlohmann::json;

namespace larch {

void set_port_admin_state(std::uint16_t port_id, bool state)
{
	json port_state_json;
	port_state_json["openconfig-interfaces:config"]["enabled"] = true;

	gnmi_set(
	    "/openconfig-interfaces:interfaces/interface[name=Ethernet"
		+ std::to_string(port_id) + "]/config",
	    port_state_json.dump());
}

void set_port_speed(std::uint16_t port_id, std::uint32_t speed)
{
	auto speed_to_str = [](std::uint32_t speed) {
		switch (speed)
		{
			case UCENTRAL_PORT_SPEED_10_E:
				return "10";
			case UCENTRAL_PORT_SPEED_100_E:
				return "100";
			case UCENTRAL_PORT_SPEED_1000_E:
				return "1000";
			case UCENTRAL_PORT_SPEED_2500_E:
				return "2500";
			case UCENTRAL_PORT_SPEED_5000_E:
				return "5000";
			case UCENTRAL_PORT_SPEED_10000_E:
				return "10000";
			case UCENTRAL_PORT_SPEED_25000_E:
				return "25000";
			case UCENTRAL_PORT_SPEED_40000_E:
				return "40000";
			case UCENTRAL_PORT_SPEED_100000_E:
				return "100000";

			default:
			{
				UC_LOG_ERR("Unknown port speed");
				throw std::runtime_error{"Unknown port speed"};
			}
		}
	};

	const std::string port_name = "Ethernet" + std::to_string(port_id);

	json port_speed_json;
	port_speed_json["ifname"] = port_name;
	port_speed_json["speed"] = speed_to_str(speed);

	json set_port_speed_json;
	set_port_speed_json["sonic-port:PORT_LIST"] = {port_speed_json};

	gnmi_set(
	    "/sonic-port:sonic-port/PORT/PORT_LIST[ifname=" + port_name + "]",
	    set_port_speed_json.dump());
}

void apply_port_config(plat_cfg *cfg)
{
	std::size_t i = 0;

	BITMAP_FOR_EACH_BIT_SET(i, cfg->ports_to_cfg, MAX_NUM_OF_PORTS)
	{
		const plat_port &port = cfg->ports[i];
		const bool state = port.state == UCENTRAL_PORT_ENABLED_E;

		set_port_admin_state(i, state);

		if (state)
		{
			set_port_speed(i, port.speed);
		}
	}
}

} // namespace larch
