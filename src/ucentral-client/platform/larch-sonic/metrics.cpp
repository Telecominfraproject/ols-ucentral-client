#include <fdb.hpp>
#include <metrics.hpp>
#include <port.hpp>
#include <route.hpp>

#include <nlohmann/json.hpp>

#define UC_LOG_COMPONENT UC_LOG_COMPONENT_PLAT
#include <ucentral-log.h>
#include <ucentral-platform.h>

#include <sys/sysinfo.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>  // std::setw
#include <iterator> // std::begin, std::size
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility> // std::move

using nlohmann::json;

namespace larch {

namespace {
	const std::string metrics_config_path =
	    "/var/lib/ucentral/metrics_cfg.json";
}

static plat_system_info get_system_info()
{
	plat_system_info system_info{};

	// Get load average
	std::array<double, std::size(system_info.load_average)> load_average{};

	if (getloadavg(load_average.data(), load_average.size()) < 0)
	{
		UC_LOG_ERR("Failed to get load average");
	}
	else
	{
		for (double &elem : load_average)
			elem /= 100.0;

		std::copy(
		    load_average.cbegin(),
		    load_average.cend(),
		    std::begin(system_info.load_average));
	}

	// Get RAM cached
	std::ifstream is{"/proc/meminfo"};
	if (!is)
	{
		UC_LOG_ERR("Failed to get memory info");
	}
	else
	{
		std::string line;
		std::uint64_t cached = 0;
		bool found = false;

		while (std::getline(is, line))
		{
			if (std::sscanf(line.c_str(), "Cached:%lu", &cached)
			    == 1)
			{
				system_info.ram_cached = cached * 1024;
				found = true;
			}
		}

		if (!found)
		{
			UC_LOG_ERR("Can't find Cached entry in /proc/meminfo");
		}
	}

	// Get other system information
	struct sysinfo sys_info = {};

	if (sysinfo(&sys_info) < 0)
	{
		UC_LOG_ERR(
		    "Failed to get system info: %s",
		    std::strerror(errno));
	}
	else
	{
		system_info.localtime =
		    static_cast<std::uint64_t>(std::time(nullptr));
		system_info.uptime = sys_info.uptime;
		system_info.ram_buffered =
		    sys_info.bufferram * sys_info.mem_unit;
		system_info.ram_free =
		    (sys_info.freeram + sys_info.freeswap) * sys_info.mem_unit;
		system_info.ram_total = sys_info.totalram * sys_info.mem_unit;
	}

	return system_info;
}

std::pair<plat_state_info, state_data> get_state_info()
{
	plat_state_info state_info{};
	state_data data{};

	state_info.system_info = get_system_info();

	// Get port info
	try
	{
		data.port_info = get_port_info();
		state_info.port_info = data.port_info.data();
		state_info.port_info_count = data.port_info.size();
	}
	catch (const std::exception &ex)
	{
		UC_LOG_ERR("Failed to get port info: %s", ex.what());
	}

	// Get learned MAC addresses
	try
	{
		data.learned_mac_addrs = get_learned_mac_addrs();
		state_info.learned_mac_list = data.learned_mac_addrs.data();
		state_info.learned_mac_list_size =
		    data.learned_mac_addrs.size();
	}
	catch (const std::exception &ex)
	{
		UC_LOG_ERR(
		    "Failed to get learned MAC addresses: %s",
		    ex.what());
	}

	// Get GW addresses
	try
	{
		data.gw_addresses = get_gw_addresses();
		state_info.gw_addr_list = data.gw_addresses.data();
		state_info.gw_addr_list_size = data.gw_addresses.size();
	}
	catch (const std::exception &ex)
	{
		UC_LOG_ERR("Failed to get GW addresses: %s", ex.what());
	}

	return {std::move(state_info), std::move(data)};
}

void save_metrics_config(const plat_metrics_cfg *cfg)
{
	json metrics_cfg;

	json &telemetry_cfg = metrics_cfg["telemetry"];
	telemetry_cfg["enabled"] = static_cast<bool>(cfg->telemetry.enabled);
	telemetry_cfg["interval"] = cfg->telemetry.interval;

	json &healthcheck_cfg = metrics_cfg["healthcheck"];
	healthcheck_cfg["enabled"] =
	    static_cast<bool>(cfg->healthcheck.enabled);
	healthcheck_cfg["interval"] = cfg->healthcheck.interval;

	json &state_cfg = metrics_cfg["state"];
	state_cfg["enabled"] = static_cast<bool>(cfg->state.enabled);
	state_cfg["lldp_enabled"] = static_cast<bool>(cfg->state.lldp_enabled);
	state_cfg["clients_enabled"] =
	    static_cast<bool>(cfg->state.clients_enabled);
	state_cfg["interval"] = cfg->state.interval;
	state_cfg["max_mac_count"] = cfg->state.max_mac_count;
	state_cfg["public_ip_lookup"] = cfg->state.public_ip_lookup;

	std::ofstream os{metrics_config_path};
	os << std::setw(4) << metrics_cfg << std::endl;

	if (!os)
	{
		throw std::runtime_error{
		    "Failed to write metrics config to the file"};
	}
}

void load_metrics_config(plat_metrics_cfg *cfg)
{
	std::ifstream is{metrics_config_path};

	// Metrics configuration doesn't exist yet, return silently without any
	// error
	if (!is.is_open())
		return;

	json metrics_cfg = json::parse(is);

	if (metrics_cfg.contains("telemetry"))
	{
		const json &telemetry_cfg = metrics_cfg.at("telemetry");
		cfg->telemetry.enabled =
		    telemetry_cfg.at("enabled").template get<bool>();
		cfg->telemetry.interval =
		    telemetry_cfg.at("interval").template get<std::size_t>();
	}

	if (metrics_cfg.contains("healthcheck"))
	{
		const json &healthcheck_cfg = metrics_cfg.at("healthcheck");
		cfg->healthcheck.enabled =
		    healthcheck_cfg.at("enabled").template get<bool>();
		cfg->healthcheck.interval =
		    healthcheck_cfg.at("interval").template get<std::size_t>();
	}

	if (metrics_cfg.contains("state"))
	{
		const json &state_cfg = metrics_cfg.at("state");
		cfg->state.enabled =
		    state_cfg.at("enabled").template get<bool>();
		cfg->state.lldp_enabled =
		    state_cfg.at("lldp_enabled").template get<bool>();
		cfg->state.clients_enabled =
		    state_cfg.at("clients_enabled").template get<bool>();
		cfg->state.interval =
		    state_cfg.at("interval").template get<std::size_t>();
		cfg->state.max_mac_count =
		    state_cfg.at("max_mac_count").template get<std::size_t>();

		std::strncpy(
		    cfg->state.public_ip_lookup,
		    state_cfg.at("public_ip_lookup")
			.template get<std::string>()
			.c_str(),
		    std::size(cfg->state.public_ip_lookup) - 1);
	}
}

periodic::~periodic()
{
	if (thread_ && thread_->joinable())
		thread_->join();
}

void periodic::start(
    std::function<void()> callback,
    std::chrono::seconds period)
{
	if (thread_)
		stop();

	callback_ = std::move(callback);
	period_ = std::move(period);

	thread_ =
	    std::make_unique<std::thread>(std::bind(&periodic::worker, this));
}

void periodic::stop()
{
	if (!thread_)
		return;

	{
		std::scoped_lock lk{mut_};
		stop_signal_ = true;
	}
	cv_.notify_one();

	if (thread_->joinable())
		thread_->join();

	thread_.reset();
	stop_signal_ = false;
}

void periodic::worker()
{
	std::unique_lock lk{mut_};

	while (!stop_signal_)
	{
		try
		{
			callback_();
		}
		catch (const std::exception &ex)
		{
			UC_LOG_ERR(
			    "Error occurred during periodic task execution: %s",
			    ex.what());
		}

		cv_.wait_for(lk, period_, [this] { return stop_signal_; });
	}
}

} // namespace larch
