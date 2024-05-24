#include <metrics.hpp>

#define UC_LOG_COMPONENT UC_LOG_COMPONENT_PLAT
#include <ucentral-log.h>
#include <ucentral-platform.h>

#include <sys/sysinfo.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iterator> // std::begin, std::size
#include <stdexcept>
#include <string>

namespace larch {

static plat_system_info get_system_info()
{
	plat_system_info system_info;

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

plat_state_info get_state_info()
{
	plat_state_info state_info{};

	state_info.system_info = get_system_info();

	return state_info;
}

} // namespace larch
