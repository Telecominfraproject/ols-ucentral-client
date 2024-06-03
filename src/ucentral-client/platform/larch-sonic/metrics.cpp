#include <metrics.hpp>
#include <port.hpp>

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
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility> // std::move

namespace larch {

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
	data.port_info = get_port_info();
	state_info.port_info = data.port_info.data();
	state_info.port_info_count = data.port_info.size();

	return {std::move(state_info), std::move(data)};
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
