
#ifndef LARCH_PLATFORM_METRICS_HPP_
#define LARCH_PLATFORM_METRICS_HPP_

#include <state.hpp>

#include <ucentral-platform.h>

#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <utility> // std::pair
#include <vector>

namespace larch {

struct state_data {
	std::vector<plat_port_info> port_info;
	std::vector<plat_learned_mac_addr> learned_mac_addrs;
};

/**
 * @brief Get state information.
 *
 * @return A pair of @c plat_state_info and @c state_data. The latter is used as
 * an actual storage for all the gathered information, while the former
 * references the data in it. Pay attention to the fact that @c state_data must
 * outlive @c plat_state_info.
 */
std::pair<plat_state_info, state_data> get_state_info();

class periodic {
public:
	periodic() = default;
	~periodic();

	void start(std::function<void()> callback, std::chrono::seconds period);
	void stop();

protected:
	void worker();

	std::unique_ptr<std::thread> thread_;
	std::condition_variable cv_;
	std::mutex mut_;
	bool stop_signal_ = false;

	std::chrono::seconds period_{};
	std::function<void()> callback_;
};

} // namespace larch

#endif // !LARCH_PLATFORM_METRICS_HPP_
