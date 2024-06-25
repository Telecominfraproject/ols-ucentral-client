#ifndef LARCH_PLATFORM_STATE_HPP_
#define LARCH_PLATFORM_STATE_HPP_

#include <gnmi.grpc.pb.h>
#include <gnmi.pb.h>

#include <grpc++/grpc++.h>

#include <router-utils.h>
#include <ucentral-platform.h>

#include <memory>
#include <vector>

// Forward declarations
namespace sw::redis {
class Redis;
}

namespace larch {

class periodic;

struct platform_state {
	~platform_state();

	std::shared_ptr<grpc::ChannelInterface> channel;
	std::unique_ptr<gnmi::gNMI::Stub> gnmi_stub;

	std::unique_ptr<periodic> telemetry_periodic;
	std::unique_ptr<periodic> state_periodic;

	std::unique_ptr<sw::redis::Redis> redis_asic;
	std::unique_ptr<sw::redis::Redis> redis_counters;

	std::vector<plat_ipv4> interfaces_addrs;
	ucentral_router router{};
};

inline std::unique_ptr<platform_state> state;

} // namespace larch

#endif // !LARCH_PLATFORM_STATE_HPP_
