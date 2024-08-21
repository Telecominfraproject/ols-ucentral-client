#ifndef LARCH_PLATFORM_STATE_HPP_
#define LARCH_PLATFORM_STATE_HPP_

#include <gnmi.grpc.pb.h>
#include <gnmi.pb.h>
#include <sonic_gnoi.grpc.pb.h>
#include <sonic_gnoi.pb.h>
#include <system.grpc.pb.h>
#include <system.pb.h>

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

	std::unique_ptr<gnoi::system::System::Stub> system_gnoi_stub;

	std::unique_ptr<gnoi::sonic::SonicService::Stub> stub_gnoi_sonic;

	std::unique_ptr<periodic> telemetry_periodic;
	std::unique_ptr<periodic> state_periodic;
	std::unique_ptr<periodic> health_periodic;

	std::unique_ptr<sw::redis::Redis> redis_asic;
	std::unique_ptr<sw::redis::Redis> redis_counters;

	std::vector<plat_ipv4> interfaces_addrs;
	ucentral_router router{};
};

inline std::unique_ptr<platform_state> state;

} // namespace larch

#endif // !LARCH_PLATFORM_STATE_HPP_
