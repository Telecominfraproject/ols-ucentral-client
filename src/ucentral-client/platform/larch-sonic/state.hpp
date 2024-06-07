#ifndef LARCH_PLATFORM_STATE_HPP_
#define LARCH_PLATFORM_STATE_HPP_

#include <gnmi.grpc.pb.h>
#include <gnmi.pb.h>

#include <grpc++/grpc++.h>

#include <memory>

namespace larch {

class periodic;

struct platform_state {
	~platform_state();

	std::shared_ptr<grpc::ChannelInterface> channel;
	std::unique_ptr<gnmi::gNMI::Stub> gnmi_stub;

	std::unique_ptr<periodic> telemetry_periodic;
	std::unique_ptr<periodic> state_periodic;
};

inline std::unique_ptr<platform_state> state;

} // namespace larch

#endif // !LARCH_PLATFORM_STATE_HPP_
