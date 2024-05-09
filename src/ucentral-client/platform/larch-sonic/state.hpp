#ifndef LARCH_PLATFORM_STATE_HPP_
#define LARCH_PLATFORM_STATE_HPP_

#include <gnmi.pb.h>
#include <gnmi.grpc.pb.h>

#include <grpc++/grpc++.h>

#include <memory>

namespace larch {

struct platform_state {
	std::shared_ptr<grpc::ChannelInterface> channel;
	std::unique_ptr<gnmi::gNMI::Stub> gnmi_stub;
};

inline thread_local std::unique_ptr<platform_state> state;

}

#endif // !LARCH_PLATFORM_STATE_HPP_
