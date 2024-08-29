#ifndef LARCH_PLATFORM_IGMP_HPP_
#define LARCH_PLATFORM_IGMP_HPP_

#include <ucentral-platform.h>

namespace larch {

void apply_igmp_config(uint16_t vid, struct plat_igmp *igmp);

}

#endif // !LARCH_PLATFORM_IGMP_HPP_
