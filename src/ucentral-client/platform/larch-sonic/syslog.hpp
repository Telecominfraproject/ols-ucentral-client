#ifndef LARCH_PLATFORM_SYSLOG_HPP_
#define LARCH_PLATFORM_SYSLOG_HPP_

#include <ucentral-platform.h>

namespace larch {

void gnma_syslog_cfg_clear(void);

void apply_syslog_config(struct plat_syslog_cfg *cfg, int count);

}

#endif // !LARCH_PLATFORM_SYSLOG_HPP_
