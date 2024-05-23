#ifndef UCENTRAL_LOG_H
#define UCENTRAL_LOG_H

#include <syslog.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef UC_LOG_COMPONENT
#define UC_LOG_COMPONENT UC_LOG_COMPONENT_UNKNOWN
#endif

#define UC_LOG_SV_EMERG 0
#define UC_LOG_SV_ALRET 1
#define UC_LOG_SV_CRIT 2
#define UC_LOG_SV_ERR 3
#define UC_LOG_SV_WARN 4
#define UC_LOG_SV_NOTICE 5
#define UC_LOG_SV_INFO 6
#define UC_LOG_SV_DEBUG 7

enum uc_log_component {
	UC_LOG_COMPONENT_UNKNOWN,
	UC_LOG_COMPONENT_PROTO,
	UC_LOG_COMPONENT_PLAT,
	UC_LOG_COMPONENT_CLIENT,
	UC_LOG_COMPONENT_MAX,
};

void uc_log_send_cb_register(void (*cb)(const char *, int sv));
void uc_log_severity_set(enum uc_log_component c, int sv);
void uc_log(enum uc_log_component c, int sv, const char *fmt, ...);

#define UC_LOG_INFO(...)                                               \
	do {                                                           \
		syslog(LOG_INFO, __VA_ARGS__);                         \
		uc_log(UC_LOG_COMPONENT, UC_LOG_SV_INFO, __VA_ARGS__); \
	} while (0)

#define UC_LOG_DBG(FMT, ...)                                           \
	do {                                                           \
		syslog(LOG_DEBUG, "%s:%u: " FMT, __func__,             \
		       (unsigned)__LINE__ __VA_OPT__(, ) __VA_ARGS__); \
		uc_log(UC_LOG_COMPONENT, UC_LOG_SV_DEBUG,              \
		       FMT __VA_OPT__(, ) __VA_ARGS__);                \
	} while (0)

#define UC_LOG_ERR(FMT, ...)                                           \
	do {                                                           \
		syslog(LOG_ERR, "%s:%u: " FMT, __func__,               \
		       (unsigned)__LINE__ __VA_OPT__(, ) __VA_ARGS__); \
		uc_log(UC_LOG_COMPONENT, UC_LOG_SV_ERR,                \
		       FMT __VA_OPT__(, ) __VA_ARGS__);                \
	} while (0)

#define UC_LOG_CRIT(FMT, ...)                                          \
	do {                                                           \
		syslog(LOG_CRIT, "%s:%u: " FMT, __func__,              \
		       (unsigned)__LINE__ __VA_OPT__(, ) __VA_ARGS__); \
		uc_log(UC_LOG_COMPONENT, UC_LOG_SV_CRIT,                \
		       FMT __VA_OPT__(, ) __VA_ARGS__);                \
	} while (0)

#ifdef __cplusplus
}
#endif

#endif
