#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>

#include <ucentral-log.h>

#define ALEN(array) (sizeof((array)) / sizeof((array)[0]))

static const char *comp2str[] = {
	[UC_LOG_COMPONENT_PROTO] = "uc-proto",
	[UC_LOG_COMPONENT_PLAT] = "uc-plat",
	[UC_LOG_COMPONENT_CLIENT] = "uc-client",
};
static int comp_sv[UC_LOG_COMPONENT_MAX];

static void (*send_cb)(const char *s, int sv);

static int severity_get(enum uc_log_component c)
{
	/* returns -1 if loggig is disabled for component */
	if (c >= 0 && c < UC_LOG_COMPONENT_MAX) {
		return comp_sv[c] - 1;
	}
	return -1;
}

void uc_log_severity_set(enum uc_log_component c, int sv)
{
	if (c >= 0 && c < UC_LOG_COMPONENT_MAX) {
		comp_sv[c] = sv + 1;
	}
}

void uc_log_send_cb_register(void (*cb)(const char *, int sv))
{
	send_cb = cb;
}

static const char *uc_comp2str(enum uc_log_component c)
{
	if (c < 0 || c >= ALEN(comp2str) || !comp2str[c]) {
		return "unknown";
	}
	return comp2str[c];
}

void uc_log(enum uc_log_component c, int sv, const char *fmt, ...)
{
	/* TODO(vb) replace this buffer with send_printf_cb(...), avoid using
	 * cJSON, allocate directly into txq msg */
	static __thread int is_recursion;
	static __thread char buf[4096];
	va_list ap;
	int n = 0;
	const char *comp_str = uc_comp2str(c);

	if (is_recursion)
		return;

	if (sv < 0)
		return;

	if (!send_cb || severity_get(c) < sv)
		return;

	va_start(ap, fmt);
	n = snprintf(buf, sizeof buf, "%s: ", comp_str);
	if (n >= 0 && (size_t)n <= sizeof buf) {
		n = vsnprintf(&buf[n], sizeof buf - n, fmt, ap);
	}
	if (n >= 0) {
		is_recursion = 1;
		send_cb(buf, sv);
		is_recursion = 0;
	}

	va_end(ap);
}
