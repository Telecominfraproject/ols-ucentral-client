/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Test Stubs for Configuration Parser Tests
 *
 * Provides stub/mock implementations of global variables and functions
 * that proto.c references but are not needed for testing cfg_parse()
 */

#include <time.h>
#include <string.h>
#include "ucentral.h"

/*
 * Minimal stub definition for struct blob
 * proto.c uses this type in many functions, but these functions are not
 * actually called during cfg_parse() testing. We just need the type to exist
 * so proto.c can compile.
 */
struct blob {
	char *data;
	size_t len;
};

/* Stub global variables needed by proto.c */
struct client_config client = {
	.redirector_file = "/tmp/test",
	.redirector_file_dbg = "/tmp/test",
	.ols_client_version_file = "/tmp/test",
	.ols_schema_version_file = "/tmp/test",
	.server = "test.example.com",
	.port = 443,
	.path = "/",
	.serial = "TEST123456",
	.CN = "test",
	.firmware = "1.0.0",
	.devid = "00000000-0000-0000-0000-000000000000",
	.selfsigned = 0,
	.debug = 0
};
time_t conn_time = 0;
struct plat_metrics_cfg ucentral_metrics = {0};

/* Stub platform functions that cfg_parse() needs */

/*
 * Return a dummy port count for testing
 *
 * RATIONALE: Configuration parser tests need to simulate a real hardware platform
 * to properly validate port selection and configuration. Originally this returned
 * 100 ports, but that didn't match actual ECS hardware models.
 *
 * FIX: Changed to return 54 ports (Ethernet0-Ethernet53) to accurately simulate
 * the ECS4150-54P (54-port PoE) and ECS4150-54T (54-port non-PoE) switch models.
 * This ensures test configurations using port ranges or wildcards are validated
 * against realistic hardware constraints.
 *
 * NOTE: This affects all test configs that use "Ethernet*" wildcard or specify
 * individual ports - they will now be validated against 0-53 port range.
 */
int plat_port_num_get(uint16_t *num_of_active_ports)
{
	/* Return 54 ports (Ethernet0-Ethernet53) to match ECS4150-54P/54T hardware */
	*num_of_active_ports = 54;
	return 0; /* Success */
}

/* Fill in dummy port list for testing */
int plat_port_list_get(uint16_t list_size, struct plat_ports_list *ports)
{
	struct plat_ports_list *port = ports;
	uint16_t i;

	/* Fill in port names like Ethernet0, Ethernet1, etc. */
	for (i = 0; i < list_size && port; i++) {
		snprintf(port->name, PORT_MAX_NAME_LEN, "Ethernet%u", i);
		port = port->next;
	}

	return 0; /* Success */
}

/* Stub function for destroying platform config - no-op in tests */
void plat_config_destroy(struct plat_cfg *cfg)
{
	(void)cfg; /* Unused in test - just a no-op */
}

/* Additional platform function stubs needed by proto.c */

int plat_saved_config_id_get(uint64_t *id)
{
	*id = 0;
	return 0;
}

int plat_info_get(struct plat_platform_info *info)
{
	strncpy(info->platform, "test", sizeof(info->platform) - 1);
	strncpy(info->hwsku, "test", sizeof(info->hwsku) - 1);
	strncpy(info->mac, "00:00:00:00:00:00", sizeof(info->mac) - 1);
	return 0;
}

int plat_metrics_restore(struct plat_metrics_cfg *cfg)
{
	(void)cfg;
	return 0;
}

void plat_state_poll_stop(void) {}
void plat_health_poll_stop(void) {}
void plat_telemetry_poll_stop(void) {}
void plat_upgrade_poll_stop(void) {}

void plat_state_poll(void (*cb)(struct plat_state_info *), int period_sec)
{
	(void)cb;
	(void)period_sec;
}

void plat_health_poll(void (*cb)(struct plat_health_info *), int period_sec)
{
	(void)cb;
	(void)period_sec;
}

void plat_telemetry_poll(void (*cb)(struct plat_state_info *), int period_sec)
{
	(void)cb;
	(void)period_sec;
}

void plat_log_flush(void) {}

int plat_config_apply(struct plat_cfg *cfg, uint32_t id)
{
	(void)cfg;
	(void)id;
	return 0;
}

int plat_config_restore(void)
{
	return 0;
}

int plat_config_save(uint64_t id)
{
	(void)id;
	return 0;
}

int plat_metrics_save(const struct plat_metrics_cfg *cfg)
{
	(void)cfg;
	return 0;
}

char *plat_log_pop_concatenate(void)
{
	return NULL;
}

int plat_reboot(void)
{
	return 0;
}

int plat_factory_default(void)
{
	return 0;
}

int plat_rtty(struct plat_rtty_cfg *rtty_cfg)
{
	(void)rtty_cfg;
	return 0;
}

int plat_upgrade(char *uri, char *signature)
{
	(void)uri;
	(void)signature;
	return 0;
}

void plat_upgrade_poll(int (*cb)(struct plat_upgrade_info *), int period_sec)
{
	(void)cb;
	(void)period_sec;
}

int plat_run_script(struct plat_run_script *script)
{
	(void)script;
	return 0;
}

int plat_reboot_cause_get(struct plat_reboot_cause *cause)
{
	cause->cause = PLAT_REBOOT_CAUSE_UNAVAILABLE;
	cause->ts = 0;
	strncpy(cause->desc, "test", sizeof(cause->desc) - 1);
	return 0;
}

int plat_event_subscribe(const struct plat_event_callbacks *cbs)
{
	(void)cbs;
	return 0;
}

void plat_event_unsubscribe(void) {}

int plat_init(void)
{
	fprintf(stderr, "[STUB] plat_init() - platform initialization (stub mode)\n");
	return 0;
}
