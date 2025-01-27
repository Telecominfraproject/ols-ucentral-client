#include <stdio.h>

#include <ucentral-platform.h>
#include <ucentral-log.h>
#include <plat-revision.h>

#define UNUSED_PARAM(param) (void)((param))

int plat_init(void)
{
	return 0;
}

int plat_info_get(struct plat_platform_info *info)
{
	*info = (struct plat_platform_info){0};
        snprintf(info->platform, sizeof info->platform, "%s", "Example Platform" );
        snprintf(info->hwsku, sizeof info->hwsku, "%s", "example-platform-sku");
        snprintf(info->mac, sizeof info->mac, "%s", "24:fe:9a:0f:48:f0");

	return 0;
}

/* Platform independent mid-layer OS related functions definitions */
int plat_reboot(void)
{
	return 0;
}

int plat_config_apply(struct plat_cfg *cfg, uint32_t id)
{
	UNUSED_PARAM(cfg);
	UNUSED_PARAM(id);
	return 0;
}

int plat_config_save(uint64_t id)
{
	UNUSED_PARAM(id);
	return 0;
}

int plat_config_restore(void)
{
	return 0;
}

int plat_saved_config_id_get(uint64_t *id)
{
	UNUSED_PARAM(id);
	return 0;
}

void plat_config_destroy(struct plat_cfg *cfg)
{
	UNUSED_PARAM(cfg);
}

int plat_factory_default(void)
{
	return 0;
}

int plat_rtty(struct plat_rtty_cfg *rtty_cfg)
{
	UNUSED_PARAM(rtty_cfg);
	return 0;
}

int plat_upgrade(char *uri, char *signature)
{
	UNUSED_PARAM(signature);
	UNUSED_PARAM(uri);
	return 0;
}

char *plat_log_pop(void)
{
	return NULL;
}

void plat_log_flush(void)
{
}

char *plat_log_pop_concatenate(void)
{
	return NULL;
}


int plat_alarm_subscribe(plat_alarm_cb cb)
{
	UNUSED_PARAM(cb);
	return 0;
}

void plat_alarm_unsubscribe(void)
{
}

int plat_linkstatus_subscribe(plat_linkstatus_cb cb)
{
	UNUSED_PARAM(cb);
	return 0;
}

void plat_linkstatus_unsubscribe(void)
{
}

void plat_health_poll(void (*cb)(struct plat_health_info *), int period_sec)
{
	UNUSED_PARAM(period_sec);
	UNUSED_PARAM(cb);
}

void plat_health_poll_stop(void)
{
}

void plat_telemetry_poll(void (*cb)(struct plat_state_info *), int period_sec)
{
	UNUSED_PARAM(period_sec);
	UNUSED_PARAM(cb);
}

void plat_telemetry_poll_stop(void)
{
}

void plat_state_poll(void (*cb)(struct plat_state_info *), int period_sec)
{
	UNUSED_PARAM(period_sec);
	UNUSED_PARAM(cb);
}

void plat_state_poll_stop(void)
{
}

void plat_upgrade_poll(int (*cb)(struct plat_upgrade_info *), int period_sec)
{
	UNUSED_PARAM(period_sec);
	UNUSED_PARAM(cb);
}

void plat_upgrade_poll_stop(void)
{
}

int plat_port_list_get(uint16_t list_size, struct plat_ports_list *ports)
{
	UNUSED_PARAM(ports);
	UNUSED_PARAM(list_size);
	return 0;
}

int plat_port_num_get(uint16_t *num_of_active_ports)
{
	UNUSED_PARAM(num_of_active_ports);
	return 0;
}
int plat_revision_get(char *str, size_t str_max_len) 
{
        snprintf(str, str_max_len, PLATFORM_REVISION);
        return 0;
}
int plat_reboot_cause_get(struct plat_reboot_cause *cause)
{
	UNUSED_PARAM(cause);
	return 0;
}
int plat_event_subscribe(const struct plat_event_callbacks *cbs)
{
	UNUSED_PARAM(cbs);
        return 0;
}
void plat_event_unsubscribe(void)
{
	return;
}
	
int plat_running_img_name_get(char *str, size_t str_max_len)
{
	UNUSED_PARAM(str_max_len);
	UNUSED_PARAM(str);
	return 0;
}
int plat_metrics_save(const struct plat_metrics_cfg *cfg)
{
	UNUSED_PARAM(cfg);
        return 0;
}
int plat_metrics_restore(struct plat_metrics_cfg *cfg)
{
	UNUSED_PARAM(cfg);
        return 0;
}
int plat_run_script(struct plat_run_script *p)
{
	UNUSED_PARAM(p);
        return 0;
}

