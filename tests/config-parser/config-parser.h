/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include <cjson/cJSON.h>
#include <ucentral-platform.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * cfg_parse - Parse a JSON configuration object into a platform configuration
 * @config: cJSON object containing the configuration
 *
 * Parses the uCentral configuration JSON and populates a struct plat_cfg
 * with the parsed values. The caller is responsible for freeing the returned
 * structure using plat_config_destroy() and free().
 *
 * Returns: Pointer to allocated plat_cfg on success, NULL on failure
 */
struct plat_cfg *cfg_parse(cJSON *config);

#ifdef __cplusplus
}
#endif

#endif /* CONFIG_PARSER_H */
