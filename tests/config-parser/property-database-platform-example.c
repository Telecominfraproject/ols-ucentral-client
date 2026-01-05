/* Platform-specific property database template
 * 
 * Copy this file to property-database-platform-YOUR_PLATFORM.c
 * and regenerate with your platform code.
 *
 * This database tracks properties parsed by platform-specific code in:
 * - platform/your-platform/plat-*.c
 *
 * To regenerate this database:
 *   cd tests/tools
 *   python3 rebuild-property-database.py \
 *       ../../src/ucentral-client/platform/your-platform/plat-*.c \
 *       ../../config-samples/cfg*.json \
 *       > ../config-parser/property-database-platform-your-platform.c
 */

static const struct property_metadata platform_property_database_example[] = {
    /* Platform-specific properties go here */
    /* Example entries:
     * {"services.custom-feature.enabled", PROP_CONFIGURED, "platform/example/plat-example.c", "config_custom_apply", 100, ""},
     * {"ethernet[].vendor-specific", PROP_CONFIGURED, "platform/example/plat-example.c", "config_port_vendor_apply", 200, ""},
     */
    
    {NULL, 0, NULL, NULL, 0, NULL}  /* Terminator */
};
