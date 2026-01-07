/*
 * Platform Mock Template
 *
 * This is a template for creating platform mocks for new platforms.
 * Copy this file and replace with your platform-specific mock implementations.
 *
 * See tests/ADDING_NEW_PLATFORM.md for complete documentation.
 *
 * USAGE:
 * 1. Copy this file: cp example-platform.c your-platform.c
 * 2. Try building: make clean && make test-config-parser USE_PLATFORM=your-platform
 * 3. For each "undefined reference" error, add a mock function here
 * 4. Repeat until it builds successfully
 */

#include <stdio.h>
#include <ucentral-platform.h>

/* ============================================================================
 * EXAMPLE MOCK FUNCTIONS
 * ============================================================================
 * Replace these with your platform's hardware abstraction layer functions
 */

/* Example initialization mock */
int example_platform_init(void)
{
    fprintf(stderr, "[MOCK:example-platform] Initialized\n");
    return 0;
}

/* Example port configuration mock */
int example_platform_port_set(int port_id, int speed, int duplex)
{
    fprintf(stderr, "[MOCK:example-platform] port_set(port=%d, speed=%d, duplex=%d)\n",
            port_id, speed, duplex);
    return 0;  /* Success */
}

/* Example VLAN creation mock */
int example_platform_vlan_create(int vlan_id)
{
    fprintf(stderr, "[MOCK:example-platform] vlan_create(vlan=%d)\n", vlan_id);
    return 0;  /* Success */
}

/* ============================================================================
 * ADD YOUR PLATFORM'S MOCK FUNCTIONS BELOW
 * ============================================================================
 *
 * General pattern for mock functions:
 *
 * int your_platform_function_name(parameters...)
 * {
 *     fprintf(stderr, "[MOCK:your-platform] function_name(...)\n");
 *     // Log parameters for debugging
 *     // Optionally validate parameters
 *     return 0;  // Return success
 * }
 *
 * Tips:
 * - Use fprintf(stderr, ...) to log function calls
 * - Return 0 for success, -1 for error
 * - Start simple (always return success)
 * - Add validation logic later if needed
 * - See brcm-sonic.c for more complex examples
 */
