/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * EST client stubs for the configuration parser tests
 *
 * proto.c's reenroll handler calls the EST client. The tests never run it,
 * but the symbols must resolve in both stub and platform mode, so these are
 * kept apart from the platform stubs in test-stubs.c.
 */

#include <stddef.h>
#include "est-client.h"

const char* est_get_server_url(const char *cert_path)
{
	(void)cert_path;
	return "est.test.example.com";  /* Dummy EST server URL */
}

int est_simple_reenroll(const char *est_server,
                        const char *operational_cert, const char *key,
                        const char *ca_bundle,
                        char **renewed_cert_out)
{
	(void)est_server;
	(void)operational_cert;
	(void)key;
	(void)ca_bundle;
	(void)renewed_cert_out;
	return 0;  /* EST_SUCCESS - stub always succeeds */
}

const char* est_get_error(void)
{
	return "EST stub mode - no real error";
}
