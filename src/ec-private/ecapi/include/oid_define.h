#ifndef OID_DEFINE_H
#define OID_DEFINE_H

#include <sys_adpt.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

const static oid O_MAIN_MAC[] = { SYS_ADPT_PRIVATEMIB_OID, 1, 5, 6, 1, 0 };
const static oid O_SERIAL[] = { SYS_ADPT_PRIVATEMIB_OID, 1, 1, 3, 1, 10, 1 };
const static oid O_OPCODE_VERSION[] = { SYS_ADPT_PRIVATEMIB_OID, 1, 1, 5, 4, 0 };
const static oid O_SYS_UPTIME[] = { 1, 3, 6, 1, 2, 1, 1, 3, 0 };
const static oid O_VLAN_STATUS[] = { 1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 3, 1, 5};
const static oid O_POE_PORT_ENABLE[] ={1, 3, 6, 1, 2, 1, 105, 1, 1, 1, 3, 1};
const static oid O_PORT_CPAPBILITIES[] = { SYS_ADPT_PRIVATEMIB_OID, 1, 2, 1, 1, 6, 1 };

#define O_FACTORY_DEFAULT SYSTEM_OID"1.24.2.1.1.4.1.70.97.99.116.111.114.121.95.68.101.102.97.117.108.116.95.67.111.110.102.105.103.46.99.102.103"
#define O_FW_UPGRADE_MGMT SYSTEM_OID"1.24.6.1.0"
#define O_DEVICE_MODEL SYSTEM_OID"1.1.5.1.0"
#define O_DEVICE_COMPANY SYSTEM_OID"1.1.5.2.0"
#define O_STR_POE_PORT_ENABLE "1.3.6.1.2.1.105.1.1.1.3.1"
#define O_STR_POE_MAX_POWER SYSTEM_OID"1.28.6.1.13.1"
#define O_STR_POE_USAGE_THRESHOLD "1.3.6.1.2.1.105.1.3.1.1.5.1"
#define O_STR_IF_ADMIN_STATUS "1.3.6.1.2.1.2.2.1.7"
#define O_STR_PORT_CPAPBILITIES SYSTEM_OID"1.2.1.1.6"
#define O_STR_PVID "1.3.6.1.2.1.17.7.1.4.5.1.1"
#define O_STR_VLAN_NAME "1.3.6.1.2.1.17.7.1.4.3.1.1"
#define O_STR_VLAN_EGRESS "1.3.6.1.2.1.17.7.1.4.3.1.2"
#define O_STR_VLAN_STATUS "1.3.6.1.2.1.17.7.1.4.3.1.5"
#define O_STR_VLAN_UNTAGGED "1.3.6.1.2.1.17.7.1.4.3.1.4"
#define O_STR_COPY_SRC_TYPE SYSTEM_OID"1.24.1.1.0"
#define O_STR_COPY_DST_TYPE SYSTEM_OID"1.24.1.3.0"
#define O_STR_COPY_DST_NAME SYSTEM_OID"1.24.1.4.0"
#define O_STR_COPY_FILE_TYPE SYSTEM_OID"1.24.1.5.0"
#define O_STR_COPY_ACTION SYSTEM_OID"1.24.1.8.0"
#define O_NTP_STATUS SYSTEM_OID"1.23.5.1.0"
#define O_SNTP_STATUS SYSTEM_OID"1.23.1.1.0"
#define O_SNTP_INTERVAL SYSTEM_OID"1.23.1.3.0"
#define O_SNTP_SERVER_TYPE SYSTEM_OID"1.23.1.4.1.4"
#define O_SNTP_SERVER_ADDR SYSTEM_OID"1.23.1.4.1.5"

#endif