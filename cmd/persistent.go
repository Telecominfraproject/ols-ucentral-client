package main

// Common commands
const RebootCMD = "reboot"
const FileUploadUriPrefix = "https://openwifi.wlan.local:16003/v1/upload/"

// Files
const TmpDir = "/tmp/"
const ClishScriptFile = "/usr/local/bin/scripts/clish.sh"
const LedScriptFile = "/usr/local/bin/scripts/led.sh"
const ConfigureScriptFile = "/usr/local/bin/scripts/configure.sh"
const ConfigDBFile = "/etc/sonic/config_db.json"
const SonicVersionFile = "/etc/sonic/sonic_version.yml"
const ScriptCmdFile = "/tmp/ucentral_script.cmd"
const ScriptCmdResultFile = "/tmp/ucentral_script_result.gz"
const ScriptCmdResultFileName = "ucentral_script_result"
const TraceCmdResultFile = "/tmp/ucentral_trace.pcap"
const FirmwareFile = "/tmp/firmware.bin"
const SSBFileName = "/tmp/ucentral_diagnostic_result.log"
const SSBFileBundle = "/tmp/ucentral_diagnostic_result"

// DB
const DB_STATE_TABLE_NAME_SEPARATOR = "|"
const DB_CONFIG_TABLE_NAME_SEPARATOR = "|"
const DB_K_DEVICE_METADATA = "DEVICE_METADATA|localhost"
const DB_K_MGMT_INTERFACES = "MGMT_INTERFACE|*"

// Error codes
//
//	0 : configuration was applied as-is.
//	1 : configuration was applied with the included substitutions in the rejected section. The device is operating with the new modified config.
//	2 : configuration was rejected and will not be applied at all. The rejected section can be used to tell the controller why.
const ErrorCodeSuccess = 0
const ErrorCodePartSuccess = 1
const ErrorCodeFail = 2

const METRICS_WIRED_CLIENTS_MAX_NUM = 2000
