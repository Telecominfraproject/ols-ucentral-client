package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"io/ioutil"
	"net/http"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/load"
	"github.com/spf13/viper"

	"asterfusion/client/logger"
	utils "asterfusion/client/utils"
)

var ReportStatsCount = 0
var crashLogRecord = mapset.NewSet[string]()

type PoeStatus int

const (
	offline PoeStatus = iota
	online
)

var G_PoeStatus map[string]PoeStatus = make(map[string]PoeStatus)
var G_StatLLDPs map[string]map[string]string = make(map[string]map[string]string)

func GetHealthcheckData(RequestUuid string) ([]byte, error) {
	return []byte{}, nil
}

func getStateTemp() ([]Temperature, error) {
	return []Temperature{}, nil
}

func getStatePSU() ([]Psu, error) {
	return []Psu{}, nil
}

func getStateFans() ([]Fan, error) {
	return []Fan{}, nil
}

func getStateConfiguration() (map[string]interface{}, error) {
	var data map[string]interface{}
	content, err := ioutil.ReadFile(ConfigDBFile)

	if err != nil {
		return data, fmt.Errorf("Read file with error %v", err)
	} else {
		err = json.Unmarshal([]byte(content), &data)
		if err != nil {
			return data, fmt.Errorf("Unmarshal json error %v", err)
		}
	}

	return data, nil
}

func getStateHostname() (string, error) {
	hostname := ""
	const DeviceMetaDate = "DEVICE_METADATA|localhost"
	hostname, err := ConfigDb.Db.HGet(DeviceMetaDate, "hostname").Result()
	if err != nil {
		return hostname, err
	}
	return hostname, nil
}

func getStateHwsku() (string, error) {
	const DeviceMetaDate = "DEVICE_METADATA|localhost"
	hwsku, _ := ConfigDb.Db.HGet(DeviceMetaDate, "hwsku").Result()

	return hwsku, nil
}

func GetStateData(RequestUuid string) ([]byte, error) {
	stateData := StateEvent{}
	stateData.Jsonrpc = "2.0"
	stateData.Method = "state"
	stateData.StateParams = StateParams{}
	stateData.StateParams.Serial = SerialNum
	stateData.StateParams.Uuid = ActiveUuid
	stateData.StateParams.RequestUuid = RequestUuid
	stateData.StateParams.State = State{}
	var currentUnit Unit
	var currentInterfaces []Interface
	var memory Memory

	systemInfo, err := StateDb.Db.HGetAll("SYSTEM_INFO|GLOBAL").Result()
	if err != nil {
		logger.Warn("Failed to get system info: %s", err.Error())
		return []byte{}, err
	}
	// unit is B-> byte get memory info
	memoryTotal, _ := strconv.ParseInt(systemInfo["memory_total"], 10, 64)
	memoryAvailable, _ := strconv.ParseInt(systemInfo["memory_available"], 10, 64)
	// memoryUsed, _ := strconv.Atoi(systemInfo["memory_used"])
	cpuUsagePercentage, _ := strconv.Atoi(systemInfo["cpu_usage_percentage"])
	memory.Total = memoryTotal * 1000
	memory.Free = memoryAvailable * 1000
	memory.Cached = 0
	memory.Buffered = 0
	currentUnit.Cpu = cpuUsagePercentage
	currentUnit.Memory = memory
	// get load info
	load, _ := load.Avg()
	currentUnit.Load = []float64{float64(load.Load1), float64(load.Load5), float64(load.Load15)}
	// get current device time
	currentUnit.Localtime = uint64(time.Now().Unix())
	// get uptime
	currentUnit.Uptime, _ = host.Uptime()
	// get hostname
	currentUnit.Hostname, _ = getStateHostname()

	/* get tempreature
	*  psu | fans
	 */
	currentUnit.Temperatures, _ = getStateTemp()
	currentUnit.Psus, _ = getStatePSU()
	currentUnit.Fans, _ = getStateFans()
	stateData.StateParams.State.Unit = currentUnit

	currentGps := Gps{}
	stateData.StateParams.State.Gps = currentGps

	currentInterfaces, _ = getInterfacesStats()

	stateData.StateParams.State.Interfaces, _ = GetOLSInterface(currentInterfaces)
	stateData.StateParams.State.AclStats.AclIntfStats, _ = GetOLSAclbasedPort()

	// OLS state
	if linkState, err := GetOLSLinkState(currentInterfaces); err == nil {
		stateData.StateParams.State.LinkState = linkState
	} else {
		stateData.StateParams.State.LinkState = OLSLinkStates{
			UpStream:   make(map[string]OLSPortLinkState),
			DownStream: make(map[string]OLSPortLinkState),
		}
	}
	if poe, err := GetOLSPoE(); err == nil {
		stateData.StateParams.State.Unit.PoE = poe
	}
	if lldpPeers, err := GetOLSLldpPeers(); err == nil {
		stateData.StateParams.State.LldpPeers = lldpPeers
	}

	if body, err := GetStaticTrunkStatusData(); err == nil {
		stateData.StateParams.State.StaticTrunks = body
	}

	if body, err := GetDynamicTrunkStatusData(); err == nil {
		stateData.StateParams.State.LacpTrunks = body
	}

	if body, err := GetNtpServersData(); err == nil {
		stateData.StateParams.State.NTPStatus = body
	}

	// OLS mac address
	currentMacs, _ := getOLSMacs()
	stateData.StateParams.State.MacAddressList = currentMacs

	// OLS private ip
	stateData.StateParams.State.PrivateIp = getStatePrivateIP()

	// OLS public ip
	stateData.StateParams.State.PublicIp = getStatePublicIP()

	// OLS interface_uplink
	stateData.StateParams.State.UplinkInterface = getStateUplinkInterface()

	// stp
	if stpStatus, err := getOLStpStatus(); err == nil {
		stateData.StateParams.State.StpStats = stpStatus
	}

	resultJson, err := json.Marshal(stateData)

	if err != nil {
		logger.Error("Failed to marshal JSON: %s", err.Error())
		return []byte{}, err
	}

	return resultJson, nil
}

func getStatePrivateIP() string {
	keys, err := ConfigDb.Db.Keys("MGMT_INTERFACE|eth0|*").Result()
	if err != nil {
		return ""
	}
	if len(keys) > 0 {
		ipArr := strings.Split(keys[0], "|")
		if len(ipArr) == 3 {
			ip := ipArr[2]
			return ip
		}
	}

	return ""
}

func getStatePublicIP() string {
	if PublicIpLookup == "" {
		return ""
	}
	resp, err := http.Get("http://" + PublicIpLookup)
	if err != nil {
		logger.Warn("Failed to get state event public ip, [PublicIpLookup: %s], [error : %s]", PublicIpLookup, err.Error())
		serverIP, _ := ConfigDb.Db.HGet("UCENTRAL_CLIENT|SERVER", "ip").Result()
		if len(serverIP) != 0 {
			operStatus, err := APPDb.Db.HGet("VLAN_TABLE:Vlan1", "oper_status").Result()
			if err == nil && operStatus == "up" {
				cmd := "systemctl reset-failed ucentral-client"
				utils.RunShellCommandWithTimeout(cmd, 3)
				cmd = "systemctl restart ucentral-client"
				utils.RunShellCommandWithTimeout(cmd, 3)
			}
		}
		return ""
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(body)
}

func getStateUplinkInterface() string {
	portListStr := ""
	return portListStr
}

func getOsMemory() {
	_, err := exec.Command("/usr/bin/cat", "/proc/loadavg").Output()
	if err != nil {
		logger.Warn("Failed to get memory info: %s", err.Error())
	}
}

func getPoeInfo(intf string, status bool) (PoeInfo, error) {
	return PoeInfo{}, nil
}

func getInterfacesStats() ([]Interface, error) {
	// need to implement by SonicOS.
	return []Interface{}, nil
}

func percentStrTransferFloat(util string) float64 {
	res := 0.0
	if util == "N/A" {
		return res
	}

	utilValue := strings.ReplaceAll(util, "%", "")
	res, _ = strconv.ParseFloat(utilValue, 64)

	return res
}

func byteUnitTransferB(rate string) float64 {
	res := 0.0
	if rate == "N/A" {
		return res
	}
	arr := strings.Split(rate, " ")
	if len(arr) == 2 {
		rateValue := strings.Split(rate, " ")[0]
		rateUnit := strings.Split(rate, " ")[1]

		if rateUnit == "B/s" {
			res, _ = strconv.ParseFloat(rateValue, 64)
		} else if rateUnit == "KB/s" {
			res, _ = strconv.ParseFloat(rateValue, 64)
			res = res * 1000
		} else if rateUnit == "MB/s" {
			res, _ = strconv.ParseFloat(rateValue, 64)
			res = res * 1000 * 1000
		}
	}
	return res
}

func byteUnitDisplay(rate float64) string {
	res := ""

	if rate > 1000*1000*10 {
		res = strconv.FormatFloat(rate/1000/1000, 'f', 2, 64)
		res += " MB"
	} else if rate > 1000*10 {
		res = strconv.FormatFloat(rate/1000, 'f', 2, 64)
		res += " KB"
	} else {
		res = strconv.FormatFloat(rate, 'f', 2, 64)
		res += " B"
	}

	res += "/s"
	return res
}

func GetCrashLogData() ([]byte, error) {
	// {"jsonrpc":"2.0","method":"log","params":{"serial":"53494d000000","log":"I am an useless log ...","severity":7,"data":{}}}
	// report discovery crashlog,
	loglines := []string{}
	logData := CrashLogEvent{
		Jsonrpc: "2.0",
		Method:  "crashlog",
		Params: struct {
			Serial   string   `json:"serial"`
			Uuid     int      `json:"uuid"`
			Loglines []string `json:"loglines"`
		}{
			Serial:   SerialNum,
			Uuid:     ActiveUuid,
			Loglines: loglines,
		},
	}
	var newAddCrashLog []string
	var resultJson = []byte{}
	err := filepath.Walk("/var/core", func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			logger.Warn("Prevent panic by handling failure accessing a path %q: %v\n", path, err)
			return err
		}
		// logger.Info("visited file or dir: %q\n", path)
		if path != "/var/core" {
			if !crashLogRecord.Contains(path) {
				// avoid json body tol large
				if len(newAddCrashLog) < 10 {
					newAddCrashLog = append(newAddCrashLog, path)
				}
				crashLogRecord.Add(path)
			}
		}
		return nil
	})
	if len(newAddCrashLog) > 0 {
		logData.Params.Loglines = newAddCrashLog
		resultJson, err = json.Marshal(logData)
		if err != nil {
			logger.Error("Failed to marshal JSON: %s", err.Error())
			return []byte{}, err
		}
	}
	return resultJson, nil
}

func GetSyslogData() ([]byte, error) {
	// {"jsonrpc":"2.0","method":"log","params":{"serial":"53494d000000","log":"I am an useless log ...","severity":7,"data":{}}}
	// report discovery crashlog,
	logTemp := LogData{
		Loglines: 50,
		Data:     "",
	}
	showLogCMD := "tail -n 50 /var/log/syslog"
	// max len 20000
	exit, output := utils.RunShellCommand(showLogCMD)
	// max len 20000
	if len(output) > 20000 {
		output = output[:20000]
	}

	if exit != 0 {
		logger.Error("Exec shell(tail -n 50 /var/log/syslog) failed, exit code: %d, error: %s", exit, output)
	} else {
		logTemp.Data = output
	}

	logData := LogEvent{
		Jsonrpc: "2.0",
		Method:  "log",
		Params: struct {
			Serial   string  `json:"serial"`
			Log      string  `json:"log"`
			Severity int     `json:"severity"`
			Data     LogData `json:"data"`
		}{
			Serial: SerialNum,
			Log:    "Display the last 50 lines log of syslog.",
			// crash log
			Severity: 7,
			Data:     logTemp,
		},
	}
	resultJson, err := json.Marshal(logData)
	if err != nil {
		logger.Error("Failed to marshal JSON: %s", err.Error())
		return []byte{}, err
	}

	return resultJson, nil
}

func GetPingData() ([]byte, error) {
	pingData := PingEvent{
		Jsonrpc: "2.0",
		Method:  "ping",
		Params: struct {
			Serial string `json:"serial"`
			Uuid   int    `json:"uuid"`
		}{
			Serial: SerialNum,
			Uuid:   ActiveUuid,
		},
	}
	resultJson, err := json.Marshal(pingData)
	if err != nil {
		logger.Error("Failed to marshal JSON: %s", err.Error())
		return []byte{}, err
	}
	return resultJson, nil
}

func GetConfigChangeData(uuid int) ([]byte, error) {
	configChangeData := CfgEvent{
		Jsonrpc: "2.0",
		Method:  "cfgpending",
		Params: struct {
			Serial string `json:"serial"`
			Active int    `json:"active"`
			Uuid   int    `json:"uuid"`
		}{
			Serial: SerialNum,
			Active: ActiveUuid,
			Uuid:   uuid,
		},
	}
	resultJson, err := json.Marshal(configChangeData)
	if err != nil {
		logger.Error("Failed to marshal JSON: %s", err.Error())
		return []byte{}, err
	}
	return resultJson, nil
}

func GetDeviceUpdateData() ([]byte, error) {
	deviceUpdateData := DeviceUpdateEvent{
		Jsonrpc: "2.0",
		Method:  "deviceupdate",
		Params: struct {
			Serial string `json:"serial"`
		}{
			Serial: SerialNum,
		},
	}
	resultJson, err := json.Marshal(deviceUpdateData)
	if err != nil {
		logger.Error("Failed to marshal JSON: %s", err.Error())
		return []byte{}, err
	}
	return resultJson, nil
}

func GetRecoveryData() ([]byte, error) {
	recoveryData := RecoveryEvent{
		Jsonrpc: "2.0",
		Method:  "recovery",
		Params: struct {
			Serial   string   `json:"serial"`
			Uuid     int      `json:"uuid"`
			Firmware string   `json:"firmware"`
			Reboot   bool     `json:"reboot"`
			Loglines []string `json:"loglines"`
		}{
			Serial:   SerialNum,
			Uuid:     ActiveUuid,
			Firmware: "96afb8c5-3f3a-4f06-a35d-303a88378e13",
			Reboot:   false,
		},
	}
	resultJson, err := json.Marshal(recoveryData)
	if err != nil {
		logger.Error("Failed to marshal JSON: %s", err.Error())
		return []byte{}, err
	}
	return resultJson, nil
}

func getLLDPDeviceInfo() (LLDPDeviceInfo, error) {
	var deviceInfo LLDPDeviceInfo

	// Get mgmt IP data
	var mgmtIP string
	var mgmtIPv4 string
	var mgmtIPv6 string
	if result, err := ConfigDb.Db.Keys(DB_K_MGMT_INTERFACES).Result(); err != nil {
		logger.Warn("Failed to get mgmt IP: %s", err.Error())
	} else {
		mgmtIpList := []string{}
		for _, v := range result {
			parts := strings.Split(v, "|")
			ip := parts[len(parts)-1]
			ipVersion := utils.IPversion(utils.RemoveIPMask(ip))
			if ipVersion == 4 {
				mgmtIPv4 = ip
				mgmtIpList = append(mgmtIpList, fmt.Sprintf("%v", ip))
			} else if ipVersion == 6 {
				mgmtIPv6 = ip
				mgmtIpList = append(mgmtIpList, fmt.Sprintf("%v", ip))
			} else {
				logger.Error("Failed to parse IP: %s.", ip)
			}
		}
		mgmtIP = strings.Join(mgmtIpList, " ")
	}

	// Get device meta
	var deviceMeta map[string]string
	if result, err := ConfigDb.Db.HGetAll(DB_K_DEVICE_METADATA).Result(); err != nil {
		logger.Warn("Failed to get device metadata: %s", err.Error())
	} else {
		deviceMeta = result
	}

	// Get version
	// init Viper
	var version struct {
		BuildVersion string `yaml:"build_version"`
	}
	viper.SetConfigFile(SonicVersionFile)
	viper.SetConfigType("yaml")
	if err := viper.ReadInConfig(); err != nil {
		logger.Warn("Failed to read Sonic version file: %s", err.Error())
	} else {
		if buildVersion, ok := viper.Get("build_version").(string); ok {
			version.BuildVersion = buildVersion
		} else {
			logger.Warn("Failed to get build_version.")
		}
	}

	// assignment
	deviceInfo.Compatible = deviceMeta["hwsku"]
	deviceInfo.DeviceType = "Switch"
	deviceInfo.Hostname = deviceMeta["hostname"]
	deviceInfo.IP = mgmtIP
	deviceInfo.IPv4 = mgmtIPv4
	deviceInfo.IPv6 = mgmtIPv6
	if code, mac := utils.RunShellCommand("ip link show eth0 | awk '/ether/ {print $2}'"); code == 0 {
		deviceInfo.MAC = strings.TrimSpace(mac)
	} else {
		deviceInfo.MAC = deviceMeta["mac"]
	}
	deviceInfo.Manufacturer = "asterfusion"
	deviceInfo.Platform = deviceMeta["platform"]
	deviceInfo.RouterType = deviceMeta["type"]
	deviceInfo.Version = version.BuildVersion

	return deviceInfo, nil
}

func getLLDPInterfaces() ([]LLDPInterface, error) {
    // need to implement by SonicOS.
	return []LLDPInterface{}, nil
}

func GetLLDPData() ([]byte, error) {
    // need to implement by SonicOS.
	return []byte{}, nil
}

func getInterfaceOidMap() (map[string]string, error) {
    // need to implement by SonicOS.
	return map[string]string{}, nil
}

func getBridgePortMap() (map[string]string, error) {
    // need to implement by SonicOS.
	return map[string]string{}, nil
}

func getMacs() ([]MACData, error) {
    // need to implement by SonicOS.
	macs := []MACData{}
	return macs, nil
}

func getOLSMacs() (map[string]interface{}, error) {
    // need to implement by SonicOS.
	macDict := make(map[string]interface{})
	return macDict, nil
}

func getArps() ([]ARPData, error) {
    // need to implement by SonicOS.
	arps := []ARPData{}
	return arps, nil
}

func getRoutes() ([]string, error) {
    // need to implement by SonicOS.
	routes := []string{}
	return routes, nil
}

func GetUsertableData() ([]byte, error) {
    // need to implement by SonicOS.
	return []byte{}, nil
}

func GetMacData() ([]byte, error) {
    // need to implement by SonicOS.
	return []byte{}, nil
}

func GetArpData() ([]byte, error) {
    // need to implement by SonicOS.
	return []byte{}, nil

}

func GetRouteData() ([]byte, error) {
    // need to implement by SonicOS.
	return []byte{}, nil

}

func GetDeviceIP() (string, string, string) {
    // need to implement by SonicOS.
	var mgmtIP string
	var mgmtIPv4 string
	var mgmtIPv6 string
	return mgmtIP, mgmtIPv4, mgmtIPv6
}

func GetPortLinkStatusData() error {
    // need to implement by SonicOS.
	return nil
}

func GetStaticTrunkStatusData() ([]OLSStaticTrunks, error) {
    // need to implement by SonicOS.
	StaticTrunkStatusArray := []OLSStaticTrunks{}
	return StaticTrunkStatusArray, nil
}

func GetDynamicTrunkStatusData() ([]OLSLacpTrunks, error) {
    // need to implement by SonicOS.
	DynamicTrunkStatusArray := []OLSLacpTrunks{}
	return DynamicTrunkStatusArray, nil
}

func GetNtpServersData() ([]OLSNTPStatus, error) {
    // need to implement by SonicOS.
	ntpArray := []OLSNTPStatus{}
	return ntpArray, nil
}

func GetPoeLinkStatusData() error {
    // need to implement by SonicOS.
	return nil
}

func getTypeByPoeStatusCode(poeStatusCode string) string {
    // need to implement by SonicOS.
	return ""
}

func sendToController(msg []byte) error {
    // need to implement by SonicOS.
	return nil
}

func getOLStpStatus() (StpStats, error) {
    // need to implement by SonicOS.
	stpStats := StpStats{}
	return stpStats, nil
}
