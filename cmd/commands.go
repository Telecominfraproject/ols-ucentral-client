package main

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"asterfusion/client/logger"
	utils "asterfusion/client/utils"

	"github.com/mitchellh/mapstructure"
)

func handleControllerMsg(wsconn *WsConn, controllerMsg ControllerMsg) error {
	var err error
	method := controllerMsg.Method
	logger.Info("Received %s event message.", method)
	switch method {
	case "configure":
		err = handleUcentralConfigureCommand(wsconn, controllerMsg)
	case "reboot":
		err = handleRebootCommand(wsconn, controllerMsg)
	case "factory":
		err = handleFactoryCommand(wsconn, controllerMsg)
	case "leds":
		err = handleLedsCommand(wsconn, controllerMsg)
	case "trace":
		err = handleTraceCommand(wsconn, controllerMsg)
	case "request":
		err = handleRequestCommand(wsconn, controllerMsg)
	case "telemetry":
		err = handleRequestCommand(wsconn, controllerMsg)
	case "rtty":
		err = handleRttyCommand(wsconn, controllerMsg)
	case "ping":
		err = handlePingCommand(wsconn, controllerMsg)
	case "script":
		err = handleScriptCommand(wsconn, controllerMsg)
	case "upgrade":
		err = handleUpgradeCommand(wsconn, controllerMsg)
	case "powercycle":
		err = handlePowerCycleCommand(wsconn, controllerMsg)
	default:
		logger.Warn("Received unsupported event message: %s.", method)
	}
	if err != nil {
		logger.Info("An error occurred while processing the %s event: %s", method, err.Error())
		return err
	}

	return nil
}

func handlePowerCycleCommand(wsconn *WsConn, message ControllerMsg) error {
	id := message.Id
	params, _ := message.Params.(map[string]interface{})

	ports := PowerCycleObj{}
	err := mapstructure.Decode(params, &ports)
	if err != nil {
		logger.Error("Failed to decode map to struct, [map : %v], [err: %s]", params, err.Error())
	}

	for _, portCycleItem := range ports.PowerCycleArr {
		go setPortPoePowerCycle(portCycleItem.Name, portCycleItem.Cycle)
	}

	result := DeviceResponse{
		Jsonrpc: "2.0",
		Id:      id,
		Result: Result{
			Serial: SerialNum,
			Status: Status{
				Err:  0,
				Text: "success",
				When: 0,
				Rejected: []Rejected{{
					Parameter:    struct{}{},
					Reason:       "",
					Substitution: struct{}{},
				}},
			},
		},
	}

	err = utils.SyncWriteWebsocketJSONResponse(wsconn.Conn, &wsconn.Mux, result)
	if err != nil {
		logger.Error("An error occurred while returning a power cycle event response: %s", err.Error())
		return err
	}

	return nil
}

func setPortPoePowerCycle(portName string, cycle int) {
	ethernetID := strings.Trim(portName, "Ethernet")
	ethernetIDInt, _ := strconv.Atoi(ethernetID)
	asterSonicEthernetID := ethernetIDInt + 1
	portKey := "PORT|Ethernet" + strconv.Itoa(asterSonicEthernetID)
	// 1. check key exists
	iskeyExist, _ := ConfigDb.Db.Exists(portKey).Result()

	if int(iskeyExist) == 0 {
		logger.Warn("Failed to config port poe cycle, the port no exist!")
		return
	}
	// 2. set poe cycle
	portInfo, _ := ConfigDb.Db.HGetAll(portKey).Result()
	if portInfo["media_type"] == "copper" {
		// Power Cycle
		_, _ = ConfigDb.Db.HSet(portKey, "poe_status", "disable").Result()
		_, _ = ConfigDb.Db.HSet(portKey, "poe_enable_mode", "disable").Result()
		time.Sleep(time.Duration(cycle) * time.Millisecond)
		_, _ = ConfigDb.Db.HSet(portKey, "poe_status", "enable").Result()
		_, _ = ConfigDb.Db.HSet(portKey, "poe_enable_mode", "enable").Result()
	}
}

func handleFactoryCommand(wsconn *WsConn, message ControllerMsg) error {
	id := message.Id
	params, _ := message.Params.(map[string]interface{})
	serial, _ := params["serial"].(string)
	// Note: When Redirector is not kept, devices will re-contact the Certificate Authority to re-discover their OpenWiFi cloud address
	// keepRdirector := params["keep_redirector"].(float64)

	// load default_setting && remove /etc/ucentral/ucentral.active
	exit, msg := utils.RunFactoryCommand()
	if exit <= 0 {
		msg = ""
	}

	result := DeviceResponse{
		Jsonrpc: "2.0",
		Id:      id,
		Result: Result{
			Serial: serial,
			Status: Status{
				Err:  int(exit),
				Text: msg,
				When: 0,
				Rejected: []Rejected{{
					Parameter:    struct{}{},
					Reason:       "",
					Substitution: struct{}{},
				}},
			},
		},
	}

	err := utils.SyncWriteWebsocketJSONResponse(wsconn.Conn, &wsconn.Mux, result)
	if err != nil {
		logger.Error("An error occurred while returning a factory event response: %s", err.Error())
		return err
	}

	utils.RebootDelay(uint(15), fmt.Sprintf("Reboot occurred after factory command 15s ..."))

	return nil
}

func changeLedsStatus(led_status string) (exit uint8, msg string) {
	led_status_support := []string{"blink", "down", "up"}
	if led_status == "" {
		return 1, fmt.Sprintf(`Action not supported: nil. Only support: ["%s"].`, strings.Join(led_status_support, `", "`))
	}
	if utils.FindIndex(led_status_support, led_status) >= len(led_status_support) {
		return 1, fmt.Sprintf(`Action not supported: %s. Only support: ["%s"].`, led_status, strings.Join(led_status_support, `", "`))
	}

	if led_status == "down" {
		return utils.RunClishCommandWithTimeout("no led loc", 30)
	} else {
		return utils.RunClishCommandWithTimeout("led loc", 30)
	}
}

func handleLedsStatus(led_status string, duration uint) (exit uint8, msg string) {
	led_status_support := []string{"blink", "down", "up"}
	if led_status == "" {
		return 1, fmt.Sprintf(`Action not supported: nil. Only support: ["%s"].`, strings.Join(led_status_support, `", "`))
	}
	if utils.FindIndex(led_status_support, led_status) >= len(led_status_support) {
		return 1, fmt.Sprintf(`Action not supported: %s. Only support: ["%s"].`, led_status, strings.Join(led_status_support, `", "`))
	}

	exit, msg = utils.RunClishCommandWithTimeout("do show led loc", 30)
	if exit > 0 {
		return exit, msg
	}
	old_led_status := "" // "LOC LED is set to: off" or "LOC LED is set to: on"
	if strings.Contains(msg, "on") {
		old_led_status = "up"
	} else {
		old_led_status = "down"
	}

	if old_led_status == "up" {
		if led_status == "up" || led_status == "blink" {
			logger.Info("The current led status is already %s, no need to change.", led_status)
			return 0, ""
		}
	} else {
		if led_status == "down" {
			logger.Info("The current led status is already %s, no need to change.", led_status)
			return 0, ""
		}
	}

	exit, msg = changeLedsStatus(led_status)
	if exit == 0 {
		if duration <= 0 {
			logger.Info(`No need to add a task to restore the led state. Duration is %v.`, duration)
			return
		}
		if utils.FindIndex(led_status_support, old_led_status) >= len(led_status_support) {
			logger.Warn(`Adding the task of restoring the LED state to %s failed.`, old_led_status)
			return
		}

		logger.Info(`Adding the task of restoring the LED state to %s. When to exec: after %vs.`, old_led_status, duration)
		time.AfterFunc(time.Duration(duration)*time.Second, func() {
			exit, msg = changeLedsStatus(old_led_status)
			if exit > 0 {
				logger.Error("Failed to restore leds state to %s.", old_led_status)
			} else {
				logger.Info("Restore LED state to %s.", old_led_status)
			}
		})
	}
	return exit, msg
}

func handleLedsCommand(wsconn *WsConn, message ControllerMsg) error {
	id := message.Id
	params, _ := message.Params.(map[string]interface{})

	serial, _ := params["serial"].(string)
	duration := params["duration"].(float64)
	pattern := params["pattern"].(string)

	exit, msg := handleLedsStatus(pattern, uint(duration))
	errcode := 0 // 0-succes 1-not support 2-error
	if exit <= 0 {
		errcode = 0
	} else {
		if strings.Contains(msg, "Current device do not support the feature") {
			errcode = 1
			msg = "Current device do not support the feature"
		} else {
			errcode = 2
		}
	}

	result := DeviceResponse{
		Jsonrpc: "2.0",
		Id:      id,
		Result: Result{
			Serial: serial,
			Status: Status{
				Err:  (errcode),
				Text: msg,
				When: 0,
				Rejected: []Rejected{{
					Parameter:    struct{}{},
					Reason:       "",
					Substitution: struct{}{},
				}},
			},
		},
	}

	err := utils.SyncWriteWebsocketJSONResponse(wsconn.Conn, &wsconn.Mux, result)
	if err != nil {
		logger.Error("An error occurred while returning a leds event response: %s.", err.Error())
		return err
	}

	return nil
}

func handlePingCommand(wsconn *WsConn, message ControllerMsg) error {
	id := message.Id
	params, _ := message.Params.(map[string]interface{})
	serial, _ := params["serial"].(string)
	deviceUTCTime := time.Now().UTC().UnixMilli()

	result := CMDPingDeviceResponse{
		Jsonrpc: "2.0",
		Id:      id,
		Result: CMDPingResult{
			Serial:        serial,
			Uuid:          ActiveUuid,
			DeviceUTCTime: deviceUTCTime,
		},
	}

	err := utils.SyncWriteWebsocketJSONResponse(wsconn.Conn, &wsconn.Mux, result)
	if err != nil {
		logger.Error("An error occurred while returning a ping event response: %s", err.Error())
		return err
	}

	return nil
}

func handleRebootCommand(wsconn *WsConn, message ControllerMsg) error {
	id := message.Id
	params, _ := message.Params.(map[string]interface{})
	serial, _ := params["serial"].(string)
	when, _ := params["when"].(int64)

	result := DeviceResponse{
		Jsonrpc: "2.0",
		Id:      id,
		Result: Result{
			Serial: serial,
			Status: Status{
				Err:  0,
				Text: "success",
				When: 0,
				Rejected: []Rejected{{
					Parameter:    struct{}{},
					Reason:       "",
					Substitution: struct{}{},
				}},
			},
		},
	}

	err := utils.SyncWriteWebsocketJSONResponse(wsconn.Conn, &wsconn.Mux, result)
	if err != nil {
		logger.Error("An error occurred while returning a reboot event response: %s", err.Error())
		return err
	}

	utils.RebootDelay(uint(when), fmt.Sprintf("Task added by reboot command, params is %v.", params))
	return nil
}

func handleRttyCommand(wsconn *WsConn, message ControllerMsg) error {
	id := message.Id
	params, _ := message.Params.(map[string]interface{})
	serial, _ := params["serial"].(string)

	device_id, _ := params["id"].(string)
	port, _ := params["port"].(float64)
	server, _ := params["server"].(string)
	token, _ := params["token"].(string)
	timeout, _ := params["timeout"].(float64)
	// user, _ := params["user"].(string)

	vrf, _ := ConfigDb.Db.HGet("UCENTRAL_CLIENT|SERVER", "vrf").Result()

	rttyCmd := ""
	if vrf == "default" || vrf == "" {
		rttyCmd = fmt.Sprintf("rtty -a -v -D -I %s -h %s -p %v -t %s -e %v -s -c %scert.pem -k %skey.pem -d 'rtty'", device_id, server, port, token, timeout, ucentralCertPath, ucentralCertPath)
	} else {
		rttyCmd = fmt.Sprintf("rtty -a -v -D -I %s -h %s -p %v -r %s -t %s -e %v -s -c %scert.pem -k %skey.pem -d 'rtty'", device_id, server, port, vrf, token, timeout, ucentralCertPath, ucentralCertPath)
	}

	exit, msg := utils.RunShellCommand(rttyCmd)

	result := DeviceResponse{
		Jsonrpc: "2.0",
		Id:      id,
		Result: Result{
			Serial: serial,
			Status: Status{
				Err:  int(exit),
				Text: msg,
				When: 0,
				Rejected: []Rejected{{
					Parameter:    struct{}{},
					Reason:       "",
					Substitution: struct{}{},
				}},
			},
		},
	}

	err := utils.SyncWriteWebsocketJSONResponse(wsconn.Conn, &wsconn.Mux, result)
	if err != nil {
		logger.Error("An error occurred while returning a rtty event response: %s", err.Error())
		return err
	}

	return nil
}

func reloadDeviceConfig(config any) (exit uint8, msg string) {
	configJSON, err := json.Marshal(config)
	if err != nil {
		logger.Error("Failed to marshal JSON: %s", err.Error())
		return 2, err.Error()
	}

	// format json
	var fileContent bytes.Buffer
	err = json.Indent(&fileContent, configJSON, "", "    ")
	if err != nil {
		logger.Error("Failed to indent JSON: %s", err.Error())
		return 2, err.Error()
	}

	// Device need to apply configuration?
	oldConfigMd5, err := utils.MD5File(ConfigDBFile)
	if err != nil {
		return 2, err.Error()
	}
	newConfigMd5, err := utils.MD5Str(fileContent.String())
	if err != nil {
		return 2, err.Error()
	}
	if bytes.Equal(oldConfigMd5, newConfigMd5) {
		return 0, "The configuration has been applied. No need to update."
	}

	exit, msg = utils.RunShellScript(fmt.Sprintf("%s reload '%s'", ConfigureScriptFile, fileContent.String()))
	if exit == 0 {
		msg = ""
	}

	return exit, msg
}

func generateDiffConfig(deviceConfig map[string]interface{}) (map[string]interface{}, error) {

	checkKeys := []string{"MGMT_INTERFACE", "DEVICE_METADATA"}
	currentConfig, err := getStateConfiguration()

	if err != nil {
		return deviceConfig, err
	}

	for _, key := range checkKeys {
		if _, found := deviceConfig[key]; found {
			if value, ok := currentConfig[key]; ok {
				deviceConfig[key] = value
			}
		} else {
			return deviceConfig, fmt.Errorf(fmt.Sprintf("Not exit %s", key))
		}
	}

	return deviceConfig, nil
}

func traceDevice(config CMDTraceConifg) (errCode uint, result string) {
	duration := config.Duration
	packets := config.Packets
	interfaces := config.Interface
	uri := config.Uri

	// tcpdump
	filePath := TraceCmdResultFile
	cmd := fmt.Sprintf("tcpdump -w %s", filePath)
	if duration <= 0 && packets <= 0 {
		return 1, "Duration and packets is 0. "
	}
	if duration > 0 {
		cmd += fmt.Sprintf(" -W 1 -G %v", duration)
	} else {
		cmd += " -W 1 -G 120"
	}
	if packets > 0 {
		cmd += fmt.Sprintf(" -c %v", packets)
	}

	if interfaces != "" {
		cmd += fmt.Sprintf(" -i %s", interfaces)
	}

	exit, output := utils.RunShellCommandWithTimeout(cmd, 150)
	if exit > 0 {
		return uint(exit), output
	}

	vrf, err := ConfigDb.Db.HGet("UCENTRAL_CLIENT|SERVER", "vrf").Result()
	if err != nil {
		logger.Error("Failed to get vrf: %v", err)
		return 1, err.Error()
	}
	if err := utils.UploadFile(filePath, uri, vrf); err != nil {
		return 1, err.Error()
	}

	return 0, "done"
}

func handleTraceCommand(wsconn *WsConn, message ControllerMsg) error {
	id := message.Id
	params, _ := message.Params.(map[string]interface{})

	serial, _ := params["serial"].(string)
	duration, _ := params["duration"].(float64)
	packets, _ := params["packets"].(float64)
	network, _ := params["network"].(string)
	interfaces, _ := params["interface"].(string)
	uri, _ := params["uri"].(string)

	var errCode uint
	var errInfo string
	traceConfig := CMDTraceConifg{
		Duration:  int64(duration),
		Packets:   int64(packets),
		Network:   network,
		Interface: interfaces,
		Uri:       uri,
	}
	errCode, errInfo = traceDevice(traceConfig)

	response := DeviceResponse{
		Jsonrpc: "2.0",
		Id:      id,
		Result: Result{
			Serial: serial,
			Status: Status{
				Err:  int(errCode),
				Text: errInfo,
				When: 0,
				Rejected: []Rejected{{
					Parameter:    struct{}{},
					Reason:       "",
					Substitution: struct{}{},
				}},
			},
		},
	}

	err := utils.SyncWriteWebsocketJSONResponse(wsconn.Conn, &wsconn.Mux, response)
	if err != nil {
		logger.Error("An error occurred while returning a trace event response: %s.", err.Error())
		return err
	}

	return nil
}

func handleRequestCommand(wsconn *WsConn, message ControllerMsg) error {
	id := message.Id
	params, _ := message.Params.(map[string]interface{})

	messageType := params["message"].(string)
	// use to present specific request
	requestUuid := params["request_uuid"].(string)
	var resultJson = []byte{}

	if messageType == "state" {
		resultJson, _ = GetStateData(requestUuid)
	} else if messageType == "healthcheck" {
		resultJson, _ = GetHealthcheckData(requestUuid)
	} else {
		logger.Info("The %s type not supported by the request event.", messageType)
		return nil
	}

	result := DeviceResponse{
		Jsonrpc: "2.0",
		Id:      id,
		Result: Result{
			Serial: SerialNum,
			Status: Status{
				Err:  0,
				Text: "success",
				When: 0,
				Rejected: []Rejected{{
					Parameter:    struct{}{},
					Reason:       "",
					Substitution: struct{}{},
				}},
			},
		},
	}
	err := utils.SyncWriteWebsocketJSONResponse(wsconn.Conn, &wsconn.Mux, result)
	if err != nil {
		logger.Error("An error occurred while returning a request event response: %s", err.Error())
		return err
	}
	// Add state/healthcheck event
	err = utils.SyncWriteWebsocketWithJsonResponse(wsconn.Conn, &wsconn.Mux, resultJson)
	if err != nil {
		logger.Error("An error occurred while returning a request event response: %s", err.Error())
		return err
	}

	return nil
}

func runScriptCommand(script string, timeout uint) (errCode uint, result string) {
	rawData, err := base64.StdEncoding.DecodeString(script)
	if err != nil {
		logger.Error("Failed to decode script: %s", err.Error())
		return 2, "invalid base64"
	}

	const scriptPath = ScriptCmdFile
	err = os.WriteFile(scriptPath, rawData, 0700)
	if err != nil {
		logger.Error("Failed to write script file: %s", err.Error())
		return 2, err.Error()
	}

	if timeout <= 0 {
		exit, output := utils.RunShellScriptWithTimeout(scriptPath, 300) // max timeout 300s, same with web
		return uint(exit), output
	} else {
		exit, output := utils.RunShellScriptWithTimeout(scriptPath, timeout)
		return uint(exit), output
	}
}

func uploadSSBResult(content string, uri string) (errCode uint, result string) {
	// Compress and save file
	now := time.Now().UTC() // time format ISO 8601
	filePath := fmt.Sprintf("%s%s.log", SSBFileBundle, now.Format("2006-01-02T15-04-05Z"))

	os.WriteFile(filePath, []byte(content), 0644)

	bundleFileName := fmt.Sprintf("%s%s.gz", SSBFileBundle, now.Format("2006-01-02T15-04-05Z"))

	cmd := fmt.Sprintf("sudo tar -cvf %s /var/log/syslog /var/log/syslog.1 %s --strip-components=1", bundleFileName, filePath)
	utils.RunShellCommandWithTimeout(cmd, 10)

	// upload file
	vrf, err := ConfigDb.Db.HGet("UCENTRAL_CLIENT|SERVER", "vrf").Result()
	if err != nil {
		logger.Error("Failed to get vrf: %v", err)
		return 1, err.Error()
	}
	if err := utils.UploadFile(bundleFileName, uri, vrf); err != nil {
		cmd := fmt.Sprintf("sudo rm %s %s", bundleFileName, filePath)
		utils.RunShellCommandWithTimeout(cmd, 10)
		return 1, err.Error()
	}

	return 0, "done"
}

func uploadScriptCommandResult(content []byte, uri string) (errCode uint, result string) {
	// Compress and save file
	filePath := ScriptCmdResultFile
	now := time.Now().UTC() // time format ISO 8601
	hdr := &tar.Header{
		Name:    fmt.Sprintf("%s.%s.txt", ScriptCmdResultFileName, now.Format("2006-01-02T15-04-05Z")),
		Mode:    0644,
		Size:    int64(len(content)),
		ModTime: now,
	}
	if err := utils.CompressBlobToTarGz(content, filePath, hdr); err != nil {
		return 1, err.Error()
	}

	// upload file
	vrf, err := ConfigDb.Db.HGet("UCENTRAL_CLIENT|SERVER", "vrf").Result()
	if err != nil {
		logger.Error("Failed to get vrf: %v", err)
		return 1, err.Error()
	}
	if err := utils.UploadFile(filePath, uri, vrf); err != nil {
		return 1, err.Error()
	}

	return 0, "done"
}

func handleSSB(wsconn *WsConn, uri string, id int) error {
	var execCode uint
	var execResult string
	uuidInt, _ := strconv.Atoi(currentPlatCfg.Uuid)

	execResponse := CMDScriptDeviceResponse{
		Jsonrpc: "2.0",
		Id:      id,
		Result: CMDScriptResult{
			Uuid:uuidInt,
			Serial: SerialNum,
			Status: CMDScriptStatus{
				Err:    0,
				Result: "pending",
			},
		},
	}

	err := utils.WriteWebsocketJSONResponse(wsconn.Conn, execResponse)
	if err != nil {
		logger.Error("An error occurred while returning a script event response: %s", err.Error())
		return err
	}

	pid := os.Getpid()
	script := fmt.Sprintf("echo 'sudo cat /proc/%d/cmdline;'\n" , pid)
	script += fmt.Sprintf("sudo cat /proc/%d/cmdline;\n" , pid)
	script += fmt.Sprintf("echo 'sudo cat /proc/%d/limits;'\n" , pid)
	script += fmt.Sprintf("sudo cat /proc/%d/limits;\n" , pid)
	script += fmt.Sprintf("echo 'sudo cat /proc/%d/maps;'\n" , pid)
	script += fmt.Sprintf("sudo cat /proc/%d/maps;\n" , pid)
	script += fmt.Sprintf("echo 'sudo cat /proc/%d/smaps;'\n" , pid)
	script += fmt.Sprintf("sudo cat /proc/%d/smaps;\n" , pid)
	script += fmt.Sprintf("echo 'sudo cat /proc/%d/stat;'\n" , pid)
	script += fmt.Sprintf("sudo cat /proc/%d/stat;\n" , pid)
	script += fmt.Sprintf("echo 'sudo cat /proc/%d/statm;'\n" , pid)
	script += fmt.Sprintf("sudo cat /proc/%d/statm;\n" , pid)
	script += fmt.Sprintf("echo 'sudo cat /proc/%d/status;'\n" , pid)
	script += fmt.Sprintf("sudo cat /proc/%d/status;\n" , pid)
	script += fmt.Sprintf("echo 'sudo cat /proc/%d/syscall;'\n" , pid)
	script += fmt.Sprintf("sudo cat /proc/%d/syscall;\n" , pid)
	script += fmt.Sprintf("echo 'sudo cat /proc/%d/wchan;'\n" , pid)
	script += fmt.Sprintf("sudo cat /proc/%d/wchan;\n" , pid)
	script += fmt.Sprintf("echo 'sudo cat /proc/%d/mounts;'\n" , pid)
	script += fmt.Sprintf("sudo cat /proc/%d/mounts;\n" , pid)
	script += fmt.Sprintf("echo 'sudo cat /proc/%d/mountstats;'\n" , pid)
	script += fmt.Sprintf("sudo cat /proc/%d/mountstats;\n" , pid)
	script += fmt.Sprintf("echo 'sudo cat /proc/%d/environ;'\n" , pid)
	script += fmt.Sprintf("sudo cat /proc/%d/environ;\n" , pid)
	script += fmt.Sprintf("echo 'sudo ls -l /proc/%d/fd;'\n" , pid)
	script += fmt.Sprintf("sudo ls -l /proc/%d/fd;\n" , pid)
	script += fmt.Sprintf("echo 'sudo ls -l /proc/%d/fdinfo;'\n" , pid)
	script += fmt.Sprintf("sudo ls -l /proc/%d/fdinfo;\n" , pid)
	script += fmt.Sprintf("echo 'sudo ls -l /proc/%d/net;'\n" , pid)
	script += fmt.Sprintf("sudo ls -l /proc/%d/net;\n" , pid)
	script += fmt.Sprintf("echo 'sudo ls -l /proc/%d/task;'\n" , pid)
	script += fmt.Sprintf("sudo ls -l /proc/%d/task;\n" , pid)
	script += "echo 'sudo dmesg;'\n"
	script += "sudo dmesg;\n"
	script += "echo 'sudo netstat -an;'\n"
	script += "sudo netstat -an;\n"
	script += "echo 'sudo route;'\n"
	script += "sudo route;\n"
	script += "echo 'sudo ps;'\n"
	script += "sudo ps;\n"
	script += "echo 'sudo arp;'\n"
	script += "sudo arp;\n"
	script += "echo 'sudo fdbshow;'\n"
	script += "sudo fdbshow;\n"
	script += "echo 'sudo cat /proc/meminfo;'\n"
	script += "sudo cat /proc/meminfo;\n"
	script += "echo 'sudo cat /proc/devices;'\n"
	script += "sudo cat /proc/devices;\n"
	script += "echo 'sudo xasterdestryt -n 1 -b;'\n"
	script += "sudo xasterdestryt -n 1 -b;\n"
	script += "echo 'sudo  df -h;'\n"
	script += "sudo  df -h;\n"
	script += "echo 'sudo cat /etc/sonic/config_db.json;'\n"
	script += "sudo cat /etc/sonic/config_db.json;\n"

	exit, result := utils.RunShellCommandWithTimeout(script, 300)
	if exit == 0 && uri != "" {
		execCode = 0
		execResult = "done"
	} else {
		execCode = uint(exit)
		execResult = "failed"
	}

	execResponse = CMDScriptDeviceResponse{
		Jsonrpc: "2.0",
		Id:      id,
		Result: CMDScriptResult{
			Serial: SerialNum,
			Uuid:uuidInt,
			Status: CMDScriptStatus{
				Err:    0,
				Result: execResult,
			},
		},
	}

	err = utils.WriteWebsocketJSONResponse(wsconn.Conn, execResponse)
	if err != nil {
		logger.Error("An error occurred while returning a script event response: %s", err.Error())
		return err
	}

	if execCode == 0 {
		// Upload file
		_, _ = uploadSSBResult(result, uri)

		uplaodResponse := LogSSBEvent{
			Jsonrpc: "2.0",
			Method:  "log",
			Params: struct {
				Serial   string  `json:"serial"`
				Log      string  `json:"log"`
				Severity int     `json:"severity"`
			}{
				Serial: SerialNum,
				Log:    "upload complete",
				Severity: 6,
			},
		}

		err = utils.WriteWebsocketJSONResponse(wsconn.Conn, uplaodResponse)
		if err != nil {
			logger.Error("An error occurred while returning a script event response: %s", err.Error())
			return err
		}
	}
	return nil
}

func handleScriptCommand(wsconn *WsConn, message ControllerMsg) error {
	id := message.Id
	params, _ := message.Params.(map[string]interface{})
	script, _ := params["script"].(string)
	stype, _ := params["type"].(string)
	uri, _ := params["uri"].(string)
	timeout, _ := params["timeout"].(float64)
	// when, _ := params["when"].(float64)

	// max timeout in seconds, default is 30, unused if URI is supplied
	usedUri := true
	if uri == "" {
		usedUri = false
	} else {
		timeout = 0
	}

	// Err code:
	//  0 - success
	//  1 - "script did not generate any output"
	//  2 - "invalid base64"
	//  3 - "invalid signature"
	//  255 - "timed out" || "unknown"

	if stype == "shell" {
		var execCode uint
		var execResult string

		exit, result := runScriptCommand(script, uint(timeout))
		if exit == 0 && uri != "" {
			execCode = 0
			execResult = "pending"
		} else {
			execCode = exit
			execResult = result
		}

		execResponse := CMDScriptDeviceResponse{
			Jsonrpc: "2.0",
			Id:      id,
			Result: CMDScriptResult{
				Serial: SerialNum,
				Status: CMDScriptStatus{
					Err:    execCode,
					Result: execResult,
				},
			},
		}

		err := utils.WriteWebsocketJSONResponse(wsconn.Conn, execResponse)
		if err != nil {
			logger.Error("An error occurred while returning a script event response: %s", err.Error())
			return err
		}

		if execCode == 0 && usedUri {
			// Upload file
			uploadCode, uploadResult := uploadScriptCommandResult([]byte(result), uri)

			uplaodResponse := CMDScriptDeviceResponse{
				Jsonrpc: "2.0",
				Id:      id,
				Result: CMDScriptResult{
					Serial: SerialNum,
					Status: CMDScriptStatus{
						Err:    uploadCode,
						Result: uploadResult,
					},
				},
			}
			err = utils.WriteWebsocketJSONResponse(wsconn.Conn, uplaodResponse)
			if err != nil {
				logger.Error("An error occurred while returning a script event response: %s", err.Error())
				return err
			}
		}
	} else if stype == "diagnostic" {
		go handleSSB(wsconn, uri, id)
	} else {
		execResponse := CMDScriptDeviceResponse{
			Jsonrpc: "2.0",
			Id:      id,
			Result: CMDScriptResult{
				Serial: SerialNum,
				Status: CMDScriptStatus{
					Err:    3,
					Result: "invalid signature",
				},
			},
		}
		err := utils.WriteWebsocketJSONResponse(wsconn.Conn, execResponse)
		if err != nil {
			logger.Error("An error occurred while returning a script event response: %s", err.Error())
			return err
		}
	}

	return nil
}

func upgradeDevice(wsconn *WsConn, uri string, signature string) (errCode uint, result string) {
	// Signature check is not implemented!
	if signature == "" {
		logger.Warn("Missing signature.")
	}
	if len(signature) != 32 {
		logger.Warn("Invalid signature: len(signature) %v", len(signature))
	}
	logger.Info("Signature check is not implemented!\n")
	logger.Info("Downloading image...\n")
	vrf, err := ConfigDb.Db.HGet("UCENTRAL_CLIENT|SERVER", "vrf").Result()
	if err != nil {
		logger.Error("Failed to get vrf: %v", err)
		return 1, err.Error()
	}
	newVersion := ""
	uriList := strings.Split(uri, "/")
	FirmwareArr := strings.Split(uriList[len(uriList)-1], "-v")
	if len(FirmwareArr) == 2 {
		newVersion = "v" + strings.ReplaceAll(FirmwareArr[1], ".bin", "")
	}

	upgradeStatusEvent(wsconn, "upg.download-in-progress", newVersion, "", "1")
	upgradeStatusEvent(wsconn, "upg.validation-start", newVersion, "", "")
	if err := utils.DownloadFile(FirmwareFile, uri, vrf, ""); err != nil {
		upgradeStatusEvent(wsconn, "upg.download-failed", newVersion, err.Error(), "")
		return 1, err.Error()
	}
	upgradeStatusEvent(wsconn, "upg.download-in-progress", newVersion, "", "100")

	logger.Info("Installing image...\n")
	if exit, output := utils.RunShellCommand(fmt.Sprintf("sonic_installer install -y %s", FirmwareFile)); exit > 0 {
		return uint(exit), output
	}

	logger.Info("Install image finished.")
	return 0, ""
}

func handleUpgradeCommand(wsconn *WsConn, message ControllerMsg) error {
	id := message.Id
	params, _ := message.Params.(map[string]interface{})

	serial, _ := params["serial"].(string)
	uri, _ := params["uri"].(string)
	signature, _ := params["signature"].(string)
	newVersion := ""
	uriList := strings.Split(uri, "/")
	FirmwareArr := strings.Split(uriList[len(uriList)-1], "-v")
	if len(FirmwareArr) == 2 {
		newVersion = "v" + strings.ReplaceAll(FirmwareArr[1], ".bin", "")
	}
	upgradeStatusEvent(wsconn, "upg.upgrade-start", newVersion, "", "")

	code, msg := upgradeDevice(wsconn, uri, signature)
	if code == 1 {
		upgradeStatusEvent(wsconn, "upg.upgrade-failed", newVersion, msg, "")
	}

	response := DeviceResponse{
		Jsonrpc: "2.0",
		Id:      id,
		Result: Result{
			Serial: serial,
			Status: Status{
				Err:  int(code),
				Text: msg,
				When: 0,
			},
		},
	}
	err := utils.WriteWebsocketJSONResponse(wsconn.Conn, response)
	if err != nil {
		logger.Error("An error occurred while returning a script event response: %s", err.Error())
		return err
	}
	upgradeStatusEvent(wsconn, "upg.upgrade-success", newVersion, "", "")
	utils.RebootDelay(uint(15), fmt.Sprintf("Reboot occurred after upgrade command 15s ..."))
	return nil
}

func upgradeStatusEvent(wsconn *WsConn, eventType string, newVersion string, errorMsg string, process string) error {
	switchIP := getStatePublicIP()
	playload := map[string]interface{}{}
	objectMap := map[string]string{}
	switchIPList := strings.Split(switchIP, "/")
	objectMap["name"] = switchIPList[0]
	if !currentPlatCfg.Switch.RTEvent.FwUpgrade.Enabled {
		return nil
	}
	if eventType == "upg.upgrade-start" {
		if !currentPlatCfg.Switch.RTEvent.FwUpgrade.SubEvents.UpgInstallStart {
			return nil
		}
		objectMap["from_version"] = FIRMWARE
		objectMap["to_version"] = newVersion
	} else if eventType == "upg.upgrade-success" {
		if !currentPlatCfg.Switch.RTEvent.FwUpgrade.SubEvents.UpgSuccess {
			return nil
		}
		objectMap["version"] = newVersion
	} else if eventType == "upg.validation-start" {
		if !currentPlatCfg.Switch.RTEvent.FwUpgrade.SubEvents.UpgValidationStart {
			return nil
		}
		objectMap["version"] = newVersion
	} else if eventType == "upg.upgrade-failed" {
		if !currentPlatCfg.Switch.RTEvent.FwUpgrade.SubEvents.UpgInstallFailed {
			return nil
		}
		objectMap["version"] = newVersion
		objectMap["reason"] = errorMsg
	} else if eventType == "upg.download-failed" {
		if !currentPlatCfg.Switch.RTEvent.FwUpgrade.SubEvents.UpgDownloadFailed {
			return nil
		}
		objectMap["version"] = newVersion
		objectMap["reason"] = errorMsg
	} else if eventType == "upg.download-in-progress" {
		if !currentPlatCfg.Switch.RTEvent.FwUpgrade.SubEvents.UpgDownloadinProgress {
			return nil
		}
		objectMap["version"] = newVersion
		objectMap["progress"] = process
	}

	playload["payload"] = objectMap
	playload["type"] = eventType
	timeStamp := uint64(time.Now().Unix())
	eventData := []interface{}{}
	eventData = append(eventData, timeStamp)
	eventData = append(eventData, playload)

	var DataEvent DataStruct
	DataEvent.Event = eventData

	event := UpgradeStatusEvent{
		Jsonrpc: "2.0",
		Method:  "event",
		Params: struct {
			Serial string     `json:"serial"`
			Data   DataStruct `json:"data"`
		}{
			Serial: SerialNum,
			Data:   DataEvent,
		},
	}
	err := utils.WriteWebsocketJSONResponse(wsconn.Conn, event)
	if err != nil {
		logger.Error("An error occurred while returning a upgrade event response: %s", err.Error())
		return err
	}
	return nil
}

func handleUcentralConfigureCommand(wsconn *WsConn, message ControllerMsg) error {
	id := message.Id
	params, _ := message.Params.(map[string]interface{})
	uuid, _ := params["uuid"].(float64)
	uuidStr := strconv.FormatFloat(uuid, 'f', 0, 64)
	uuidInt, _ := strconv.Atoi(uuidStr)
	serial, _ := params["serial"].(string)
	RestartUcentralclient = false

	// Error codes
	//  0 : configuration was applied as-is.
	//  1 : configuration was applied with the included substitutions in the rejected section. The device is operating with the new modified config.
	//  2 : configuration was rejected and will not be applied at all. The rejected section can be used to tell the controller why.
	errorCode := ErrorCodeSuccess
	errorInfo := ""
	// ## 1. validate json
	config, isMap := params["config"].(map[string]interface{})

	if !isMap {
		errorCode = ErrorCodeFail
		errorInfo = "unsupported configuration."
		// check uuid && serial && config
	} else if uuidStr == "" || serial == "" {
		errorCode = ErrorCodeFail
		errorInfo = "configure message is missing parameters."
	} else {
		resultVlan := DeviceResponse{
			Jsonrpc: "2.0",
			Id:      id,
			Result: Result{
				Serial: serial,
				Uuid:   uuidInt,
				Status: Status{
					Err:  0,
					Text: "",
					When: 0,
					Rejected: []Rejected{{
						Parameter:    struct{}{},
						Reason:       "",
						Substitution: struct{}{},
					}},
				},
			},
		}
		ret, err := platConfigHandle(config, uuidStr, wsconn, resultVlan)
		errorCode = ret
		if err != nil {
			errorInfo = err.Error()
		} else {
			ActiveUuid = uuidInt
		}
	}

	// ## 4. return contoller result
	result := DeviceResponse{
		Jsonrpc: "2.0",
		Id:      id,
		Result: Result{
			Serial: serial,
			Uuid:   uuidInt,
			Status: Status{
				Err:  errorCode,
				Text: errorInfo,
				When: 0,
				Rejected: []Rejected{{
					Parameter:    struct{}{},
					Reason:       errorInfo,
					Substitution: struct{}{},
				}},
			},
		},
	}

	err := utils.SyncWriteWebsocketJSONResponse(wsconn.Conn, &wsconn.Mux, result)
	if err != nil {
		logger.Error("An error occurred while returning a configure event response: %s", err.Error())
		return err
	}

	if RestartUcentralclient {
		time.Sleep(2000 * time.Millisecond)
		cmd := "systemctl restart ucentral-client"
		utils.RunShellCommandWithTimeout(cmd, 3)
	}

	return nil
}

func platConfigHandle(config map[string]interface{}, uuid string, wsconn *WsConn, resultVlan DeviceResponse) (int, error) {
	// do not need check, check in every modules,like port/vlan etc..
	/*
		// 1. check old & new config is same
		isSame, err := checkUcentralCfgIsSame(config)

		if err != nil {
			return ErrorCodeFail, err
		}
		new config is the same as old config, do not need config
		if isSame {
			return ErrorCodeSuccess, nil
		}
	*/
	// 2. parse Json
	platCfg, err := cfgParse(config)
	if err != nil {
		return ErrorCodeFail, err
	}
	// 3. apply config (plat_config_apply)
	ret, err := platConfigApply(platCfg, config, wsconn, resultVlan)
	if ret > 0 {
		logger.Error("Failed to platConfigApply to switch, [error: %s]", err.Error())
		return ret, err
	}
	// 4. save config
	ret, err = platConfigSave()
	if ret > 0 {
		return ret, err
	}
	// 5. save config to /etc/ucentral/ucentral.cfg.XXXXX
	ret, err = ucentralConfigSave(config, uuid)
	if ret > 0 {
		return ret, err
	}
	// 6. save config to currentcfg
	currentPlatCfg = platCfg
	return ErrorCodeSuccess, nil
}

func ucentralConfigSave(config map[string]interface{}, uuid string) (int, error) {
	newuCentralCfgPath := uCentrakCfgPathPrefix + uuid
	file, err := os.OpenFile(newuCentralCfgPath, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		logger.Error("Failed to create file: %s, err: %s", newuCentralCfgPath, err.Error())
		return ErrorCodeFail, err
	}
	defer file.Close()
	configByte, err := json.Marshal(config)
	if err != nil {
		logger.Error("Failed to marshal config to json str: %v, err: %s", config, err.Error())
		return ErrorCodeFail, err
	}
	_, err = file.Write(configByte)
	if err != nil {
		logger.Error("Failed to write config to file: %s, err: %s", newuCentralCfgPath, err.Error())
		return ErrorCodeFail, err
	}
	// relink to new cfgpath
	_, err = os.Stat(uCentrakCfgPath)
	// exist
	if err == nil {
		err = os.Remove(uCentrakCfgPath)
		if err != nil {
			logger.Error("Failed to remove file: %s, err: %s", uCentrakCfgPath, err.Error())
			return ErrorCodeFail, err
		}
	}
	// ucentral.cfg.active ---> /etc/ucentral/ucentral.cfg.XXXXX
	err = os.Symlink(newuCentralCfgPath, uCentrakCfgPath)
	if err != nil {
		logger.Error("Failed to link from %s to %s, err: %s", uCentrakCfgPath, newuCentralCfgPath, err.Error())
		return ErrorCodeFail, err
	}
	logger.Info("Save ucentral config %s to switch successfully!!!", newuCentralCfgPath)
	return ErrorCodeSuccess, nil
}

func platConfigSave() (int, error) {
	env := []string{"CONFIG_VIEW=true"}
	// 1. save klish commands
	cmds := []string{"/usr/sbin/cli/af-cli-frr.py", "save", "running-config"}
	exit, msg := utils.RunCommand("python", env, cmds...)
	if exit > 0 {
		return 1, errors.New(msg)
	}
	// 2. save sonic cli
	cmdSave := "config save -y"
	exit, msg = utils.RunCommand("bash", env, "-c", cmdSave)
	if exit > 0 {
		return 1, errors.New(msg)
	}
	return 0, nil
}

func platConfigSaveByKlish() (int, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	env := []string{"CONFIG_VIEW=true"}
	cmd := exec.Command("/usr/local/bin/scripts/clish_start", "-c", "write")
	cmd.Stdin = strings.NewReader("y")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = env
	err := cmd.Run()
	if err != nil {
		logger.Error("Command failed with error: %q. Stderr: %q", err.Error(), stderr.String())
		codestr := strings.TrimPrefix(err.Error(), "exit status ")
		code, e := strconv.Atoi(codestr)
		if e != nil {
			code = 1
		}
		return code, errors.New(codestr)
	}
	return 0, nil
}

func cfgParse(config map[string]interface{}) (PlatCfg, error) {
	platCfg := PlatCfg{}
	// platCfg.Strict = config["strict"].(bool)
	uuid, _ := config["uuid"].(float64)
	uuidStr := strconv.FormatFloat(uuid, 'f', 0, 64)
	platCfg.Uuid = uuidStr
	if config["public_ip_lookup"] != nil {
		platCfg.PublicIpLookup = config["public_ip_lookup"].(string)
		PublicIpLookup = platCfg.PublicIpLookup
	}
	err := mapstructure.Decode(config["unit"], &platCfg.Unit)
	if err != nil {
		logger.Error("Failed to decode JSON, [unit], [json : %v], [err: %s]", config["unit"], err.Error())
	}

	err = mapstructure.Decode(config["globals"], &platCfg.Globals)
	if err != nil {
		logger.Error("Failed to decode JSON, [globals], [json : %v], [err: %s]", config["globals"], err.Error())
	}

	err = mapstructure.Decode(config["ethernet"], &platCfg.Ethernet)
	if err != nil {
		logger.Error("Failed to decode JSON, [ethernet], [json : %v], [err: %s]", config["ethernet"], err.Error())
	}

	err = mapstructure.Decode(config["interfaces"], &platCfg.Interfaces)
	if err != nil {
		logger.Error("Failed to decode JSON, [interfaces], [json : %v], [err: %s]", config["interfaces"], err.Error())
	}

	err = mapstructure.Decode(config["metrics"], &platCfg.Metrics)
	if err != nil {
		logger.Error("Failed to decode JSON, [metrics], [json : %v], [err: %s]", config["metrics"], err.Error())
	}

	err = mapstructure.Decode(config["switch"], &platCfg.Switch)
	if err != nil {
		logger.Error("Failed to decode JSON, [switch], [json : %v], [err: %s]", config["switch"], err.Error())
	}

	err = mapstructure.Decode(config["services"], &platCfg.Services)
	if err != nil {
		logger.Error("Failed to decode JSON, [service], [json : %v], [err: %s]", config["service"], err.Error())
	}

	return platCfg, nil
}

func platConfigApply(platCfg PlatCfg, rawConfig map[string]interface{}, wsconn *WsConn, resultVlan DeviceResponse) (int, error) {
	// result := []string{}

	issameConfig["Interfaces"] = reflect.DeepEqual(platCfg.Interfaces, currentPlatCfg.Interfaces)
	issameConfig["Ethernet"] = reflect.DeepEqual(platCfg.Ethernet, currentPlatCfg.Ethernet)
	issameConfig["Switch"] = reflect.DeepEqual(platCfg.Switch, currentPlatCfg.Switch)

	// 1.config vlan
	_, err := configVlanApply(platCfg, wsconn, resultVlan)
	if err != nil {
		return ErrorCodePartSuccess, err
	}
	// 2.config port/poe/dot1x/lag
	_, err = platPortConfigApply(platCfg)
	if err != nil {
		return ErrorCodePartSuccess, err
	}
	// 10.config AAA, need before dot1x
	_, err = configIeee8021xApply(platCfg)
	if err != nil {
		return ErrorCodePartSuccess, err
	}
	// 3.config unit
	_, err = configUnitApply(platCfg)
	if err != nil {
		return ErrorCodePartSuccess, err
	}
	// 4.config STP
	_, err = configStpApply(platCfg)
	if err != nil {
		return ErrorCodePartSuccess, err
	}
	// bind mstp instance with specific vlan
	_, err = configStpInstanceBindVlan(platCfg)
	if err != nil {
		return ErrorCodePartSuccess, err
	}
	// 5.config SVI
	_, err = configVlanIpv4Apply(platCfg)
	if err != nil {
		return ErrorCodePartSuccess, err
	}
	// 6.config Port L2 IPv4
	_, err = configPortl2Ipv4Apply(platCfg)
	if err != nil {
		return ErrorCodePartSuccess, err
	}
	// 8.config Metrics
	_, err = configMetricsApply(platCfg, rawConfig)
	if err != nil {
		return ErrorCodePartSuccess, err
	}
	// 9.config Router
	_, err = configRouterApply(platCfg)
	if err != nil {
		return ErrorCodePartSuccess, err
	}
	// 10.config Dynamic vlan
	_, err = configDynamicVlanApply(platCfg)
	if err != nil {
		return ErrorCodePartSuccess, err
	}

	// 10.5 config Mvr
	_, err = configMvrApply(platCfg)
	if err != nil {
		return ErrorCodePartSuccess, err
	}

	// 11.config Igmp
	_, err = configIGMPApply(platCfg)
	if err != nil {
		return ErrorCodePartSuccess, err
	}
	// 12. config port isolation
	_, err = configPortIsolationApply(platCfg)
	if err != nil {
		return ErrorCodePartSuccess, err
	}
	// 13. config port mirror
	_, err = configPortMirrorApply(platCfg)
	if err != nil {
		return ErrorCodePartSuccess, err
	}

	// 14. config service state
	_, err = configServiceApply(platCfg, rawConfig)
	if err != nil {
		return ErrorCodePartSuccess, err
	}

	// 15. config trunk balance method (hash mode)
	_, err = configTrunkBalanceMethodApply(platCfg)
	if err != nil {
		return ErrorCodePartSuccess, err
	}

	// 16. config jumbo frames
	_, err = configJumboFramesApply(platCfg)
	if err != nil {
		return ErrorCodePartSuccess, err
	}

	// 17. config dhcp snooping
	_, err = configDhcpSnoopingApply(platCfg)
	if err != nil {
		return ErrorCodePartSuccess, err
	}

	// 18. config Mac Acl or IP Acl
	_, err = configAclApply(platCfg)
	if err != nil {
		return ErrorCodePartSuccess, err
	}

	// 19.config DHCP Relay
	_, err = configVlanDhcpRelayApply(platCfg)
	if err != nil {
		return ErrorCodePartSuccess, err
	}

	// 20.config Voice Vlan
	_, err = configVoiceVlanApply(platCfg)
	if err != nil {
		return ErrorCodePartSuccess, err
	}

	// 21.config Mclag
	_, err = configMclagApply(platCfg)
	if err != nil {
		return ErrorCodePartSuccess, err
	}

	// 22.config IPSG
	_, err = configIPSGApply(platCfg)
	if err != nil {
		return ErrorCodePartSuccess, err
	}

	// 23.config rate limit
	_, err = configRateLimitApply(platCfg)
	if err != nil {
		return ErrorCodePartSuccess, err
	}

	// 24.config DAI
	_, err = configDAIApply(platCfg)
	if err != nil {
		return ErrorCodePartSuccess, err
	}

	// 25.config LLdp
	_, err = configLLDPApply(platCfg)
	if err != nil {
		return ErrorCodePartSuccess, err
	}

	// 26.config BPDU Guard
	_, err = configBpduGuardApply(platCfg)
	if err != nil {
		return ErrorCodePartSuccess, err
	}

	// 27.config BUM
	_, err = configBUMApply(platCfg)
	if err != nil {
		return ErrorCodePartSuccess, err
	}

	logger.Info("Config ucentral config to switch successfully!!!")
	return ErrorCodeSuccess, nil
}

func configServiceApply(platCfg PlatCfg, rawConfig map[string]interface{}) (int, error) {
    // need to implement by SonicOS.
	return ErrorCodeSuccess, nil
}

func configPortIsolationApply(platCfg PlatCfg) (int, error) {
    // need to implement by SonicOS.	
	return ErrorCodeSuccess, nil
}

func configTrunkBalanceMethodApply(platCfg PlatCfg) (int, error) {
    // need to implement by SonicOS.
	return ErrorCodeSuccess, nil

}

func configJumboFramesApply(platCfg PlatCfg) (int, error) {
    // need to implement by SonicOS.
	return ErrorCodeSuccess, nil

}

func configMvrApply(platCfg PlatCfg) (int, error) {
    // need to implement by SonicOS.
	return ErrorCodeSuccess, nil

}

func configDhcpSnoopingApply(platCfg PlatCfg) (int, error) {
    // need to implement by SonicOS.
	return ErrorCodeSuccess, nil

}

func configAclApply(platCfg PlatCfg) (int, error) {
    // need to implement by SonicOS.
	return ErrorCodeSuccess, nil

}

func configPortMirrorApply(platCfg PlatCfg) (int, error) {
    // need to implement by SonicOS.
	return ErrorCodeSuccess, nil

}

func configIGMPApply(platCfg PlatCfg) (int, error) {
    // need to implement by SonicOS.
	return ErrorCodeSuccess, nil

}

func configVlanApply(platCfg PlatCfg, wsconn *WsConn, resultVlan DeviceResponse) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil
}

func configIeee8021xApply(platCfg PlatCfg) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil

}

func configDynamicVlanApply(platCfg PlatCfg) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil

}

func configRouterApply(platCfg PlatCfg) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil

}

func platRouterConfigSet(klishCmd string) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil
}

func configMetricsApply(platCfg PlatCfg, rawConfig map[string]interface{}) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil
}

func configVlanDhcpRelayApply(platCfg PlatCfg) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil
}

func configVoiceVlanApply(platCfg PlatCfg) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil
}

func configMclagApply(platCfg PlatCfg) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil
}

func configIPSGApply(platCfg PlatCfg) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil
}


func configRateLimitApply(platCfg PlatCfg) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil
}

func configBpduGuardApply(platCfg PlatCfg) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil
}


func configBUMApply(platCfg PlatCfg) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil
}


func configDAIApply(platCfg PlatCfg) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil
}

func configLLDPApply(platCfg PlatCfg) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil
}

func configStpApply(platCfg PlatCfg) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil
}

func configStpInstanceBindVlan(platCfg PlatCfg) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil
}

func configStpStateSet(configStpEnabled bool) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil
}

func configPortl2Ipv4Apply(platCfg PlatCfg) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil
}

func in(target string, str_array []string) bool {
	sort.Strings(str_array)
	index := sort.SearchStrings(str_array, target)
	if index < len(str_array) && str_array[index] == target {
		return true
	}
	return false
}

func configVlanIpv4Apply(platCfg PlatCfg) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil
}

func configUnitApply(platCfg PlatCfg) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil
}

func platIeee8021xConfigSet(klishCmd string) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil
}

func platPortConfigApply(platCfg PlatCfg) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil
}

func platLagConfigApply(platCfg PlatCfg) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil
}

func poeSwitchAsterPoePowerlimit(configPoe int) int {
	result := 0
	if configPoe <= 15000 {
		result = 15
	} else if configPoe <= 30000 {
		result = 30
	} else {
		result = 60
	}
	return result
}

func poeSwitchAsterPoePriority(configPoe string) string {
	result := "low"
	if configPoe == "medium" {
		result = "low"
	} else {
		result = configPoe
	}
	return result
}

func platPortPoeConfigYesSet(asterSonicEthernetID int, klishCmd string) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil
}

func platPortPoeConfigSet(asterSonicEthernetID int, klishCmd string) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil
}

func platPortConfigSet(asterSonicEthernetID int, klishCmd string) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil
}

func platVlanConfigSet(asterSonicVlanID int) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil
}

func platVlanMembersConfigSet(asterSonicEthernetID int, klishCmd string) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil
}

func platVlanIfConfigDel(asterSonicVlanID int) (int, error) {
	// need to implement by SonicOS.
	return ErrorCodeSuccess, nil
}

func checkUcentralCfgIsSame(config any) (bool, error) {
	return false, nil
}
