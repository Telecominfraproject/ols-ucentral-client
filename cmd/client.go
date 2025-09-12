package main

import (
	"asterfusion/client/config"
	"asterfusion/client/logger"
	"asterfusion/client/utils"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"os/exec"

	"github.com/go-co-op/gocron"
	"github.com/gorilla/websocket"
	"golang.org/x/sys/unix"
)

type WsConn struct {
	*websocket.Conn
	Mux sync.RWMutex
}

const (
	reconnectDelay         = 10 * time.Second // Time to wait before attempting to reconnect
	checkConfigDbInitDelay = 5 * time.Second  // Time to wait before attempting to reconnect
)

const (
	ucentralCertPath       = "/etc/ucentral/certs/"
	certPath               = "/etc/ucentral/certs/cert.pem"
	keyPath                = "/etc/ucentral/certs/key.pem"
	casPath                = "/etc/ucentral/certs/cas.pem"
	operationalPath        = "/etc/ucentral/certs/operational.pem"
	operationalCAPath        = "/etc/ucentral/certs/operational.ca"
	devidPath              = "/etc/ucentral/certs/dev-id"
	uCentrakCfgPath        = "/etc/ucentral/ucentral.active"
	uCentrakCfgPathPrefix  = "/etc/ucentral/ucentral.cfg."
	uCentralRedirectorHost = "https://clientauth.one.digicert.com/iot/api/v2/device/"
	redirectorFile         = "/tmp/ucentral-redirector.json"
	redirectorFileDbg      = "/tmp/firstcontact.hdr"
)

var (
	cloudDiscoveryHost     	= "https://discovery.open-lan.org/v1/devices/"
)

var (
	Client    WsConn
	ConfigDb  *RedisSingleObj
	CounterDb *RedisSingleObj
	StateDb   *RedisSingleObj
	APPDb     *RedisSingleObj
	ASICDb    *RedisSingleObj
)

var (
	ControllerAddr = ""
	ControllerPort = "15002"
	ReportInterval = 1.0
	FIRMWARE       = "v4.1.0-rc2"
	RestartUcentralclient = false
)

var (
	StateEventEnabled              = true
	HealthCheckEventEnabled        = true
	StateEventReportInterval       = 60
	HealthCheckEventReportInterval = 60
	MaxMacCount                    = METRICS_WIRED_CLIENTS_MAX_NUM
)

var (
	SerialNum            string = "000000000000"
	ActiveUuid           int    = 0
	ConnectEventInstance        = ConnectEvent{
		Jsonrpc: "2.0",
		Method:  "connect",
		Params: struct {
			Serial       string       `json:"serial"`
			Uuid         int          `json:"uuid"`
			Firmware     string       `json:"firmware"`
			Wanip        []string     `json:"wanip"`
			Capabilities Capabilities `json:"capabilities"`
		}{
			Serial:       SerialNum, // Device serial number
			Uuid:         1,
			Firmware:     "",             // Device firmware version
			Wanip:        []string{},     // WAN IP addresses (empty for now)
			Capabilities: Capabilities{}, // Device capabilities (e.g. supported protocols)
		},
	}
)

var (
	currentPlatCfg        = PlatCfg{}
	issameConfig	      = map[string]bool{"Interfaces": false, "Ethernet": false, "Switch": false}
	currentPortLinkStatus = map[int]string{}
	currentPoeLinkStatus  = map[int]string{}
	PublicIpLookup        = "ifconfig.me"
	VlanStatsLast = map[string]InterfaceCounter{}
	PortStatsLast = map[string]OLSInterfaceCounter{}
)

func sendMessageToController() error {
	stateJson, err := GetStateData("")
	if err != nil {
		// do not disconnect with controller
		logger.Info("Failed to send state data when init connection to controller.")
		return nil
	}
	logger.Info("Sending state data when init connection to controller.")

	err = utils.SyncWriteWebsocketWithJsonResponse(Client.Conn, &Client.Mux, stateJson)
	if err != nil {
		logger.Error("Error writing state data to controller: %s", err.Error())
		return err
	}
	return nil
}

// Connect to the controller.
func connectToController() error {
	if err := utils.WriteWebsocketJSONResponse(Client.Conn, ConnectEventInstance); err != nil {
		logger.Error("Failed to connect controller: %s", err.Error())
		return err
	}
	return nil
}

func setSocketOptions(network, address string, c syscall.RawConn, interfaceName string) (err error) {
	if interfaceName == "" || (!isTCPSocket(network) && !isUDPSocket(network)) {
		return
	}
	logger.Info("Bind to device %s.", interfaceName)

	err = c.Control(func(fd uintptr) {
		host, _, _ := net.SplitHostPort(address)
		if ip := net.ParseIP(host); ip != nil && !ip.IsGlobalUnicast() {
			return
		}

		if innerErr := unix.BindToDevice(int(fd), interfaceName); innerErr != nil {
			return
		}
	})
	return
}

func isTCPSocket(network string) bool {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return true
	default:
		return false
	}
}

func isUDPSocket(network string) bool {
	switch network {
	case "udp", "udp4", "udp6":
		return true
	default:
		return false
	}
}

// Open a WebSocket connection with the controller.
func openConnection() (*websocket.Conn, error) {
	vrf, _ := ConfigDb.Db.HGet("UCENTRAL_CLIENT|SERVER", "vrf").Result()

	netDialer := &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			return setSocketOptions(network, address, c, vrf)
		},
	}

	var dialer *websocket.Dialer
	ctx := context.Background()

	if vrf == "default" || vrf == "" {
		dialer = websocket.DefaultDialer
	} else {
		dialer = &websocket.Dialer{
			Proxy:            http.ProxyFromEnvironment,
			HandshakeTimeout: 60 * time.Second,
			NetDial: func(network, address string) (net.Conn, error) {
				return netDialer.DialContext(ctx, network, address)
			},
		}
	}

	controllerUrl := ControllerAddr + ":" + ControllerPort
	u := url.URL{
		Scheme: "wss",
		Host:   controllerUrl,
		Path:   "/",
	}

	// TIP certs --> Device certs(cas.pem/cert.pem/key.pem)
	cert, err := tls.LoadX509KeyPair(operationalPath, keyPath)
	if err != nil {
		logger.Error("Loading certs failed, Error: %s", err.Error())
	}
	logger.Info("Loading certs of device successfully!!! ")
	
	caCertPool := x509.NewCertPool()

	caCert, err := os.ReadFile(casPath)
	if err != nil {
		logger.Error("Reading %s failed, err is %s:", casPath, err.Error())
	} else {
		caCertPool.AppendCertsFromPEM(caCert)
	}
	opreationalCaCert, err := os.ReadFile(operationalCAPath)
	if err != nil {
		logger.Error("Reading %s failed, err is %s:", operationalCAPath, err.Error())
	} else {
		caCertPool.AppendCertsFromPEM(opreationalCaCert)
	}
	
	tlsConfig := &tls.Config{
		RootCAs:			caCertPool,
		Certificates:       []tls.Certificate{cert},
	}

	logger.Info("Connecting to %s", u.String())
	dialer.TLSClientConfig = tlsConfig
	dialer.WriteBufferSize = 200000
	c, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		return nil, err
	}

	return c, nil
}

// Attempt to reconnect to the controller if the connection is lost.
func waitForConnection() {
	// Initialize the connection state to unconnected before connecting
	vrf, _ := ConfigDb.Db.HGet("UCENTRAL_CLIENT|SERVER", "vrf").Result()
	serverIP, _ := ConfigDb.Db.HGet("UCENTRAL_CLIENT|SERVER", "ip").Result()
	if len(serverIP) != 0 {
		StateDb.Db.HSet(fmt.Sprintf("%s|%s|%s", "UCENTRAL_CLIENT_SERVER", serverIP, vrf), "status", "unconnected")
	}

	for {
		client, err := openConnection()
		if err == nil {
			Client.Conn = client

			// Set connection to connected
			if len(serverIP) != 0 {
				StateDb.Db.HSet(fmt.Sprintf("%s|%s|%s", "UCENTRAL_CLIENT_SERVER", serverIP, vrf), "status", "connected")
			}

			logger.Info("Connection established successfully.")
			return
		}

		logger.Warn("Connection failed: %s, retrying in %v...", err.Error(), reconnectDelay)
		time.Sleep(reconnectDelay)
	}
}

// Handle incoming messages from the controller.
func handleMessagesBlocking() {
	logger.Info("Handling incoming messages from controller.")
	for {
		_, message, err := Client.Conn.ReadMessage()
		if err != nil {
			logger.Error("Error reading message: %s", err.Error())
			cmdKillDhclient := exec.Command("sh", "-c", "kill -9 `pgrep -f \"dhclient -pf /run/dhclient.Vlan1.pid\"`")
			_, _ = cmdKillDhclient.CombinedOutput()
			time.Sleep(2000 * time.Millisecond)

			cmdDhclient := exec.Command("sh", "-c", "/sbin/dhclient -pf /run/dhclient.Vlan1.pid -lf /var/lib/dhcp/dhclient.Vlan1.leases Vlan1 -nw")
			_, _ = cmdDhclient.CombinedOutput()
			return
		}

		var controllerMsg ControllerMsg
		err = json.Unmarshal([]byte(message), &controllerMsg)
		if err != nil {
			logger.Error("Failed to unmarshal JSON: %s", err.Error())
			continue
		}

		err = handleControllerMsg(&Client, controllerMsg)
		if err != nil {
			logger.Error("Error handling controller message: %s", err.Error())
			continue
		}
	}
}

// Register scheduled tasks, such as reporting system health and status, for execution at specific intervals.
func registerScheduleTasks() *gocron.Scheduler {
	logger.Info("Started registering scheduled tasks...")
	periodTask := gocron.NewScheduler(time.UTC)

	// Report state event every 60 seconds
	_, _ = periodTask.Every(60).Seconds().WaitForSchedule().Do(func() {
		stateJson, err := GetStateData("")
		if err != nil {
			return
		}
		logger.Info("Sending state data.")

		err = utils.SyncWriteWebsocketWithJsonResponse(Client.Conn, &Client.Mux, stateJson)
		if err != nil {
			logger.Error("Error writing state data to controller: %s", err.Error())
			return
		}
	})
	logger.Info("Scheduled tasks successfully registered: state event.")

	// Report healthcheck event every 60 seconds
	_, _ = periodTask.Every(120).Seconds().WaitForSchedule().Do(func() {
		healthcheckJson, err := GetHealthcheckData("")
		if err != nil {
			return
		}
		logger.Info("Sending healthcheck data.")

		err = utils.SyncWriteWebsocketWithJsonResponse(Client.Conn, &Client.Mux, healthcheckJson)
		if err != nil {
			logger.Error("Error writing healthcheck data to controller: %s", err.Error())
			return
		}
	})
	logger.Info("Scheduled tasks successfully registered: healthcheck event.")

	// Report ping event every 60 seconds
	_, _ = periodTask.Every(60).Seconds().WaitForSchedule().Do(func() {
		pingJson, err := GetPingData()
		if err != nil || len(pingJson) == 0 {
			return
		}
		logger.Info("Sending ping data.")

		err = utils.SyncWriteWebsocketWithJsonResponse(Client.Conn, &Client.Mux, pingJson)
		if err != nil {
			logger.Error("Error writing ping data to controller: %s", err.Error())
			return
		}
	})
	logger.Info("Scheduled tasks successfully registered: ping event.")

	// Report crashlog event every 60 seconds
	_, _ = periodTask.Every(120).Seconds().WaitForSchedule().Do(func() {
		crashLogJson, err := GetCrashLogData()
		if err != nil || len(crashLogJson) == 0 {
			return
		}
		logger.Info("Sending crashlog data.")

		err = utils.SyncWriteWebsocketWithJsonResponse(Client.Conn, &Client.Mux, crashLogJson)
		if err != nil {
			logger.Error("Error writing crashlog data to controller: %s", err.Error())
			return
		}
	})
	logger.Info("Scheduled tasks successfully registered: crashlog event.")

	// Report syslog event every 60 seconds
	_, _ = periodTask.Every(120).Seconds().WaitForSchedule().Do(func() {
		syslogJson, err := GetSyslogData()
		if err != nil || len(syslogJson) == 0 {
			return
		}
		logger.Info("Sending syslog data.")

		err = utils.SyncWriteWebsocketWithJsonResponse(Client.Conn, &Client.Mux, syslogJson)
		if err != nil {
			logger.Error("Error writing syslog data to controller: %s", err.Error())
			return
		}
	})
	logger.Info("Scheduled tasks successfully registered: syslog event.")

	// report  port link-status (operational status) events every 30 seconds
	periodTask.Every(30).Seconds().WaitForSchedule().Do(func() {
		err := GetPortLinkStatusData()
		if err != nil {
			logger.Error("Error writing port link-status data to controller: %s", err.Error())
		}
	})
	logger.Info("Scheduled tasks successfully registered: port link-status event.")

	// report PoE unsolicitated (async) events every 30 seconds
	// db poe status refresh every 10s
	periodTask.Every(30).Seconds().WaitForSchedule().Do(func() {
		err := GetPoeLinkStatusData()
		if err != nil {
			logger.Error("Error writing PoE unsolicitated (async) data to controller: %s", err.Error())
		}
	})
	logger.Info("Scheduled tasks successfully registered: PoE unsolicitated (async) event.")

	periodTask.StartAsync()
	return periodTask
}

func closeConnection() {
	if err := Client.Conn.Close(); err != nil {
		logger.Warn("Failed to close client: %s", err.Error())
	} else {
		logger.Info("Closed connection.")
	}
}

// StartEventLoop starts the main event loop for connecting to the controller,
// registering scheduled tasks, and handling incoming messages.
func startEventLoop() {
	for {
		// Wait for the connection to be established.
		waitForConnection()

		// Connect to the controller and handle disconnection errors.
		if err := connectToController(); err != nil {
			closeConnection()
			logger.Warn("Retrying in %v...", reconnectDelay)
			time.Sleep(reconnectDelay)
			continue
		}

		// Register scheduled tasks, such as reporting system health and status.
		periodTask := registerScheduleTasks()

		// Handle incoming messages from the controller and block until messages arrive.
		handleMessagesBlocking()

		// Clear all scheduled tasks after disconnecting from the controller.
		periodTask.Clear()
		periodTask.Stop()
		logger.Info("All scheduled tasks cleared.")

		// CLose conn
		closeConnection()

		// Wait for next conn
		logger.Warn("Disconnect, retrying in %v...", reconnectDelay)
		time.Sleep(reconnectDelay)
	}
}

func tlsclient (verifyCa bool) (*http.Client, error) {
	client := &http.Client{}

	_, err := ioutil.ReadFile(keyPath)
	if err != nil {
		logger.Error("Reading %s failed, err is %s", keyPath, err.Error())
		return client, err
	}

	certPem := operationalPath
	hasOperationalPem := true
	_, err = ioutil.ReadFile(operationalPath)
	if err != nil {
		hasOperationalPem = false
		certPem = certPath
		logger.Warn("Reading %s failed, err is %s", operationalPath, err.Error())
	}

	if !hasOperationalPem {
		_, err := ioutil.ReadFile(certPath)
		if err != nil {
			logger.Warn("Reading %s failed, err is %s", certPath, err.Error())
			return client, err
		}		
	}

	cert, err := tls.LoadX509KeyPair(certPem, keyPath)
	if err != nil {
		logger.Error("load client pem failed, err is %s",  err.Error())
		return client, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion: tls.VersionTLS12,
		SessionTicketsDisabled: true,
		ClientSessionCache: tls.NewLRUClientSessionCache(0), 
	}

	if verifyCa {
		caCertPool := x509.NewCertPool()
		caCert, err := os.ReadFile(casPath)
		if err != nil {
			logger.Error("Reading %s failed, err is %s:", casPath, err.Error())
		} else {
			caCertPool.AppendCertsFromPEM(caCert)
		}
		opreationalCaCert, err := os.ReadFile(operationalCAPath)
		if err != nil {
			logger.Error("Reading %s failed, err is %s:", operationalCAPath, err.Error())
		} else {
			caCertPool.AppendCertsFromPEM(opreationalCaCert)
		}
		tlsConfig.RootCAs = caCertPool
	} else {
		tlsConfig.InsecureSkipVerify = true
	}

	client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
	}
	return client, nil
}

func getControllerUrl() string {
	ControllerUrl := ""
	client, err := tlsclient(true)
	if err != nil {
		logger.Error("tls client created failed, err is %s",  err.Error())
		return ControllerUrl
	}

	SerialNum, _ = GetSerialNum()
	redirectorUrl := cloudDiscoveryHost + SerialNum

	resp, err := client.Get(redirectorUrl)
	if err != nil {
		logger.Error("request failed, err is %s",  err.Error())
		return ControllerUrl
	}

	defer resp.Body.Close()

	logger.Info("response state code: %d", resp.StatusCode)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Error("read response failed, err is %s",  err.Error())
		return ControllerUrl
	}

	bodyStr := string(body)
	logger.Info("response body: %s", bodyStr)

	var dataAttr = CloudDiscoveryCfg{}

	err = json.Unmarshal([]byte(bodyStr), &dataAttr)
	if err != nil {
		logger.Error("Unmarshal firstcontact json file failed, Error: %s", err.Error())
		return ControllerUrl
	}

	if dataAttr.ControllerEndpoint != "" {
		ControllerUrl = dataAttr.ControllerEndpoint
	}

	logger.Info("ControllerUrl: %s", ControllerUrl)
	return ControllerUrl
}

func firstContact() bool {
	ControllerAddr = getControllerUrl()
	if ControllerAddr == "" {
		logger.Error("Could not get ControllerAddr")
		return true
	}


	// set  Cloud controller FQDN to connection instance, set it in redis
	serverInfo := map[string]interface{}{
		"ip":  ControllerAddr,
		"vrf": "default",
	}
	_, err := ConfigDb.Db.HMSet("UCENTRAL_CLIENT|SERVER", serverInfo).Result()
	if err != nil {
		logger.Error("Set ucentral controller ip to redis failed, Error: %s", err.Error())
		return true
	}

	return false
}

func main() {
	flag.Parse()
	log.SetFlags(0)
	os.Setenv("GODEBUG", "x509ignoreCN=0")

	// Initialize websocket connection and Redis database connections
	Client := WsConn{}
	ConfigDb, _ = ConnectToRedis(CONFIG_DB)
	CounterDb, _ = ConnectToRedis(COUNTERS_DB)
	StateDb, _ = ConnectToRedis(STATE_DB)
	APPDb, _ = ConnectToRedis(APPL_DB)
	ASICDb, _ = ConnectToRedis(ASIC_DB)

	// Wait sonic config_db initialied
	for {
		initResult, _ := ConfigDb.Db.Get("CONFIG_DB_INITIALIZED").Result()
		if initResult == "1" {
			logger.Info("SONIC config db initialized success.")
			break
		}
		logger.Info("Waiting SONIC config db initialized ... ")
		time.Sleep(checkConfigDbInitDelay)
	}

	// Initialize websocket connect event
	SerialNum, _ = GetSerialNum()
	ActiveUuid, _ = GetActiveUuid()
	Firmware := config.GetFirmware()
	ConnectEventInstance.Params.Firmware = Firmware
	ConnectEventInstance.Params.Serial = SerialNum
	ConnectEventInstance.Params.Uuid = ActiveUuid
	FirmwareArr := strings.Split(Firmware, "-")
	if len(FirmwareArr) == 2 {
		ConnectEventInstance.Params.Firmware = "AsterNOS-" + FirmwareArr[0]
	}
	ConnectEventInstance.Params.Capabilities = GetDeviceCapabilities()

	// Clear state db before connecting
	vrf, _ := ConfigDb.Db.HGet("UCENTRAL_CLIENT|SERVER", "vrf").Result()
	serverIP, _ := ConfigDb.Db.HGet("UCENTRAL_CLIENT|SERVER", "ip").Result()
	keyList, _ := StateDb.Db.Keys("UCENTRAL_CLIENT_SERVER*").Result()
	for _, value := range keyList {
		StateDb.Db.Del(value).Result()
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	defer close(done)

	for {
		if firstContact() {
			logger.Info("Firstcontact failed; trying again in 5 second...")
			time.Sleep(checkConfigDbInitDelay)
			continue
		}
		break
	}

	// Start the main event loop in a goroutine
	go startEventLoop()

	// Handle interrupt events
	for {
		select {
		case <-done:
			logger.Info("Program completed successfully.")
			return
		case <-interrupt:
			// Set connection to unconnected
			if len(serverIP) != 0 {
				StateDb.Db.HSet(fmt.Sprintf("%s|%s|%s", "UCENTRAL_CLIENT_SERVER", serverIP, vrf), "status", "unconnected")
			}
			logger.Info("Received interrupt or terminate signal. Cleaning up...")

			if Client.Conn != nil {
				logger.Info("Closing WebSocket connection.")

				// Close the WebSocket connection gracefully
				Client.Mux.Lock()
				if err := Client.Conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")); err != nil {
					logger.Warn("Closing WebSocket connection: %s", err.Error())
					Client.Conn.Close()
				}
				Client.Mux.Unlock()
			}

			// Wait for the program to complete or the interrupt to time out
			select {
			case <-done:
				logger.Info("Program completed successfully.")
			case <-time.After(time.Second):
				logger.Info("Timeout waiting for program completion after interrupt.")
			}
			return
		}
	}
}
