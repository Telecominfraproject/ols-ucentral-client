package main

import (
	"asterfusion/client/logger"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func GetSerialNum() (string, error) {
	deviceMac := ""
	isExist, _ := ConfigDb.Db.HExists("DEVICE_METADATA|localhost", "mac").Result()

	if isExist {
		// configdb
		mac, err := ConfigDb.Db.HGet("DEVICE_METADATA|localhost", "mac").Result()
		if err != nil {
			logger.Error("Failed to get serial number: %s", err.Error())
			return "", err
		}
		deviceMac = mac
	} else {
		// statedb
		mac, err := StateDb.Db.HGet("DEVICE_METADATA|localhost", "mac").Result()
		if err != nil {
			logger.Error("Failed to get serial number: %s", err.Error())
			return "", err
		}
		deviceMac = mac
	}

	devivceMacStr := strings.Replace(deviceMac, ":", "", -1)
	return devivceMacStr, nil
}

func GetBaseMac() (string, error) {
	deviceMac := ""
	isExist, _ := ConfigDb.Db.HExists("DEVICE_METADATA|localhost", "mac").Result()

	if isExist {
		// configdb
		mac, err := ConfigDb.Db.HGet("DEVICE_METADATA|localhost", "mac").Result()
		if err != nil {
			logger.Error("Failed to get serial number: %s", err.Error())
			return "", err
		}
		deviceMac = mac
	} else {
		// statedb
		mac, err := StateDb.Db.HGet("DEVICE_METADATA|localhost", "mac").Result()
		if err != nil {
			logger.Error("Failed to get serial number: %s", err.Error())
			return "", err
		}
		deviceMac = mac
	}

	return deviceMac, nil
}

func GetActiveUuid() (int, error) {
	uuid := 1
	// check ucentral.active
	_, err := os.Stat(uCentrakCfgPath)
	// exist
	if err == nil {
		path, _ := filepath.EvalSymlinks(uCentrakCfgPath)
		uuidStr := strings.ReplaceAll(path, "/etc/ucentral/ucentral.cfg.", "")
		uuid, _ = strconv.Atoi(uuidStr)
	}
	return uuid, nil
}

func GetDeviceCapabilities() Capabilities {
	var capabilities = Capabilities{}
	// 1. get serial number
	capabilities.Serial, _ = GetSerialNum()
	// 2. get firmware version, mannuall set
	capabilities.Firmware = FIRMWARE
	// 3. platform
	capabilities.Platform = "switch"
	// 4. get model
	capabilities.Model = ""
	deviceModel, err := ConfigDb.Db.HGet("DEVICE_METADATA|localhost", "hwsku").Result()
	if err == nil {
		capabilities.Model = deviceModel
	}
	// 5. get hwsku
	capabilities.HwSku = strings.ToLower(capabilities.Model)
	// get hwsku
	capabilities.Compatible = capabilities.HwSku
	// 6. get base mac, "aa:bb:cc:dd:ee:ff"
	capabilities.BaseMac, _ = GetBaseMac()
	// 7. get port list
	capabilities.PortList = GetPortList()
	// 8. get port capabilities
	capabilities.PortCapabilities = GetPortCapabilities()
	// 9. get poe capabilities
	capabilities.PoECapabilities = GetPoECapabilities()
	// 10. get supported features
	capabilities.SupportedFeatures = GetSupportedFeatures()
	// 11. get acl capabilities
	capabilities.AclCapabilities = GetAclCapabilities()
	// 12. get mvr(mvlan) capabilities
	capabilities.MvrCapabilities = GetMvrCapabilities()
	// 13. get dhcp-snoop-capabilities capabilities
	capabilities.DhcpSnoopingCapabilities = GetDhcpSnoopingCapabilities()
	// 14. get mclag-capabilities capabilities
	capabilities.MclagCapabilities = GetMclagCapabilities()
	// 15. get ipsg-capabilities capabilities
	capabilities.MaxMacBindingEntry = 2000
	
	return capabilities
}

func GetPortList() []CAPPort {
	portList := make([]CAPPort, 0)
	// get port list
	keys, _ := ConfigDb.Db.Keys("PORT|Ethernet*").Result()
	len := len(keys)
	for i := 0; i < len; i++ {
		port := CAPPort{}
		port.Name = fmt.Sprintf("Ethernet%d", i)
		port.FrontPanelNumber = i + 1
		portList = append(portList, port)
	}
	return portList
}

func GetPortCapabilities() PortCapabilities {
	PortCapabilitiesDict := PortCapabilities{}
	portList := make([]PortListStruct, 0)
	FormFactorsList := []string{}
	deviceModel, err := ConfigDb.Db.HGet("DEVICE_METADATA|localhost", "hwsku").Result()
	// get device model
	if err == nil {
		arr := strings.Split(deviceModel, "-")
		if len(arr) >= 2 {
			frontPortCapabilities := PortListStruct{}
			frontPortNumber := 0
			backPortCapabilities := PortListStruct{}
			backPortNumber := 0
			portType01 := arr[1]
			if strings.Contains(portType01, "GT") {
				number := strings.TrimRight(portType01, "GT")
				frontPortNumber, _ = strconv.Atoi(number)
				frontPortCapabilities.Type = "RJ45"
			} else if strings.Contains(portType01, "S") {
				number := strings.TrimRight(portType01, "S")
				frontPortNumber, _ = strconv.Atoi(number)
				frontPortCapabilities.Type = "SFP+"
			} else if strings.Contains(portType01, "Y") {
				number := strings.TrimRight(portType01, "Y")
				frontPortNumber, _ = strconv.Atoi(number)
				frontPortCapabilities.Type = "SFP28"
			} else {
				// do nothing
			}
			FormFactorsList = append(FormFactorsList, frontPortCapabilities.Type)
			for i := 0; i < frontPortNumber; i++ {
				ethernet := fmt.Sprintf("Ethernet%d", i)
				frontPortCapabilities.Ports = append(frontPortCapabilities.Ports, ethernet)
			}
			portType02 := arr[0]
			portTypeSubstr := portType02[len(portType02)-2:]
			if strings.Contains(portTypeSubstr, "S") {
				number := strings.TrimRight(portTypeSubstr, "S")
				backPortNumber, _ = strconv.Atoi(number)
				backPortCapabilities.Type = "SFP+"

			} else if strings.Contains(portTypeSubstr, "Y") {
				number := strings.TrimRight(portTypeSubstr, "Y")
				backPortNumber, _ = strconv.Atoi(number)
				backPortCapabilities.Type = "SFP28"
			} else if strings.Contains(portTypeSubstr, "P") {
				number := strings.TrimRight(portTypeSubstr, "P")
				backPortNumber, _ = strconv.Atoi(number)
				backPortCapabilities.Type = "QSFP28"
			} else {
				// do nothing
			}
			FormFactorsList = append(FormFactorsList, backPortCapabilities.Type)
			for i := frontPortNumber; i < frontPortNumber+backPortNumber; i++ {
				ethernet := fmt.Sprintf("Ethernet%d", i)
				backPortCapabilities.Ports = append(backPortCapabilities.Ports, ethernet)
			}
			// add in portList
			portList = append(portList, frontPortCapabilities)
			portList = append(portList, backPortCapabilities)
		}
	}
	PortCapabilitiesDict.PortsList = portList
	PortCapabilitiesDict.FormFactors = FormFactorsList
	return PortCapabilitiesDict
}

func GetPoECapabilities() PoECapabilities {
	poECapabilities := PoECapabilities{}
	// get port list
	deviceModel, err := ConfigDb.Db.HGet("DEVICE_METADATA|localhost", "hwsku").Result()
	frontPortNumber := 0
	if err == nil {
		arr := strings.Split(deviceModel, "-")
		if len(arr) >= 4 {
			deviceModelPower := arr[3]
			if deviceModelPower == "SWP" {
				poECapabilities.PowerBudget = 150
			} else if deviceModelPower == "SWP2" {
				poECapabilities.PowerBudget = 370
			} else if deviceModelPower == "SWP4" {
				poECapabilities.PowerBudget = 740
			} else {
				return poECapabilities
			}
			portType01 := arr[1]
			if strings.Contains(portType01, "GT") {
				number := strings.TrimRight(portType01, "GT")
				frontPortNumber, _ = strconv.Atoi(number)
			} else {
				return poECapabilities
			}
		} else {
			return poECapabilities
		}
	}
	// poECapabilities.SupportedStandards = []string{".3AF-POE", ".3AT-POE+", ".3BT-PoE++", " PreStandard-Passive"}
	poECapabilities.SupportedStandards = []string{".3AF-POE", ".3AT-POE+", ".3BT-PoE++"}
	portof60W := PoePort{}
	portof60W.Type = ".3BT-PoE++"
	portof60W.BudgetCapacity = 60
	// front 8 port support 60w
	portof60W.Ports = []string{"Ethernet0", "Ethernet1", "Ethernet2", "Ethernet3", "Ethernet4", "Ethernet5", "Ethernet6", "Ethernet7"}
	portof30W := PoePort{}
	portof30W.Type = ".3AT-POE+"
	portof30W.BudgetCapacity = 30
	portof30W.Ports = []string{}
	// other port support 30w
	for i := 8; i < frontPortNumber; i++ {
		ethernet := fmt.Sprintf("Ethernet%d", i)
		portof30W.Ports = append(portof30W.Ports, ethernet)
	}
	poECapabilities.PoePorts = append(poECapabilities.PoePorts, portof60W)
	poECapabilities.PoePorts = append(poECapabilities.PoePorts, portof30W)
	return poECapabilities
}

func GetAclCapabilities() AclCapabilities {
	Capabilities := AclCapabilities{}
	Capabilities.MaxAclPerSwitch = 500
	Capabilities.MaxRulesPerAcl = 1
	Capabilities.MaxAclPerInterface = 54
	return Capabilities
}

func GetMvrCapabilities() MvrCapabilities {
	Capabilities := MvrCapabilities{}
	Capabilities.MvrMaxDomains = 1
	Capabilities.MvrMaxGroups = 0
	Capabilities.MvrSupportedModes = "transparent, proxy-mode"
	return Capabilities
}

func GetDhcpSnoopingCapabilities() DhcpSnoopingCapabilities {
	Capabilities := DhcpSnoopingCapabilities{}
	Capabilities.DhcpSnoopPortRateLimit = 16
	return Capabilities
}

func GetMclagCapabilities() MclagCapabilities {
	Capabilities := MclagCapabilities{}
	Capabilities.MaxMclagGroups = 1
	Capabilities.MaxPortsPerMclagGroup = 54
	Capabilities.MaxVlansPerMclagGroup = 4094
	Capabilities.PeerLinkBandWidth = "10G"
	Capabilities.DualActiveDetection = "ICCP"
	Capabilities.FailoverTime = 200
	Capabilities.VlanSynchronization = true
	Capabilities.MaxMacEntriesPerMclag = 32768
	return Capabilities
}

func GetSupportedFeatures() []string {
	features := []string{
		"VLAN",
		"Port-Isolation",
		"Spanning-Tree",
		"Link-Aggregation-Static",
		"Link-Aggregation-LACP",
		"Jumbo-frames",
		"Port-Mirror",
		"Multicast-VLAN-Registration",
		"Spanning-Tree-MSTP",
		"SVI-StaticIPv4",
		"SVI-StaticIPv6",
		"Interface-StaticIPv4",
		"Interface-StaticIPv6",
		"Routing-VRF",
		"Routing-IPv4-Route-Blackhole",
		"Routing-IPv4-Route-Unreachable",
		"Routing-IPv4-Nexthop",
		"Routing-IPv4-Broadcast",
		"Routing-IPv4-Multicast-IGMP-Snooping",
		"Routing-IPv4-Multicast-IGMP-Querier",
		"Routing-IPv4-Multicast-IGMP-Static",
		"Routing-IPv4-DHCP-Server",
		"Routing-IPv4-DHCP-Relay",
		"Routing-IPv4-DHCP-Snooping",
		"Routing-IPv4-Port-Forward",
		"Routing-IPv6-DHCP-Relay",
		"Routing-IPv6-DHCP-Stateful",
		"Routing-IPv6-DHCP-Stateless",
		"Routing-IPv6-Port-Forward",
		"PoE",
		"PoE-Reset",
		"Port-Access-Control",
		"PAC-Dynamic-Auth",
		"System-PasswordChange",
		"System-SwUpdate",
		"Service-SSH",
		"Service-RSSH",
		"Service-Telnet",
		"Service-LLDP",
		"Service-IGMP",
		"Service-NTP",
		"Service-QoS",
		"Service-Syslog",
		"Service-PAC",
		"Service-CaptivePortal",
		"Service-PublicIpCheck",
		"Tunneling",
		"Tunneling-VxLAN",
		"Tunneling-GRE",
		"Tunneling-GRE6",
		"MAC-ACL",
		"IP-ACL",
		"VLAN-Voice",
		"LLDP-MED-PoE-Negotiation",
		"mac-address-bypass",
		"Link-Aggregation-MCLAG",
		"IP-Source-Guard",
		"Rate-Limiting",
		"ARP-Inspect",
		"RT-Event-Select",
		"BPDU-Guard",
		"Storm-Control",
	}
	return features
}
