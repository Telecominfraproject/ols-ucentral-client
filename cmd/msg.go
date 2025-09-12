package main

type DBType int

const (
	APPL_DB         DBType = 0
	ASIC_DB         DBType = 1
	COUNTERS_DB     DBType = 2
	LOGLEVEL_DB     DBType = 3
	CONFIG_DB       DBType = 4
	PFC_WD_DB       DBType = 5
	FLEX_COUNTER_DB DBType = 5
	STATE_DB        DBType = 6
	SNMP_OVERLAY_DB DBType = 7
)

type UcentralMethod string

const (
	STATE        UcentralMethod = "state"
	HEALTHCHECK  UcentralMethod = "healthcheck"
	CONNECT      UcentralMethod = "connect"
	LOG          UcentralMethod = "log"
	EVENTS       UcentralMethod = "event"
	ALARM        UcentralMethod = "alarm"
	CRASHLOG     UcentralMethod = "crashlog"
	CFGPENDING   UcentralMethod = "cfgpending"
	DEVICEUPDATE UcentralMethod = "deviceupdate"
	PING         UcentralMethod = "ping"
	FACTORY      UcentralMethod = "factory"
)

type ConnectEvent struct {
	Jsonrpc string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  struct {
		Serial       string       `json:"serial"`
		Uuid         int          `json:"uuid"`
		Firmware     string       `json:"firmware"`
		Wanip        []string     `json:"wanip"`
		Capabilities Capabilities `json:"capabilities"`
	} `json:"params"`
}

type AclCapabilities struct {
	MaxAclPerSwitch    int `json:"max-acl-per-switch"`
	MaxRulesPerAcl     int `json:"max-rules-per-acl"`
	MaxAclPerInterface int `json:"max-acl-per-interface"`
}

type MvrCapabilities struct {
	MvrMaxDomains     int    `json:"mvr-max-domains"`
	MvrMaxGroups      int    `json:"mvr-max-groups"`
	MvrSupportedModes string `json:"mvr-supported-modes"`
}

type DhcpSnoopingCapabilities struct {
	DhcpSnoopPortRateLimit int `json:"dhcp-snoop-port-rate-limit"`
}

type MclagCapabilities struct {
	MaxMclagGroups        int    `json:"max-mclag-groups"`
	MaxPortsPerMclagGroup int    `json:"max-ports-per-mclag-group"`
	MaxVlansPerMclagGroup int    `json:"max-vlans-per-mclag-group"`
	PeerLinkBandWidth     string `json:"peer-link-bandwidth"`
	DualActiveDetection   string `json:"dual-active-detection"`
	FailoverTime          int    `json:"failover-time"`
	VlanSynchronization   bool   `json:"vlan-synchronization"`
	MaxMacEntriesPerMclag int    `json:"max-mac-entries-per-mclag"`
}

type Capabilities struct {
	Serial                   string                   `json:"serial"`
	Firmware                 string                   `json:"firmware"`
	Platform                 string                   `json:"platform"`
	Model                    string                   `json:"model"`
	HwSku                    string                   `json:"hw-sku"`
	Compatible               string                   `json:"compatible"`
	BaseMac                  string                   `json:"base-mac"`
	PortList                 []CAPPort                `json:"port-list"`
	PortCapabilities         PortCapabilities         `json:"port-capabilities"`
	PoECapabilities          PoECapabilities          `json:"poe-capabilities"`
	AclCapabilities          AclCapabilities          `json:"acl-capabilities"`
	MvrCapabilities          MvrCapabilities          `json:"mvr-capabilities"`
	DhcpSnoopingCapabilities DhcpSnoopingCapabilities `json:"dhcp-snoop-capabilities"`
	MclagCapabilities        MclagCapabilities        `json:"mclag-capabilities"`
	MaxMacBindingEntry       int                      `json:"max-mac-binding-entry"`
	SupportedFeatures        []string                 `json:"supported-features"`
}

type CAPPort struct {
	Name             string `json:"name"`
	FrontPanelNumber int    `json:"front-panel-number"`
}

type PortListStruct struct {
	Type  string   `json:"type"`
	Ports []string `json:"ports"`
}

type PortCapabilities struct {
	FormFactors []string         `json:"form-factors"`
	PortsList   []PortListStruct `json:"ports-list"`
}

type PoECapabilities struct {
	SupportedStandards []string  `json:"supported-standards"`
	PowerBudget        int       `json:"power-budget"`
	PoePorts           []PoePort `json:"poe-ports"`
}

type PoePort struct {
	Type           string   `json:"type"`
	BudgetCapacity int      `json:"budget-capacity"`
	Ports          []string `json:"ports"`
}

type StateEvent struct {
	Jsonrpc     string      `json:"jsonrpc"`
	Method      string      `json:"method"`
	StateParams StateParams `json:"params"`
}

type DataStruct struct {
	Event []interface{} `json:"event"`
}

type PortLinkStatusEvent struct {
	Jsonrpc string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  struct {
		Serial string     `json:"serial"`
		Data   DataStruct `json:"data"`
	} `json:"params"`
}

type UpgradeStatusEvent struct {
	Jsonrpc string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  struct {
		Serial string     `json:"serial"`
		Data   DataStruct `json:"data"`
	} `json:"params"`
}

type PoEStatusEvent struct {
	Jsonrpc string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  struct {
		Serial string        `json:"serial"`
		Data   []interface{} `json:"data"`
	} `json:"params"`
}

type AlarmEvent struct {
	Jsonrpc string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  struct {
		Serial     string      `json:"serial"`
		DeviceType string      `json:"deviceType"`
		DeviceIP   string      `json:"deviceIP"`
		Hostname   string      `json:"hostname"`
		Data       []AlarmData `json:"data"`
	} `json:"params"`
}

type AlarmData struct {
	Id        string                   `json:"id"`
	Type      string                   `json:"type"`
	AlarmInfo string                   `json:"info"`
	Payload   []map[string]interface{} `json:"payload"`
	Tag       []string                 `json:"tag"`
}

type StateParams struct {
	Serial      string `json:"serial"`
	Uuid        int    `json:"uuid"`
	RequestUuid string `json:"request_uuid"`
	State       State  `json:"state"`
}

type State struct {
	Unit            Unit                   `json:"unit"`
	Gps             Gps                    `json:"gps"`
	Interfaces      []OLSInterface         `json:"interfaces"`
	LinkState       OLSLinkStates          `json:"link-state"`
	LldpPeers       []OLSLldpPeer          `json:"lldp-peers"`
	MacAddressList  map[string]interface{} `json:"mac-address-list"`
	PublicIp        string                 `json:"public_ip"` // generate by public_ip_lookup param, config in ucentral config state service
	UplinkInterface string                 `json:"uplink_interface,omitempty"`
	PrivateIp       string                 `json:"private_ip"`
	StaticTrunks    []OLSStaticTrunks      `json:"static-trunks"`
	LacpTrunks      []OLSLacpTrunks        `json:"lacp-trunks"`
	NTPStatus       []OLSNTPStatus         `json:"ntp-status"`
	AclStats        AclStatsStruct         `json:"acl-stats"`
	StpStats        StpStats               `json:"stp"`
}

type StpStats struct {
	Enabled           bool          `json:"enabled"`
	Mode              string        `json:"mode"`                         // stp/rstp/mstp/pvst/rpvstp
	TransmissionLimit int           `json:"transmission-limit,omitempty"` // Maximum BPDUs per hello time
	PathCostMethod    string        `json:"path-cost-method,omitempty"`   // short/long
	MaxHops           int           `json:"max-hops,omitempty"`
	Instances         []StpInstance `json:"instances,omitempty"`
}

type StpInstance struct {
	InstanceId                int    `json:"instance-id"`
	Vlans                     string `json:"vlans"`
	BridgePriority            int    `json:"bridge-priority"`
	BridgeHelloTime           int    `json:"bridge-hello-time,omitempty"`
	BridgeMaxAge              int    `json:"bridge-max-age,omitempty"`
	BridgeForwardDelay        int    `json:"bridge-forward-delay,omitempty"`
	RemainingHops             int    `json:"remaining-hops,omitempty"`
	RootBridgeId              string `json:"root-bridge-id,omitempty"`
	RootPort                  string `json:"root-port,omitempty"`
	RootCost                  int    `json:"root-cost,omitempty"`
	TopologyChanges           int    `json:"topology-changes,omitempty"`
	LastTopologyChangeSeconds int    `json:"last-topology-change-seconds,omitempty"`
}

type Unit struct {
	Load         []float64     `json:"load"`
	Localtime    uint64        `json:"localtime"`
	Uptime       uint64        `json:"uptime"`
	Temperatures []Temperature `json:"temperatures"`
	Psus         []Psu         `json:"powers"`
	Fans         []Fan         `json:"fans"`
	Memory       Memory        `json:"memory"`
	Cpu          int           `json:"cpu"`
	Hostname     string        `json:"hostname"`
	PoE *OLSPoE `json:"poe,omitempty"`
}

type Memory struct {
	Total    int64 `json:"total"`
	Free     int64 `json:"free"`
	Cached   int64 `json:"cached"`
	Buffered int64 `json:"buffered"`
}

type Temperature struct {
	Tag   string  `json:"tag"`
	Value float64 `json:"value"`
}

type Psu struct {
	Tag        string  `json:"tag"`
	Presence   bool    `json:"presence"`
	Status     bool    `json:"status"`
	Power      bool    `json:"power"`
	CurrentIn  float64 `json:"currentIn"`
	CurrentOut float64 `json:"currentOut"`
	VoltageIn  float64 `json:"voltageIn"`
	VoltageOut float64 `json:"voltageOut"`
	PowerIn    float64 `json:"powerIn"`
	PowerOut   float64 `json:"powerOut"`
}

type Fan struct {
	Tag       string `json:"tag"`
	Status    bool   `json:"status"`
	Presence  bool   `json:"presence"`
	Direction string `json:"direction"`
	Speed     int    `json:"speed"`
}

type SyslogConfig struct {
	SourceIp string `json:"source_ip"`
}

type Gps struct {
	Latitude  int `json:"latitude"`
	Longitude int `json:"longitude"`
	Elevation int `json:"elevation"`
}

type Radios struct {
	Load []int `json:"load"`
}

type EnabledGroup struct {
	EgressPorts []string `json:"egress-ports"`
	Address     string   `json:"address"`
}

type StateIGMP struct {
	EnabledGroups []EnabledGroup `json:"enabled-groups"`
}

type StateMulticast struct {
	IGMP StateIGMP `json:"igmp"`
}

type Interface struct {
	Location  string          `json:"location"`
	Uptime    int             `json:"uptime"`
	Name      string          `json:"name"`
	PortId    int             `json:"port_id"`
	Counters  Counters        `json:"counters"`
	Status    InterfaceStatus `json:"-"`
	Multicast StateMulticast  `json:"multicast"`
}

type DhcpSnoopingEntries struct {
	DhcpSnoopBindMacAddress   string `json:"dhcp-snoop-bind-mac-address"`
	DhcpSnoopBindIPAddress    string `json:"dhcp-snoop-bind-ip-address"`
	DhcpSnoopBindLeaseSeconds int    `json:"dhcp-snoop-bind-lease-seconds"`
	DhcpSnoopBindType         string `json:"dhcp-snoop-bind-type"`
	DhcpSnoopBindVlan         int    `json:"dhcp-snoop-bind-vlan"`
	DhcpSnoopBindInterf       string `json:"dhcp-snoop-bind-interf"`
}

type DhcpSnoopBindingStruct struct {
	Entries []DhcpSnoopingEntries `json:"entries"`
}

type AclIntfStatsStruct struct {
	AclInftId     string `json:"acl-intf-id"`
	AclType       string `json:"acl-type"`
	AclRuleAction string `json:"acl-rule-action"`
	AclName       string `json:"acl-name"`
}

type AclStatsStruct struct {
	AclIntfStats []AclIntfStatsStruct `json:"acl-intf-stats"`
}

type OLSInterface struct {
	Location      string            `json:"location"`
	Uptime        int               `json:"uptime,omitempty"`
	Name          string            `json:"name"`
	VlanId        int               `json:"vlan_id"`
	NtpServer     string            `json:"ntp_server"`
	DnsServers    []string          `json:"dns_servers,omitempty"`
	Ipv4          Ipv4              `json:"ipv4"`
	Ipv6Addresses Ipv6_addresses    `json:"ipv6_addresses,omitempty"`
	Clients       []InterfaceClient `json:"clients,omitempty"`
	Multicast        StateMulticast         `json:"multicast"`
	DhcpSnoopBinding DhcpSnoopBindingStruct `json:"dhcp-snoop-binding"`
}

type OLSStaticTrunks struct {
	TrunkId     int      `json:"trunk-identifier"`
	MemberPorts []string `json:"member-ports"`
}

type OLSLacpTrunks struct {
	TrunkId        int    `json:"trunk-identifier"`
	MemberPort     string `json:"member-port"`
	SystemPriority int    `json:"system-priority"`
	PortPriority   int    `json:"port-priority"`
	OperState      string `json:"oper-state"`
	PortState      string `json:"port-state"`
}

type OLSNTPStatus struct {
	PEERADDRESS string `json:"peer-address"`
}

type Ipv4 struct {
	Addresses []string `json:"addresses,omitempty"`
	PublicIP  string   `json:"public_ip,omitempty"`
	Leasetime  int     `json:"leasetime,omitempty"`
	DhcpServer string  `json:"dhcp_server,omitempty"`
	Leases     []Lease `json:"leases,omitempty"`
}

type Lease struct {
	Address  string `json:"address"`
	Assigned string `json:"assigned"`
	Hostname string `json:"hostname"`
	Mac      string `json:"mac"`
}

type InterfaceClient struct {
	Mac           string   `json:"mac"`
	Ipv4Addresses []string `json:"ipv4_addresses"`
	Ipv6Addresses []string `json:"ipv6_addresses"`
	Ports         []string `json:"ports"`
	LastSeen      int      `json:"last_seen,omitempty"`
}

type InterfaceCounter struct {
	Collisions int `json:"collisions"`
	Multicast  int `json:"multicast"`
	RxBytes    int `json:"rx_bytes"`
	RxPackets  int `json:"rx_packets"`
	RxError    int `json:"rx_error"`
	RxDropped  int `json:"rx_dropped"`
	TxBytes    int `json:"tx_bytes"`
	TxPackets  int `json:"tx_packets"`
	TxError    int `json:"tx_error"`
	TxDropped  int `json:"tx_dropped"`
}

type Ipv6_addresses struct {
	Address []string `json:"address"`
	Valid   int      `json:"valid"`
}

type Counters struct {
	Collisions int     `json:"collision"`
	Multicast  int     `json:"multicast"`
	RxBytes    int     `json:"rx_bytes"`
	RxPackets  int     `json:"rx_packets"`
	RxError    int     `json:"rx_errors"`
	RxDropped  int     `json:"rx_dropped"`
	RxBPS      float64 `json:"rx_bps"`
	RxUtil    float64 `json:"rx_util"`
	TxBytes   int     `json:"tx_bytes"`
	TxPackets int     `json:"tx_packets"`
	TxError   int     `json:"tx_errors"`
	TxDropped int     `json:"tx_dropped"`
	TxBPS     float64 `json:"tx_bps"`
	TxUtil float64 `json:"tx_util"`
}

type InterfaceStatus struct {
	Lanes       string `json:"lanes"`
	Alias       string `json:"alias"`
	OperStatus  string `json:"oper_status"`
	AdminStatus string `json:"admin_status"`
	Speed       string `json:"speed"`
	Mtu         string `json:"mtu"`
	Fec         string `json:"fec"`
	Description string `json:"description"`
	Type        string `json:"type"`
	PfcAsym     string `json:"pfc_asym"`
}
type PoeInfo struct {
	Status       bool       `json:"status"`
	OnlineNumber int        `json:"online_number"`
	Power        float64    `json:"power"`
	Current      float64    `json:"current"`
	Voltage      float64    `json:"voltage"`
	Temperature  float64    `json:"temperature"`
	MaxPower     float64    `json:"max_power"`
	OnlineInfo   OnlineInfo `json:"online_info"`
}

type OnlineInfo struct {
	Mac        string `json:"mac"`
	IP         string `json:"ip"`
	IPv6       string `json:"ipv6"`
	Hostname   string `json:"hostname"`
	ChassisDes string `json:"chassisDes"`
}

type HealthcheckEvent struct {
	Jsonrpc string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  struct {
		Serial      string            `json:"serial"`
		Uuid        int               `json:"uuid"`
		RequestUuid string            `json:"request_uuid"`
		Sanity      int               `json:"sanity"`
		Data        map[string]string `json:"data"`
	} `json:"params"`
}

type LogEvent struct {
	Jsonrpc string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  struct {
		Serial   string  `json:"serial"`
		Log      string  `json:"log"`
		Severity int     `json:"severity"`
		Data     LogData `json:"data"`
	} `json:"params"`
}

type LogSSBEvent struct {
	Jsonrpc string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  struct {
		Serial   string `json:"serial"`
		Log      string `json:"log"`
		Severity int    `json:"severity"`
	} `json:"params"`
}

type LogData struct {
	Loglines int    `json:"loglines"`
	Data     string `json:"data"`
}

type CrashLogEvent struct {
	Jsonrpc string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  struct {
		Serial   string   `json:"serial"`
		Uuid     int      `json:"uuid"`
		Loglines []string `json:"loglines"`
	} `json:"params"`
}

type PingEvent struct {
	Jsonrpc string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  struct {
		Serial string `json:"serial"`
		Uuid   int    `json:"uuid"`
	} `json:"params"`
}

type CfgEvent struct {
	Jsonrpc string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  struct {
		Serial string `json:"serial"`
		// <UUID current active configuration uuid>
		Active int `json:"active"`
		// <UUID waiting to apply this configuration>
		Uuid int `json:"uuid"`
	} `json:"params"`
}

type DeviceUpdateEvent struct {
	Jsonrpc string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  struct {
		Serial string `json:"serial"`
		// # a list of key value pairs representing the change i.e
		// # "currentPassword" : "mynewpassword"
		// CurrentPassword string `json:"currentPassword"`
	} `json:"params"`
}

// Device may decide it has to do into recovery mode.
// This event should be used.
type RecoveryEvent struct {
	Jsonrpc string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  struct {
		Serial   string `json:"serial"`
		Uuid     int    `json:"uuid"`
		Firmware string `json:"firmware"`
		// (shoudld the device be instructed to reboot after loggin the information)
		Reboot   bool     `json:"reboot"`
		Loglines []string `json:"loglines"`
	} `json:"params"`
}

type ControllerMsg struct {
	Jsonrpc string      `json:"jsonrpc"`
	Id      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

type ControllerConfigMsg struct {
	Jsonrpc string       `json:"jsonrpc"`
	Id      int          `json:"id"`
	Method  string       `json:"method"`
	Params  ConfigParams `json:"params"`
}

type ConfigParams struct {
	Config interface{} `json:"config"`
	Serial string      `json:"serial"`
	Uuid   int         `json:"uuid"`
	When   int         `json:"when"`
}

type DeviceResponse struct {
	Jsonrpc string `json:"jsonrpc"`
	Id      int    `json:"id"`
	Result  Result `json:"result"`
}

type Result struct {
	Serial string `json:"serial"`
	Uuid   int    `json:"uuid"`
	Status Status `json:"status"`
}

type Status struct {
	Err      int        `json:"error"`
	Text     string     `json:"text"`
	When     int        `json:"when"`
	Rejected []Rejected `json:"rejected,omitempty"`
}

type Rejected struct {
	Parameter    interface{} `json:"parameter"`
	Reason       string      `json:"reason"`
	Substitution interface{} `json:"substitution"`
}

// LLDP from device shell
type DeviceLLDPChassis map[string]struct {
	Id          DeviceLLDPChassisId `json:"id"`
	MgmtIp      interface{}         `json:"mgmt-ip"`
	Description string              `json:"descr"`
	Capability  interface{}         `json:"capability"`
}

// sonic:{} or {} can decode
type AnyLLDPChassis struct {
	Id          DeviceLLDPChassisIdMap `mapstructure:"id"`
	MgmtIp      interface{}            `mapstructure:"mgmt-ip"`
	Description string                 `mapstructure:"descr"`
	Capability  interface{}            `mapstructure:"capability"`
}

type DeviceLLDPChassisIdMap struct {
	Type  string `mapstructure:"type"`
	Value string `mapstructure:"value"`
}

type DeviceLLDPPort struct {
	Id              DeviceLLDPPortId      `json:"id"`
	Description     string                `json:"descr"`
	TTL             string                `json:"ttl"`
	AutoNegotiation AutoNegotiationStruct `json:"auto-negotiation"`
}

type DeviceLLDPChassisId struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type DeviceLLDPPortId struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type DeviceLLDPInterface map[string]struct {
	Chassis map[string]interface{} `json:"chassis" `
	Port    DeviceLLDPPort         `json:"port" `
}

type DeviceLLDP struct {
	LLDP struct {
		Interface DeviceLLDPInterface `json:"interface"`
	} `json:"lldp"`
}

type DeviceLLDPs struct {
	LLDP struct {
		Interfaces []DeviceLLDPInterface `json:"interface"`
	} `json:"lldp"`
}

// LLDP event
type LLDPEvent struct {
	Jsonrpc string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  struct {
		Serial string  `json:"serial"`
		Uuid   int     `json:"uuid"`
		LLDP   LLDPMsg `json:"lldp"`
	} `json:"params"`
}

type LLDPMsg struct {
	DeviceInfo LLDPDeviceInfo  `json:"deviceInfo"`
	Interfaces []LLDPInterface `json:"interface"`
}

type LLDPDeviceInfo struct {
	Compatible   string `json:"compatible"`
	Description  string `json:"description"`
	DeviceType   string `json:"deviceType"`
	Hostname     string `json:"hostname"`
	IP           string `json:"ip"`
	IPv4         string `json:"ipv4"`
	IPv6         string `json:"ipv6"`
	MAC          string `json:"mac"`
	Manufacturer string `json:"manufacturer"`
	Platform     string `json:"platform"`
	RouterType   string `json:"routerType"`
	Version      string `json:"version"`
}

type LLDPInterface struct {
	Neighbor LLDPNeighbor `json:"neighbor"`
	Port     string       `json:"port"`
}

type LLDPNeighbor struct {
	Chassis      LLDPChassis `json:"chassis"`
	Port         LLDPPort    `json:"port"`
	SerialNumber string      `json:"serialNumber"`
}

type LLDPChassis struct {
	Description string        `json:"description"`
	DeviceType  string        `json:"deviceType"`
	Hostname    string        `json:"hostname"`
	Id          LLDPChassisId `json:"id"`
	IP          string        `json:"ip"`
	IPv4        string        `json:"ipv4"`
	IPv6        string        `json:"ipv6"`
	MAC         string        `json:"mac"`
	Capability  interface{}   `json:"capability"`
}

type LLDPChassisId struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type LLDPPort struct {
	Id              LLDPPortId            `json:"id"`
	Description     string                `json:"description"`
	TTL             int                   `json:"ttl"`
	AutoNegotiation AutoNegotiationStruct `json:"auto-negotiation"`
}

type AutoNegotiationStruct struct {
	Supported bool `json:"supported"`
	Enabled   bool `json:"enabled"`
}

type LLDPPortId struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type UsertableEvent struct {
	Jsonrpc string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  struct {
		Serial    string        `json:"serial"`
		Uuid      int           `json:"uuid"`
		Usertable UsertableData `json:"usertable"`
	} `json:"params"`
}

type UsertableData struct {
	MAC      []MACData `json:"macs"`
	ARP      []ARPData `json:"arps"`
	Route    []string  `json:"routes"`
	Snooping []string  `json:"snoopings"`
}

type MACData struct {
	Vlan       string `json:"v"`
	MacAddress string `json:"m"`
	Port       string `json:"p"`
	Type       string `json:"t"`
}

type ARPData struct {
	Address    string `json:"a"`
	MacAddress string `json:"m"`
	Interface  string `json:"i"`
	Vlan       string `json:"v"`
	Type       string `json:"t"`
	Family     string `json:"f"`
}

type SnoopingData struct {
}

type FDB struct {
	Bvid     string `json:"bvid"`
	Mac      string `json:"mac"`
	SwitchId string `json:"switch_id"`
}

type MacEvent struct {
	Jsonrpc string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  struct {
		Serial string `json:"serial"`
		Uuid   int    `json:"uuid"`
		MAC    MACObj `json:"mac"`
	} `json:"params"`
}

type MACObj struct {
	MAC []MACData `json:"macs"`
}

type ArpEvent struct {
	Jsonrpc string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  struct {
		Serial string `json:"serial"`
		Uuid   int    `json:"uuid"`
		ARP    ARPObj `json:"arp"`
	} `json:"params"`
}

type ARPObj struct {
	ARP []ARPData `json:"arps"`
}

type RouteEvent struct {
	Jsonrpc string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  struct {
		Serial string   `json:"serial"`
		Uuid   int      `json:"uuid"`
		Route  RouteObj `json:"route"`
	} `json:"params"`
}

type RouteObj struct {
	Route []string `json:"routes"`
}

type PowerCycleItem struct {
	Name  string `mapstructure:"name"`
	Cycle int    `mapstructure:"cycle"`
}

type PowerCycleObj struct {
	Serial        int              `mapstructure:"serial"`
	PowerCycleArr []PowerCycleItem `mapstructure:"ports"`
	When          int              `mapstructure:"when"`
}

// ============================= ucentral cfg strut ======================================

type PlatUnitPoeCfg struct {
	PowerMgmt           string `mapstructure:"power-management"`
	UsageThreshold      uint   `mapstructure:"usage-threshold"`
	IsPowerMgmtSet      bool
	IsUsageThresholdSet bool
}

type PlatUnitMulticast struct {
	IgmpSnoopingEnable bool `mapstructure:"igmp-snooping-enable"`
	MldSnoopingEnable  bool `mapstructure:"mld-snooping-enable"`
}

type PlatUnit struct {
	Name           string            `mapstructure:"name"`
	Hostname       string            `mapstructure:"hostname"`
	Location       string            `mapstructure:"location"`
	Timezone       string            `mapstructure:"timezone"`
	LedsActive     bool              `mapstructure:"leds-active"`
	RandomPassword string            `mapstructure:"random-password"`
	SystemPassword string            `mapstructure:"system-password"`
	Poe            PlatUnitPoeCfg    `mapstructure:"poe"`
	Multicast      PlatUnitMulticast `mapstructure:"multicast"`
}

type POE struct {
	AdminMode          bool   `mapstructure:"admin-mode"`
	DoReset            bool   `mapstructure:"do-reset"`
	Detection          string `mapstructure:"detection"`
	IsDetectionModeSet bool
	PowerLimit         int `mapstructure:"power-limit"`
	IsPowerLimitSet    bool
	Priority           string `mapstructure:"priority"`
	IsPrioritySet      bool
}

type PlatIeee8021xPortControlMode uint8

const (
	PORTCONTROLFORCEAUTHORIZED   PlatIeee8021xPortControlMode = 0
	PORTCONTROLFORCEUNAUTHORIZED PlatIeee8021xPortControlMode = 1
	PORTCONTROLAUTO              PlatIeee8021xPortControlMode = 2
)

type PlatIeee8021xPortHostMode uint8

const (
	HOSTMODEMULTIAUTH   PlatIeee8021xPortHostMode = 0
	HOSTMODEMULTIDOMAIN PlatIeee8021xPortHostMode = 1
	HOSTMODEMULTIHOST   PlatIeee8021xPortHostMode = 2
	HOSTMODESINGLEHOST  PlatIeee8021xPortHostMode = 3
)

type IEEE8021X struct {
	IsAuthenticator     bool   `mapstructure:"is-authenticator"`     // default false, do not support config
	AuthenticationMode  string `mapstructure:"authentication-mode"`  // auto/force-authorized
	HostMode            string `mapstructure:"host-mode"`            // default multi-auth, do not support config
	GuestVlan           int    `mapstructure:"guest-vlan"`           // guest-vlan
	UnauthenticatedVlan int    `mapstructure:"unauthenticated-vlan"` // restrict-vlan
	MacAddressBypass    bool   `mapstructure:"mac-address-bypass"`
}

type BpduGuardStruct struct {
	Enabled              bool `mapstructure:"enabled"`
	AutoRecoveryInterval int  `mapstructure:"auto-recovery-interval"`
}

type StormControlStruct struct {
	BroadcastPps      int `mapstructure:"broadcast-pps"`
	MulticastPps      int `mapstructure:"multicast-pps"`
	UnknownUnicastPps int `mapstructure:"unknown-unicast-pps"`
}

type PlatPort struct {
	SelectPorts             []string                      `mapstructure:"select-ports"`
	Speed                   int                           `mapstructure:"speed"`
	Enabled                 bool                          `mapstructure:"enabled"`
	Duplex                  string                        `mapstructure:"duplex"` // only Full
	Services                []string                      `mapstructure:"services"`
	Poe                     POE                           `mapstructure:"poe"`
	Ieee8021x               IEEE8021X                     `mapstructure:"ieee8021x"`
	TrunkGroup              int                           `mapstructure:"trunk-group"`
	LacpConfig              LacpConfigStruct              `mapstructure:"lacp-config"`
	Name                    string                        `mapstructure:"name"`
	VoiceVlanIntfConfig     VoiceVlanIntfConfigStruct     `mapstructure:"voice-vlan-intf-config"`
	Acl                     []AclInterfaceStruct          `mapstructure:"acl"`
	DhcpSnoopPort           DhcpSnoopPortStruct           `mapstructure:"dhcp-snoop-port"`
	IpSourceGuardIntfConfig IpSourceGuardIntfConfigStruct `mapstructure:"ip-source-guard-port"`
	RateLimitConfig         RateLimitConfigStruct         `mapstructure:"rate-limit-port"`
	IPArpInspectIntfConfig  IPArpInspectIntfConfigStruct  `mapstructure:"ip-arp-inspect-port"`
	EdgePort                bool                          `mapstructure:"edge-port"`
	BpduGuard               BpduGuardStruct               `mapstructure:"bpdu-guard"`
	StormControl            interface{}					  `mapstructure:"storm-control"`
}

type IPArpInspectIntfConfigStruct struct {
	IPArpInspectRateLimit int  `mapstructure:"rate-limit-pps"`
	IPArpInspectTrust     bool `mapstructure:"trusted"`
}

type RateLimitConfigStruct struct {
	RateLimitIngress int `mapstructure:"ingress-kbps"`
	RateLimitEgress  int `mapstructure:"egress-kbps"`
}

type IpSourceGuardIntfConfigStruct struct {
	IpSourceGuardRule    string `mapstructure:"rule"`
	IpSourceGuardMode    string `mapstructure:"mode"`
	IpSourceGuardBinding int    `mapstructure:"max-binding"`
}

type Ethernet struct {
	SelectPorts []string `mapstructure:"select-ports"`
	Multicast   bool     `mapstructure:"multicast"`
	Learning    bool     `mapstructure:"learning"` // MAC Learning
	Name        string   `mapstructure:"name"`
	Isolate     bool     `mapstructure:"isolate"`
	Macaddr     string   `mapstructure:"macaddr"`
	VlanTag     string   `mapstructure:"vlan-tag"` // tagged/un-tagged/auto
}

type PlatLogicInterfaceVLAN struct {
	ID          int    `mapstructure:"id"`
	Porto       string `mapstructure:"proto"`        // 802.1ad//802.1q
	RangeStart  int    `mapstructure:"range-start"`
	RangeEnd    int    `mapstructure:"range-end"`
	StpInstance int    `mapstructure:"stp-instance"` //MSTP instance identifier of the vlan.
}

type SubNet struct {
	Prefix string `mapstructure:"prefix"` // uc-cidr4 --> 192.168.1.0/24
	Vrf    int    `mapstructure:"vrf"`
}

type GateWay struct {
	Prefix  string `mapstructure:"prefix"`  // uc-cidr4 --> 192.168.1.0/24
	Nexthop string `mapstructure:"nexthop"` // ipv4 str
	Vrf     int    `mapstructure:"vrf"`
	Metric  int    `mapstructure:"metric"` // Optional metric value (define a NH route's weight / metric).
}

type Broadcast struct {
	Prefix string `mapstructure:"prefix"` // uc-cidr4 --> 192.168.1.0/24
	Vrf    int    `mapstructure:"vrf"`
}

type InterfaceIpv4DHCP struct {
	LeaseFirst      int    `mapstructure:"lease-first"`
	LeaseCount      int    `mapstructure:"lease-count"`
	LeaseTime       string `mapstructure:"lease-time"`
	RelayServer     string `mapstructure:"relay-server"`
	CircuitIdFormat string `mapstructure:"circuit-id-format"`
	RemoteIdFormat  string `mapstructure:"remote-id-format"`
}

type InterfaceIpv4DHCPLeases struct {
	Macaddr           string `mapstructure:"macaddr"`
	StaticLeaseOffset int    `mapstructure:"static-lease-offset"`
	LeaseTime         string `mapstructure:"lease-time"`
	PublishHostname   string `mapstructure:"publish-hostname"`
}

type StaticMcastGroup struct {
	EgressPorts []string `mapstructure:"egress-ports"`
	Address     string   `mapstructure:"address"`
}

type InterfaceIGMP struct {
	SnoopingEnable          bool               `mapstructure:"snooping-enable"`
	Version                 int                `mapstructure:"version"`
	FastLeaveEnable         bool               `mapstructure:"fast-leave-enable"`
	QuerierEnable           bool               `mapstructure:"querier-enable"`
	QueryInterval           int                `mapstructure:"query-interval"`
	LastMemberQueryInterval int                `mapstructure:"last-member-query-interval"`
	MaxResponseTime         int                `mapstructure:"max-response-time"`
	StaticMcastGroups       []StaticMcastGroup `mapstructure:"static-mcast-groups"`
}

type InterfaceMulticast struct {
	UnknownMutiFlowCtrl bool          `mapstructure:"unknown-multicast-flood-control"`
	IGMP                InterfaceIGMP `mapstructure:"igmp"`
}

type InterfaceMvr struct {
	MvrIntfMvrRole     string `mapstructure:"mvr-intf-mvr-role"`
	MvrIntfImmedLeave  string `mapstructure:"mvr-intf-immed-leave"`
	MvrIntfAssocDomain int    `mapstructure:"mvr-intf-assoc-domain"`
}

type VoiceVlanIntfConfigStruct struct {
	VoiceVlanIntfMode        string `mapstructure:"voice-vlan-intf-mode"`
	VoiceVlanIntfPriority    int    `mapstructure:"voice-vlan-intf-priority"`
	VoiceVlanIntfDetectVoice string `mapstructure:"voice-vlan-intf-detect-voice"`
	VoiceVlanIntfSecurity    bool   `mapstructure:"voice-vlan-intf-security"`
}

type InterfaceIpv4 struct {
	Addressing             string                       `mapstructure:"addressing"` // dynamic/static/none
	Subnet                 []SubNet                     `mapstructure:"subnet"`     // ????? string or struct
	Gateway                []GateWay                    `mapstructure:"gateway"`
	Broadcast              []Broadcast                  `mapstructure:"broadcast"`
	SendHostname           bool                         `mapstructure:"send-hostname"` // include the devices hostname inside DHCP requests
	UseDns                 interface{}                  `mapstructure:"use-dns"`
	Dhcp                   InterfaceIpv4DHCP            `mapstructure:"dhcp"`
	DhcpLeases             InterfaceIpv4DHCPLeases      `mapstructure:"dhcp-leases"`
	PortForward            interface{}                  `mapstructure:"port-forward"`
	Multicast              InterfaceMulticast           `mapstructure:"multicast"`
	Mvr                    InterfaceMvr                 `mapstructure:"mvr"`
	DhcpSnoopVlanEnable    bool                         `mapstructure:"dhcp-snoop-vlan-enable"`
	IPArpInspectVlanConfig IPArpInspectVlanConfigStruct `mapstructure:"ip-arp-inspect-vlan"`
}

type IPArpInspectVlanConfigStruct struct {
	IPArpInspectVlanEnable            bool   `mapstructure:"vlan-enable"`
	IPArpInspectVlanAclRule           string `mapstructure:"vlan-acl-rule"`
	IPArpInspectVlanAclNodhcpBindings bool   `mapstructure:"vlan-acl-nodhcp-bindings"`
}

type InterfaceIpv6 struct {
}

type DhcpSnoopPortStruct struct {
	DhcpSnoopPortTrust bool `mapstructure:"dhcp-snoop-port-trust"`
}

type AclInterfaceStruct struct {
	AclInfPolicyPreference      int    `mapstructure:"acl-inf-policy-preference"`
	AclInfPolicyIngress         string `mapstructure:"acl-inf-policy-ingress"`
	AclInfPolicyCountersIngress bool   `mapstructure:"acl-inf-counters-ingress"`
	AclInfPolicyEgress          string `mapstructure:"acl-inf-policy-egress"`
	AclInfPolicyCountersEgress  bool   `mapstructure:"acl-inf-counters-egress"`
}
type PlatLogicInterface struct {
	Name      string                 `mapstructure:"name"`
	Role      string                 `mapstructure:"role"` // upstream/downstream
	Metric    int                    `mapstructure:"metric"`
	Mtu       int                    `mapstructure:"mtu"`
	Services  []string               `mapstructure:"services"`
	Vlan      PlatLogicInterfaceVLAN `mapstructure:"vlan"`
	Ethernets []Ethernet             `mapstructure:"ethernet"`
	Ipv4      InterfaceIpv4          `mapstructure:"ipv4"`
	Ipv6      interface{}            `mapstructure:"ipv6"`
}

type LacpConfigStruct struct {
	LacpEnable         bool   `mapstructure:"lacp-enable"`
	LacpRole           string `mapstructure:"lacp-role"`
	LacpMode           string `mapstructure:"lacp-mode"`
	LacpPortAdminkey   int    `mapstructure:"lacp-port-admin-key"`
	LacpPortPriority   int    `mapstructure:"lacp-port-priority"`
	LacpSystemPriority int    `mapstructure:"lacp-system-priority"`
	LacpPchanAdminKey  int    `mapstructure:"lacp-pchan-admin-key"`
	LacpTimeout        string `mapstructure:"lacp-timeout"`
}

type Telemetry struct {
	Enabled  bool
	Interval uint16 `mapstructure:"interval"`
}
type Healthcheck struct {
	Enabled  bool
	Interval uint16 `mapstructure:"interval"`
}

type Statistics struct {
	Interval    uint16   `mapstructure:"interval"`
	Types       []string `mapstructure:"types"` // "ssids"/"lldp"/"clients"/"tid-stats"
	MaxMacCount int      `mapstructure:"wired-clients-max-num"`
}

type PlatMetricsCfg struct {
	Statistics  Statistics  `mapstructure:"statistics"`
	Telemetry   Telemetry   `mapstructure:"telemetry"`
	Healthcheck Healthcheck `mapstructure:"health"`
}

type PlatSyslogCfg struct {
	Port     uint32
	Size     uint32
	Priority uint32
	IsTcp    uint32
	Host     string
}

type PlatIpv4 struct {
	Subnet    uint32
	SubnetLen int
	Exist     bool
}

type Router struct {
	Subnet    uint32
	SubnetLen int
	Exist     bool
}

type PlatStpInstanceCfg struct {
	Enabled      bool
	ForwardDelay uint16
	HelloTime    uint16
	MaxAge       uint16
	Priority     uint16
}

type Radius struct {
	ServerHost               string `mapstructure:"server-host"`
	ServerAuthenticationPort int    `mapstructure:"server-authentication-port"`
	ServerKey                string `mapstructure:"server-key"`
	ServerPriority           int    `mapstructure:"server-priority"`
	SourceAddr               string `mapstructure:"source-addr"`
}

type RadiusArray []Radius

func (array RadiusArray) Len() int {
	return len(array)
}

func (array RadiusArray) Less(i, j int) bool {
	return array[i].ServerPriority > array[j].ServerPriority
}

func (array RadiusArray) Swap(i, j int) {
	array[i], array[j] = array[j], array[i]
}

type PortMirror struct {
	MonitorPorts []string `mapstructure:"monitor-ports"`
	AnalysisPort string   `mapstructure:"analysis-port"`
}

type StpInstances struct {
	ID           int  `mapstructure:"id"`
	Enabled      bool `mapstructure:"enabled"`
	Priority     int  `mapstructure:"priority"`
	ForwardDelay int  `mapstructure:"forward_delay"`
	HellowTime   int  `mapstructure:"hellow_time"` // default 2
	MaxAge       int  `mapstructure:"max_age"`
}

type LoopDetection struct {
	Protocol  string         `mapstructure:"protocol"`
	Roles     []string       `mapstructure:"roles"` // upstream/downstream
	Instances []StpInstances `mapstructure:"instances"`
}

type DAC struct {
	Address   string `mapstructure:"address"`
	ServerKey string `mapstructure:"server-key"`
}

type DynamicAuthorization struct {
	AuthType  string `mapstructure:"auth-type"` //only support any
	ServerKey string `mapstructure:"server-key"`
	Client    []DAC  `mapstructure:"client"`
}

type Ieee8021x struct {
	AuthControlEnable    bool                 `mapstructure:"auth-control-enable"`
	Radius               []Radius             `mapstructure:"radius"`
	DynamicAuthorization DynamicAuthorization `mapstructure:"dynamic-authorization"`
}

type Session struct {
	ID       int  `mapstructure:"id"`
	Uplink   Link `mapstructure:"uplink"`
	Downlink Link `mapstructure:"downlink"`
}

type Link struct {
	InterfaceList []string `mapstructure:"interface-list"`
}

type PortIsolation struct {
	Sessions []Session `mapstructure:"sessions"`
}

type DhcpSnoopingStruct struct {
	DhcpSnoopEnable bool `mapstructure:"dhcp-snoop-enable"`
}

type AclRuleStruct struct {
	AclRuleAction       string `mapstructure:"acl-rule-action"`
	AclSourceMacAddress string `mapstructure:"acl-source-macaddress"`
	AclSourceMacBitMask string `mapstructure:"acl-source-macbitmask"`
	AclDestMacAddress   string `mapstructure:"acl-dest-macaddress"`
	AclDestMacBitMask   string `mapstructure:"acl-dest-macbitmask"`
	AclPacketFormat     string `mapstructure:"acl-packet-format"`
	AclVlanId           int    `mapstructure:"acl-vlanid"`
	AclVidBitMask       int    `mapstructure:"acl-vid-bitmask"`
	AclEtherType        string `mapstructure:"acl-ethertype"`
	AclEtherTypeBitMask string `mapstructure:"acl-ethertype-bitmask"`
	AclCos              int    `mapstructure:"acl-cos"`
	AclCosBitMask       int    `mapstructure:"acl-cos-bitmask"`

	AclIpv4SourceAddress      string `mapstructure:"acl-ipv4-source-address"`
	AclIpv4SourceSubnetmask   string `mapstructure:"acl-ipv4-source-subnetmask"`
	AclIpv4DestAddress        string `mapstructure:"acl-ipv4-dest-address"`
	AclIpv4DestSubnetmask     string `mapstructure:"acl-ipv4-dest-subnetmask"`
	AclIpv6SourceAddress      string `mapstructure:"acl-ipv6-source-address"`
	AclIpv6SourcePrefixLength int    `mapstructure:"acl-ipv6-source-prefix-length"`
	AclIpv6DestAddress        string `mapstructure:"acl-ipv6-dest-address"`
	AclIpv6DestPrefixLength   int    `mapstructure:"acl-ipv6-dest-prefix-length"`
	AclIpProto                int    `mapstructure:"acl-ip-proto"`
	AclIpv6NexHeader          int    `mapstructure:"acl-ipv6-next-header"`
	AclIpv6FlowLabel          int    `mapstructure:"acl-ipv6-flow-label"`
	AclIpSourcePort           int    `mapstructure:"acl-ip-source-port"`
	AclIpSourcePortBitmask    int    `mapstructure:"acl-ip-source-port-bitmask"`
	AclIpDestPort             int    `mapstructure:"acl-ip-dest-port"`
	AclIpDestPortBitmask      int    `mapstructure:"acl-ip-dest-port-bitmask"`
	AclIpv4FragmentOffset     int    `mapstructure:"acl-ipv4-fragment-offset"`
	AclIpv6FragmentOffset     int    `mapstructure:"acl-ipv6-fragment-offset"`
	AclIpTTL                  int    `mapstructure:"acl-ip-ttl"`
	AclIpv6HopLimit           int    `mapstructure:"acl-ipv6-hop-limit"`
}

type AclStruct struct {
	AclName  string                              `mapstructure:"acl-name"`
	AclType  string                              `mapstructure:"acl-type"`
	AclRules map[string][]map[string]interface{} `mapstructure:"acl-rules"`
}

type MvrConfigStruct struct {
	MvrEnalbe          bool   `mapstructure:"mvr-enable"`
	MvrProxyQueryIntvl int    `mapstructure:"mvr-proxy-query-intvl"`
	MvrProxySwtiching  bool   `mapstructure:"mvr-proxy-switching"`
	MvrRobustnessVal   int    `mapstructure:"mvr-robustness-val"`
	MvrSourcePortMode  string `mapstructure:"mvr-source-port-mode"`
}

type MvrDomainConfigStruct struct {
	MvrDomainId          int    `mapstructure:"mvr-domain-id"`
	MvrDomainEnable      bool   `mapstructure:"mvr-domain-enable"`
	MvrDomainVlanId      int    `mapstructure:"mvr-domain-vlan-id"`
	MvrDomainUpstreamSip string `mapstructure:"mvr-domain-upstream-sip"`
}

type MvrGroupConfigStruct struct {
	MvrGroupName        string `mapstructure:"mvr-group-name"`
	MvrGroupRangeStart  string `mapstructure:"mvr-group-range-start"`
	MvrGroupRangeEnd    string `mapstructure:"mvr-group-range-end"`
	MvrGroupAssocDomain []int  `mapstructure:"mvr-group-assoc-domain"`
}

type VoiceVlanOuiConfigStruct struct {
	VoiceVlanOuiMac         string `mapstructure:"voice-vlan-oui-mac"`
	VoiceVlanOuiMask        string `mapstructure:"voice-vlan-oui-mask"`
	VoiceVlanOuiDescription string `mapstructure:"voice-vlan-oui-description"`
}

type VoiceVlanConfigStruct struct {
	VoiceVlanEnable     bool                       `mapstructure:"voice-vlan-enable"`
	VoiceVlanId         int                        `mapstructure:"voice-vlan-id"`
	VoiceVlanAgeingTime int                        `mapstructure:"voice-vlan-ageing-time"`
	VoiceVlanOuiConfig  []VoiceVlanOuiConfigStruct `mapstructure:"voice-vlan-oui-config"`
}

type PeerLinkStruct struct {
	Type  string `mapstructure:"type"`
	Value int    `mapstructure:"value"`
}

type McLagLacpConfigStruct struct {
	LacpEnable  bool   `mapstructure:"lacp-enable"`
	LacpRole    string `mapstructure:"lacp-role"`
	LacpTimeout string `mapstructure:"lacp-timeout"`
}

type McLagGroupStruct struct {
	GroupId    int                   `mapstructure:"group-id"`
	Members    []string              `mapstructure:"members"`
	LacpConfig McLagLacpConfigStruct `mapstructure:"lacp-config"`
}
type McLagDomainStruct struct {
	McLagDomain         int              `mapstructure:"mclag-domain"`
	PeerLink            PeerLinkStruct   `mapstructure:"peer-link"`
	McLagGroup          McLagGroupStruct `mapstructure:"mclag-group"`
	SystemPriority      int              `mapstructure:"system-priority"`
	DualActiveDetection bool             `mapstructure:"dual-active-detection"`
}

type McLagConfigStruct struct {
	McLagDomains []McLagDomainStruct `mapstructure:"mclag-domains"`
}

type Switch struct {
	PortMirror []PortMirror `mapstructure:"port-mirror"`
	LoopDetection       LoopDetection             `mapstructure:"loop-detection"`
	Ieee8021x           Ieee8021x                 `mapstructure:"ieee8021x"`
	PortIsolation       PortIsolation             `mapstructure:"port-isolation"`
	TrunkBalanceMethod  string                    `mapstructure:"trunk-balance-method"`
	JumboFrames         bool                      `mapstructure:"jumbo-frames"`
	DhcpSnooping        DhcpSnoopingStruct        `mapstructure:"dhcp-snooping"`
	Acl                 []AclStruct               `mapstructure:"acl"`
	MvrConfig           MvrConfigStruct           `mapstructure:"mvr-config"`
	MvrDomainConfig     []MvrDomainConfigStruct   `mapstructure:"mvr-domain-config"`
	MvrGroupConfig      []MvrGroupConfigStruct    `mapstructure:"mvr-group-config"`
	VoiceVlanConfig     VoiceVlanConfigStruct     `mapstructure:"voice-vlan-config"`
	McLag               bool                      `mapstructure:"mc-lag"`
	McLagConfig         McLagConfigStruct         `mapstructure:"mclag-config"`
	IPSourceGuardConfig IPSourceGuardConfigStruct `mapstructure:"ip-source-guard"`
	RTEvent             RTEventStruct             `mapstructure:"rt-events"`
	LLdpGlobalConfig    interface{}               `mapstructure:"lldp-global-config"`
}

type LLdpGlobalConfigStruct struct {
	LLdpEnable               bool `mapstructure:"lldp-enable"`
	LLdpHoldTimeMultiplier   int  `mapstructure:"lldp-holdtime-multiplier"`
	LLdpMedFastStartCount    int  `mapstructure:"lldp-med-fast-start-count"`
	LLdpRefreshInterval      int  `mapstructure:"lldp-refresh-interval"`
	LLdpReinitDelay          int  `mapstructure:"lldp-reinit-delay"`
	LLdpTxDelay              int  `mapstructure:"lldp-tx-delay"`
	LLdpNotificationInterval int  `mapstructure:"lldp-notification-interval"`
}

type RTEventStruct struct {
	PortStatus   RTPortStatusStruct   `mapstructure:"port-status"`
	Module       RTModuleStruct       `mapstructure:"module"`
	Stp          RTStpStruct          `mapstructure:"stp"`
	Rstp         RTRstpStruct         `mapstructure:"rstp"`
	FwUpgrade    FwUpgradeStruct      `mapstructure:"fw-upgrade"`
	DhcpSnooping RTDhcpSnoopingStruct `mapstructure:"dhcp-snooping"`
}

type RTDhcpSnoopingStruct struct {
	Enabled   bool                        `mapstructure:"enabled"`
	SubEvents DhcpSnoopingSubEventsStruct `mapstructure:"sub-events"`
}

type DhcpSnoopingSubEventsStruct struct {
	DhcpSnoopingViolationDetected bool `mapstructure:"dhcp-snooping.violation-detected"`
	DhcpSnoopingViolationCleared  bool `mapstructure:"dhcp-snooping.violation-cleared"`
}

type FwUpgradeStruct struct {
	Enabled   bool                     `mapstructure:"enabled"`
	SubEvents FwUpgradeSubEventsStruct `mapstructure:"sub-events"`
}

type FwUpgradeSubEventsStruct struct {
	UpgDownloadStart         bool `mapstructure:"upg.download-start"`
	UpgDownloadinProgress    bool `mapstructure:"upg.download-in-progress"`
	UpgDownloadFailed        bool `mapstructure:"upg.download-failed"`
	UpgValidationStart       bool `mapstructure:"upg.validation-start"`
	UpgValidationSuccess     bool `mapstructure:"upg.validation-success"`
	UpgValidationFailed      bool `mapstructure:"upg.validation-failed"`
	UpgBackupCurrentFirmware bool `mapstructure:"upg.backup-current-firmware"`
	UpgInstallStart          bool `mapstructure:"upg.install-start"`
	UpgInstallFailed         bool `mapstructure:"upg.install-failed"`
	UpgRebootStart           bool `mapstructure:"upg.reboot-start"`
	UpgSuccess               bool `mapstructure:"upg.success"`
}

type RTRstpStruct struct {
	Enabled   bool                `mapstructure:"enabled"`
	SubEvents RstpSubEventsStruct `mapstructure:"sub-events"`
}

type RstpSubEventsStruct struct {
	RstpLoopDetected bool `mapstructure:"rstp.loop-detected"`
	RstpLoopCleared  bool `mapstructure:"rstp.loop-cleared"`
	RstpStateChange  bool `mapstructure:"rstp.state-change"`
}

type RTStpStruct struct {
	Enabled   bool               `mapstructure:"enabled"`
	SubEvents StpSubEventsStruct `mapstructure:"sub-events"`
}

type StpSubEventsStruct struct {
	StpLoopDetected bool `mapstructure:"stp.loop-detected"`
	StpLoopCleared  bool `mapstructure:"stp.loop-cleared"`
	StpStateChange  bool `mapstructure:"stp.state-change"`
}

type RTModuleStruct struct {
	Enabled   bool                  `mapstructure:"enabled"`
	SubEvents ModuleSubEventsStruct `mapstructure:"sub-events"`
}

type ModuleSubEventsStruct struct {
	ModulePlugout bool `mapstructure:"module.plugout"`
	ModulePlugin  bool `mapstructure:"module.plugin"`
}

type RTPortStatusStruct struct {
	Enabled   bool                      `mapstructure:"enabled"`
	SubEvents PortStatusSubEventsStruct `mapstructure:"sub-events"`
}

type PortStatusSubEventsStruct struct {
	WiredCarrierDown bool `mapstructure:"wired.carrier-down"`
	WiredCarrierUp   bool `mapstructure:"wired.carrier-up"`
}

type IPSourceGuardConfigStruct struct {
	IPSourceGuardBindings []IPSourceGuardBindingsStruct `mapstructure:"bindings"`
}

type IPSourceGuardBindingsStruct struct {
	IPSourceGuardBindingMode      string `mapstructure:"binding-mode"`
	IPSourceGuardBindingMac       string `mapstructure:"binding-mac"`
	IPSourceGuardBindingIP        string `mapstructure:"binding-ip"`
	IPSourceGuardBindingVlans     int    `mapstructure:"binding-vlans"`
	IPSourceGuardBindingInterface string `mapstructure:"binding-port"`
}
type StaticRoute struct {
	Prefix string `mapstructure:"prefix"`
	Vrf    uint16 `mapstructure:"vrf"`
}

type PlatGlobal struct {
	Ipv4Network     string        `mapstructure:"ipv4-network"`
	Ipv6Network     string        `mapstructure:"ipv6-network"`
	Ipv4Blackhole   []StaticRoute `mapstructure:"blackhole"`
	Ipv4Unreachable []StaticRoute `mapstructure:"unreachable"`
}

type LLDP struct {
	Describe string `mapstructure:"describe"`
	Location string `mapstructure:"location"`
}

type SSH struct {
	Port                   uint32   `mapstructure:"port"`
	AuthorizedKeys         []string `mapstructure:"authorized-keys"`
	PasswordAuthentication bool     `mapstructure:"password-authentication"`
	Enable                 bool     `mapstructure:"enable"`
}

type NTP struct {
	Servers     []string `mapstructure:"servers"`
	LocalServer bool     `mapstructure:"local-server"`
}

type NtpSupportStruct struct {
	NtpEnable             bool                          `mapstructure:"ntp-enable"`
	NtpAuthEnable         bool                          `mapstructure:"ntp-auth-enable"`
	Servers               ServicesStruct                `mapstructure:"servers"`
	NtpAuthenticationKeys []NtpAuthenticationKeysStruct `mapstructure:"ntp-authentication-keys"`
}

type ServicesStruct struct {
	ServerAddress     string `mapstructure:"server-address"`
	AuthenticationKey uint8  `mapstructure:"authentication-key"`
}

type NtpAuthenticationKeysStruct struct {
	KeyId         uint8  `mapstructure:"key-id"`
	AuthAlgorithm string `mapstructure:"auth-algorithm"`
	AuthKey       string `mapstructure:"auth-key"`
}

type RTTY struct {
}

type ServiceLOG struct {
	Host     string `mapstructure:"host"`
	Port     uint32 `mapstructure:"port"`
	Proto    string `mapstructure:"proto"` // tcp/udp
	Size     uint32 `mapstructure:"size"`
	Priority uint8  `mapstructure:"priority"`
}

type DhcpRelayVlan struct {
	Vlan            uint32 `mapstructure:"vlan"`
	RelayServer     string `mapstructure:"relay-server"`
	CircuitIdFormat string `mapstructure:"circuit-id-format"` // vlan-id/ap-mac/ssid
	RemoteIdFormat  string `mapstructure:"remote-id-format"`
}

type DhcpRelay struct {
	SelectPorts []string        `mapstructure:"select-ports"`
	Vlans       []DhcpRelayVlan `mapstructure:"vlans"`
}

type ServiceIGMP struct {
	Enable bool `mapstructure:"enable"`
}

type Services struct {
	Lldp       LLDP             `mapstructure:"lldp"`
	Ssh        SSH              `mapstructure:"ssh"`
	Ntp        NTP              `mapstructure:"ntp"`
	Rtty       RTTY             `mapstructure:"rtty"`
	Log        ServiceLOG       `mapstructure:"log"`
	DhcpRelay  DhcpRelay        `mapstructure:"dhcp-relay"`
	IGMP       ServiceIGMP      `mapstructure:"igmp"`
	NtpSupport NtpSupportStruct `mapstructure:"ntp-support"`
}

type PlatCfg struct {
	Strict         bool       `mapstructure:"strict"`
	Uuid           string     `mapstructure:"uuid"`
	PublicIpLookup string     `mapstructure:"public_ip_lookup"`
	Unit           PlatUnit   `mapstructure:"unit"`
	Globals        PlatGlobal `mapstructure:"globals"`
	Ethernet       []PlatPort `mapstructure:"ethernet"`
	Interfaces []PlatLogicInterface `mapstructure:"interfaces"`
	Metrics  PlatMetricsCfg `mapstructure:"metrics"`
	Services Services       `mapstructure:"services"`
	Switch   Switch         `mapstructure:"switch"`
}

type PortLinkStatus struct {
	PortId int
	Status string
}

type PoeLinkStatus struct {
	PortId int
	Status string
}

// ============================= ucentral cfg strut ======================================

// ============================= sonic cfg strut ======================================
type SonicConfigRadiusServer struct {
}

// ============================= sonic cfg strut ======================================

// ============================= ucentral redirector strut ======================================

type Division struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

type DeviceProfile struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

type DirectorField struct {
	Id        string `json:"id"`
	Name      string `json:"name"`
	Value     string `json:"value"`
	Mandatory bool   `json:"mandatory"`
}

type redirectorCfg struct {
	Id                              string          `json:"id"`
	AccountId                       string          `json:"account_id"`
	Division                        Division        `json:"division"`
	DeviceIdentifier                string          `json:"device_identifier"`
	DeviceProfile                   DeviceProfile   `json:"device_profile"`
	Created                         string          `json:"created"`
	Updated                         string          `json:"updated"`
	Status                          string          `json:"status"`
	Fields                          []DirectorField `json:"fields"`
	DeviceApiAllowRead              bool            `json:"device_api_allow_read"`
	DeviceApiAllowWrite             bool            `json:"device_api_allow_write"`
	DeviceApiAllowRenewCertificate  bool            `json:"device_api_allow_renew_certificate"`
	DeviceApiAllowEnrollCertificate bool            `json:"device_api_allow_enroll_certificate"`
	DeviceApiAllowRevoke            bool            `json:"device_api_allow_revoke"`
}

type CloudDiscoveryCfg struct {
	MacAddress         string `json:"mac_address"`
	ControllerEndpoint string `json:"controller_endpoint"`
	Metadata           string `json:"metadata"`
	OrganizationId     string `json:"organization_id"`
	CreateAt           string `json:"created_at"`
	UpdateAt           string `json:"updated_at"`
}

// ============================= ucentral redirector strut ======================================
