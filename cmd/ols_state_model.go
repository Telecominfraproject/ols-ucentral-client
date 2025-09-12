package main

// The physical links duplex mode.
type OLSDuplex string

const (
	Full OLSDuplex = "full"
	Half OLSDuplex = "half"
)

type OLSPoE struct {
	MaxPowerBudget float64 `json:"max-power-budget"`
	PowerConsumed  float64 `json:"power-consumed"`
	PowerStatus    string  `json:"power-status"`
}

type OLSPoECounter struct {
	// Displays the number of times that the power was stopped to the powered device because the
	// powered device was no longer detected.
	Absent float64 `json:"absent,omitempty"`
	// Displays the times that an invalid signature was received. Signatures are the means by
	// which the powered device identifies itself to the PSE. Signatures are generated during
	// powered device detection, classification, or maintenance.
	InvalidSignature float64 `json:"invalid-signature,omitempty"`
	// Displays the total number of power overload occurrences. (Powered Device is consuming
	// more power than the maximum limit of a port)
	Overload float64 `json:"overload,omitempty"`
	// Displays the number of times that the powered device was denied power. (possible cause
	// could be that Requested power exceeds PSE capability)
	PowerDenied float64 `json:"power-denied,omitempty"`
	// Displays the total number of power shortage occurrences.
	Short float64 `json:"short,omitempty"`
}

// This section describes the ethernet poe-port link-state object (statistics + PD info).
// Present only in case if port has any Power sourcing capabilities.
type OLSPortPoE struct {
	// Reports which PoE power class PD has been assigned by the Power sourcing equipment.
	ClassAssigned int64 `json:"class-assigned"`
	// Reports which PoE power class PD requested.
	ClassRequested int64 `json:"class-requested"`
	// Counters       OLSPoECounter `json:"counters,omitempty"`
	// Reports the fault status of poe-port's PSE (in case if any).
	FaultStatus string `json:"fault-status"`
	// Reports the current value (in milliamps, mA) poe-port's Powered Device is currently
	// draining.
	OutputCurrent float64 `json:"output-current"`
	// Reports the power-value (in milliwatts, mW) poe-port's Powered Device is currently
	// draining.
	OutputPower float64 `json:"output-power"`
	// Reports the operational voltage-level-value of poe-port's Power sourcing equipment (in
	// Volts, V).
	OutputVoltage string `json:"output-voltage"`
	// Reports the operational status of poe-port's Power sourcing equipment. Searching option -
	// the poe-port's PSE is trying to detect a Powered Device. Delivering option - the
	// poe-port's PSE is delivering power to a Powered Device. Disabled option - the poe-port's
	// PSE is either disabled or PoE power is enabled but the PoE module does not have enough
	// power available to supply the port's power needs. Fault option - the poe-port's PSE
	// detects a problem with the Powered Device. Other Fault option - the PSE has detected an
	// internal fault that prevents it from supplying power on that port.
	Status string `json:"status"`
	// Reports the operational temperature of poe-port's Power sourcing equipment (in Celsius,
	// C).
	Temp string `json:"temp"`
}

type OLSAuthenticatedClient struct {
	// Authentication method used by client for it's authentication.
	AuthenticatedMethod string `json:"authenticated-method,omitempty"`
	// MAC address of authenticated client.
	MACAddress string `json:"mac-address,omitempty"`
	// Client session time.
	SessionTime int64 `json:"session-time,omitempty"`
	// Client username.
	Username string `json:"username,omitempty"`
	// Vlan type of authenticated client (Authorization status of the client).
	VLANID int64 `json:"vlan-id,omitempty"`
	// Vlan type of authenticated client (Authorization status of the client).
	VLANType string `json:"vlan-type,omitempty"`
}

// This section describes the per-port specific 802.1X (port access control) link-state
// object (authenticated clients). Present only in case if port has enabled EAP processing
// and has any authenticated clients.
type OLSIeee8021X struct {
	// List of authenticated clients and (their) authentication data.
	AuthenticatedClients []OLSAuthenticatedClient `json:"authenticated-clients,omitempty"`
}

type OLSPortLinkState struct {
	// The physical interfaces carrier state.
	Carrier bool `json:"carrier"`
	// This section contains the traffic counters of the logical interface.
	Counters      OLSInterfaceCounter `json:"counters"`
	DeltaCounters OLSInterfaceCounter `json:"delta_counters"`
	// The physical links duplex mode.
	Duplex OLSDuplex `json:"duplex"`
	// // This section describes the per-port specific 802.1X (port access control) link-state
	// // object (authenticated clients). Present only in case if port has enabled EAP processing
	// // and has any authenticated clients.
	// Ieee8021X OLSIeee8021X `json:"ieee8021x,omitempty"`
	// This section describes the ethernet poe-port link-state object (statistics + PD info).
	// Present only in case if port has any Power sourcing capabilities.
	PoE *OLSPortPoE `json:"poe,omitempty"`
	// The speed of the physical link.
	Speed float64 `json:"speed"`

	StateIeee8021X     StateIeee8021X           `json:"ieee8021x"`
	TransceiverInfo    TransceiverInfo          `json:"transceiver-info,omitempty"`
	StromStatus        StormStatusStruct        `json:"storm-status"`
	LoopDetectProtocol LoopDetectProtocolStruct `json:"loop-detect-protocol"`
}

type LoopDetectProtocolStruct struct {
	Stp PortStpStruct `json:"stp,omitempty"`
	Lbd LbdStruct     `json:"lbd,omitempty"`
}

type PortStpStruct struct {
	Protocol       string `json:"protocol"`
	State          string `json:"state"`
	Role           string `json:"role"`
	BridgeId       string `json:"bridge-id"`
	RootBridgeId   string `json:"root-bridge-id,omitempty"`
	OperEdgePort   bool   `json:"oper-edge-port,omitempty"`
	Cost           int    `json:"cost,omitempty"`
	DesignatedCost int    `json:"designated-cost,omitempty"`
	Transittions   int    `json:"transitions,omitempty"`
}

type LbdStruct struct {
	Enabled bool   `json:"enabled"`
	State   string `json:"state,omitempty"`
	Action  string `json:"action,omitempty"`
}

type StormStatusStruct struct {
	Broadcast      bool `json:"broadcast"`
	Multicast      bool `json:"multicast"`
	UnknownUnicast bool `json:"unknown-unicast"`
}

type TransceiverInfo struct {
	VendorName         string   `json:"vendor-name"`
	FormFactor         string   `json:"form-factor"`
	SupportedLinkModes []string `json:"supported-link-modes,omitempty"`
	PartNumber         string   `json:"part-number"`
	SerialNumber       string   `json:"serial-number"`
	Revision           string   `json:"revision"`
	Temperature        float64  `json:"temperature"`
	TxOpticalPower     float64  `json:"tx-optical-power"`
	RxOpticalPower     float64  `json:"rx-optical-power"`
	MaxModulePower     float64  `json:"max-module-power,omitempty"`
}

type StateIeee8021X struct {
}

// interface.counter，This section contains the traffic counters of the logical interface.
type OLSInterfaceCounter struct {
	Collisions int `json:"collisions"`
	Multicast  int `json:"multicast"`
	// The number of bytes received.
	RxBytes int `json:"rx_bytes"`
	// The number of received packets that were dropped.
	RxDropped int `json:"rx_dropped"`
	// The number of receive errors.
	RxError int `json:"rx_error"`
	// The number of packets received.
	RxPackets int `json:"rx_packets"`
	// The number of bytes transmitted.
	TxBytes int `json:"tx_bytes"`
	// The number of transmitted packets that were dropped.
	TxDropped int `json:"tx_dropped"`
	// The number of transmit errors.
	TxError int `json:"tx_error"`
	// The number of packets transmitted.
	TxPackets int `json:"tx_packets"`
}

type OLSLinkStates struct {
	UpStream   map[string]OLSPortLinkState `json:"upstream"`
	DownStream map[string]OLSPortLinkState `json:"downstream"`
}

// lldp-peers
// A list of all LLDP peers that this logical interface is connected to.

type LLDPRemotePortInfoStruct struct {
	LLDPRemotePortId           string                           `json:"lldp-remote-port-id"`
	LLDPRemotePortIdType       string                           `json:"lldp-remote-port-id-type"`
	LLDPRemoteTTL              int                              `json:"lldp-remote-ttl"`
	LLDPRemotePortDescr        string                           `json:"lldp-remote-port-descr"`
	LLDPRemotePortMaxMtu       string                           `json:"lldp-remote-port-max-mtu,omitempty"`
	LLDPRemoteSysDescr         string                           `json:"lldp-remote-sys-descr"`
	LLDPRemoteSysCapab         []string                         `json:"lldp-remote-sys-capab,omitempty"`
	LLDPRemoteEnabledCapab     []string                         `json:"lldp-remote-enabled-capab,omitempty"`
	LLDPRemotePortMgmtAddress  string                           `json:"lldp-remote-port-mgmt-address,omitempty"`
	LLDPRemotePortVlanId       int                              `json:"lldp-remote-port-vlan-id,omitempty"`
	LLDPRemotePortProtocolId   string                           `json:"lldp-remote-port-protocol-id,omitempty"`
	LLDPRemotePortMacPhyStatus LLDPRemotePortMacPhyStatusStruct `json:"lldp-remote-port-mac-phy-status,omitempty"`
	LLDPRemotePortPowerInfo    LLDPRemotePortPowerInfoStruct    `json:"lldp-remote-port-power-info,omitempty"`
	LLDPRemotePortLagInfo      LLDPRemotePortLagInfoStruct      `json:"lldp-remote-port-lag-info,omitempty"`
}

type LLDPRemotePortMacPhyStatusStruct struct {
	LLDPRemotePortAnegSupport       bool   `json:"lldp-remote-port-aneg-support"`
	LLDPRemotePortAnegEnabled       bool   `json:"lldp-remote-port-aneg-enabled"`
	LLDPRemotePortAnegAdvertisedCap string `json:"lldp-remote-port-aneg-advertised-cap,omitempty"`
	LLDPRemotePortMauType           int    `json:"lldp-remote-port-mau-type,omitempty"`
}

type LLDPRemotePortPowerInfoStruct struct {
	LLDPRemotePortPowerClass         string `json:"lldp-remote-port-power-class,omitempty"`
	LLDPRemotePortMdiSupport         bool   `json:"lldp-remote-port-power-mdi-support,omitempty"`
	LLDPRemotePortPowerMdiEnabled    bool   `json:"lldp-remote-port-power-mdi-enabled,omitempty"`
	LLDPRemotePortPowerPairControl   bool   `json:"lldp-remote-port-power-pair-control,omitempty"`
	LLDPRemotePortPowerClassfication string `json:"lldp-remote-port-power-classification,omitempty"`
}

type LLDPRemotePortLagInfoStruct struct {
	LLDPRemotePortLagSupport bool `json:"lldp-remote-port-lag-support,omitempty"`
	LLDPRemotePortLagEnabled bool `json:"lldp-remote-port-lag-enabled,omitempty"`
	LLDPRemotePortLagPortId  int  `json:"lldp-remote-port-lag-port-id,omitempty"`
}

type OLSLldpPeer struct {
	// The device capabilities that our neighbour is announcing.
	Capability []string `json:"capability,omitempty"`
	// The chassis description that our neighbour is announcing.
	Description string `json:"description,omitempty"`
	// The chassis ID/MAC that our neighbour is announcing.
	MAC string `json:"mac,omitempty"`
	// The management IPs that our neighbour is announcing.
	ManagementIPS []string `json:"management_ips,omitempty"`
	// The physical network port that we see this neighbour on.
	Port               string                   `json:"port,omitempty"`
	LLDPRemotePortInfo LLDPRemotePortInfoStruct `json:"lldp-remote-port-info,omitempty"`
}

type OLSLldpPeers struct {
	UpStream   map[string]OLSLldpPeer `json:"upstream"`
	DownStream map[string]OLSLldpPeer `json:"downstream"`
}

type OLSConfiguration struct {
	Interfaces []struct {
		Ethernet []struct {
			SelectPorts []string `json:"select-ports"`
		} `json:"ethernet"`
		Role string `json:"role"`
	} `json:"interfaces"`
}

// LLDP from device shell
type OLSDeviceLldpChassis map[string]struct {
	Id struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"id"`
	MgmtIp      interface{} `json:"mgmt-ip"`
	Description string      `json:"descr"`
	Capability  interface{} `json:"capability"`
}

type OLSDeviceLldpPort struct {
	Id struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"id"`
	Description string `json:"descr"`
}

type OLSDeviceLldpInterface map[string]struct {
	Chassis OLSDeviceLldpChassis `json:"chassis" `
	Port    OLSDeviceLldpPort    `json:"port" `
}

type OLSDeviceLldp struct {
	LLDP struct {
		Interface OLSDeviceLldpInterface `json:"interface"`
	} `json:"lldp"`
}

type OLSDeviceLldps struct {
	LLDP struct {
		Interfaces []OLSDeviceLldpInterface `json:"interface"`
	} `json:"lldp"`
}

// LLDP info
type OLSLldpChassis struct {
	Id struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"id"`
	Description string      `json:"description"`
	Hostname    string      `json:"hostname"`
	IP          string      `json:"ip"`
	IPv4        string      `json:"ipv4"`
	IPv6        string      `json:"ipv6"`
	MAC         string      `json:"mac"`
	Capability  interface{} `json:"capability"`
}

type OLSLldpPort struct {
	Id struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"id"`
	Description string `json:"description"`
}

type OLSLldpNeighbor struct {
	Chassis OLSLldpChassis `json:"chassis"`
	Port    OLSLldpPort    `json:"port"`
}

type OLSLldpInterface struct {
	Neighbor OLSLldpNeighbor `json:"neighbor"`
	Port     string          `json:"port"`
}
