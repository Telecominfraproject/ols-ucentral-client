package main

import ()

const olsConfigFile = "/etc/ucentral/ucentral.active"


var POE_STATUS_DICT = map[string]string{}

func includeString(target string, array []string) bool {
	// need to implement by SonicOS.
	return false
}

func includeInt(target int, array []int) bool {
	// need to implement by SonicOS.
	return false
}

func findIndexInterface(port string, array []Interface) int {
	// need to implement by SonicOS.
	return -1
}

func isPoe() bool {
	// need to implement by SonicOS.
	return true
}

func getStreamPort(configuration *OLSConfiguration, role string) []string {
	// need to implement by SonicOS.
	ports := []string{}
	return ports
}

func getOLSPortSpeed(port string) (float64, error) {
	// need to implement by SonicOS.
	return 0.0, nil
}

func getStateDbPoeStatus(intfName string, statusType string) string {
	// need to implement by SonicOS.
	status := ""
	return status
}

func getApplDbPortStatus(intfName string, statusType string) string {
	// need to implement by SonicOS.
	status := ""
	return status
}

func getOLSPortPoe(port string) (*OLSPortPoE, error) {
	// need to implement by SonicOS.
	poe := new(OLSPortPoE)
	return poe, nil
}

func getTransceiverInfo(port string) (TransceiverInfo, error) {
	// need to implement by SonicOS.
	transceiverData := TransceiverInfo{}
	return transceiverData, nil
}

func getOLSPortLinkState(port string, interfaces []Interface, bridgeId string, stpInfoFormMstpctl string) (OLSPortLinkState, error) {
	// need to implement by SonicOS.
	portLinkState := OLSPortLinkState{}
	return portLinkState, nil
}

func GetOLSConfiguration() (OLSConfiguration, error) {
	// need to implement by SonicOS.
	var data OLSConfiguration
	return data, nil
}

func GetOLSLinkState(interfaces []Interface) (OLSLinkStates, error) {
	// need to implement by SonicOS.
	linkState := OLSLinkStates{}
	return linkState, nil
}

func GetOLSPoE() (*OLSPoE, error) {
	// need to implement by SonicOS.
	poe := new(OLSPoE)
	return poe, nil
}

func GetOLSLldpPeers() ([]OLSLldpPeer, error) {
	// need to implement by SonicOS.
	lldpPeers := []OLSLldpPeer{}
	return lldpPeers, nil
}

func GetOLSInterface(interfaces []Interface) ([]OLSInterface, error) {
	// need to implement by SonicOS.
	interfaceArr := []OLSInterface{}
	return interfaceArr, nil
}

func GetOLSAclbasedPort() ([]AclIntfStatsStruct, error) {
	// need to implement by SonicOS.
	aclInftList := []AclIntfStatsStruct{}
	return aclInftList, nil
}

func getStormStatus(portId string) (StormStatusStruct, error) {
	// need to implement by SonicOS.
	stormStatus := StormStatusStruct{}
	return stormStatus, nil
}
