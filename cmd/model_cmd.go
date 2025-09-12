package main

type CMDPingDeviceResponse struct {
	Jsonrpc string        `json:"jsonrpc"`
	Id      int           `json:"id"`
	Result  CMDPingResult `json:"result"`
}

type CMDPingResult struct {
	Serial        string `json:"serial"`
	Uuid          int    `json:"uuid"`
	DeviceUTCTime int64  `json:"deviceUTCTime"`
}

type CMDTraceConifg struct {
	Duration  int64  `json:"duration"`
	Packets   int64  `json:"packets"`
	Network   string `json:"network"`
	Interface string `json:"interface"`
	Uri       string `json:"uri"`
}
