package main

type CMDScriptDeviceResponse struct {
	Jsonrpc string          `json:"jsonrpc"`
	Id      int             `json:"id"`
	Result  CMDScriptResult `json:"result"`
}

type CMDScriptResult struct {
	Serial string          `json:"serial"`
	Uuid   int             `json:"uuid"`
	Status CMDScriptStatus `json:"status"`
}

type CMDScriptStatus struct {
	Err      uint    `json:"error"`
	Result64 string `json:"result_64,omitempty"`
	ResultSZ uint `json:"result_sz,omitempty"`
	Result   string `json:"result,omitempty"`
}
