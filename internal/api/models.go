package api

// APIResponse 标准响应结构
type APIResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type ScanOptionOverrides struct {
	Threads  string `json:"threads,omitempty"`
	Retry    string `json:"retry,omitempty"`
	Timeout  string `json:"timeout,omitempty"`
	Header   string `json:"header,omitempty"`
	RandomUA *bool  `json:"random_ua,omitempty"`
}

type DirscanRequest struct {
	ScanOptionOverrides
	Targets       []string             `json:"targets"`
	DirscanConfig *DirscanModuleConfig `json:"dirscan_config,omitempty"`
}

type DirscanModuleConfig struct {
	WordList         string `json:"word_list,omitempty"`
	ValidStatusCodes []int  `json:"valid_status_codes,omitempty"`
	Filter           int64  `json:"filter,omitempty"`
}

type FingerprintRequest struct {
	ScanOptionOverrides
	Targets           []string                 `json:"targets"`
	FingerprintConfig *FingerprintModuleConfig `json:"fingerprint_config,omitempty"`
}

type FingerprintModuleConfig struct {
	RulesPath   string `json:"rules_path,omitempty"`
	ShowSnippet *bool  `json:"show_snippet,omitempty"`
}

type PortscanRequest struct {
	ScanOptionOverrides
	Targets []string        `json:"targets,omitempty"`
	Config  *PortscanConfig `json:"portscan_config"`
}

type CombinedRequest struct {
	ScanOptionOverrides
	Targets           []string                 `json:"targets"`
	DirscanConfig     *DirscanModuleConfig     `json:"dirscan_config,omitempty"`
	FingerprintConfig *FingerprintModuleConfig `json:"fingerprint_config,omitempty"`
	PortscanConfig    *PortscanConfig          `json:"portscan_config,omitempty"`
}

type PortscanConfig struct {
	Ports   string `json:"ports"`
	Rate    int    `json:"rate,omitempty"`
	Service *bool  `json:"service,omitempty"`
}
