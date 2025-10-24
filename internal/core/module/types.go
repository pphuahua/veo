package module

// ModuleType 模块类型
type ModuleType string

const (
	ModuleFinger  ModuleType = "finger"  // 指纹识别模块
	ModuleDirscan ModuleType = "dirscan" // 目录扫描模块
)

// ModuleStatus 模块状态
type ModuleStatus int

const (
	StatusStopped ModuleStatus = iota // 已停止
	StatusStarted                     // 已启动
	StatusError                       // 错误状态
)

