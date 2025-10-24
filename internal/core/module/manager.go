package module

import (
	"veo/proxy"
)

// Module 模块接口
type Module interface {
	// GetName 获取模块名称
	GetName() ModuleType

	// Start 启动模块
	Start() error

	// Stop 停止模块
	Stop() error

	// GetStatus 获取模块状态
	GetStatus() ModuleStatus

	// GetAddons 获取模块的proxy addons
	GetAddons() []proxy.Addon

	// IsRequired 检查模块是否为必需模块（如collector在dirscan中是必需的）
	IsRequired() bool
}
