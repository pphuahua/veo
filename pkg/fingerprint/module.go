package fingerprint

import (
	"veo/internal/core/logger"
	"veo/proxy"
)

// ModuleStatus 模块状态
type ModuleStatus int

const (
	ModuleStatusStopped ModuleStatus = iota // 已停止
	ModuleStatusStarted                     // 已启动
	ModuleStatusError                       // 错误状态
)

// FingerprintModule 指纹识别模块
type FingerprintModule struct {
	addon  *FingerprintAddon
	status ModuleStatus
}

// NewFingerprintModule 创建指纹识别模块
func NewFingerprintModule() (*FingerprintModule, error) {
	// 创建指纹识别插件
	addon, err := CreateDefaultAddon()
	if err != nil {
		logger.Errorf("创建失败: %v", err)
		return nil, err
	}

	module := &FingerprintModule{
		addon:  addon,
		status: ModuleStatusStopped,
	}

	logger.Debug("模块创建成功")
	return module, nil
}

// Start 启动模块
func (fm *FingerprintModule) Start() error {
	if fm.status == ModuleStatusStarted {
		logger.Debug("模块已经启动")
		return nil
	}

	// 设置全局实例
	SetGlobalAddon(fm.addon)

	fm.status = ModuleStatusStarted
	logger.Debug("模块启动成功")
	return nil
}

// SetHTTPClient 设置HTTP客户端（用于主动探测）
// 此方法由模块管理器调用，注入dirscan模块的HTTP客户端
func (fm *FingerprintModule) SetHTTPClient(client interface{}) {
	if fm.addon != nil {
		fm.addon.SetHTTPClient(client)
		logger.Debug("HTTP客户端已设置，支持主动探测功能")
	}
}

// Stop 停止模块
func (fm *FingerprintModule) Stop() error {
	if fm.status == ModuleStatusStopped {
		logger.Debug("模块已经停止")
		return nil
	}

	fm.status = ModuleStatusStopped
	logger.Debug("模块停止成功")
	return nil
}

// GetStatus 获取模块状态
func (fm *FingerprintModule) GetStatus() ModuleStatus {
	return fm.status
}

// GetAddons 获取模块的proxy addons
func (fm *FingerprintModule) GetAddons() []proxy.Addon {
	if fm.addon == nil {
		return []proxy.Addon{}
	}
	return []proxy.Addon{fm.addon}
}

// IsRequired 检查模块是否为必需模块
func (fm *FingerprintModule) IsRequired() bool {
	return false // 指纹识别是可选模块
}

// GetAddon 获取addon实例
func (fm *FingerprintModule) GetAddon() *FingerprintAddon {
	return fm.addon
}
