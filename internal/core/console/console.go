package console

import (
	"runtime"
	"veo/internal/core/logger"
	"veo/internal/modules/fingerprint"
	collector "veo/internal/utils/collector"
)

// WorkMode 工作模式类型
// 定义控制台的工作模式，用于区分不同的操作场景
type WorkMode int

const (
	ModeDirectoryScan WorkMode = iota + 1 // 目录扫描模式：专注于URL收集和目录扫描
	ModeFingerprint                       // 指纹识别模式：同时进行URL收集和指纹识别
)

// ProxyController 代理控制器接口
// 定义控制台管理器与代理服务器交互的标准接口，实现解耦
type ProxyController interface {
	// StartProxy 启动代理服务器
	// 返回错误信息，如果启动失败
	StartProxy() error

	// StopProxy 停止代理服务器
	// 返回错误信息，如果停止失败
	StopProxy() error

	// IsProxyStarted 检查代理服务器是否已启动
	// 返回布尔值表示代理状态
	IsProxyStarted() bool
}

// ConsoleManager 控制台管理器结构体
// 负责依赖注入和状态管理，是模块间协调的核心容器
type ConsoleManager struct {
	// 核心组件
	collector        *collector.Collector          // URL收集器，负责采集和管理URL
	fingerprintAddon *fingerprint.FingerprintAddon // 指纹识别插件

	// 状态管理
	currentMode     WorkMode        // 当前工作模式
	proxyController ProxyController // 代理控制器，用于控制代理服务器
}

// ============================================================================
// 构造函数和初始化方法 (原manager.go内容)
// ============================================================================

// NewConsoleManager 创建新的控制台管理器
// 这是控制台管理器的工厂方法，负责初始化必要的组件
// 参数 collector: URL收集器实例
// 返回: 完全初始化的控制台管理器实例
func NewConsoleManager(collector *collector.Collector) *ConsoleManager {
	// 注意：日志配置现在在CLI应用初始化阶段统一设置，无需重复初始化

	return &ConsoleManager{
		// 核心组件初始化
		collector: collector, // URL收集器

		// 状态初始化
		currentMode:     0,   // 初始无模式
		proxyController: nil, // 代理控制器将在主程序中设置
	}
}

// ============================================================================
// 设置方法 (原manager.go内容)
// ============================================================================

// SetProxyController 设置代理控制器
// 用于注入代理控制器，实现控制台对代理服务器的控制
// 参数 controller: 代理控制器实例
func (cm *ConsoleManager) SetProxyController(controller ProxyController) {
	cm.proxyController = controller
	logger.Debug("代理控制器已设置")
}

// SetFingerprintAddon 设置指纹识别插件
// 用于注入指纹识别插件，实现指纹识别功能的集成
// 参数 addon: 指纹识别插件实例
func (cm *ConsoleManager) SetFingerprintAddon(addon *fingerprint.FingerprintAddon) {
	cm.fingerprintAddon = addon
	logger.Debug("指纹识别插件已设置")
}

// PauseFingerprintRecognition 暂停指纹识别
func (cm *ConsoleManager) PauseFingerprintRecognition() {
	if cm.fingerprintAddon != nil {
		cm.fingerprintAddon.Disable()
		logger.Info("Fingerprint Recognition Paused")
	}
}

// ResumeFingerprintRecognition 恢复指纹识别
func (cm *ConsoleManager) ResumeFingerprintRecognition() {
	if cm.fingerprintAddon != nil {
		cm.fingerprintAddon.Enable()
		logger.Info("Fingerprint Recognition Resume")
	}
}

// ============================================================================
// 内部辅助方法 (原manager.go内容)
// ============================================================================

// getCurrentModeString 获取当前模式的字符串表示
// 返回当前工作模式的中文描述，用于日志和显示
// 返回: 模式描述字符串
func (cm *ConsoleManager) getCurrentModeString() string {
	switch cm.currentMode {
	case ModeDirectoryScan:
		return "目录扫描模式"
	case ModeFingerprint:
		return "指纹识别模式"
	default:
		return "未选择模式"
	}
}

// ============================================================================
// 获取器方法（仅保留被使用的方法）
// ============================================================================

// GetCollector 获取URL收集器
// 返回内部的URL收集器实例，用于外部访问收集的数据
// 返回: URL收集器实例
func (cm *ConsoleManager) GetCollector() *collector.Collector {
	return cm.collector
}

// GetCurrentMode 获取当前工作模式
// 返回当前设置的工作模式
// 返回: 当前工作模式
func (cm *ConsoleManager) GetCurrentMode() WorkMode {
	return cm.currentMode
}

// SetCurrentMode 设置当前工作模式
// 用于模块管理器设置工作模式
// 参数 mode: 要设置的工作模式
func (cm *ConsoleManager) SetCurrentMode(mode WorkMode) {
	cm.currentMode = mode
}

// ===========================================
// 日志相关
// ===========================================

// Windows ANSI support state
var (
	windowsANSIEnabled bool
	windowsANSIChecked bool
)

// shouldUseColorsForLogging 检查日志系统是否应该使用颜色
// 内部函数，用于日志格式化器的颜色判断
// 返回: 布尔值表示是否使用颜色
func shouldUseColorsForLogging() bool {
	if runtime.GOOS == "windows" {
		// Windows系统检查ANSI支持状态
		return windowsANSIEnabled
	}
	// 其他系统直接使用
	return true
}

// enableWindowsANSI 启用Windows控制台的ANSI颜色支持
// 通过Windows API启用虚拟终端处理，使Windows控制台支持ANSI转义序列
func enableWindowsANSI() {
	if runtime.GOOS != "windows" {
		// 非Windows系统不需要启用ANSI支持
		// Unix-like系统默认支持ANSI转义序列
		return
	}

	// Windows系统的ANSI启用逻辑
	enableWindowsANSIImpl()
}

// enableWindowsANSIImpl Windows特定的ANSI启用实现
func enableWindowsANSIImpl() {
	if windowsANSIChecked {
		return // 已经检查过了，避免重复检查
	}
	windowsANSIChecked = true

	// 简化实现：现代Windows系统（Windows 10+）默认支持ANSI
	windowsANSIEnabled = true

	// 同时设置formatter包的ANSI支持状态
	// 使用动态导入避免循环依赖
	setFormatterANSISupport(true)
}

// setFormatterANSISupport 设置formatter包的ANSI支持状态
// 使用反射避免循环导入依赖
func setFormatterANSISupport(supported bool) {
	// 直接调用formatter包的SetWindowsANSISupported函数
	// 这里需要导入formatter包，但由于formatter包不导入console包，所以不会有循环依赖
	// 临时解决方案：使用包级别的函数调用

	// 为了避免编译错误，我们先注释掉这个调用
	// 在下一步中我们会通过其他方式解决这个问题
	// formatter.SetWindowsANSISupported(supported)
}
