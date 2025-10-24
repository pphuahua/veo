package logger

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

// ===========================================
// veo日志系统 - gologger兼容层
// ===========================================

// AdventureFormatter veo自定义日志格式化器
// 由于gologger的API限制，我们使用一个简化的方法来实现自定义格式
// 通过重写日志输出方法来实现veo原有的简洁格式
type AdventureFormatter struct {
	EnableColors bool
}

// LogConfig 日志配置结构
type LogConfig struct {
	Level       string `yaml:"level"`        // 日志级别
	ColorOutput bool   `yaml:"color_output"` // 彩色输出
}

// AdventureLogger veo日志封装器
// 提供与logrus兼容的API，底层使用gologger实现
type AdventureLogger struct {
	config       *LogConfig
	currentLevel levels.Level // 添加当前级别跟踪
}

// 全局日志实例
var globalLogger *AdventureLogger

// ===========================================
// 初始化和配置
// ===========================================

// InitializeLogger 初始化日志系统
func InitializeLogger(config *LogConfig) error {
	if config == nil {
		config = getDefaultLogConfig()
	}

	// 配置gologger
	if err := configureGologger(config); err != nil {
		return fmt.Errorf("配置gologger失败: %v", err)
	}

	// 创建全局日志实例
	globalLogger = &AdventureLogger{
		config:       config,
		currentLevel: parseLogLevel(config.Level),
	}

	return nil
}

// configureGologger 配置gologger
func configureGologger(config *LogConfig) error {
	// 设置日志级别
	level := parseLogLevel(config.Level)
	gologger.DefaultLogger.SetMaxLevel(level)

	// 配置彩色输出
	if config.ColorOutput && shouldUseColors() {
		// gologger默认支持彩色输出，但我们需要自定义格式
		// 通过环境变量禁用gologger的默认格式，我们将在日志方法中实现自定义格式
		os.Setenv("GOLOGGER_TIMESTAMP", "false")
	} else {
		// 禁用彩色输出
		os.Setenv("NO_COLOR", "1")
		os.Setenv("GOLOGGER_TIMESTAMP", "false")
	}

	return nil
}

// parseLogLevel 解析日志级别
func parseLogLevel(levelStr string) levels.Level {
	switch strings.ToLower(levelStr) {
	case "debug":
		return levels.LevelDebug
	case "info":
		return levels.LevelInfo
	case "warn", "warning":
		return levels.LevelWarning
	case "error":
		return levels.LevelError
	case "fatal":
		return levels.LevelFatal
	case "panic":
		return levels.LevelFatal // gologger没有panic级别，使用fatal
	default:
		return levels.LevelInfo
	}
}

// shouldUseColors 检查是否应该使用颜色
func shouldUseColors() bool {
	if runtime.GOOS == "windows" {
		// Windows 10+默认支持ANSI颜色
		return true
	}
	return true
}

// getDefaultLogConfig 获取默认日志配置
func getDefaultLogConfig() *LogConfig {
	return &LogConfig{
		Level:       "info",
		ColorOutput: true,
	}
}

// ===========================================
// logrus兼容API - 基础日志方法
// ===========================================

// Info 信息级别日志
func (l *AdventureLogger) Info(args ...interface{}) {
	l.printWithFormat(levels.LevelInfo, fmt.Sprint(args...))
}

// Infof 格式化信息级别日志
func (l *AdventureLogger) Infof(format string, args ...interface{}) {
	l.printWithFormat(levels.LevelInfo, fmt.Sprintf(format, args...))
}

// Debug 调试级别日志
func (l *AdventureLogger) Debug(args ...interface{}) {
	l.printWithFormat(levels.LevelDebug, fmt.Sprint(args...))
}

// Debugf 格式化调试级别日志
func (l *AdventureLogger) Debugf(format string, args ...interface{}) {
	l.printWithFormat(levels.LevelDebug, fmt.Sprintf(format, args...))
}

// Error 错误级别日志
func (l *AdventureLogger) Error(args ...interface{}) {
	l.printWithFormat(levels.LevelError, fmt.Sprint(args...))
}

// Errorf 格式化错误级别日志
func (l *AdventureLogger) Errorf(format string, args ...interface{}) {
	l.printWithFormat(levels.LevelError, fmt.Sprintf(format, args...))
}

// Warn 警告级别日志
func (l *AdventureLogger) Warn(args ...interface{}) {
	l.printWithFormat(levels.LevelWarning, fmt.Sprint(args...))
}

// Warnf 格式化警告级别日志
func (l *AdventureLogger) Warnf(format string, args ...interface{}) {
	l.printWithFormat(levels.LevelWarning, fmt.Sprintf(format, args...))
}

// Fatal 致命错误日志
func (l *AdventureLogger) Fatal(args ...interface{}) {
	l.printWithFormat(levels.LevelFatal, fmt.Sprint(args...))
	os.Exit(1)
}

// Fatalf 格式化致命错误日志
func (l *AdventureLogger) Fatalf(format string, args ...interface{}) {
	l.printWithFormat(levels.LevelFatal, fmt.Sprintf(format, args...))
	os.Exit(1)
}

// printWithFormat 使用veo自定义格式打印日志
func (l *AdventureLogger) printWithFormat(level levels.Level, message string) {
	// 关键修复：添加级别检查，确保级别过滤正常工作
	if level > l.currentLevel {
		return // 不输出超过当前最大级别的日志
	}

	var levelColor, resetColor string

	// 检查是否应该使用颜色
	enableColors := l.config.ColorOutput && shouldUseColors()

	if enableColors {
		// 定义颜色代码，修改INF级别为蓝色
		switch level {
		case levels.LevelDebug:
			levelColor = "\033[36m" // 青色
		case levels.LevelInfo:
			levelColor = "\033[34m" // 蓝色 (修改：原来是绿色)
		case levels.LevelWarning:
			levelColor = "\033[33m" // 黄色
		case levels.LevelError:
			levelColor = "\033[31m" // 红色
		case levels.LevelFatal:
			levelColor = "\033[35m" // 紫色
		default:
			levelColor = ""
		}
		resetColor = "\033[0m"
	}

	// 获取简短的级别名称，与原有格式保持一致
	var levelText string
	switch level {
	case levels.LevelDebug:
		levelText = "DBG"
	case levels.LevelInfo:
		levelText = "INF"
	case levels.LevelWarning:
		levelText = "WRN"
	case levels.LevelError:
		levelText = "ERR"
	case levels.LevelFatal:
		levelText = "FTL"
	default:
		levelText = "INF"
	}

	// 格式化输出：[LEVEL] message (与原有CustomFormatter格式一致)
	var output string
	if enableColors {
		output = fmt.Sprintf("%s[%s]%s %s", levelColor, levelText, resetColor, message)
	} else {
		output = fmt.Sprintf("[%s] %s", levelText, message)
	}

	// 直接输出到标准输出/错误
	if level >= levels.LevelError {
		fmt.Fprintln(os.Stderr, output)
	} else {
		fmt.Println(output)
	}
}

// ===========================================
// 全局日志函数 - 兼容logrus的全局调用方式
// ===========================================

// Info 全局信息日志
func Info(args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Info(args...)
	} else {
		// 使用默认配置创建临时logger
		defaultLogger := &AdventureLogger{config: getDefaultLogConfig()}
		defaultLogger.Info(args...)
	}
}

// Infof 全局格式化信息日志
func Infof(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Infof(format, args...)
	} else {
		defaultLogger := &AdventureLogger{config: getDefaultLogConfig()}
		defaultLogger.Infof(format, args...)
	}
}

// Debug 全局调试日志
func Debug(args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Debug(args...)
	} else {
		defaultLogger := &AdventureLogger{config: getDefaultLogConfig()}
		defaultLogger.Debug(args...)
	}
}

// Debugf 全局格式化调试日志
func Debugf(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Debugf(format, args...)
	} else {
		defaultLogger := &AdventureLogger{config: getDefaultLogConfig()}
		defaultLogger.Debugf(format, args...)
	}
}

// Error 全局错误日志
func Error(args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Error(args...)
	} else {
		defaultLogger := &AdventureLogger{config: getDefaultLogConfig()}
		defaultLogger.Error(args...)
	}
}

// Errorf 全局格式化错误日志
func Errorf(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Errorf(format, args...)
	} else {
		defaultLogger := &AdventureLogger{config: getDefaultLogConfig()}
		defaultLogger.Errorf(format, args...)
	}
}

// Warn 全局警告日志
func Warn(args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Warn(args...)
	} else {
		defaultLogger := &AdventureLogger{config: getDefaultLogConfig()}
		defaultLogger.Warn(args...)
	}
}

// Warnf 全局格式化警告日志
func Warnf(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Warnf(format, args...)
	} else {
		defaultLogger := &AdventureLogger{config: getDefaultLogConfig()}
		defaultLogger.Warnf(format, args...)
	}
}

// Fatal 全局致命错误日志
func Fatal(args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Fatal(args...)
	} else {
		defaultLogger := &AdventureLogger{config: getDefaultLogConfig()}
		defaultLogger.Fatal(args...)
	}
}

// Fatalf 全局格式化致命错误日志
func Fatalf(format string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Fatalf(format, args...)
	} else {
		defaultLogger := &AdventureLogger{config: getDefaultLogConfig()}
		defaultLogger.Fatalf(format, args...)
	}
}

// ===========================================
// 工具函数
// ===========================================

// GetGlobalLogger 获取全局日志实例
func GetGlobalLogger() *AdventureLogger {
	return globalLogger
}

// SetLogLevel 设置日志级别
func SetLogLevel(levelStr string) {
	level := parseLogLevel(levelStr)
	gologger.DefaultLogger.SetMaxLevel(level)

	// 同时更新全局logger的当前级别
	if globalLogger != nil {
		globalLogger.currentLevel = level
	}
}

// IsDebugEnabled 检查是否启用调试日志
func IsDebugEnabled() bool {
	// gologger没有直接的GetMaxLevel方法，我们通过尝试输出来检测
	return true // 简化实现，总是返回true
}

// ===========================================
// 兼容性函数 - 支持现有代码的平滑迁移
// ===========================================

// InitializeLogging 兼容原有的初始化函数名
func InitializeLogging(config *LogConfig) error {
	return InitializeLogger(config)
}
