# AdventureX 目录扫描模块

## 概述

这是一个完全独立的目录扫描模块，通过监听代理服务器的请求包收集URL，然后生成字典扫描URL进行目录发现。

## 特性

- ✅ **完全独立**: 不依赖core/module包装器，可作为独立SDK使用
- ✅ **高性能**: 支持高并发扫描，可配置并发数量
- ✅ **智能收集**: 自动收集和过滤有效URL
- ✅ **字典生成**: 基于收集的URL智能生成扫描字典
- ✅ **响应过滤**: 智能过滤和分析扫描结果
- ✅ **报告生成**: 自动生成详细的扫描报告
- ✅ **用户交互**: 支持交互式扫描控制

## 架构设计

```
├── types.go          # 核心类型定义
├── engine.go         # 目录扫描引擎
├── addon.go          # Proxy插件实现
└── README.md         # 说明文档
```

### 核心组件

1. **Engine (引擎)**: 负责扫描流程控制、URL生成、请求处理和结果过滤
2. **DirscanAddon (插件)**: 实现proxy.Addon接口，提供统一的SDK接口
3. **Statistics (统计)**: 实时统计扫描进度和结果
4. **ScanResult (结果)**: 完整的扫描结果数据结构

## API接口

### 基础操作

```go
// 创建插件
addon, err := dirscan.CreateDefaultAddon()

// 启用/禁用
addon.Enable()
addon.Disable()

// 获取收集的URL
urls := addon.GetCollectedURLs()

// 触发扫描
result, err := addon.TriggerScan()

// 获取统计信息
stats := addon.GetStats()

// 清空结果
addon.ClearResults()
```

### 配置管理

```go
// 自定义配置
config := &dirscan.EngineConfig{
    MaxConcurrency:   50,
    RequestTimeout:   30 * time.Second,
    EnableCollection: true,
    EnableFiltering:  true,
    EnableReporting:  true,
}

addon, err := dirscan.NewDirscanAddon(config)
```

### 依赖注入

```go
// 设置控制台管理器
addon.SetConsoleManager(consoleManager)

// 获取collector（用于代理服务器集成）
collector := addon.GetCollector()

// 获取请求处理器（用于模块间依赖注入）
processor := addon.GetRequestProcessor()
```

## 使用方法

### 1. 基本使用

```go
package main

import (
    "adventurex/pkg/modules/dirscan"
    "adventurex/proxy"
)

func main() {
    // 创建目录扫描插件
    addon, err := dirscan.CreateDefaultAddon()
    if err != nil {
        panic(err)
    }

    // 创建代理服务器
    proxyServer := proxy.NewProxy(":8080")
    
    // 添加插件到代理服务器
    proxyServer.AddAddon(addon)
    
    // 启动输入监听器
    addon.StartInputListener()
    
    // 启动代理服务器
    proxyServer.Start()
}
```

### 2. 与模块管理器集成

```go
// 在core/module包装器中使用
func NewDirscanModule(consoleManager *console.ConsoleManager) (*DirscanModule, error) {
    // 使用dirscan模块的SDK接口
    addon, err := dirscan.CreateDefaultAddon()
    if err != nil {
        return nil, err
    }
    
    // 设置控制台管理器
    addon.SetConsoleManager(consoleManager)
    
    return &DirscanModule{
        addon:  addon,
        status: StatusStopped,
    }, nil
}
```

### 3. 扫描流程

```
1. URL收集阶段
   ├── 监听代理请求
   ├── 过滤静态资源
   ├── 收集有效URL
   └── 实时统计

2. 扫描触发阶段
   ├── 用户按回车触发
   ├── 生成扫描字典
   ├── 执行HTTP请求
   └── 应用响应过滤

3. 结果处理阶段
   ├── 过滤和分析结果
   ├── 生成扫描报告
   ├── 显示统计信息
   └── 等待用户确认
```

## 数据结构

### ScanResult 扫描结果

```go
type ScanResult struct {
    Target        string                     // 扫描目标
    CollectedURLs []string                   // 收集的URL
    ScanURLs      []string                   // 生成的扫描URL
    Responses     []*interfaces.HTTPResponse // HTTP响应
    FilterResult  *interfaces.FilterResult  // 过滤结果
    ReportPath    string                     // 报告路径
    StartTime     time.Time                  // 开始时间
    EndTime       time.Time                  // 结束时间
    Duration      time.Duration              // 扫描耗时
}
```

### Statistics 统计信息

```go
type Statistics struct {
    TotalCollected   int64     // 总收集URL数
    TotalGenerated   int64     // 总生成URL数
    TotalRequests    int64     // 总请求数
    SuccessRequests  int64     // 成功请求数
    FailedRequests   int64     // 失败请求数
    FilteredResults  int64     // 过滤后结果数
    ValidResults     int64     // 有效结果数
    StartTime        time.Time // 启动时间
    LastScanTime     time.Time // 最后扫描时间
    TotalScans       int64     // 总扫描次数
}
```

## 配置选项

### EngineConfig 引擎配置

```go
type EngineConfig struct {
    MaxConcurrency    int           // 最大并发数 (默认: 20)
    RequestTimeout    time.Duration // 请求超时时间 (默认: 30s)
    EnableCollection  bool          // 是否启用URL收集 (默认: true)
    EnableFiltering   bool          // 是否启用响应过滤 (默认: true)
    EnableReporting   bool          // 是否启用报告生成 (默认: true)
    DictionaryPath    string        // 字典文件路径 (默认: "dict/")
    OutputFormat      string        // 输出格式 (默认: "json")
    LogLevel          string        // 日志级别 (默认: "info")
}
```

## 与fingerprint模块的一致性

### 相同的SDK架构模式

```go
// fingerprint模块
addon, err := fingerprint.CreateDefaultAddon()
addon.Enable()
addon.Disable()
matches := addon.GetMatches()
stats := addon.GetStats()

// dirscan模块
addon, err := dirscan.CreateDefaultAddon()
addon.Enable()
addon.Disable()
urls := addon.GetCollectedURLs()
stats := addon.GetStats()
```

### 相同的接口设计原则

1. **统一的创建方式**: `CreateDefaultAddon()`
2. **标准的控制接口**: `Enable()`, `Disable()`
3. **一致的数据获取**: `GetStats()`, `GetXXX()`
4. **统一的清理接口**: `ClearResults()`

## 技术实现

### 高性能设计

1. **并发控制**: 可配置的并发数量控制
2. **内存优化**: 及时清理和复用数据结构
3. **异步处理**: 非阻塞的用户交互和扫描流程

### 独立性设计

1. **独立数据结构**: 使用dirscan.ScanResult而不是依赖外部接口
2. **独立配置**: 有自己的EngineConfig配置结构
3. **独立接口**: 完整的SDK接口，可独立使用

## 错误处理

1. **配置错误**: 使用默认配置继续运行
2. **网络错误**: 重试机制和错误统计
3. **文件错误**: 优雅降级，不影响核心功能

## 扩展指南

### 添加新的扫描策略

1. 在 `engine.go` 中扩展 `PerformScan` 方法
2. 添加新的配置选项到 `EngineConfig`
3. 更新统计信息结构

### 自定义过滤器

1. 实现自定义的过滤器接口
2. 在 `engine.go` 中集成新的过滤器
3. 更新配置以支持过滤器选择

## 故障排除

### 常见问题

1. **没有收集到URL**: 检查代理配置和主机白名单
2. **扫描无结果**: 检查字典文件和网络连接
3. **报告生成失败**: 检查文件权限和磁盘空间

### 调试模式

```go
config := &dirscan.EngineConfig{
    LogLevel: "debug",
    // ... 其他配置
}
```
