# AdventureX Console 控制台包

## 概述

Console包提供了AdventureX的控制台管理功能，支持交互式操作和状态管理。

## 架构组成

### 核心组件

- **`types.go`** - 类型定义、接口和控制台管理器核心功能
- **`filtering.go`** - 响应过滤和结果处理
- **`utils.go`** - 工具方法和辅助函数
- **`logging.go`** - 日志配置和格式化

> **注意**: 扫描相关功能已迁移到 `addon/module/dirscan_module.go` 中，实现了更清晰的模块化架构。

### 支持组件

- **`fingerprint.go`** - 指纹识别控制台
- **`url_management.go`** - URL管理功能

## 控制台管理器

### 核心功能

```go
type ConsoleManager struct {
    collector       *collector.Collector      // URL收集器
    contentManager  *requests.ContentManager  // 内容管理器
    processor       *requests.RequestProcessor // 请求处理器
    filter          *filter.ResponseFilter    // 响应过滤器
    depthScanner    *requests.DepthScanner    // 深度扫描器
    currentMode     WorkMode                  // 当前工作模式
}
```

### 工作模式

- **目录扫描模式** - 处理URL收集和目录扫描
- **指纹识别模式** - 处理被动指纹识别
- **混合模式** - 同时支持多种功能

## 数据流

```
URL采集 → 内容生成 → HTTP请求 → 响应过滤 → 结果展示
```

**现在的流程**：
collector.go (URL采集) → dirscan_module.go (扫描处理) → filtering.go (结果过滤)

## 状态管理

控制台管理器维护以下状态：

- 收集器状态 (启用/禁用)
- 当前工作模式
- 代理控制器连接状态
- 指纹识别插件状态

## 文件说明

| 文件 | 行数 | 功能描述 | 重要性 |
|------|------|----------|--------|
| `types.go` | 148 | 类型定义和核心管理器 | 高 |
| `filtering.go` | 80 | 结果过滤（简化版） | 中 |
| `utils.go` | 132 | 工具方法（优化版） | 中 |
| `logging.go` | 140 | 日志管理（精简版） | 中 |

## 使用示例

### 创建控制台管理器

```go
collector := collector.NewCollector()
manager := console.NewConsoleManager(collector)
```

### 设置代理控制器

```go
manager.SetProxyController(proxyController)
```

### 设置指纹识别插件

```go
manager.SetFingerprintAddon(fingerprintAddon)
```

## 扩展性

控制台系统支持：

- 插件式架构
- 动态模式切换
- 自定义过滤器
- 扩展工作模式

## 注意事项

1. **线程安全** - 所有核心操作都是线程安全的
2. **资源管理** - 自动管理HTTP连接和内存使用
3. **错误处理** - 完善的错误处理和恢复机制
4. **性能优化** - 并发处理和内存池优化

## 迁移说明

原有的 `scanning.go` 功能已完全迁移到 `addon/module/dirscan_module.go`：

- **普通目录扫描** - 按回车键触发
- **递归目录扫描** - 输入 'depth' 触发
- **扫描状态管理** - 集成到模块状态管理中
- **结果显示** - 统一的输出格式 