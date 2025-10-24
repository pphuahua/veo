# AdventureX 被动指纹识别模块

## 概述

这是一个完全独立的被动指纹识别模块，通过监听代理服务器的响应包，使用nuclei风格的DSL表达式来识别目标网站的技术栈。

## 特性

- ✅ **完全独立**: 不依赖collector、contents等其他模块
- ✅ **高性能**: 支持高并发处理，默认20个并发工作者
- ✅ **Nuclei DSL**: 使用nuclei风格的DSL表达式进行匹配
- ✅ **智能过滤**: 自动过滤图片、压缩包等静态文件
- ✅ **简化输出**: 输出目标URL和对应的技术栈信息
- ✅ **多协议支持**: 支持HTTP/HTTPS协议
- ✅ **多方法支持**: 支持GET、POST请求方法

## 架构设计

```
├── types.go          # 核心类型定义
├── dsl_parser.go     # DSL表达式解析器
├── engine.go         # 指纹识别引擎
├── addon.go          # Proxy插件实现
└── README.md         # 说明文档
```

### 核心组件

1. **Engine (引擎)**: 负责规则加载、匹配处理和结果管理
2. **DSLParser (解析器)**: 实现nuclei风格的DSL表达式解析
3. **FingerprintAddon (插件)**: 实现proxy.Addon接口，监听响应包
4. **过滤器**: 智能过滤静态文件和大型响应

## 支持的DSL函数

### 基础函数

- `contains(body, "text")` - 检查响应体是否包含指定文本
- `contains(header, "text")` - 检查响应头是否包含指定文本
- `contains(title, "text")` - 检查页面标题是否包含指定文本
- `contains(server, "text")` - 检查服务器头是否包含指定文本
- `contains(url, "text")` - 检查URL是否包含指定文本

### 多文本匹配（OR逻辑）

- `contains(body, "text1", "text2", "text3")` - 检查响应体是否包含任意一个指定文本（OR逻辑）
- `contains(header, "text1", "text2")` - 检查响应头是否包含任意一个指定文本
- `contains(title, "text1", "text2")` - 检查页面标题是否包含任意一个指定文本
- `contains(server, "text1", "text2")` - 检查服务器头是否包含任意一个指定文本
- `contains(url, "text1", "text2")` - 检查URL是否包含任意一个指定文本

### 高级函数

- `contains_all('text1', 'text2', 'text3')` - 检查响应体是否包含所有指定文本

### 正则表达式

- `regex(body, "pattern")` - 在响应体中匹配正则表达式
- `regex(header, "pattern")` - 在响应头中匹配正则表达式

### 状态码检查

- `status_code == 200` - 检查状态码等于指定值
- `status_code != 404` - 检查状态码不等于指定值
- `status_code >= 200` - 检查状态码大于等于指定值

### 图标检查

- `icon('/favicon.ico', 'md5hash')` - 检查图标的MD5哈希值

### 逻辑运算符

- `&&` - 逻辑与
- `||` - 逻辑或

### 条件控制

- `condition: and` - 所有DSL表达式都必须匹配
- `condition: or` - 任意一个DSL表达式匹配即可（默认）

## 使用方法

### 1. 程序启动

```bash
go run ./cmd/main.go
```

### 2. 选择指纹识别模式

```
请选择工作模式:
1. 目录扫描模式
2. 指纹识别模式  <- 选择这个
0. 退出程序
```

### 3. 配置代理

代理服务器默认监听 `:9080` 端口，将浏览器代理设置为：
- HTTP代理: `127.0.0.1:9080`
- HTTPS代理: `127.0.0.1:9080`

### 4. 查看识别结果

#### 实时输出
当有匹配的技术栈时，会实时输出：

```
INFO[time] [fingerprint] https://example.com -> Apache Tomcat
INFO[time] [fingerprint] https://example.com -> Spring Framework
```

#### 控制台菜单功能
选择指纹识别模式后，可以使用以下功能：

```
================================
指纹识别模式
[menu.go] 当前模式: 被动指纹识别
[menu.go] 工作状态: 监听代理流量
================================
1. 查看指纹识别结果     # 显示所有匹配的技术栈
2. 查看指纹识别统计     # 显示引擎统计信息
3. 清空指纹识别结果     # 清空历史匹配结果
4. 返回主菜单
0. 退出程序
```

**注意**: 在指纹识别模式下，URL收集功能会自动禁用，确保完全独立运行。

## 配置文件

### 规则文件位置

```
configs/fingerprint/converted_web_rules_fixed.yaml
```

### 规则文件格式

```yaml
# AND条件示例：所有规则都必须匹配
ngaf:
  condition: and
  dsl:
    - "contains(body, 'SANGFOR')"
    - "contains(header, 'NGAF')"
    - "contains_all('btncss', 'btnjs')"
    - "contains(body, 'login')"

# OR条件示例：任意一个规则匹配即可
apache-tomcat:
  condition: or
  dsl:
    - "contains(body, 'Apache Tomcat')"
    - "contains(header, 'Server: Apache-Coyote')"

# 默认OR条件（可省略condition字段）
spring-boot:
  dsl:
    - "contains(body, 'Whitelabel Error Page')"
    - "status_code == 404 && contains(body, 'Spring')"

# 多文本匹配示例（OR逻辑）
web-framework:
  dsl:
    - "contains(body, 'Laravel', 'Symfony', 'CodeIgniter')"  # 任意一个框架名称匹配即可
    - "contains(header, 'X-Powered-By', 'Server')"          # 任意一个头字段匹配即可
```

## 性能参数

### 默认配置

- 最大并发数: `20`
- 匹配超时: `5秒`
- 最大响应体: `1MB`
- 文件过滤: `启用`

### 过滤的文件类型

**图片文件**: `.jpg`, `.png`, `.gif`, `.ico`, `.svg` 等
**压缩文件**: `.zip`, `.rar`, `.7z`, `.tar.gz` 等
**文档文件**: `.pdf`, `.doc`, `.xls`, `.ppt` 等
**媒体文件**: `.mp3`, `.mp4`, `.avi` 等

## API接口

### 基础操作

```go
// 创建插件
addon, err := fingerprint.CreateDefaultAddon()

// 启用/禁用
addon.Enable()
addon.Disable()

// 获取结果
matches := addon.GetMatches()

// 获取统计
stats := addon.GetStats()

// 清空结果
addon.ClearMatches()
```

### 统计信息

```go
type Statistics struct {
    TotalRequests    int64     // 总请求数
    MatchedRequests  int64     // 匹配的请求数
    FilteredRequests int64     // 过滤的请求数
    RulesLoaded      int       // 加载的规则数
    StartTime        time.Time // 启动时间
    LastMatchTime    time.Time // 最后匹配时间
}
```

## 技术实现

### 高性能设计

1. **信号量控制**: 使用信号量控制并发数量
2. **原子操作**: 统计计数使用atomic包
3. **读写锁**: 规则和结果使用读写锁保护
4. **预过滤**: 静态文件在DSL解析前就被过滤

### 独立性设计

1. **独立数据结构**: 使用fingerprint.HTTPResponse而不是interfaces.HTTPResponse
2. **独立过滤器**: 内置文件类型过滤，不依赖外部filter模块
3. **独立配置**: 有自己的EngineConfig配置结构

## 错误处理

1. **规则加载失败**: 程序会继续运行但不进行指纹识别
2. **DSL解析错误**: 单个表达式错误不影响其他规则
3. **响应解析失败**: 跳过当前响应，不影响后续处理

## 日志输出

### 调试日志

```
[fingerprint.engine] 开始加载指纹规则: configs/fingerprint/...
[fingerprint.engine] 成功加载 2452 个指纹规则
[fingerprint.addon] 指纹识别插件初始化完成
```

### 匹配日志

```
[fingerprint] https://example.com -> Apache Tomcat
[fingerprint] https://example.com/login -> Spring Security
```

## 扩展指南

### 添加新的DSL函数

1. 在 `dsl_parser.go` 中的 `evaluateSingleFunction` 方法中添加新函数
2. 实现对应的 `evaluate[FunctionName]` 方法
3. 更新文档

### 添加新的过滤规则

1. 修改 `StaticFileExtensions` 或 `StaticContentTypes` 数组
2. 或在 `shouldFilterResponse` 方法中添加自定义逻辑

### 自定义配置

```go
config := &fingerprint.EngineConfig{
    RulesPath:       "custom/rules.yaml",
    MaxConcurrency:  50,
    EnableFiltering: true,
    LogMatches:      true,
}

addon, err := fingerprint.NewFingerprintAddon(config)
```

## 故障排除

### 规则文件找不到

确保规则文件路径正确：
```
configs/fingerprint/converted_web_rules_fixed.yaml
```

### 没有匹配结果

1. 检查是否启用了指纹识别模式
2. 确认代理配置正确
3. 查看日志中的过滤信息

### 性能问题

1. 减少并发数: 调整 `MaxConcurrency`
2. 减少响应体大小限制: 调整 `MaxBodySize`
3. 启用更严格的过滤: 设置 `EnableFiltering = true` 