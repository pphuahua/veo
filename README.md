# VEO 主动扫描工具与 SDK 指南

VEO 是一款面向安全测试与攻防演练的主动扫描框架，专注于目录探测、指纹识别和敏感信息发现。项目提供：

- **CLI 工具**：一键执行目录扫描、指纹识别、代理联动等任务。
- **Go SDK (`veo/pkg/sdk/scan`)**：在程序中嵌入完整的扫描流水线，获得与 CLI 完全一致的结果。

本文档介绍核心参数、配置文件、最佳实践以及 SDK 用法，帮助你快速落地 VEO 的能力。

---
## 1. CLI 快速上手

```bash
# 目录扫描 + 指纹识别（默认配置）
./veo -u http://target.com

# 使用自定义字典、输出 JSON 报告
./veo -u http://target.com -w dict/custom.txt --json-report report.json

# 仅指纹识别
./veo --finger -u http://target.com
```

### 常用参数

| 参数 | 说明 | 示例 |
|------|------|------|
| `-u` | 目标 URL 或逗号分隔列表 | `-u http://a.com,http://b.com` |
| `-w` | 自定义目录字典 | `-w dict/custom.txt` |
| `--stats` | 实时输出进度统计 | `--stats` |
| `--debug` | 打开调试日志 | `--debug` |
| `--finger` | 仅执行指纹识别 | `--finger -u http://target.com` |
| `--json-report` | 导出 JSON 报告 | `--json-report report.json` |

> 完整参数请查看 `./veo --help`。

---
## 2. 配置文件说明

默认配置位于 `configs/config.yaml`，主要分为以下模块：

### 2.1 服务器与主机过滤
```yaml
server:
  listen: ":9080"

hosts:
  allow:
    - "*"
  reject:
    - "*.baidu.com"
    - "*.google.*"
```
- `allow` / `reject` 控制可访问的目标域，支持通配符。

### 2.2 目录扫描相关配置
```yaml
addon:
  collector:
    GenerationStatusCodes: [200, 403, 401, 500, 405]
    static:
      path: ["/css/", "/js/"]
      extensions: [".css", ".js", ".png", ...]
```
- `GenerationStatusCodes`：被动收集时保留的状态码。
- `static.path` / `static.extensions`：过滤静态资源，减少噪声。

### 2.3 过滤与哈希阈值
```yaml
addon:
  filter:
    enable: true
    ValidStatusCodes: [200, 401, 403, 405, 302, 301, 500]
    filter_tolerance: 50
```
- `filter_tolerance`：相似页面容错字节数（默认 50 字节）。
- 支持开启/关闭主要哈希、二次哈希过滤。

### 2.4 请求配置
```yaml
addon:
  request:
    timeout: 5
    retry: 2
    threads: 200
    max_response_body_size: 1048576
```
- `timeout`：单请求超时时间（秒）。
- `threads`：最大并发数。
- `max_response_body_size`：响应体截断大小（防止内存占用过大）。

---
## 3. 过滤细节回顾

1. **状态码过滤**：默认白名单 `200/301/302/401/403/405/500`，可覆写。
2. **静态资源过滤**：根据 Content-Type / 扩展名排除图片、视频等页面。
3. **主要哈希过滤**：剔除重复或异常页面，默认阈值 3。
4. **二次哈希过滤**：对相似页面进行去重，默认阈值 1。
5. **相似页面容错**：默认 50 字节，可通过配置文件或 SDK 参数调整。
6. **认证头探测**：对 401/403 响应自动提取认证信息，帮助定位登录入口。
7. **指纹识别**：解压 gzip/deflate/brotli，自动识别编码，执行 DSL 规则，输出 `<rule_name>` 与 `<rule_content>`。

---
## 4. SDK 使用

### 4.1 安装依赖
确保 `go.mod` 中引用本仓库：
```bash
go get github.com/your-org/veo/pkg/sdk/scan
```

### 4.2 代码示例
```go
package main

import (
    "fmt"
    "log"
    "time"

    "veo/pkg/sdk/scan"
)

func main() {
    dirCfg := scan.DefaultDirscanConfig()
    dirCfg.MaxConcurrency = 150
    dirCfg.RequestTimeout = 8 * time.Second
    dirCfg.EnableReporting = false
    dirCfg.Filter = &scan.DirscanFilterOptions{
        ValidStatusCodes:     []int{200, 301, 302, 401, 403, 405, 500},
        InvalidPageThreshold: scan.Int(3),
        SecondaryThreshold:   scan.Int(1),
        FilterTolerance:      scan.Int64(50),
    }

    fpCfg := scan.DefaultFingerprintConfig()
    fpCfg.MaxConcurrency = 150
    fpCfg.MaxBodySize = 2 * 1024 * 1024
    fpCfg.LogLevel = "debug"

    autoSkip := true

    cfg := &scan.Config{
        DirTargets:         []string{"http://221.214.214.36/"},
        FingerprintTargets: []string{"http://221.214.214.36/"},
        SkipTLSVerify:      false,
        AutoSkipTLSForIP:   &autoSkip,
        HTTPTimeout:        20 * time.Second,
        Dirscan:            dirCfg,
        Fingerprint:        fpCfg,
    }

    resultJSON, err := scan.RunJSON(cfg)
    if err != nil {
        log.Fatalf("扫描失败: %v", err)
    }

    fmt.Println(string(resultJSON))
}
```

### 4.3 常见字段

| 字段 | 说明 |
|------|------|
| `DirTargets` / `FingerprintTargets` | 目录扫描和额外指纹识别 URL 列表 |
| `SkipTLSVerify` / `AutoSkipTLSForIP` | TLS 校验策略，裸 IP 默认自动跳过 |
| `HTTPTimeout` | `RequestProcessor` 的请求超时 |
| `Dirscan.Filter` | 状态码、哈希阈值、容错等过滤参数 |
| `Fingerprint.Filters` | 静态资源过滤选项 |

辅助函数 `scan.Bool` / `scan.Int` / `scan.Int64` 用于快速传入指针参数。

---
## 5. 最佳实践

1. **资产盘点联动**：将实时资产清单导入 `DirTargets`，即可批量探测新增路径或泄露接口。
2. **敏感信息识别**：通过添加 DSL，如 `<contains(body, 'ACCESSKEY')>`，快速定位潜在 Key 泄漏。
3. **同源多目标扫描**：将认证成功后的 Cookie 通过 CLI/SDK 注入，探索管理员后台、调试接口等敏感路径。
4. **报告联动**：JSON 结果中包含细粒度的 `fingerprints` 与 `summary`，便于接入后续风控/告警平台。
5. **定制字典**：结合业务常见目录（`/upload/`, `/auth/`, `/api/v1/`），提升扫描命中率。

---
## 6. 常见问题

| 问题 | 可能原因 |
|------|----------|
| 指纹结果少 | 静态资源过滤过严，或响应被压缩/编码转换失败（检查 ResponseBody&Content-Encoding） |
| 目录结果为空 | 目标全部被过滤；调高 `FilterTolerance` 或修改状态码白名单 |
| TLS 报错 | 裸 IP 且未启用 `AutoSkipTLSForIP`；手动设置 `SkipTLSVerify=true` |
| 401/403 忽略认证提示 | 确保未覆盖默认的 `RequestProcessor`，或手动传入自定义头后启用认证探测 |

---
## 7. 结语

得益于与 CLI 完全一致的实现，VEO SDK 可以保证目录扫描与指纹识别结果高度可靠。无论是构建自动化安全扫描平台，还是在红队工具链中集成，都可以快速落地并保持一致性。

欢迎提交 Issue/PR，一起共建更完善的扫描能力！
