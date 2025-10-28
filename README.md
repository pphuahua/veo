# VEO 主被动扫描工具
VEO 是一款专注于目录探测、指纹识别和敏感信息发现。**欢迎使用任何同类型工具进行准确性和误报对比**。

---
![https://youke1.picui.cn/s1/2025/10/24/68fb5aa3b09a6.jpg](https://youke1.picui.cn/s1/2025/10/24/68fb5aa3b09a6.jpg)

## 更新日志 

- 2025/10/28

  ```
  1、修改字典加载模式，默认只加载common.txt字典，剩余字典需用户-w指定。支持多文件选择，例如-w dict/common.txt,dict/xxx.txt
  2、新增-vv参数，对指纹识别/敏感信息识别内容提取高亮，方便查看匹配的具体特征上下文。
  3、精简配置config.yaml配置文件，修改为命令行接收配置参数。
  4、新增优化指纹信息和目录字典。
  5、优化404探测指纹显示方式，统一进行指纹显示的合并。
  6、新增execl报告输出。
  7、新增-nc参数：取消控制台颜色输出，防止windows系统下乱码的情况。
  8、新增--json参数：控制台输出结果变为纯json结果输出，方便其他工具接收输出作为第三方工具的输入。
  ```

  



## 1. 快速上手

被动扫描时，首次使用请解压ca-cert.zip安装证书。

```bash
# 目录扫描 + 指纹识别（默认配置，使用内置字典）
./veo -u http://target.com

# 使用自定义字典、输出 JSON 报告
./veo -u http://target.com -w dict/custom.txt --output report.json

# 使用自定义字典、输出 HTML 报告
./veo -u http://target.com -w dict/custom.txt --output report.html

# 仅指纹识别
./veo -m finger -u http://target.com

# 仅目录扫描
./veo -m dirscan -u http://target.com

# 被动扫描（默认监听端口9080）
./veo -u http://target.com --listen
```

### 详细参数

| 参数 | 说明 | 示例 |
|------|------|------|
| `-u` | 目标 URL 或逗号分隔列表 | `-u http://a.com,http://b.com` |
| `-w` | 自定义目录字典 | `-w dict/custom.txt` |
| `--stats` | 实时输出进度统计 | `--stats` |
| `--debug` | 打开调试日志 | `--debug` |
| `--json-report` | 导出 HTML 报告          | `--output report.html`         |

> 完整参数请查看 `./veo -h

---
## 2. 配置文件说明

默认配置位于 `configs/config.yaml`，主要分为以下模块：

### 2.1 服务器与主机过滤
```yaml
server:
  listen: ":9080" # 被动扫描时，监听的端口

hosts:
  allow:  # 被动扫描时默认允许的主机
    - "*"
  reject: # 被动扫描时默认拒绝的主机
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
- `GenerationStatusCodes` ：被动扫描时，仅采集符合状态码的URL
- `path`：过滤静态目录
- `extensions`：过滤静态文件

```yaml
addon:
  filter:
    enable: true
    ValidStatusCodes: [200, 401, 403, 405, 302, 301, 500]
    filter_tolerance: 50
```
- `ValidStatusCodes`：目录扫描过滤的状态码
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
- `retry`：重试次数
- `threads`：最大并发数。
- `max_response_body_size`：响应体限制大小（防止内存占用过大）。

---
## 3. 目录扫描无效页面过滤逻辑

1. **状态码过滤**：默认白名单 `200/301/302/401/403/405/500`，可覆写。
2. **静态资源过滤**：根据 Content-Type / 扩展名排除图片、视频等页面。
3. **主要哈希过滤**：剔除重复或异常页面，默认阈值 3。
4. **二次哈希过滤**：对相似页面进行去重，默认阈值 1。
5. **相似页面容错**：默认 50 字节，可通过配置文件或 SDK 参数调整。
6. **认证头探测**：对 401/403 响应自动提取认证信息，携带认证扫描，出货率更高。
7. **指纹识别**：解压 gzip/deflate/brotli，自动识别编码，执行 DSL 规则，输出 `<rule_name>` 与 `<rule_content>`。

---

## 4. 指纹库编写规则和仓库
https://github.com/Nuclei-Template-Hub/VEO-Fingerprint
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
        DirTargets:         []string{"http://x.x.x.x/"},
        FingerprintTargets: []string{"http://x.x.x.x/"},
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
## 7. 结语

欢迎提交 Issue/PR。
