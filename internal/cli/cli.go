package cli

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"veo/internal/core/config"
	"veo/internal/core/console"
	"veo/internal/core/logger"
	modulepkg "veo/internal/core/module"
	"veo/internal/modules/authlearning"
	"veo/internal/modules/dirscan"
	"veo/internal/modules/fingerprint"
	"veo/internal/utils/collector"
	"veo/internal/utils/dictionary"
	"veo/internal/utils/filter"
	"veo/internal/utils/formatter"
	"veo/internal/utils/httpclient"
	"veo/proxy"

	// "os/exec" // removed: masscan执行迁移至模块
	portscanpkg "veo/internal/modules/portscan"
	masscanrunner "veo/internal/modules/portscan/masscan"
	report "veo/internal/modules/reporter"
	// neturl "net/url" // not used after logic change
)

// arrayFlags 实现flag.Value接口，支持多个相同参数
type arrayFlags []string

func (af *arrayFlags) String() string {
	return strings.Join(*af, ", ")
}

func (af *arrayFlags) Set(value string) error {
	*af = append(*af, value)
	return nil
}

// CLIArgs CLI参数结构体
type CLIArgs struct {
	Targets    []string // 目标主机/URL (-u)
	TargetFile string   // 新增：目标文件路径 (-f)
	Modules    []string // 启用的模块 (-m)
	Port       int      // 监听端口 (-lp)
	// 端口扫描（masscan）相关
	Ports    string // 扫描端口表达式 (-p 例如: 80,443,8000-8100 或 1-65535)
	Rate     int    // 扫描速率 (--rate，包/秒)
	Wordlist string // 自定义字典路径 (-w)
	Listen   bool   // 被动代理模式 (--listen)
	Debug    bool   // 调试模式 (--debug)

	// 新增：线程并发控制和全局配置参数
	Threads int // 统一线程并发数量 (-t, --threads)
	Retry   int // 重试次数 (--retry)
	Timeout int // 全局超时时间 (--timeout)

	// 新增：报告输出控制参数
	Output string // 报告文件输出路径 (-o, --output)

	// 新增：实时统计显示参数
	Stats bool // 启用实时扫描进度统计显示 (--stats)

	// 输出控制
	NoColor    bool // 禁用彩色输出 (-nc)
	JSONOutput bool // 控制台输出JSON结果 (--json)

	// 指纹细节输出开关
	VeryVerbose  bool // 指纹匹配内容展示开关 (-vv)
	NoAliveCheck bool // 跳过存活检测 (-na)

	// 新增：HTTP认证头部参数
	Headers []string // 自定义HTTP认证头部 (--header "Header-Name: Header-Value")

	// 新增：状态码过滤参数
	StatusCodes string // 自定义过滤HTTP状态码 (-s "200,301,302")

	// 新增：相似页面过滤容错阈值参数
	FilterTolerance int // 相似页面过滤容错阈值 (--filter-tolerance)
}

// ValidModules 有效的模块列表（使用module包的类型定义）
var ValidModules = []string{string(modulepkg.ModuleFinger), string(modulepkg.ModuleDirscan), "port"}

// CLIApp CLI应用程序
type CLIApp struct {
	proxy             *proxy.Proxy
	collector         *collector.Collector
	consoleManager    *console.ConsoleManager
	dirscanModule     *dirscan.DirscanModule
	fingerprintAddon  *fingerprint.FingerprintAddon
	authLearningAddon *authlearning.AuthLearningAddon
	proxyStarted      bool
	args              *CLIArgs
}

var app *CLIApp

// Execute 执行CLI命令
func Execute() {
	// 优先初始化配置系统
	if err := config.InitConfig(); err != nil {
		// 如果配置加载失败，使用默认配置
		fmt.Printf("配置文件加载失败，使用默认配置: %v\n", err)
	}

	// 初始化日志系统
	loggerConfig := &logger.LogConfig{
		Level:       "info",
		ColorOutput: true,
	}
	if err := logger.InitializeLogger(loggerConfig); err != nil {
		// 如果初始化失败，使用默认配置
		logger.InitializeLogger(nil)
	}
	logger.Debug("日志系统初始化完成")

	// 初始化formatter包的Windows ANSI支持
	// Windows 10+默认支持ANSI颜色
	if runtime.GOOS == "windows" {
		formatter.SetWindowsANSISupported(true)
		logger.Debug("Windows ANSI颜色支持已启用")
	}

	// 解析命令行参数
	args := ParseCLIArgs()

	// 应用CLI参数到配置（包括--debug标志）
	applyArgsToConfig(args)

	//  提前显示启动信息，确保banner在所有日志输出之前显示
	displayStartupInfo(args)

	// 仅端口扫描模式：-m port
	if !args.Listen && args.HasModule("port") && len(args.Modules) == 1 {
		if strings.TrimSpace(args.Ports) == "" {
			logger.Fatalf("端口扫描模块需要指定 -p 端口范围，例如: -p 1-600,80,8001,800-900")
		}
		if err := runMasscanPortScan(args); err != nil {
			logger.Fatalf("端口扫描失败: %v", err)
		}
		return
	}

	// 保持既有逻辑：不携带 -p 时，按原有模块执行（目录扫描+指纹识别）。
	// 若携带 -p，则先执行正常扫描（目录扫描+指纹识别），结束后再执行端口扫描。

	// 初始化应用程序（仅当非端口扫描场景）
	var err error
	app, err = initializeApp(args)
	if err != nil {
		logger.Fatalf("初始化应用程序失败: %v", err)
	}

	// 根据模式启动应用程序
	if args.Listen {
		// 被动代理模式
		if err := startApplication(args); err != nil {
			logger.Fatalf("启动应用程序失败: %v", err)
		}
		// 等待中断信号
		waitForSignal()
	} else {
		// 主动扫描模式
		if err := runActiveScanMode(args); err != nil {
			logger.Fatalf("主动扫描失败: %v", err)
		}
		// 若用户指定了 -p，则在正常扫描完成后执行端口扫描（仅当未输出合并JSON文件时）
		if strings.TrimSpace(args.Ports) != "" && !args.JSONOutput && !strings.HasSuffix(strings.ToLower(args.Output), ".json") {
			if err := runMasscanPortScan(args); err != nil {
				logger.Fatalf("端口扫描失败: %v", err)
			}
		}
	}
}

// ParseCLIArgs 解析命令行参数
func ParseCLIArgs() *CLIArgs {
	var (
		targetsStr = flag.String("u", "", "目标主机/URL，多个目标用逗号分隔 (例如: -u www.baidu.com,api.baidu.com)")
		targetFile = flag.String("f", "", "目标文件路径，每行一个目标 (例如: -f targets.txt)")
		modulesStr = flag.String("m", "", "启用的模块，多个模块用逗号分隔 (例如: -m finger,dirscan)")
		localPort  = flag.Int("lp", 9080, "本地代理监听端口，仅在被动模式下使用 (默认: 9080)")
		portsArg   = flag.String("p", "", "端口范围，支持单端口或范围，逗号分隔 (例如: -p 80,443,8000-8100 或 1-65535)")
		rateArg    = flag.Int("rate", 0, "端口扫描速率(包/秒)，仅在启用端口扫描时使用 (例如: --rate 10000)")
		wordlist   = flag.String("w", "", "自定义字典文件路径 (例如: -w /path/to/custom.txt)")
		listen     = flag.Bool("listen", false, "启用被动代理模式 (默认: 主动扫描模式)")
		debug      = flag.Bool("debug", false, "启用调试模式，显示详细日志 (默认: 仅显示INFO及以上级别)")

		// 新增：线程并发控制和全局配置参数
		threads     = flag.Int("t", 0, "统一线程并发数量，对所有模块生效 (默认: 200)")
		threadsLong = flag.Int("threads", 0, "统一线程并发数量，对所有模块生效 (默认: 200)")
		retry       = flag.Int("retry", 0, "扫描失败目标的重试次数 (默认: 3)")
		timeout     = flag.Int("timeout", 0, "全局连接超时时间(秒)，对所有模块生效 (默认: 5)")

		// 新增：报告输出控制参数
		output     = flag.String("o", "", "输出报告文件路径 (默认不输出文件)")
		outputLong = flag.String("output", "", "输出报告文件路径 (默认不输出文件)")

		// 新增：实时统计显示参数
		stats       = flag.Bool("stats", false, "启用实时扫描进度统计显示")
		veryVerbose = flag.Bool("vv", false, "控制指纹匹配内容展示开关 (默认关闭，可使用 --vv 开启)")
		noColor     = flag.Bool("nc", false, "禁用彩色输出，适用于控制台不支持ANSI的环境")
		jsonOutput  = flag.Bool("json", false, "使用JSON格式输出扫描结果，便于与其他工具集成")
		noAlive     = flag.Bool("na", false, "跳过扫描前的存活检测 (默认进行存活检测)")

		// 新增：状态码过滤参数
		statusCodes = flag.String("s", "", "指定需要保留的HTTP状态码，逗号分隔 (例如: -s 200,301,302)")

		// 新增：相似页面过滤容错阈值参数（-1表示使用默认值）
		filterTolerance = flag.Int("filter", -1, "相似页面过滤容错阈值(字节)，值越大过滤越严格 (默认: 50, 范围: 0-500, 0表示禁用过滤)")

		help     = flag.Bool("h", false, "显示帮助信息")
		helpLong = flag.Bool("help", false, "显示帮助信息")
	)

	// 新增：自定义HTTP头部参数（支持多个）
	var headers arrayFlags
	flag.Var(&headers, "header", "自定义HTTP认证头部，格式: \"Header-Name: Header-Value\" (可重复使用)")

	// 设置自定义帮助信息
	flag.Usage = showCustomHelp

	flag.Parse()

	// 显示帮助信息
	if *help || *helpLong {
		flag.Usage()
		os.Exit(0)
	}

	// 创建CLIArgs实例
	args := &CLIArgs{
		TargetFile: *targetFile,
		Port:       *localPort,
		Ports:      *portsArg,
		Rate:       *rateArg,
		Wordlist:   *wordlist,
		Listen:     *listen,
		Debug:      *debug,

		// 新增参数处理：支持短参数和长参数
		Threads:      getMaxInt(*threads, *threadsLong),
		Retry:        *retry,
		Timeout:      *timeout,
		Output:       getStringValue(*output, *outputLong),
		Stats:        *stats,
		VeryVerbose:  *veryVerbose,
		NoColor:      *noColor,
		JSONOutput:   *jsonOutput,
		NoAliveCheck: *noAlive,

		// 新增：HTTP认证头部参数
		Headers: []string(headers),

		// 新增：状态码过滤参数
		StatusCodes: *statusCodes,

		// 新增：相似页面过滤容错阈值参数
		FilterTolerance: *filterTolerance,
	}

	if *targetsStr != "" {
		args.Targets = parseTargets(*targetsStr)
	}

	if *modulesStr != "" {
		args.Modules = parseModules(*modulesStr)
	}

	// [新增] 如果未指定模块，使用默认模块
	if len(args.Modules) == 0 {
		args.Modules = []string{string(modulepkg.ModuleFinger), string(modulepkg.ModuleDirscan)}
		logger.Debugf("未指定模块，使用默认模块: %s, %s", modulepkg.ModuleFinger, modulepkg.ModuleDirscan)
	}

	if args.JSONOutput {
		args.Stats = false
	}

	// 验证参数
	if err := validateArgs(args); err != nil {
		logger.Error(fmt.Sprintf("参数验证失败: %v", err))
		os.Exit(1)
	}

	return args
}

// HasModule 检查是否包含指定模块
func (args *CLIArgs) HasModule(module string) bool {
	for _, m := range args.Modules {
		if m == module {
			return true
		}
	}
	return false
}

// getMaxInt 获取两个整数中的最大值，用于处理短参数和长参数
func getMaxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// getStringValue 获取字符串参数值，优先使用非空值，用于处理短参数和长参数
func getStringValue(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// showCustomHelp 显示自定义帮助信息
func showCustomHelp() {
	fmt.Printf(`

veo - 双模式安全扫描工具

用法:
  %s -u <targets> -m <modules> [options]          # 主动扫描模式 (默认)
  %s -f <file> -m <modules> [options]             # 批量文件扫描模式
  %s -u <targets> -m <modules> --listen [options] # 被动代理模式

目标指定参数 (二选一或组合使用):
  -u string
        目标主机/URL，多个目标用逗号分隔
        支持格式:
          - 完整URL: https://example.com, http://api.example.com/v1
          - 域名: example.com, api.example.com
          - 带端口: example.com:8080, 192.168.1.1:443
        主动模式: -u www.example.com,api.example.com/path
        被动模式: -u www.example.com (或 * 表示全部抓取)

  -f string
        目标文件路径，每行一个目标，支持批量扫描
        文件格式要求:
          - 每行一个目标URL或域名
          - 支持 # 开头的注释行
          - 支持空行（自动跳过）
          - 文件编码: UTF-8
        支持的目标格式:
          - https://example.com
          - example.com:8080
          - 192.168.1.1:443
          - api.example.com/path
        示例: -f targets.txt

扫描模块参数:
  -m string
        启用的模块，多个模块用逗号分隔 (默认: finger,dirscan)
        如果未指定此参数，将自动启用 finger 和 dirscan 模块
        可用模块:
          - finger: 指纹识别模块
          - dirscan: 目录扫描模块
          - port: 端口扫描模块（仅端口扫描）
        示例: -m finger              # 只启用指纹识别
              -m dirscan             # 只启用目录扫描
              -m port               # 只启用端口扫描（需同时指定 -p）
              -m finger,dirscan      # 启用指纹识别和目录扫描（默认）

可选参数:
  --debug
        启用调试模式，显示详细的调试日志 (默认: 仅显示INFO及以上级别)
        调试模式下会显示 [DBG], [INF], [WRN], [ERR], [FTL] 所有级别的日志
        正常模式下仅显示 [INF], [WRN], [ERR], [FTL] 级别的日志

  --listen
        启用被动代理模式 (默认: 主动扫描模式)
        被动模式下工具作为代理服务器运行，拦截HTTP流量

  -lp int
        本地代理监听端口，仅在被动模式下使用 (默认: 9080)
        示例: -lp 9080

  -w string
        自定义字典文件路径，覆盖配置文件中的默认字典
        字典文件格式: 每行一个路径，支持注释行
        示例: -w /path/to/custom.txt

性能控制参数:
  -t, --threads int
        统一线程并发数量，对所有模块(指纹识别、目录扫描、连通性检测)生效
        范围: 1-1000，默认: 200
        示例: -t 50, --threads 100

  --retry int
        扫描失败目标的重试次数，对所有模块生效
        范围: 0-10，默认: 3
        示例: --retry 5

  --timeout int
        全局连接超时时间(秒)，对所有模块生效，覆盖配置文件设置
        范围: 1-300，默认: 5
        示例: --timeout 10

  -o, --output string
        输出报告文件路径 (默认不输出文件)
        支持格式: HTML, JSON
        示例: --output report.html (HTML格式)
              --output report.json (JSON格式)
              --output /path/to/report.html
              --output ./reports/scan_result.json

  --stats
        启用实时扫描进度统计显示
        显示内容: 运行时间、主机数、RPS、完成数、超时数、请求进度
        示例: --stats

  --header string
        自定义HTTP认证头部，格式: "Header-Name: Header-Value"
        可重复使用多次添加多个头部，支持所有HTTP请求方法
        常用认证头部: Authorization, Cookie, X-API-Key, X-Auth-Token
        示例: --header "Authorization: Bearer token123"
              --header "Cookie: session=abc123; csrf=xyz789"
              --header "X-API-Key: your-api-key"

  -s string
        指定需要保留的HTTP状态码，逗号分隔 (默认: 使用配置文件中的ValidStatusCodes)
        只有匹配这些状态码的结果才会被输出，CLI参数优先级高于配置文件
        状态码范围: 100-599之间的整数
        示例: -s 200                    # 只返回200状态码
              -s 200,301,302            # 返回200、301、302状态码
              -s 200,403,500            # 返回200、403、500状态码

  --filter int
        相似页面过滤容错阈值(字节)，用于控制目录扫描中相似页面的过滤敏感度
        值越大过滤越严格，值越小过滤越宽松
        范围: 0-500 (默认: 50)
        特殊值: 0 表示禁用相似页面过滤
        示例: --filter=100  # 严格过滤
              --filter=30   # 宽松过滤
              --filter=0    # 禁用过滤

  -h, --help
        显示此帮助信息

主动扫描模式示例:
  # 单目标基本扫描
  %s -u target.com -m dirscan                    # 目录扫描
  %s -u target.com -m finger                     # 指纹识别
  %s -u target.com -m finger,dirscan             # 组合扫描

  # 多目标扫描
  %s -u target1.com,target2.com/api -m finger,dirscan

  # 带端口的目标扫描
  %s -u target.com:8080,192.168.1.1:443 -m finger

  # 多层级目录扫描
  %s -u target.com/api/v1/users -m dirscan

批量文件扫描示例:
  # 基本批量扫描
  %s -f targets.txt -m finger,dirscan            # 从文件读取目标列表

  # 混合模式扫描 (命令行 + 文件)
  %s -u target.com -f targets.txt -m finger      # 合并命令行和文件目标

  # 使用自定义字典的批量扫描
  %s -f targets.txt -m dirscan -w custom.txt     # 批量目录扫描

被动代理模式示例:
  # 基本代理模式
  %s -u target.com -m dirscan --listen

  # 全部抓取模式
  %s -m finger,dirscan --listen -lp 8080

  # 使用自定义字典
  %s -u target.com -m dirscan -w /path/to/wordlist.txt --listen

  # 多目标指纹识别
  %s -u target1.com,target2.com -m finger,dirscan -lp 9080 --listen

目标文件格式示例 (targets.txt):
  # 这是注释行，会被自动跳过
  https://example.com
  http://api.example.com/v1
  target.com:8080
  192.168.1.1:443
  subdomain.example.com

  # 支持空行分隔
  another-target.com

常用命令组合:
  # 快速指纹识别
  %s -u target.com -m finger

  # 深度目录扫描
  %s -u target.com -m dirscan -w large-wordlist.txt

  # 批量安全评估
  %s -f company-domains.txt -m finger,dirscan

  # 混合目标全面扫描
  %s -u primary.com -f backup-targets.txt -m finger,dirscan

故障排除:
  - 确保目标文件存在且可读
  - 检查目标URL格式是否正确
  - 验证网络连接和目标可达性
  - 查看日志输出获取详细错误信息

配置文件:
  配置文件位置: ./configs/config.yaml
  CLI参数优先级高于配置文件设置
  并行度和超时等参数通过配置文件控制
`, os.Args[0], os.Args[0], os.Args[0], // 用法部分 (3个)
		os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], // 主动扫描示例 (6个)
		os.Args[0], os.Args[0], os.Args[0], // 批量扫描示例 (3个)
		os.Args[0], os.Args[0], os.Args[0], os.Args[0], // 被动代理示例 (4个)
		os.Args[0], os.Args[0], os.Args[0], os.Args[0]) // 常用命令组合 (4个)
}

// parseCommaSeparatedString 解析逗号分隔的字符串
func parseCommaSeparatedString(input string) []string {
	if input == "" {
		return []string{}
	}

	items := strings.Split(input, ",")
	var cleanItems []string

	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			cleanItems = append(cleanItems, item)
		}
	}
	return cleanItems
}

func parseTargets(targetsStr string) []string {
	return parseCommaSeparatedString(targetsStr)
}

func parseModules(modulesStr string) []string {
	return parseCommaSeparatedString(modulesStr)
}

// validateArgs 验证CLI参数
func validateArgs(args *CLIArgs) error {
	// 验证端口范围（仅在被动模式下需要）
	if args.Listen && (args.Port <= 0 || args.Port > 65535) {
		return fmt.Errorf("端口必须在1-65535范围内，当前值: %d", args.Port)
	}

	// 当指定端口扫描时进行基础校验
	if strings.TrimSpace(args.Ports) != "" {
		if len(args.Targets) == 0 && strings.TrimSpace(args.TargetFile) == "" {
			return fmt.Errorf("端口扫描需要通过 -u 或 -f 指定目标")
		}
	}

	// 验证线程并发数量
	if args.Threads < 0 || args.Threads > 1000 {
		return fmt.Errorf("线程并发数量必须在0-1000范围内，当前值: %d", args.Threads)
	}

	// 验证重试次数
	if args.Retry < 0 || args.Retry > 10 {
		return fmt.Errorf("重试次数必须在0-10范围内，当前值: %d", args.Retry)
	}

	// 验证超时时间
	if args.Timeout < 0 || args.Timeout > 300 {
		return fmt.Errorf("超时时间必须在0-300秒范围内，当前值: %d", args.Timeout)
	}

	// 验证相似页面过滤容错阈值（-1表示使用默认值，不需要验证）
	if args.FilterTolerance != -1 && (args.FilterTolerance < 0 || args.FilterTolerance > 500) {
		return fmt.Errorf("相似页面过滤容错阈值必须在0-500范围内，当前值: %d", args.FilterTolerance)
	}

	// 端口扫描模块需要指定端口范围
	if args.HasModule("port") && !args.Listen {
		if strings.TrimSpace(args.Ports) == "" {
			return fmt.Errorf("端口扫描模块需要指定 -p 端口范围，例如: -p 1-600,80,8001,800-900")
		}
	}

	// 根据模式验证参数
	if args.Listen {
		// 被动代理模式：如果没有指定目标，设置默认值为 * (全部抓取)
		if len(args.Targets) == 0 {
			args.Targets = []string{"*"}
		}
	} else {
		// 主动扫描模式：必须指定具体目标或目标文件
		if len(args.Targets) == 0 && args.TargetFile == "" {
			return fmt.Errorf("主动扫描模式必须指定目标主机/URL (-u) 或目标文件 (-f)")
		}
		// 主动模式不允许使用通配符
		for _, target := range args.Targets {
			if target == "*" {
				return fmt.Errorf("主动扫描模式不支持通配符目标，请指定具体的URL")
			}
		}
	}

	// 验证目标格式
	if err := validateTargets(args.Targets); err != nil {
		return fmt.Errorf("目标参数无效: %v", err)
	}

	// 验证自定义字典文件（如果指定）
	if args.Wordlist != "" {
		if err := validateWordlistFile(args.Wordlist); err != nil {
			return fmt.Errorf("字典文件无效: %v", err)
		}
	}

	// 验证输出路径（如果指定）
	if args.Output != "" {
		if err := validateOutputPath(args.Output); err != nil {
			return fmt.Errorf("输出路径无效: %v", err)
		}
	}

	// 验证模块
	if err := validateModules(args.Modules); err != nil {
		return fmt.Errorf("模块参数无效: %v", err)
	}

	// [修改] 移除"必须指定模块"的检查，因为现在有默认模块
	// 注意：ParseCLIArgs() 已经在未指定模块时自动设置默认模块
	if len(args.Modules) == 0 {
		return fmt.Errorf("内部错误: 模块列表为空（应该已设置默认模块）")
	}

	return nil
}

// validateTargets 验证目标列表
func validateTargets(targets []string) error {
	for _, target := range targets {
		if strings.Contains(target, " ") {
			return fmt.Errorf("目标不能包含空格: '%s'", target)
		}
		if len(target) == 0 {
			return fmt.Errorf("目标不能为空")
		}

		// 允许通配符 "*" 表示全部抓取
		if target == "*" {
			continue
		}

		// 基本的目标格式检查
		if strings.HasPrefix(target, ".") || strings.HasSuffix(target, ".") {
			return fmt.Errorf("无效的目标格式: '%s'", target)
		}
	}
	return nil
}

// validateWordlistFile 验证字典文件
func validateWordlistFile(wordlistPath string) error {
	if _, err := os.Stat(wordlistPath); os.IsNotExist(err) {
		return fmt.Errorf("字典文件不存在: %s", wordlistPath)
	}

	// 检查文件是否可读
	file, err := os.Open(wordlistPath)
	if err != nil {
		return fmt.Errorf("无法读取字典文件: %v", err)
	}
	file.Close()

	return nil
}

// validateOutputPath 验证输出路径
func validateOutputPath(outputPath string) error {
	// 支持 .json 和 .xlsx 扩展名
	lowerPath := strings.ToLower(outputPath)
	if !strings.HasSuffix(lowerPath, ".json") && !strings.HasSuffix(lowerPath, ".xlsx") {
		return fmt.Errorf("输出文件必须以.json或.xlsx结尾，当前: %s", outputPath)
	}

	// 获取目录路径
	dir := filepath.Dir(outputPath)

	// 如果目录不存在，尝试创建
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("无法创建输出目录 %s: %v", dir, err)
		}
	}

	// 检查目录是否可写
	testFile := filepath.Join(dir, ".veo_write_test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return fmt.Errorf("输出目录不可写 %s: %v", dir, err)
	}
	os.Remove(testFile) // 清理测试文件

	return nil
}

// validateModules 验证模块列表
func validateModules(modules []string) error {
	for _, module := range modules {
		if !isValidModule(module) {
			return fmt.Errorf("无效的模块: '%s'，支持的模块: %s", module, strings.Join(ValidModules, ", "))
		}
	}
	return nil
}

// isValidModule 检查模块是否有效
func isValidModule(module string) bool {
	for _, validModule := range ValidModules {
		if module == validModule {
			return true
		}
	}
	return false
}

// GetTargetsString 获取目标列表字符串
func (args *CLIArgs) GetTargetsString() string {
	return strings.Join(args.Targets, ",")
}

// GetModulesString 获取模块列表字符串
func (args *CLIArgs) GetModulesString() string {
	return strings.Join(args.Modules, ",")
}

// initializeReportGenerator 初始化报告生成器（已优化为无操作）
func initializeReportGenerator() {
	// 新架构中过滤器已经独立化，不再需要全局设置
	logger.Debug("报告生成器已独立化，无需全局设置")
}

// initializeApp 初始化应用程序
func initializeApp(args *CLIArgs) (*CLIApp, error) {
	// 配置系统和日志系统已在Execute()函数开始时初始化，这里无需重复

	// 初始化报告生成器
	initializeReportGenerator()

	// 创建代理服务器
	logger.Debug("创建代理服务器...")
	proxyServer, err := createProxy()
	if err != nil {
		return nil, fmt.Errorf("创建代理服务器失败: %v", err)
	}

	// 只在启用dirscan模块时创建collector和相关组件
	var collectorInstance *collector.Collector
	var consoleManager *console.ConsoleManager
	var dirscanModule *dirscan.DirscanModule

	if args.HasModule(string(modulepkg.ModuleDirscan)) {
		logger.Debug("启用目录扫描模块，创建相关组件...")

		// 创建collector
		logger.Debug("创建URL采集器...")
		collectorInstance = collector.NewCollector()

		// 创建控制台管理器
		logger.Debug("创建控制台管理器...")
		consoleManager = console.NewConsoleManager(collectorInstance)

		// 创建目录扫描模块
		logger.Debug("创建目录扫描模块...")
		dirscanModule, err = dirscan.NewDirscanModule(consoleManager)
		if err != nil {
			return nil, fmt.Errorf("创建目录扫描模块失败: %v", err)
		}
	} else {
		logger.Debug("未启用目录扫描模块，跳过collector和consoleManager创建")
	}

	// 创建指纹识别插件（如果启用）
	var fingerprintAddon *fingerprint.FingerprintAddon
	if args.HasModule(string(modulepkg.ModuleFinger)) {
		logger.Debug("创建指纹识别插件...")
		fingerprintAddon, err = createFingerprintAddon()
		if err != nil {
			logger.Warnf("指纹识别插件初始化失败: %v", err)
		}
	}

	// 创建认证学习插件（总是创建，用于被动代理模式下的认证学习）
	logger.Debug("创建认证学习插件...")
	authLearningAddon := createAuthLearningAddon()

	// 创建应用程序实例
	app := &CLIApp{
		proxy:             proxyServer,
		collector:         collectorInstance, // 可能为nil
		consoleManager:    consoleManager,    // 可能为nil
		dirscanModule:     dirscanModule,     // 可能为nil
		fingerprintAddon:  fingerprintAddon,  // 可能为nil
		authLearningAddon: authLearningAddon, // 总是存在
		proxyStarted:      false,
		args:              args,
	}

	// 只在有控制台管理器时设置回调
	if consoleManager != nil {
		consoleManager.SetProxyController(app)
		if fingerprintAddon != nil {
			consoleManager.SetFingerprintAddon(fingerprintAddon)
		}
	}

	logger.Debug("应用程序初始化完成")
	return app, nil
}

// ApplyArgsToConfig 将CLI参数应用到配置系统（导出用于测试）
func ApplyArgsToConfig(args *CLIArgs) {
	applyArgsToConfig(args)
}

// applyArgsToConfig 将CLI参数应用到配置系统
func applyArgsToConfig(args *CLIArgs) {
	// 设置监听端口
	serverConfig := config.GetServerConfig()
	serverConfig.Listen = fmt.Sprintf(":%d", args.Port)

	// 应用调试模式设置
	if args.Debug {
		logger.SetLogLevel("debug")
		logger.Debug("调试模式已启用，显示所有级别日志")
	} else {
		logger.SetLogLevel("info")
	}

	if args.NoColor {
		formatter.SetColorEnabled(false)
		logger.SetColorOutput(false)
		os.Setenv("NO_COLOR", "1")
	}

	if args.JSONOutput && !args.Debug {
		logger.SetLogLevel("error")
	}

	// 应用新的CLI参数到配置
	requestConfig := config.GetRequestConfig()

	// 应用线程并发数量（如果指定）
	if args.Threads > 0 {
		requestConfig.Threads = args.Threads
		logger.Debugf("CLI参数覆盖：线程并发数量设置为 %d", args.Threads)
	}

	// 应用重试次数（如果指定）
	if args.Retry > 0 {
		requestConfig.Retry = args.Retry
		logger.Debugf("CLI参数覆盖：重试次数设置为 %d", args.Retry)
	}

	// 应用超时时间（如果指定）
	if args.Timeout > 0 {
		requestConfig.Timeout = args.Timeout
		logger.Debugf("CLI参数覆盖：超时时间设置为 %d 秒", args.Timeout)
	}

	// 新增：处理HTTP认证头部参数
	if len(args.Headers) > 0 {
		if err := applyCustomHeaders(args.Headers); err != nil {
			logger.Errorf("HTTP头部参数处理失败: %v", err)
		}
	}

	// 新增：处理状态码过滤参数
	// 目标：统一主动/被动两种模式对状态码来源的处理逻辑
	// 1) 设置全局 ResponseFilter 的有效状态码（影响目录扫描结果过滤）
	// 2) 同步覆盖被动模式 URL 采集器（Collector）的状态码白名单
	var customFilterConfig *filter.FilterConfig

	if args.StatusCodes != "" {
		statusCodes, err := parseStatusCodes(args.StatusCodes)
		if err != nil {
			logger.Errorf("状态码过滤参数处理失败: %v", err)
		} else if len(statusCodes) > 0 {
			logger.Debugf("成功解析 %d 个状态码: %v", len(statusCodes), statusCodes)

			// 1) 覆盖全局过滤配置（供 ResponseFilter 使用）
			customFilterConfig = filter.DefaultFilterConfig()
			customFilterConfig.ValidStatusCodes = statusCodes
			logger.Infof("CLI参数覆盖：状态码过滤设置为 %v", statusCodes)

			// 2) 覆盖被动模式 Collector 的采集状态码白名单
			collectorCfg := config.GetCollectorConfig()
			if collectorCfg != nil {
				collectorCfg.GenerationStatusCodes = statusCodes
				logger.Infof("CLI参数覆盖：被动采集状态码白名单设置为 %v", statusCodes)
			}
		}
	}

	if args.FilterTolerance != -1 {
		if customFilterConfig == nil {
			customFilterConfig = filter.DefaultFilterConfig()
		}
		customFilterConfig.FilterTolerance = int64(args.FilterTolerance)
		logger.Debugf("CLI参数覆盖：相似页面过滤容错阈值设置为 %d 字节", args.FilterTolerance)
	}

	if customFilterConfig != nil {
		filter.SetGlobalFilterConfig(customFilterConfig)
	}

	// 设置目标白名单（支持子域名匹配）
	if len(args.Targets) > 0 {
		hostConfig := config.GetHostsConfig()
		// 🔧 修正：考虑代理服务器会使用extractHost去除端口号
		// 当用户指定 -u 47.104.27.15:65 时，自动允许：
		// 1. 47.104.27.15:65 (原始)
		// 2. 47.104.27.15 (去除端口，用于代理过滤)
		// 3. *.47.104.27.15 (子域名通配符)
		allowList := make([]string, 0, len(args.Targets)*3)
		for _, target := range args.Targets {
			allowList = append(allowList, target) // 原始目标（可能包含端口）

			// 如果目标包含端口，同时添加不含端口的版本
			if host, _, err := net.SplitHostPort(target); err == nil {
				allowList = append(allowList, host)      // 不含端口的主机名
				allowList = append(allowList, "*."+host) // 子域名通配符
			} else {
				// 如果没有端口，添加子域名通配符
				allowList = append(allowList, "*."+target)
			}
		}
		hostConfig.Allow = allowList

		logger.Debugf("主机白名单已设置: %v", allowList)
		logger.Debugf("支持主域名和子域名匹配，例如: %s 和 *.%s", args.Targets[0], args.Targets[0])
	}

	// 应用自定义字典路径
	if args.Wordlist != "" {
		wordlists := parseWordlistPaths(args.Wordlist)
		dictionary.SetWordlistPaths(wordlists)
		logger.Infof("使用自定义字典: %s", strings.Join(wordlists, ","))
	} else {
		dictionary.SetWordlistPaths(nil)
	}

	// 应用输出文件路径
}

// createProxy 创建代理服务器
func createProxy() (*proxy.Proxy, error) {
	serverConfig := config.GetServerConfig()
	proxyConfig := config.GetProxyConfig()

	opts := &proxy.Options{
		Addr:              serverConfig.Listen,
		StreamLargeBodies: proxyConfig.StreamLargebody,
		SslInsecure:       proxyConfig.SSLInsecure, // 添加缺失的SSL配置
	}
	return proxy.NewProxy(opts)
}

// runMasscanPortScan 调用内嵌 masscan 扫描（模块化实现）
func runMasscanPortScan(args *CLIArgs) error {
	effectiveRate := masscanrunner.ComputeEffectiveRate(args.Rate)

	// 端口表达式：若未指定 -p 且未使用 -f，则从URL中推导（默认80/443或URL显式端口）
	portsExpr := strings.TrimSpace(args.Ports)
	if portsExpr == "" && strings.TrimSpace(args.TargetFile) == "" {
		portsExpr = masscanrunner.DerivePortsFromTargets(args.Targets)
		if portsExpr == "" {
			return fmt.Errorf("未指定 -p 且无法从URL目标推导端口")
		}
	}

	// 目标转换：若使用 -u，则将URL/域名转换为IP列表；若 -f 则保持 -iL 传参
	var msTargets []string
	if strings.TrimSpace(args.TargetFile) == "" {
		var err error
		msTargets, err = masscanrunner.ResolveTargetsToIPs(args.Targets)
		if err != nil {
			return fmt.Errorf("目标解析失败: %v", err)
		}
	}

	// 模块开始前空行，提升可读性
	fmt.Println()
	logger.Infof("%s", formatter.FormatBold(fmt.Sprintf("Start Port Scan, Ports: %s rate=%d", portsExpr, effectiveRate)))
	opts := portscanpkg.Options{
		Ports:      portsExpr,
		Rate:       effectiveRate,
		Targets:    msTargets,
		TargetFile: args.TargetFile,
	}
	results, err := masscanrunner.Run(opts)
	if err != nil {
		return err
	}
	// --json 模式：输出合并JSON（仅包含 portscan_results）到控制台；如指定 --output .json，则写入相同内容
	if args.JSONOutput {
		pr := aggregatePortResults(results)
		params := map[string]interface{}{
			"ports": portsExpr,
			"rate":  effectiveRate,
		}
		jsonStr, jerr := report.GenerateCombinedJSON(nil, nil, nil, nil, pr, params)
		if jerr != nil {
			return jerr
		}
		fmt.Println(jsonStr)
		if strings.TrimSpace(args.Output) != "" && strings.HasSuffix(strings.ToLower(args.Output), ".json") {
			if err := os.MkdirAll(filepath.Dir(args.Output), 0o755); err != nil {
				logger.Errorf("创建输出目录失败: %v", err)
			} else if werr := os.WriteFile(args.Output, []byte(jsonStr), 0o644); werr != nil {
				logger.Errorf("写入合并JSON失败: %v", werr)
			}
		}
		return nil
	}
	for _, r := range results {
		logger.Infof("%s:%d", r.IP, r.Port)
	}
	logger.Debugf("端口扫描完成，发现开放端口: %d", len(results))

	// 若指定输出路径，则根据扩展名导出 JSON 或 Excel
	if strings.TrimSpace(args.Output) != "" {
		out := strings.TrimSpace(args.Output)
		lower := strings.ToLower(out)
		if strings.HasSuffix(lower, ".json") {
			// 落盘合并JSON（仅包含 portscan_results），与 --json 控制台一致
			pr := aggregatePortResults(results)
			params := map[string]interface{}{"ports": portsExpr, "rate": effectiveRate}
			if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
				logger.Errorf("创建输出目录失败: %v", err)
			} else {
				if jsonStr, jerr := report.GenerateCombinedJSON(nil, nil, nil, nil, pr, params); jerr != nil {
					logger.Errorf("生成合并JSON失败: %v", jerr)
				} else if werr := os.WriteFile(out, []byte(jsonStr), 0o644); werr != nil {
					logger.Errorf("端口扫描合并JSON报告写入失败: %v", werr)
				}
			}
		} else if strings.HasSuffix(lower, ".xlsx") {
			if _, err := report.GeneratePortscanExcel(results, out); err != nil {
				logger.Errorf("端口扫描Excel报告生成失败: %v", err)
			}
		} else {
			logger.Warnf("未知的输出文件类型: %s (支持 .json/.xlsx)", out)
		}
	}
	return nil
}

// aggregatePortResults 将 OpenPortResult 列表按 IP 聚合为 SDKPortResult（端口字符串数组）
func aggregatePortResults(results []portscanpkg.OpenPortResult) []report.SDKPortResult {
	if len(results) == 0 {
		return nil
	}
	m := make(map[string]map[int]struct{})
	for _, r := range results {
		if _, ok := m[r.IP]; !ok {
			m[r.IP] = make(map[int]struct{})
		}
		m[r.IP][r.Port] = struct{}{}
	}
	out := make([]report.SDKPortResult, 0, len(m))
	for ip, portsSet := range m {
		ports := make([]int, 0, len(portsSet))
		for p := range portsSet {
			ports = append(ports, p)
		}
		for i := 0; i < len(ports); i++ {
			for j := i + 1; j < len(ports); j++ {
				if ports[j] < ports[i] {
					ports[i], ports[j] = ports[j], ports[i]
				}
			}
		}
		portStrs := make([]string, len(ports))
		for i, p := range ports {
			portStrs[i] = strconv.Itoa(p)
		}
		out = append(out, report.SDKPortResult{IP: ip, Port: portStrs})
	}
	return out
}

// createFingerprintAddon 创建指纹识别插件
func createFingerprintAddon() (*fingerprint.FingerprintAddon, error) {
	addon, err := fingerprint.CreateDefaultAddon()
	if err != nil {
		return nil, err
	}

	fingerprint.SetGlobalAddon(addon)
	return addon, nil
}

// createAuthLearningAddon 创建认证学习插件
func createAuthLearningAddon() *authlearning.AuthLearningAddon {
	addon := authlearning.NewAuthLearningAddon()
	logger.Debug("认证学习插件创建成功")
	return addon
}

// startApplication 启动应用程序
func startApplication(args *CLIArgs) error {
	// 启动代理服务器
	if err := app.StartProxy(); err != nil {
		return fmt.Errorf("启动代理服务器失败: %v", err)
	}

	// 启动指定的模块
	logger.Debug("开始启动指定的模块...")

	// 启动指纹识别模块
	if args.HasModule(string(modulepkg.ModuleFinger)) && app.fingerprintAddon != nil {
		// 注意：fingerprintAddon是直接的addon，不是模块，需要设置为全局实例
		fingerprint.SetGlobalAddon(app.fingerprintAddon)
		app.fingerprintAddon.Enable()

		// 使 -vv 在被动模式下生效：控制片段输出
		app.fingerprintAddon.EnableSnippet(args.VeryVerbose)

		// 将指纹识别addon添加到代理服务器
		app.proxy.AddAddon(app.fingerprintAddon)
		logger.Debug("指纹识别addon已添加到代理服务器")
		logger.Debug("指纹识别模块启动成功")
	}

	// 启动目录扫描模块
	if args.HasModule(string(modulepkg.ModuleDirscan)) && app.dirscanModule != nil {
		if err := app.dirscanModule.Start(); err != nil {
			logger.Errorf("启动目录扫描模块失败: %v", err)
		} else {
			logger.Debug("目录扫描模块启动成功")
		}
	}

	// 执行模块间依赖注入
	if app.fingerprintAddon != nil {
		// 使用HTTP客户端工厂创建客户端（代码质量优化）
		userAgent := "Moziilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0"
		httpClient := httpclient.CreateClientWithUserAgent(userAgent)

		// 注入到指纹识别模块
		app.fingerprintAddon.SetHTTPClient(httpClient)
		logger.Debug("HTTP客户端已注入到指纹识别模块（使用工厂模式）")
	}

	logger.Debug("模块启动和依赖注入完成")
	return nil
}

func displayStartupInfo(args *CLIArgs) {
	// 显示模块状态
	fmt.Print(`
		veo@Evilc0de

`)
	logger.Debugf("模块状态:")
	logger.Debugf("指纹识别: %s\n", getModuleStatus(args.HasModule(string(modulepkg.ModuleFinger))))
	logger.Debugf("目录扫描: %s\n", getModuleStatus(args.HasModule(string(modulepkg.ModuleDirscan))))
}

// StartProxy 启动代理服务器
func (app *CLIApp) StartProxy() error {
	if app.proxyStarted {
		return nil
	}

	// 总是添加认证学习插件（用于被动代理模式下的认证学习）
	if app.authLearningAddon != nil {
		app.proxy.AddAddon(app.authLearningAddon)
		logger.Debug("认证学习插件已添加到代理服务器")
	}

	// 只在启用目录扫描模块时添加collector
	if app.args.HasModule(string(modulepkg.ModuleDirscan)) && app.collector != nil {
		app.proxy.AddAddon(app.collector)
	}

	// 根据启用的模块添加插件
	if app.args.HasModule(string(modulepkg.ModuleFinger)) && app.fingerprintAddon != nil {
		app.proxy.AddAddon(app.fingerprintAddon)
	}

	// 启动代理服务器
	go func() {
		if err := app.proxy.Start(); err != nil {
			logger.Error(err)
		}
	}()

	app.proxyStarted = true
	return nil
}

// StopProxy 停止代理服务器
func (app *CLIApp) StopProxy() error {
	if !app.proxyStarted {
		return nil
	}

	if err := app.proxy.Close(); err != nil {
		return err
	}

	app.proxyStarted = false
	return nil
}

// IsProxyStarted 检查代理是否已启动
func (app *CLIApp) IsProxyStarted() bool {
	return app.proxyStarted
}

// GetFingerprintAddon 获取指纹识别插件
func (app *CLIApp) GetFingerprintAddon() *fingerprint.FingerprintAddon {
	return app.fingerprintAddon
}

// getModuleStatus 获取模块状态文本
func getModuleStatus(enabled bool) string {
	if enabled {
		return "[√]"
	}
	return "[X]"
}

// waitForSignal 等待中断信号
func waitForSignal() {
	// 创建信号通道
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 等待信号
	sig := <-sigChan
	fmt.Println()
	logger.Info(sig)

	// 执行清理
	cleanup()
}

// cleanup 清理资源
func cleanup() {

	if app != nil {
		// 停止目录扫描模块
		if app.dirscanModule != nil {
			if err := app.dirscanModule.Stop(); err != nil {
				logger.Errorf("停止目录扫描模块失败: %v", err)
			}
		}

		// 停止代理服务器
		if err := app.StopProxy(); err != nil {
			logger.Errorf("停止代理服务器失败: %v", err)
		}
	}

	// 等待清理完成
	time.Sleep(500 * time.Millisecond)
	os.Exit(0)
}

// runActiveScanMode 运行主动扫描模式
func runActiveScanMode(args *CLIArgs) error {
	logger.Debug("启动主动扫描模式")

	// [修复] 使用已经应用了CLI参数的全局配置，而不是重新加载配置文件
	// 这样可以确保CLI参数（如-t线程数）能够正确生效
	cfg := config.GetConfig()

	// 创建扫描控制器并运行
	scanner := NewScanController(args, cfg)
	return scanner.Run()
}

// ===========================================
// HTTP头部解析和验证函数
// ===========================================

// parseHTTPHeaders 解析CLI参数中的HTTP头部
func parseHTTPHeaders(headers []string) (map[string]string, error) {
	parsedHeaders := make(map[string]string)

	for _, header := range headers {
		if err := validateHeaderFormat(header); err != nil {
			return nil, fmt.Errorf("无效的头部格式 '%s': %v", header, err)
		}

		parts := strings.SplitN(header, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("头部格式错误，应为 'Header-Name: Header-Value'，实际: %s", header)
		}

		headerName := strings.TrimSpace(parts[0])
		headerValue := strings.TrimSpace(parts[1])

		if headerName == "" {
			return nil, fmt.Errorf("头部名称不能为空: %s", header)
		}

		parsedHeaders[headerName] = headerValue
		logger.Debugf("解析HTTP头部: %s = %s", headerName, headerValue)
	}

	return parsedHeaders, nil
}

// validateHeaderFormat 验证HTTP头部格式
func validateHeaderFormat(header string) error {
	if header == "" {
		return fmt.Errorf("头部不能为空")
	}

	if !strings.Contains(header, ":") {
		return fmt.Errorf("头部必须包含冒号分隔符")
	}

	// 检查是否包含非法字符（基本验证）
	if strings.Contains(header, "\n") || strings.Contains(header, "\r") {
		return fmt.Errorf("头部不能包含换行符")
	}

	return nil
}

// HasCustomHeaders 检查是否指定了自定义HTTP头部
func (args *CLIArgs) HasCustomHeaders() bool {
	return len(args.Headers) > 0
}

// applyCustomHeaders 应用自定义HTTP头部到配置系统
func applyCustomHeaders(headers []string) error {
	// 解析HTTP头部
	parsedHeaders, err := parseHTTPHeaders(headers)
	if err != nil {
		return fmt.Errorf("解析HTTP头部失败: %v", err)
	}

	if len(parsedHeaders) == 0 {
		logger.Debug("未指定有效的HTTP头部")
		return nil
	}

	logger.Debugf("成功解析 %d 个HTTP头部", len(parsedHeaders))

	// 将解析后的头部存储到配置系统中
	config.SetCustomHeaders(parsedHeaders)

	return nil
}

// ===========================================
// 状态码过滤解析和验证函数
// ===========================================

// parseStatusCodes 解析CLI参数中的状态码字符串
func parseStatusCodes(statusCodesStr string) ([]int, error) {
	if statusCodesStr == "" {
		return nil, fmt.Errorf("状态码字符串不能为空")
	}

	// 分割逗号分隔的状态码
	codeStrings := strings.Split(statusCodesStr, ",")
	statusCodes := make([]int, 0, len(codeStrings))

	for _, codeStr := range codeStrings {
		codeStr = strings.TrimSpace(codeStr)
		if codeStr == "" {
			continue // 跳过空字符串
		}

		// 转换为整数
		code, err := strconv.Atoi(codeStr)
		if err != nil {
			return nil, fmt.Errorf("无效的状态码 '%s': 必须是整数", codeStr)
		}

		// 验证状态码范围
		if err := validateStatusCode(code); err != nil {
			return nil, fmt.Errorf("无效的状态码 %d: %v", code, err)
		}

		statusCodes = append(statusCodes, code)
		logger.Debugf("解析状态码: %d", code)
	}

	if len(statusCodes) == 0 {
		return nil, fmt.Errorf("未解析到有效的状态码")
	}

	return statusCodes, nil
}

// validateStatusCode 验证单个状态码的有效性
func validateStatusCode(code int) error {
	// HTTP状态码范围: 100-599
	if code < 100 || code > 599 {
		return fmt.Errorf("状态码必须在100-599之间")
	}
	return nil
}

func parseWordlistPaths(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	seen := make(map[string]struct{})
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}
