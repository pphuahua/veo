package portscan

import "veo/pkg/types"

// OpenPortResult is now an alias to types.OpenPortResult
type OpenPortResult = types.OpenPortResult

// Options 端口扫描选项
// 参数说明：
//   - Ports: 端口表达式，如 "80,443,8000-8100" 或 "1-65535"
//   - Rate: 扫描速率（包/秒）
//   - Targets: 目标列表（与 TargetFile 二选一）
//   - TargetFile: 目标文件路径
//
// 返回：无
type Options struct {
	Ports      string
	Rate       int
	Targets    []string
	TargetFile string
}
