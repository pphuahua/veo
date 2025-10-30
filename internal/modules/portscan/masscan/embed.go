package masscan

import (
    "embed"
    "fmt"
    "os"
    "path"
    "runtime"
)

// 注意：此处仅建立嵌入框架。请将各平台的 masscan 二进制置于 assets 目录下：
//   - macOS(arm64): internal/modules/portscan/masscan/assets/darwin/arm64/masscan
//   - macOS(amd64): internal/modules/portscan/masscan/assets/darwin/amd64/masscan
//   - Linux(amd64): internal/modules/portscan/masscan/assets/linux/amd64/masscan
//   - Windows(amd64): internal/modules/portscan/masscan/assets/windows/amd64/masscan.exe
// 编译时将自动内嵌；若未提供对应平台的内嵌二进制，将直接报错提示缺失。

//go:embed assets
var embeddedFS embed.FS

// ExtractEmbeddedBinary 将内嵌的 masscan 二进制释放到临时文件
// 参数：
//   - 无（使用当前 GOOS/GOARCH 推断路径）
// 返回：
//   - string: 落地的临时可执行文件路径
//   - error: 错误信息
func ExtractEmbeddedBinary() (string, error) {
	osName := runtime.GOOS
	arch := runtime.GOARCH

	candidates := []string{}
    switch osName {
    case "darwin":
        // 优先考虑精确架构
        candidates = append(candidates,
            path.Join("assets", "darwin", arch, "masscan"),
            path.Join("assets", "darwin", "masscan"),
        )
    case "linux":
        candidates = append(candidates,
            path.Join("assets", "linux", arch, "masscan"),
            path.Join("assets", "linux", "masscan"),
        )
    case "windows":
        candidates = append(candidates,
            path.Join("assets", "windows", arch, "masscan.exe"),
            path.Join("assets", "windows", "masscan.exe"),
        )
    default:
        // 未知平台仍尝试泛路径
        candidates = append(candidates, path.Join("assets", osName, arch, "masscan"))
    }

    var data []byte
    var tried []string
    for _, p := range candidates {
        b, err := embeddedFS.ReadFile(p)
        if err == nil && len(b) > 0 {
            data = b
            break
        }
        tried = append(tried, p)
    }

    if len(data) == 0 {
        return "", fmt.Errorf("未找到masscan二进制文件，请为平台 %s/%s 放置对应文件到 assets 目录 (尝试路径: %v)", osName, arch, tried)
    }

	// 落地临时可执行文件
	suffix := ""
	if osName == "windows" {
		suffix = ".exe"
	}
	f, err := os.CreateTemp("", "veo-masscan-*-bin"+suffix)
	if err != nil {
		return "", fmt.Errorf("创建临时文件失败: %v", err)
	}
	path := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return "", fmt.Errorf("写入临时文件失败: %v", err)
	}
	f.Close()

	// 设置可执行权限（非 Windows）
	if osName != "windows" {
		_ = os.Chmod(path, 0o755)
	}
	return path, nil
}
