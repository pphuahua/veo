#!/bin/bash

# veo 发布打包脚本
# 自动创建包含所有必要文件的发布包

set -e  # 遇到错误立即退出

# ============================================================================
# 配置区域
# ============================================================================

PROJECT_NAME="veo"
VERSION=${VERSION:-"v1.0.0"}
BUILD_DIR="dist"
RELEASE_DIR="release"

# 需要包含的资源文件
RESOURCE_FILES=(
    "configs"
    "dict" 
    "ca-cert.zip"
    "README.md"
)

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# ============================================================================
# 工具函数
# ============================================================================

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_step() {
    echo -e "${PURPLE}[STEP]${NC} $1"
}

# 显示帮助信息
show_help() {
    cat << EOF
veo 发布打包脚本

用法: $0 [选项]

选项:
    -h, --help          显示此帮助信息
    -c, --clean         清理发布目录
    -v, --version VER   指定版本号 (默认: v1.0.0)
    -b, --build-dir DIR 指定构建目录 (默认: dist)
    -r, --release-dir DIR 指定发布目录 (默认: release)
    --no-compress       不压缩发布包
    --readme            生成README文件

示例:
    $0                          # 创建所有发布包
    $0 -c                       # 清理发布目录
    $0 -v v2.0.0               # 指定版本创建发布包

EOF
}

# 检查构建目录
check_build_dir() {
    if [[ ! -d "$BUILD_DIR" ]]; then
        print_error "构建目录不存在: $BUILD_DIR"
        print_info "请先运行 './build.sh -a' 编译所有平台"
        exit 1
    fi
    
    local binary_count=$(find "$BUILD_DIR" -type f -executable 2>/dev/null | wc -l)
    if [[ $binary_count -eq 0 ]]; then
        binary_count=$(find "$BUILD_DIR" -type f \( -name "*.exe" -o ! -name "*.*" \) | wc -l)
    fi
    
    if [[ $binary_count -eq 0 ]]; then
        print_error "构建目录中没有找到可执行文件"
        print_info "请先运行 './build.sh -a' 编译所有平台"
        exit 1
    fi
    
    print_info "找到 $binary_count 个可执行文件"
}

# 检查资源文件
check_resources() {
    print_step "检查资源文件..."
    
    local missing_files=()
    for file in "${RESOURCE_FILES[@]}"; do
        if [[ ! -e "$file" ]]; then
            missing_files+=("$file")
        fi
    done
    
    if [[ ${#missing_files[@]} -gt 0 ]]; then
        print_warning "以下资源文件缺失: ${missing_files[*]}"
        print_info "发布包将不包含这些文件"
    else
        print_success "所有资源文件检查完成"
    fi
}

# 清理发布目录
clean_release() {
    if [[ -d "$RELEASE_DIR" ]]; then
        print_step "清理发布目录: $RELEASE_DIR"
        rm -rf "$RELEASE_DIR"
        print_success "清理完成"
    fi
}

# 创建发布目录
create_release_dir() {
    if [[ ! -d "$RELEASE_DIR" ]]; then
        mkdir -p "$RELEASE_DIR"
        print_info "创建发布目录: $RELEASE_DIR"
    fi
}

# 生成README文件
generate_readme() {
    local package_dir="$1"
    local os="$2"
    local arch="$3"
    
    local readme_file="$package_dir/README.md"
    local binary_name="$PROJECT_NAME"
    
    if [[ "$os" == "windows" ]]; then
        binary_name="${binary_name}.exe"
    fi
    
    cat > "$readme_file" << EOF
# veo ${VERSION}

高性能网络安全扫描工具

## 系统信息

- **平台**: ${os}/${arch}
- **版本**: ${VERSION}
- **构建时间**: $(date +"%Y-%m-%d %H:%M:%S")

## 快速开始

### 1. 基本使用

\`\`\`bash
# 显示帮助信息
./${binary_name} --help

# 指纹识别模式
./${binary_name} -u target.com -m finger

# 目录扫描模式  
./${binary_name} -u target.com -m dirscan

# 混合模式
./${binary_name} -u target.com -m finger,dirscan
\`\`\`

### 2. 高级功能

\`\`\`bash
# 使用自定义字典
./${binary_name} -u target.com -m dirscan -w custom_dict.txt

# 指定多个目标
./${binary_name} -u "target1.com,target2.com,192.168.1.0/24" -m finger

# 调试模式
./${binary_name} -u target.com -m finger --debug
\`\`\`

## 配置文件

- **configs/config.yaml**: 主配置文件
- **configs/fingerprint/finger.yaml**: 指纹识别规则
- **dict/**: 目录扫描字典文件

## 目录结构

\`\`\`
.
├── ${binary_name}              # 主程序
├── configs/                    # 配置文件目录
│   ├── config.yaml            # 主配置
│   └── fingerprint/           # 指纹识别规则
├── dict/                      # 字典文件目录
│   ├── common.txt            # 通用字典
│   ├── api.txt               # API字典  
│   └── files.txt             # 文件字典
├── ca-cert.zip               # CA证书文件
└── README.md                 # 说明文档
\`\`\`

## 特性说明

### 指纹识别
- 支持 2000+ 指纹规则
- 被动识别，不干扰业务
- 自动检测Web应用、框架、服务器

### 📁 目录扫描  
- 多字典支持
- 智能去重过滤
- 自定义扫描深度
- 并发扫描优化

### 🌐 网络代理
- 内置HTTP代理服务器
- 支持流量拦截分析
- WebSocket连接支持

### 💻 跨平台支持
- Windows ANSI颜色支持
- 自适应终端输出
- 统一配置管理

## 故障排除

### 常见问题

1. **程序无法启动**
   - 检查可执行权限: \`chmod +x ${binary_name}\`
   - 检查配置文件是否存在

2. **扫描无结果**  
   - 检查目标可达性
   - 验证字典文件路径
   - 调整超时设置

3. **代理连接失败**
   - 检查端口占用
   - 验证防火墙设置
   - 查看日志输出

### 获取帮助

- GitHub: https://github.com/your-org/veo
- Issues: https://github.com/your-org/veo/issues
- Wiki: https://github.com/your-org/veo/wiki

## 许可证

本软件仅供安全研究和授权测试使用，请遵守相关法律法规。

---

veo - 专业的网络安全扫描工具
EOF

    print_info "生成README文件: $readme_file"
}

# 创建单个平台的发布包
create_platform_package() {
    local binary_file="$1"
    local filename=$(basename "$binary_file")
    
    # 解析平台信息
    if [[ "$filename" =~ ${PROJECT_NAME}_([a-z]+)_([a-z0-9]+)(\.exe)?$ ]]; then
        local os="${BASH_REMATCH[1]}"
        local arch="${BASH_REMATCH[2]}"
        local extension="${BASH_REMATCH[3]}"
    else
        print_warning "无法解析文件名格式: $filename"
        return 1
    fi
    
    local package_name="${PROJECT_NAME}_${VERSION}_${os}_${arch}"
    local package_dir="${RELEASE_DIR}/${package_name}"
    
    print_step "创建 ${os}/${arch} 发布包..."
    
    # 创建包目录
    mkdir -p "$package_dir"
    
    # 复制二进制文件
    local target_binary="${package_dir}/${PROJECT_NAME}${extension}"
    cp "$binary_file" "$target_binary"
    
    # 设置可执行权限 (非Windows)
    if [[ "$os" != "windows" ]]; then
        chmod +x "$target_binary"
    fi
    
    # 复制资源文件
    for resource in "${RESOURCE_FILES[@]}"; do
        if [[ -e "$resource" ]]; then
            cp -r "$resource" "$package_dir/"
        fi
    done
    
    # 生成README文件
    if [[ "$GENERATE_README" == "true" ]]; then
        generate_readme "$package_dir" "$os" "$arch"
    fi
    
    # 压缩包
    if [[ "$CREATE_ARCHIVES" == "true" ]]; then
        cd "$RELEASE_DIR"
        
        if [[ "$os" == "windows" ]]; then
            # Windows使用ZIP
            if command -v zip &> /dev/null; then
                zip -r "${package_name}.zip" "$package_name" >/dev/null
                print_success "✅ ${package_name}.zip"
            else
                print_warning "zip命令不可用，跳过ZIP压缩"
            fi
        else
            # Linux/macOS使用tar.gz
            tar -czf "${package_name}.tar.gz" "$package_name"
            print_success "✅ ${package_name}.tar.gz"
        fi
        
        cd - >/dev/null
    else
        print_success "✅ ${package_name}/"
    fi
    
    return 0
}

# 创建所有发布包
create_all_packages() {
    print_step "创建发布包..."
    
    local success_count=0
    local fail_count=0
    
    # 遍历所有二进制文件
    for binary in "$BUILD_DIR"/*; do
        if [[ -f "$binary" ]]; then
            if create_platform_package "$binary"; then
                ((success_count++))
            else
                ((fail_count++))
            fi
        fi
    done
    
    print_info "发布包创建完成: 成功 $success_count, 失败 $fail_count"
}

# 显示发布结果
show_release_results() {
    print_step "发布包结果:"
    
    if [[ ! -d "$RELEASE_DIR" ]]; then
        print_warning "发布目录不存在"
        return
    fi
    
    echo ""
    printf "%-35s %-15s %-20s\n" "包名" "类型" "大小"
    echo "----------------------------------------------------------------------"
    
    local total_size=0
    
    # 显示目录
    for dir in "$RELEASE_DIR"/*/; do
        if [[ -d "$dir" ]]; then
            local dirname=$(basename "$dir")
            local dir_size=$(du -sh "$dir" 2>/dev/null | cut -f1 || echo "unknown")
            printf "%-35s %-15s %-20s\n" "$dirname" "目录" "$dir_size"
        fi
    done
    
    # 显示压缩包
    for archive in "$RELEASE_DIR"/*.zip "$RELEASE_DIR"/*.tar.gz "$RELEASE_DIR"/*.tgz; do
        [[ -f "$archive" ]] || continue
        if [[ -f "$archive" ]]; then
            local archivename=$(basename "$archive")
            local archive_type=""
            if [[ "$archivename" == *.zip ]]; then
                archive_type="ZIP"
            elif [[ "$archivename" == *.tar.gz ]] || [[ "$archivename" == *.tgz ]]; then
                archive_type="TAR.GZ"
            fi
            
            # 获取文件大小
            if [[ "$OSTYPE" == "darwin"* ]]; then
                # macOS
                local size=$(stat -f%z "$archive" | awk '{
                    if ($1 > 1024*1024) printf "%.1fMB", $1/1024/1024
                    else if ($1 > 1024) printf "%.1fKB", $1/1024
                    else printf "%dB", $1
                }')
            else
                # Linux
                local size=$(stat -c%s "$archive" | awk '{
                    if ($1 > 1024*1024) printf "%.1fMB", $1/1024/1024
                    else if ($1 > 1024) printf "%.1fKB", $1/1024
                    else printf "%dB", $1
                }')
            fi
            
            printf "%-35s %-15s %-20s\n" "$archivename" "$archive_type" "$size"
        fi
    done
    
    echo "----------------------------------------------------------------------"
    echo ""
}

# ============================================================================
# 主程序
# ============================================================================

# 默认参数
CLEAN_ONLY=false
CREATE_ARCHIVES=true
GENERATE_README=true

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -c|--clean)
            CLEAN_ONLY=true
            shift
            ;;
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        -b|--build-dir)
            BUILD_DIR="$2"
            shift 2
            ;;
        -r|--release-dir)
            RELEASE_DIR="$2"
            shift 2
            ;;
        --no-compress)
            CREATE_ARCHIVES=false
            shift
            ;;
        --readme)
            GENERATE_README=true
            shift
            ;;
        -*)
            print_error "未知选项: $1"
            show_help
            exit 1
            ;;
        *)
            print_error "未知参数: $1"
            show_help
            exit 1
            ;;
    esac
done

# 显示脚本头部信息
echo ""
print_info "📦 veo 发布打包脚本"
print_info "================================================"

# 如果只是清理，执行清理后退出
if [[ "$CLEAN_ONLY" == "true" ]]; then
    clean_release
    exit 0
fi

print_info "版本: $VERSION"
print_info "构建目录: $BUILD_DIR"
print_info "发布目录: $RELEASE_DIR"
echo ""

# 检查构建目录
check_build_dir

# 检查资源文件
check_resources

# 创建发布目录
create_release_dir

# 创建所有发布包
create_all_packages

# 显示结果
show_release_results

print_success "🎉 发布包创建完成!"
print_info "发布目录: $RELEASE_DIR"

# 提示下一步操作
echo ""
print_info "💡 下一步操作:"
print_info "  上传发布包: 将 $RELEASE_DIR 中的文件上传到发布平台"
print_info "  测试发布包: 解压并测试各平台的发布包"
print_info "  清理发布: $0 --clean" 
