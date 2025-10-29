package shared

import (
    "bytes"
    "compress/flate"
    "compress/gzip"
    "io"
    "strings"
    "veo/internal/core/logger"

    "github.com/andybalholm/brotli"
)

// DecompressByEncoding 根据 Content-Encoding 对响应体进行解压缩。
// 参数：
//   - data: 原始字节串
//   - contentEncoding: Content-Encoding 头部（大小写不敏感）
// 返回：若解压成功返回解压后的字节串，否则返回原始 data。
func DecompressByEncoding(data []byte, contentEncoding string) []byte {
    if len(data) == 0 {
        return data
    }
    enc := strings.ToLower(contentEncoding)
    if enc == "" {
        return data
    }
    if strings.Contains(enc, "gzip") {
        r, err := gzip.NewReader(bytes.NewReader(data))
        if err != nil {
            logger.Debugf("gzip解压失败: %v, 返回原始内容", err)
            return data
        }
        defer r.Close()
        out, err := io.ReadAll(r)
        if err != nil {
            logger.Debugf("gzip读取失败: %v, 返回原始内容", err)
            return data
        }
        logger.Debugf("gzip解压成功: %d -> %d bytes", len(data), len(out))
        return out
    }
    if strings.Contains(enc, "deflate") {
        r := flate.NewReader(bytes.NewReader(data))
        defer r.Close()
        out, err := io.ReadAll(r)
        if err != nil {
            logger.Debugf("deflate读取失败: %v, 返回原始内容", err)
            return data
        }
        logger.Debugf("deflate解压成功: %d -> %d bytes", len(data), len(out))
        return out
    }
    if strings.Contains(enc, "br") {
        r := brotli.NewReader(bytes.NewReader(data))
        out, err := io.ReadAll(r)
        if err != nil {
            logger.Debugf("brotli读取失败: %v, 返回原始内容", err)
            return data
        }
        logger.Debugf("brotli解压成功: %d -> %d bytes", len(data), len(out))
        return out
    }
    logger.Debugf("不支持的压缩格式: %s", enc)
    return data
}

