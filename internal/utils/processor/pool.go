package processor

import (
	"veo/internal/core/interfaces"
	"strings"
	"sync"
)

// Deprecated: ResponsePool 响应对象池当前未被使用，保留以备未来扩展；建议直接使用 fasthttp 的对象池。
// ResponsePool 响应对象池，用于减少内存分配和GC压力
type ResponsePool struct {
	pool sync.Pool
}

// NewResponsePool 创建新的响应对象池
func NewResponsePool() *ResponsePool {
	return &ResponsePool{
		pool: sync.Pool{
			New: func() interface{} {
				return &interfaces.HTTPResponse{}
			},
		},
	}
}

// AcquireResponse 从对象池获取响应对象
func (rp *ResponsePool) AcquireResponse() *interfaces.HTTPResponse {
	return rp.pool.Get().(*interfaces.HTTPResponse)
}

// ReleaseResponse 将响应对象归还到对象池
func (rp *ResponsePool) ReleaseResponse(resp *interfaces.HTTPResponse) {
	if resp == nil {
		return
	}

	// 重置对象状态，避免数据污染
	resp.URL = ""
	resp.StatusCode = 0
	resp.ContentLength = 0
	resp.ContentType = ""
	resp.ResponseHeaders = nil
	resp.RequestHeaders = nil
	resp.ResponseBody = ""
	resp.Title = ""
	resp.Server = ""
	resp.Duration = 0
	resp.IsDirectory = false

	// 归还到对象池
	rp.pool.Put(resp)
}

// 全局响应对象池实例
var globalResponsePool = NewResponsePool()

// Deprecated: AcquireResponse 当前未被使用。
// AcquireResponse 便捷函数：从全局对象池获取响应对象
func AcquireResponse() *interfaces.HTTPResponse {
	return globalResponsePool.AcquireResponse()
}

// ReleaseResponse 便捷函数：将响应对象归还到全局对象池
func ReleaseResponse(resp *interfaces.HTTPResponse) {
	globalResponsePool.ReleaseResponse(resp)
}

// Deprecated: StringBuilderPool 当前未被使用。
// StringBuilderPool 字符串构建器对象池，用于减少字符串拼接时的内存分配
type StringBuilderPool struct {
	pool sync.Pool
}

// NewStringBuilderPool 创建新的字符串构建器对象池
func NewStringBuilderPool() *StringBuilderPool {
	return &StringBuilderPool{
		pool: sync.Pool{
			New: func() interface{} {
				return &strings.Builder{}
			},
		},
	}
}

// AcquireBuilder 从对象池获取字符串构建器
func (sbp *StringBuilderPool) AcquireBuilder() *strings.Builder {
	return sbp.pool.Get().(*strings.Builder)
}

// ReleaseBuilder 将字符串构建器归还到对象池
func (sbp *StringBuilderPool) ReleaseBuilder(builder *strings.Builder) {
	if builder == nil {
		return
	}

	// 重置构建器状态
	builder.Reset()

	// 如果构建器容量过大，不归还到池中，让GC回收
	if builder.Cap() > 64*1024 { // 64KB
		return
	}

	// 归还到对象池
	sbp.pool.Put(builder)
}

// 全局字符串构建器对象池实例
var globalStringBuilderPool = NewStringBuilderPool()

// Deprecated: AcquireBuilder 当前未被使用。
// AcquireBuilder 便捷函数：从全局对象池获取字符串构建器
func AcquireBuilder() *strings.Builder {
	return globalStringBuilderPool.AcquireBuilder()
}

// ReleaseBuilder 便捷函数：将字符串构建器归还到全局对象池
func ReleaseBuilder(builder *strings.Builder) {
	globalStringBuilderPool.ReleaseBuilder(builder)
}

// Deprecated: ByteSlicePool 当前未被使用。
// ByteSlicePool 字节切片对象池，用于减少字节切片分配
type ByteSlicePool struct {
	pool sync.Pool
	size int
}

// NewByteSlicePool 创建新的字节切片对象池
func NewByteSlicePool(size int) *ByteSlicePool {
	return &ByteSlicePool{
		size: size,
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 0, size)
			},
		},
	}
}

// AcquireSlice 从对象池获取字节切片
func (bsp *ByteSlicePool) AcquireSlice() []byte {
	return bsp.pool.Get().([]byte)
}

// ReleaseSlice 将字节切片归还到对象池
func (bsp *ByteSlicePool) ReleaseSlice(slice []byte) {
	if slice == nil {
		return
	}

	// 重置切片长度但保留容量
	slice = slice[:0]

	// 如果容量过大，不归还到池中
	if cap(slice) > bsp.size*2 {
		return
	}

	// 归还到对象池
	bsp.pool.Put(slice)
}

// 全局字节切片对象池实例（4KB）
var globalByteSlicePool = NewByteSlicePool(4 * 1024)

// Deprecated: AcquireSlice 当前未被使用。
// AcquireSlice 便捷函数：从全局对象池获取字节切片
func AcquireSlice() []byte {
	return globalByteSlicePool.AcquireSlice()
}

// ReleaseSlice 便捷函数：将字节切片归还到全局对象池
func ReleaseSlice(slice []byte) {
	globalByteSlicePool.ReleaseSlice(slice)
}
