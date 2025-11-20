package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"

	"veo/internal/core/config"
	"veo/internal/core/logger"
)

// extractHost 从主机字符串中提取主机名（去除端口）
// 参数 hostWithPort: 可能包含端口的主机字符串（如 "example.com:443"）
// 返回: 不含端口的主机名（如 "example.com"）
func extractHost(hostWithPort string) string {
	host, _, err := net.SplitHostPort(hostWithPort)
	if err != nil {
		// 如果没有端口或格式不正确，直接返回原始字符串
		return hostWithPort
	}
	return host
}

// ResponseCheck 本地响应检查器（从helper包迁移）
type ResponseCheck struct {
	http.ResponseWriter
	Wrote bool
}

// NewResponseCheck 创建响应检查器
func NewResponseCheck(r http.ResponseWriter) http.ResponseWriter {
	return &ResponseCheck{
		ResponseWriter: r,
	}
}

// WriteHeader 写入响应头
func (r *ResponseCheck) WriteHeader(statusCode int) {
	r.Wrote = true
	r.ResponseWriter.WriteHeader(statusCode)
}

// Write 写入响应体
func (r *ResponseCheck) Write(bytes []byte) (int, error) {
	r.Wrote = true
	return r.ResponseWriter.Write(bytes)
}

// IsTls 检查是否为TLS连接（从helper包迁移）
func IsTls(buf []byte) bool {
	if len(buf) < 3 {
		return false
	}
	return buf[0] == 0x16 && buf[1] == 0x03 && buf[2] <= 0x03
}

// wrap tcpListener for remote client
type wrapListener struct {
	net.Listener
	proxy *Proxy
}

func (l *wrapListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	proxy := l.proxy
	wc := newWrapClientConn(c, proxy)
	connCtx := newConnContext(wc, proxy)
	wc.connCtx = connCtx

	for _, addon := range proxy.Addons {
		addon.ClientConnected(connCtx.ClientConn)
	}

	return wc, nil
}

// wrap tcpConn for remote client
type wrapClientConn struct {
	net.Conn
	r       *bufio.Reader
	proxy   *Proxy
	connCtx *ConnContext

	closeMu   sync.Mutex
	closed    bool
	closeErr  error
	closeChan chan struct{}
}

func newWrapClientConn(c net.Conn, proxy *Proxy) *wrapClientConn {
	return &wrapClientConn{
		Conn:      c,
		r:         bufio.NewReader(c),
		proxy:     proxy,
		closeChan: make(chan struct{}),
	}
}

func (c *wrapClientConn) Peek(n int) ([]byte, error) {
	return c.r.Peek(n)
}

func (c *wrapClientConn) Read(data []byte) (int, error) {
	return c.r.Read(data)
}

func (c *wrapClientConn) Close() error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return c.closeErr
	}
	// log.Debugln("in wrapClientConn close", c.connCtx.ClientConn.Conn.RemoteAddr())

	c.closed = true
	c.closeErr = c.Conn.Close()
	c.closeMu.Unlock()
	close(c.closeChan)

	for _, addon := range c.proxy.Addons {
		addon.ClientDisconnected(c.connCtx.ClientConn)
	}

	if c.connCtx.ServerConn != nil && c.connCtx.ServerConn.Conn != nil {
		c.connCtx.ServerConn.Conn.Close()
	}

	return c.closeErr
}

// wrap tcpConn for remote server
type wrapServerConn struct {
	net.Conn
	proxy   *Proxy
	connCtx *ConnContext

	closeMu  sync.Mutex
	closed   bool
	closeErr error
}

func (c *wrapServerConn) Close() error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return c.closeErr
	}
	// log.Debugln("in wrapServerConn close", c.connCtx.ClientConn.Conn.RemoteAddr())

	c.closed = true
	c.closeErr = c.Conn.Close()
	c.closeMu.Unlock()

	for _, addon := range c.proxy.Addons {
		addon.ServerDisconnected(c.connCtx)
	}

	if !c.connCtx.ClientConn.Tls {
		c.connCtx.ClientConn.Conn.(*wrapClientConn).Conn.(*net.TCPConn).CloseRead()
	} else {
		// if keep-alive connection close
		if !c.connCtx.closeAfterResponse {
			c.connCtx.ClientConn.Conn.Close()
		}
	}

	return c.closeErr
}

type entry struct {
	proxy  *Proxy
	server *http.Server
}

func newEntry(proxy *Proxy) *entry {
	e := &entry{proxy: proxy}
	e.server = &http.Server{
		Addr:    proxy.Opts.Addr,
		Handler: e,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connContextKey, c.(*wrapClientConn).connCtx)
		},
	}
	return e
}

func (e *entry) start() error {
	addr := e.server.Addr
	if addr == "" {
		addr = ":http"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	logger.Infof("Listend at %v\n", e.server.Addr)
	pln := &wrapListener{
		Listener: ln,
		proxy:    e.proxy,
	}
	return e.server.Serve(pln)
}

func (e *entry) close() error {
	return e.server.Close()
}

func (e *entry) shutdown(ctx context.Context) error {
	return e.server.Shutdown(ctx)
}

func (e *entry) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	proxy := e.proxy

	prefix := fmt.Sprintf("[Proxy.entry.ServeHTTP host=%s]", req.Host)

	// 检查主机是否被允许（对于有效的代理请求）
	if req.URL.IsAbs() && req.URL.Host != "" {
		host := extractHost(req.URL.Host) // 🔧 提取主机名（去除端口）
		if !config.IsHostAllowed(host) {
			logger.Debugf("%s 主机被拒绝，拒绝代理: %s (原始: %s)", prefix, host, req.URL.Host)
			httpError(res, "Host not allowed", http.StatusForbidden)
			return
		}
	}

	// Add entry proxy authentication
	if e.proxy.authProxy != nil {
		b, err := e.proxy.authProxy(res, req)
		if !b {
			logger.Errorf("%s 代理认证失败: %s", prefix, err.Error())
			httpError(res, "", http.StatusProxyAuthRequired)
			return
		}
	}
	// proxy via connect tunnel
	if req.Method == "CONNECT" {
		e.handleConnect(res, req)
		return
	}

	if !req.URL.IsAbs() || req.URL.Host == "" {
		res = NewResponseCheck(res)
		for _, addon := range proxy.Addons {
			addon.AccessProxyServer(req, res)
		}
		if res, ok := res.(*ResponseCheck); ok {
			if !res.Wrote {
				res.WriteHeader(400)
				io.WriteString(res, "此为代理服务器，不能直接发起请求")
			}
		}
		return
	}

	// http proxy
	proxy.attacker.initHttpDialFn(req)
	proxy.attacker.attack(res, req)
}

func (e *entry) handleConnect(res http.ResponseWriter, req *http.Request) {
	proxy := e.proxy

	prefix := fmt.Sprintf("[Proxy.entry.handleConnect host=%s]", req.Host)

	// 检查主机是否被允许
	host := extractHost(req.Host) // 🔧 提取主机名（去除端口）
	if !config.IsHostAllowed(host) {
		logger.Debugf("%s 主机被拒绝，拒绝CONNECT: %s (原始: %s)", prefix, host, req.Host)
		httpError(res, "Host not allowed", http.StatusForbidden)
		return
	}

	shouldIntercept := proxy.shouldIntercept == nil || proxy.shouldIntercept(req)
	f := newFlow()
	f.Request = newRequest(req)
	f.ConnContext = req.Context().Value(connContextKey).(*ConnContext)
	f.ConnContext.Intercept = shouldIntercept
	defer f.finish()

	// trigger addon event Requestheaders
	for _, addon := range proxy.Addons {
		addon.Requestheaders(f)
	}

	if !shouldIntercept {
		// log.Debugf("begin transpond %v", req.Host)
		e.directTransfer(res, req, f)
		return
	}

	if f.ConnContext.ClientConn.UpstreamCert {
		e.httpsDialFirstAttack(res, req, f)
		return
	}

	// log.Debugf("begin intercept %v", req.Host)
	e.httpsDialLazyAttack(res, req, f)
}

func (e *entry) establishConnection(res http.ResponseWriter, f *Flow) (net.Conn, error) {
	cconn, _, err := res.(http.Hijacker).Hijack()
	if err != nil {
		res.WriteHeader(502)
		return nil, err
	}
	_, err = io.WriteString(cconn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	if err != nil {
		cconn.Close()
		return nil, err
	}

	f.Response = &Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}

	// trigger addon event Responseheaders
	for _, addon := range e.proxy.Addons {
		addon.Responseheaders(f)
	}

	return cconn, nil
}

func (e *entry) directTransfer(res http.ResponseWriter, req *http.Request, f *Flow) {
	proxy := e.proxy
	prefix := fmt.Sprintf("[Proxy.entry.directTransfer host=%s]", req.Host)

	conn, err := proxy.getUpstreamConn(req.Context(), req)
	if err != nil {
		// log.Error(err)
		res.WriteHeader(502)
		return
	}
	defer conn.Close()

	cconn, err := e.establishConnection(res, f)
	if err != nil {
		// log.Error(err)
		return
	}
	defer cconn.Close()

	transfer(prefix, conn, cconn)
}

func (e *entry) httpsDialFirstAttack(res http.ResponseWriter, req *http.Request, f *Flow) {
	proxy := e.proxy
	prefix := fmt.Sprintf("[Proxy.entry.httpsDialFirstAttack host=%s]", req.Host)

	conn, err := proxy.attacker.httpsDial(req.Context(), req)
	if err != nil {
		// log.Error(err)
		res.WriteHeader(502)
		return
	}

	cconn, err := e.establishConnection(res, f)
	if err != nil {
		conn.Close()
		// log.Error(err)
		return
	}

	peek, err := cconn.(*wrapClientConn).Peek(3)
	if err != nil {
		cconn.Close()
		conn.Close()
		// log.Error(err)
		return
	}
	if !IsTls(peek) {
		// todo: http, ws
		transfer(prefix, conn, cconn)
		cconn.Close()
		conn.Close()
		return
	}

	// is tls
	f.ConnContext.ClientConn.Tls = true
	proxy.attacker.httpsTlsDial(req.Context(), cconn, conn)
}

func (e *entry) httpsDialLazyAttack(res http.ResponseWriter, req *http.Request, f *Flow) {
	proxy := e.proxy
	prefix := fmt.Sprintf("[Proxy.entry.httpsDialLazyAttack host=%s]", req.Host)

	cconn, err := e.establishConnection(res, f)
	if err != nil {
		// log.Error(err)
		return
	}

	peek, err := cconn.(*wrapClientConn).Peek(3)
	if err != nil {
		cconn.Close()
		// log.Error(err)
		return
	}

	if !IsTls(peek) {
		// todo: http, ws
		conn, err := proxy.attacker.httpsDial(req.Context(), req)
		if err != nil {
			cconn.Close()
			// log.Error(err)
			return
		}
		transfer(prefix, conn, cconn)
		conn.Close()
		cconn.Close()
		return
	}

	// is tls
	f.ConnContext.ClientConn.Tls = true
	proxy.attacker.httpsLazyAttack(req.Context(), cconn, req)
}
