package dnsresolver

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	pkg_flags "github.com/komari-monitor/komari-agent/cmd/flags"
)

var flags = pkg_flags.GlobalConfig
var (
	DNSServers = []string{
		"[2606:4700:4700::1111]:53", // Cloudflare IPv6
		"[2606:4700:4700::1001]:53", // Cloudflare IPv6 备用
		"[2001:4860:4860::8888]:53", // Google IPv6
		"[2001:4860:4860::8844]:53", // Google IPv6 备用

		"114.114.114.114:53", // 114DNS，中国大陆
		"1.1.1.1:53",         // Cloudflare IPv4
		"8.8.8.8:53",         // Google IPv4
		"8.8.4.4:53",         // Google IPv4 备用
		"223.5.5.5:53",       // 阿里DNS，中国大陆
		"119.29.29.29:53",    // DNSPod，中国大陆
	}

	// CustomDNSServer 自定义DNS服务器，可以通过命令行参数设置
	CustomDNSServer string

	httpClientMu sync.Mutex
	httpClients  = make(map[httpClientKey]*http.Client)
)

// happyEyeballsDelay lets an unavailable address family fall back quickly
// without sending duplicate application requests.
const happyEyeballsDelay = 250 * time.Millisecond

type httpClientKey struct {
	timeout          time.Duration
	ignoreUnsafeCert bool
	preferIPVersion  string
}

// SetCustomDNSServer 设置自定义DNS服务器
func SetCustomDNSServer(dnsServer string) {
	if dnsServer == "" {
		return
	}
	CustomDNSServer = normalizeDNSServer(dnsServer)
}

// normalizeDNSServer 将输入的 DNS 服务器字符串规范化为 host:port 形式：
// - IPv6 地址自动加方括号并补全端口 :53（若未提供）
// - IPv4/域名未提供端口时补全 :53
func normalizeDNSServer(s string) string {
	s = strings.TrimSpace(s)
	// 已是 [ipv6]:port 或 host:port 形式
	if (strings.HasPrefix(s, "[") && strings.Contains(s, "]:")) || (strings.Count(s, ":") == 1 && !strings.Contains(s, "]")) {
		return s
	}
	// 纯 IPv6（未加端口/括号）
	if strings.Count(s, ":") >= 2 && !strings.Contains(s, "]") {
		return "[" + s + "]:53"
	}
	// 其它情况：若未包含端口则补 53
	if !strings.Contains(s, ":") {
		return s + ":53"
	}
	return s
}

// getCurrentDNSServer 获取当前要使用的DNS服务器
func getCurrentDNSServer() string {
	if CustomDNSServer != "" {
		return CustomDNSServer
	}
	// 如果没有设置自定义DNS，返回空字符串，表示应使用系统默认解析器
	return ""
}

// GetCustomResolver 返回一个解析器：
// - 若设置了自定义 DNS：使用该服务器（并在失败时尝试内置列表作为兜底）。
// - 若未设置自定义 DNS：返回系统默认解析器（不使用内置列表）。
func GetCustomResolver() *net.Resolver {
	// 未设置自定义 DNS，直接使用系统默认解析器
	if getCurrentDNSServer() == "" {
		return net.DefaultResolver
	}

	// 设置了自定义 DNS，则构造使用自定义 DNS 的解析器
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 10 * time.Second}

			// 优先使用自定义 DNS 服务器
			dnsServer := getCurrentDNSServer()
			if dnsServer != "" {
				if conn, err := d.DialContext(ctx, "udp", dnsServer); err == nil {
					return conn, nil
				}
			}
			log.Printf("Custom DNS server %s is unreachable, trying fallback servers", dnsServer)
			// 如果自定义DNS不可用，则尝试内置列表作为兜底
			for _, server := range DNSServers {
				if server == dnsServer {
					continue
				}
				if conn, err := d.DialContext(ctx, "udp", server); err == nil {
					return conn, nil
				}
			}

			return nil, fmt.Errorf("no available DNS server")
		},
	}
}

// buildTransport 构建带有自定义解析/拨号策略的 HTTP 传输层，可注入 TLS 配置
func buildTransport(timeout time.Duration, tlsConfig *tls.Config) *http.Transport {
	return buildTransportWithPreference(timeout, tlsConfig, "")
}

func buildTransportWithPreference(timeout time.Duration, tlsConfig *tls.Config, preferIPVersion string) *http.Transport {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	customResolver := GetCustomResolver()
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := customResolver.LookupHost(ctx, host)
			if err != nil {
				return nil, err
			}
			return dialResolved(ctx, network, ips, port, timeout, preferIPVersion)
		},
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   4,
		MaxConnsPerHost:       8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsConfig,
		ForceAttemptHTTP2:     true,
	}
}

func GetHTTPClient(timeout time.Duration) *http.Client {
	return getHTTPClient(timeout, "")
}

// GetHTTPClientWithPreference 返回一个使用自定义解析器的 HTTP 客户端。
// preferIPVersion 为 "4" 或 "6" 时固定使用对应优先级；为空/auto 时启用双栈竞速。
func GetHTTPClientWithPreference(timeout time.Duration, preferIPVersion string) *http.Client {
	return getHTTPClient(timeout, normalizeIPVersionPreference(preferIPVersion))
}

func getHTTPClient(timeout time.Duration, preferIPVersion string) *http.Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	key := httpClientKey{timeout: timeout, ignoreUnsafeCert: flags.IgnoreUnsafeCert, preferIPVersion: preferIPVersion}
	httpClientMu.Lock()
	defer httpClientMu.Unlock()
	if client := httpClients[key]; client != nil {
		return client
	}
	client := &http.Client{
		Transport: buildTransportWithPreference(timeout, &tls.Config{
			InsecureSkipVerify: flags.IgnoreUnsafeCert,
		}, preferIPVersion),
		Timeout: timeout,
	}
	httpClients[key] = client
	return client
}

// GetNetDialer 返回一个使用自定义DNS解析器的网络拨号器
func GetNetDialer(timeout time.Duration) *net.Dialer {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	return &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		Resolver:  GetCustomResolver(),
	}
}

// GetDialContext 返回一个自定义 DialContext：
// - 使用自定义解析器解析主机名
// - 自动模式使用 Happy Eyeballs，同时兼容纯 IPv4/纯 IPv6 主机
func GetDialContext(timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return GetDialContextWithPreference(timeout, "")
}

// GetDialContextWithPreference 返回一个可显式指定 IPv4/IPv6 优先级的 DialContext。
// preferIPVersion 为 "4" 或 "6" 时固定优先对应地址；为空/auto 时启用双栈竞速。
func GetDialContextWithPreference(timeout time.Duration, preferIPVersion string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	resolver := GetCustomResolver()
	preferIPVersion = normalizeIPVersionPreference(preferIPVersion)

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		// 为解析设置一个带超时的子 context，避免整体拨号过快超时
		lookupCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		ips, err := resolver.LookupHost(lookupCtx, host)
		if err != nil {
			return nil, err
		}

		return dialResolved(ctx, network, ips, port, timeout, preferIPVersion)
	}
}

func normalizeIPVersionPreference(preferIPVersion string) string {
	preferIPVersion = strings.ToLower(strings.TrimSpace(preferIPVersion))
	if preferIPVersion == "4" || preferIPVersion == "6" {
		return preferIPVersion
	}
	return ""
}

func sortIPsByPreference(ips []string, preferIPVersion string) {
	preferIPVersion = normalizeIPVersionPreference(preferIPVersion)
	if preferIPVersion == "" {
		return
	}

	preferred := make([]string, 0, len(ips))
	others := make([]string, 0, len(ips))
	for _, ip := range ips {
		parsedIP := net.ParseIP(ip)
		isIPv4 := parsedIP != nil && parsedIP.To4() != nil
		isIPv6 := parsedIP != nil && parsedIP.To4() == nil
		if (preferIPVersion == "4" && isIPv4) || (preferIPVersion == "6" && isIPv6) {
			preferred = append(preferred, ip)
		} else {
			others = append(others, ip)
		}
	}
	n := copy(ips, preferred)
	copy(ips[n:], others)
}

type dialResult struct {
	conn net.Conn
	err  error
}

// dialResolved establishes one connection to a set of resolved addresses.
// Explicit 4/6 preferences remain deterministic. Auto mode starts IPv6 and
// then IPv4 (with a short stagger), so a broken IPv6 route cannot block IPv4.
func dialResolved(ctx context.Context, network string, ips []string, port string, timeout time.Duration, preferIPVersion string) (net.Conn, error) {
	ordered := deduplicateIPs(ips)
	if len(ordered) == 0 {
		return nil, fmt.Errorf("failed to resolve any address")
	}
	preferIPVersion = normalizeIPVersionPreference(preferIPVersion)
	if preferIPVersion != "" {
		sortIPsByPreference(ordered, preferIPVersion)
		var lastErr error
		for _, ip := range ordered {
			conn, err := dialOne(ctx, network, ip, port, timeout)
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, fmt.Errorf("failed to dial to any of the resolved IPs: %w", lastErr)
	}

	ordered = happyEyeballsOrder(ordered)
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan dialResult, len(ordered))
	for index, ip := range ordered {
		go func(index int, ip string) {
			if index > 0 {
				timer := time.NewTimer(time.Duration(index) * happyEyeballsDelay)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-dialCtx.Done():
					results <- dialResult{err: dialCtx.Err()}
					return
				}
			}
			conn, err := dialOne(dialCtx, network, ip, port, timeout)
			results <- dialResult{conn: conn, err: err}
		}(index, ip)
	}

	var lastErr error
	for range ordered {
		select {
		case result := <-results:
			if result.err == nil {
				cancel()
				return result.conn, nil
			}
			lastErr = result.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("failed to dial to any of the resolved IPs: %w", lastErr)
}

func dialOne(ctx context.Context, network, ip, port string, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second, DualStack: true}
	return dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
}

func deduplicateIPs(ips []string) []string {
	seen := make(map[string]struct{}, len(ips))
	result := make([]string, 0, len(ips))
	for _, ip := range ips {
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		result = append(result, ip)
	}
	return result
}

func happyEyeballsOrder(ips []string) []string {
	v4 := make([]string, 0, len(ips))
	v6 := make([]string, 0, len(ips))
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed != nil && parsed.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	ordered := make([]string, 0, len(ips))
	for len(v4) > 0 || len(v6) > 0 {
		if len(v6) > 0 {
			ordered = append(ordered, v6[0])
			v6 = v6[1:]
		}
		if len(v4) > 0 {
			ordered = append(ordered, v4[0])
			v4 = v4[1:]
		}
	}
	return ordered
}
