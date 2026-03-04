# resolver

基于 DoH (DNS over HTTPS) 的轻量 DNS 解析器，核心特性是 **ECS (EDNS Client Subnet)** 支持——适用于 CDN 域名的智能解析场景。

## 特性

- **DoH 解析** — 通过 HTTPS 发起 DNS 查询，避免 UDP 劫持 / 污染
- **ECS 智能解析** — 传入多个 ECS 前缀（代表不同地区出口 IP），每次查询**随机选一个**，让权威 DNS 返回就近节点
- **DialContext** — 可直接赋给 `http.Transport.DialContext`，令整个 HTTP 客户端走自定义解析
- **内置常用 DoH 端点** — Cloudflare / Google / Quad9 / DNSPod / 360

## 安装

```bash
go get github.com/dnsoa/net/resolver
```

## 快速开始

### 基本解析

```go
r, _ := resolver.New(resolver.DoHCloudflare)
ips, _ := r.LookupNetIP(ctx, "ip4", "www.example.com")
fmt.Println(ips)
```

### 带 ECS 智能解析（CDN 场景）

```go
r, _ := resolver.New(resolver.DoHDnspod,
    resolver.WithECS(
        "222.246.50.25",   // 湖南
        "42.121.2.24",     // 上海
        "116.31.0.0/16",   // 广东
    ),
    resolver.WithTimeout(3*time.Second),
)

// 每次查询随机带一个 ECS prefix，权威 DNS 返回对应区域的 CDN 节点 IP
ips, _ := r.LookupNetIP(ctx, "ip4", "cdn.example.com")
```

ECS 参数支持两种格式：
- CIDR 前缀：`"116.31.0.0/16"`
- 单个 IP（自动补掩码 IPv4 → /24，IPv6 → /56）：`"222.246.50.25"`

### 作为 HTTP 客户端的 DialContext

```go
r, _ := resolver.New(resolver.DoHDnspod,
    resolver.WithECS("222.246.50.25", "42.121.2.24"),
)

client := &http.Client{
    Transport: &http.Transport{
        DialContext: r.DialContext,
    },
}

resp, _ := client.Get("https://cdn.example.com/resource")
```

这样该 `http.Client` 所有请求的域名解析都走 DoH + ECS。

## API

### 构造

```go
func New(dohEndpoint string, opts ...Option) (*Resolver, error)
```

`dohEndpoint` 为 DoH 服务地址，包内预定义了常用端点常量：

| 常量 | 地址 |
|------|------|
| `DoHCloudflare` | `https://cloudflare-dns.com/dns-query` |
| `DoHGoogle` | `https://dns.google/dns-query` |
| `DoHQuad9` | `https://dns.quad9.net/dns-query` |
| `DoHDnspod` | `https://sm2.doh.pub/dns-query` |
| `DoH360` | `https://doh.360.cn/dns-query` |

### Option

| 函数 | 说明 |
|------|------|
| `WithECS(prefixes ...string)` | 设置 ECS 前缀列表，每次查询随机选一个 |
| `WithTimeout(d time.Duration)` | 单次查询超时，默认 5s |
| `WithHTTPTransport(rt http.RoundTripper)` | 自定义 DoH 的 HTTP Transport |
| `WithDebug(on bool)` | 开启调试日志，打印查询详情、ECS、解析结果及连接信息 |

### 方法

| 方法 | 说明 |
|------|------|
| `LookupNetIP(ctx, network, host)` | 解析域名，network: `"ip4"` / `"ip6"` / `"ip"` |
| `LookupHost(ctx, host)` | 解析域名，返回 `[]string` |
| `DialContext(ctx, network, address)` | 解析 + 拨号，可直接用于 `http.Transport` |

## 许可证

见仓库根目录 [LICENSE](../LICENSE)。
