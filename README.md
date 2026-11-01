# sing-box on Redmi AX6000

在 Redmi AX6000（小米原厂固件）上用 sing-box 给局域网设备做透明代理。

- 路由器：MediaTek MT7986（4 核 Cortex-A53），内核 5.4，只有 iptables（没有 nftables）
- sing-box：1.14.4，自己交叉编译的精简版
- 订阅转换：在 Mac 上用 `sub/sub2sb.py` 把机场订阅转成 `conf/outbounds.json`

## 目录结构

本仓库就是路由器上的 `/data/sing-box`：

```text
/data/sing-box/
├── sbctl.sh          启动脚本：起停 sing-box、配置 iptables
├── sing-box.xz       压缩后的 sing-box 二进制（不进仓库，约 9 MB）
├── geoip-cn.srs      中国 IP 规则集，用于在防火墙层面直连（sbctl.sh update_cnip 下载）
├── mac_blacklist     不走代理的设备 MAC，一行一个
├── direct_ip         不走代理的目标 IP/CIDR，一行一个
├── ui/               面板 metacubexd（不进仓库， https://github.com/MetaCubeX/metacubexd/releases/tag/v1.152.0 ）
├── conf/             sing-box 加载这里所有 .json，按文件名排序后合并
│   ├── base.json     DNS、入站、路由规则、规则集、Clash API
│   └── outbounds.json  节点和分组，由 sub2sb.py 生成（不要手改）
└── sub/              只在 Mac 上用
    ├── sub2sb.py     订阅转换脚本
    └── groups.toml   订阅地址、国家分组、策略组定义
```

`conf/` 里只能放配置文件，多出来的 `.json` 也会被合并进去，大概率导致启动失败。

运行时文件都在内存里，不写闪存：

| 路径 | 说明 |
|---|---|
| `/tmp/bin/sing-box` | 启动时从 `sing-box.xz` 解压出来 |
| `/tmp/cache.db` | sing-box 缓存（fakeip、面板选择） |
| `/var/run/sing-box.pid` | PID 文件 |

## 编译 sing-box

只编译需要的功能，减小体积：

```bash
cd ~/git/sing-box && git checkout v1.14.4
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOTOOLCHAIN=local \
go build -trimpath \
  -tags "with_quic,with_utls,with_clash_api,badlinkname,tfogo_checklinkname0" \
  -ldflags "-X 'github.com/sagernet/sing-box/constant.Version=1.14.4' $(cat release/LDFLAGS) -s -w -buildid=" \
  -o sing-box ./cmd/sing-box
xz -k sing-box        # 37 MB -> 9 MB
```

- `with_utls`：Reality 节点和 TLS 指纹需要；`with_clash_api`：面板需要；`with_quic`：hysteria2、tuic 等 QUIC 协议需要。
- 以后如果加 WireGuard 要加 `with_wireguard`，用 TUN 入站要加 `with_gvisor`，否则启动时会报 "not included in this build"。
- `xz -9e` 只能小 0.5 MB，`--arm64` 过滤器能小 1.2 MB，但路由器上要求 xz ≥ 5.4，不值得折腾，默认参数就好。

## 生成节点（Mac）

```bash
cd sub
export SUB_KUIBEN='https://...'          # 订阅地址，不进仓库，可以写进 ~/.bashrc
./sub2sb.py -o ../conf/outbounds.json    # 默认读同目录的 groups.toml
```

只依赖 Python 3.11+ 标准库。`groups.toml` 的各字段在文件里有注释，要点：

- `[[subscriptions]]`：每个机场一项。`url` 可以写成 `"env:VAR"`，从环境变量读，避免 token 进仓库。
- `[[countries]]`：按国家自动建 urltest 组，没匹配到节点的国家会跳过。
- `[[groups]]`：策略组，输出顺序就是定义顺序。`"{subscriptions}"` 和 `"{countries}"` 会展开成自动生成的组；`{ expand = "..." }` 标记决定这些组放在哪里。
- `GLOBAL`：要自己定义，并且列出所有组。metacubexd 的代理页按每个组在 `GLOBAL` 里的位置排序，没列出的组会排在最前面。不自己定义的话，sing-box 自动生成的 `GLOBAL` 会把 `route.final`（DIRECT）放在第一个。

生成后在本机检查一下再传到路由器：

```bash
sing-box check -C conf
```

## 部署到路由器

```bash
scp -O -r sbctl.sh mac_blacklist direct_ip conf root@192.168.36.1:/data/sing-box/
scp -O sing-box.xz root@192.168.36.1:/data/sing-box/
ssh root@192.168.36.1 'chmod +x /data/sing-box/sbctl.sh && /data/sing-box/sbctl.sh update_cnip'
```

`-O` 让 scp 用旧的 SCP 协议，路由器上没有 sftp-server 时需要。

## 使用

```sh
/data/sing-box/sbctl.sh start        # 解压二进制（如需）、启动、等端口监听后加防火墙规则
/data/sing-box/sbctl.sh stop         # 先删防火墙规则再停进程
/data/sing-box/sbctl.sh restart
/data/sing-box/sbctl.sh status       # 运行时长、内存占用
/data/sing-box/sbctl.sh fw_start     # 只重新加防火墙规则（比如固件重载防火墙之后）
/data/sing-box/sbctl.sh fw_stop      # 只删防火墙规则，sing-box 意外退出导致断网时用
/data/sing-box/sbctl.sh update_cnip  # 更新 geoip-cn.srs 并重新加规则
/data/sing-box/sbctl.sh watchdog     # 没在运行就启动，可以放到 cron 里
```

面板：<http://192.168.36.1:9999/ui/>

目前是开机后手动启动，没有做开机自启。

### 端口

| 端口 | 入站 | 用途 |
|---|---|---|
| 7890 | `mixed-in` | HTTP/SOCKS 代理，按规则分流 |
| 20170 | `proxy-in` | HTTP/SOCKS 代理，全部走 `❄️ 代理节点` |
| 7892 | `redirect-in` | 透明代理 TCP（redir 和 mixed 模式） |
| 7893 | `tproxy-in` | 透明代理 TCP/UDP（tproxy 和 mixed 模式） |
| 1053 | `dns-in` | 局域网 DNS 被劫持到这里 |
| 9999 | Clash API | 面板 |

改端口要同时改 `base.json` 和 `sbctl.sh` 开头的变量。

## 工作原理

### 防火墙模式

`sbctl.sh` 里的 `MODE`：

| 模式 | TCP | UDP |
|---|---|---|
| `redir` | nat 表 REDIRECT 到 7892 | 不代理（DNS 除外） |
| `tproxy` | mangle 表 TPROXY 到 7893 | 同左 |
| `mixed` | REDIRECT | TPROXY |

TPROXY 需要策略路由：打了 mark 7892 的包查路由表 100，表里只有一条 `local default dev lo`，让包交给本机的 sing-box。sing-box 自己发出的包带 `route.default_mark` 7894，两个 mark 不能相同。

所有模式下 DNS（53 端口 TCP/UDP）都在 nat 表 REDIRECT 到 1053。

不进 sing-box 的流量：

- 保留地址（内网、组播等）
- `geoip-cn.srs` 里的中国 IP，以及 `direct_ip`：启动时解出来放进 ipset `singbox_bypass4` / `singbox_bypass6`
- `mac_blacklist` 里的设备：连 DNS 劫持也跳过
- 不在 `PROXY_PORTS` 里的目标端口；但 fakeip 段 198.18.0.0/15 所有端口都代理

### DNS 和分流

- 国内域名、`my-direct`：用本机 DNS（`127.0.0.1`，即固件的 dnsmasq）解析，返回真实 IP
- 明确要代理的域名（谷歌、Telegram、YouTube、`my-proxy`、`geolocation-!cn` 等）：返回 fakeip，sing-box 拿到域名后通过代理连接
- 其他域名：先用本机 DNS 查，结果是中国 IP 就直接返回，否则走 `dns_proxy`（8.8.8.8 DoH，经代理）
- 路由兜底 `route.final` 是 `DIRECT`，没匹配到规则的流量直连

## 注意事项

### sing-box 挂了会断网

iptables 规则不会随进程退出自动删除（nftables 的 `owner` 标志要内核 5.12+）。sing-box 意外退出后，DNS 还被劫持到 1053，连国内网站也打不开。处理方法：

```sh
/data/sing-box/sbctl.sh fw_stop
```

之前拿到 fakeip 的域名，客户端可能缓存最多 10 分钟（fakeip 的 TTL 是 600 秒），这段时间内仍然打不开，可以在客户端清 DNS 缓存。
