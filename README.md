# Nimbus VPNGate Hub

多区域 **VPNGate OpenVPN** 网关栈：独立 **scanner** 负责节点测活与共享池，各区域 **worker** 只负责连接与本地代理，**Hub** 统一管理。

当前区域：

| 区域 | 容器 | 代理端口 | 说明 |
| --- | --- | ---: | --- |
| JP | `nimbus-jp` | `20001` | 日本 |
| US | `nimbus-us` | `20002` | 美国（节点常稀缺，可自动备援） |
| KR | `nimbus-kr` | `20003` | 韩国 |
| RU | `nimbus-ru` | `20004` | 俄罗斯 |
| VN | `nimbus-vn` | `20005` | 越南 |
| OTHER | `nimbus-other` | `20006` | 除 JP/US/KR/RU/VN 外的国家 |
| Hub | `nimbus-hub` | `8788` | 管理面板 |
| Scanner | `nimbus-scanner` | — | 扫描/共享池（不对外暴露代理） |

仓库：

```text
https://github.com/amymelton6886272/nimbus-vpngate
git@github.com:amymelton6886272/nimbus-vpngate.git
```

## 架构

```text
VPNGate → nimbus-scanner（测活 OpenVPN + 可选 FreeProxyDB）
        → shared_nodes / configs / shared_proxies
        → region workers（优先连 OpenVPN；不足/失败则备援）
        → 每区本地 HTTP+SOCKS5 代理 :20001–20006
        → Hub :8788 管理与节点池
```

- **OpenVPN 优先**：有可用 VPN 时连最佳节点。  
- **备援补充**：VPN 不足时列表展示 FreeProxyDB；**无可用 VPN 时自动切备援**。  
- 客户端始终使用 **区域代理端口**，不要直接拿列表里的 FreeProxyDB IP 当代理。

## 功能

- Docker Compose 多容器部署（scanner + 6 worker + hub）
- Hub 仪表盘：区域状态、连接最佳/备援、同步共享、出口检测
- 节点池页：检测状态可视化、手动复测、检测时间 / 下次周期检测
- 共享节点池瘦身（配置与元数据分离）
- 代理来源限制（可配 `PROXY_ALLOW_CIDRS`）+ 建议防火墙仅放行内网
- Hub Basic Auth（`hub/.htpasswd`，不进 Git）
- 容器间 API 使用 `X-Nimbus-Hub-Token` / `HUB_API_TOKEN`

## 快速开始

依赖：

- Linux + Docker / Docker Compose
- 主机启用 `/dev/net/tun`
- 有权限使用 `NET_ADMIN` 与 TUN 设备

```bash
git clone git@github.com:amymelton6886272/nimbus-vpngate.git
cd nimbus-vpngate

# Hub 登录密码
mkdir -p hub
htpasswd -nbB admin '你的强密码' > hub/.htpasswd
# 若无 htpasswd: apt-get update && apt-get install -y apache2-utils

# 可选：覆盖内部 API Token
cp .env.example .env
# 编辑 .env 中的 HUB_API_TOKEN

docker compose up -d --build
```

打开 Hub：

```text
http://<服务器IP>:8788/
```

使用 Basic Auth（`admin` / 你在 `.htpasswd` 里设置的密码）。

## 代理地址

同一端口同时支持 **HTTP 代理** 与 **SOCKS5**：

```text
socks5://<服务器IP>:20001  # JP
socks5://<服务器IP>:20002  # US
socks5://<服务器IP>:20003  # KR
socks5://<服务器IP>:20004  # RU
socks5://<服务器IP>:20005  # VN
socks5://<服务器IP>:20006  # OTHER
```

也可用 `http://<服务器IP>:2000x`。

**安全建议：代理端口与 Hub 仅对内网开放**（例如 `10.10.10.0/24`），不要裸奔公网。

```bash
# 示例：仅放行内网（按你的网段修改）
# ufw allow from 10.10.10.0/24 to any port 8788 proto tcp
# ufw allow from 10.10.10.0/24 to any port 20001:20006 proto tcp
```

> 旧文档中的 `21001–21006` 分区管理端口 **已不再映射**。区域 Web UI 默认不对公网暴露，请通过 Hub 操作。

## Hub 常用操作

| 操作 | 说明 |
| --- | --- |
| 触发扫描 | 让 scanner 刷新 VPNGate / 共享池 |
| 连接最佳/备援 | 有 VPN 连 VPN；无 VPN 自动备援 |
| 同步共享 / 同步并检测 | worker 拉取共享并测出口 |
| 节点池 → 复测 | 手动复测所选或全部「待检测」OpenVPN 节点 |
| 退出备援 | 关闭 FreeProxyDB 上游，可再连 OpenVPN |

节点选择大致策略：

1. 优先住宅/移动类型（若有质量字段）  
2. 再考虑延迟、质量分  
3. 失败冷却，避免死循环打坏节点  

## 配置

主配置：`docker-compose.yml`  
区域元数据：`hub/regions.yaml` / `hub/regions.json`（改完可跑校验）

```bash
python3 scripts/validate_regions.py
```

重要环境变量：

| 变量 | 说明 |
| --- | --- |
| `IS_SCANNER` | scanner 为 `true`，worker 为 `false` |
| `FORCE_COUNTRY` | 区域锁定国家（JP/US/…） |
| `EXCLUDE_COUNTRIES` | OTHER 排除的国家列表 |
| `HUB_API_TOKEN` | Hub→节点内部 Token（可用 `.env` 覆盖） |
| `CHECK_INTERVAL_SECONDS` | 扫描周期（默认约 1260 秒） |
| `LOCAL_PROXY_MAX_CONNECTIONS` | 代理最大连接数 |
| `PROXY_ALLOW_CIDRS` | 代理允许的客户端网段（可选） |
| `FREEPROXYDB_*` | 备援拉取/测活相关 |

## 仓库结构

```text
Dockerfile / docker-compose.yml
docker/entrypoint.sh
vpngate_manager.py          # scanner + workers 主逻辑
proxy_server.py / vpn_utils.py
hub/                        # Hub 静态页 + nginx + regions
scripts/validate_regions.py
install.sh                  # 可选：旧版单机安装（多区域请用 Compose）
.env.example
data/                       # 运行时数据（gitignore，仅保留 .gitkeep）
```

## 安全

- 不要提交 `hub/.htpasswd`、`data/`、`.env`
- 生产环境务必修改 `HUB_API_TOKEN` 与 Hub 密码
- 公网暴露代理端口前必须做来源限制；本项目默认假设内网使用
- `/healthz` 仅返回最小状态；详细信息走 Hub 鉴权 API

## 运维

```bash
docker compose ps
docker compose logs -f nimbus-scanner
docker compose logs -f nimbus-jp

# 改代码后
docker compose up -d --build

# 仅重建 Hub
docker compose up -d --no-deps --force-recreate nimbus-hub
```

日志建议在宿主机对 `data/*/vpngate.log` 做 logrotate（`copytruncate`，单文件上限如 100M）。

容器内健康检查：

```bash
docker exec nimbus-jp curl -sf http://127.0.0.1:8787/healthz
```

经 Hub（需 Basic Auth）：

```bash
curl -fsS -u admin:'密码' http://127.0.0.1:8788/api/jp/health
```

## 排障

| 现象 | 处理 |
| --- | --- |
| 无 `/dev/net/tun` | 主机开启 TUN；compose 需 `NET_ADMIN` + tun 设备 |
| Hub 卡片全失败 | `docker compose ps` / 查对应 worker 日志；确认 `.htpasswd` 存在 |
| 某国 0 可用节点 | VPNGate 本身波动；点「触发扫描」或等周期扫描；US 等可走备援 |
| 点备援超时 | 免费代理质量差；稍后「刷新状态」或换区；可看 worker 日志 |
| 外网狂扫代理端口 | 正常；请防火墙只放行内网，并保留 `PROXY_ALLOW_CIDRS` |

## License

见 `LICENSE`。
