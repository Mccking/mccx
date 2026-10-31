# MccX · WARP 客户端（安卓直装，自带隧道）

把 WireGuard 官方 tunnel 库（`libwg-go.so`，就是 WireGuard App 里的同一个 Go 内核）打进 APK：
装一个包、点一下「连接」，VPN 直接起来，不依赖第二个 App。

```
dist\mccx-3.2.apk             26,355,043 字节
sha256: 647EA393DCA18B27FB1F10437DAE1E9A7E4109CF176FF7855536BD1F49E16BE1
package com.xehn.warp  versionCode 9  versionName 3.2  minSdk 24  targetSdk 33
ABI: arm64-v8a, armeabi-v7a
```

## 覆盖安装

包名仍是 `com.xehn.warp`（保证能覆盖升级），桌面显示名改为 **MccX**；同签名（证书 SHA-256 `73583643…`），直接覆盖安装即可，
已注册的 WARP 设备记录保留。

## 用法

1. 安装 APK（允许未知来源）。
2. 打开 **MccX**，点「连接」。
3. 第一次会弹系统 VPN 授权框——允许。
4. 状态变「已连接」，状态栏出现 VPN 钥匙图标。
5. 连上后自动自检：界面第二行显示 **出口 IP · WARP on · 机房**。
6. 再点一次「断开」。

首次连接约 10–20 秒（注册 + 26 个端点测速）；之后复用设备，快很多。

## 连上后怎么判断真的通了

APP 会自动请求 `https://www.cloudflare.com/cdn-cgi/trace`（这个请求也走隧道），并显示：

```
出口 104.28.x.x · WARP on · HKG (HK)
```

- `WARP on` + 出口 IP 不是本地宽带 IP → 流量确实从 WARP 出去，成功。
- `WARP off` → 隧道建立了但流量没走 WARP，需要排查。
- `自检失败：…` → 隧道内 DNS/连通性有问题。

也可以手动验证：手机浏览器打开 `https://www.cloudflare.com/cdn-cgi/trace`，看 `warp=on`。

## 3.2：mihomo 引擎（实验）

真机探测确认 lib/ 目录里的二进制可以执行（可执行 true、Mihomo Meta ... android arm64、退出码 0），所以走子进程方案，不需要 NDK。

``
VpnService 建 TUN（排除本应用 UID，避免内核自己的包回环）
  → abstract socket 传 fd 给 libmccxcore.so
  → libmccxcore 以 ExtraFiles 把 fd 放到 3 后 exec libmihomo.so
  → mihomo 按 tun.file-descriptor: 3 接管
``

- 入口：界面「隧道引擎」选 **mihomo（实验）**，默认仍是「内置 WireGuard」。
- 配置由 MihomoConfig 生成：wireguard 出站（单 peer 放在 `peers:` 列表里）、可选 amnezia-wg-option、tun 块、fake-ip DNS、`MATCH,PROXY` 规则。
- 生成的配置已用官方 mihomo `-t` 校验通过（含 AWG 参数与 `DOMAIN-SUFFIX` 规则）。
- 已知取舍：不生成 GEOIP/GEOSITE 规则——它们会让 mihomo 启动时下载 geoip.metadb，下载失败会导致整份配置初始化失败。

**未在真机验证**：fd 交接时序、mihomo 在 Android 上的 gvisor 栈、DNS 劫持。失败时切回「内置 WireGuard」即可，那条路已验证可用。

## 3.1：自动更新（云端构建 + 端内安装）

分两半，缺一不可：

### 云端：CI 跟着上游自动构建

```
.github/workflows/release.yml     每天 04:00 检查上游，有变化就构建并发布
tools/build.sh                    Linux 构建（与 build.ps1 同流程）
tools/sync_upstream.ps1           常量同步
```

- 只有 `UpstreamDefaults.java` 真的变了才构建发布；手动 `workflow_dispatch` 则强制构建。
- versionCode = `1000 + run_number`，保证单调递增（自更新靠它判断新旧）。
- 发布产物：`mccx-3.1.<run>.apk` + `update.json`（含 sha256/url/notes）。

启用需要三个动作：

1. 把本目录推到 GitHub 仓库；
2. 加 secrets：`MCCX_KEYSTORE_BASE64`（`base64 -w0 keystore.jks`）、`MCCX_KEYSTORE_PASS`——
   **必须用现有 keystore**，否则新包无法覆盖安装；
3. 把 `Updater.MANIFEST_URL` 改成
   `https://github.com/<owner>/<repo>/releases/latest/download/update.json`，重打一次包。之后就能自更新了。

### 端内：下载 → 校验 → 交给系统安装器

```
点「检查更新」→ GET update.json → versionCode 比较
  → 下载 APK 到 cache → SHA-256 校验 → PackageInstaller 会话写入 → 系统安装弹窗
```

- 不需要 FileProvider、不需要存储权限：字节直接写进安装会话；
- 系统安装确认框无法跳过（Android 的限制），用户点一下即可；
- `InstallReceiver` 负责把 `STATUS_PENDING_USER_ACTION` 里的确认界面拉起来，否则安装会静默卡住。

## 2.4 变化：跟上上游

原项目（`hezhanleiok/xehn`）还在更新，但它的 Windows 界面、mihomo 编排、Psiphon 分支在 Android 上都不存在，**代码层没法自动同步**。能自动的是它输出的"数据"：

| 层 | 能否自动 | 做法 |
|---|---|---|
| API 地址 / 版本号 / UA、MTU、keepalive、AWG junk 参数、WARP 端点池 | ✅ 全自动 | `tools/sync_upstream.ps1` 拉上游源码，正则提取，生成 `UpstreamDefaults.java` |
| 扫描/注册/配置渲染的算法 | ⚠️ 半自动 | 结构变了脚本会报错（找不到常量），届时人工对齐 |
| 界面、隧道、系统集成 | ❌ 不能 | Android 端是 Java 重写 + 官方 WireGuard 内核，与上游 GUI 无关 |

`powershell
pwsh tools/sync_upstream.ps1          # 只同步常量
pwsh tools/sync_upstream.ps1 -Check   # 只检测漂移，有变化退出码 1（可放 CI）
pwsh tools/release.ps1                # 同步 + 出包，一条命令
`

- 生成的文件带上游 commit：`UPSTREAM_COMMIT = "c319e7c…"`；APP 连接时的日志也会打 `引擎基线 xehn@c319e7c`。
- 端点池现在是 **14 个网段 × 4 个地址 = 56 个候选**（上游改了网段，重跑一次就跟着变），再加本机实测好的 2 个 162.159.204.x。
- 上游 Go 文件被重构时会直接报错停下，而不是生成一份错的常量——宁可构建失败，也不静默发行。

## 2.3 变化（针对 2.1 自检误报）

- 品牌改为 **MccX**：应用名、启动页标题、图标（圆角玻璃底 + 环形 + `Mcc` 白 / `X` 青）。
- 自检改为**握手成功之后再发起**，失败自动重试 3 次（每次间隔 3 秒），不再在握手未完成时就判死。
- 自动重连只在**确有证据**时触发：`tx > 0` 且 `rx == 0`；统计读不到时不做任何拆除，避免把能用的隧道拆了。
- 新增「重新自检」按钮；日志区固定显示 `握手 Xs 前 · rx / tx`。

## 2.2 变化（针对"隧道起来但没网"）

- 修正界面状态：之前活动里没接住 tunnel 引用，连上了仍显示「未连接」。
- 新增**端点端口选择**：2408 / 500 / 1701 / 443，选完记住；2408 不通时直接换端口再试。
- 新增**握手诊断**：连上后每 2 秒读一次 WireGuard 计数，日志出现
  握手 3s 前 · rx 812B / tx 1.2KB 表示真的通了；握手 未握手 · rx 0B / tx N 表示包发出去了但没回音。
- 12 秒没握手会自动改用默认端点 `engage.cloudflareclient.com:2408` 重试一次。
- 自检失败会回退到 `https://1.1.1.1/cdn-cgi/trace` 再试一次。
- 新增「复制日志」按钮。

### 怎么读日志

| 日志 | 含义 |
|---|---|
| `握手 2s 前 · rx 1.2KB / tx 800B` | 隧道正常，接着看出口 IP |
| `握手 未握手 · rx 0B / tx 3KB`（tx 在涨） | 包已发出但无回包：UDP 被网络掐了，或这个端点不支持 WARP |
| 换 4 个端口 + 默认端点都这样 | 当前网络（常见于国内蜂窝网）封了 WARP 的 UDP，只能换网络/走中继 |
| `自检失败：failed to connect ... from /172.16.0.2` | TUN 与路由是好的（源地址已经是 WARP 地址），问题在隧道出口 |

## 它做了什么

```
点击连接
  ├─ Warp.generate()       注册 WARP 设备（X25519 + POST/PATCH /reg）
  │                        26 个边缘 IP 做 TCP 443 测速，选最快
  │                        渲染 wg-quick 配置
  ├─ VpnService.prepare()  系统授权
  ├─ GoBackend.setState(UP, Config)
  │     ├─ 建 TUN（地址、路由 0.0.0.0/0 + ::/0、DNS 1.1.1.1、MTU 1280）
  │     ├─ wgTurnOn(tunFd, wg-userspace 配置)   ← libwg-go.so
  │     └─ protect() WireGuard 收发 socket，避免流量绕回隧道
  └─ SelfCheck              通过隧道请求 trace，确认出口
```

隧道、路由、DNS、socket 保护都由官方库完成；本项目的代码只有：WARP 注册（`Warp.java`）、
配置渲染、接线（`TunnelManager`/`WarpTunnel`）、单页 UI、自检（`SelfCheck.java`）。

## 验证状态

已在真机（用户的设备）上确认：注册、`warp_enabled`、端点扫描、TUN 建立全部走通
（日志出现 `状态：已连接` / `隧道已建立`）。

| 检查 | 结果 |
|---|---|
| X25519 vs RFC 7748（5 组向量） | 通过 |
| 真实注册 + `warp_enabled` PATCH + 端点扫描 | 通过 |
| `Config.parse()` 解析生成的配置（APK 同款解析器） | 通过 |
| 解析出的 `wg-userspace` 串（键/AllowedIPs/Endpoint/Keepalive） | 正确 |
| 真机：TUN 建立、隧道 up | 通过 |
| 真机：流量确实经 WARP 出口 | 待自检结果确认 |
| APK：431 类、`GoBackend$VpnService` 已声明、两个 ABI 的 `.so` | 通过 |
| v2+v3 签名、zipalign、证书可覆盖升级 | 通过 |

## 已知限制

- 只支持 WireGuard 协议（官方 tunnel 库不认 AmneziaWG 的 `Jc/Jmin/Jmax`）。
- 需要能访问 `api.cloudflareclient.com`；部分网络下要先挂代理注册。
- 没有按应用分流 / 自定义 DNS / 订阅等功能，目标就是「一键能用」。
- 非官方客户端，Cloudflare WARP 的使用受其服务条款约束；本项目仅供学习交流，禁止售卖。

## 构建

不依赖 Gradle：aapt2 → javac → d8 → 打包 `.so` → zipalign → apksigner。

```powershell
pwsh -File .\tools\release.ps1    # 同步上游 + 构建，产物 dist\mccx-2.4.apk
```

| 组件 | 版本 | 说明 |
|---|---|---|
| JDK | Temurin 17.0.20.1 | |
| Android SDK | platform 34 / **build-tools 35.0.0** | 34 的 d8 读不了 tunnel 库（class 文件 major 61），必须 35 |
| WireGuard tunnel | `com.wireguard.android:tunnel:1.0.20230706` | Apache-2.0，内含 `libwg-go.so`（wireguard-go，MIT） |
| androidx.collection | 1.2.0（源码编译） | tunnel 库唯一实依赖 |
| OkHttp / Okio | 3.14.9 / 1.17.5 | 注册需要 `PATCH`，平台 `HttpURLConnection` 不支持 |

```
src/com/xehn/warp/
├── Curve25519.java      X25519（RFC 7748 向量校验）
├── Warp.java            注册 / PATCH / 端点扫描 / 配置渲染（OkHttp）
├── WarpTunnel.java      交给 GoBackend 的隧道身份
├── TunnelManager.java   GoBackend 单例 + up/down
├── SelfCheck.java       连上后 tracer 自检（出口 IP / warp 状态）
└── MainActivity.java    单页 UI：状态、连接/断开、运行日志
harness/ConfigCheck.java 桌面验证：用 APK 同款解析器解析生成的配置
```








