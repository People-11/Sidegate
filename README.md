# Sidegate

一个第三方的 **Palo Alto GlobalProtect** VPN 客户端（Windows）。单个 exe，双击即用，不装驱动、不装服务，退出后不留任何进程。

## 为什么要做这个

官方 GlobalProtect 客户端的问题：

- 要安装一块虚拟网卡，还要常驻一个系统服务（PanGPS），不用 VPN 时也一直在后台；
- 每次连接都要重新走一遍学校门户（SSO）登录。

Sidegate 的目标：

1. **即点即用、退出不残留**：不需要管理员权限，不装网卡、不装服务。退出后进程全部结束，系统代理恢复原状。
2. **尽量不用重复登录**：网关会话（有效期由网关配置决定，常见为数天）加密保存在本地，下次直接复用。过期后才走 SSO，而 SSO 在你的默认浏览器里完成，Okta 等 IdP 的登录状态会保留，通常点一下就好。

## 功能

- 仿 Cloudflare WARP 的托盘弹窗：一个大开关，点窗口外自动收起，点托盘图标弹出，右键托盘可退出。
- 用系统默认浏览器完成 SAML 登录，登录结果经 `globalprotectcallback:` 链接交回本程序。这个链接协议只在登录期间临时注册到 HKCU。
- **分流**：只有学校的网段和域名走 VPN，其余流量直连。DNS 也分流，公网域名不会发给学校的 DNS。
- 提供本地代理：HTTP `127.0.0.1:10809`、SOCKS5 `127.0.0.1:10808`。系统代理用 PAC 脚本自动设置。
- **失效安全**：即使程序被强制结束、崩溃或断电，浏览器取不到 PAC，会自动直连，上网不受影响。关机或注销时会正常恢复系统代理。
- 退出登录时会通知网关注销会话，并删除本地的会话文件和日志。

## 工作原理

```
浏览器 / 应用
   │  (PAC: 学校域名/网段 → 本地代理, 其余 DIRECT)
   ▼
本地 HTTP / SOCKS5 代理 ──(公网目标)──► 直连
   │ (学校目标)
   ▼
用户态 TCP/IP 协议栈 (gVisor)
   │  IP 包
   ▼
GlobalProtect SSL 隧道 (TLS, /ssl-tunnel-connect.sslvpn) ──► 网关
```

- **协议**：与 openconnect 的 `gpst` 实现相同。依次调用 `prelogin.esp`（取 SAML 请求）→ SAML → `login.esp`（取 authcookie）→ `getconfig.esp`（取 IP、DNS、路由）→ SSL 隧道，数据帧头 16 字节，magic 为 `0x1a2b3c4d`。
- **为什么不用虚拟网卡**：用户态协议栈把 IP 包变成普通的 socket 连接，所以不需要驱动和管理员权限。代价是只有走代理的流量才进 VPN，ping、RDP、映射网络驱动器之类用不了。
- **TLS 兼容性**：部分网关不支持 RFC 5746（安全重协商），OpenSSL 和 openconnect 会拒绝握手，Go 的 TLS 可以正常连接（重协商保持关闭）。

## 目录结构

```
core/   Go：协议、隧道、协议栈、代理、系统代理、登录
        以 -buildmode=c-archive 编译成静态库
gui/    Rust + egui：托盘弹窗界面
        build.rs 会自动编译 core/ 并链接进来，再用 windres 嵌入图标
```

两者通过 4 个 C 函数通信（`GpSend` / `GpRecv` / `GpFree` / `GpCallback`），传递的是 Tab 分隔的文本行，最终产物只有一个 exe、一个进程。

## 构建

以下命令都在 Windows **命令提示符（CMD）** 中运行。工具链来自 [MSYS2](https://www.msys2.org/) 的 MINGW64 环境。

### 1. 安装工具链

```sh
pacman -S --needed \
  mingw-w64-x86_64-go \
  mingw-w64-x86_64-rust \
  mingw-w64-x86_64-gcc \
  mingw-w64-x86_64-binutils
```

本项目验证过的版本：go 1.26.4、rust 1.96.0、gcc 16.1.0、binutils 2.46。

> 不要混用 MSVC 版的 Rust（`x86_64-pc-windows-msvc`），它无法链接 MinGW 编译的 Go 静态库。

### 2. 编译

```cmd
cd gui
cargo build --release
```

`build.rs` 会自动完成下面几步：

1. 在 `core\` 下执行 `go build -buildmode=c-archive`，生成 `libgpcore.a`（放在 Cargo 的 `OUT_DIR`）。
2. 用 `windres` 把 `icon.ico` 编译成资源对象。
3. 把两者和 Rust 代码链接成一个 exe。

产物位于 `gui\target\release\sidegate.exe`，可以复制到任意位置使用。首次编译需要下载依赖，之后增量编译大约 40 秒（主要耗时在 LTO）。

#### 发布用构建：去除本机路径

Rust 会把依赖源码的绝对路径（例如 `C:\Users\<用户名>\.cargo\registry\...`）写进二进制，用于 panic 信息，这会暴露构建机上的 Windows 用户名。Go 部分已经用 `-trimpath` 处理过。要公开分发 exe 时，请这样构建：

```cmd
cd gui
set "CARGO_ENCODED_RUSTFLAGS=--remap-path-prefix=%USERPROFILE%=~"
cargo build --release
findstr /c:"%USERNAME%" target\release\sidegate.exe >nul && echo FOUND || echo CLEAN
```

最后的检查应输出 `CLEAN`，说明 exe 里已经不含用户名。

- 用户目录前缀会被替换成 `~`。
- 这里用 `CARGO_ENCODED_RUSTFLAGS` 而不是 `RUSTFLAGS`，这样用户目录路径里有空格也能正常工作。
- 修改这个变量会触发一次全量重编译；构建完成后清空它，避免影响后续的日常构建。
- Cargo 的 `trim-paths` 配置项还没有稳定，稳定之后可以改为写进 `Cargo.toml`。

### 3. 测试

```cmd
cd core
go vet ./...
go test ./...
```

测试内容：

- 隧道帧的编解码；
- SAML 回调解析；
- GlobalProtect XML 字段提取；
- 分流 DNS 的判定；
- 退出登录后本地凭证确实被删除；
- 用户态协议栈端到端的 TCP 传输和隧道内 DNS 解析；
- 用 Windows 自带的 PAC 引擎（WinHTTP）实际执行 PAC 脚本，包括程序退出后自动直连的情况。

### 体积相关的构建选项

- **Rust**（`gui/Cargo.toml`）：`opt-level = "s"`（在本项目里比 `"z"` 小约 600 KB）、`lto`、`codegen-units = 1`、`panic = "abort"`、`strip`。
- **Go**（`gui/build.rs`）：`-trimpath -ldflags="-s -w"`。除了数据通路上的 gVisor、crypto 和 runtime，其余包都关闭内联（`-gcflags=all=-l`），这样既减小体积，又不影响吞吐。

## 运行时数据

全部存放在 `%LOCALAPPDATA%\Sidegate\`：

| 文件 | 内容 |
|---|---|
| `endpoint.txt` | 网关地址 |
| `session.bin` | 网关会话，用 DPAPI 加密，只有当前 Windows 用户能解密 |
| `log.txt` | 运行日志：只记录状态变化和错误，不含账号、内网 IP、网关地址、凭证或访问目标，可以直接附在 issue 里。退出登录时会清空 |

删除这个目录，就等于恢复成全新状态。

## 已知限制

- 只实现了 SSL 隧道，没有实现 IPsec/ESP（UDP 4501）。
- 不发送 HIP 报告；如果网关强制要求 HIP，访问可能会受限。
- 只支持 IPv4。SOCKS5 只支持 CONNECT，不支持 UDP。
- 门户和网关假定是同一台主机，会跳过门户的网关选择步骤。
- 不读取系统代理的程序（git、ssh 等）需要手动设置 SOCKS5 `127.0.0.1:10808`。

## 许可证

本项目采用 **MIT 或 Apache-2.0 双许可**，使用者可以任选其一，见 [LICENSE-MIT](LICENSE-MIT) 和 [LICENSE-APACHE](LICENSE-APACHE)。

除非你另有明确声明，否则你有意提交给本项目的任何贡献，都将按上述双许可授权，不附加任何其他条款或条件。

### 第三方组件

编译出的 exe 静态链接了以下组件。分发二进制时，请一并附上它们的许可证。

| 组件 | 许可证 |
|---|---|
| [gVisor](https://github.com/google/gvisor)（用户态 TCP/IP 协议栈） | Apache-2.0 |
| Go 标准库、[golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys) | BSD-3-Clause |
| [egui / eframe](https://github.com/emilk/egui)、[winit](https://github.com/rust-windowing/winit)、[glow](https://github.com/grovesNL/glow)、[windows-sys](https://github.com/microsoft/windows-rs) 等 Rust crate | MIT 或 Apache-2.0 |

协议实现参考了 [openconnect](https://www.infradead.org/openconnect/) 对 GlobalProtect 协议的公开文档和行为，没有使用它的代码。

## 免责声明

本项目是独立的第三方实现，与 Palo Alto Networks 没有任何关联，也未获其认可或支持。“GlobalProtect”和“Palo Alto Networks”是 Palo Alto Networks, Inc. 的商标，本文中出现这些名称仅用于说明兼容性。

请只在你有权使用的网络上使用本软件，并遵守所在机构的网络使用规定。
