# t3-gate

一个配合 Caddy `forward_auth` 使用的轻量 TOTP 登录网关，用 Go 编写（核心逻辑全基于标准库，仅引入 `github.com/skip2/go-qrcode` 生成绑定二维码），打包为 `scratch` 静态二进制容器。

最初用于给通过公网域名 + Tailscale 暴露的 **T3 Code** 提供干净、无浏览器原生 Basic Auth 弹窗干扰的长期会话认证，也适用于任何需要前置 TOTP 登录保护的自托管 Web 服务。

## 特性

- **极简轻量**：单文件 Go 实现，多阶段构建为 `FROM scratch` 镜像，无数据库依赖。
- **开箱即用的首次绑定**：首次访问 `/_gate/login` 自动展示二维码与手动密钥。每个浏览器通过 `HMAC-SHA256` 派生独立候选密钥，只有第一个提交有效 6 位验证码的浏览器完成绑定，其余浏览器看到的二维码自动失效。
- **TOTP 防重放与安全加固**：
  - RFC 6238 标准 6 位 TOTP，容忍 ±1 个时间步（±30 秒）时钟偏差，记录 `LastStep` 防止同一验证码重放，常量时间比对（`hmac.Equal`）。
  - 使用 `__Host-` 前缀 Cookie（`Secure`、`HttpOnly`、`SameSite=Lax`），服务端仅存储会话 Token 的 SHA-256 摘要，会话默认有效期 1 年。
  - 状态文件采用临时文件 + `fsync` + `rename` 原子写入。
  - `POST` 校验 `Origin` 头、限制表单体积、全站每分钟最多 8 次尝试、严格 CSP 与 `Cache-Control: no-store`。
- **对 SPA / API / WebSocket 友好**：
  - 浏览器页面导航未登录时返回 `303 See Other` 跳转到 `/_gate/login`；
  - API / XHR / WebSocket 请求未登录时返回 `401 Unauthorized`；
  - Caddy `forward_auth` 配置 `header_up -Authorization`，不干扰上游服务自己的 `Authorization` 鉴权头。
- **容器加固**：监听 `127.0.0.1:8787`，`read_only: true`，`cap_drop: [ALL]`。

## 快速部署

1. 克隆仓库并修改配置：
   - 编辑 [Caddyfile](./Caddyfile)：将 `t3.example.com` 改为你的域名，将 `http://100.64.0.10:3773` 改为你的上游服务地址（如 Tailscale 内网 IP 与端口）。
   - 编辑 [docker-compose.yml](./docker-compose.yml)：将 `T3_GATE_ORIGIN` 改为你的实际 HTTPS 域名（需与 `Caddyfile` 一致，否则登录提交会因 `Origin` 校验失败返回 `403`）。

2. 启动服务：

   ```sh
   docker compose up -d --build
   ```

3. 首次绑定：
   - 浏览器打开 `https://你的域名/`，会自动跳转到 `/_gate/login`。
   - 使用 Authy、1Password、Google Authenticator 等 TOTP 认证器扫描二维码（或展开「手动添加」复制密钥）。
   - 输入认证器生成的 6 位验证码并点击「完成绑定」，即完成初始化并进入目标服务。

## 环境变量

| 变量名 | 默认值 | 说明 |
| --- | --- | --- |
| `T3_GATE_ORIGIN` | `https://t3.example.com` | 允许提交登录表单的 Origin，必须与实际访问的 `https://域名` 一致 |
| `T3_GATE_DATA_DIR` | `/data/t3-gate` | 持久化目录，存放 `state.json` |

## 数据持久化与重置

- 绑定密钥、已使用时间步和会话哈希均保存在 `/data/t3-gate/state.json`，容器重建不影响已登录会话。
- 请确保宿主机 `/data/t3-gate` 目录权限受限（仅 root 可读），备份时注意保密。
- 如需重置绑定或踢出所有会话，停止容器并删除 `state.json` 后重启即可。
