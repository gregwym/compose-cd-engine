# Synology Deployer 部署方案

目标：在 DS923+ 的 Container Manager 中运行完整部署引擎，通过独立 Tailscale 容器提供私有 HTTPS；不配置 NAS 层的 Serve 或 DSM 反向代理。

**状态：部署方案，尚未在 DSM 实机验收。仓库尚无配套的完整单文件 Compose 和初始化脚本；现有叠加模板不能直接作为本方案粘贴安装。**

## 部署结构

```text
iPhone / Mac（连接 Tailscale）
  → deployer 的 Tailscale 容器：HTTPS 443 / 8443
  → Approval / Management
  → Runner（通过私有 Unix socket 通信，无网络）
  → NAS Docker socket
  → 应用容器（与引擎同级，不是 Docker 套 Docker）
```

- Tailscale、Approval、Management 共享网络命名空间；Serve 转发到本地 HTTP 服务。
- Tailscale 使用 userspace 模式，不使用 host 网络、privileged、TUN 或额外网络 capabilities。
- 不发布宿主机端口，不启用 Funnel、子网路由或出口节点；仅 tailnet 可访问。
- 只有 Runner 挂 Docker socket；Tailscale 不持有引擎密钥、应用数据或 Docker 权限。
- 保留 Receiver、Verifier 和 Project Verifier 的既有职责；不开放 webhook 入口。
- NAS 原有 Tailscale 可继续运行；容器以独立设备 `deployer` 加入 tailnet。

## 部署步骤

| 步骤 | 做什么 | 目的 |
| --- | --- | --- |
| 1. 检查环境 | 确认 DSM 7、Container Manager、Docker/Compose 兼容性、amd64 平台、可用资源；tailnet 开启 MagicDNS 和 HTTPS。 | 排除宿主机兼容问题。 |
| 2. 固定版本 | 选择源码版本和引擎、Tailscale 镜像 digest；按可信发布身份验证引擎签名。 | 不依赖 `latest`，保留可回退版本。 |
| 3. 初始化目录 | 在 `/volume1/compose-cd` 放配置、密钥、状态；另建 root 管理的工作区、应用配置和测试下载目录。按服务 UID/GID 设置权限。 | 隔离引擎、应用和现有 NAS 数据；不改现有共享目录 ACL。 |
| 4. 生成密钥 | 分别生成管理、代理 HMAC、审批 RPC、验签 RPC 密钥；写入受限文件，不写入 Git 或 Compose。 | 分离管理员、代理和服务身份。 |
| 5. 设置策略 | 配置允许的镜像、签名身份、存储别名、端口、出站网络和资源额度；先保持 `enabled: false`。 | 安装引擎不等于开放应用部署。 |
| 6. 导入 Compose | 在 Container Manager 创建 `compose-cd` 项目，导入完整单文件 Compose，挂载已初始化目录与 Serve 配置。 | 一次启动引擎和独立 Tailscale 入口。 |
| 7. 接入 tailnet | 首次通过管理员登录或短期认证密钥加入；持久化 Tailscale 身份，确认实际设备域名。 | 重启保留同一设备，不依赖 NAS 层 Serve。 |
| 8. 验证 HTTPS | Serve 的 443 转发到 `127.0.0.1:18793`，8443 转发到 `127.0.0.1:18792`；将 Approval 的 `origin`、`rp_id` 设为实际 HTTPS 域名。 | 提供 Passkey 安全上下文；NAS 无需开放对应端口。 |
| 9. 限制访问 | tailnet 策略仅允许管理员设备访问 443、Mac 客户端访问 8443；验证其他设备和原始 HTTP 端口不能访问。 | 防止绕过 HTTPS 和访问控制。 |
| 10. 注册 Passkey | 管理员在 NAS 独立终端生成一次性注册码，用 iPhone Safari 注册，并添加恢复凭据。 | 建立审批身份；注册码和 Passkey 不交给代理。 |
| 11. 连接 Mac | 仅将代理 HMAC 密钥安全复制到 Mac，设为 0600；通过 `scripts/agent.py` 连接 8443 API。 | 日常提交计划、查询状态，无需 NAS SSH 或 DSM 密码。 |
| 12. 测试后启用 | 配置真实测试镜像及签名、探针和独立目录，再启用 Policy；验证审批部署、重启续跑、撤销阻断、失败保护和退役保留数据。 | 验收通过后才接 AutoBangumi、下载器和真实媒体目录。 |

示例入口（以实际分配的域名为准）：

```text
审批：https://deployer.<tailnet>.ts.net
API：https://deployer.<tailnet>.ts.net:8443
```

审批 `origin` 使用完整 HTTPS 地址，`rp_id` 只填域名。注册后保持域名稳定；Serve 必须保留外部 Host。

## 安装包仍需补齐

1. **完整单文件 Compose**：包含上述服务、固定镜像、同路径 Runner 挂载、资源限制及启动依赖；不能只是叠加文件。
2. **一次性初始化脚本**：检查环境，创建目录、权限、独立密钥及初始策略；遇到已有状态停止，不能覆盖。
3. **Tailscale Serve 配置**：以 `TS_SERVE_CONFIG` 加载，挂载配置目录；设置 `TS_STATE_DIR`、`TS_AUTH_ONCE=true` 和 `TS_USERSPACE=true`，持久化非临时设备身份。
4. **HTTP 监听收紧**：当前 `management/gateway.py`、`authorization/server.py` 均绑定 `0.0.0.0`；此方案须支持仅绑定共享命名空间的 `127.0.0.1`，同时拒绝 tailnet 对 18792/18793 的直连。仅不写 `ports` 不能证明入口隔离。
5. **验收检查**：检查最终 Compose 无宿主机端口、Runner 无网络、密钥挂载分离；实测 HTTPS、Host、拒绝访问和 Tailscale 重建后关联服务恢复。

## 维护与恢复

- NAS 管理备份：保存策略、密钥、Approval 数据库、部署工作区及 Tailscale 身份；不把备份权限交给引擎。
- 升级前保留旧 digest 和状态；数据库变更需确认恢复方法，不承诺自动降级。
- 停止引擎只关闭管理入口，不自动停止已部署应用；不使用 prune 或删除数据卷。
- Tailscale 容器故障会中断管理入口，不中断现有应用；重建它后须检查共享网络的服务，必要时一并重建。
- Docker socket 仍等同宿主机管理权限；Policy 和 Passkey 约束请求，不能隔离被攻破的 Runner。

## 参考

- [身份、目录权限、注册与客户端](agent-authorization.md)
- [应用部署策略与同路径挂载](project-provisioning.md)
- [旧版 DSM 反向代理方案（不是本方案）](synology.md)
- [Tailscale Docker sidecar](https://tailscale.com/blog/docker-tailscale-guide)
- [Tailscale 容器配置参数](https://tailscale.com/docs/features/containers/docker/docker-params)
