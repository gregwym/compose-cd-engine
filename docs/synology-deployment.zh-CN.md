# Synology Deployer：单项目安装

目标：DS923+ / DSM 7 / Container Manager。**设置一个路径变量 → 导入 Compose 启动 → 登录 Tailscale → 注册 Passkey**。不需要 SSH、Python、手工创建子目录或修改 JSON。

> 目前提供独立 Compose 文件与容器验证；DSM 界面、真实 tailnet HTTPS 和 iPhone Face ID 仍需实机验收。适用全新安装，不自动迁移旧目录或接管现有应用。

## 安装前

- NAS 已安装 Container Manager；Mac / iPhone 已连接自己的 Tailscale。
- Tailscale 后台启用 MagicDNS、HTTPS；需要设备审批时，由你批准新设备。
- 自选专用项目目录；下面以 `/volume1/docker/my-deployer` 为例，**不是固定路径**。不改现有项目、照片、共享文件夹或 NAS 备份设置。
- 当前模板使用 Compose 长格式依赖及 `depends_on.restart`（Compose 2.17+）。DSM 若提示不支持该字段，应先更新 Container Manager，不能删掉初始化依赖继续安装。

## 1. 选择目录，设置唯一的路径变量

在 DSM File Station 创建你选定的专用项目目录，例如 `/volume1/docker/my-deployer`。在该目录创建文本文件 `.env`，内容只有一行：

```dotenv
DEPLOY_ROOT=/volume1/docker/my-deployer
```

填你自己的 **NAS 绝对路径**，不要末尾斜线；有空格时用单引号包住值。目录可以改名或换卷，不限于 `/volume1/docker/`。`DEPLOY_ROOT` 必填，没有隐藏的默认部署路径；内部 `config/`、`state/`、`runtime/`、`apps/` 和生成的应用挂载均从它派生。

Compose 必须读取这个项目目录中的 `.env`。不要把路径设成 Mac 的路径或依赖 `$PWD`；应用挂载由 NAS Docker daemon 解析，必须是宿主机实际路径。

直接使用这份 [compose.yaml](https://raw.githubusercontent.com/kurisu-agi/compose-cd-engine/main/synology/compose.yaml)：下载保存到该目录，或在 Container Manager 编辑器粘贴内容。**无需 ZIP、源码、README 或其他运行文件**；`.env` 只是你自己选择的路径配置，不含密钥。

```text
你选择的项目目录/
  .env
  compose.yaml
```

ZIP 仅是可选的 Compose + 说明书副本，不参与启动。首次安装前，目录中不应有其他安装留下的数据。Docker 预建的空目录会由初始化器接管。

## 2. 点击启动

Container Manager → **项目 → 新增**：

| 设置 | 填写 |
| --- | --- |
| 项目名称 | 自选，例如 `my-deployer` |
| 路径 | 与 `.env` 的 `DEPLOY_ROOT` 完全一致 |
| Compose | 使用 `compose.yaml`，或粘贴文件内容 |
| Web Station | 不启用 |
| 路径配置 | 读取项目目录 `.env` 的 `DEPLOY_ROOT`，不需要额外端口 |

选择创建后启动。镜像首次下载需要一些时间。无需逐个修改 Compose 挂载路径。若提示 `DEPLOY_ROOT` 未设置，先检查项目目录与 `.env`，不要删掉变量校验继续启动。

初始化容器 `init` **退出码 0 / 已停止**是正常结果，它不是常驻服务。其余服务自动启动；`approval` 和 `configure` 在你完成 Tailscale 登录前等待，不必重启整个项目。

## 3. 登录 Tailscale

Container Manager → 容器 → 本项目的 **tailscale** → **日志**。

在自己的浏览器中打开日志里的 Tailscale 登录链接，批准设备 `deployer` 加入 tailnet。不要将登录链接发进聊天。

登录成功后，程序自动读取设备的真实 `*.ts.net` 域名、生成审批配置并启动私有 HTTPS。即使实际设备名为 `deployer-1` 也不需要你复制域名到配置中。

若等待不结束，在 **configure** 日志查看原因。它会区分等待登录、尚未启用 HTTPS、域名变更等情况，不输出 peer 列表或密钥。

## 4. 注册 Passkey

打开本项目 **approval** 容器日志，找到：

- `FIRST INSTALL: open https://实际域名/enroll`
- `Single-use enrollment code ...` 后面的注册码。

iPhone 打开 Tailscale，再用 **Safari** 打开该地址，粘贴注册码并点击 **Create Passkey**，用 Face ID 完成。随后点击 **Sign in with Passkey** 登录。

注册码单次使用、10 分钟有效；未完成首次注册时日志会自动生成新码，旧码随即作废。第一次注册成功后停止自动发码，重启也不会重新开放首次注册。注册码只在你自己的 DSM 管理界面查看，不发给代理。

审批入口是 `https://实际域名/`；代理 API 是 `https://实际域名:8443`。服务不会向 NAS 局域网或公网发布端口，Funnel 默认禁用。Tailnet 内的网络可达范围由你的 Tailscale ACL / grants 决定，**默认不是“仅本人的两台设备可达”**；审批仍需 Passkey，代理 API 仍需独立密钥。

## 安装完成后

- Container Manager 中 `configure`、`runner`、`management`、`approval`、`project-verifier` 应显示健康；`tailscale` 的登录和 Serve 状态查看自身日志。**容器启动不等于 HTTPS / Passkey 实机验证完成**。
- 审批页可打开、能注册并登录 Passkey 后，才算首次安装验收完成。
- 初始应用策略保持 `enabled: false`，示例镜像仅占位，未授权任何真实应用部署。应用策略、存储范围和代理配对属于后续配置，不阻塞引擎安装。
- 代理密钥在 `config/agent-keys/openclaw.key`；不要给代理服务密钥、审批数据库或 DSM 管理员权限。连接客户端的手工参考见 [旧指南第 9 节](https://github.com/kurisu-agi/compose-cd-engine/blob/main/docs/synology-deployment-manual.zh-CN.md#9-连接-macnas--mac)，新布局下密钥位置以上述路径为准。

## 日常使用

| 操作 | 在哪里做 |
| --- | --- |
| 启停整个安装 | Container Manager 项目界面 |
| 查看入口、首次注册码 | `approval` 日志 |
| 查看登录 / HTTPS 等待原因 | `tailscale` / `configure` 日志 |
| 更新镜像 | Container Manager 拉取新镜像后重新创建项目容器；保留项目文件夹 |
| 新增恢复 Passkey | 可信管理员控制台执行现有 `--bootstrap owner`；不会自动为已有身份重开发码 |

引擎使用 `ghcr.io/kurisu-agi/compose-cd-engine:edge`，Tailscale 使用 `tailscale/tailscale:stable`，不 pin 版本或 digest。移动标签不代表自动更新，镜像发布后仍需你触发拉取和重新创建。建议整项目重建，不单独重建共享网络命名空间的 Tailscale 容器。

## 数据与恢复

安装器自动管理所选目录下的文件权限和密钥：

```text
所选项目目录/
  .env
  compose.yaml
  installation.json  # 布局标记，支持安全重试
  config/            # 分服务只读策略和独立密钥
  state/             # 身份、任务、Tailscale 登录；按服务隔离
  runtime/           # Unix sockets
  apps/              # 仅供后续批准的应用使用
```

初始化器只处理本项目，仅接收 Docker 预建的空目录；遇到无标记的既有数据、符号链接、异常权限或布局版本或已记录的根路径不匹配会停止，不覆盖。重复运行保留配置、密钥、身份和应用数据。项目根目录会改为 root 管理，避免普通账号替换策略；不递归修改现有应用文件或父目录 ACL。若 DSM ACL 导致无法访问，查看 `init` 日志，由管理员检查这个专用目录，不能扩大到共享目录递归改权限。

备份仍由 NAS 负责，安装器不创建额外 tar 快照，不删除应用媒体。保留整个安装目录，尤其 `state/approval`、`state/workspace`、`state/tailscale` 和 `config/`。不要通过删除 `state/` 来解决登录故障。域名变更会停止自动配置，不能在已有 Passkey 后静默换域名。

**已有安装只要 `DEPLOY_ROOT` 填原来的根目录即可继续使用；修改该变量不是迁移命令。** 已有数据库和应用挂载包含原始绝对路径，直接搬目录后启动会被拒绝，迁移需单独处理。

旧手工流程保留在 [历史参考](https://github.com/kurisu-agi/compose-cd-engine/blob/main/docs/synology-deployment-manual.zh-CN.md)，不是新安装步骤；旧布局迁移和数据库降级不包含在此安装包中。

路径变量与 `.env` 使用 Docker Compose 的标准插值机制，参见 [Docker 官方文档](https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/)。
