# Synology 安装

适用：DSM 7.2+、Container Manager、Tailscale。全程不需要 SSH。设计说明见 [design.md](design.md)。

## 1. 准备

- Tailscale 管理后台：启用 **MagicDNS** 和 **HTTPS Certificates**。
- 选一个 deployer 自己的目录，例如 `/volume1/docker/deployer`（下文称 `DEPLOY_ROOT`）。
- 确认你的 CM 项目都在同一个根目录下，默认 `/volume1/docker`（下文称 `PROJECTS_ROOT`）。不在这个目录下的项目只能查看，不能管理。

## 2. 导入项目

1. File Station 中创建 `DEPLOY_ROOT` 目录，放入两个文件：
   - [`synology/compose.yaml`](../synology/compose.yaml)
   - `.env`，内容：
     ```dotenv
     DEPLOY_ROOT=/volume1/docker/deployer
     PROJECTS_ROOT=/volume1/docker
     ```
     runner 只挂载 `PROJECTS_ROOT`（其中的 `DEPLOY_ROOT` 被空 tmpfs 覆盖）。项目的媒体目录（如
     `/volume1/download/bangumi`）由 Docker 按项目的 Compose 文件挂载，runner 不挂载、不读取也不验证；
     授权按 Compose 中写的路径生效（不检查符号链接）。
2. Container Manager → 项目 → 新增 → 路径选 `DEPLOY_ROOT` → 使用现有 compose.yaml → 启动。

会先运行一次 `prepare`（初始化 deployer 自己的状态和 socket 目录，完成后显示"已退出"，属正常），再启动三个容器：`tailscale`、`gateway`、`runner`。不需要 SSH 建目录或改属主。

## 3. 登录 Tailscale

打开 `tailscale` 容器日志，点击其中的登录链接，把设备加入你的 tailnet（设备名 `deployer`）。
`gateway` 日志随后显示 `Gateway ready: https://deployer.<你的tailnet>.ts.net/`。

## 4. 注册 Passkey

`gateway` 日志中会出现：

```
FIRST PASSKEY: open https://deployer.xxx.ts.net/enroll on your iPhone and enter code XXXX (valid 10 minutes)
```

用已登录同一 tailnet 的 iPhone 打开这个地址，输入注册码，用 Face ID 创建 Passkey。注册码不要发给 agent。之后可以在主页"Passkey"里添加更多设备。

## 5. 连接 OpenClaw

在运行 OpenClaw 的机器上（需要已加入同一 tailnet，Python 3.10+，`pip install cryptography`）：

```sh
python3 cdctl.py init https://deployer.xxx.ts.net
python3 cdctl.py pair --label openclaw --wait
```

把输出的链接在 iPhone 上打开，比对指纹后 Face ID 批准。用法见 [client/SKILL.md](../client/SKILL.md)。

## 6. 可选：webhook 自动更新

触发源有三种（`client/SKILL.md` 有命令示例），每个都要 Passkey 批准一次：

| 方式 | 适用 | 做什么 |
|---|---|---|
| pin（不带 `--tag`） | 自己的 GitHub 仓库 | 找分支 head 的 `sha-<提交>` 镜像，把该服务的镜像改成 `镜像@digest`（改 compose.yaml/.env） |
| pull + GitHub（`--tag latest`） | 自己的 GitHub 仓库 | compose.yaml 保持 `镜像:latest`；标签指向的镜像须由该 workflow/分支签名；pull + up |
| pull + registry（`--source registry --tag latest`） | 上游镜像，如 RSSHub、RustDesk | 标签 digest 变化就 pull + up；无签名校验 |

pull 方式：
- 项目里所有用这个 `镜像:标签` 的服务一起 pull、一起重建（例如 web 和 worker 共用一个镜像）。
- 不改文件。文件与批准触发源时**完全一致**时不重新审查（批准页会列出项目超出常规限制的配置，比如挂载 docker.sock）；文件改过之后，每次更新都按硬策略/管理边界重新检查，不通过就拒绝，需要重新申请触发源。
- 拉取后核对镜像 digest 是 gateway 校验过的那个；不是则恢复旧镜像、不重建。
- 健康检查失败自动恢复旧镜像。失败过的同一个 digest，轮询不再重试；webhook 会重试。
- 拉取前要求 `PROJECTS_ROOT` 所在磁盘剩余空间 ≥ `CD_MIN_FREE_MB`（默认 1024）+ 2 倍镜像压缩大小；设为 0 关闭。
- 轮询标签只用 HEAD 请求（Docker Hub 不计入拉取次数）。

没有 webhook 也能用：deployer 每 30 分钟轮询一次。webhook 只是让它立即检查。

### webhook 怎样到达 deployer

主页"自动部署触发源"里可以看到 webhook 地址和密钥。GitHub 仓库 Settings → Webhooks：Content type 选 `application/json`，事件选 Workflow runs。registry 触发源可接受任何带正确 `X-Hub-Signature-256` 的 JSON POST（可选）。

两种公开方式，**只公开 `/hooks/`**；主页、审批和 agent API 始终只在 tailnet 内：

- **Tailscale Funnel**（NAS 推荐）：Tailscale 访问策略中给该设备 `funnel` 节点属性；`.env` 加 `CD_FUNNEL=1` 并重启项目。Funnel 只开放 `8443` 端口的 `/hooks/`。
- **已有反向代理**（VPS）：用 `synology/compose.hooks.yaml` 叠加启动：

  ```sh
  # .env 追加
  CD_HOOK_URL=https://hooks.example.com
  # CD_HOOK_PUBLISH=127.0.0.1:18791   默认值，只监听本机
  docker compose -f compose.yaml -f compose.hooks.yaml up -d
  ```

  反向代理只把 `https://hooks.example.com/hooks/` 转发到 `http://127.0.0.1:18791/hooks/`。该端口上只有 `/hooks/`，每个请求都要 HMAC 签名；它只能唤醒检查，选哪个镜像由 deployer 自己向 GitHub/镜像仓库查询决定。

pin 方式和 pull + GitHub 方式的镜像要求：
- 由该仓库、该 workflow、该分支的 GitHub Actions 用 Cosign keyless 签名；
- pin：tag 为 `sha-<完整提交哈希>`（`docker/metadata-action` 的 `type=sha,format=long`），并带 `org.opencontainers.image.revision=<提交哈希>` 标签；
- pull：CI 推送 `latest`（或你指定的标签）即可，revision 标签只用于显示。

### 在 VPS 上使用

VPS 不是 Synology，但 deployer 只依赖 Docker + Compose：
- `.env` 设 `PROJECTS_ROOT` 为项目所在目录（如 `/opt/apps`），`DEPLOY_ROOT` 为 deployer 自己的目录（如 `/opt/deployer`），用 `docker compose up -d` 启动；
- 项目必须用 `docker compose` 在 `PROJECTS_ROOT/<项目>/` 下启动过（deployer 从容器标签识别项目），compose 文件在项目目录内；
- 首次 Tailscale 登录、Passkey 注册同第 3、4 节。

## 7. 升级与备份

- 升级：Container Manager 中对 deployer 项目执行"构建"（拉取新镜像并重建）。
- 备份 `DEPLOY_ROOT/state/`。从旧备份恢复可能让已撤销的授权复活，恢复后请在主页检查授权列表。
- Tailscale 设备名改变后，已注册的 Passkey 失效，需要清空 `state/gateway` 重新注册。

## 实机验收清单

这些在 CI 中无法验证，首次部署时请逐项确认：

- [ ] CM 中 `prepare` 退出码为 0，三个容器正常运行；deployer 项目在 agent 的项目列表里显示为不可管理。
- [ ] iPhone Safari 能注册并使用 Passkey。
- [ ] agent 修改某项目后，CM 中仍是同一个项目，可正常启动、停止、构建；编辑器里是新内容。
- [ ] 修改后 `compose.yaml` 的属主、权限、File Station 中的 ACL 不变；旁边有 `.bak-` 备份。
- [ ] agent 新建的项目在 CM 中可见（或经"新增 → 使用现有 compose.yaml"导入一次后可见）。
- [ ] CM 自带的 Compose 能打开 agent 写入的 yaml（deployer 内置 Compose v2.40）。
- [ ] Serve 路由 `https://deployer.xxx.ts.net:<端口>` 能访问到应用（`host.docker.internal` 可达）。
- [ ] 开 Funnel（或经反向代理）时 GitHub webhook 投递返回 202。
- [ ] pull 触发源：上游标签更新后服务被重建；文件被改动后变为重新检查。
