# 设计：Synology 上的受限 Compose 管理代理

本文是项目唯一的设计文档。代码与本文不一致时，以本文为准并修代码。

## 1. 目标

让 AI agent（OpenClaw）管理 NAS 上的 Docker Compose 项目，但**不给它 NAS 或 Docker 的直接访问权**：

- agent 只能调用一组固定操作；每类操作由主人用 Passkey（Face ID）批准。
- 所有项目与 DSM **Container Manager（CM）完全兼容**：agent 改过的项目，CM 里仍是同一个项目，CM 按钮照常可用。
- GitHub webhook 自动部署保留，作为"更新镜像"的另一种触发源。

不做：任意命令、任意 Docker API、`build:`、数据删除（`down -v`、prune）、NAS 备份/快照、DSM 设置。

## 2. 组件

一个 Compose 项目（`synology/compose.yaml`），三个常驻容器，外加启动前运行一次的 `prepare`：

```
OpenClaw ── 签名 HTTPS ──┐
GitHub ── webhook (可选 Funnel) ─┤
iPhone ── Passkey ───────┤
                         ▼
 tailscale ─(同一网络命名空间)─ gateway ── unix socket ── runner ── docker.sock
 tailnet HTTPS / Serve            唯一 sqlite                 network: none
                                  授权、审计、触发源            CM 项目目录读写
```

| 容器 | 权限 | 职责 |
|---|---|---|
| `tailscale` | 普通容器，userspace 模式 | tailnet HTTPS 证书、Serve 路由、可选 Funnel（仅 webhook 端口） |
| `gateway` | 无 Docker socket，无项目目录 | agent API、Passkey 审批页、webhook、镜像签名校验、**唯一的 sqlite** |
| `runner` | Docker socket，`network_mode: none` | 执行固定 Compose 操作；强制执行硬策略；无数据库 |
| `prepare` | 一次性，`network_mode: none`，只挂载 `DEPLOY_ROOT` | 把 `state/` 和 `run/` 下 deployer 自用的目录设为 root 所有、权限符合各服务要求（Tailscale 状态目录必须是 `0700`），然后退出；不删除任何内容，可重复执行 |

信任边界：
- runner 信任 gateway 的"谁被授权"判断（同一主机、只通过 root-only unix socket 通信）。
- runner **不信任** gateway 给出的内容：每次执行前独立重新校验项目身份、文件 hash 和硬策略（§6）。gateway 被攻破的最坏结果，是在硬策略范围内操作项目，而不是拿到宿主机 root。
- Docker socket 等同宿主机 root，只有 runner 持有。

## 3. Container Manager 兼容规则

1. **项目身份来自容器标签**：`com.docker.compose.project`、`.project.working_dir`、`.project.config_files`。runner 永远以
   `docker compose -p <name> --project-directory <working_dir> -f <config_files...>` 执行，不改名、不搬目录、不生成替代配置文件、不追加 override 文件。执行后标签不变。
2. **原地修改**：变更写回原 `compose.yaml` / `.env`，保持 inode、属主、权限（因此保留 Synology ACL）。写前在同目录生成 `compose.yaml.bak-<UTC时间>`（`.env` 同理），保留最近 5 份。
3. **`.env` 按 Compose 标准读取**（项目目录下），与 CM 行为一致。runner 以干净环境变量运行 compose，避免自身环境变量参与插值。
4. **操作语义对应 CM 按钮**：start=`start`，stop=`stop`，restart=`restart`，up=`up -d`，update=`pull` + `up -d`，down=`down`（不带 `-v`）。
5. **并发**：CM 可能同时被人操作。所有写操作在执行前比对批准时记录的 `compose.yaml`/`.env` hash；不一致即拒绝（`stale`），绝不覆盖 CM 里的修改。
6. **新建项目**放在 `PROJECTS_ROOT/<name>/compose.yaml`（默认 `/volume1/docker`，即 CM 默认位置）。CM 是否自动列出命令行创建的项目需 DSM 实机确认；若不列出，在 CM 中"新增 → 使用现有 compose.yaml"指向该目录一次即可，之后两边一致。
7. **语法兼容**：runner 内置 Compose v2.40，可能比 CM 自带的新。agent 写入的 yaml 应只用常见语法；DSM 实机验收需覆盖。

可管理范围：工作目录位于 `PROJECTS_ROOT` 下、配置文件位于工作目录内的项目。其他项目只读可见。deployer 自身项目（`DEPLOY_ROOT`）永远不可管理。

## 4. 授权模型

只有一种持久授权：**grant = (agent, 项目, 项目身份, 过期时间)**，表示"运维档"。其余是一次性审批。

| 档位 | 操作 | 如何获得 |
|---|---|---|
| 读 | `projects`（所有项目状态、镜像、端口）、`logs`（有界） | 配对成功即有，直到解除配对 |
| 运维 | `read`（compose.yaml 原文 + `.env` 键名）、start/stop/restart/up/update | 每项目一次 Passkey，默认 7 天，最长 30 天 |
| 变更 | 改 compose/`.env`、新建项目、down、Tailscale Serve 路由、webhook 触发源 | 每次一次 Passkey；审批页展示完整 diff 和风险项；批准即执行 |

规则：
- 审批链接是不可猜测的 capability URL；打开无需登录，**批准/拒绝需要一次 Passkey 断言**，challenge 绑定请求内容的 hash。请求内容在创建后不可变。
- 发起请求的 agent 也知道这个 ID，所以 diff、风险项和 agent 未提供的 compose 原文只给已用 Passkey 登录的主人；未登录打开变更审批页时先登录再显示批准按钮。agent 自己收到的请求视图同样不含这些内容。
- 运维 grant 记录批准时的项目身份（name/working_dir/config_files）。每次操作时 runner 比对实际标签，不一致即拒绝。
- 新建项目的审批同时签发该项目的运维 grant。
- 解除配对会撤销该 agent 的所有 grant 和待审请求。任何 grant 可在审批页单独撤销。
- `.env` 的值永远不返回给 agent；审批页对 `.env` 变更只显示键名和"新增/修改/删除"。

## 5. 流程

**安装（一次）**：CM 导入 `synology/compose.yaml` → `tailscale` 日志中的链接登录 → `gateway` 日志中的一次性码在 iPhone 注册 Passkey。

**配对**：agent 生成 Ed25519 密钥，调用 `pair`，得到审批链接；主人比对指纹后 Face ID 批准。

**托管**：`request operate <project>` → 审批页显示项目身份、可执行操作、时长 → 批准。

**变更**：agent 先 `read` 原文，修改后 `request change`（完整新 `compose.yaml` 和/或 `.env` set/unset）。runner 立即用 `docker compose config` 渲染新配置、执行硬策略并生成 diff 和风险项；违反硬策略直接拒绝，不生成审批。批准后执行：
1. 重新校验身份、文件 hash、硬策略；
2. 备份、原地写入；
3. `up -d --remove-orphans`，等待健康（§7）；
4. 失败则恢复备份并再次 `up -d`，结果为 `rolled_back`。

**更新镜像（update）**：记录当前镜像 ID → `pull` → `up -d` → 等待健康。失败时把原镜像 ID 重新打回原 tag 再 `up -d`——不改任何文件，CM 兼容。

**Webhook 触发源**：一次变更审批登记（项目、服务、GitHub 仓库/workflow/分支、镜像仓库）。之后每次 webhook（或每 30 分钟轮询）：
1. 取分支 head commit；
2. 解析 `<image>:sha-<commit>` 的平台 digest；
3. Cosign 校验签名身份 `https://github.com/<repo>/<workflow>@refs/heads/<branch>`，并校验镜像 `org.opencontainers.image.revision` 标签；
4. runner 把该服务的镜像改为 `<image>@<digest>`：若 yaml 中 `image:` 是 `${VAR}` 则改 `.env`，否则改那一行；再验证渲染结果只有该服务的 image 变化；然后 up + 健康检查，失败恢复。

webhook 密钥由 gateway 生成，只在 Passkey 登录后的主页显示。`CD_FUNNEL=1` 且存在触发源时，Funnel 只暴露 `8443` 端口（该端口只有 `/hooks/`）；不开 Funnel 时只靠轮询。

**发布到 tailnet（Serve）**：变更审批，内容为 `https://<deployer域名>:<端口> → host.docker.internal:<项目已发布的端口>`，仅 tailnet。gateway 通过 Tailscale LocalAPI 写入整份 Serve 配置（443 给主页/agent API，8443 给 webhook，其余为批准的路由），启动时也会重写一次。

## 6. 硬策略（runner 独立执行）

对**变更后完整渲染的配置**检查；违反则拒绝，不进入审批：
- `privileged: true`；`cap_add` 含 `ALL`、`SYS_ADMIN`、`SYS_MODULE`；`pid`/`userns_mode: host`；`security_opt` 含 `unconfined`；
- 挂载 Docker socket；挂载 `/`、系统目录（`/etc`、`/proc`、`/sys`、`/dev`、`/boot`、`/root`、`/usr`、`/run`、`/var/run`、`/var/lib/docker`、`/var/packages`）、卷根（`/volumeN`）、`@` 开头的系统目录、deployer 自身目录及包含它的上级目录。同样的路径规则适用于 bind 挂载、`driver_opts.device` 指向宿主路径的命名卷、`secrets`/`configs` 的 `file:`；runner 能看到的路径还按解析符号链接后的目标再查一次；
- `use_api_socket`（Compose 会注入 Docker socket）；
- `build:`。

风险项（允许，但在审批页高亮）：`network_mode: host`、其余 `cap_add`、`devices`、挂载项目目录以外的路径（bind 挂载显示读写属性）、新增或变更的端口。

`env_file`、`include`、`extends.file` 由 runner 里的 Compose 在渲染时读取，渲染结果中已不再出现，硬策略看不到它们的来源。runner 容器里 deployer 目录被一层空 tmpfs 覆盖，所以读不到 deployer 状态；读取其他项目的文件只能在审批页的 compose.yaml diff 中由主人审查（见 SECURITY.md）。

已有项目本身违反硬策略（例如 Portainer 挂了 docker.sock）时：只读操作和 start/stop/restart 可用；会重建容器的 `up`/`update` 和变更都被拒绝，需在 CM 里处理。`up`/`update` 每次执行前重新检查硬策略，因为批准后文件或符号链接可能已改变。

## 7. 健康判定

`up` 之后最多等待 `health_timeout`（默认 120 秒）：项目每个容器都满足以下之一即成功：
- 运行中，且无 healthcheck 或 healthcheck 为 `healthy`；
- 已退出、退出码 0，且重启策略为 `no`（一次性初始化容器）。

出现 `unhealthy`、非零退出、或超时即失败。

## 8. 状态

- gateway：`DEPLOY_ROOT/state/gateway/gateway.sqlite`——凭证、agent、请求、grant、任务、触发源、Serve 路由、nonce、审计（审计只追加）。
- runner：无数据库。证据是 CM 项目目录里的备份文件和 gateway 任务记录。
- gateway 重启时，处于 `running` 的任务标记为 `unknown`；agent 应重新读取项目状态，不要自动重试变更。

## 9. Agent API

`POST https://<deployer域名>/agent`，正文 JSON：
`{agent, public_key, audience, op, args, request_id, timestamp}`，请求头 `X-Agent-Signature: ed25519=<hex>`，签名对象是原始正文。时间窗 ±60 秒，`request_id` 防重放。

| op | 档位 | args |
|---|---|---|
| `pair` | — | `label` |
| `whoami` | 已配对 | — |
| `projects` | 读 | — |
| `logs` | 读 | `project`, `service?`, `tail?` (≤500) |
| `read` | 运维 | `project` |
| `start` `stop` `restart` `up` `update` | 运维 | `project`, `services?` |
| `request` | — | `kind` ∈ `operate` `change` `create` `down` `serve` `unserve` `trigger` 及对应参数 |
| `request_status` | — | `id` |
| `job` | — | `id` |

执行类操作立即返回 `job_id`；用 `job` 查询 `queued`/`running`/`success`/`failed`/`rolled_back`/`stale`/`unknown`。参考客户端：`client/cdctl.py`。

## 10. 未在实机验证的点

DSM Container Manager 对命令行创建项目的识别、CM 自带 Compose 版本、Synology ACL 下原地写入、`host.docker.internal` 在 tailscale userspace 模式下的可达性、Funnel 节点属性、iPhone Passkey。验收清单见 `docs/synology.zh-CN.md`。

## Reusable grants (2026-10-29; supersedes legacy authorization sections)

Pairing authenticates an agent; it no longer implicitly grants environment reads.
Request kind=read, project=*, permanent=true for reusable environment-wide Docker
diagnosis, including the deployer itself. projects/logs/diagnose/read use allowlisted
Docker metadata, never arbitrary host files. Environment values, commands, health
output, arbitrary labels and driver options are omitted. Logs scrub known container
environment values and common credential patterns; arbitrary application-generated
secrets remain a best-effort limitation.

Request kind=manage for one immutable project identity with boundary JSON:
{"mounts":[{"path":"/volume1/media","mode":"ro"}],"networks":["shared-edge"]}.
Mount roots and sources must exist, be canonical and visible to runner; sources
must stay under an approved root without ro-to-rw escalation. new=true authorizes
a not-yet-created project under PROJECTS_ROOT, then request create deploys it.
Read/manage accept permanent=true, otherwise days=1..30 (default seven). Repeated
change/create/down under manage return jobs without approval. Lifecycle rechecks
boundaries too. Expansion requires a replacement manage request; out-of-bound
changes fail closed. Deployer self-management remains prohibited, self read allowed.

Project-owned default-named local volumes/bridge networks are supported; existing
resources must bear the exact Compose project label, not just a matching prefix.
Foreign/external volumes and custom names/drivers/options are rejected. External
networks must be named in the approved boundary; only attachment is permitted.
Reusable configs reject capabilities/devices, host/shared namespaces, privileged,
build, sockets, hooks/providers, security overrides, secrets/configs and file-loading
Compose features before rendering. A conservative lexical YAML gate rejects
escapes/tags/aliases and file-loader keys: deliberately a narrower Compose subset,
without a parser dependency. No down -v, prune or arbitrary Docker API is exposed.

Request kind=elevated, seconds=900 (1..3600; no permanent mode) after manage.
Elevation binds to the exact manage grant. exec takes project, full container ID,
argv array and timeout (1..120 seconds). No implicit shell, privileged exec or Docker
options are accepted; explicit shell argv is permitted within elevation, without a
command whitelist. Gateway rechecks agent and grants when the job executes; runner
rechecks project identity, live container mounts/privileges, boundary and expiry
inside its lock. Output is capped at 64 KiB with exit/timeout/truncation evidence.
Containers require GNU/BusyBox timeout. This mandatory in-container wrapper bounds
ordinary commands; malicious images/commands can fork/daemonize, replace timeout or
evade termination. This is NOT a hostile-code sandbox. Expiry/revocation prevents
new execution, cannot undo commands already started. Exec inherits app credentials
and network access. Replacing manage invalidates its elevation and linked triggers.

Migration adds scope/boundary columns idempotently; existing grants become legacy,
never manage/read. Existing one-shot requests retain semantics. Existing webhook
triggers retain narrower signer-pinned image-only updates. New triggers on managed
projects bind to the exact manage grant and recheck it before applying. Repository
numeric ID, branch/workflow signer, digest/revision and image-repository checks stay.
Authenticated matching webhook payload hashes are deduplicated for seven days.
Webhooks only wake polling; current branch head is resolved independently, so stale
delivery cannot select an old digest.

Gateway.public_preview(item) is the HTTP review contract for anonymous and owner
sessions: structural safe_diff from before/after rendered config, no raw compose,
diff, env values or job outcomes. Legacy requests without safe_diff show a withheld
placeholder. Scalar values are all hidden rather than guessing which are secrets.

Official references: Docker container exec CLI, Compose volumes/networks reference,
GitHub validating webhook deliveries/best practices. Explicit resource names are
not project-scoped, hence default-name AND ownership-label checks.

Primary references: https://docs.docker.com/reference/cli/docker/container/exec/ ; https://docs.docker.com/reference/compose-file/volumes/ ; https://docs.docker.com/reference/compose-file/networks/ ; https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks

### Exec readiness handshake

Exec uses a two-phase exchange on the existing root-only runner Unix connection.
After acquiring its execution lock and validating live container identity/mounts,
runner sends a random challenge and hash of the exact request. Gateway rechecks the
active agent, exact manage grant and exact elevated grant against SQLite, then
acknowledges that challenge and hash. Runner accepts only that same-connection
acknowledgment within five seconds, checks expiry again, and dispatches exec.
Disconnect, timeout, malformed/replayed/mismatched acknowledgments fail closed.
No database is mounted into runner and no additional listening endpoint is created.
The successful readiness authorization is the execution authorization point:
revocations committed before that check prevent execution, including revocations
while the request waits for runner's lock. Revocations after authorization cannot
retroactively cancel the already-authorized command. Ordinary single-response
clients cannot execute through the socket; the handshake is mandatory.
