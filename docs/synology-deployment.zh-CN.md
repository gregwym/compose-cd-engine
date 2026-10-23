# Synology Deployer 部署指南

目标：DS923+ / DSM 7 / Container Manager，独立 Tailscale 容器提供私有 HTTPS；不用 NAS 层 Serve 或 DSM 反向代理。

**适用全新安装。下列命令安装引擎和 Passkey，不接管现有应用。已验证固定镜像的配置生成与两个 HTTP 服务启动；尚未在 DSM 实机验收。**

## 步骤总览

| 步骤 | 做什么 | 目的 |
| --- | --- | --- |
| 1 | 检查环境 | 确认 amd64、Compose、tailnet HTTPS。 |
| 2 | 下载固定版本、验签 | 固定源码与镜像，避免 `latest` 漂移。 |
| 3 | 创建目录和密钥 | 分离配置、身份、状态和应用数据。 |
| 4 | 生成策略、Serve 和完整 Compose | 七个服务一次导入；HTTP 只监听回环地址。 |
| 5 | 启动 Tailscale 并登录 | 获取独立设备的真实域名。 |
| 6 | 写入域名并启动引擎 | 让 Passkey 与 HTTPS 域名一致。 |
| 7 | 限制并验证访问 | 只开放 tailnet HTTPS，不暴露原始 HTTP。 |
| 8 | 注册 Passkey | 用 iPhone 建立审批身份。 |
| 9 | 连接 Mac | 只给客户端代理密钥，不给 NAS 管理权限。 |
| 10 | 配置实际应用策略 | 明确镜像、探针、存储与资源边界。 |
| 11 | 审批部署与验收 | 先测独立目录，再接真实应用。 |
| 12 | 维护与恢复 | 保留身份、状态和旧版本，不删除应用数据。 |

```text
iPhone / Mac（Tailscale）
  → tailscale 容器：HTTPS 443 / 8443
  → Approval / Management（共享网络，只监听 127.0.0.1）
  → Runner（Unix socket，无网络）→ NAS Docker → 应用容器
```

只有 Runner 挂 Docker socket；它仍拥有宿主机管理级权限。其余服务不挂应用工作区。NAS 原有 Tailscale 可以保留。

## 1. 检查环境【NAS 管理员终端】

NAS 命令在**同一个 root shell** 中依次执行；代码块失败就停，不跳过。需要新开 shell 时先执行第 6 节的变量恢复命令。

```sh
sudo -i
set -eu
uname -m
docker version
docker compose version
df -h /volume1
```

应为 `x86_64`；Compose 必须支持 `config --format json`。不支持时先更新 Container Manager，不混用旧版 `docker-compose`。

在 Tailscale 后台启用 **MagicDNS、HTTPS**；Mac、iPhone 已加入同一 tailnet。确认 GID `30001–30005` 未与 NAS 敏感组冲突；本文固定使用这组编号。

## 2. 下载与固定镜像【NAS】

四个路径中任何一个已存在都会停止，不覆盖旧状态或密钥。

```sh
for d in /volume1/compose-cd /volume1/compose-deployer-private \
         /volume1/compose-app-config /volume1/compose-downloads; do
  if [ -e "$d" ] || [ -L "$d" ]; then
    echo "停止：目录已存在：$d" >&2
    exit 1
  fi
done
mkdir -m 755 /volume1/compose-cd
cd /volume1/compose-cd
curl -fL https://github.com/kurisu-agi/compose-cd-engine/archive/d4f1358200e0cefb3a26fc2d97c3edc0305021a7.tar.gz -o source.tar.gz
tar -xzf source.tar.gz --strip-components=1
ENGINE=ghcr.io/kurisu-agi/compose-cd-engine@sha256:3d9714291df7e075869add6187455f7a1658d02d2f949891ea6197f9a7528fb6
docker pull "$ENGINE"
```

引擎对应源码 `2d3cffb`；下载的 `d4f1358` 只额外增加文档。[发布记录](https://github.com/kurisu-agi/compose-cd-engine/actions/runs/39213347618)。

在**可信管理员机器**上用已安装的 Cosign 验证；成功后再继续 NAS 安装：

```sh
cosign verify \
  --certificate-identity 'https://github.com/kurisu-agi/compose-cd-engine/.github/workflows/engine.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/kurisu-agi/compose-cd-engine@sha256:3d9714291df7e075869add6187455f7a1658d02d2f949891ea6197f9a7528fb6
```

**NAS：**首次拉取官方 Tailscale `stable`，立即固定为拉取到的 digest，后续不跟随标签漂移。这不是引擎的签名验证步骤。

```sh
docker pull tailscale/tailscale:stable
TAILSCALE_IMAGE=$(docker image inspect tailscale/tailscale:stable --format '{{index .RepoDigests 0}}')
case "$TAILSCALE_IMAGE" in
  *@sha256:*) ;;
  *) echo '停止：未获取 Tailscale digest' >&2; exit 1 ;;
esac
cat > .env <<EOF
CD_ENGINE_IMAGE=$ENGINE
CD_TAILSCALE_IMAGE=$TAILSCALE_IMAGE
CD_DEPLOYER_WORKSPACE=/volume1/compose-deployer-private
CD_DEPLOYER_CONFIG_ROOT=/volume1/compose-app-config
CD_DEPLOYER_DOWNLOAD_ROOT=/volume1/compose-downloads
EOF
chmod 600 .env
```

## 3. 创建目录、权限和密钥【NAS】

只修改新建目录，不递归修改 `/volume1` 或现有共享文件夹 ACL。所有配置及其祖先目录须由 root 管理，不能允许普通用户写入。

```sh
mkdir routes targets sources candidates inbox secrets run state agent-keys
mkdir management-policy management-run management-state provisioning-policy
mkdir approval-policy approval-state approval-run verification-state verification-run
mkdir tailscale-config tailscale-state loopback
chmod 755 routes targets management-policy provisioning-policy approval-policy tailscale-config loopback
chown root:30001 sources candidates
chmod 750 sources candidates
chown 10001:30001 inbox
chmod 750 inbox
chown root:30002 secrets agent-keys
chmod 750 secrets agent-keys
chown root:30001 run
chmod 2770 run
chmod 700 state tailscale-state
chown root:30003 management-run
chmod 750 management-run
chown 10001:10001 management-state
chmod 700 management-state
chown 10004:30004 approval-state approval-run
chmod 700 approval-state
chmod 750 approval-run
chown 10005:30005 verification-state verification-run
chmod 700 verification-state
chmod 750 verification-run
mkdir -m 700 /volume1/compose-deployer-private
mkdir -m 755 /volume1/compose-app-config /volume1/compose-downloads

umask 077
openssl rand -hex 32 > secrets/management.key
openssl rand -hex 32 > secrets/approval-service.key
openssl rand -hex 32 > secrets/verification-service.key
openssl rand -hex 32 > agent-keys/openclaw.key
chown root:30002 secrets/management.key agent-keys/openclaw.key
chown root:30004 secrets/approval-service.key
chown root:30005 secrets/verification-service.key
chmod 640 secrets/*.key agent-keys/openclaw.key
printf '[]\n' > secrets/scan-fingerprints.json
chmod 600 secrets/scan-fingerprints.json
umask 022
cp examples/agent-gateway.json management-policy/gateway.json
cp examples/agent-deployer-policy.json provisioning-policy/policy.json
cp examples/approval-policy.json approval-policy/policy.json
chmod 644 management-policy/gateway.json provisioning-policy/policy.json approval-policy/policy.json
```

策略保留 `enabled: false`、`projects: {}`；示例镜像、探针和 `bind_ip` **不是真实应用配置**。

## 4. 生成完整安装配置【NAS】

展开现有模板，再加入 Tailscale。NAS 无须安装 Python：临时使用引擎镜像中的 Python，不挂 Docker socket。

```sh
docker compose \
  -f compose.yml -f compose.management.yml -f compose.provisioning.yml \
  -f compose.authorization.yml -f examples/compose.provisioning.synology.yml \
  config --format json > compose.base.json

cat > generate-install.py <<'PY'
import json
from pathlib import Path

root = Path.cwd()
cfg = json.loads((root / 'compose.base.json').read_text())
services = cfg['services']
env = dict(line.split('=', 1) for line in (root / '.env').read_text().splitlines())

# 当前固定镜像没有 listen 参数：只替换已确认的监听语句，独立挂载。
# 升级到原生支持 loopback 的镜像后，删除这两份兼容补丁和挂载。
for service, module, port in [('management', 'management/gateway.py', 18792),
                               ('approval', 'authorization/server.py', 18793)]:
    source = Path('/app', module).read_text()
    old = f"('0.0.0.0', {port})"
    assert source.count(old) == 1, '镜像代码不匹配，停止生成'
    target = root / 'loopback' / (service + '.py')
    target.write_text(source.replace(old, f"('127.0.0.1', {port})"))
    target.chmod(0o644)
    svc = services[service]
    svc.pop('networks', None)
    svc['network_mode'] = 'service:tailscale'
    svc['depends_on'] = {'tailscale': {'condition': 'service_started'}}
    svc['volumes'].append({'type': 'bind', 'source': str(target),
                           'target': '/app/' + module, 'read_only': True,
                           'bind': {'create_host_path': False}})

serve = {'TCP': {}, 'Web': {}, 'AllowFunnel': {}}
for port, backend in [(443, 18793), (8443, 18792)]:
    host = '${TS_CERT_DOMAIN}:' + str(port)
    serve['TCP'][str(port)] = {'HTTPS': True}
    serve['Web'][host] = {'Handlers': {'/': {'Proxy': f'http://127.0.0.1:{backend}'}}}
    serve['AllowFunnel'][host] = False
(root / 'tailscale-config' / 'serve.json').write_text(json.dumps(serve, indent=2) + '\n')

services['tailscale'] = {
    'image': env['CD_TAILSCALE_IMAGE'], 'restart': 'unless-stopped',
    'hostname': 'deployer', 'user': '0:0',
    'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'],
    'mem_limit': '256m', 'pids_limit': 128,
    'environment': {'TS_HOSTNAME': 'deployer', 'TS_USERSPACE': 'true',
                    'TS_AUTH_ONCE': 'true', 'TS_STATE_DIR': '/var/lib/tailscale',
                    'TS_SERVE_CONFIG': '/config/serve.json'},
    'networks': ['caddy_net'],
    'volumes': [
        {'type': 'bind', 'source': str(root / 'tailscale-state'), 'target': '/var/lib/tailscale'},
        {'type': 'bind', 'source': str(root / 'tailscale-config'), 'target': '/config', 'read_only': True}
    ]
}
cfg['networks'] = {'caddy_net': {'name': 'compose-cd-private', 'driver': 'bridge'}}
assert len(services) == 7
assert all(not svc.get('ports') for svc in services.values())
assert services['runner']['network_mode'] == 'none'
assert [name for name, svc in services.items() if any(
    v.get('source') == '/var/run/docker.sock' for v in svc.get('volumes', [])
)] == ['runner']
(root / 'compose.generated.json').write_text(json.dumps(cfg, indent=2) + '\n')
PY

docker run --rm -i --network none --user 0:0 --cap-drop ALL \
  --security-opt no-new-privileges:true --entrypoint python3 \
  -v "$PWD:/work" -w /work "$ENGINE" - < generate-install.py

# /work 是生成器内部路径，换回实际 NAS 路径。
sed 's|/work/|/volume1/compose-cd/|g' compose.generated.json > compose.nas.json
docker compose -f compose.nas.json config > compose.install.yml
docker compose -f compose.install.yml config --quiet
```

最终导入 `/volume1/compose-cd/compose.install.yml`。它不再依赖叠加模板；仍须保留策略、密钥、状态、`loopback/` 和 `tailscale-config/`。

## 5. 启动独立 Tailscale 并登录【NAS】

先只启动入口；后端未启动，访问返回 502 属正常现象。

```sh
docker compose -p compose-cd -f compose.install.yml up -d tailscale
docker compose -p compose-cd -f compose.install.yml logs --tail=50 tailscale
```

在自己浏览器打开日志中的登录链接，批准 `deployer` 加入 tailnet；需要设备审批时也在后台批准。**不把登录链接发进聊天。**不使用 auth key，不把凭据写进 Compose。

```sh
docker compose -p compose-cd -f compose.install.yml exec -T tailscale tailscale status
docker compose -p compose-cd -f compose.install.yml exec -T tailscale \
  tailscale status --json > tailscale-status.json
DOMAIN=$(docker run --rm --network none --entrypoint python3 \
  -v "$PWD:/work:ro" "$ENGINE" -c \
  'import json; print(json.load(open("/work/tailscale-status.json"))["Self"]["DNSName"].rstrip("."))')
case "$DOMAIN" in
  *.ts.net) ;;
  *) echo '停止：未获取实际设备域名' >&2; exit 1 ;;
esac
printf '%s\n' "$DOMAIN" > deployer-domain.txt
```

实际域名可能是 `deployer-1.…ts.net`；注册 Passkey 后不随意改设备名。

## 6. 写入域名并启动全部服务【NAS】

以下也用于新开 shell 后恢复变量：

```sh
cd /volume1/compose-cd
set -eu
ENGINE=$(sed -n 's/^CD_ENGINE_IMAGE=//p' .env)
DOMAIN=$(cat deployer-domain.txt)
cat > approval-policy/policy.json <<EOF
{
  "state": "/var/lib/compose-cd-approval",
  "origin": "https://$DOMAIN",
  "rp_id": "$DOMAIN",
  "socket": "/run/compose-cd-approval/approval.sock",
  "service_key": "/etc/compose-cd/secrets/approval-service.key"
}
EOF
chmod 644 approval-policy/policy.json
```

Container Manager → 项目 → 新增：项目名 `compose-cd`、路径 `/volume1/compose-cd`，导入 **`compose.install.yml`**；不启用 Web Station，不加端口。第 5 步已创建同名项目，若界面不能接管，继续用 CLI 管理，不另建不同项目名。

```sh
docker compose -p compose-cd -f compose.install.yml up -d
docker compose -p compose-cd -f compose.install.yml ps
docker compose -p compose-cd -f compose.install.yml exec -T tailscale tailscale serve status
```

应有七个服务：`receiver`、`verifier`、`runner`、`management`、`approval`、`project-verifier`、`tailscale`。Serve 应显示 443 → 18793、8443 → 18792；无证书时检查 tailnet HTTPS 和容器日志，不改成 Funnel。

## 7. 限制并验证入口【Tailscale 后台 / Mac】

在 Tailscale 访问策略中合并以下规则，替换三个 IP 为 **iPhone、Mac、deployer 容器各自的 Tailscale IPv4**；不是 NAS 原有 Tailscale IP：

```json
{
  "grants": [
    {"src": ["100.64.0.11", "100.64.0.12"], "dst": ["100.64.0.13"], "ip": ["tcp:443"]},
    {"src": ["100.64.0.12"], "dst": ["100.64.0.13"], "ip": ["tcp:8443"]}
  ]
}
```

这是**合并片段**，不覆盖其他设备规则。允许规则会叠加；现有 ACL / grants 若有“所有人访问所有端口”，须移除或收紧对 deployer 的广泛授权，否则上面两条不起限制作用。

**Mac：**替换域名和 NAS 局域网 IP，再检查：

```sh
DOMAIN='deployer.你的tailnet.ts.net'
NAS_LAN_IP='192.168.你的NAS地址'
curl --max-time 15 -sS -o /dev/null -w '%{http_code}\n' "https://$DOMAIN/"
curl --max-time 5 -sS -o /dev/null "http://$DOMAIN:18793/"
curl --max-time 5 -sS -o /dev/null "http://$DOMAIN:18792/"
curl --max-time 5 -sS -o /dev/null "http://$NAS_LAN_IP:18793/"
curl --max-time 5 -sS -o /dev/null "http://$NAS_LAN_IP:18792/"
```

第一条应为 `200`；其余应失败或超时。另用未授权 tailnet 设备验证 443 / 8443 均拒绝。不要加 `-k`；不用 `curl -I`，审批服务不支持 HEAD。

## 8. 注册 Passkey【独立 NAS 管理终端 / iPhone】

```sh
docker compose -p compose-cd -f compose.install.yml exec -T approval \
  python3 -m authorization.server --bootstrap owner
```

只在自己终端查看十分钟有效的注册码。iPhone 开 Tailscale → Safari 打开 `https://实际域名/enroll` → 输入注册码 → Face ID 创建 Passkey。再执行一次 bootstrap，可注册恢复凭据。注册码和管理员会话不交给代理。

## 9. 连接 Mac【NAS → Mac】

只传 `/volume1/compose-cd/agent-keys/openclaw.key`，不传服务密钥或审批数据库。用普通 NAS SSH 账号临时接收文件，再用 `scp` 获取；替换账号和地址。

**Mac：**需要 Python 3.12+；源码目录若存在，另选新目录，不覆盖。

```sh
mkdir -p ~/.config/compose-cd
chmod 700 ~/.config/compose-cd
mkdir -p ~/Repos
git clone https://github.com/kurisu-agi/compose-cd-engine.git ~/Repos/compose-cd-engine-client
cd ~/Repos/compose-cd-engine-client
git checkout --detach 2d3cffb35ec173e7c6fab0127550719739e8ab00
python3 --version
```

**NAS root 终端：**

```sh
NAS_USER='你的NAS账号'
NAS_HOME=$(awk -F: -v u="$NAS_USER" '$1 == u {print $6}' /etc/passwd)
test -n "$NAS_HOME"
test -d "$NAS_HOME"
test ! -e "$NAS_HOME/.compose-cd-agent-transfer"
test ! -L "$NAS_HOME/.compose-cd-agent-transfer"
mkdir -m 700 "$NAS_HOME/.compose-cd-agent-transfer"
cp agent-keys/openclaw.key "$NAS_HOME/.compose-cd-agent-transfer/openclaw.key"
chown -R "$NAS_USER" "$NAS_HOME/.compose-cd-agent-transfer"
chmod 600 "$NAS_HOME/.compose-cd-agent-transfer/openclaw.key"
```

**Mac：**

```sh
scp '你的NAS账号@你的NAS地址:.compose-cd-agent-transfer/openclaw.key' ~/.config/compose-cd/openclaw.key
chmod 600 ~/.config/compose-cd/openclaw.key
cd ~/Repos/compose-cd-engine-client
DOMAIN='deployer.你的tailnet.ts.net'
PYTHONPATH=. python3 scripts/agent.py status smoke \
  --agent openclaw --endpoint "https://$DOMAIN:8443" \
  --secret-file ~/.config/compose-cd/openclaw.key
```

`smoke` 尚不存在，可以返回业务层拒绝 / 不存在；只验证认证和 API 连通，不算部署验收。`401`、TLS 错误或连接失败须先修复。

传输完成后在 **NAS** 删除临时副本（不删除原密钥）：

```sh
test -n "$NAS_HOME"
unlink "$NAS_HOME/.compose-cd-agent-transfer/openclaw.key"
rmdir "$NAS_HOME/.compose-cd-agent-transfer"
```

## 10. 配置实际应用策略【NAS 管理员】

**引擎已安装，应用部署仍关闭。**首次选独立测试应用，不接真实下载 / 媒体 / 备份目录。编辑 `/volume1/compose-cd/provisioning-policy/policy.json`：

| 字段 | 必须替换成什么 |
| --- | --- |
| `images` 仓库名 | 实际镜像仓库，删除 `ghcr.io/example/app`。 |
| `identity` / `issuer` / `platform` | 实际签名工作流身份、GitHub OIDC、`linux/amd64`，不是随意填 URL。 |
| `healthcheck` | 镜像内确实存在、能证明就绪的命令数组。 |
| `environment` | 允许的环境变量名称，不填密码值。 |
| `storage` | 暂用本文独立测试目录；确认应用实际 UID/GID。 |
| `bind_ip` / `port_range` | 应用端口的 NAS 绑定 IP 与范围，不是 sidecar IP。 |
| `allow_egress` / 资源额度 | 应用是否可出站，以及 CPU / 内存 / PID 上限。 |
| `enabled` | 上述配置完成并复核后才改为 `true`。 |

sidecar 只保护引擎入口，不自动代理部署的应用；应用端口隔离需单独验收。校验策略 schema 后重载：

```sh
docker run --rm --network none --entrypoint python3 \
  -v "$PWD/provisioning-policy:/policy:ro" "$ENGINE" -c \
  'import json; from deployer.schema import policy; policy(json.load(open("/policy/policy.json"))); print("Policy schema OK")'
docker compose -p compose-cd -f compose.install.yml restart runner project-verifier
```

此处需要**真实应用的镜像 / 签名 / 探针信息**，没有通用可直接部署的应用配置。应用 spec 完整字段见 [project-provisioning.md](project-provisioning.md)。

## 11. 首次审批与验收【Mac / iPhone】

将与 Policy 一致的实际应用 spec 保存为 `~/.config/compose-cd/smoke.json`，然后在 **Mac**：

```sh
cd ~/Repos/compose-cd-engine-client
chmod 600 ~/.config/compose-cd/smoke.json
PYTHONPATH=. python3 scripts/agent.py deploy smoke \
  --agent openclaw --endpoint "https://$DOMAIN:8443" \
  --secret-file ~/.config/compose-cd/openclaw.key \
  --spec ~/.config/compose-cd/smoke.json \
  --state ~/.config/compose-cd/smoke-flow.json \
  --mode persistent --follow
```

打开返回的审批链接，用 iPhone Safari / Passkey 核对批准；客户端继续执行原计划。断线后用**同一命令、同一 state 文件**恢复。

验收：部署与探针成功；引擎重启后状态保留；撤销后新变更被拒；退役不删测试数据；其他 NAS 服务未重建。通过后才接 AutoBangumi / 下载器，不是七个容器启动就算验收通过。

## 12. 维护与恢复【NAS】

以下按需选一条执行，不是顺序安装步骤：

```sh
cd /volume1/compose-cd
# 查看状态
docker compose -p compose-cd -f compose.install.yml ps
# 暂停引擎；已部署应用继续运行
docker compose -p compose-cd -f compose.install.yml stop
# 恢复
docker compose -p compose-cd -f compose.install.yml up -d
# 入口容器被重建后，同步重建共享网络的服务；短暂中断管理连接
docker compose -p compose-cd -f compose.install.yml up -d --force-recreate tailscale management approval
```

不运行 `down -v`、prune 或删除状态目录。NAS 管理员备份：策略、密钥、`approval-state`、`management-state`、引擎 `state`、私有部署工作区、Tailscale 身份及安装文件 / loopback 补丁。SQLite 一致性备份前停止引擎；备份不交给部署代理。恢复旧授权库可能恢复已撤销 Grant，恢复后先禁用执行并复核授权。

升级保留旧 digest；loopback 补丁与固定版本绑定，不能换镜像后继续盲用。新版本原生支持回环监听时，改用原生配置并移除补丁。数据库不兼容时依赖 NAS 恢复，不承诺自动降级。

## 已验证与待验收

- 已验证：19 段 shell 语法；固定镜像生成七服务 Compose；无宿主机端口、Runner 无网络且独占 Docker socket；初始 Policy schema；两个服务按非 root UID 启动、仅监听回环；审批主页和静态脚本 GET 返回 200。
- 待实机验收：DSM 权限 / Container Manager 接管、Tailscale 登录与 HTTPS / Host 转发、拒绝访问、iPhone Passkey、应用部署及入口重建。以上命令不代表已改动 NAS。

## 配置文件索引

| 文件 / 目录（位于 `/volume1/compose-cd`） | 用途 |
| --- | --- |
| `.env` | 固定镜像与三个路径；不含密钥值。 |
| `compose.install.yml` | Container Manager / CLI 使用的最终单文件。 |
| `generate-install.py`、`compose.base.json` | 生成步骤留档；启动不依赖它们。 |
| `loopback/*.py` | 固定镜像的 HTTP 回环监听兼容补丁。 |
| `tailscale-config/serve.json` | 443 / 8443 转发；Funnel 关闭。 |
| `tailscale-state/` | Tailscale 设备身份，持久保留。 |
| `approval-policy/policy.json` | 实际 HTTPS origin、RP ID 和审批 RPC。 |
| `management-policy/gateway.json` | 代理身份和空的固定项目清单。 |
| `provisioning-policy/policy.json` | 应用权限上限，初始禁用。 |
| `secrets/`、`agent-keys/` | 独立的服务密钥与代理密钥。 |

参考：[授权与注册](agent-authorization.md) · [应用策略与 spec](project-provisioning.md) · [Tailscale 容器参数](https://tailscale.com/docs/features/containers/docker/docker-params) · [Serve sidecar 示例](https://tailscale.com/blog/docker-tailscale-guide) · [grants 语法](https://tailscale.com/docs/reference/syntax/grants)
