'use strict';
let csrf = '', signedIn = false;

async function decide(action, request) {
  if (!signedIn) { await passkey('login'); signedIn = true; }
  await api('decision', {action, target: request.id, binding: request.binding});
  await route();
}
const $ = id => document.getElementById(id);
const b64 = v => Uint8Array.from(atob(v.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const u64 = v => btoa(String.fromCharCode(...new Uint8Array(v))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const when = t => t ? new Date(t * 1000).toLocaleString() : '—';
const ERRORS = {stale_request: '请求已失效或已处理，请刷新。', invalid_enrollment_code: '注册码无效或已过期。',
  verification_failed: 'Passkey 验证失败。', sign_in_required: '请先用 Passkey 登录。', last_passkey: '不能删除最后一个 Passkey。'};

async function api(path, body) {
  const r = await fetch('/api/' + path, body === undefined ? {} : {method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf}, body: JSON.stringify(body)});
  const data = await r.json();
  if (!r.ok) throw new Error(ERRORS[data.error] || ('被拒绝：' + data.error));
  return data;
}

async function passkey(action, target = '', token) {
  const start = await api('begin', {action, target, ...(token ? {token} : {})});
  const pk = start.options.publicKey;
  pk.challenge = b64(pk.challenge);
  for (const k of ['allowCredentials', 'excludeCredentials']) if (pk[k]) pk[k] = pk[k].map(c => ({...c, id: b64(c.id)}));
  if (pk.user) pk.user.id = b64(pk.user.id);
  const cred = await navigator.credentials[action === 'enroll' ? 'create' : 'get']({publicKey: pk});
  const response = {clientDataJSON: u64(cred.response.clientDataJSON)};
  for (const k of ['attestationObject', 'authenticatorData', 'signature', 'userHandle']) if (cred.response[k]) response[k] = u64(cred.response[k]);
  return api('finish', {ceremony_id: start.ceremony_id, response: {id: cred.id, rawId: u64(cred.rawId), type: cred.type,
    response, clientExtensionResults: cred.getClientExtensionResults()}});
}

function el(parent, tag, text, cls) {
  const n = document.createElement(tag);
  if (text !== undefined) n.textContent = text;
  if (cls) n.className = cls;
  parent.append(n);
  return n;
}
function button(parent, label, fn, primary) {
  const b = el(parent, 'button', label, primary ? 'primary' : '');
  b.onclick = async () => {
    b.disabled = true; $('message').textContent = '处理中…';
    try { await fn(); $('message').textContent = '完成。'; } catch (e) { $('message').textContent = e.message; }
    finally { b.disabled = false; }
  };
  return b;
}
function list(parent, items, cls) { const ul = el(parent, 'ul'); for (const i of items) el(ul, 'li', i, cls); return ul; }
function diff(parent, text) {
  const pre = el(parent, 'pre', undefined, 'diff');
  for (const line of text.split('\n')) {
    const cls = line.startsWith('@@') ? 'hunk' : line.startsWith('+') && !line.startsWith('+++') ? 'add'
      : line.startsWith('-') && !line.startsWith('---') ? 'del' : '';
    el(pre, 'span', line + '\n', cls);
  }
}
function identity(parent, id) {
  el(parent, 'p', '目录：' + id.working_dir, 'muted');
  el(parent, 'p', '文件：' + id.config_files.join(', '), 'muted');
}

const KIND = {read: '全局只读授权', manage: '项目管理授权', elevated: '限时高级运维授权', operate: '运维授权', change: '修改配置', create: '新建项目', down: '停止并删除容器', serve: '发布到 tailnet',
  unserve: '取消 tailnet 发布', trigger: '自动部署触发源'};

function plan(box, p) {
  if (p.redacted) {
    el(box, 'p', '此旧请求没有安全预览，请重新提交请求。', 'risk');
    return false;
  }
  if (p.highlights.length) { el(box, 'h3', '需要注意', 'risk'); list(box, p.highlights, 'risk'); }
  const env = p.env;
  if (env.added.length || env.changed.length || env.removed.length) {
    el(box, 'h3', '.env 变更（值不显示）');
    list(box, [...env.added.map(k => '新增 ' + k), ...env.changed.map(k => '修改 ' + k), ...env.removed.map(k => '删除 ' + k)]);
  }
  if (p.diff) { el(box, 'h3', 'compose.yaml 变更'); diff(box, p.diff); }
  el(box, 'p', '执行：写入前在同目录备份，然后 up -d；健康检查失败自动恢复原文件。', 'muted');
  return true;
}

function request(parent, r) {
  const box = el(parent, 'article');
  el(box, 'h3', `${KIND[r.kind]} · ${r.project || ''}`);
  el(box, 'p', `申请者：${r.agent} · 状态：${r.status} · 过期：${when(r.expires)}`, 'muted');
  const d = r.detail;
  let reviewable = true;
  if (['read', 'manage', 'elevated'].includes(r.kind)) {
    if (r.kind !== 'read') identity(box, d.identity);
    el(box, 'p', d.lifetime ? `授权有效期：${d.lifetime} 秒` : '授权有效期：无期限，可随时撤销');
    if (r.kind === 'read') {
      el(box, 'p', '读取所有 Compose 项目（包括 Deployer）及 Docker 环境诊断信息；不授予文件写入或任意主机文件读取权限。');
    } else if (r.kind === 'manage') {
      el(box, 'p', '在下列数据与资源边界内持续部署、修改配置和运维，不逐次审批。', 'muted');
      el(box, 'pre', JSON.stringify(d.boundary, null, 2));
      if ((d.unverified || []).length) {
        el(box, 'p', 'Deployer 看不到以下宿主机目录，只做了路径检查（系统目录、卷根、Deployer 目录），未检查其中的符号链接：', 'risk');
        el(box, 'pre', d.unverified.join('\n'));
      }
      el(box, 'p', '读写目录内的数据可被项目修改或删除；请保留备份。', 'risk');
    } else {
      el(box, 'p', '在现有项目管理边界内重复执行 exec；到期或撤销后禁止新的高级操作。');
      el(box, 'p', '关联管理授权：' + d.boundary.manage_grant, 'muted');
    }
  } else if (r.kind === 'operate') {
    identity(box, d.identity);
    el(box, 'p', `允许 ${d.lifetime / 86400} 天：读取 compose.yaml 原文和 .env 键名；启动、停止、重启、up、拉取新镜像并更新。`);
    el(box, 'p', '不允许：修改配置、删除容器、读取 .env 的值。', 'muted');
  } else if (r.kind === 'change' || r.kind === 'create') {
    identity(box, d.plan.identity);
    if (r.kind === 'create') el(box, 'p', `批准后同时授予该项目 ${d.lifetime / 86400} 天运维授权。`);
    reviewable = plan(box, d.plan);
  } else if (r.kind === 'down') {
    identity(box, d.identity);
    el(box, 'p', 'docker compose down：停止并删除容器和网络。卷和数据目录保留。', 'risk');
  } else if (r.kind === 'serve') {
    el(box, 'p', `${d.url} → 本机端口 ${d.target_port}（仅 tailnet 可访问，不公开到互联网）`);
  } else if (r.kind === 'unserve') {
    el(box, 'p', `移除 https 端口 ${d.https_port} 的发布`);
  } else if (r.kind === 'trigger') {
    identity(box, d.identity);
    el(box, 'p', `服务 ${d.service} 将自动更新为 GitHub ${d.config.repository} 分支 ${d.config.branch} 最新提交构建的镜像。`);
    el(box, 'p', `镜像：${d.config.image}（${d.config.platform}），必须由 ${d.signer} 签名。`, 'muted');
    el(box, 'p', '每次更新只改这个服务的镜像；健康检查失败自动恢复。', 'muted');
  }
  if (r.outcome) el(box, 'pre', JSON.stringify(r.outcome, null, 2));
  if (r.status === 'pending' && reviewable && r.binding) {
    el(box, 'p', '预览已隐藏敏感值；决定只适用于当前显示的版本。', 'muted');
    button(box, signedIn ? '批准' : '验证身份并批准', () => decide('approve', r), true);
    button(box, signedIn ? '拒绝' : '验证身份并拒绝', () => decide('deny', r));
  }
}

async function pairing(token) {
  const p = await api('pairing/' + token);
  const box = el($('content'), 'article');
  el(box, 'h3', `配对 agent：${p.label} · ${p.status}`);
  el(box, 'p', '身份：' + p.agent, 'muted');
  el(box, 'p', '请与 agent 端显示的指纹逐字比对：');
  el(box, 'pre', p.fingerprint);
  el(box, 'p', '配对只确认 agent 身份，不授予项目访问权限。随后可授予全局只读、项目管理或限时高级运维权限。');
  if (p.status === 'pending') {
    button(box, '指纹一致，用 Face ID 配对', async () => { await passkey('pair', token); await route(); }, true);
    button(box, '拒绝', async () => { await passkey('deny_pair', token); await route(); });
  }
}

async function dashboard(session) {
  const c = $('content');
  if (!session.owner) {
    const box = el(c, 'article');
    el(box, 'p', session.enrolled ? '用 Passkey 登录以查看全部授权。' : '尚未注册 Passkey。打开 /enroll 并输入 gateway 容器日志里的注册码。');
    if (session.enrolled) button(box, '用 Passkey 登录', async () => { await passkey('login'); await route(); }, true);
    return;
  }
  const d = await api('dashboard');
  el(c, 'h2', '待批准');
  if (!d.requests.length) el(c, 'p', '没有待批准的请求。', 'muted');
  for (const r of d.requests) request(c, await api('request/' + r.id));
  el(c, 'h2', 'Agent');
  for (const a of d.agents) {
    const box = el(c, 'article');
    el(box, 'h3', `${a.label} · ${a.status}`); el(box, 'p', a.id, 'muted');
    if (a.status === 'active') button(box, '解除配对（撤销全部授权）', async () => { await passkey('unpair', a.id); await route(); });
  }
  el(c, 'h2', '持续授权');
  if (!d.grants.length) el(c, 'p', '无。', 'muted');
  for (const g of d.grants) {
    const box = el(c, 'article');
    el(box, 'h3', `${KIND[g.scope] || '旧版运维授权'} · ${g.project}`);
    el(box, 'p', `${g.agent} · ${g.expires ? '到期 ' + when(g.expires) : '无期限'}`, 'muted');
    if (g.scope === 'manage') el(box, 'pre', JSON.stringify(g.boundary, null, 2));
    button(box, '撤销', async () => { await passkey('revoke', g.id); await route(); });
  }
  el(c, 'h2', '自动部署触发源');
  for (const t of d.triggers.filter(t => t.status === 'active')) {
    const box = el(c, 'article');
    el(box, 'h3', `${t.project} / ${t.service}`);
    el(box, 'p', `${t.config.repository} · ${t.config.branch} → ${t.config.image}`, 'muted');
    if (t.last) el(box, 'p', `上次检查 ${when(t.last.checked)}：${t.last.error || '正常'}${t.last.image ? ' · ' + t.last.image : ''}`, 'muted');
    button(box, '显示 GitHub webhook 设置', async () => {
      const s = await api('trigger/' + t.id);
      el(box, 'pre', `Payload URL: ${s.url}\nContent type: application/json\nSecret: ${s.secret}\nEvents: Workflow runs`);
    });
    button(box, '删除', async () => { await passkey('remove_trigger', t.id); await route(); });
  }
  el(c, 'h2', 'tailnet 发布');
  for (const r of d.routes) {
    const box = el(c, 'article');
    el(box, 'p', `:${r.https_port} → ${r.project} 端口 ${r.target_port}`);
    button(box, '取消发布', async () => { await passkey('remove_route', String(r.https_port)); await route(); });
  }
  const jobs = el(c, 'details'); el(jobs, 'summary', '最近任务');
  for (const j of d.jobs) el(jobs, 'p', `${when(j.created)} ${j.project} ${j.op} → ${j.status}${j.result && j.result.error ? '：' + j.result.error : ''}`, 'muted');
  const keys = el(c, 'details'); el(keys, 'summary', 'Passkey');
  button(keys, '添加 Passkey', async () => { await passkey('enroll'); await route(); });
  for (const k of d.credentials) button(keys, '删除 ' + k.slice(0, 12), async () => { await passkey('remove_credential', k.toUpperCase()); await route(); });
  const audit = el(c, 'details'); el(audit, 'summary', '审计日志');
  el(audit, 'pre', d.audit.map(a => `${when(a.created)} ${a.actor} ${a.action} ${a.subject}`).join('\n'));
}

function enroll() {
  const box = el($('content'), 'article');
  el(box, 'h3', '注册 Passkey');
  el(box, 'p', '在 Container Manager → 项目 → gateway 容器 → 日志中找到注册码。不要把注册码发给 agent。');
  const input = el(box, 'input'); input.autocomplete = 'off'; input.placeholder = '注册码';
  button(box, '创建 Passkey', async () => { await passkey('enroll', '', input.value.trim()); location.href = '/'; }, true);
}

async function route() {
  const session = await api('session'); csrf = session.csrf; signedIn = session.owner;
  $('content').replaceChildren(); $('nav').replaceChildren();
  if (session.owner) {
    button($('nav'), '退出', async () => { await api('logout', {}); await route(); });
  }
  const path = location.pathname;
  if (path === '/enroll') return enroll();
  if (path.startsWith('/p/')) return pairing(path.slice(3));
  if (path.startsWith('/r/')) return request($('content'), await api('request/' + path.slice(3)));
  return dashboard(session);
}
route().catch(e => { $('message').textContent = e.message; });
