'use strict';
let csrf = '';
const el = id => document.getElementById(id);
const decode = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const encode = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
async function api(path, value) {
  const response = await fetch('/api/' + path, value === undefined ? {} : {
    method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf}, body: JSON.stringify(value)
  });
  if (!response.ok) throw new Error('Request denied or expired. Refresh and try again.');
  return response.json();
}
async function ceremony(action, target = '', token) {
  const start = await api('begin', {action, target, ...(token ? {token} : {})});
  const publicKey = start.options.publicKey;
  publicKey.challenge = decode(publicKey.challenge);
  for (const key of ['allowCredentials', 'excludeCredentials']) {
    if (publicKey[key]) publicKey[key] = publicKey[key].map(c => ({...c, id: decode(c.id)}));
  }
  if (publicKey.user) publicKey.user.id = decode(publicKey.user.id);
  const cred = await navigator.credentials[action === 'enroll' ? 'create' : 'get']({publicKey});
  const response = {clientDataJSON: encode(cred.response.clientDataJSON)};
  for (const key of ['attestationObject', 'authenticatorData', 'signature', 'userHandle']) {
    if (cred.response[key]) response[key] = encode(cred.response[key]);
  }
  await api('finish', {ceremony_id: start.ceremony_id, response: {
    id: cred.id, rawId: encode(cred.rawId), type: cred.type, response,
    clientExtensionResults: cred.getClientExtensionResults()
  }});
}
async function run(fn) {
  try { el('message').textContent = 'Waiting for Passkey…'; await fn(); el('message').textContent = 'Completed.'; }
  catch (error) { el('message').textContent = error.message; }
}
function text(parent, tag, value, cls) {
  const node = document.createElement(tag); node.textContent = value; if (cls) node.className = cls; parent.append(node); return node;
}
function button(parent, title, action) {
  const node = text(parent, 'button', title);
  node.onclick = () => run(async () => { node.disabled = true; try { await action(); } finally { node.disabled = false; } });
}
function disclosure(parent, title) {
  const node = document.createElement('details'); text(node, 'summary', title); parent.append(node); return node;
}
function permissions(parent, scope) {
  if ((scope.operations || []).some(op => op.startsWith('adoption_'))) {
    text(parent, 'p', 'EXISTING PROJECT TRANSACTION: ' + scope.project + ' · ' + scope.operations.join(', '), 'sensitive');
    text(parent, 'p', 'Original project/container/mount/port/network identities are retained; no images pulled or data deleted. Redeploy can interrupt service. Runtime configuration is administrator-reviewed, NOT proven unchanged.');
    text(parent, 'p', scope.configuration_notice || '');
    text(parent, 'p', 'Configuration fields: ' + JSON.stringify(scope.configuration_changes || {}));
    text(parent, 'p', 'Local image IDs: ' + (scope.image_ids || []).join(', '));
    text(parent, 'p', 'Baseline: ' + scope.baseline_hash + '; declaration: ' + scope.declaration_hash + '; registration: ' + scope.registration_hash);
  }
  if (scope.read_only && scope.operations && scope.operations.includes('inspect')) {
    text(parent, 'p', 'READ ONLY: structural inspection of existing Compose project ' + scope.project + '.');
    text(parent, 'p', 'Reveals Compose identity/paths, image IDs, mount paths, published ports and network names. No environment values, logs or application data.');
    text(parent, 'p', 'This does not authorize adoption, recreation, lifecycle actions or ingress changes.');
  } else if (scope.read_only) {
    text(parent, 'p', 'READ ONLY: deployed application inventory across this NAS, including applications not managed by deployer.');
    text(parent, 'p', 'Visible fields: ' + (scope.fields || []).join(', ') + '. No environment values, host paths, logs or application data.');
    text(parent, 'p', 'This does not permit starting, stopping, updating, importing or taking over applications.');
  }
  if ('egress' in scope) text(parent, 'p', scope.egress ? 'Network: outbound access allowed.' : 'Network: outbound access blocked.');
  if (scope.operations) text(parent, 'p', 'Allowed actions: ' + scope.operations.join(', '));
  for (const [name, service] of Object.entries(scope.services || {})) {
    text(parent, 'h4', name);
    if (service.repository) text(parent, 'p', 'Image source: ' + service.repository);
    if (service.identity) text(parent, 'p', 'Trusted build: ' + service.identity);
    if (service.unsigned_digest) text(parent, 'p', 'Unsigned exception, exact digest: ' + service.unsigned_digest, 'sensitive');
    if (service.memory_mb !== undefined || service.cpus !== undefined) text(parent, 'p',
      `Resource ceiling: ${service.memory_mb === undefined ? 'unchanged memory' : service.memory_mb + ' MiB RAM'}; ${service.cpus === undefined ? 'unchanged CPU' : service.cpus + ' CPU(s)'}.`);
    if (service.environment && service.environment.length) text(parent, 'p', 'Configurable settings: ' + service.environment.join(', ') + ' (values withheld)');
    for (const mount of service.mounts || []) text(parent, 'p',
      `Storage: ${mount.storage} / ${mount.slot} → ${mount.target} · ${mount.read_only ? 'read only' : 'READ AND WRITE'}`, mount.read_only ? '' : 'sensitive');
    if (service.mounts && !service.mounts.length) text(parent, 'p', 'Storage: no mounted data.');
    for (const port of service.ports || []) text(parent, 'p', `Inbound: ${port.published}/${port.protocol} → application port ${port.target}`);
    if (service.ports && !service.ports.length) text(parent, 'p', 'Inbound: no published ports.');
  }
}
async function refresh() {
  const session = await api('session'); csrf = session.csrf;
  el('login').hidden = session.authenticated;
  el('refresh').hidden = el('logout').hidden = !session.authenticated;
  el('enrollment').hidden = location.pathname !== '/enroll';
  el('content').replaceChildren();
  if (!session.authenticated) return;
  const data = await api('data');
  const pairingFocus = location.pathname.startsWith('/pairings/') ? location.pathname.split('/')[2] : '';
  text(el('content'), 'h2', 'Pair an agent');
  for (const pair of (data.pairings || []).filter(p => !pairingFocus || p.id === pairingFocus)) {
    const box = document.createElement('article'); el('content').append(box);
    text(box, 'h3', pair.label + ' · ' + pair.status);
    text(box, 'p', 'Agent identity: ' + pair.agent);
    text(box, 'p', 'Compare this fingerprint with the requesting device before pairing. A device label is not proof of identity.');
    text(box, 'pre', pair.fingerprint);
    text(box, 'p', 'Pairing identifies the agent only. Reading NAS applications and modifying them require separate authorization.');
    if (pair.status === 'pending') {
      const label = document.createElement('label'); box.append(label);
      const matched = document.createElement('input'); matched.type = 'checkbox'; label.append(matched);
      text(label, 'span', 'I compared the fingerprint with my requesting device.');
      button(box, 'Pair with Passkey', async () => {
        if (!matched.checked) throw new Error('Compare the fingerprint with the requesting device first.');
        await ceremony('pair', pair.id); await refresh();
      });
      button(box, 'Deny pairing with Passkey', async () => { await ceremony('deny_pair', pair.id); await refresh(); });
    }
  }
  const paired = disclosure(el('content'), 'Paired agents');
  for (const agent of data.agents || []) {
    text(paired, 'p', agent.label + ' · ' + agent.id + ' · ' + agent.status);
    if (agent.status === 'active') button(paired, 'Disconnect agent and revoke its grants with Passkey', async () => {
      await ceremony('unpair', agent.id); await refresh();
    });
  }
  const focus = location.pathname.startsWith('/requests/') ? location.pathname.split('/')[2] : '';
  text(el('content'), 'h2', 'Requests');
  for (const request of data.requests.filter(r => !focus || r.request_id === focus)) {
    const box = document.createElement('article'); el('content').append(box);
    text(box, 'h3', request.project + ' · ' + request.status);
    text(box, 'p', `Requesting agent: ${request.agent}. Authorization: ${request.mode}${request.mode === 'expiring' ? ' for ' + request.lifetime + ' seconds' : ''}.`);
    text(box, 'p', 'New / expanded permissions grant application code the access shown below. Writable mounts can modify data; egress can transfer it.', 'sensitive');
    const existing = data.grants.filter(g => g.project === request.project && g.agent === request.agent && g.status === 'active');
    const previous = disclosure(box, 'Existing permissions');
    if (!existing.length) text(previous, 'p', 'No active project authorization.');
    for (const grant of existing) permissions(previous, grant.scope);
    text(box, 'h4', 'New or expanded permissions');
    if (Object.keys(request.grant_diff).length) permissions(box, request.grant_diff);
    else text(box, 'p', 'No expansion compared with an active authorization.');
    const complete = disclosure(box, 'Full requested authorization'); permissions(complete, request.scope);
    text(disclosure(box, 'Request verification details'), 'pre', `Plan: ${request.plan_id}\nSpecification: ${request.spec_hash}\nPolicy: ${request.policy}`);
    if (request.status === 'pending') {
      button(box, 'Approve these permissions with Passkey', async () => { await ceremony('approve', request.request_id); await refresh(); });
      button(box, 'Deny with Passkey', async () => { await ceremony('deny', request.request_id); await refresh(); });
    }
  }
  text(el('content'), 'h2', 'Authorizations');
  for (const grant of data.grants) {
    const box = document.createElement('article'); el('content').append(box);
    text(box, 'h3', `${grant.project} · ${grant.status}`);
    text(box, 'p', `Agent: ${grant.agent}. Approved by: ${grant.admin}. ${grant.mode}; expires: ${grant.expires ? new Date(grant.expires * 1000).toLocaleString() : 'never'}.`);
    permissions(disclosure(box, 'Granted permissions'), grant.scope);
    if (grant.status === 'active') button(box, 'Revoke with Passkey', async () => { await ceremony('revoke', grant.id); await refresh(); });
  }
  const settings = disclosure(el('content'), 'Manage Passkeys');
  for (const credential of data.credentials) button(settings, 'Remove Passkey ' + credential.id.slice(0, 12), async () => { await ceremony('remove', credential.id); await refresh(); });
  text(settings, 'p', 'Adding another Passkey requires a new local administrator enrollment code. The last Passkey cannot be removed here.');
  text(disclosure(el('content'), 'Recent audit events'), 'pre', JSON.stringify(data.audit, null, 2));
}
el('login').onclick = () => run(async () => { await ceremony('login'); await refresh(); });
el('enroll').onclick = () => run(async () => { const token = el('token').value; el('token').value = ''; await ceremony('enroll', '', token); await refresh(); });
el('refresh').onclick = () => run(refresh);
el('logout').onclick = () => run(async () => { await api('logout', {}); await refresh(); });
run(refresh);
