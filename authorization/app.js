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
async function refresh() {
  const session = await api('session'); csrf = session.csrf;
  el('login').hidden = session.authenticated;
  el('refresh').hidden = el('logout').hidden = !session.authenticated;
  el('enrollment').hidden = location.pathname !== '/enroll';
  el('content').replaceChildren();
  if (!session.authenticated) return;
  const data = await api('data');
  const focus = location.pathname.startsWith('/requests/') ? location.pathname.split('/')[2] : '';
  text(el('content'), 'h2', 'Requests');
  for (const request of data.requests.filter(r => !focus || r.request_id === focus)) {
    const box = document.createElement('article'); el('content').append(box);
    text(box, 'h3', request.project + ' · ' + request.status);
    text(box, 'p', `Requesting agent: ${request.agent}. Authorization: ${request.mode}${request.mode === 'expiring' ? ' for ' + request.lifetime + ' seconds' : ''}.`);
    text(box, 'p', 'New / expanded permissions grant application code the access shown below. Writable mounts can modify data; egress can transfer it.', 'sensitive');
    const existing = data.grants.filter(g => g.project === request.project && g.agent === request.agent && g.status === 'active');
    text(box, 'h4', 'Existing permissions'); text(box, 'pre', JSON.stringify(existing.map(g => g.scope), null, 2));
    text(box, 'h4', 'Requested permissions (authoritative, complete scope)'); text(box, 'pre', JSON.stringify(request.scope, null, 2));
    text(box, 'details', `Plan: ${request.plan_id}\nSpecification: ${request.spec_hash}\nPolicy: ${request.policy}`);
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
    text(box, 'pre', JSON.stringify(grant.scope, null, 2));
    if (grant.status === 'active') button(box, 'Revoke with Passkey', async () => { await ceremony('revoke', grant.id); await refresh(); });
  }
  text(el('content'), 'h2', 'Passkeys');
  for (const credential of data.credentials) button(el('content'), 'Remove Passkey ' + credential.id.slice(0, 12), async () => { await ceremony('remove', credential.id); await refresh(); });
  text(el('content'), 'p', 'Adding another Passkey requires a new local administrator enrollment code. The last Passkey cannot be removed here.');
  text(el('content'), 'h2', 'Recent audit events'); text(el('content'), 'pre', JSON.stringify(data.audit, null, 2));
}
el('login').onclick = () => run(async () => { await ceremony('login'); await refresh(); });
el('enroll').onclick = () => run(async () => { const token = el('token').value; el('token').value = ''; await ceremony('enroll', '', token); await refresh(); });
el('refresh').onclick = () => run(refresh);
el('logout').onclick = () => run(async () => { await api('logout', {}); await refresh(); });
run(refresh);
