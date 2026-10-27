'use strict';
// DOM rendering regression only; not physical browser/Passkey acceptance.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.textContent = ''; }
  append(child) { this.children.push(child); }
}
const source = fs.readFileSync(path.join(__dirname, '../authorization/app.js'), 'utf8');
const stop = source.indexOf("el('login').onclick");
assert.ok(stop > 0);
const context = vm.createContext({document: {createElement: tag => new Element(tag)}});
vm.runInContext(source.slice(0, stop), context);
const scope = {
  type: 'registered_task_v1', project: 'existing-app',
  operations: ['inspect', 'adoption_observe', 'adoption_redeploy', 'shared_ingress_apply'],
  diagnostics: 'Private structural diagnostics only',
  exclusions: ['image upgrades', 'unrelated targets'],
  envelope: {registration_hash: 'registered-hash', backend: 'autobangumi',
    route: {hostname: 'apps.example.ts.net', https_port: 9444, root_path: '/'}},
  identities: [{name: 'existing-app-web', image_id: 'sha256:fixed-local-image'}],
  adoption: {project: 'existing-app', operations: ['adoption_observe'],
    baseline_hash: 'baseline-hash', declaration_hash: 'declaration-hash',
    registration_hash: 'registered-hash', image_ids: ['sha256:fixed-local-image']}
};
function collect(node) { return [node.textContent, ...node.children.flatMap(collect)]; }
for (const [name, diff] of [
  ['prior inspect grant', {type: 'registered_task_v1', operations: ['adoption_observe', 'adoption_redeploy', 'shared_ingress_apply']}],
  ['changed existing task envelope', {envelope: {registration_hash: 'registered-hash', route: {https_port: 9444}}}],
  ['unchanged task scope', {}]
]) {
  const root = new Element('article');
  context.root = root;
  context.request = {scope, grant_diff: diff};
  vm.runInContext('requestedPermissions(root, request)', context);
  const nodes = collect(root);
  const output = nodes.join('\n');
  assert.ok(output.includes('BOUNDED TASK DELEGATION: existing-app'), name);
  assert.ok(output.includes('Allowed: ' + scope.operations.join(', ')), name);
  assert.ok(output.includes('registered-hash') && output.includes('apps.example.ts.net'), name);
  assert.ok(output.includes('image upgrades') && output.includes('unrelated targets'), name);
  assert.ok(!output.includes('undefined'), name);
  assert.ok(!root.children.some(node => node.tag === 'details'), 'full task scope must not be collapsed');
  assert.ok(root.children.some(node => node.tag === 'pre' && node.textContent === JSON.stringify(diff, null, 2)), 'separate exact partial diff');
  console.log('PASS task approval rendering: ' + name);
}
const ordinary = new Element('article');
context.root = ordinary;
context.request = {scope: {read_only: true, operations: ['inspect'], project: 'existing-app'}, grant_diff: {}};
vm.runInContext('requestedPermissions(root, request)', context);
assert.ok(ordinary.children.some(node => node.tag === 'details'), 'ordinary grants retain full disclosure');
console.log('PASS ordinary approval rendering unchanged');
