// Minimal DOM contract test. No browser package or production server required.
const vm = require('node:vm');
const fs = require('node:fs');
const assert = require('node:assert/strict');
class Node {
  constructor(tag) { this.tag = tag; this.children = []; this.textContent = ''; }
  append(n) { this.children.push(n); }
  replaceChildren() { this.children = []; }
}
const nodes = Object.fromEntries(['content','nav','message'].map(k => [k, new Node(k)]));
const context = vm.createContext({document: {getElementById: k => nodes[k], createElement: k => new Node(k)},
  location: {pathname: '/'}, console, Uint8Array, Date});
let source = fs.readFileSync('gateway/static/app.js', 'utf8');
source = source.slice(0, source.lastIndexOf('route().catch'));
vm.runInContext(source, context);
const identity = {working_dir:'/data/app',config_files:['/data/app/compose.yaml']};
for (const [kind,detail] of [
  ['change',{plan:{identity,redacted:false,diff:'- app:old\n+ app:new',highlights:[],env:{added:[],changed:[],removed:[]}}}],
  ['read',{lifetime:null}], ['manage',{identity,lifetime:null,boundary:{mounts:[{path:'/data',mode:'rw'}],networks:[]}}],
  ['elevated',{identity,lifetime:900,boundary:{manage_grant:'g1'}}],
  ['serve',{url:'https://example',target_port:8080}],
  ['trigger',{identity,service:'web',config:{repository:'owner/app',branch:'main',image:'app',platform:'linux/amd64'},signer:'owner'}]
]) {
  nodes.content.replaceChildren();
  context.sample = {id:'request',kind,project:'app',agent:'agent',status:'pending',expires:2000000000,binding:'version',detail};
  vm.runInContext("request($('content'), sample)",context);
  const all = n => [n,...n.children.flatMap(all)];
  const elements=all(nodes.content);
  assert.equal(elements.filter(n=>n.tag==='button').length,2,kind);
  assert.ok(!elements.some(n=>n.textContent.includes('登录查看')),kind);
  if(kind==='change') assert.ok(elements.some(n=>n.textContent.includes('app:new')));
}
console.log('UI contracts passed: anonymous diff and six request kinds');
