'use strict';
// Resource resolver — spec §3. Cached after first resolve(), re-resolved if
// pid changes (fork-style workers, e.g. Node cluster/pm2).

const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

function parseOtelResourceAttributes(raw) {
  const out = {};
  if (!raw) return out;
  for (const pair of raw.split(',')) {
    const p = pair.trim();
    if (!p) continue;
    const i = p.indexOf('=');
    if (i < 0) return null;
    try {
      out[decodeURIComponent(p.slice(0, i).trim())] = decodeURIComponent(p.slice(i + 1).trim());
    } catch {
      return null;
    }
  }
  return out;
}

function nearestPackageJson(startFile) {
  let dir = startFile ? path.dirname(path.resolve(startFile)) : process.cwd();
  for (let i = 0; i < 32; i++) {
    const candidate = path.join(dir, 'package.json');
    if (fs.existsSync(candidate)) {
      try {
        return JSON.parse(fs.readFileSync(candidate, 'utf8'));
      } catch {
        return null;
      }
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

function executableBasename() {
  const argv1 = process.argv[1];
  return path.basename(argv1 || process.argv[0] || 'node');
}

function uuidv4() {
  if (crypto.randomUUID) return crypto.randomUUID();
  const b = crypto.randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = b.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

function instanceId(strategy, k8s, hostName) {
  if (strategy === 'none') return undefined;
  if (strategy === 'host-pid') return `${hostName || 'unknown'}/${process.pid}`;
  if (k8s['k8s.pod.name']) {
    return [k8s['k8s.namespace.name'], k8s['k8s.pod.name'], k8s['k8s.container.name']].filter(Boolean).join('.');
  }
  return uuidv4();
}

function resolve(explicit = {}) {
  const env = process.env;
  let otelAttrs = parseOtelResourceAttributes(env.OTEL_RESOURCE_ATTRIBUTES || '');
  if (env.OTEL_RESOURCE_ATTRIBUTES && otelAttrs === null) {
    process.stderr.write('unilog: OTEL_RESOURCE_ATTRIBUTES is malformed, ignoring it entirely\n');
    otelAttrs = {};
  }
  otelAttrs = otelAttrs || {};

  const pkg = nearestPackageJson(process.argv[1]);
  const pkgName = pkg && pkg.name ? pkg.name.replace(/^@[^/]+\//, '') : null;

  const serviceName =
    explicit.serviceName || env.OTEL_SERVICE_NAME || otelAttrs['service.name'] || pkgName || `unknown_service:${executableBasename()}`;
  const serviceNamespace = explicit.serviceNamespace || env.LOG_SERVICE_NAMESPACE || otelAttrs['service.namespace'];
  const deploymentEnv = explicit.deploymentEnvironment || env.LOG_ENV || otelAttrs['deployment.environment.name'];

  let hostName;
  try {
    hostName = os.hostname();
  } catch {
    hostName = env.HOSTNAME;
  }

  const k8s = {};
  for (const [attr, v] of [
    ['k8s.namespace.name', env.K8S_NAMESPACE],
    ['k8s.pod.name', env.K8S_POD_NAME],
    ['k8s.container.name', env.K8S_CONTAINER_NAME],
    ['k8s.node.name', env.K8S_NODE_NAME],
  ]) {
    if (v) k8s[attr] = v;
  }

  const strategy = env.LOG_INSTANCE_ID_STRATEGY || 'auto';

  const resource = { 'service.name': serviceName };
  if (serviceNamespace) resource['service.namespace'] = serviceNamespace;
  const iid = instanceId(strategy, k8s, hostName);
  if (iid) resource['service.instance.id'] = iid;
  if (deploymentEnv) resource['deployment.environment.name'] = deploymentEnv;
  if (hostName) resource['host.name'] = hostName;
  if (env.LOG_RESOURCE_PROCESS !== '0') resource['process.pid'] = process.pid;
  Object.assign(resource, k8s);

  for (const [k, v] of Object.entries(otelAttrs)) {
    if (!(k in resource) && !['service.name', 'service.namespace', 'deployment.environment.name'].includes(k)) {
      resource[k] = v;
    }
  }
  return resource;
}

let _cached = null;
let _cachedPid = null;
let _explicit = {};

function configure(explicit) {
  _explicit = explicit || {};
  _cached = null;
}

function get() {
  if (_cached === null || _cachedPid !== process.pid) {
    _cached = resolve(_explicit);
    _cachedPid = process.pid;
  }
  return _cached;
}

module.exports = { resolve, get, configure };
