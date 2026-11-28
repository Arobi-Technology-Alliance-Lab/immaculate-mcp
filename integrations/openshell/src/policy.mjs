/**
 * Copyright (c) 2026 Arobi Technology Alliance, Inc. All Rights Reserved.
 *
 * The policy half of the gate: the `config` object of an OpenShell `network_middlewares` entry says what each request
 * is, as an Immaculate action and consequence tier. It grants nothing; authority comes from the operator's grants.
 *
 *   config:
 *     rules:
 *       - id: refunds                 # stable id, recorded with each decision
 *         methods: [POST]             # optional; any method when omitted
 *         hosts: ["api.stripe.com"]   # exact, "*.example.com" (subdomains, not the apex), or "*"
 *         paths: ["/v1/refunds"]      # optional; exact, or a prefix ending in "*"; any path when omitted
 *         action: payments.refund
 *         tier: critical              # low | medium | high | critical
 *     unmatched: deny                 # the default; or { action: http.other, tier: low }
 *
 * Rules are tried in order and the first match wins. A request path the gate cannot read one way only is denied,
 * whatever `unmatched` says; see normalizeRequestPath.
 */

export const TIERS = Object.freeze(['low', 'medium', 'high', 'critical']);
export const MAX_RULES = 256;

const RULE_ID = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
const ACTION = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const METHOD = /^[A-Z][A-Z-]{0,15}$/;
const LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
const DNS_NAME = new RegExp(`^${LABEL}(?:\\.${LABEL})*$`);
const IPV4 = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const IPV6 = /^[0-9a-f:.]+$/;
const MAX_PATH_PATTERN = 1024;
const RULE_KEYS = new Set(['id', 'methods', 'hosts', 'paths', 'action', 'tier']);
const CONFIG_KEYS = new Set(['rules', 'unmatched']);

const isPlainObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

function hostPattern(pattern, where) {
  if (typeof pattern !== 'string' || !pattern) throw new Error(`${where} is a non-empty string.`);
  if (pattern !== pattern.toLowerCase()) throw new Error(`${where} is lowercase.`);
  if (pattern === '*') return { any: true };
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(2);
    if (!DNS_NAME.test(suffix) || !suffix.includes('.')) {
      throw new Error(`${where} "${pattern}" is "*." followed by a domain with at least two labels.`);
    }
    return { suffix: `.${suffix}` };
  }
  if (DNS_NAME.test(pattern) || IPV4.test(pattern)) return { exact: pattern };
  if (pattern.includes(':') && IPV6.test(pattern) && !pattern.includes('*')) return { exact: pattern };
  throw new Error(`${where} "${pattern}" is a host name, an IPv4 address or a complete IPv6 address, with no port.`);
}

function pathPattern(pattern, where) {
  if (typeof pattern !== 'string' || !pattern) throw new Error(`${where} is a non-empty string.`);
  if (pattern.length > MAX_PATH_PATTERN) throw new Error(`${where} is at most ${MAX_PATH_PATTERN} characters.`);
  if (pattern === '*') return { any: true };
  if (!pattern.startsWith('/')) throw new Error(`${where} "${pattern}" starts with "/" (or is "*").`);
  const star = pattern.indexOf('*');
  if (star !== -1 && star !== pattern.length - 1) throw new Error(`${where} "${pattern}" has "*" only at its end.`);
  let normalized;
  try {
    normalized = normalizeRequestPath(star === -1 ? pattern : pattern.slice(0, -1) || '/');
  } catch (error) {
    throw new Error(`${where} "${pattern}": ${error.message}`);
  }
  if (star !== -1) {
    // A prefix keeps the trailing slash it was written with: "/v1/files/*" does not match "/v1/filesystem".
    const prefix = pattern.slice(0, -1).endsWith('/') && !normalized.endsWith('/') ? `${normalized}/` : normalized;
    return { prefix };
  }
  return { exact: normalized.length > 1 && normalized.endsWith('/') ? normalized.slice(0, -1) : normalized };
}

function actionAndTier(value, where) {
  const { action, tier } = value;
  if (typeof action !== 'string' || !ACTION.test(action)) {
    throw new Error(`${where}.action is 1-128 characters of letters, digits, ".", "_", ":" or "-", starting with a letter or digit.`);
  }
  if (!TIERS.includes(tier)) throw new Error(`${where}.tier is one of ${TIERS.join(', ')}.`);
  return { action, tier };
}

/**
 * Checks a policy entry's config. Returns { ok: true, policy } or { ok: false, reason }; the reason names the field.
 * Unknown fields are refused, so a misspelt field never changes what the gate does without anyone noticing.
 */
export function validatePolicyConfig(config) {
  try {
    if (!isPlainObject(config)) throw new Error('config is an object with `rules` (and optionally `unmatched`).');
    for (const key of Object.keys(config)) {
      if (!CONFIG_KEYS.has(key)) throw new Error(`config has an unknown field "${key}".`);
    }
    if (!Array.isArray(config.rules)) throw new Error('config.rules is a list.');
    if (config.rules.length > MAX_RULES) throw new Error(`config.rules has at most ${MAX_RULES} rules.`);
    const ids = new Set();
    const rules = config.rules.map((rule, index) => {
      const where = `config.rules[${index}]`;
      if (!isPlainObject(rule)) throw new Error(`${where} is an object.`);
      for (const key of Object.keys(rule)) {
        if (!RULE_KEYS.has(key)) throw new Error(`${where} has an unknown field "${key}".`);
      }
      if (typeof rule.id !== 'string' || !RULE_ID.test(rule.id)) {
        throw new Error(`${where}.id is 1-64 characters of lowercase letters, digits, ".", "_" or "-".`);
      }
      if (ids.has(rule.id)) throw new Error(`${where}.id "${rule.id}" is used twice.`);
      ids.add(rule.id);
      let methods = null;
      if (rule.methods !== undefined) {
        if (!Array.isArray(rule.methods) || rule.methods.length === 0) throw new Error(`${where}.methods is a non-empty list.`);
        if (rule.methods.length === 1 && rule.methods[0] === '*') {
          methods = null;
        } else {
          methods = new Set(rule.methods.map((method, i) => {
            if (typeof method !== 'string' || !METHOD.test(method)) {
              throw new Error(`${where}.methods[${i}] is an uppercase HTTP method, such as GET or POST (or the list is ["*"]).`);
            }
            return method;
          }));
        }
      }
      if (!Array.isArray(rule.hosts) || rule.hosts.length === 0) throw new Error(`${where}.hosts is a non-empty list.`);
      const hosts = rule.hosts.map((host, i) => hostPattern(host, `${where}.hosts[${i}]`));
      let paths = [{ any: true }];
      if (rule.paths !== undefined) {
        if (!Array.isArray(rule.paths) || rule.paths.length === 0) throw new Error(`${where}.paths is a non-empty list.`);
        paths = rule.paths.map((p, i) => pathPattern(p, `${where}.paths[${i}]`));
      }
      return { id: rule.id, methods, hosts, paths, ...actionAndTier(rule, where) };
    });
    let unmatched = null;
    if (config.unmatched !== undefined && config.unmatched !== 'deny') {
      if (!isPlainObject(config.unmatched)) throw new Error('config.unmatched is "deny" or { action, tier }.');
      for (const key of Object.keys(config.unmatched)) {
        if (key !== 'action' && key !== 'tier') throw new Error(`config.unmatched has an unknown field "${key}".`);
      }
      unmatched = actionAndTier(config.unmatched, 'config.unmatched');
    }
    if (rules.length === 0 && unmatched === null) {
      throw new Error('config.rules is empty and config.unmatched is "deny", so every request would be denied: add a rule.');
    }
    return { ok: true, policy: { rules, unmatched } };
  } catch (error) {
    return { ok: false, reason: error.message };
  }
}

const UNRESERVED = /[A-Za-z0-9\-._~]/;

/**
 * The one reading of a request path the gate classifies, or an Error when there is more than one. Servers disagree
 * about encoded slashes, dot segments, empty segments, path parameters and backslashes, so a path with any of them
 * could reach a different handler than the rule it matched names; the gate denies those rather than guess.
 * Percent-encoded unreserved characters are decoded (RFC 3986, 6.2.2) and other escapes are kept; then the whole path,
 * escapes included, is lower-cased, so matching ignores case: a rule then covers the same path on a case-insensitive
 * server. Rule paths are read the same way, so both sides compare alike.
 */
export function normalizeRequestPath(path) {
  if (typeof path !== 'string' || !path.startsWith('/')) throw new Error('the path does not start with "/"');
  let out = '';
  for (let i = 0; i < path.length; i += 1) {
    const ch = path[i];
    const code = ch.charCodeAt(0);
    if (code <= 0x20 || code === 0x7f) throw new Error('the path has a space or a control character');
    if (ch === '\\') throw new Error('the path has a backslash');
    if (ch === ';') throw new Error('the path has a ";" path parameter');
    if (ch === '%') {
      const hex = path.slice(i + 1, i + 3);
      if (!/^[0-9A-Fa-f]{2}$/.test(hex)) throw new Error('the path has a "%" that is not a percent-escape');
      const decoded = String.fromCharCode(parseInt(hex, 16));
      if (decoded === '/' || decoded === '\\' || decoded === ';' || decoded === '%') {
        throw new Error('the path has an encoded "/", "\\", ";" or "%"');
      }
      out += UNRESERVED.test(decoded) ? decoded : `%${hex.toUpperCase()}`;
      i += 2;
    } else {
      out += ch;
    }
  }
  const segments = out.split('/').slice(1);
  for (let i = 0; i < segments.length; i += 1) {
    const segment = segments[i];
    if (segment === '.' || segment === '..') throw new Error('the path has a "." or ".." segment');
    if (segment === '' && i !== segments.length - 1) throw new Error('the path has an empty segment ("//")');
  }
  return out.toLowerCase();
}

function hostMatches(patterns, host) {
  return patterns.some((p) => p.any || (p.exact !== undefined && p.exact === host)
    || (p.suffix !== undefined && host.endsWith(p.suffix) && host.length > p.suffix.length));
}

function pathMatches(patterns, path) {
  const bare = path.length > 1 && path.endsWith('/') ? path.slice(0, -1) : path;
  return patterns.some((p) => p.any || (p.exact !== undefined && p.exact === bare)
    || (p.prefix !== undefined && path.startsWith(p.prefix)));
}

/**
 * What a request is under a validated policy:
 *   { kind: 'rule', rule_id, action, tier }        the first rule that matches it;
 *   { kind: 'unmatched', rule_id: null, action, tier }  no rule matches, and the policy names an action for that;
 *   { kind: 'deny', reason_code, reason }          no rule matches and the policy denies it, or its path is ambiguous.
 */
export function classifyRequest(policy, target) {
  const method = String(target?.method || '').toUpperCase();
  const host = String(target?.host || '').toLowerCase().replace(/\.$/, '');
  let path;
  try {
    path = normalizeRequestPath(target?.path);
  } catch (error) {
    return { kind: 'deny', reason_code: 'immaculate_ambiguous_path', reason: `The request was denied because ${error.message}, so no rule can be matched to it with certainty.` };
  }
  if (!method || !host) {
    return { kind: 'deny', reason_code: 'immaculate_incomplete_target', reason: 'The request target has no method or no host.' };
  }
  for (const rule of policy.rules) {
    if (rule.methods && !rule.methods.has(method)) continue;
    if (!hostMatches(rule.hosts, host)) continue;
    if (!pathMatches(rule.paths, path)) continue;
    return { kind: 'rule', rule_id: rule.id, action: rule.action, tier: rule.tier };
  }
  if (policy.unmatched) return { kind: 'unmatched', rule_id: null, action: policy.unmatched.action, tier: policy.unmatched.tier };
  return { kind: 'deny', reason_code: 'immaculate_unmatched_request', reason: 'No rule in the policy matches this request, and the policy denies unmatched requests.' };
}
