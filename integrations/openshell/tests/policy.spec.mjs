import assert from 'node:assert/strict';
import test from 'node:test';

import { classifyRequest, normalizeRequestPath, validatePolicyConfig } from '../src/policy.mjs';
import { POLICY } from './helpers.mjs';

const policy = validatePolicyConfig(POLICY).policy;
const classify = (method, host, path, which = policy) => classifyRequest(which, { method, host, path });

test('the example policy validates', () => {
  const checked = validatePolicyConfig(POLICY);
  assert.equal(checked.ok, true, checked.reason);
  assert.equal(checked.policy.rules.length, 4);
  assert.equal(checked.policy.unmatched, null);
});

test('a rule maps a request to its action and tier; the first matching rule wins', () => {
  assert.deepEqual(classify('GET', 'api.crm.example', '/v1/contacts/7'), { kind: 'rule', rule_id: 'crm-read', action: 'crm.read.contacts', tier: 'low' });
  assert.deepEqual(classify('PATCH', 'api.crm.example', '/v1/contacts/7'), { kind: 'rule', rule_id: 'crm-write', action: 'crm.write.contacts', tier: 'medium' });
  assert.equal(classify('POST', 'api.payments.example', '/v1/refunds').tier, 'critical');
  const shadowed = validatePolicyConfig({ rules: [
    { id: 'broad', hosts: ['*'], action: 'any.thing', tier: 'low' },
    { id: 'narrow', hosts: ['api.payments.example'], action: 'payments.refund', tier: 'critical' },
  ] }).policy;
  assert.equal(classify('POST', 'api.payments.example', '/v1/refunds', shadowed).rule_id, 'broad');
});

test('methods, hosts and paths all have to match', () => {
  assert.equal(classify('DELETE', 'api.crm.example', '/v1/contacts/7').kind, 'deny');
  assert.equal(classify('GET', 'api.crm.example.evil', '/v1/contacts/7').kind, 'deny');
  assert.equal(classify('GET', 'api.crm.example', '/v2/contacts/7').kind, 'deny');
  assert.equal(classify('GET', 'api.crm.example', '/v1/contactsx').kind, 'deny', 'a "/x/*" prefix keeps its slash');
});

test('a "*." host pattern covers subdomains, not the apex or look-alikes', () => {
  assert.equal(classify('POST', 'eu.mail.example', '/send').rule_id, 'mail');
  assert.equal(classify('POST', 'a.b.mail.example', '/send').rule_id, 'mail');
  assert.equal(classify('POST', 'mail.example', '/send').kind, 'deny');
  assert.equal(classify('POST', 'evilmail.example', '/send').kind, 'deny');
});

test('hosts and paths compare without case, and an exact path matches with or without one trailing slash', () => {
  assert.equal(classify('get', 'API.CRM.EXAMPLE.', '/V1/Contacts/7').rule_id, 'crm-read');
  assert.equal(classify('POST', 'api.payments.example', '/v1/refunds/').rule_id, 'refunds');
  assert.equal(classify('POST', 'api.payments.example', '/V1/REFUNDS').rule_id, 'refunds');
  assert.equal(classify('POST', 'api.payments.example', '/v1/%72efunds').rule_id, 'refunds', 'an escaped unreserved letter is decoded');
});

test('a path that servers could read more than one way is denied, whatever unmatched says', () => {
  const lenient = validatePolicyConfig({ rules: POLICY.rules, unmatched: { action: 'http.other', tier: 'low' } }).policy;
  for (const path of ['/v1//refunds', '/v1/./refunds', '/v1/x/../refunds', '/v1/refunds;a=b', '/v1%2frefunds', '/v1%5Crefunds', '/v1\\refunds', '/v1/%zz', '/v1/re funds', 'v1/refunds', '/v1/%25']) {
    const result = classify('POST', 'api.payments.example', path, lenient);
    assert.equal(result.kind, 'deny', path);
    assert.equal(result.reason_code, 'immaculate_ambiguous_path', path);
  }
});

test('unmatched requests are denied by default, or classified as the policy says', () => {
  assert.deepEqual(classify('GET', 'elsewhere.example', '/'), {
    kind: 'deny',
    reason_code: 'immaculate_unmatched_request',
    reason: 'No rule in the policy matches this request, and the policy denies unmatched requests.',
  });
  const lenient = validatePolicyConfig({ rules: [], unmatched: { action: 'http.other', tier: 'low' } }).policy;
  assert.deepEqual(classify('GET', 'elsewhere.example', '/', lenient), { kind: 'unmatched', rule_id: null, action: 'http.other', tier: 'low' });
});

test('a request with no method or host is denied', () => {
  assert.equal(classifyRequest(policy, { host: 'api.crm.example', path: '/v1/contacts/7' }).reason_code, 'immaculate_incomplete_target');
  assert.equal(classifyRequest(policy, { method: 'GET', path: '/' }).reason_code, 'immaculate_incomplete_target');
});

test('invalid configs are refused with a reason naming the field', () => {
  const cases = [
    [null, /config is an object/],
    [{ rules: [], unmatched: 'deny' }, /every request would be denied/],
    [{ rules: {} }, /config.rules is a list/],
    [{ rules: [], extra: 1, unmatched: { action: 'a', tier: 'low' } }, /unknown field "extra"/],
    [{ rules: [{ id: 'a', hosts: ['x.example'], action: 'a', tier: 'urgent' }] }, /tier is one of/],
    [{ rules: [{ id: 'a', hosts: ['x.example'], action: 'a.*', tier: 'low' }] }, /action is/],
    [{ rules: [{ id: 'A', hosts: ['x.example'], action: 'a', tier: 'low' }] }, /id is/],
    [{ rules: [{ id: 'a', hosts: ['x.example'], action: 'a', tier: 'low' }, { id: 'a', hosts: ['y.example'], action: 'b', tier: 'low' }] }, /used twice/],
    [{ rules: [{ id: 'a', hosts: ['x.example:443'], action: 'a', tier: 'low' }] }, /no port/],
    [{ rules: [{ id: 'a', hosts: ['X.example'], action: 'a', tier: 'low' }] }, /lowercase/],
    [{ rules: [{ id: 'a', hosts: ['*.example'], action: 'a', tier: 'low' }] }, /at least two labels/],
    [{ rules: [{ id: 'a', hosts: [], action: 'a', tier: 'low' }] }, /hosts is a non-empty list/],
    [{ rules: [{ id: 'a', hosts: ['x.example'], methods: ['get'], action: 'a', tier: 'low' }] }, /uppercase HTTP method/],
    [{ rules: [{ id: 'a', hosts: ['x.example'], paths: ['v1'], action: 'a', tier: 'low' }] }, /starts with "\/"/],
    [{ rules: [{ id: 'a', hosts: ['x.example'], paths: ['/a/*/b'], action: 'a', tier: 'low' }] }, /only at its end/],
    [{ rules: [{ id: 'a', hosts: ['x.example'], paths: ['/a/../b'], action: 'a', tier: 'low' }] }, /"\." or "\.\." segment/],
    [{ rules: [{ id: 'a', hosts: ['x.example'], action: 'a', tier: 'low', allow: true }] }, /unknown field "allow"/],
    [{ rules: [], unmatched: 'allow' }, /"deny" or \{ action, tier \}/],
  ];
  for (const [config, pattern] of cases) {
    const checked = validatePolicyConfig(config);
    assert.equal(checked.ok, false, JSON.stringify(config));
    assert.match(checked.reason, pattern, JSON.stringify(config));
  }
});

test('IPv4 and IPv6 hosts, "*" methods and "*" paths are accepted', () => {
  const checked = validatePolicyConfig({ rules: [
    { id: 'v4', hosts: ['10.0.0.8'], methods: ['*'], paths: ['*'], action: 'net.v4', tier: 'low' },
    { id: 'v6', hosts: ['2001:db8::1'], action: 'net.v6', tier: 'low' },
  ] });
  assert.equal(checked.ok, true, checked.reason);
  assert.equal(classify('PUT', '10.0.0.8', '/anything', checked.policy).rule_id, 'v4');
  assert.equal(classify('GET', '2001:db8::1', '/', checked.policy).rule_id, 'v6');
});

test('normalizeRequestPath decodes unreserved escapes, keeps others, and lower-cases', () => {
  assert.equal(normalizeRequestPath('/A%42c/%7Euser/%C3%A9'), '/abc/~user/%c3%a9');
  assert.equal(normalizeRequestPath('/'), '/');
  assert.equal(normalizeRequestPath('/a/'), '/a/');
});
