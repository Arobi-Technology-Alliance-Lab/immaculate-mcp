/**
 * Copyright (c) 2026 Arobi Technology Alliance, Inc. All Rights Reserved.
 *
 * The gRPC services OpenShell calls (OpenShell's supervisor_middleware.proto, package openshell.middleware.v1):
 *   - SupervisorMiddleware.Describe: the manifest. One binding, HTTP_REQUEST at PRE_CREDENTIALS, with a zero payload
 *     limit (the gate decides on the request head; it never reads bodies). The extension metadata supports and requires
 *     the HTTP hooks capability, so a gateway or supervisor without HTTP hooks refuses the service at Describe. The
 *     gateway's metadata is checked the way OpenShell's own extensions check it.
 *   - SupervisorMiddleware.ValidateConfig: the policy entry's config, checked by policy.mjs.
 *   - HttpHooks.EvaluateHttpRequestHook: one stream per request. The preflight comes first; the gate answers
 *     continue_without_body or deny, then closes its side. Anything else fails the exchange, and OpenShell then blocks
 *     the request: HTTP hooks always fail closed.
 * The legacy and WebSocket RPCs answer UNIMPLEMENTED; the manifest declares no binding that would call them.
 */

import { readFileSync } from 'node:fs';

import grpc from '@grpc/grpc-js';
import protoLoader from '@grpc/proto-loader';

import { validatePolicyConfig } from './policy.mjs';
import { assertProtocolFiles, PROTOCOL_DIR } from './protocol.mjs';
import { structToJson } from './struct.mjs';

export const CONTRACT_CAPABILITY = 'openshell.supervisor-middleware.contract';
export const HTTP_HOOKS_CAPABILITY = 'openshell.supervisor-middleware.http-hooks';
export const IMPLEMENTATION_NAME = 'arobi/immaculate-openshell-gate';
export const PROTOCOL = Object.freeze({ major: 1, minor: 0 });
export const PRE_CREDENTIALS = 'SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS';
export const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;

const PREFLIGHT_TIMEOUT_MS = 30_000;
const MAX_CAPABILITIES = 128;
const CAPABILITY = /^openshell(\.[a-z0-9-]+){2,}$/;

/** The openshell.middleware.v1 package, from the protocol files fetched at the pinned commit (src/protocol.mjs). */
export function loadProtocol() {
  assertProtocolFiles();
  const definition = protoLoader.loadSync('supervisor_middleware.proto', {
    includeDirs: [PROTOCOL_DIR],
    keepCase: true,
    longs: String,
    enums: String,
    defaults: false,
    arrays: true,
    objects: true,
    oneofs: true,
  });
  return grpc.loadPackageDefinition(definition).openshell.middleware.v1;
}

function capabilityProblem(list, field) {
  if (list.length > MAX_CAPABILITIES) return `${field} has more than ${MAX_CAPABILITIES} entries`;
  const seen = new Set();
  for (const capability of list) {
    if (typeof capability !== 'string' || capability.length > 128 || !CAPABILITY.test(capability)) {
      return `${field} has "${capability}", which is not a lowercase namespaced capability`;
    }
    if (seen.has(capability)) return `${field} lists "${capability}" twice`;
    seen.add(capability);
  }
  return null;
}

/**
 * Why the gateway's Describe metadata is unacceptable, or null. The same checks OpenShell applies between its peers:
 * metadata present, the same protocol major version, valid capability lists, and each side supporting every capability
 * the other requires.
 */
export function gatewayMetadataProblem(gateway, extension) {
  if (!gateway) return 'Describe carries no gateway metadata; this middleware needs a gateway that negotiates protocol 1.0.';
  const version = gateway.protocol_version;
  if (!version) return 'The gateway metadata has no protocol_version.';
  if (Number(version.major ?? 0) !== PROTOCOL.major) {
    return `The gateway speaks protocol ${version.major ?? 0}.${version.minor ?? 0}; this middleware speaks ${PROTOCOL.major}.${PROTOCOL.minor}.`;
  }
  const supported = gateway.supported_capabilities || [];
  const required = gateway.required_capabilities || [];
  const listProblem = capabilityProblem(supported, 'The gateway supported_capabilities') || capabilityProblem(required, 'The gateway required_capabilities');
  if (listProblem) return `${listProblem}.`;
  const unmet = required.filter((capability) => !extension.supported_capabilities.includes(capability));
  if (unmet.length) return `The gateway requires capabilities this middleware does not support: ${unmet.join(', ')}.`;
  const missing = extension.required_capabilities.filter((capability) => !supported.includes(capability));
  if (missing.length) {
    return `The gateway does not support ${missing.join(', ')}, which this middleware requires: use an OpenShell gateway and supervisors with HTTP hooks.`;
  }
  return null;
}

/** The first event of a stream, or null when the stream ends first. Leaves the stream paused. */
function firstEvent(call, timeoutMs) {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      clearTimeout(timer);
      call.removeListener('data', onData);
      call.removeListener('end', onEnd);
      call.removeListener('cancelled', onEnd);
    };
    const onData = (message) => {
      cleanup();
      call.pause();
      resolve(message);
    };
    const onEnd = () => {
      cleanup();
      resolve(null);
    };
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`no preflight arrived within ${timeoutMs} ms`));
    }, timeoutMs);
    call.on('data', onData);
    call.once('end', onEnd);
    call.once('cancelled', onEnd);
  });
}

function unimplementedStream(details) {
  return (call) => call.emit('error', { code: grpc.status.UNIMPLEMENTED, details });
}

/**
 * The service implementations, unbound, so a test or another server can host them.
 * @param {object} options
 * @param {import('./gate.mjs').ImmaculateGate} options.gate
 * @param {import('./auth.mjs').ExtensionTokenVerifier|null} [options.verifier]  null only for plaintext development
 * @param {(level: string, message: string, fields?: object) => void} [options.log]
 */
export function createGateService({ gate, verifier = null, log = () => {} }) {
  const proto = loadProtocol();
  const extension = {
    protocol_version: { ...PROTOCOL },
    implementation_name: IMPLEMENTATION_NAME,
    implementation_version: VERSION,
    supported_capabilities: [CONTRACT_CAPABILITY, HTTP_HOOKS_CAPABILITY],
    required_capabilities: [CONTRACT_CAPABILITY, HTTP_HOOKS_CAPABILITY],
  };
  const manifest = {
    name: IMPLEMENTATION_NAME,
    service_version: VERSION,
    bindings: [{
      operation: 'SUPERVISOR_MIDDLEWARE_OPERATION_HTTP_REQUEST',
      phase: PRE_CREDENTIALS,
      max_payload_bytes: 0,
    }],
    expected_audience: verifier ? verifier.audience : '',
    extension,
  };

  const authenticate = (call) => (verifier ? verifier.verify(call.metadata.get('authorization')) : Promise.resolve({ ok: true, claims: null }));

  const supervisorMiddleware = {
    Describe(call, callback) {
      authenticate(call).then((auth) => {
        if (!auth.ok) {
          log('warn', 'Describe refused: the caller is not authenticated', { reason: auth.reason });
          callback({ code: grpc.status.UNAUTHENTICATED, details: auth.reason });
          return;
        }
        const problem = gatewayMetadataProblem(call.request.gateway, extension);
        if (problem) {
          log('warn', 'Describe refused: incompatible gateway', { reason: problem });
          callback({ code: grpc.status.FAILED_PRECONDITION, details: problem });
          return;
        }
        callback(null, manifest);
      }).catch((error) => callback({ code: grpc.status.INTERNAL, details: error.message }));
    },

    ValidateConfig(call, callback) {
      authenticate(call).then((auth) => {
        if (!auth.ok) {
          callback({ code: grpc.status.UNAUTHENTICATED, details: auth.reason });
          return;
        }
        let config;
        try {
          config = structToJson(call.request.config);
        } catch (error) {
          callback(null, { valid: false, reason: `config: ${error.message}` });
          return;
        }
        const checked = validatePolicyConfig(config);
        callback(null, { valid: checked.ok, reason: checked.ok ? '' : checked.reason });
      }).catch((error) => callback({ code: grpc.status.INTERNAL, details: error.message }));
    },

    EvaluateHttpRequest(call, callback) {
      callback({ code: grpc.status.UNIMPLEMENTED, details: 'The Immaculate gate implements HTTP hooks only (HttpHooks.EvaluateHttpRequestHook).' });
    },

    EvaluateWebSocketSession: unimplementedStream('The Immaculate gate evaluates HTTP requests only.'),
  };

  async function evaluateRequest(call) {
    let finished = false;
    const finish = (result) => {
      if (finished) return;
      finished = true;
      if (!call.cancelled) {
        call.write(result);
        call.end();
      }
    };
    // A status the gate sends itself is emitted as 'error' on the call; only other errors (a cancelled or broken
    // stream) are worth a log line.
    const ownStatuses = new WeakSet();
    const fail = (code, details) => {
      if (finished) return;
      finished = true;
      if (!call.cancelled) {
        const status = { code, details };
        ownStatuses.add(status);
        call.emit('error', status);
      }
    };
    call.on('error', (error) => {
      if (!ownStatuses.has(error)) log('warn', 'request hook stream error', { error: error?.message ?? String(error) });
    });

    const auth = await authenticate(call);
    if (!auth.ok) {
      log('warn', 'request hook refused: the caller is not authenticated', { reason: auth.reason });
      fail(grpc.status.UNAUTHENTICATED, auth.reason);
      return;
    }
    let event;
    try {
      event = await firstEvent(call, PREFLIGHT_TIMEOUT_MS);
    } catch (error) {
      fail(grpc.status.DEADLINE_EXCEEDED, error.message);
      return;
    }
    if (!event || call.cancelled) return;
    if (event.event !== 'preflight' || !event.preflight) {
      fail(grpc.status.FAILED_PRECONDITION, 'The first event of a request hook stream is its preflight.');
      return;
    }
    // Later events (a best-effort session_end) need no answer; read them so the stream never stalls.
    call.on('data', () => {});
    call.resume();

    const { preflight } = event;
    let refusal;
    let policy = null;
    if (preflight.phase !== PRE_CREDENTIALS) {
      refusal = { reason_code: 'immaculate_unsupported_phase', reason: `The gate evaluates requests at PRE_CREDENTIALS, not ${preflight.phase ?? 'an unset phase'}.` };
    } else {
      let config;
      try {
        config = structToJson(preflight.config);
      } catch (error) {
        config = undefined;
        refusal = { reason_code: 'immaculate_config_invalid', reason: `config: ${error.message}` };
      }
      if (!refusal) {
        const checked = validatePolicyConfig(config);
        if (checked.ok) policy = checked.policy;
        else refusal = { reason_code: 'immaculate_config_invalid', reason: checked.reason };
      }
    }
    const decision = gate.decide({
      target: preflight.request?.target,
      context: preflight.context,
      policy,
      caller: auth.claims,
      refusal,
    });
    log('info', 'decision', {
      request_id: preflight.context?.request_id || null,
      sandbox_id: preflight.context?.sandbox_id || null,
      verdict: decision.verdict,
      reason_code: decision.reason_code || null,
      action: decision.metadata.immaculate_action || null,
      tier: decision.metadata.immaculate_tier || null,
      rule: decision.metadata.immaculate_rule || null,
      record: decision.metadata.immaculate_record || null,
    });
    if (decision.verdict === 'continue') {
      finish({ preflight_result: { continue_without_body: {}, diagnostics: { reason: decision.reason, metadata: decision.metadata } } });
    } else {
      finish({ deny: { diagnostics: { reason: decision.reason, reason_code: decision.reason_code, metadata: decision.metadata } } });
    }
  }

  const httpHooks = {
    EvaluateHttpRequestHook(call) {
      evaluateRequest(call).catch((error) => {
        log('error', 'request hook failed; the exchange fails closed', { error: error.message });
        if (!call.cancelled) call.emit('error', { code: grpc.status.INTERNAL, details: 'The gate failed to evaluate the request.' });
      });
    },
    EvaluateHttpResponseHook: unimplementedStream('The Immaculate gate evaluates requests only; it declares no response binding.'),
  };

  return { proto, manifest, supervisorMiddleware, httpHooks };
}

/** A gRPC server with both services added; the caller binds it. */
export function createGateServer(options) {
  const { proto, supervisorMiddleware, httpHooks } = createGateService(options);
  const server = new grpc.Server();
  server.addService(proto.SupervisorMiddleware.service, supervisorMiddleware);
  server.addService(proto.HttpHooks.service, httpHooks);
  return server;
}
