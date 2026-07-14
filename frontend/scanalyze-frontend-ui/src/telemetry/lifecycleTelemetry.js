const OPERATIONS = new Set([
  'roles.read',
  'memberships.list',
  'invitations.create',
  'invitations.resend',
  'membership.activate',
  'membership.change_role',
  'membership.suspend',
  'membership.reactivate',
  'membership.revoke',
  'sessions.revoke',
  'audit.read',
]);
const RESULTS = new Set([
  'success',
  'denied',
  'conflict',
  'invalid',
  'session_expired',
  'degraded',
  'rate_limited',
]);
const INPUT_KEYS = new Set(['operation', 'result', 'correlationReference', 'now']);
const REFERENCE = /^ref_[0-9a-f]{24,64}$/u;
const MAX_EVENTS = 50;
const events = [];

const reject = () => {
  throw new TypeError('LIFECYCLE_TELEMETRY_REJECTED');
};

export const recordLifecycleUiEvent = (input) => {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) reject();
  if (Object.keys(input).some((key) => !INPUT_KEYS.has(key))) reject();
  if (!OPERATIONS.has(input.operation) || !RESULTS.has(input.result)) reject();
  if (
    input.correlationReference !== undefined
    && input.correlationReference !== null
    && (typeof input.correlationReference !== 'string'
      || !REFERENCE.test(input.correlationReference))
  ) reject();
  if (input.now !== undefined && typeof input.now !== 'function') reject();

  const timestamp = (input.now ?? (() => new Date().toISOString()))();
  if (typeof timestamp !== 'string' || Number.isNaN(Date.parse(timestamp))) reject();
  const event = Object.freeze({
    schemaVersion: 'lifecycle-ui-event.v1',
    operation: input.operation,
    result: input.result,
    correlationReference: input.correlationReference ?? null,
    timestamp,
  });
  events.push(event);
  if (events.length > MAX_EVENTS) events.splice(0, events.length - MAX_EVENTS);
  if (typeof globalThis.window?.dispatchEvent === 'function') {
    globalThis.window.dispatchEvent(new CustomEvent('scanalyze:lifecycle-ui-event', {
      detail: event,
    }));
  }
  return event;
};

export const lifecycleTelemetrySnapshot = () => events.map((event) => ({ ...event }));

export const clearLifecycleTelemetryForTest = () => {
  events.splice(0, events.length);
};
