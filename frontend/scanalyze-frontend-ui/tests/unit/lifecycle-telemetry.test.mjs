import assert from 'node:assert/strict';
import test from 'node:test';

import {
  clearLifecycleTelemetryForTest,
  lifecycleTelemetrySnapshot,
  recordLifecycleUiEvent,
} from '../../src/telemetry/lifecycleTelemetry.js';

test.beforeEach(() => clearLifecycleTelemetryForTest());

test('records only allowlisted lifecycle telemetry without PII or payloads', () => {
  recordLifecycleUiEvent({
    operation: 'memberships.list',
    result: 'success',
    correlationReference: `ref_${'a'.repeat(32)}`,
    now: () => '2026-07-14T00:00:00.000Z',
  });

  assert.deepEqual(lifecycleTelemetrySnapshot(), [{
    schemaVersion: 'lifecycle-ui-event.v1',
    operation: 'memberships.list',
    result: 'success',
    correlationReference: `ref_${'a'.repeat(32)}`,
    timestamp: '2026-07-14T00:00:00.000Z',
  }]);
});

test('rejects unknown operations, results and external correlation values', () => {
  for (const event of [
    { operation: 'email.synthetic@example.invalid', result: 'success' },
    { operation: 'memberships.list', result: 'raw-payload' },
    {
      operation: 'memberships.list',
      result: 'denied',
      correlationReference: 'Synthetic Person <pii@example.invalid>',
    },
  ]) {
    assert.throws(() => recordLifecycleUiEvent(event));
  }
  assert.deepEqual(lifecycleTelemetrySnapshot(), []);
});

test('uses a bounded in-memory ring and never accepts arbitrary event fields', () => {
  assert.throws(() => recordLifecycleUiEvent({
    operation: 'memberships.list',
    result: 'success',
    email: 'synthetic@example.invalid',
  }));

  for (let index = 0; index < 60; index += 1) {
    recordLifecycleUiEvent({ operation: 'memberships.list', result: 'success' });
  }
  assert.equal(lifecycleTelemetrySnapshot().length, 50);
});
