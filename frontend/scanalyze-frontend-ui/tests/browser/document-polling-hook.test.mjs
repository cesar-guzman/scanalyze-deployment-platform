import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { chromium, expect } from '@playwright/test';

// Hook-only component harness: real React StrictMode, documentApi, Axios and Chromium.
// The client boundary is synthetic; this does not test application identity or UI.
const root = fileURLToPath(new URL('../../', import.meta.url));
const DOC_ID = 'd'.repeat(32);
const NEXT_ID = 'e'.repeat(32);
const TIME = '2026-09-14T12:00:00.000Z';
const scenarios = new Map();
const caseOptions = { timeout: 25_000 };
let browser;
let server;
let baseUrl;
let nextCase = 0;

const boundarySource = `
  import axios from 'axios';
  const client = axios.create({ baseURL: location.origin + '/api', timeout: 5000,
    headers: { 'X-Synthetic-Case': new URL(location.href).searchParams.get('case') } });
  window.__transportSettled = 0;
  client.interceptors.response.use(response => {
    window.__transportSettled++; return response;
  }, error => { window.__transportSettled++; throw error; });
  export const getApiClient = () => client;
`;

const entrySource = `
  import React, { StrictMode, useEffect, useState } from 'react';
  import { createRoot } from 'react-dom/client';
  import { useDocumentJourney } from './src/hooks/useDocumentJourney';
  let root;
  let latest;
  let lastFunctions;
  const history = [];
  const counters = { commits: 0, mounts: 0, cleanups: 0, changedCallbacks: 0 };
  const control = {
    snapshot: () => latest,
    history: () => history,
    counters: () => ({ ...counters }),
    mount(mode, intervalMs, maxRetries, mountAction) {
      if (root) throw new Error('Already mounted');
      root = createRoot(document.getElementById('container'));
      if (mode !== 'probe') throw new Error('This packet only mounts the polling hook');
      root.render(<StrictMode><Probe intervalMs={intervalMs} maxRetries={maxRetries} mountAction={mountAction} /></StrictMode>);
    },
    unmount() { root.unmount(); root = null; },
  };
  function Probe({ intervalMs, maxRetries, mountAction }) {
    const [options, setOptions] = useState({ intervalMs, maxRetries });
    const [id, setId] = useState('${DOC_ID}');
    const [, render] = useState(0);
    const journey = useDocumentJourney({ documentId: id, ...options });
    useEffect(() => {
      counters.mounts++;
      return () => { counters.cleanups++; };
    }, []);
    useEffect(() => {
      const functions = [journey.startPolling, journey.stopPolling, journey.refetch];
      if (lastFunctions && functions.some((value, index) => value !== lastFunctions[index])) counters.changedCallbacks++;
      lastFunctions = functions;
      latest = { selectedId: id, data: journey.data, error: journey.error?.message ?? null, isPolling: journey.isPolling };
      history.push(latest);
      counters.commits++;
      control.start = journey.startPolling;
      control.stop = journey.stopPolling;
      control.refetch = journey.refetch;
      control.setDocumentId = setId;
      control.setOptions = updates => setOptions(previous => ({ ...previous, ...updates }));
      control.rerender = () => render(value => value + 1);
    });
    useEffect(() => {
      if (mountAction === 'stop') journey.stopPolling();
      if (mountAction === 'start') journey.startPolling();
    }, [mountAction, journey.stopPolling, journey.startPolling]);
    return <output aria-label='Polling probe'>{JSON.stringify({ id, data: journey.data, error: journey.error?.message ?? null, isPolling: journey.isPolling })}</output>;
  }
  window.__polling = control;
`;

function status(documentId, lifecycle = 'PROCESSING') {
  return {
    schemaVersion: 'scanalyze.document-status.v1', contractVersion: 'scanalyze.document-journey.v1',
    documentId, lifecycle, currentStage: ['COMPLETED', 'FAILED'].includes(lifecycle) ? 'TERMINAL' : 'INGEST',
    stageState: lifecycle === 'COMPLETED' ? 'SUCCEEDED' : lifecycle === 'FAILED' ? 'FAILED' : 'RUNNING',
    processingCondition: lifecycle === 'PROCESSING' ? 'ACTIVE' : 'NOT_APPLICABLE',
    createdAt: TIME, updatedAt: TIME,
    ...(lifecycle === 'FAILED' ? { failureDisposition: 'TERMINAL', safeFailureCode: 'DOCUMENT_PROCESSING_FAILED' } : {}),
    ...(['COMPLETED', 'FAILED'].includes(lifecycle) ? { terminalAt: TIME } : {}),
  };
}

before(async () => {
  const output = await build({
    absWorkingDir: root,
    stdin: { contents: entrySource, resolveDir: root, sourcefile: 'synthetic-polling-entry.tsx', loader: 'tsx' },
    write: false, bundle: true, format: 'esm', platform: 'browser', target: 'es2022', jsx: 'automatic', metafile: true,
    define: { 'process.env.NODE_ENV': '"development"' },
    plugins: [{ name: 'isolated-polling-boundaries', setup(plugin) {
      plugin.onResolve({ filter: /^\.\/client$/ }, args => {
        assert.ok(args.importer.endsWith('/src/api/documentApi.ts'));
        return { path: 'client-boundary', namespace: 'synthetic' };
      });
      plugin.onLoad({ filter: /.*/, namespace: 'synthetic' }, () => ({ contents: boundarySource, loader: 'js', resolveDir: root }));
      plugin.onResolve({ filter: /(?:^|\/)(?:auth|config|App|main|DocumentPage)(?:\/|\.|$)|react-oidc-context|oidc-client-ts/ },
        () => ({ errors: [{ text: 'Source is outside the hook-only packet' }] }));
    } }],
  });
  const inputs = Object.keys(output.metafile.inputs);
  for (const path of ['src/hooks/useDocumentJourney.ts', 'src/api/documentApi.ts']) {
    assert.ok(inputs.includes(path), `Real source missing: ${path}`);
  }
  assert.deepEqual(inputs.filter(path => path.startsWith('src/')).sort(), [
    'src/api/documentApi.ts',
    'src/contracts/documentJourney.v1.ts',
    'src/domain/documentResponseValidation.ts',
    'src/hooks/useDocumentJourney.ts',
  ]);
  const bundle = output.outputFiles[0].text;
  server = createServer((request, response) => {
    const url = new URL(request.url, 'http://127.0.0.1');
    response.setHeader('Cache-Control', 'no-store');
    // Serve the shell before API dispatch: every test must load a real root.
    if (url.pathname === '/') {
      response.writeHead(200, { 'Content-Type': 'text/html' });
      return response.end('<!doctype html><title>Synthetic polling</title><div id="container"></div><script type="module" src="/bundle.js"></script>');
    }
    if (url.pathname === '/bundle.js') {
      response.writeHead(200, { 'Content-Type': 'text/javascript' });
      return response.end(bundle);
    }
    if (url.pathname === '/favicon.ico') { response.writeHead(204); return response.end(); }
    const scenario = scenarios.get(request.headers['x-synthetic-case']);
    const match = url.pathname.match(/^\/api\/v2\/documents\/([0-9a-f]{32})$/);
    if (!scenario || !match) {
      if (scenario) scenario.unexpectedPaths.push(url.pathname);
      response.writeHead(404); return response.end();
    }
    const record = { method: request.method, documentId: match[1], kind: 'status', at: performance.now() };
    scenario.requests.push(record);
    const key = `${record.documentId}:${record.kind}`;
    scenario.active.set(key, (scenario.active.get(key) ?? 0) + 1);
    scenario.maxActive = Math.max(scenario.maxActive, scenario.active.get(key));
    let closed = false;
    response.once('close', () => {
      if (closed) return;
      closed = true;
      scenario.active.set(key, scenario.active.get(key) - 1);
    });
    const reply = (body, code = 200) => {
      if (response.destroyed || response.writableEnded) return;
      if (code >= 400) scenario.expectedHttpErrors++;
      record.repliedAt = performance.now();
      response.writeHead(code, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify(body));
    };
    scenario.handler(record, reply, scenario);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
  browser = await chromium.launch({ headless: true });
});

after(async () => {
  await browser?.close();
  if (server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});

async function setup(t, handler, mode = 'probe', intervalMs = 40, options = {}) {
  const caseId = String(++nextCase);
  const scenario = { handler, requests: [], active: new Map(), maxActive: 0, expectedHttpErrors: 0, unexpectedPaths: [] };
  scenarios.set(caseId, scenario);
  const context = await browser.newContext();
  t.after(async () => { await context.close(); scenarios.delete(caseId); });
  await context.route('**/*', route => route.request().url().startsWith(`${baseUrl}/`) ? route.continue() : route.abort());
  const page = await context.newPage();
  page.setDefaultTimeout(5000);
  const errors = [];
  const consoleErrors = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', message => { if (message.type() === 'error') consoleErrors.push(message.text()); });
  if (options.clockNow !== undefined) {
    await page.addInitScript(now => Object.defineProperty(performance, 'now', { value: () => now }), options.clockNow);
  }
  await page.addInitScript(() => {
    const scheduled = [];
    const pending = new Map();
    let peak = 0;
    const set = window.setTimeout.bind(window);
    const clear = window.clearTimeout.bind(window);
    window.setTimeout = (callback, delay, ...args) => {
      // Observe the real hook's caller, not selected delay values: deadlines
      // produce fractional remaining delays and can legitimately rearm at zero.
      // All callbacks still use Chromium's native scheduler and clock.
      const tracked = /\n\s*at armTimer \(/.test(new Error().stack ?? '');
      if (!tracked) return set(callback, delay, ...args);
      const observation = { delay: Number(delay), at: performance.now() };
      observation.dueAt = observation.at + observation.delay;
      const id = set(() => { pending.delete(id); callback(...args); }, delay);
      scheduled.push(observation);
      pending.set(id, observation);
      peak = Math.max(peak, pending.size);
      return id;
    };
    window.clearTimeout = id => { pending.delete(id); clear(id); };
    window.__pollTimers = () => ({ scheduled: [...scheduled], pending: pending.size, peak });
  });
  const response = await page.goto(`${baseUrl}/?case=${caseId}`);
  assert.equal(response.status(), 200);
  await expect(page.locator('#container')).toHaveCount(1);
  await page.waitForFunction(() => typeof window.__polling?.mount === 'function');
  assert.equal(await page.evaluate(() => document.hidden), false);
  await page.evaluate(({ mode, intervalMs, maxRetries, mountAction }) => window.__polling.mount(mode, intervalMs, maxRetries, mountAction), { mode, intervalMs, maxRetries: options.maxRetries ?? 3, mountAction: options.mountAction });
  assert.equal(mode, 'probe');
  await page.waitForFunction(() => !!window.__polling.snapshot());
  const assertClean = () => {
    assert.deepEqual(errors, []);
    assert.deepEqual(consoleErrors.filter(message => !(scenario.expectedHttpErrors > 0 && /^Failed to load resource: the server responded with a status of 503/.test(message))), []);
    assert.ok(scenario.requests.every(request => request.method === 'GET' && request.kind === 'status'));
    assert.deepEqual(scenario.unexpectedPaths, []);
  };
  return { page, scenario, assertClean };
}

const snapshot = page => page.evaluate(() => window.__polling.snapshot());
const statusRequests = scenario => scenario.requests.filter(request => request.kind === 'status');
const assertBackoff = (previous, next, delay) => {
  // Both observations use the server's monotonic clock. Network transit adds
  // time; five milliseconds allow only native timer/clock precision variance.
  const elapsed = next.at - previous.repliedAt;
  assert.ok(elapsed >= delay - 5, `Retry arrived after ${elapsed.toFixed(2)}ms; expected at least ${delay - 5}ms`);
};
const quiet = page => page.waitForTimeout(180); // More than four 40ms probe intervals.
const settle = async (page, count) => {
  await expect.poll(() => page.evaluate(() => window.__transportSettled)).toBe(count);
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(resolve)));
};
const visibleEvents = page => page.evaluate(() => {
  Object.defineProperty(document, 'hidden', { configurable: true, get: () => false });
  for (let index = 0; index < 12; index++) document.dispatchEvent(new Event('visibilitychange'));
});

test('visible StrictMode mount starts once and keeps all public callbacks stable', caseOptions, async t => {
  let release;
  const { page, scenario, assertClean } = await setup(t, (_record, reply) => { release = reply; });
  await expect.poll(() => scenario.requests.length).toBe(1);
  const counters = await page.evaluate(() => window.__polling.counters());
  assert.equal(counters.mounts, 2);
  assert.equal(counters.cleanups, 1);
  release(status(DOC_ID, 'COMPLETED'));
  await expect.poll(async () => (await snapshot(page)).data?.lifecycle).toBe('COMPLETED');
  await page.evaluate(() => window.__polling.rerender());
  await settle(page, 1);
  assert.equal((await page.evaluate(() => window.__polling.counters())).changedCallbacks, 0);
  assert.equal(scenario.requests.length, 1);
  assertClean();
});

test('repeated visibility events keep one request and one subsequent timer', caseOptions, async t => {
  const held = [];
  const { page, scenario, assertClean } = await setup(t, (_record, reply) => held.push(reply));
  await expect.poll(() => held.length).toBe(1);
  await visibleEvents(page);
  await quiet(page);
  assert.equal(held.length, 1);
  held[0](status(DOC_ID));
  await expect.poll(() => held.length).toBe(2);
  await visibleEvents(page);
  await quiet(page);
  assert.equal(held.length, 2);
  assert.equal(scenario.maxActive, 1);
  const timers = await page.evaluate(() => window.__pollTimers());
  assert.ok(timers.scheduled.length > 0, 'The real hook timer must be observed');
  assert.equal(timers.peak, 1);
  await page.evaluate(() => window.__polling.stop());
  held[1](status(DOC_ID, 'COMPLETED'));
  assertClean();
});

test('terminal status stops timers and visibility cannot revive polling', caseOptions, async t => {
  const { page, scenario, assertClean } = await setup(t, (_record, reply) => reply(status(DOC_ID, 'COMPLETED')));
  await expect.poll(async () => (await snapshot(page)).data?.lifecycle).toBe('COMPLETED');
  assert.equal((await snapshot(page)).isPolling, false);
  await visibleEvents(page);
  await quiet(page);
  assert.equal(scenario.requests.length, 1);
  assert.equal((await page.evaluate(() => window.__pollTimers())).pending, 0);
  assertClean();
});

test('three errors exhaust exponential backoff and reconnect the same document with GET', caseOptions, async t => {
  const { page, scenario, assertClean } = await setup(t, (_record, reply, io) => {
    if (io.requests.length <= 3) reply({ code: 'SYNTHETIC_UNAVAILABLE' }, 503);
    else reply(status(DOC_ID, 'COMPLETED'));
  });
  await expect.poll(async () => (await snapshot(page)).error).toBe('DOCUMENT_STATUS_UNAVAILABLE');
  assert.equal((await snapshot(page)).isPolling, false);
  await quiet(page);
  assert.equal(scenario.requests.length, 3);
  assertBackoff(scenario.requests[0], scenario.requests[1], 80);
  assertBackoff(scenario.requests[1], scenario.requests[2], 160);
  const timers = await page.evaluate(() => window.__pollTimers());
  assert.ok(timers.scheduled.length >= 2, 'Both backoff periods must be observed');
  assert.equal(timers.peak, 1);
  assert.equal(timers.pending, 0);
  await page.evaluate(() => { window.__polling.start(); window.__polling.start(); });
  await expect.poll(async () => (await snapshot(page)).data?.lifecycle).toBe('COMPLETED');
  assert.equal((await snapshot(page)).error, null);
  assert.equal(scenario.requests.length, 4);
  assert.ok(scenario.requests.every(request => request.documentId === DOC_ID));
  assertClean();
});

test('hidden then visible during backoff preserves the existing retry deadline', caseOptions, async t => {
  let release;
  const { page, scenario, assertClean } = await setup(t, (_record, reply, io) => {
    if (io.requests.length === 1) release = reply;
    else reply(status(DOC_ID, 'COMPLETED'));
  }, 'probe', 200); // A real 400ms first backoff leaves a stable driver observation window.
  await expect.poll(() => typeof release).toBe('function');
  release({ code: 'SYNTHETIC_UNAVAILABLE' }, 503);
  await page.waitForFunction(() => window.__pollTimers().pending === 1);
  const transition = await page.evaluate(async () => {
    const original = window.__pollTimers().scheduled.at(-1);
    Object.defineProperty(document, 'hidden', { configurable: true, get: () => true });
    document.dispatchEvent(new Event('visibilitychange'));
    const hiddenPending = window.__pollTimers().pending;
    await new Promise(resolve => setTimeout(resolve, 20));
    Object.defineProperty(document, 'hidden', { configurable: true, get: () => false });
    const visibleAt = performance.now();
    for (let index = 0; index < 12; index++) document.dispatchEvent(new Event('visibilitychange'));
    return { original, hiddenPending, visibleAt, timers: window.__pollTimers() };
  });
  assert.equal(transition.hiddenPending, 0);
  assert.ok(transition.visibleAt < transition.original.dueAt, 'Visibility must return inside the backoff window');
  assert.equal(transition.timers.pending, 1);
  assert.equal(transition.timers.peak, 1);
  assert.ok(Math.abs(transition.timers.scheduled.at(-1).dueAt - transition.original.dueAt) <= 5,
    'Visibility must retain the existing deadline');
  assert.equal(scenario.requests.length, 1, 'Visibility must not send an early retry');
  await expect.poll(async () => (await snapshot(page)).data?.lifecycle).toBe('COMPLETED');
  assert.equal(scenario.requests.length, 2);
  assertBackoff(scenario.requests[0], scenario.requests[1], 400);
  assert.equal(scenario.maxActive, 1);
  assert.equal((await page.evaluate(() => window.__pollTimers())).pending, 0);
  assertClean();
});

test('double start during an in-flight GET preserves that response without duplicating work', caseOptions, async t => {
  let release;
  const { page, scenario, assertClean } = await setup(t, (_record, reply, io) => {
    if (io.requests.length === 1) release = reply;
    else reply(status(DOC_ID, 'COMPLETED'));
  });
  await expect.poll(() => typeof release).toBe('function');
  await page.evaluate(() => { window.__polling.start(); window.__polling.start(); });
  await quiet(page);
  assert.equal(scenario.requests.length, 1);
  release(status(DOC_ID));
  await expect.poll(async () => (await snapshot(page)).data?.lifecycle).toBe('COMPLETED');
  assert.ok((await page.evaluate(() => window.__polling.history())).some(value => value.data?.lifecycle === 'PROCESSING'));
  assert.equal(scenario.requests.length, 2);
  assert.equal(scenario.maxActive, 1);
  assertClean();
});

test('stop then start retains the pending lease and discards its old generation before one new GET', caseOptions, async t => {
  const held = [];
  const { page, scenario, assertClean } = await setup(t, (_record, reply) => held.push(reply));
  await expect.poll(() => held.length).toBe(1);
  await page.evaluate(() => { window.__polling.stop(); window.__polling.start(); window.__polling.start(); });
  await expect.poll(async () => (await snapshot(page)).isPolling).toBe(true);
  await quiet(page);
  assert.equal(held.length, 1, 'Restart must wait for the outstanding read to settle');
  held[0](status(DOC_ID, 'FAILED'));
  await expect.poll(() => held.length).toBe(2);
  await settle(page, 1);
  assert.equal((await snapshot(page)).data, null);
  assert.equal((await snapshot(page)).error, null);
  assert.equal((await snapshot(page)).isPolling, true);
  assert.equal((await page.evaluate(() => window.__polling.history())).some(value => value.data?.lifecycle === 'FAILED'), false);
  await quiet(page);
  assert.equal(held.length, 2);
  assert.equal(scenario.maxActive, 1);
  const timers = await page.evaluate(() => window.__pollTimers());
  assert.ok(timers.scheduled.some(timer => timer.delay === 0), 'Observe the immediate new-generation wake');
  assert.equal(timers.peak, 1);
  held[1](status(DOC_ID, 'COMPLETED'));
  await expect.poll(async () => (await snapshot(page)).data?.lifecycle).toBe('COMPLETED');
  await quiet(page);
  assert.equal(scenario.requests.length, 2);
  assert.equal((await page.evaluate(() => window.__pollTimers())).pending, 0);
  assertClean();
});

test('stop discards a delayed response without callbacks or later requests', caseOptions, async t => {
  let release;
  const { page, scenario, assertClean } = await setup(t, (_record, reply) => { release = reply; });
  await expect.poll(() => typeof release).toBe('function');
  await page.evaluate(() => window.__polling.stop());
  await expect.poll(async () => (await snapshot(page)).isPolling).toBe(false);
  const before = await page.evaluate(() => window.__polling.counters());
  release(status(DOC_ID, 'COMPLETED'));
  await settle(page, 1);
  await visibleEvents(page);
  await quiet(page);
  assert.equal((await page.evaluate(() => window.__polling.counters())).commits, before.commits);
  assert.equal((await snapshot(page)).data, null);
  assert.equal(scenario.requests.length, 1);
  assert.equal((await page.evaluate(() => window.__pollTimers())).pending, 0);
  assertClean();
});

test('real React unmount discards pending data and leaves no timers or later callbacks', caseOptions, async t => {
  let release;
  const { page, scenario, assertClean } = await setup(t, (_record, reply) => { release = reply; });
  await expect.poll(() => typeof release).toBe('function');
  const before = await page.evaluate(() => window.__polling.counters());
  await page.evaluate(() => window.__polling.unmount());
  await expect(page.locator('#container > *')).toHaveCount(0);
  // A nonterminal response would schedule another poll if hook cleanup failed;
  // COMPLETED would stop itself and could hide a broken unmount guard.
  release(status(DOC_ID));
  await settle(page, 1);
  await visibleEvents(page);
  await quiet(page);
  const after = await page.evaluate(() => window.__polling.counters());
  assert.equal(after.cleanups, before.cleanups + 1);
  assert.equal(after.commits, before.commits);
  assert.equal(scenario.requests.length, 1);
  assert.equal((await page.evaluate(() => window.__pollTimers())).pending, 0);
  assertClean();
});

test('document id change accepts the new response and discards the old pending response', caseOptions, async t => {
  let releaseOld;
  const { page, scenario, assertClean } = await setup(t, (record, reply) => {
    if (record.documentId === DOC_ID) releaseOld = reply;
    else reply(status(NEXT_ID, 'COMPLETED'));
  });
  await expect.poll(() => typeof releaseOld).toBe('function');
  await page.evaluate(id => window.__polling.setDocumentId(id), NEXT_ID);
  await expect.poll(async () => (await snapshot(page)).data?.documentId).toBe(NEXT_ID);
  const before = await page.evaluate(() => window.__polling.counters());
  releaseOld(status(DOC_ID, 'FAILED'));
  await settle(page, 2);
  await quiet(page);
  assert.equal((await snapshot(page)).data.documentId, NEXT_ID);
  assert.equal((await page.evaluate(() => window.__polling.counters())).commits, before.commits);
  assert.equal((await page.evaluate(() => window.__polling.counters())).changedCallbacks, 0);
  assert.deepEqual(statusRequests(scenario).map(request => request.documentId), [DOC_ID, NEXT_ID]);
  assertClean();
});



test('mount stop precedes deferred automatic startup and sends no GET', caseOptions, async t => {
  const { page, scenario, assertClean } = await setup(t, (_record, reply) => reply(status(DOC_ID)), 'probe', 40, { mountAction: 'stop' });
  await quiet(page);
  assert.equal(scenario.requests.length, 0);
  assert.equal((await snapshot(page)).isPolling, false);
  assert.equal((await page.evaluate(() => window.__pollTimers())).pending, 0);
  assertClean();
});

test('mount start retains an accurate indicator while its only GET is pending', caseOptions, async t => {
  let release;
  const { page, scenario, assertClean } = await setup(t, (_record, reply) => { release = reply; }, 'probe', 40, { mountAction: 'start' });
  await expect.poll(() => scenario.requests.length).toBe(1);
  assert.equal((await snapshot(page)).isPolling, true);
  release(status(DOC_ID, 'COMPLETED'));
  await expect.poll(async () => (await snapshot(page)).data?.lifecycle).toBe('COMPLETED');
  assert.equal(scenario.requests.length, 1);
  assertClean();
});

for (const update of [{ intervalMs: 80 }, { maxRetries: 2 }]) {
  test(`changing ${Object.keys(update)[0]} waits for the same document's pending GET`, caseOptions, async t => {
    const held = [];
    const { page, scenario, assertClean } = await setup(t, (_record, reply) => held.push(reply));
    await expect.poll(() => held.length).toBe(1);
    await page.evaluate(value => window.__polling.setOptions(value), update);
    await quiet(page);
    assert.equal(held.length, 1, 'Option changes must retain the active read until it settles');
    held[0](status(DOC_ID));
    await expect.poll(() => held.length).toBe(2);
    assert.equal((await snapshot(page)).data, null, 'The previous generation must not publish');
    assert.equal(scenario.maxActive, 1);
    held[1](status(DOC_ID, 'COMPLETED'));
    await expect.poll(async () => (await snapshot(page)).data?.lifecycle).toBe('COMPLETED');
    assertClean();
  });
}

for (const interval of [NaN, Infinity, 0, -1, 0.5, 2 ** 31]) {
  test(`invalid interval ${String(interval)} uses the existing 3000ms default`, caseOptions, async t => {
    const { page, scenario, assertClean } = await setup(t, (_record, reply) => reply(status(DOC_ID)), 'probe', interval);
    await page.waitForFunction(() => window.__pollTimers().scheduled.length > 0);
    const timers = await page.evaluate(() => window.__pollTimers());
    assert.ok(timers.scheduled.every(timer => timer.delay > 2900 && timer.delay <= 3000));
    await page.evaluate(() => window.__polling.stop());
    assert.equal(scenario.requests.length, 1);
    assertClean();
  });
}

for (const retries of [NaN, Infinity, 0, -1, 1.5]) {
  test(`invalid retry count ${String(retries)} uses the existing three-attempt default`, caseOptions, async t => {
    const { page, scenario, assertClean } = await setup(t, (_record, reply) => reply({ code: 'SYNTHETIC_UNAVAILABLE' }, 503), 'probe', 40, { maxRetries: retries });
    await expect.poll(async () => (await snapshot(page)).error).toBe('DOCUMENT_STATUS_UNAVAILABLE');
    assert.equal(scenario.requests.length, 3);
    assert.equal((await snapshot(page)).isPolling, false);
    assertClean();
  });
}

test('large backoff saturates below the native timer overflow boundary', caseOptions, async t => {
  const maximum = 2 ** 31 - 1;
  // A fractional clock deterministically exercises rounding in deadline subtraction.
  const { page, scenario, assertClean } = await setup(t, (_record, reply) => reply({ code: 'SYNTHETIC_UNAVAILABLE' }, 503), 'probe', maximum, { clockNow: 1.3 });
  await page.waitForFunction(() => window.__pollTimers().scheduled.length > 0);
  const timers = await page.evaluate(() => window.__pollTimers());
  assert.ok(timers.scheduled.every(timer => timer.delay > maximum - 1000 && timer.delay <= maximum),
    `Observed native timer delays: ${JSON.stringify(timers.scheduled.map(timer => timer.delay))}`);
  await page.evaluate(() => window.__polling.stop());
  assert.equal(scenario.requests.length, 1);
  assertClean();
});

for (const state of ['stopped', 'terminal']) {
  for (const update of [{ intervalMs: 80 }, { maxRetries: 2 }]) {
    test(`option changes do not restart ${state} polling: ${Object.keys(update)[0]}`, caseOptions, async t => {
      const held = [];
      const { page, scenario, assertClean } = await setup(t, (_record, reply) => held.push(reply));
      await expect.poll(() => held.length).toBe(1);
      if (state === 'stopped') await page.evaluate(() => window.__polling.stop());
      held[0](status(DOC_ID, state === 'terminal' ? 'COMPLETED' : 'PROCESSING'));
      await settle(page, 1);
      await expect.poll(async () => (await snapshot(page)).isPolling).toBe(false);
      await page.evaluate(value => window.__polling.setOptions(value), update);
      await quiet(page);
      assert.equal(held.length, 1, 'Changing options must retain stopped/terminal intent');
      assert.equal((await snapshot(page)).isPolling, false);
      assert.equal((await page.evaluate(() => window.__pollTimers())).pending, 0);
      await page.evaluate(() => window.__polling.start());
      await expect.poll(() => held.length).toBe(2);
      held[1](status(DOC_ID, 'COMPLETED'));
      await expect.poll(async () => (await snapshot(page)).data?.lifecycle).toBe('COMPLETED');
      assert.equal(scenario.requests.length, 2);
      assertClean();
    });
  }
}
