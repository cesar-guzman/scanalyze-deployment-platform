import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { chromium, expect } from '@playwright/test';

// Run: node --test tests/browser/bulk-recovery-review.test.mjs
// Independent review against REAL BulkUploadRecovery + BulkUpload (esbuild bundle,
// Chromium sessionStorage, Axios). Complements tests/browser/bulk-upload-recovery.test.mjs
// against the integrated product. Covers causal gaps: storage replace mid-await,
// config scope change after await, batch CREATE PENDING uncertainty, lease across
// React remount/unmount. Synthetic network boundaries; no cloud access.
const root = fileURLToPath(new URL('../../', import.meta.url));
const CONTRACT = 'scanalyze.document-journey.v1';
const ACTOR = 'synthetic-bulk-actor-a';
const BATCH_ID = 'b'.repeat(32);
const TIME = '2026-09-14T12:00:00.000Z';
const scenarios = new Map();
let browser;
let server;
let baseUrl;

const fixtureSource = `
  import { useSyncExternalStore } from 'react';
  import { User } from 'oidc-client-ts';
  import axios from 'axios';
  export const config = {
    apiBaseUrl: location.origin + '/api',
    cognitoIssuerUrl: 'https://identity.synthetic.invalid/pool',
    cognitoClientId: 'synthetic-client',
    customerId: 'cust_01ARZ3NDEKTSV4RRFFQ69G5FAV',
    deploymentId: 'dep_01ARZ3NDEKTSV4RRFFQ69G5FAV'
  };
  export const getConfig = () => config;
  export function mutateConfig(patch) { Object.assign(config, patch); }
  const oidcKey = 'oidc.user:' + config.cognitoIssuerUrl + ':' + config.cognitoClientId;
  const makeUser = subject => new User({
    access_token: 'synthetic-access-fixture', id_token: 'synthetic-id-fixture',
    token_type: 'Bearer', expires_at: Math.floor(Date.now() / 1000) + 3600,
    profile: { sub: subject, iss: config.cognitoIssuerUrl, aud: config.cognitoClientId,
      exp: Math.floor(Date.now() / 1000) + 3600, iat: Math.floor(Date.now() / 1000) }
  });
  const savedUser = sessionStorage.getItem(oidcKey);
  const user = savedUser ? User.fromStorageString(savedUser) : makeUser('${ACTOR}');
  if (!savedUser) sessionStorage.setItem(oidcKey, user.toStorageString());
  let auth = { user, isAuthenticated: true, isLoading: false };
  const listeners = new Set();
  export const useAuth = () => useSyncExternalStore(
    listener => { listeners.add(listener); return () => listeners.delete(listener); },
    () => auth
  );
  export function setActor(subject) {
    const next = makeUser(subject);
    sessionStorage.setItem(oidcKey, next.toStorageString());
    auth = { ...auth, user: next };
    listeners.forEach(listener => listener());
  }
  export const currentActor = () => auth.user.profile.sub;
  export const isRealUser = () => auth.user instanceof User;
  const client = axios.create({ baseURL: config.apiBaseUrl, headers: {
    Authorization: 'Bearer synthetic-access-fixture',
    'X-Synthetic-Case': new URL(location.href).searchParams.get('case')
  } });
  export function getApiClient(expectedSubject) {
    client.defaults.headers.common['X-Synthetic-Expected-Subject'] = expectedSubject || '';
    return client;
  }
`;

const entrySource = `
  import React, { StrictMode, useEffect } from 'react';
  import { createRoot } from 'react-dom/client';
  import { MemoryRouter } from 'react-router-dom';
  import { BulkUpload } from './src/pages/BulkUpload';
  import { BulkUploadRecovery } from './src/domain/bulkUploadRecovery';
  import { uploadStorageKey } from './src/domain/uploadRecovery';
  import { setActor, currentActor, isRealUser, mutateConfig } from 'synthetic-boundaries';
  let recovery;
  let root;
  let mounts = 0;
  let cleanups = 0;
  function Probe() { useEffect(() => { mounts++; return () => { cleanups++; }; }, []); return null; }
  function mount() {
    root = createRoot(document.getElementById('root'));
    root.render(<StrictMode><MemoryRouter initialEntries={['/bulk-upload']}>
      <Probe/><BulkUpload/>
    </MemoryRouter></StrictMode>);
  }
  const files = specs => specs.map(spec => new File([spec.content], spec.name,
    { type: spec.type || 'application/pdf', lastModified: 1 }));
  const open = async () => {
    const actor = currentActor();
    recovery = await BulkUploadRecovery.open(actor, () => currentActor() === actor);
    return recovery.snapshot();
  };
  const capture = async (controller, action) => {
    try { await action(); return { snapshot: controller?.snapshot() }; }
    catch (error) {
      let snapshot;
      try { snapshot = controller?.snapshot(); } catch { /* obsolete actor/storage */ }
      return { error: error.message, snapshot };
    }
  };
  window.__bulkReview = {
    open,
    create: specs => { const controller = recovery; return capture(controller, () => controller.create(files(specs))); },
    attach: specs => { const controller = recovery; return capture(controller, () => controller.attach(files(specs))); },
    run: () => { const controller = recovery; return capture(controller, () => controller.run(() => {})); },
    // Second controller for lease collisions; must not replace the in-flight recovery binding.
    collide: async () => {
      const actor = currentActor();
      const other = await BulkUploadRecovery.open(actor, () => currentActor() === actor);
      return capture(other, () => other.run(() => {}));
    },
    snapshot: () => recovery?.snapshot(),
    setActor,
    mutateConfig,
    namespace: () => uploadStorageKey(currentActor()).then(key => key + ':bulk'),
    journal: () => Object.fromEntries(Object.keys(sessionStorage)
      .filter(key => key.startsWith('scanalyze.upload.'))
      .map(key => [key, sessionStorage.getItem(key)])),
    replaceJournalRaw: raw => uploadStorageKey(currentActor()).then(key => {
      sessionStorage.setItem(key + ':bulk', raw);
      return key + ':bulk';
    }),
    evidence: () => ({ nativeStorage: sessionStorage instanceof Storage,
      realUser: isRealUser(), mounts, cleanups }),
    remount: () => { root.unmount(); mount(); },
  };
  mount();
`;

before(async () => {
  const output = await build({
    absWorkingDir: root,
    stdin: { contents: entrySource, resolveDir: root, sourcefile: 'synthetic-bulk-review-entry.tsx', loader: 'tsx' },
    write: false, bundle: true, format: 'esm', platform: 'browser', target: 'es2022',
    jsx: 'automatic', metafile: true,
    define: { 'process.env.NODE_ENV': '"development"' },
    plugins: [{
      name: 'synthetic-boundaries-before-file-resolution',
      setup(plugin) {
        plugin.onResolve({ filter: /(^|\/)config(?:\.[cm]?[jt]s)?$|^(?:\.{1,2}\/)+(?:api\/)?client(?:\.[cm]?[jt]s)?$|^react-oidc-context$|^synthetic-boundaries$/ },
          () => ({ path: 'boundaries', namespace: 'synthetic' }));
        plugin.onLoad({ filter: /.*/, namespace: 'synthetic' },
          () => ({ contents: fixtureSource, loader: 'js', resolveDir: root }));
        plugin.onResolve({ filter: /(^|\/)(?:\.env(?:\..*)?|config\.py|session_renewal\.spec\.ts|App\.tsx|main\.tsx)$|backend\/adapters/ },
          () => ({ errors: [{ text: 'Prohibited application/config source in isolated browser harness' }] }));
      },
    }],
  });
  assert.equal(Object.keys(output.metafile.inputs).some(path => /^src\/(?:config|api\/client)\./.test(path)), false);
  assert.ok(Object.keys(output.metafile.inputs).some(path => path.includes('bulkUploadRecovery')));
  const bundle = output.outputFiles[0].text;
  server = createServer((request, response) => {
    const url = new URL(request.url, 'http://127.0.0.1');
    if (url.pathname === '/bundle.js') {
      response.writeHead(200, { 'Content-Type': 'text/javascript', 'Cache-Control': 'no-store' });
      return response.end(bundle);
    }
    if (url.pathname === '/bulk-upload') {
      response.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-store' });
      return response.end('<!doctype html><title>Bulk recovery review</title><div id="root"></div><script type="module" src="/bundle.js"></script>');
    }
    const state = scenarios.get(request.headers['x-synthetic-case']);
    if (!state || !url.pathname.startsWith('/api/')) {
      response.writeHead(404);
      return response.end('No synthetic route');
    }
    void respond(state, request, response, url.pathname).catch(error => {
      state.errors.push(error.message);
      if (!response.destroyed) { response.writeHead(500); response.end('Synthetic handler failed'); }
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
  browser = await chromium.launch({ headless: true });
});

after(async () => {
  await browser?.close();
  if (server) {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});

function gate() {
  let release;
  const promise = new Promise(resolve => { release = resolve; });
  return { promise, release };
}

function capability(id) {
  return { method: 'PUT', url: `https://upload.synthetic.invalid/${id}?synthetic-capability=opaque`,
    expiresAt: '2099-01-01T00:00:00.000Z', requiredHeaders: { 'Content-Type': 'application/pdf' } };
}

function durableDocument(documentId) {
  return { schemaVersion: 'scanalyze.document-create-result.v1', contractVersion: CONTRACT,
    operation: 'documents.create', documentId, batchId: BATCH_ID, status: 'UPLOAD_PENDING',
    contentType: 'application/pdf', createdAt: TIME };
}

const batchDurable = { schemaVersion: 'scanalyze.batch-create-result.v1', contractVersion: CONTRACT,
  operation: 'batches.create', batchId: BATCH_ID, status: 'OPEN', createdAt: TIME };

async function respond(state, request, response, path) {
  let raw = '';
  for await (const chunk of request) raw += chunk.toString();
  const payload = raw ? JSON.parse(raw) : undefined;
  const key = request.headers['idempotency-key'];
  const call = { method: request.method, path, key,
    expectedSubject: request.headers['x-synthetic-expected-subject'],
    contract: request.headers['x-scanalyze-contract-version'] };
  const json = (body, status = 200) => {
    response.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    response.end(JSON.stringify(body));
  };
  const loseResponse = () => {
    response.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': '4096' });
    response.write('{');
    setTimeout(() => response.destroy(), 10);
  };
  if (path === '/api/v2/batches' && request.method === 'POST') {
    state.calls.push({ ...call, kind: 'batch', payload });
    if (state.options.loseBatch && !state.batchLost) {
      state.batchLost = true;
      loseResponse();
      return;
    }
    return json({ schemaVersion: 'scanalyze.operation-response.v1', contractVersion: CONTRACT,
      replayed: false, durableResponse: batchDurable });
  }
  if (/\/operations\/(?:documents|batches)\.create\/reconciliation$/.test(path)) {
    const batch = path.includes('batches.create');
    state.calls.push({ ...call, kind: batch ? 'batch-reconcile' : 'reconcile' });
    const doc = state.ledger.get(key);
    const ledgerState = state.options.reconciliationState || 'SUCCEEDED';
    if (ledgerState === 'PENDING') {
      return json({ schemaVersion: 'scanalyze.reconciliation.v1', contractVersion: CONTRACT,
        operation: batch ? 'batches.create' : 'documents.create', ledgerState: 'PENDING',
        createdAt: TIME, updatedAt: TIME, expiresAt: '2099-01-01T00:00:00.000Z' });
    }
    const failures = {
      FAILED_RETRYABLE: 'CREATE_FAILED_RETRYABLE', FAILED_TERMINAL: 'CREATE_FAILED_TERMINAL',
      UNKNOWN_OR_QUARANTINED: 'UNKNOWN_WRITE_OUTCOME', EXPIRED: 'OPERATION_EXPIRED',
    };
    return json({ schemaVersion: 'scanalyze.reconciliation.v1', contractVersion: CONTRACT,
      operation: batch ? 'batches.create' : 'documents.create', ledgerState,
      createdAt: TIME, updatedAt: TIME,
      ...(ledgerState === 'FAILED_RETRYABLE' ? {} : { completedAt: TIME }),
      expiresAt: ledgerState === 'EXPIRED' ? TIME : '2099-01-01T00:00:00.000Z',
      ...(ledgerState === 'SUCCEEDED'
        ? { durableResponse: batch ? batchDurable : durableDocument(doc.id) }
        : { failureCode: failures[ledgerState] }) });
  }
  if (path === '/api/v2/documents' && request.method === 'POST') {
    state.calls.push({ ...call, kind: 'create', batchId: payload.batchId });
    let doc = state.ledger.get(key);
    if (!doc) {
      doc = { id: (state.ledger.size + 1).toString(16).padStart(32, '0'), submitted: false };
      state.ledger.set(key, doc);
    }
    state.active.add(doc.id);
    state.peak = Math.max(state.peak, state.active.size);
    if (state.createGate) await state.createGate.promise;
    if (state.options.loseCreate && !state.createLost) {
      state.createLost = true;
      state.active.delete(doc.id);
      loseResponse();
      return;
    }
    return json({ schemaVersion: 'scanalyze.operation-response.v1', contractVersion: CONTRACT,
      replayed: false, durableResponse: durableDocument(doc.id), uploadCapability: capability(doc.id) });
  }
  const documentRoute = path.match(/^\/api\/v2\/documents\/([0-9a-f]{32})(?:\/(submit|upload-capabilities))?$/);
  if (documentRoute) {
    const [, id, operation] = documentRoute;
    const doc = [...state.ledger.values()].find(candidate => candidate.id === id);
    assert.ok(doc, 'API references a document accepted by the synthetic ledger');
    if (operation === 'submit' && request.method === 'POST') {
      state.calls.push({ ...call, kind: 'submit', id });
      doc.submitted = true;
      state.active.delete(id);
      return json({ schemaVersion: 'scanalyze.document-submit.v1', contractVersion: CONTRACT,
        documentId: id, stage: 'ingest', enqueued: true });
    }
    if (operation === 'upload-capabilities' && request.method === 'POST') {
      state.calls.push({ ...call, kind: 'capability', id });
      return json({ schemaVersion: 'scanalyze.upload-capability.v1', contractVersion: CONTRACT,
        documentId: id, uploadCapability: capability(id) });
    }
    if (!operation && request.method === 'GET') {
      state.calls.push({ ...call, kind: 'status', id });
      return json({ schemaVersion: 'scanalyze.document-status.v1', contractVersion: CONTRACT,
        documentId: id, batchId: BATCH_ID, createdAt: TIME, updatedAt: TIME,
        lifecycle: doc.submitted ? 'PROCESSING' : 'UPLOAD_PENDING',
        currentStage: doc.submitted ? 'OCR' : 'INGEST',
        stageState: doc.submitted ? 'RUNNING' : 'PENDING', processingCondition: 'ACTIVE' });
    }
  }
  state.errors.push(`Unexpected synthetic route: ${request.method} ${path}`);
  json({ code: 'UNEXPECTED_TEST_ROUTE' }, 404);
}

const fileSpecs = (count = 1) => Array.from({ length: count }, (_, i) => ({
  name: `synthetic-private-filename-${i}.pdf`, content: `%PDF-1.7 synthetic content ${i}`,
}));
const count = (state, kind) => state.calls.filter(call => call.kind === kind).length;
const calls = (state, kind) => state.calls.filter(call => call.kind === kind);

async function scenario(options, action) {
  const id = randomUUID();
  const state = { options, calls: [], errors: [], ledger: new Map(), active: new Set(), peak: 0,
    createGate: options.holdCreate ? gate() : undefined };
  scenarios.set(id, state);
  const context = await browser.newContext();
  const external = [];
  const browserErrors = [];
  try {
    await context.route('**/*', async route => {
      const request = route.request();
      const url = new URL(request.url());
      if (url.origin === baseUrl) return route.continue();
      if (url.origin === 'https://upload.synthetic.invalid') {
        if (request.method() === 'OPTIONS') return route.fulfill({ status: 204, headers: {
          'Access-Control-Allow-Origin': baseUrl, 'Access-Control-Allow-Methods': 'PUT, POST',
          'Access-Control-Allow-Headers': '*',
        } });
        state.calls.push({ kind: 'upload', id: url.pathname.slice(1), method: request.method(),
          hasAuthorization: Boolean(request.headers().authorization), bytes: request.postDataBuffer()?.length });
        return route.fulfill({ status: 200, headers: { 'Access-Control-Allow-Origin': baseUrl }, body: '' });
      }
      external.push('EXTERNAL_REQUEST_BLOCKED');
      return route.abort();
    });
    const page = await context.newPage();
    page.on('pageerror', error => browserErrors.push(error.message));
    await page.goto(`${baseUrl}/bulk-upload?case=${id}`);
    await page.waitForFunction(() => window.__bulkReview?.evidence().mounts === 2);
    const evidence = await page.evaluate(() => window.__bulkReview.evidence());
    assert.deepEqual(evidence, { nativeStorage: true, realUser: true, mounts: 2, cleanups: 1 });
    await action(page, state);
    assert.deepEqual(state.errors, []);
    assert.deepEqual(external, []);
    assert.deepEqual(browserErrors, []);
  } finally {
    state.createGate?.release();
    await context.close();
    scenarios.delete(id);
  }
}

async function prepare(page, specs = fileSpecs()) {
  await page.evaluate(() => window.__bulkReview.open());
  const result = await page.evaluate(specs => window.__bulkReview.create(specs), specs);
  assert.equal(result.error, undefined);
  return result;
}

test('storage replaced during CREATE await stops before upload/submit and keeps original create count', async () => {
  await scenario({ holdCreate: true }, async (page, state) => {
    const specs = fileSpecs();
    await prepare(page, specs);
    await page.evaluate(() => { window.__pendingRun = window.__bulkReview.run(); });
    await expect.poll(() => count(state, 'create')).toBe(1);
    const before = await page.evaluate(() => window.__bulkReview.journal());
    assert.ok(Object.keys(before).length > 0);
    // External replacement of the bulk journal (other tab / corruption) while Axios is in flight.
    await page.evaluate(() => window.__bulkReview.replaceJournalRaw(JSON.stringify({
      version: 1,
      key: crypto.randomUUID(),
      phase: 'CREATE_UNKNOWN',
      items: [{ id: crypto.randomUUID(), fileDigest: 'a'.repeat(64), state: 'PENDING' }],
    })));
    state.createGate.release();
    const result = await page.evaluate(() => window.__pendingRun);
    assert.ok(result.error, 'replaced journal must fail context after await');
    assert.equal(count(state, 'create'), 1);
    assert.equal(count(state, 'upload'), 0);
    assert.equal(count(state, 'submit'), 0);
  });
});

test('config scope change after CREATE await blocks upload and submit', async () => {
  await scenario({ holdCreate: true }, async (page, state) => {
    await prepare(page);
    await page.evaluate(() => { window.__pendingRun = window.__bulkReview.run(); });
    await expect.poll(() => count(state, 'create')).toBe(1);
    await page.evaluate(() => window.__bulkReview.mutateConfig({
      deploymentId: 'dep_01REPLACEDCONFIGSCOPE000000000001',
    }));
    state.createGate.release();
    const result = await page.evaluate(() => window.__pendingRun);
    assert.ok(result.error);
    assert.match(result.error, /sesión|vista|cambió/i);
    assert.equal(count(state, 'create'), 1);
    assert.equal(count(state, 'upload'), 0);
    assert.equal(count(state, 'submit'), 0);
  });
});

test('uncertain batch CREATE with PENDING reconciliation never starts file CREATE and does not STOP', async () => {
  await scenario({ loseBatch: true, reconciliationState: 'PENDING' }, async (page, state) => {
    await page.evaluate(() => window.__bulkReview.open());
    await page.evaluate(specs => window.__bulkReview.create(specs), fileSpecs());
    assert.equal(count(state, 'batch'), 1);
    assert.equal(count(state, 'create'), 0);
    const first = await page.evaluate(() => window.__bulkReview.run());
    assert.ok(first.error);
    assert.match(first.error, /lote sigue sin confirmarse|revisión/i);
    assert.equal(count(state, 'batch-reconcile'), 1);
    assert.equal(count(state, 'create'), 0);
    assert.equal(count(state, 'upload'), 0);
    const journal = await page.evaluate(() => window.__bulkReview.journal());
    const bulk = Object.entries(journal).find(([key]) => key.endsWith(':bulk'));
    assert.ok(bulk);
    assert.equal(JSON.parse(bulk[1]).phase, 'CREATE_UNKNOWN');
    const checkpoint = state.calls.length;
    await new Promise(resolve => setTimeout(resolve, 1100));
    const second = await page.evaluate(() => window.__bulkReview.run());
    assert.ok(second.error);
    assert.equal(JSON.parse((await page.evaluate(() => window.__bulkReview.journal()))[bulk[0]]).phase, 'CREATE_UNKNOWN');
    assert.equal(count(state, 'create'), 0);
    assert.ok(state.calls.length >= checkpoint);
    assert.equal(calls(state, 'batch-reconcile').length >= 2, true);
  });
});

test('module lease survives React remount while CREATE is in flight; lease frees after unmounted work ends', async () => {
  await scenario({ holdCreate: true }, async (page, state) => {
    const specs = fileSpecs();
    await prepare(page, specs);
    await page.evaluate(() => { window.__pendingRun = window.__bulkReview.run(); });
    await expect.poll(() => count(state, 'create')).toBe(1);
    const createKey = calls(state, 'create')[0].key;

    // Remount React while the module lease is still held by the in-flight exclusive.
    await page.evaluate(() => window.__bulkReview.remount());
    await page.waitForFunction(() => window.__bulkReview?.evidence().mounts >= 4);

    const collision = await page.evaluate(() => window.__bulkReview.collide());
    assert.match(collision.error, /operación del lote en curso/);
    assert.equal(count(state, 'create'), 1);
    assert.equal(count(state, 'upload'), 0);
    assert.equal(count(state, 'submit'), 0);

    state.createGate.release();
    const settled = await page.evaluate(() => window.__pendingRun);
    assert.equal(settled.error, undefined, settled.error);

    // Explicit post-lease recovery: must not mint another CREATE/upload/submit.
    await page.evaluate(() => window.__bulkReview.open());
    const recovered = await page.evaluate(() => window.__bulkReview.run());
    assert.equal(recovered.error, undefined, recovered.error);
    assert.equal(count(state, 'create'), 1);
    assert.equal(count(state, 'upload'), 1);
    assert.equal(count(state, 'submit'), 1);
    assert.equal(calls(state, 'create')[0].key, createKey);
    assert.equal(new Set(calls(state, 'create').map(call => call.key)).size, 1);
  });
});
