import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { chromium, expect } from '@playwright/test';

// Run: node --test tests/browser/bulk-upload-recovery.test.mjs
// Real product helper, BulkUpload, React StrictMode, Axios, OIDC User and native
// Chromium sessionStorage. Only config/client/useAuth boundaries are fixtures.
// HTTP requests reach a synthetic localhost ledger; HTTPS upload capabilities
// are intercepted before external network access. No application startup,
// real frontend config, backend adapters or oracle scheduler.
// This is client recovery evidence, not authentication or production evidence.
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
  // Deliberately no actor guard here: the actual recovery helper must enforce
  // its checks itself. This boundary records expectedSubject without replacing
  // Axios, its adapter, promises, progress events or error classification.
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
  import { BankStatements } from './src/pages/BankStatements';
  import { BulkUploadRecovery } from './src/domain/bulkUploadRecovery';
  import { uploadStorageKey } from './src/domain/uploadRecovery';
  import { setActor, currentActor, isRealUser, config } from 'synthetic-boundaries';
  let recovery;
  let root;
  let mounts = 0;
  let cleanups = 0;
  function Probe() { useEffect(() => { mounts++; return () => { cleanups++; }; }, []); return null; }
  function mount() {
    root = createRoot(document.getElementById('root'));
    root.render(<StrictMode><MemoryRouter initialEntries={['/bulk-upload']}>
      <Probe/>{new URL(location.href).searchParams.get('surface') === 'bank' ? <BankStatements/> : <BulkUpload/>}
    </MemoryRouter></StrictMode>);
  }
  const files = specs => specs.map(spec => new File([spec.content], spec.name,
    { type: spec.type || 'application/pdf', lastModified: 1 }));
  const open = async () => {
    const actor = currentActor();
    recovery = await BulkUploadRecovery.open(actor, () => currentActor() === actor);
    return recovery.snapshot();
  };
  const capture = async action => {
    try { await action(); return { snapshot: recovery?.snapshot() }; }
    catch (error) {
      let snapshot;
      try { snapshot = recovery?.snapshot(); } catch { /* An obsolete actor cannot read its former snapshot. */ }
      return { error: error.message, snapshot };
    }
  };
  window.__bulkTest = {
    open,
    create: specs => capture(() => recovery.create(files(specs))),
    attach: specs => capture(() => recovery.attach(files(specs))),
    run: () => capture(() => recovery.run(() => {})),
    snapshot: () => recovery?.snapshot(),
    setActor,
    changeConfig: () => { config.deploymentId = "dep_01ARZ3NDEKTSV4RRFFQ69G5FB0"; },
    namespace: () => uploadStorageKey(currentActor()).then(key => key + ':bulk'),
    journal: () => Object.fromEntries(Object.keys(sessionStorage)
      .filter(key => key.startsWith('scanalyze.upload.'))
      .map(key => [key, sessionStorage.getItem(key)])),
    evidence: () => ({ nativeStorage: sessionStorage instanceof Storage,
      realUser: isRealUser(), mounts, cleanups }),
    remount: () => { root.unmount(); mount(); },
    failWrites: (itemsOnly = false) => {
      const native = Storage.prototype.setItem;
      Storage.prototype.setItem = function(key, value) {
        if (String(key).startsWith('scanalyze.upload.') && (!itemsOnly || String(key).includes(':item:'))) {
          throw new DOMException('Synthetic quota failure', 'QuotaExceededError');
        }
        return native.call(this, key, value);
      };
      return sessionStorage instanceof Storage;
    }
  };
  mount();
`;

before(async () => {
  const output = await build({
    absWorkingDir: root,
    stdin: { contents: entrySource, resolveDir: root, sourcefile: 'synthetic-bulk-entry.tsx', loader: 'tsx' },
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
  const bundle = output.outputFiles[0].text;
  server = createServer((request, response) => {
    const url = new URL(request.url, 'http://127.0.0.1');
    if (url.pathname === '/bundle.js') {
      response.writeHead(200, { 'Content-Type': 'text/javascript', 'Cache-Control': 'no-store' });
      return response.end(bundle);
    }
    if (url.pathname === '/bulk-upload') {
      response.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-store' });
      return response.end('<!doctype html><title>Synthetic bulk recovery</title><div id="root"></div><script type="module" src="/bundle.js"></script>');
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
    // Drop an already-started response. Dropping an entirely silent keepalive
    // socket permits Chromium's transport to replay the POST transparently,
    // which would test HTTP reconnection rather than the recovery controller.
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
    const body = { schemaVersion: 'scanalyze.reconciliation.v1', contractVersion: CONTRACT,
      operation: batch ? 'batches.create' : 'documents.create', ledgerState,
      createdAt: TIME, updatedAt: TIME, expiresAt: '2099-01-01T00:00:00.000Z',
      ...(ledgerState === 'SUCCEEDED' ? { completedAt: TIME, durableResponse: batch ? batchDurable : durableDocument(doc.id) }
        : ledgerState === 'PENDING' ? {}
          : { failureCode: 'CREATE_FAILED_TERMINAL', completedAt: TIME }) };
    state.reconciliationBodies.push(body);
    return json(body);
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
      replayed: false, durableResponse: { ...durableDocument(doc.id), ...(state.options.wrongDurableBatch ? { batchId: 'c'.repeat(32) } : {}) }, uploadCapability: capability(doc.id) });
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
      if (state.options.loseSubmit && !state.submitLost) {
        state.submitLost = true;
        loseResponse();
        return;
      }
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
  const state = { options, calls: [], errors: [], reconciliationBodies: [], ledger: new Map(), active: new Set(), peak: 0,
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
    await page.goto(`${baseUrl}/bulk-upload?case=${id}${options.surface === 'bank' ? '&surface=bank' : ''}`);
    await page.waitForFunction(() => window.__bulkTest?.evidence().mounts === 2);
    const evidence = await page.evaluate(() => window.__bulkTest.evidence());
    assert.deepEqual(evidence, { nativeStorage: true, realUser: true, mounts: 2, cleanups: 1 });
    await action(page, state);
    assert.deepEqual(state.errors, []);
    assert.deepEqual(external, []);
    assert.deepEqual(browserErrors, []);
    for (const upload of calls(state, 'upload')) {
      assert.equal(upload.hasAuthorization, false, 'upload must use the clean Axios instance');
      assert.equal(upload.method, 'PUT');
      assert.ok(upload.bytes > 0);
    }
    for (const call of state.calls.filter(call => call.kind !== 'upload')) {
      assert.equal(call.contract, CONTRACT);
      assert.equal(call.expectedSubject, ACTOR);
      if (['batch', 'batch-reconcile', 'create', 'reconcile'].includes(call.kind)) {
        assert.match(call.key, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
      }
    }
  } finally {
    state.createGate?.release();
    await context.close();
    scenarios.delete(id);
  }
}

async function prepare(page, specs = fileSpecs()) {
  await page.evaluate(() => window.__bulkTest.open());
  const result = await page.evaluate(specs => window.__bulkTest.create(specs), specs);
  assert.equal(result.error, undefined);
  return result;
}

const run = page => page.evaluate(() => window.__bulkTest.run());

async function recover(page) {
  // The product's minimum transport-error backoff is one second. Let that
  // real deadline pass without replacing its clock or retry policy.
  await new Promise(resolve => setTimeout(resolve, 1100));
  return run(page);
}

function assertComplete(result, expectedCount = 1) {
  assert.equal(result.error, undefined);
  assert.equal(result.snapshot.tasks.length, expectedCount);
  assert.deepEqual(result.snapshot.tasks.map(task => task.status), Array(expectedCount).fill('SUCCESS'));
}

function assertOpaqueJournal(journal, specs = fileSpecs()) {
  assert.ok(Object.keys(journal).length > 0, 'recovery references survive the response loss');
  const serialized = JSON.stringify(journal);
  for (const forbidden of [...specs.map(file => file.name), ...specs.map(file => file.content),
    ACTOR, 'synthetic-access-fixture', 'synthetic-id-fixture', 'synthetic-capability',
    'upload.synthetic.invalid', 'uploadCapability', 'requiredHeaders']) {
    assert.equal(serialized.includes(forbidden), false, `journal excludes ${forbidden}`);
  }
}

test('accepted CREATE with a lost response reconciles its original key without another CREATE', async () => {
  await scenario({ loseCreate: true }, async (page, state) => {
    await prepare(page);
    await run(page);
    assert.equal(count(state, 'create'), 1);
    assert.equal(count(state, 'upload'), 0);
    assert.equal(count(state, 'submit'), 0);
    assertOpaqueJournal(await page.evaluate(() => window.__bulkTest.journal()));
    assertComplete(await recover(page));
    assert.equal(count(state, 'create'), 1);
    assert.deepEqual(calls(state, 'reconcile').map(call => call.key), calls(state, 'create').map(call => call.key));
    assert.equal(count(state, 'upload'), 1);
    assert.equal(count(state, 'submit'), 1);
  });
});

test('accepted SUBMIT with a lost response recovers via status without CREATE, upload or another SUBMIT', async () => {
  await scenario({ loseSubmit: true }, async (page, state) => {
    await prepare(page);
    await run(page);
    assert.equal(count(state, 'create'), 1);
    assert.equal(count(state, 'upload'), 1);
    assert.equal(count(state, 'submit'), 1);
    const checkpoint = state.calls.length;
    assertComplete(await recover(page));
    assert.deepEqual(state.calls.slice(checkpoint).map(call => call.kind), ['status']);
  });
});

test('reload preserves only opaque references and requires matching original file fingerprints', async () => {
  await scenario({ loseCreate: true }, async (page, state) => {
    const specs = fileSpecs();
    await prepare(page, specs);
    await run(page);
    const originalKey = calls(state, 'create')[0].key;
    const journal = await page.evaluate(() => window.__bulkTest.journal());
    assertOpaqueJournal(journal, specs);
    await page.reload();
    await page.waitForFunction(() => window.__bulkTest?.evidence().mounts === 2);
    assert.deepEqual(await page.evaluate(() => window.__bulkTest.journal()), journal);
    await page.evaluate(() => window.__bulkTest.open());
    const wrong = await page.evaluate(specs => window.__bulkTest.attach(specs),
      [{ ...specs[0], content: specs[0].content.replace('content', 'changed') }]);
    assert.ok(wrong.error, 'same filename with different bytes must not replace the original intent');
    assert.equal(count(state, 'create'), 1);
    assert.equal(count(state, 'upload'), 0);
    const attached = await page.evaluate(specs => window.__bulkTest.attach(specs), specs);
    assert.equal(attached.error, undefined);
    assertComplete(await run(page));
    assert.equal(count(state, 'create'), 1);
    assert.deepEqual(calls(state, 'reconcile').map(call => call.key), [originalKey]);
    assert.equal(count(state, 'upload'), 1);
    assert.equal(count(state, 'submit'), 1);
  });
});

test('mounted BulkUpload under real StrictMode limits concurrent file work to three without duplicates', async () => {
  await scenario({ holdCreate: true }, async (page, state) => {
    const specs = fileSpecs(7);
    await page.locator('input[type=file]').setInputFiles(specs.map(spec => ({
      name: spec.name, mimeType: 'application/pdf', buffer: Buffer.from(spec.content),
    })));
    await page.getByRole('button', { name: /Iniciar Lote/ }).click();
    await expect.poll(() => count(state, 'create')).toBe(3);
    // The barrier leaves all three actual Axios requests unresolved; the
    // StrictMode-mounted product must retain its three-slot bound here.
    assert.equal(count(state, 'create'), 3);
    state.createGate.release();
    await expect.poll(() => count(state, 'submit')).toBe(7);
    await expect(page.getByText('7 completados, 0 fallidos de 7')).toBeVisible();
    assert.equal(count(state, 'batch'), 1);
    assert.deepEqual(calls(state, 'batch')[0].payload, {});
    assert.equal(count(state, 'create'), 7);
    assert.equal(count(state, 'upload'), 7);
    assert.equal(new Set(calls(state, 'create').map(call => call.key)).size, 7);
    assert.equal(new Set(calls(state, 'submit').map(call => call.id)).size, 7);
    assert.equal(state.peak, 3);
    for (const call of calls(state, 'create')) assert.equal(call.batchId, BATCH_ID);
  });
});

test('actor change while CREATE is pending prevents upload and SUBMIT after the response arrives', async () => {
  await scenario({ holdCreate: true }, async (page, state) => {
    await prepare(page);
    await page.evaluate(() => { window.__pendingRun = window.__bulkTest.run(); });
    await expect.poll(() => count(state, 'create')).toBe(1);
    await page.evaluate(() => window.__bulkTest.setActor('synthetic-bulk-actor-b'));
    state.createGate.release();
    await page.evaluate(() => window.__pendingRun);
    assert.equal(count(state, 'create'), 1);
    assert.equal(count(state, 'upload'), 0);
    assert.equal(count(state, 'submit'), 0);
  });
});

test('a second real controller cannot start a journal that already has three pending file requests', async () => {
  await scenario({ holdCreate: true }, async (page, state) => {
    await prepare(page, fileSpecs(7));
    await page.evaluate(() => { window.__pendingRun = window.__bulkTest.run(); });
    await expect.poll(() => count(state, 'create')).toBe(3);
    await page.evaluate(() => window.__bulkTest.open());
    const collision = await run(page);
    assert.match(collision.error, /operación del lote en curso/);
    assert.equal(count(state, 'create'), 3);
    state.createGate.release();
    await page.evaluate(() => window.__pendingRun);
    assert.equal(count(state, 'create'), 7);
    assert.equal(count(state, 'upload'), 7);
    assert.equal(count(state, 'submit'), 7);
    assert.equal(state.peak, 3);
    const checkpoint = state.calls.length;
    // A fresh controller re-reads the completed journal after the first
    // controller's custody has ended; it must not mint any replacement intent.
    await page.evaluate(() => window.__bulkTest.open());
    assertComplete(await run(page), 7);
    assert.equal(state.calls.length, checkpoint, 'completed journal cannot start again through a fresh controller');
  });
});

test('native storage quota failure prevents the first batch or document API effect', async () => {
  await scenario({}, async (page, state) => {
    await page.evaluate(() => window.__bulkTest.open());
    assert.equal(await page.evaluate(() => window.__bulkTest.failWrites()), true);
    const result = await page.evaluate(specs => window.__bulkTest.create(specs), fileSpecs());
    assert.ok(result.error);
    assert.deepEqual(state.calls, []);
  });
});

test('terminal reconciliation persists STOPPED and a subsequent run causes no effects', async () => {
  await scenario({ loseCreate: true, reconciliationState: 'FAILED_TERMINAL' }, async (page, state) => {
    await prepare(page);
    await run(page);
    await recover(page);
    const journal = await page.evaluate(() => window.__bulkTest.journal());
    assert.ok(Object.values(journal).some(value => JSON.parse(value).phase === 'STOPPED'));
    const checkpoint = state.calls.length;
    // Exercise STOPPED after its error backoff has elapsed, so a timer skip
    // cannot produce a false pass for the absence of additional HTTP effects.
    await recover(page);
    assert.equal(state.calls.length, checkpoint);
    assert.equal(count(state, 'create'), 1);
    assert.equal(count(state, 'upload'), 0);
    assert.equal(count(state, 'submit'), 0);
  });
});

test('an uncertain batch CREATE reconciles its original batch key before any file CREATE', async () => {
  await scenario({ loseBatch: true }, async (page, state) => {
    await page.evaluate(() => window.__bulkTest.open());
    await page.evaluate(specs => window.__bulkTest.create(specs), fileSpecs());
    assert.equal(count(state, 'batch'), 1);
    assert.equal(count(state, 'create'), 0);
    assertComplete(await run(page));
    assert.equal(count(state, 'batch'), 1);
    assert.deepEqual(calls(state, 'batch-reconcile').map(call => call.key), calls(state, 'batch').map(call => call.key));
    assert.equal(count(state, 'create'), 1);
    assert.equal(count(state, 'submit'), 1);
  });
});


test('configuration change while CREATE is pending blocks every subsequent effect', async () => {
  await scenario({ holdCreate: true }, async (page, state) => {
    await prepare(page);
    await page.evaluate(() => { window.__pendingRun = window.__bulkTest.run(); });
    await expect.poll(() => count(state, 'create')).toBe(1);
    await page.evaluate(() => window.__bulkTest.changeConfig());
    state.createGate.release();
    const result = await page.evaluate(() => window.__pendingRun);
    assert.ok(result.error);
    assert.equal(count(state, 'upload'), 0);
    assert.equal(count(state, 'submit'), 0);
  });
});

test('corrupt stored journal cannot open or cause an API effect', async () => {
  await scenario({}, async (page, state) => {
    const error = await page.evaluate(async () => {
      const key = await window.__bulkTest.namespace();
      sessionStorage.setItem(key, '{corrupt');
      try { await window.__bulkTest.open(); } catch (error) { return error.message; }
    });
    assert.ok(error);
    assert.deepEqual(state.calls, []);
  });
});

test('same-key journal replacement during CREATE stops before upload and SUBMIT', async () => {
  await scenario({ holdCreate: true }, async (page, state) => {
    await prepare(page);
    await page.evaluate(() => { window.__pendingRun = window.__bulkTest.run(); });
    await expect.poll(() => count(state, 'create')).toBe(1);
    await page.evaluate(async () => {
      const key = await window.__bulkTest.namespace();
      const journal = JSON.parse(sessionStorage.getItem(key));
      journal.items[0].fileDigest = '0'.repeat(64);
      sessionStorage.setItem(key, JSON.stringify(journal));
    });
    state.createGate.release();
    const result = await page.evaluate(() => window.__pendingRun);
    assert.ok(result.error);
    assert.equal(count(state, 'create'), 1);
    assert.equal(count(state, 'upload'), 0);
    assert.equal(count(state, 'submit'), 0);
  });
});

test('per-file persistence failure stops before document CREATE', async () => {
  await scenario({}, async (page, state) => {
    await prepare(page);
    await page.evaluate(() => window.__bulkTest.failWrites(true));
    await run(page);
    assert.equal(count(state, 'batch'), 1);
    assert.equal(count(state, 'create'), 0);
    assert.equal(count(state, 'upload'), 0);
    assert.equal(count(state, 'submit'), 0);
  });
});

test('UI remount during CREATE preserves the key and resumes only through reconciliation', async () => {
  await scenario({ holdCreate: true }, async (page, state) => {
    const specs = fileSpecs();
    const inputFiles = specs.map(spec => ({ name: spec.name, mimeType: 'application/pdf', buffer: Buffer.from(spec.content) }));
    await page.locator('input[type=file]').setInputFiles(inputFiles);
    await page.getByRole('button', { name: /Iniciar Lote/ }).click();
    await expect.poll(() => count(state, 'create')).toBe(1);
    const originalKey = calls(state, 'create')[0].key;
    await page.evaluate(() => window.__bulkTest.remount());
    await page.waitForFunction(() => window.__bulkTest.evidence().mounts === 4);
    state.createGate.release();
    await new Promise(resolve => setTimeout(resolve, 1100));
    assert.equal(count(state, 'create'), 1);
    assert.equal(count(state, 'upload'), 0);
    assert.equal(count(state, 'submit'), 0);
    await page.getByLabel('Seleccionar originales').setInputFiles(inputFiles);
    await page.getByRole('button', { name: 'Recuperar lote', exact: true }).click();
    await expect(page.getByText('1 completados, 0 fallidos de 1')).toBeVisible();
    assert.equal(count(state, 'create'), 1);
    assert.deepEqual(calls(state, 'reconcile').map(call => call.key), [originalKey]);
    assert.equal(count(state, 'upload'), 1);
    assert.equal(count(state, 'submit'), 1);
  });
});


test('mounted BankStatements uses the same recovery after an accepted SUBMIT response is lost', async () => {
  await scenario({ surface: 'bank', loseSubmit: true }, async (page, state) => {
    const spec = fileSpecs()[0];
    await page.locator('input[type=file]').setInputFiles({ name: spec.name, mimeType: 'application/pdf', buffer: Buffer.from(spec.content) });
    await page.getByRole('button', { name: /Iniciar envío/ }).click();
    await expect(page.getByText('0 confirmados · 1 por recuperar · 1 total')).toBeVisible();
    assert.equal(count(state, 'batch'), 1);
    assert.equal(count(state, 'create'), 1);
    assert.equal(count(state, 'upload'), 1);
    assert.equal(count(state, 'submit'), 1);
    const checkpoint = state.calls.length;
    await new Promise(resolve => setTimeout(resolve, 1100));
    await page.getByRole('button', { name: 'Recuperar lote', exact: true }).click();
    await expect(page.getByText('1 confirmados · 0 por recuperar · 1 total')).toBeVisible();
    assert.deepEqual(state.calls.slice(checkpoint).map(call => call.kind), ['status']);
  });
});


test('CREATE response bound to another batch is rejected before uploading the file', async () => {
  await scenario({ wrongDurableBatch: true }, async (page, state) => {
    await prepare(page);
    await run(page);
    assert.equal(count(state, 'create'), 1);
    assert.equal(count(state, 'upload'), 0);
    assert.equal(count(state, 'submit'), 0);
  });
});


test('early recovery reports its cooldown without an API request or replacing the original intent', async () => {
  await scenario({ loseSubmit: true }, async (page, state) => {
    await prepare(page);
    await run(page);
    const checkpoint = state.calls.length;
    const journal = await page.evaluate(() => window.__bulkTest.journal());
    const result = await run(page);
    assert.equal(result.error, undefined);
    assert.equal(result.snapshot.tasks[0].status, 'ERROR');
    assert.match(result.snapshot.tasks[0].errorMsg, /Espera .* antes de recuperar/);
    assert.equal(state.calls.length, checkpoint);
    assert.deepEqual(await page.evaluate(() => window.__bulkTest.journal()), journal);
    assertComplete(await recover(page));
    assert.deepEqual(state.calls.slice(checkpoint).map(call => call.kind), ['status']);
  });
});

test('mounted UI never labels uncertain or reloaded pending tasks as a completed batch', async () => {
  await scenario({ loseSubmit: true }, async (page, state) => {
    const spec = fileSpecs()[0];
    await page.locator('input[type=file]').setInputFiles({ name: spec.name, mimeType: 'application/pdf', buffer: Buffer.from(spec.content) });
    await page.getByRole('button', { name: /Iniciar Lote/ }).click();
    await expect(page.getByText('0 completados, 1 fallidos de 1')).toBeVisible();
    assert.equal(await page.getByText('Envíos confirmados').count(), 0);
    assert.equal(await page.getByText('Exportar Resultados del Lote').count(), 0);
    await expect(page.getByRole('button', { name: 'Recuperar lote', exact: true })).toBeVisible();
    const checkpoint = state.calls.length;
    await page.reload();
    await page.waitForFunction(() => window.__bulkTest?.evidence().mounts === 2);
    await expect(page.getByRole('button', { name: 'Recuperar lote', exact: true })).toBeVisible();
    assert.equal(await page.getByText('Envíos confirmados').count(), 0);
    assert.equal(state.calls.length, checkpoint, 'reloading a pending batch does not start requests');
    await page.getByRole('button', { name: 'Recuperar lote', exact: true }).click();
    await expect(page.getByText('1 completados, 0 fallidos de 1')).toBeVisible();
    await expect(page.getByText('Envíos confirmados')).toBeVisible();
    assert.deepEqual(state.calls.slice(checkpoint).map(call => call.kind), ['status']);
  });
});

test('valid PENDING reconciliation has no failure or completion fields and remains recoverable', async () => {
  await scenario({ loseCreate: true, reconciliationState: 'PENDING' }, async (page, state) => {
    await prepare(page);
    await run(page);
    const pending = await recover(page);
    assert.equal(pending.error, undefined);
    assert.equal(pending.snapshot.tasks[0].phase, 'CREATE_UNKNOWN');
    assert.equal(pending.snapshot.tasks[0].status, 'ERROR');
    assert.equal(count(state, 'create'), 1);
    assert.equal(count(state, 'upload'), 0);
    const response = state.reconciliationBodies[0];
    for (const field of ['failureCode', 'completedAt', 'durableResponse']) {
      assert.equal(Object.hasOwn(response, field), false);
    }
    state.options.reconciliationState = 'SUCCEEDED';
    assertComplete(await recover(page));
    assert.equal(count(state, 'create'), 1);
    assert.equal(count(state, 'upload'), 1);
    assert.equal(count(state, 'submit'), 1);
    assert.deepEqual(calls(state, 'reconcile').map(call => call.key), [calls(state, 'create')[0].key, calls(state, 'create')[0].key]);
  });
});


test('Bank results link only the retained batch and document without analytics requests or fabricated completion', async () => {
  await scenario({ surface: 'bank' }, async (page, state) => {
    const spec = fileSpecs()[0];
    await page.locator('input[type=file]').setInputFiles({ name: spec.name, mimeType: 'application/pdf', buffer: Buffer.from(spec.content) });
    await page.getByRole('button', { name: 'Iniciar envío', exact: true }).click();
    await expect(page.getByText('1 confirmados · 0 por recuperar · 1 total')).toBeVisible();
    const checkpoint = state.calls.length;
    await page.getByRole('button', { name: 'Ver Resultados', exact: true }).click();
    const results = page.getByRole('region', { name: 'Resultados del lote', exact: true });
    await expect(results).toBeVisible();
    await expect(results.getByRole('link', { name: 'Ver lote', exact: true })).toHaveAttribute('href', `/batch/${BATCH_ID}`);
    const documentId = calls(state, 'create').length && [...state.ledger.values()][0].id;
    await expect(results.getByRole('link', { name: /Ver documento/ })).toHaveAttribute('href', `/document/${documentId}`);
    await expect(results.getByText('Envío confirmado. Consulta el documento para conocer el estado del procesamiento.')).toBeVisible();
    await expect(results.getByText('Consulta Historial para abrir resultados anteriores y exportar sus transacciones.')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Historial', exact: true })).toBeVisible();
    assert.equal(await results.getByRole('button', { name: /CSV/ }).count(), 0);
    assert.equal(await results.getByText(/procesados|Completado|No se encontró resultado/).count(), 0);
    assert.equal(state.calls.length, checkpoint, 'showing retained references performs no API/result lookup');
    await page.reload();
    await page.waitForFunction(() => window.__bulkTest?.evidence().mounts === 2);
    await page.getByRole('button', { name: 'Resultados del lote', exact: true }).click();
    await expect(results.getByRole('link', { name: /Ver documento/ })).toHaveAttribute('href', `/document/${documentId}`);
    assert.equal((await results.textContent()).includes(spec.name), false, 'filename is not reconstructed from persisted references');
    assert.equal(state.calls.length, checkpoint, 'reload and local batch references do not query account history');
  });
});

test('Bank results with no tab journal state that local limitation without claiming an empty account history', async () => {
  await scenario({ surface: 'bank' }, async (page, state) => {
    await page.getByRole('button', { name: 'Resultados del lote', exact: true }).click();
    const results = page.getByRole('region', { name: 'Resultados del lote', exact: true });
    await expect(results.getByText('No hay un lote guardado en esta pestaña.')).toBeVisible();
    assert.equal(await results.getByRole('link').count(), 0);
    await expect(page.getByRole('button', { name: 'Historial', exact: true })).toBeVisible();
    assert.equal(await results.getByText('Aún no hay estados de cuenta bancarios procesados.').count(), 0);
    assert.deepEqual(state.calls, []);
  });
});
