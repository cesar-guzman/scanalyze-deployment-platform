import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { chromium, expect } from '@playwright/test';

// Actual document page, hook and API with a synthetic client and loopback server.
// These cases validate public response handling, not application authentication.
const root = fileURLToPath(new URL('../../', import.meta.url));
const scenarios = new Map();
const caseOptions = { timeout: 25_000 };
let browser;
let server;
let baseUrl;
let nextCase = 0;
let fixtures;
let documentId;

before(async () => {
  const fixtureBundle = await build({
    absWorkingDir: root, entryPoints: ['src/contracts/documentJourney.v1.fixtures.ts'],
    bundle: true, write: false, format: 'esm', platform: 'node',
  });
  fixtures = await import(`data:text/javascript;base64,${Buffer.from(fixtureBundle.outputFiles[0].text).toString('base64')}`);
  documentId = fixtures.BANK_STATEMENT_RESULT_FIXTURE.documentId;
  const output = await build({
    absWorkingDir: root,
    stdin: { contents: `
      import React, { StrictMode } from 'react';
      import { createRoot } from 'react-dom/client';
      import { MemoryRouter, Route, Routes } from 'react-router-dom';
      import DocumentPage from './src/pages/DocumentPage';
      createRoot(document.getElementById('container')).render(
        <StrictMode><MemoryRouter initialEntries={['/document/${documentId}']}>
          <Routes><Route path='/document/:id' element={<DocumentPage />} /></Routes>
        </MemoryRouter></StrictMode>
      );
    `, resolveDir: root, sourcefile: 'synthetic-document-response-entry.tsx', loader: 'tsx' },
    write: false, bundle: true, format: 'esm', platform: 'browser', target: 'es2022',
    jsx: 'automatic', metafile: true, define: { 'process.env.NODE_ENV': '"development"' },
    plugins: [{ name: 'synthetic-document-client', setup(plugin) {
      plugin.onResolve({ filter: /^\.\/client$/ }, args => {
        assert.ok(args.importer.endsWith('/src/api/documentApi.ts'));
        return { path: 'response-client', namespace: 'synthetic' };
      });
      plugin.onLoad({ filter: /.*/, namespace: 'synthetic' }, () => ({
        contents: `import axios from 'axios';
          const client = axios.create({ baseURL: location.origin + '/api', timeout: 5000,
            headers: { 'X-Synthetic-Case': new URL(location.href).searchParams.get('case') } });
          export const getApiClient = () => client;`,
        loader: 'js', resolveDir: root,
      }));
      plugin.onResolve({ filter: /(?:^|\/)(?:auth|config|App|main)(?:\/|\.|$)|react-oidc-context|oidc-client-ts/ },
        () => ({ errors: [{ text: 'Source is outside the response-validation harness' }] }));
    } }],
  });
  assert.deepEqual(Object.keys(output.metafile.inputs).filter(path => path.startsWith('src/')).sort(), [
    'src/api/documentApi.ts',
    'src/contracts/documentJourney.v1.ts',
    'src/domain/documentResponseValidation.ts',
    'src/hooks/useDocumentJourney.ts',
    'src/pages/DocumentPage.tsx',
  ]);
  const bundle = output.outputFiles[0].text;
  server = createServer((request, response) => {
    const url = new URL(request.url, 'http://127.0.0.1');
    response.setHeader('Cache-Control', 'no-store');
    if (url.pathname === '/') {
      response.writeHead(200, { 'Content-Type': 'text/html' });
      return response.end('<!doctype html><title>Synthetic response validation</title><div id="container"></div><script type="module" src="/bundle.js"></script>');
    }
    if (url.pathname === '/bundle.js') {
      response.writeHead(200, { 'Content-Type': 'text/javascript' });
      return response.end(bundle);
    }
    if (url.pathname === '/favicon.ico') { response.writeHead(204); return response.end(); }
    const scenario = scenarios.get(request.headers['x-synthetic-case']);
    const match = url.pathname.match(/^\/api\/v2\/documents\/([0-9a-f]{32})(\/result)?$/);
    if (!scenario || !match || match[1] !== documentId) {
      if (scenario) scenario.unexpectedPaths.push(url.pathname);
      response.writeHead(404); return response.end();
    }
    const kind = match[2] ? 'result' : 'status';
    scenario.requests.push({ kind, method: request.method, contract: request.headers['x-scanalyze-contract-version'] });
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify(scenario[kind]));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
  browser = await chromium.launch({ headless: true });
});

after(async () => {
  await browser?.close();
  if (server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});

async function openCase(t, changes = {}) {
  const caseId = String(++nextCase);
  const scenario = {
    status: structuredClone(fixtures.DOCUMENT_STATUS_RESPONSE_FIXTURE),
    result: structuredClone(fixtures.BANK_STATEMENT_RESULT_FIXTURE),
    requests: [], unexpectedPaths: [],
  };
  changes.changeStatus?.(scenario);
  changes.changeResult?.(scenario);
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
  const response = await page.goto(`${baseUrl}/?case=${caseId}`);
  assert.equal(response.status(), 200);
  return { page, scenario, assertClean: () => {
    assert.deepEqual(errors, []);
    assert.deepEqual(consoleErrors, []);
    assert.deepEqual(scenario.unexpectedPaths, []);
    assert.ok(scenario.requests.length > 0);
    assert.ok(scenario.requests.every(request => request.method === 'GET' && request.contract === 'scanalyze.document-journey.v1'));
  } };
}

test('canonical response reaches the actual document renderer', caseOptions, async t => {
  const { page, scenario, assertClean } = await openCase(t);
  await expect(page.getByRole('heading', { name: 'Resultados de Extracción' })).toBeVisible();
  await expect(page.getByText('Synthetic Bank', { exact: true })).toBeVisible();
  assert.ok(scenario.requests.some(request => request.kind === 'result'));
  assertClean();
});

test('validated zero and null remain distinct in the rendered result', caseOptions, async t => {
  const { page, assertClean } = await openCase(t, { changeResult: scenario => {
    scenario.result.quality.overallConfidence = 0;
    const transaction = scenario.result.data.transactions[0];
    scenario.result.data.transactions = [
      { ...transaction, description: 'Synthetic zero amount', amount: 0 },
      { ...transaction, description: 'Synthetic absent amount', amount: null },
    ];
  } });
  await expect(page.getByText('Confianza: 0%', { exact: true })).toBeVisible();
  await expect(page.getByRole('row').filter({ hasText: 'Synthetic zero amount' }).getByRole('cell').nth(2)).toContainText('0.00');
  await expect(page.getByRole('row').filter({ hasText: 'Synthetic absent amount' }).getByRole('cell').nth(2)).toHaveText('—');
  assertClean();
});

const invalidResults = [
  ['incomplete envelope', scenario => { scenario.result = { documentId: scenario.result.documentId }; }],
  ['null data', scenario => { scenario.result.data = null; }],
  ['missing account', scenario => { delete scenario.result.data.account; }],
  ['text amount', scenario => { scenario.result.data.transactions[0].amount = 'SYNTHETIC_PAYLOAD_MARKER'; }],
  ['out-of-range confidence', scenario => { scenario.result.quality.overallConfidence = 101; }],
  ['unknown warning', scenario => { scenario.result.warnings = [{ code: 'SYNTHETIC_PAYLOAD_MARKER' }]; }],
  ['different document', scenario => { scenario.result.documentId = 'e'.repeat(32); scenario.result.resultId = `result_${scenario.result.documentId}_v1`; }],
  ['different result binding', scenario => { scenario.result.resultId = `result_${'e'.repeat(32)}_v1`; }],
  ['unknown envelope field', scenario => { scenario.result.extra = 'SYNTHETIC_PAYLOAD_MARKER'; }],
  ['impossible transaction date', scenario => { scenario.result.data.transactions[0].date = '2025-02-29'; }],
];
for (const [name, changeResult] of invalidResults) {
  test(`malformed result ${name} shows recovery error without a renderer crash`, caseOptions, async t => {
    const { page, scenario, assertClean } = await openCase(t, { changeResult });
    await expect(page.getByText(/No se pudo cargar el resultado:/)).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Resultados de Extracción' })).toHaveCount(0);
    await expect(page.getByRole('table')).toHaveCount(0);
    await expect(page.locator('body')).not.toContainText('SYNTHETIC_PAYLOAD_MARKER');
    assert.ok(scenario.requests.some(request => request.kind === 'result'));
    assertClean();
  });
}

const invalidStatuses = [
  ['unknown lifecycle', scenario => { scenario.status.lifecycle = 'SYNTHETIC_PAYLOAD_MARKER'; }],
  ['inconsistent terminal state', scenario => { scenario.status.stageState = 'RUNNING'; }],
  ['different document', scenario => { scenario.status.documentId = 'e'.repeat(32); }],
  ['missing timestamp', scenario => { delete scenario.status.createdAt; }],
  ['invalid progress', scenario => { scenario.status.progress = { completedStages: 2, totalStages: 1 }; }],
];
for (const [name, changeStatus] of invalidStatuses) {
  test(`malformed status ${name} never triggers a result read`, caseOptions, async t => {
    const { page, scenario, assertClean } = await openCase(t, { changeStatus });
    await expect(page.getByText('Se perdió la conexión para el rastreo del documento.')).toBeVisible({ timeout: 22_000 });
    await expect(page.getByRole('heading', { name: 'Resultados de Extracción' })).toHaveCount(0);
    await expect(page.locator('body')).not.toContainText('SYNTHETIC_PAYLOAD_MARKER');
    assert.equal(scenario.requests.filter(request => request.kind === 'result').length, 0);
    assertClean();
  });
}
