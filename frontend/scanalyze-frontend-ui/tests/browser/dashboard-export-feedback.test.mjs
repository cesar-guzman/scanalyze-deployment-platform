import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { chromium, expect } from '@playwright/test';
import fs from 'node:fs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const scenarios = new Map();
const caseOptions = { timeout: 35_000 };
let browser;
let server;
let baseUrl;
let nextCase = 0;

before(async () => {
  const output = await build({
    absWorkingDir: root,
    stdin: { contents: `
      import React, { StrictMode } from 'react';
      import { createRoot } from 'react-dom/client';
      import { MemoryRouter, Route, Routes } from 'react-router-dom';
      import { AuthProvider } from 'react-oidc-context';
      import { Dashboard } from './src/pages/Dashboard';
      createRoot(document.getElementById('container')).render(
        <StrictMode>
          <AuthProvider authority="http://localhost" client_id="mock" redirect_uri="http://localhost">
            <MemoryRouter initialEntries={['/']}>
              <Routes><Route path='/' element={<Dashboard />} /></Routes>
            </MemoryRouter>
          </AuthProvider>
        </StrictMode>
      );
    `, resolveDir: root, sourcefile: 'synthetic-dashboard-feedback-entry.tsx', loader: 'tsx' },
    write: false, bundle: true, format: 'esm', platform: 'browser', target: 'es2022',
    jsx: 'automatic', metafile: true, define: { 'process.env.NODE_ENV': '"development"' },
    plugins: [{ name: 'synthetic-dashboard-client', setup(plugin) {
      plugin.onResolve({ filter: /^\.\.\/api\/client$/ }, () => {
        return { path: 'response-client', namespace: 'synthetic' };
      });
      plugin.onLoad({ filter: /.*/, namespace: 'synthetic' }, () => ({
        contents: `import axios from 'axios';
          const client = axios.create({ baseURL: location.origin + '/api', timeout: 5000,
            headers: { 'X-Synthetic-Case': new URL(location.href).searchParams.get('case') } });
          export const getApiClient = () => client;`,
        loader: 'js', resolveDir: root,
      }));
      plugin.onResolve({ filter: /^\.\.\/api\/employeeProfilesApi$/ }, () => {
        return { path: 'employee-profiles-api', namespace: 'synthetic-ep' };
      });
      plugin.onLoad({ filter: /.*/, namespace: 'synthetic-ep' }, () => ({
        contents: `export const employeeProfilesApi = { getStatus: async () => ({ tenantEnabled: false }) };`,
        loader: 'js', resolveDir: root,
      }));
      plugin.onResolve({ filter: /^react-oidc-context$/ }, () => {
        return { path: 'mock-oidc', namespace: 'synthetic-oidc' };
      });
      plugin.onLoad({ filter: /.*/, namespace: 'synthetic-oidc' }, () => ({
        contents: `export const useAuth = () => ({ isAuthenticated: true });
                   export const AuthProvider = ({ children }) => children;`,
        loader: 'js', resolveDir: root,
      }));
    } }],
  });

  const bundle = output.outputFiles[0].text;
  server = createServer((request, response) => {
    const url = new URL(request.url, 'http://127.0.0.1');
    response.setHeader('Cache-Control', 'no-store');
    if (url.pathname === '/') {
      response.writeHead(200, { 'Content-Type': 'text/html' });
      return response.end('<!doctype html><title>Synthetic feedback validation</title><div id="container"></div><script type="module" src="/bundle.js"></script>');
    }
    if (url.pathname === '/bundle.js') {
      response.writeHead(200, { 'Content-Type': 'text/javascript' });
      return response.end(bundle);
    }

    const scenario = scenarios.get(request.headers['x-synthetic-case']);
    if (!scenario) {
      response.writeHead(404); return response.end();
    }

    if (url.pathname.startsWith('/api/') && url.pathname !== '/api/health') {
        scenario.requests.push({ url: url.pathname, query: url.search, method: request.method });
    }

    if (url.pathname === '/api/health') {
      response.writeHead(200, { 'Content-Type': 'application/json' });
      return response.end(JSON.stringify({ status: 'API Operacional' }));
    }
    if (url.pathname === '/api/analytics/batches') {
      response.writeHead(200, { 'Content-Type': 'application/json' });
      return response.end(JSON.stringify([{ batchId: 'batch-123456789012', status: 'COMPLETED', metadata: { name: 'Test Batch' } }]));
    }
    if (url.pathname === '/api/analytics/ine-docs') {
      response.writeHead(200, { 'Content-Type': 'application/json' });
      return response.end(JSON.stringify({ total: 2, documents: [{ documentId: 'doc-123', filename: 'test.pdf', status: 'COMPLETED' }, { documentId: 'doc-456', filename: 'test2.pdf', status: 'COMPLETED' }] }));
    }

    if (url.pathname === '/api/analytics/export-ine') {
      const isError = scenario.errorNext;
      if (isError) {
        scenario.errorNext = false;
        const sendError = () => {
          response.writeHead(scenario.errorCode || 503, { 'Content-Type': 'application/json' });
          response.end(JSON.stringify({ error: 'RAW_ERROR_TEXT_SYNTHETIC' }));
        };
        if (scenario.holdResponse) {
          scenario.heldResponses.push(sendError);
          return;
        }
        return sendError();
      }

      const sendSuccess = () => {
        response.writeHead(200, { 'Content-Type': 'text/csv' });
        response.end('col1,col2\nval1,val2');
      };

      if (scenario.holdResponse) {
        scenario.heldResponses.push(sendSuccess);
        return;
      }
      return sendSuccess();
    }

    response.writeHead(404); return response.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
  browser = await chromium.launch({ headless: true });
});

after(async () => {
  await browser?.close();
  if (server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});

async function openCase(t, config = {}) {
  const caseId = String(++nextCase);
  const scenario = { requests: [], errorNext: config.errorNext, errorCode: config.errorCode, holdResponse: config.holdResponse || false, heldResponses: [] };
  scenarios.set(caseId, scenario);
  const context = await browser.newContext();
  t.after(async () => { await context.close(); scenarios.delete(caseId); });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  const response = await page.goto(`${baseUrl}/?case=${caseId}`);
  assert.equal(response.status(), 200);

  const downloads = [];
  page.on('download', download => downloads.push(download));

  return { page, scenario, downloads, assertClean: () => {
    assert.deepEqual(errors, []);
  } };
}

const exportPath = '/api/analytics/export-ine';
const csvBody = 'col1,col2\nval1,val2';
const feedback = 'No fue posible descargar el reporte. Revisa tus permisos o vuelve a intentarlo.';
const modes = [
  { name: 'filters', button: 'Descargar CSV', filename: 'ine_export.csv',
    params: { startDate: '2026-09-01', endDate: '2026-09-20', userId: 'synthetic-reviewer' } },
  { name: 'manual', button: 'Descargar (2)', filename: 'ine_export.csv',
    params: { documentIds: 'doc-123,doc-456' } },
  { name: 'batch', button: 'Descargar Lote (2 INEs)', filename: 'ine_export_batch-123456.csv',
    params: { batchId: 'batch-123456789012' } },
];
const modal = page => page.getByRole('heading', { name: 'Exportación INE / KYC' });
const exportsFor = scenario => scenario.requests.filter(r => r.url === exportPath);

async function openModal(page) {
  await page.locator('div.glass-card', { hasText: 'Datos Personales y KYC' }).click();
  await expect(modal(page)).toBeVisible();
}

async function selectMode(page, mode) {
  await openModal(page);
  if (mode.name === 'filters') {
    await page.getByRole('button', { name: 'Filtros', exact: true }).click();
    await page.locator('input[type="date"]').first().fill(mode.params.startDate);
    await page.locator('input[type="date"]').nth(1).fill(mode.params.endDate);
    await page.getByPlaceholder('ID de Usuario / Email').fill(mode.params.userId);
  } else if (mode.name === 'manual') {
    await page.getByRole('button', { name: 'Manual', exact: true }).click();
    await page.getByRole('checkbox').nth(0).check();
    await page.getByRole('checkbox').nth(1).check();
  } else {
    await page.getByRole('button', { name: 'Por Lote', exact: true }).click();
    await page.getByRole('button', { name: /Test Batch/ }).click();
  }
  await expect(page.getByRole('button', { name: mode.button, exact: true })).toBeEnabled();
}

async function assertSelection(page, mode) {
  if (mode.name === 'filters') {
    await expect(page.locator('input[type="date"]').first()).toHaveValue(mode.params.startDate);
    await expect(page.locator('input[type="date"]').nth(1)).toHaveValue(mode.params.endDate);
    await expect(page.getByPlaceholder('ID de Usuario / Email')).toHaveValue(mode.params.userId);
  } else if (mode.name === 'manual') {
    await expect(page.getByRole('checkbox').nth(0)).toBeChecked();
    await expect(page.getByRole('checkbox').nth(1)).toBeChecked();
  } else {
    await expect(page.getByRole('button', { name: /Test Batch/ })).toHaveClass(/border-pink-500\/40/);
  }
}

function assertRequests(scenario, mode, count) {
  const requests = exportsFor(scenario);
  assert.equal(requests.length, count);
  for (const request of requests) {
    assert.equal(request.method, 'GET');
    assert.deepEqual(Object.fromEntries(new URLSearchParams(request.query)), mode.params);
  }
}

async function assertDownload(download, filename) {
  assert.equal(download.suggestedFilename(), filename);
  assert.equal(await download.failure(), null);
  assert.equal(fs.readFileSync(await download.path(), 'utf8'), csvBody);
}

async function waitHeld(scenario, count = 1) {
  await expect.poll(() => scenario.heldResponses.length).toBe(count);
}

async function completeHeld(page, scenario) {
  await waitHeld(scenario);
  const downloadPromise = page.waitForEvent('download');
  scenario.heldResponses.shift()();
  return downloadPromise;
}

async function releaseStale(page, scenario) {
  const responsePromise = page.waitForResponse(r => new URL(r.url()).pathname === exportPath);
  scenario.heldResponses.shift()();
  await (await responsePromise).finished();
  // Bounded absence window after delivery, allowing the mounted component to settle.
  await page.waitForTimeout(250);
}

for (const mode of modes) {
  for (const errorCode of [403, 503]) {
    test(`${mode.name}: ${errorCode} preserves input, gives generic feedback and retries only explicitly`, caseOptions, async t => {
      const { page, scenario, downloads, assertClean } = await openCase(t, { errorNext: true, errorCode });
      await selectMode(page, mode);
      await page.getByRole('button', { name: mode.button, exact: true }).click();
      await expect(page.getByRole('alert')).toHaveText(feedback);
      await expect(modal(page)).toBeVisible();
      await expect(page.getByRole('button', { name: mode.button, exact: true })).toBeEnabled();
      await assertSelection(page, mode);
      await expect(page.locator('body')).not.toContainText('RAW_ERROR_TEXT_SYNTHETIC');
      await page.waitForTimeout(500); // Observe that a failure does not cause an automatic retry.
      assert.equal(downloads.length, 0);
      assertRequests(scenario, mode, 1);

      scenario.holdResponse = true;
      await page.getByRole('button', { name: mode.button, exact: true }).click();
      await waitHeld(scenario);
      await expect(page.getByRole('alert')).toHaveCount(0);
      await expect(page.getByRole('button', { name: 'Descargando...', exact: true })).toBeDisabled();
      await assertSelection(page, mode);
      assertRequests(scenario, mode, 2);
      await assertDownload(await completeHeld(page, scenario), mode.filename);
      await expect(modal(page)).toHaveCount(0);
      assert.equal(downloads.length, 1);
      assertRequests(scenario, mode, 2);
      assertClean();
    });
  }

  test(`${mode.name}: first successful attempt preserves CSV bytes, filename and parameters`, caseOptions, async t => {
    const { page, scenario, downloads, assertClean } = await openCase(t);
    await selectMode(page, mode);
    const downloadPromise = page.waitForEvent('download');
    await page.getByRole('button', { name: mode.button, exact: true }).click();
    await assertDownload(await downloadPromise, mode.filename);
    await expect(modal(page)).toHaveCount(0);
    assert.equal(downloads.length, 1);
    assertRequests(scenario, mode, 1);
    assertClean();
  });
}

test('cancelling visible feedback clears it for the next modal interaction', caseOptions, async t => {
  const { page, downloads, assertClean } = await openCase(t, { errorNext: true, errorCode: 403 });
  await openModal(page);
  await page.getByRole('button', { name: 'Descargar CSV', exact: true }).click();
  await expect(page.getByRole('alert')).toHaveText(feedback);
  await page.getByRole('button', { name: 'Cancelar', exact: true }).click();
  await expect(modal(page)).toHaveCount(0);
  await openModal(page);
  await expect(page.getByRole('alert')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Descargar CSV', exact: true })).toBeEnabled();
  assert.equal(downloads.length, 0);
  assertClean();
});

for (const errorNext of [true, false]) {
  test(`late ${errorNext ? 'failure' : 'success'} after cancellation cannot affect a newer pending export`, caseOptions, async t => {
    const { page, scenario, downloads, assertClean } = await openCase(t, { holdResponse: true, errorNext, errorCode: 503 });
    await openModal(page);
    await page.getByRole('button', { name: 'Descargar CSV', exact: true }).click();
    await waitHeld(scenario);
    await page.getByRole('button', { name: 'Cancelar', exact: true }).click();
    await expect(modal(page)).toHaveCount(0);
    await openModal(page);
    await expect(page.getByRole('button', { name: 'Descargar CSV', exact: true })).toBeEnabled();
    // Different inputs permit two in-flight requests without Chromium serializing identical GETs.
    await page.getByPlaceholder('ID de Usuario / Email').fill('synthetic-new-attempt');
    await page.getByRole('button', { name: 'Descargar CSV', exact: true }).click();
    await waitHeld(scenario, 2);
    await releaseStale(page, scenario);
    await expect(modal(page)).toBeVisible();
    await expect(page.getByRole('alert')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Descargando...', exact: true })).toBeDisabled();
    assert.equal(downloads.length, 0);
    assert.equal(exportsFor(scenario).length, 2);
    assert.deepEqual(exportsFor(scenario).map(r => Object.fromEntries(new URLSearchParams(r.query))),
      [{}, { userId: 'synthetic-new-attempt' }]);
    await assertDownload(await completeHeld(page, scenario), 'ine_export.csv');
    await expect(modal(page)).toHaveCount(0);
    assert.equal(downloads.length, 1);
    assertClean();
  });
}

test('a cancelled late failure leaves a fresh idle modal ready for use', caseOptions, async t => {
  const { page, scenario, downloads, assertClean } = await openCase(t, { holdResponse: true, errorNext: true, errorCode: 403 });
  await openModal(page);
  await page.getByRole('button', { name: 'Descargar CSV', exact: true }).click();
  await waitHeld(scenario);
  await page.getByRole('button', { name: 'Cancelar', exact: true }).click();
  await expect(modal(page)).toHaveCount(0);
  await openModal(page);
  await releaseStale(page, scenario);
  await expect(modal(page)).toBeVisible();
  await expect(page.getByRole('alert')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Descargar CSV', exact: true })).toBeEnabled();
  assert.equal(downloads.length, 0);
  assert.equal(exportsFor(scenario).length, 1);
  assertClean();
});
