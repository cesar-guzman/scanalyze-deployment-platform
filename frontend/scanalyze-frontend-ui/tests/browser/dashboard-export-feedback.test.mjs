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
      const mockAuth = { isAuthenticated: true, user: { profile: { sub: 'synthetic-user' } } };
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
      plugin.onResolve({ filter: /^\.\.\/api\/client$/ }, args => {
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
      return response.end(JSON.stringify({ documents: [{ documentId: 'doc-123', filename: 'test.pdf', status: 'COMPLETED' }, { documentId: 'doc-456', filename: 'test2.pdf', status: 'COMPLETED' }] }));
    }
    
    if (url.pathname === '/api/analytics/export-ine') {
      const isError = scenario.errorNext;
      if (isError) {
        scenario.errorNext = false;
        const sendError = () => {
          response.writeHead(scenario.errorCode || 500, { 'Content-Type': 'application/json' });
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

test('export failure shows accessible feedback without raw error, preserves modal, handles explicit retry (403 filter mode)', caseOptions, async t => {
  const { page, scenario, downloads, assertClean } = await openCase(t, { errorNext: true, errorCode: 403 });
  
  await page.locator('div.glass-card', { hasText: 'Datos Personales y KYC' }).click();
  await expect(page.getByRole('heading', { name: 'Exportación INE / KYC' })).toBeVisible();
  
  await page.getByRole('button', { name: 'Filtros' }).click();
  await page.locator('input[type="date"]').first().fill('2026-09-01');
  await page.locator('input[type="date"]').nth(1).fill('2026-09-20');
  await page.locator('input[placeholder="ID de Usuario / Email"]').fill('user-abc');
  
  await page.getByRole('button', { name: 'Descargar CSV' }).click();
  
  const alert = page.locator('div[role="alert"]');
  await expect(alert).toContainText('No fue posible descargar el reporte. Revisa tus permisos o vuelve a intentarlo.');
  await expect(page.getByRole('heading', { name: 'Exportación INE / KYC' })).toBeVisible();
  
  await expect(page.locator('input[type="date"]').first()).toHaveValue('2026-09-01');
  await expect(page.locator('input[type="date"]').nth(1)).toHaveValue('2026-09-20');
  await expect(page.locator('input[placeholder="ID de Usuario / Email"]')).toHaveValue('user-abc');
  await expect(page.getByRole('button', { name: 'Descargar CSV' })).toBeEnabled();
  
  await expect(page.locator('body')).not.toContainText('RAW_ERROR_TEXT_SYNTHETIC');
  assert.equal(downloads.length, 0);
  
  const exportRequests = scenario.requests.filter(r => r.url === '/api/analytics/export-ine');
  assert.equal(exportRequests.length, 1);
  assert.match(exportRequests[0].query, /startDate=2026-09-01/);
  assert.match(exportRequests[0].query, /endDate=2026-09-20/);
  assert.match(exportRequests[0].query, /userId=user-abc/);

  await page.waitForTimeout(1000);
  assert.equal(scenario.requests.filter(r => r.url === '/api/analytics/export-ine').length, 1);

  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: 'Descargar CSV' }).click()
  ]);
  
  await expect(page.getByRole('heading', { name: 'Exportación INE / KYC' })).toHaveCount(0);
  
  assert.equal(download.suggestedFilename(), 'ine_export.csv');
  const path = await download.path();
  const buffer = fs.readFileSync(path);
  assert.equal(buffer.toString(), 'col1,col2\nval1,val2');

  const allExportRequests = scenario.requests.filter(r => r.url === '/api/analytics/export-ine');
  assert.equal(allExportRequests.length, 2);

  assertClean();
});

test('export failure with 503 handled correctly for manual mode', caseOptions, async t => {
  const { page, scenario, downloads, assertClean } = await openCase(t, { errorNext: true, errorCode: 503 });
  
  await page.locator('div.glass-card', { hasText: 'Datos Personales y KYC' }).click();
  await page.getByRole('button', { name: 'Manual' }).click();
  
  await page.locator('input[type="checkbox"]').first().check();
  await page.locator('input[type="checkbox"]').nth(1).check();
  
  await page.getByRole('button', { name: 'Descargar (2)' }).click();
  
  const alert = page.locator('div[role="alert"]');
  await expect(alert).toContainText('No fue posible descargar el reporte. Revisa tus permisos o vuelve a intentarlo.');
  
  assert.equal(downloads.length, 0);
  const exportRequests = scenario.requests.filter(r => r.url === '/api/analytics/export-ine');
  // allow both %2C and , encoding
  assert.match(exportRequests[0].query, /documentIds=doc-123(%2C|,)doc-456/);

  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: 'Descargar (2)' }).click()
  ]);
  
  await expect(page.getByRole('heading', { name: 'Exportación INE / KYC' })).toHaveCount(0);
  assert.equal(downloads.length, 1);
  
  assertClean();
});

test('export failure handled correctly for batch mode', caseOptions, async t => {
  const { page, scenario, downloads, assertClean } = await openCase(t, { errorNext: true, errorCode: 500 });
  
  await page.locator('div.glass-card', { hasText: 'Datos Personales y KYC' }).click();
  await page.getByRole('button', { name: 'Por Lote' }).click();
  
  await page.locator('button', { hasText: 'batch-123456' }).click();
  await page.getByRole('button', { name: /Descargar Lote/ }).click();
  
  await expect(page.locator('div[role="alert"]')).toBeVisible();
  assert.equal(downloads.length, 0);
  const exportRequests = scenario.requests.filter(r => r.url === '/api/analytics/export-ine');
  assert.match(exportRequests[0].query, /batchId=batch-123456789012/);

  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: /Descargar Lote/ }).click()
  ]);
  
  await expect(page.getByRole('heading', { name: 'Exportación INE / KYC' })).toHaveCount(0);
  assert.ok(download.suggestedFilename().startsWith('ine_export_batch-123456'));
  
  assertClean();
});

test('stale feedback cleared on fresh modal and retry clears error while pending', caseOptions, async t => {
  const { page, scenario, assertClean } = await openCase(t, { errorNext: true, holdResponse: true });
  
  await page.locator('div.glass-card', { hasText: 'Datos Personales y KYC' }).click();
  await page.getByRole('button', { name: 'Descargar CSV' }).click();
  
  await page.waitForTimeout(50);
  scenario.heldResponses.shift()();
  
  await expect(page.locator('div[role="alert"]')).toBeVisible();
  
  scenario.holdResponse = true;
  await page.getByRole('button', { name: 'Descargar CSV' }).click();
  
  await expect(page.locator('div[role="alert"]')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Descargando...' })).toBeDisabled();
  
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    scenario.heldResponses.shift()()
  ]);
  
  await expect(page.getByRole('heading', { name: 'Exportación INE / KYC' })).toHaveCount(0);
  
  await page.locator('div.glass-card', { hasText: 'Datos Personales y KYC' }).click();
  await expect(page.locator('div[role="alert"]')).toHaveCount(0);
  
  assertClean();
});

test('late failure from cancelled attempt does not affect fresh modal', caseOptions, async t => {
  const { page, scenario, downloads, assertClean } = await openCase(t, { holdResponse: true, errorNext: true });
  
  await page.locator('div.glass-card', { hasText: 'Datos Personales y KYC' }).click();
  await page.getByRole('button', { name: 'Descargar CSV' }).click();
  
  await page.getByRole('button', { name: 'Cancelar' }).click();
  await expect(page.getByRole('heading', { name: 'Exportación INE / KYC' })).toHaveCount(0);
  
  await page.locator('div.glass-card', { hasText: 'Datos Personales y KYC' }).click();
  await expect(page.getByRole('heading', { name: 'Exportación INE / KYC' })).toBeVisible();
  
  scenario.heldResponses.shift()();
  
  await page.waitForTimeout(500);
  
  await expect(page.locator('div[role="alert"]')).toHaveCount(0);
  assert.equal(downloads.length, 0);
  
  assertClean();
});

test('late success from cancelled attempt does not close fresh modal or trigger stale download', caseOptions, async t => {
  const { page, scenario, downloads, assertClean } = await openCase(t, { holdResponse: true });
  
  await page.locator('div.glass-card', { hasText: 'Datos Personales y KYC' }).click();
  await expect(page.getByRole('heading', { name: 'Exportación INE / KYC' })).toBeVisible();
  
  await page.getByRole('button', { name: 'Descargar CSV' }).click();
  await expect(page.getByRole('button', { name: 'Descargando...' })).toBeDisabled();
  
  await page.getByRole('button', { name: 'Cancelar' }).click();
  await expect(page.getByRole('heading', { name: 'Exportación INE / KYC' })).toHaveCount(0);
  
  await page.locator('div.glass-card', { hasText: 'Datos Personales y KYC' }).click();
  await expect(page.getByRole('heading', { name: 'Exportación INE / KYC' })).toBeVisible();
  
  const clickPromise = page.getByRole('button', { name: 'Descargar CSV' }).click();
  await clickPromise;
  
  await expect(page.getByRole('button', { name: 'Descargando...' })).toBeDisabled();
  
  // resolve first OLD response
  scenario.heldResponses.shift()();
  
  await page.waitForTimeout(500);
  
  await expect(page.getByRole('heading', { name: 'Exportación INE / KYC' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Descargando...' })).toBeDisabled();
  assert.equal(downloads.length, 0);
  
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    scenario.heldResponses.shift()()
  ]);
  
  await expect(page.getByRole('heading', { name: 'Exportación INE / KYC' })).toHaveCount(0);
  assert.equal(downloads.length, 1);
  
  assertClean();
});
