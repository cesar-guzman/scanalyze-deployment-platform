import { test, expect, type Page } from '@playwright/test';
import {
  BANK_STATEMENT_RESULT_FIXTURE,
  DOCUMENT_STATUS_RESPONSE_FIXTURE,
} from '../src/contracts/documentJourney.v1.fixtures';
import type {
  BankStatementResult,
  DocumentJourneyErrorEnvelope,
} from '../src/contracts/documentJourney.v1';
import {
  syntheticAuthState,
  syntheticOidcStorageKey,
  syntheticRuntimeConfig,
} from './runtime';

// Local browser contract coverage. Authentication, API and processing are
// synthetic; these tests do not establish a deployed or production journey.
const LOCAL_ORIGIN = new URL(syntheticRuntimeConfig.api_endpoint).origin;
const DOCUMENT_ID = BANK_STATEMENT_RESULT_FIXTURE.documentId;
const STATUS_PATH = `/api/v2/documents/${DOCUMENT_ID}`;
const RESULT_PATH = `${STATUS_PATH}/result`;

test.beforeEach(async ({ page }) => {
  // Block every external request and any API request without an exact mock.
  await page.route('**/*', async route => {
    const url = new URL(route.request().url());
    if (url.origin !== LOCAL_ORIGIN || url.pathname.startsWith('/api')) {
      await route.abort('blockedbyclient');
      return;
    }
    await route.continue();
  });
  await page.route(url => url.origin === LOCAL_ORIGIN && url.pathname === '/config.json', async route => {
    await route.fulfill({ json: syntheticRuntimeConfig });
  });
  await page.addInitScript(({ key, state, origin }) => {
    if (window.location.origin === origin) {
      sessionStorage.setItem(key, JSON.stringify(state));
    }
  }, { key: syntheticOidcStorageKey, state: syntheticAuthState, origin: LOCAL_ORIGIN });
});

const mockResult = async (
  page: Page,
  result: BankStatementResult | DocumentJourneyErrorEnvelope,
  status = 200,
) => {
  await page.route(url => url.origin === LOCAL_ORIGIN && url.pathname === STATUS_PATH, async route => {
    expect(route.request().method()).toBe('GET');
    await route.fulfill({ json: DOCUMENT_STATUS_RESPONSE_FIXTURE });
  });
  await page.route(url => url.origin === LOCAL_ORIGIN && url.pathname === RESULT_PATH, async route => {
    expect(route.request().method()).toBe('GET');
    expect(route.request().headers()['x-scanalyze-contract-version']).toBe('scanalyze.document-journey.v1');
    await route.fulfill({ status, json: result });
  });
};

test('renders a nullable transaction amount as missing instead of zero', async ({ page }) => {
  const result: BankStatementResult = {
    ...BANK_STATEMENT_RESULT_FIXTURE,
    data: {
      ...BANK_STATEMENT_RESULT_FIXTURE.data,
      transactions: [{
        ...BANK_STATEMENT_RESULT_FIXTURE.data.transactions[0],
        description: 'Synthetic amount unavailable',
        amount: null,
      }],
    },
  };
  await mockResult(page, result);
  await page.goto(`/document/${DOCUMENT_ID}`);

  await expect(page.getByRole('heading', { name: 'Resultados de Extracción' })).toBeVisible();
  const row = page.getByRole('row').filter({ hasText: 'Synthetic amount unavailable' });
  await expect(row.getByRole('cell').nth(2)).toHaveText('—');
  await expect(row).not.toContainText('0.00');
});

test('renders canonical warning codes with Spanish explanations', async ({ page }) => {
  const result: BankStatementResult = {
    ...BANK_STATEMENT_RESULT_FIXTURE,
    warnings: [
      { code: 'BALANCE_RECONCILIATION_WARNING' },
      { code: 'INCOMPLETE_EXTRACTION' },
      { code: 'LOW_CONFIDENCE' },
    ],
  };
  await mockResult(page, result);
  await page.goto(`/document/${DOCUMENT_ID}`);

  await expect(page.getByText('Los saldos no coinciden con las transacciones extraídas.', { exact: true })).toBeVisible();
  await expect(page.getByText('La extracción está incompleta; revisa los datos disponibles.', { exact: true })).toBeVisible();
  await expect(page.getByText('La extracción tiene baja confianza; revisa los datos.', { exact: true })).toBeVisible();
});

test('preserves zero confidence and explicitly displays an empty result', async ({ page }) => {
  const result: BankStatementResult = {
    ...BANK_STATEMENT_RESULT_FIXTURE,
    data: { ...BANK_STATEMENT_RESULT_FIXTURE.data, transactions: [] },
    quality: { overallConfidence: 0 },
  };
  await mockResult(page, result);
  await page.goto(`/document/${DOCUMENT_ID}`);

  await expect(page.getByText('Confianza: 0%', { exact: true })).toBeVisible();
  await expect(page.getByText('No se encontraron transacciones en este resultado.', { exact: true })).toBeVisible();
  await expect(page.getByRole('table')).toHaveCount(0);
});

test('shows no extracted result when the result API denies access', async ({ page }) => {
  const denied: DocumentJourneyErrorEnvelope = {
    schemaVersion: 'scanalyze.error.v1',
    code: 'AUTHORIZATION_DENIED',
    message: 'The operation is not authorized.',
    correlationId: 'corr.synthetic.denied',
    retryClass: 'TERMINAL',
  };
  await mockResult(page, denied, 403);
  await page.goto(`/document/${DOCUMENT_ID}`);

  await expect(page.getByText(/No se pudo cargar el resultado:/)).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Resultados de Extracción' })).toHaveCount(0);
  await expect(page.getByText('Synthetic Bank', { exact: true })).toHaveCount(0);
  await expect(page.getByRole('table')).toHaveCount(0);
});

test('bank statement history reads the canonical result envelope and keeps unknown amounts', async ({ page }) => {
  const result: BankStatementResult = {
    ...BANK_STATEMENT_RESULT_FIXTURE,
    data: {
      ...BANK_STATEMENT_RESULT_FIXTURE.data,
      transactions: [{
        ...BANK_STATEMENT_RESULT_FIXTURE.data.transactions[0],
        description: 'Synthetic amount unavailable',
        amount: null,
      }],
    },
  };
  await mockResult(page, result);
  await page.route(url => url.origin === LOCAL_ORIGIN && url.pathname === '/api/analytics/docs', async route => {
    expect(new URL(route.request().url()).searchParams.get('classRoute')).toBe('bank-extract');
    await route.fulfill({ json: { documents: [{
      documentId: DOCUMENT_ID,
      filename: 'synthetic-statement.pdf',
      status: 'COMPLETED',
      createdAt: DOCUMENT_STATUS_RESPONSE_FIXTURE.createdAt,
    }], nextCursor: null } });
  });
  await page.goto('/bank-statements');
  await page.getByRole('button', { name: 'Historial', exact: true }).click();
  await page.getByRole('button', { name: /synthetic-statement\.pdf/ }).click();

  await expect(page.getByText('Synthetic Bank', { exact: true })).toBeVisible();
  await expect(page.getByText('Synthetic Account Holder', { exact: true })).toBeVisible();
  const row = page.getByRole('row').filter({ hasText: 'Synthetic amount unavailable' });
  await expect(row.getByRole('cell').nth(4)).toContainText('—');
  await expect(row.getByRole('cell').nth(4)).not.toContainText('0.00');
});

const bankHistoryDocument = {
  documentId: DOCUMENT_ID, filename: 'previous-statement.pdf', status: 'COMPLETED',
  createdAt: DOCUMENT_STATUS_RESPONSE_FIXTURE.createdAt,
};

test('bank history exists independently of the current tab journal and follows pagination', async ({ page }) => {
  const cursors: (string | null)[] = [];
  await page.route(url => url.origin === LOCAL_ORIGIN && url.pathname === '/api/analytics/docs', async route => {
    const params = new URL(route.request().url()).searchParams;
    expect(params.get('classRoute')).toBe('bank-extract');
    expect(params.get('limit')).toBe('50');
    cursors.push(params.get('cursor'));
    await route.fulfill({ json: params.has('cursor')
      ? { documents: [bankHistoryDocument], nextCursor: null }
      : { documents: [], nextCursor: 'synthetic-page-two' } });
  });
  await mockResult(page, BANK_STATEMENT_RESULT_FIXTURE);
  await page.goto('/bank-statements');
  await page.getByRole('button', { name: 'Resultados del lote', exact: true }).click();
  await expect(page.getByText('No hay un lote guardado en esta pestaña.')).toBeVisible();
  expect(cursors).toEqual([]);
  await page.getByRole('button', { name: 'Historial', exact: true }).click();
  await page.getByRole('button', { name: 'Cargar más', exact: true }).click();
  await page.getByRole('button', { name: /previous-statement.pdf/ }).click();
  await expect(page.getByText('Synthetic Bank', { exact: true })).toBeVisible();
  expect(cursors).toEqual([null, 'synthetic-page-two']);
});

for (const status of [401, 403, 404, 500]) {
  test(`bank history failure ${status} never claims the account history is empty`, async ({ page }) => {
    await page.route(url => url.origin === LOCAL_ORIGIN && url.pathname === '/api/analytics/docs', route => route.fulfill({ status, json: {} }));
    await page.goto('/bank-statements');
    await page.getByRole('button', { name: 'Historial', exact: true }).click();
    await expect(page.getByRole('alert')).toContainText('No se pudo consultar el historial');
    await expect(page.getByText(/No hay estados de cuenta/)).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Exportar CSV', exact: true })).toHaveCount(0);
  });
}

test('bank history denies an invalid document locator before navigating or reading a result', async ({ page }) => {
  await page.route(url => url.origin === LOCAL_ORIGIN && url.pathname === '/api/analytics/docs', route => route.fulfill({
    json: { documents: [{ ...bankHistoryDocument, documentId: '../../foreign' }], nextCursor: null },
  }));
  await page.goto('/bank-statements');
  await page.getByRole('button', { name: 'Historial', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('No se pudo consultar el historial');
  await expect(page.getByRole('button', { name: /previous-statement.pdf/ })).toHaveCount(0);
});

test('bank result denial leaves no extracted data or CSV action', async ({ page }) => {
  await page.route(url => url.origin === LOCAL_ORIGIN && url.pathname === '/api/analytics/docs', route => route.fulfill({ json: { documents: [bankHistoryDocument], nextCursor: null } }));
  await page.route(url => url.origin === LOCAL_ORIGIN && url.pathname === RESULT_PATH, route => route.fulfill({ status: 403, json: {} }));
  await page.goto('/bank-statements');
  await page.getByRole('button', { name: 'Historial', exact: true }).click();
  await page.getByRole('button', { name: /previous-statement.pdf/ }).click();
  await expect(page.getByRole('alert')).toContainText('No se pudo consultar el resultado');
  await expect(page.getByText('Synthetic Bank', { exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Exportar CSV', exact: true })).toHaveCount(0);
});

test('bank CSV uses the selected historical document and reports export denial', async ({ page }) => {
  await page.route(url => url.origin === LOCAL_ORIGIN && url.pathname === '/api/analytics/docs', route => route.fulfill({ json: { documents: [bankHistoryDocument], nextCursor: null } }));
  await mockResult(page, BANK_STATEMENT_RESULT_FIXTURE);
  let exportCalls = 0;
  await page.route(url => url.origin === LOCAL_ORIGIN && url.pathname === '/api/analytics/export-bank', route => {
    expect(new URL(route.request().url()).searchParams.get('documentIds')).toBe(DOCUMENT_ID);
    exportCalls++;
    return route.fulfill({ status: 403, json: {} });
  });
  await page.goto('/bank-statements');
  await page.getByRole('button', { name: 'Historial', exact: true }).click();
  await page.getByRole('button', { name: /previous-statement.pdf/ }).click();
  await page.getByRole('button', { name: 'Exportar CSV', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('No fue posible descargar el reporte CSV');
  expect(exportCalls).toBe(1);
});

test('bank history discards a late response after the stored actor changes', async ({ page }) => {
  let release!: () => void;
  let requested!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const seen = new Promise<void>(resolve => { requested = resolve; });
  await page.route(url => url.origin === LOCAL_ORIGIN && url.pathname === '/api/analytics/docs', async route => {
    requested();
    await gate;
    await route.fulfill({ json: { documents: [bankHistoryDocument], nextCursor: null } });
  });
  await page.goto('/bank-statements');
  await page.getByRole('button', { name: 'Historial', exact: true }).click();
  await seen;
  await page.evaluate(key => {
    const state = JSON.parse(sessionStorage.getItem(key)!);
    state.profile.sub = 'synthetic-user-b';
    sessionStorage.setItem(key, JSON.stringify(state));
  }, syntheticOidcStorageKey);
  release();
  await expect(page.getByRole('alert')).toContainText('No se pudo consultar el historial');
  await expect(page.getByRole('button', { name: /previous-statement.pdf/ })).toHaveCount(0);
});

test('bank CSV successfully downloads the authorized historical selection', async ({ page }) => {
  await page.route(url => url.origin === LOCAL_ORIGIN && url.pathname === '/api/analytics/docs', route => route.fulfill({ json: { documents: [bankHistoryDocument], nextCursor: null } }));
  await mockResult(page, BANK_STATEMENT_RESULT_FIXTURE);
  await page.route(url => url.origin === LOCAL_ORIGIN && url.pathname === '/api/analytics/export-bank', route => {
    expect(new URL(route.request().url()).searchParams.get('documentIds')).toBe(DOCUMENT_ID);
    return route.fulfill({ contentType: 'text/csv', headers: { 'content-disposition': 'attachment; filename=bank_statements.csv' }, body: 'documentId,amount\r\nsynthetic,\r\n' });
  });
  await page.goto('/bank-statements');
  await page.getByRole('button', { name: 'Historial', exact: true }).click();
  await page.getByRole('button', { name: /previous-statement.pdf/ }).click();
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Exportar CSV', exact: true }).click();
  expect((await download).suggestedFilename()).toBe('bank_statements.csv');
  await expect(page.getByRole('alert')).toHaveCount(0);
});
