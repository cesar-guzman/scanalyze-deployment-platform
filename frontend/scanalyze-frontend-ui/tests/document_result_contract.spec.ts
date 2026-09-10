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
    }] } });
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
