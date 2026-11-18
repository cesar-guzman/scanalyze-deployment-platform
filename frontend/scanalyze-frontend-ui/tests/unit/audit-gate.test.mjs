import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  AuditGateError,
  MAX_EXCEPTION_DAYS,
  collectAdvisories,
  evaluateAudit,
  validateExceptions,
} from '../../scripts/audit-gate.mjs';

const TODAY = '2026-11-17';
const PICOMATCH = 'GHSA-fc5q-39xc-vjpf';
const SYNTHETIC = 'GHSA-2222-3333-4444';

const advisory = (overrides = {}) => ({
  source: 1000001,
  name: 'picomatch',
  dependency: 'picomatch',
  title: 'picomatch vulnerable to ReDoS through single-branch repeated extglobs',
  url: `https://github.com/advisories/${PICOMATCH}`,
  severity: 'high',
  range: '<=4.0.7',
  ...overrides,
});

const report = (vulnerabilities = {}) => {
  const counts = { info: 0, low: 0, moderate: 0, high: 0, critical: 0 };
  for (const entry of Object.values(vulnerabilities)) counts[entry.severity] += 1;
  return {
    auditReportVersion: 2,
    vulnerabilities,
    metadata: { vulnerabilities: { ...counts, total: Object.keys(vulnerabilities).length } },
  };
};

// The shape npm reports for the picomatch advisory: one advisory object, and
// packages such as vite that are affected only through picomatch.
const picomatchTree = (extra = {}) =>
  report({
    picomatch: { name: 'picomatch', severity: 'high', via: [advisory()], nodes: ['node_modules/picomatch'] },
    vite: { name: 'vite', severity: 'high', via: ['picomatch'], nodes: ['node_modules/vite'] },
    ...extra,
  });

const exception = (overrides = {}) => ({
  advisory: PICOMATCH,
  package: 'picomatch',
  scope: 'development',
  granted: '2026-11-17',
  expires: '2026-12-17',
  reason: 'No fixed release exists; reached only through build tooling.',
  ...overrides,
});

const documentWith = (...entries) => ({ schema_version: 1, exceptions: entries });

test('a granted development exception passes when production dependencies are clean', () => {
  const { exceptions, errors } = validateExceptions(documentWith(exception()), TODAY);
  assert.deepEqual(errors, []);

  const result = evaluateAudit({ fullReport: picomatchTree(), productionReport: report(), exceptions });
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.warnings, []);
  assert.deepEqual(
    result.excepted.map((item) => [item.id, item.package, item.expires]),
    [[PICOMATCH, 'picomatch', '2026-12-17']],
  );
});

test('an advisory without an exception fails', () => {
  const other = advisory({
    name: 'axios',
    title: 'synthetic advisory',
    url: `https://github.com/advisories/${SYNTHETIC}`,
    severity: 'moderate',
  });
  const fullReport = picomatchTree({ axios: { name: 'axios', severity: 'moderate', via: [other] } });
  const { exceptions } = validateExceptions(documentWith(exception()), TODAY);

  const result = evaluateAudit({ fullReport, productionReport: report(), exceptions });
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /GHSA-2222-3333-4444 \(axios, moderate\) has no exception/);
});

test('production dependencies get no exception, even for a granted advisory', () => {
  const { exceptions } = validateExceptions(documentWith(exception()), TODAY);

  const result = evaluateAudit({ fullReport: picomatchTree(), productionReport: picomatchTree(), exceptions });
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /GHSA-fc5q-39xc-vjpf in production dependencies/);
});

test('the exception must name the same package as the advisory', () => {
  const { exceptions } = validateExceptions(documentWith(exception({ package: 'micromatch' })), TODAY);

  const result = evaluateAudit({ fullReport: picomatchTree(), productionReport: report(), exceptions });
  assert.match(result.errors.join('\n'), /GHSA-fc5q-39xc-vjpf \(picomatch, high\) has no exception/);
  assert.match(result.warnings.join('\n'), /no longer appears in the audit/);
});

test('an exception applies through its expiry day and fails the day after', () => {
  assert.deepEqual(validateExceptions(documentWith(exception()), '2026-12-17').errors, []);

  const { exceptions, errors } = validateExceptions(documentWith(exception()), '2026-12-18');
  assert.deepEqual(exceptions, []);
  assert.match(errors.join('\n'), /expired on 2026-12-17/);
});

test(`an exception cannot last more than ${MAX_EXCEPTION_DAYS} days or start in the future`, () => {
  const tooLong = validateExceptions(documentWith(exception({ expires: '2026-12-18' })), TODAY);
  assert.match(tooLong.errors.join('\n'), /0 to 30 days after granted \(got 31\)/);

  const future = validateExceptions(documentWith(exception({ granted: '2026-11-20', expires: '2026-12-20' })), TODAY);
  assert.match(future.errors.join('\n'), /granted 2026-11-20 is in the future/);
});

test('only development scope, the closed key set and GitHub advisory IDs are accepted', () => {
  const cases = [
    [exception({ scope: 'production' }), /scope must be "development"/],
    [exception({ advisory: 'CVE-2026-0001' }), /GitHub advisory ID/],
    [exception({ granted: '2026-02-30' }), /granted must be a YYYY-MM-DD date/],
    [exception({ reason: 'later' }), /reason must explain/],
    [{ ...exception(), owner: 'someone' }, /keys must be exactly/],
  ];
  for (const [entry, pattern] of cases) {
    const { exceptions, errors } = validateExceptions(documentWith(entry), TODAY);
    assert.deepEqual(exceptions, []);
    assert.match(errors.join('\n'), pattern);
  }

  assert.match(validateExceptions({ exceptions: [] }, TODAY).errors[0], /schema_version/);
  assert.match(validateExceptions(documentWith(exception(), exception()), TODAY).errors.join('\n'), /duplicate/);
});

test('an npm error, an unknown report or an inconsistent report fails closed', () => {
  assert.throws(
    () => collectAdvisories({ error: { code: 'ENOTFOUND', summary: 'request to the registry failed' } }, 'full audit'),
    AuditGateError,
  );
  assert.throws(() => collectAdvisories({ auditReportVersion: 1, advisories: {} }, 'full audit'), /auditReportVersion 2/);
  assert.throws(() => collectAdvisories('not a report', 'full audit'), AuditGateError);

  const onlyTransitive = report({ vite: { name: 'vite', severity: 'high', via: ['picomatch'] } });
  assert.throws(() => collectAdvisories(onlyTransitive, 'full audit'), /listed no advisory/);
});

test('info advisories do not count, as with --audit-level=low', () => {
  const info = report({ picomatch: { name: 'picomatch', severity: 'info', via: [advisory({ severity: 'info' })] } });
  assert.deepEqual(collectAdvisories(info, 'full audit'), []);
});

test('the committed exception file is well formed', () => {
  const document = JSON.parse(readFileSync(new URL('../../audit-exceptions.json', import.meta.url), 'utf8'));
  const latestGrant = document.exceptions.map((entry) => entry.granted).sort().at(-1) ?? TODAY;

  assert.deepEqual(validateExceptions(document, latestGrant).errors, []);
});
