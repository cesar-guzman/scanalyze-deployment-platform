import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';

const frontendRoot = fileURLToPath(new URL('../../', import.meta.url));
let temporaryDirectory;
let validator;
// Stable wrappers exist while tests register; before() initializes their module.
const parseStatus = (...args) => validator.parseDocumentStatusResponse(...args);
const parseResult = (...args) => validator.parseDocumentResultResponse(...args);

before(async () => {
  temporaryDirectory = await mkdtemp(join(tmpdir(), 'scanalyze-document-response-validation-'));
  try {
    const outfile = join(temporaryDirectory, 'documentResponseValidation.mjs');
    const output = await build({
      absWorkingDir: frontendRoot,
      entryPoints: ['src/domain/documentResponseValidation.ts'],
      outfile,
      bundle: true,
      platform: 'node',
      format: 'esm',
      target: 'node22',
      metafile: true,
      logLevel: 'silent',
    });
    assert.deepEqual(Object.keys(output.metafile.inputs).sort(), [
      'src/contracts/documentJourney.v1.ts',
      'src/domain/documentResponseValidation.ts',
    ]);
    validator = await import(pathToFileURL(outfile).href);
  } catch (error) {
    await rm(temporaryDirectory, { recursive: true, force: true });
    throw error;
  }
});

after(async () => {
  if (temporaryDirectory) await rm(temporaryDirectory, { recursive: true, force: true });
});

const ID = 'a'.repeat(32);
const OTHER_ID = 'b'.repeat(32);
const TIME = '2024-02-29T12:00:00Z';
const STATUS_ERROR = 'La respuesta de estado del documento no es válida.';
const RESULT_ERROR = 'La respuesta de resultado del documento no es válida.';
const openapi = JSON.parse(readFileSync(new URL('../../../../schemas/scanalyze-document-journey.openapi.v1.json', import.meta.url), 'utf8'));
const resultSchema = JSON.parse(readFileSync(new URL('../../../../schemas/scanalyze-document-journey-result.v1.schema.json', import.meta.url), 'utf8'));

function status(overrides = {}) {
  return { schemaVersion: 'scanalyze.document-status.v1', contractVersion: 'scanalyze.document-journey.v1', documentId: ID,
    lifecycle: 'PROCESSING', currentStage: 'INGEST', stageState: 'RUNNING', processingCondition: 'ACTIVE', createdAt: TIME, updatedAt: TIME, ...overrides };
}
function transaction() {
  return { date: null, description: null, reference: null, direction: 'credit', amount: null, balanceAfter: null, category: null };
}
function result() {
  return { schemaVersion: 'scanalyze.document-result.v1', contractVersion: 'scanalyze.document-journey.v1', documentType: 'bank_statement', resultType: 'bank_statement',
    documentId: ID, resultId: `result_${ID}_v1`, resultVersion: '1.0',
    provenance: { processor: 'bank-extract', producerSchemaVersion: '1.0', promptVersion: '1.0.0', generatedAt: TIME },
    data: { bank: { name: null }, account: { holder: null, numberMasked: null, clabeMasked: null, currency: null },
      statement: { periodStart: null, periodEnd: null }, balances: { opening: null, closing: null, totalCredits: null, totalDebits: null },
      transactions: [], accountType: null, bankCountry: null, fees: null, interestEarned: null, interestCharged: null, summaryText: null },
    warnings: [], quality: { overallConfidence: 0 } };
}
function populatedResult() {
  const value = result();
  value.data.transactions = [transaction()];
  value.data.fees = { totalFees: null, ivaOnFees: null };
  value.warnings = [{ code: 'LOW_CONFIDENCE' }];
  return value;
}
function at(value, path) { return path.reduce((node, key) => node[key], value); }
function setAt(value, path, replacement) { at(value, path.slice(0, -1))[path.at(-1)] = replacement; }
function rejected(parser, value, message, ...identity) {
  const expectedId = identity.length ? identity[0] : ID;
  const code = parser === parseStatus ? 'DOCUMENT_STATUS_RESPONSE_INVALID' : 'DOCUMENT_RESULT_RESPONSE_INVALID';
  assert.throws(() => parser(value, expectedId), error => error instanceof Error && error.message === message && error.code === code && !('cause' in error));
}

const validStates = [
  { lifecycle: 'UPLOAD_PENDING', currentStage: 'INGEST', stageState: 'PENDING', processingCondition: 'ACTIVE' },
  ...['PENDING', 'RUNNING'].map(stageState => ({ lifecycle: 'SUBMITTED', currentStage: 'INGEST', stageState, processingCondition: 'ACTIVE' })),
  ...['INGEST', 'OCR', 'CLASSIFY', 'BANK_EXTRACT', 'PERSONAL_EXTRACT', 'VALIDATE'].flatMap(currentStage =>
    ['PENDING', 'RUNNING', 'SUCCEEDED'].map(stageState => ({ lifecycle: 'PROCESSING', currentStage, stageState, processingCondition: 'ACTIVE' }))),
  { lifecycle: 'SUBMITTED', currentStage: 'INGEST', stageState: 'FAILED', processingCondition: 'NOT_APPLICABLE', failureDisposition: 'RETRYABLE', safeFailureCode: 'ENQUEUE_FAILED' },
  { lifecycle: 'COMPLETED', currentStage: 'TERMINAL', stageState: 'SUCCEEDED', processingCondition: 'NOT_APPLICABLE', terminalAt: TIME },
  ...['DOCUMENT_PROCESSING_FAILED', 'OCR_FAILED'].map(safeFailureCode => ({ lifecycle: 'FAILED', currentStage: 'TERMINAL', stageState: 'FAILED', processingCondition: 'NOT_APPLICABLE', terminalAt: TIME, failureDisposition: 'TERMINAL', safeFailureCode })),
];
for (const [index, variant] of validStates.entries()) {
  test(`status accepts canonical combination ${index + 1}: ${variant.lifecycle}/${variant.currentStage}/${variant.stageState}`, () => {
    const value = status(variant);
    assert.equal(parseStatus(value, ID), value);
  });
}

test('status discriminants match all public schema oneOf combinations, including forbidden fields', () => {
  const branches = openapi.components.schemas.DocumentStatusResponse.oneOf;
  const candidates = {
    lifecycle: openapi.components.schemas.DocumentLifecycle.enum,
    currentStage: openapi.components.schemas.PipelineStage.enum,
    stageState: openapi.components.schemas.StageState.enum,
    processingCondition: openapi.components.schemas.ProcessingCondition.enum,
    failureDisposition: [undefined, ...openapi.components.schemas.FailureDisposition.enum],
    safeFailureCode: [undefined, ...openapi.components.schemas.SafeFailureCode.enum],
    terminalAt: [undefined, TIME],
  };
  const branchMatches = (value, branch) => {
    if (branch.required.some(key => !Object.hasOwn(value, key))) return false;
    for (const [key, rule] of Object.entries(branch.properties)) {
      if ('const' in rule && value[key] !== rule.const) return false;
      if (rule.enum && !rule.enum.includes(value[key])) return false;
    }
    if (branch.not?.required?.every(key => Object.hasOwn(value, key))) return false;
    if (branch.not?.anyOf?.some(rule => rule.required.every(key => Object.hasOwn(value, key)))) return false;
    return true;
  };
  let examined = 0;
  let accepted = 0;
  function visit(entries, partial) {
    if (!entries.length) {
      const value = status(partial);
      const expected = branches.filter(branch => branchMatches(value, branch)).length === 1;
      if (expected) { assert.equal(parseStatus(value, ID), value); accepted++; }
      else rejected(parseStatus, value, STATUS_ERROR);
      examined++;
      return;
    }
    const [[key, values], ...rest] = entries;
    for (const value of values) visit(rest, value === undefined ? partial : { ...partial, [key]: value });
  }
  visit(Object.entries(candidates), {});
  assert.equal(examined, 6720);
  assert.equal(accepted, 25);
});

test('status optional bounds and progress counts use the contract, not the number of stage enum values', () => {
  const value = status({ batchId: OTHER_ID, correlationReference: 'a' + '.'.repeat(127), progress: { attempt: 1000, completedStages: 10, totalStages: 10 } });
  assert.equal(parseStatus(value, ID), value);
  assert.equal(parseStatus(status({ progress: {} }), ID).progress.totalStages, undefined);
  assert.equal(parseStatus(status({ progress: { completedStages: 10 } }), ID).progress.completedStages, 10);
});

for (const key of openapi.components.schemas.DocumentStatusResponse.required) {
  test(`status requires own field ${key}`, () => { const value = status(); delete value[key]; rejected(parseStatus, value, STATUS_ERROR); });
}

const invalidStatusFields = [
  ['schemaVersion', 'other'], ['contractVersion', 'other'], ['documentId', OTHER_ID], ['documentId', ID.toUpperCase()], ['documentId', ID + '\n'],
  ['batchId', null], ['batchId', 'a'.repeat(31)], ['batchId', OTHER_ID + '\n'], ['batchId', undefined],
  ['lifecycle', 'UNRECOGNIZED'], ['currentStage', 'GOV_EXTRACT'], ['stageState', 'UNKNOWN'], ['processingCondition', 'UNKNOWN'],
  ['correlationReference', 'a'.repeat(7)], ['correlationReference', 'a'.repeat(129)], ['correlationReference', '_abcdefg'], ['correlationReference', 'abcdefgh\n'],
  ['progress', null], ['progress', []], ['progress', { attempt: -1 }], ['progress', { attempt: 1001 }], ['progress', { attempt: 0.5 }],
  ['progress', { attempt: Infinity }], ['progress', { attempt: NaN }], ['progress', { attempt: '1' }], ['progress', { attempt: undefined }],
  ['progress', { completedStages: -1 }], ['progress', { completedStages: 11 }], ['progress', { totalStages: 0 }], ['progress', { totalStages: 11 }],
  ['progress', { completedStages: 3, totalStages: 2 }], ['progress', { extra: 1 }], ['extra', 'not allowed'],
  ['terminalAt', null], ['failureDisposition', undefined], ['safeFailureCode', undefined],
];
for (const [index, [field, value]] of invalidStatusFields.entries()) {
  test(`status rejects invalid field ${index + 1}: ${field}`, () => rejected(parseStatus, status({ [field]: value }), STATUS_ERROR));
}

const invalidTimes = [
  '0000-01-01T00:00:00Z', '10000-01-01T00:00:00Z', '2025-02-29T00:00:00Z', '1900-02-29T00:00:00Z',
  '2024-02-30T00:00:00Z', '2024-04-31T00:00:00Z', '2024-13-01T00:00:00Z', '2024-00-01T00:00:00Z', '2024-01-00T00:00:00Z',
  '2024-01-01T24:00:00Z', '2024-01-01T00:60:00Z', '2024-01-01T00:00:60Z', '2024-01-01T00:00:00',
  '2024-01-01 00:00:00Z', '2024-01-01T00:00:00+24:00', '2024-01-01T00:00:00+00:60', '2024-01-01T00:00:00+0000',
  '2024-01-01T00:00:00.Z', '2024-01-01T00:00:00Z\n', null, 0,
];
for (const [index, value] of invalidTimes.entries()) {
  test(`both responses reject invalid timestamp ${index + 1}`, () => {
    rejected(parseStatus, status({ createdAt: value }), STATUS_ERROR);
    const output = result(); output.provenance.generatedAt = value; rejected(parseResult, output, RESULT_ERROR);
  });
}

for (const timestamp of ['0001-01-01T00:00:00Z', '0099-12-31T23:59:59Z', '2000-02-29T00:00:00Z', '9999-12-31T23:59:59Z',
  '2024-02-29t12:00:00z', '2024-02-29T23:59:59+23:59', '2024-02-29T00:00:00-23:59', '2024-02-29T00:00:00-00:00', '2024-02-29T00:00:00.12345678901234567890Z']) {
  test(`accepts real timezone-aware timestamp ${timestamp}`, () => {
    const value = status({ createdAt: timestamp, updatedAt: timestamp }); assert.equal(parseStatus(value, ID), value);
    const output = result(); output.provenance.generatedAt = timestamp; assert.equal(parseResult(output, ID), output);
  });
}

test('timestamp ordering normalizes offsets without truncating arbitrary fractional precision', () => {
  const equal = status({ createdAt: '2024-03-01T00:00:00.1234000+01:00', updatedAt: '2024-02-29T23:00:00.1234Z' });
  assert.equal(parseStatus(equal, ID), equal);
  rejected(parseStatus, status({ createdAt: '2024-02-29T12:00:00.0000000002Z', updatedAt: '2024-02-29T12:00:00.0000000001Z' }), STATUS_ERROR);
  rejected(parseStatus, status({ createdAt: '2024-02-29T12:00:00.1Z', updatedAt: '2024-02-29T12:00:00.01Z' }), STATUS_ERROR);
  const terminal = status({ ...validStates[22], createdAt: '2024-02-29T12:00:00.001Z', terminalAt: '2024-02-29T12:00:00.002Z', updatedAt: '2024-02-29T12:00:00.003Z' });
  assert.equal(parseStatus(terminal, ID), terminal);
  for (const terminalAt of ['2024-02-29T12:00:00.0009999999Z', '2024-02-29T12:00:00.0030000001Z']) {
    rejected(parseStatus, { ...terminal, terminalAt }, STATUS_ERROR);
  }
  const differentOffsets = status({ ...validStates[22], createdAt: '2026-03-31T23:59:59.123450+02:00', terminalAt: '2026-03-31T21:59:59.123450Z', updatedAt: '2026-03-31T16:59:59.123451-05:00' });
  assert.equal(parseStatus(differentOffsets, ID), differentOffsets);
  rejected(parseStatus, { ...terminal, createdAt: '2024-02-29T12:00:00Z', terminalAt: '2024-02-29T12:00:00.100900Z', updatedAt: '2024-02-29T12:00:00.100200Z' }, STATUS_ERROR);
});

test('result accepts every required nullable field, empty collections and zero confidence', () => {
  const value = result(); assert.equal(parseResult(value, ID), value);
});
test('result preserves zero, negative finite amounts, null, whitespace and unconstrained country/currency codes', () => {
  const value = populatedResult();
  value.data.bank.name = ' ';
  value.data.account = { holder: 'Synthetic Holder', numberMasked: '****1', clabeMasked: '****1234', currency: 'ZZZ' };
  value.data.bankCountry = 'ZZ';
  value.data.balances = { opening: -10, closing: 0, totalCredits: -0, totalDebits: null };
  value.data.fees = { totalFees: -0.5, ivaOnFees: 0 };
  value.data.transactions[0] = { ...transaction(), date: '2024-02-29', amount: -5, balanceAfter: 0, category: 'nómina' };
  value.data.interestEarned = Number.MAX_VALUE;
  value.quality.overallConfidence = 100;
  assert.equal(parseResult(value, ID), value);
  assert.equal(value.data.transactions[0].amount, -5);
  assert.equal(value.data.balances.totalDebits, null);
  assert.ok(Object.is(value.data.balances.totalCredits, -0));
});

const objects = [
  [[], resultSchema], [['provenance'], resultSchema.$defs.provenance], [['data'], resultSchema.$defs.bankStatementData],
  [['data', 'bank'], resultSchema.$defs.bank], [['data', 'account'], resultSchema.$defs.account], [['data', 'statement'], resultSchema.$defs.statement],
  [['data', 'balances'], resultSchema.$defs.balances], [['data', 'transactions', 0], resultSchema.$defs.transaction], [['data', 'fees'], resultSchema.$defs.fees],
  [['warnings', 0], resultSchema.$defs.warning], [['quality'], resultSchema.$defs.quality],
];
for (const [path, schema] of objects) {
  test(`result enforces all required and closed keys at ${path.join('.') || 'root'}`, () => {
    assert.equal(schema.additionalProperties, false);
    for (const key of schema.required) {
      const value = populatedResult(); delete at(value, path)[key]; rejected(parseResult, value, RESULT_ERROR);
    }
    const value = populatedResult(); at(value, path).unexpected = 'fixture'; rejected(parseResult, value, RESULT_ERROR);
    if (path.length) for (const invalid of [undefined, null, [], 'object', 0]) {
      if (path.join('.') === 'data.fees' && invalid === null) continue;
      const wrongType = populatedResult(); setAt(wrongType, path, invalid); rejected(parseResult, wrongType, RESULT_ERROR);
    }
  });
}

const invalidResultFields = [
  [['schemaVersion'], 'wrong'], [['contractVersion'], 'wrong'], [['documentType'], 'personal'], [['resultType'], 'personal'], [['resultVersion'], '2.0'],
  [['documentId'], OTHER_ID], [['resultId'], `result_${OTHER_ID}_v1`], [['resultId'], `result_${ID}_v1\n`],
  [['provenance', 'processor'], 'ocr'], [['provenance', 'producerSchemaVersion'], '2.0'], [['provenance', 'promptVersion'], '1.0'],
  [['provenance', 'promptVersion'], '1.0.0\n'], [['provenance', 'promptVersion'], '1.0.0-'], [['provenance', 'promptVersion'], '1.0.0+hello world'],
  [['data', 'bank', 'name'], ''], [['data', 'account', 'holder'], 42], [['data', 'account', 'numberMasked'], '1234'],
  [['data', 'account', 'numberMasked'], '****'], [['data', 'account', 'numberMasked'], '****12345'], [['data', 'account', 'clabeMasked'], '****a'],
  [['data', 'account', 'numberMasked'], '****1\n'], [['data', 'account', 'currency'], 'usd'], [['data', 'account', 'currency'], 'USD\n'],
  [['data', 'accountType'], 'checking'], [['data', 'bankCountry'], 'MEX'], [['data', 'bankCountry'], 'US\n'],
  [['data', 'transactions'], null], [['data', 'transactions'], {}], [['data', 'transactions', 0, 'direction'], 'CREDIT'],
  [['data', 'transactions', 0, 'category'], 'unknown'], [['data', 'transactions', 0, 'description'], ''], [['data', 'transactions', 0, 'reference'], false],
  [['warnings'], null], [['warnings'], {}], [['warnings', 0, 'code'], 'UNKNOWN'], [['warnings', 0, 'code'], null],
  [['quality', 'overallConfidence'], -0.01], [['quality', 'overallConfidence'], 100.01], [['quality', 'overallConfidence'], '50'],
  [['quality', 'overallConfidence'], Infinity], [['quality', 'overallConfidence'], NaN], [['quality', 'overallConfidence'], null],
];
for (const [index, [path, invalid]] of invalidResultFields.entries()) {
  test(`result rejects invalid field ${index + 1}: ${path.join('.')}`, () => {
    const value = populatedResult(); setAt(value, path, invalid); rejected(parseResult, value, RESULT_ERROR);
  });
}

const amountPaths = [
  ...['opening', 'closing', 'totalCredits', 'totalDebits'].map(key => ['data', 'balances', key]),
  ...['amount', 'balanceAfter'].map(key => ['data', 'transactions', 0, key]),
  ...['totalFees', 'ivaOnFees'].map(key => ['data', 'fees', key]),
  ['data', 'interestEarned'], ['data', 'interestCharged'],
];
for (const path of amountPaths) {
  test(`finite nullable amount at ${path.join('.')}`, () => {
    for (const valid of [null, 0, -1, 0.1, Number.MIN_VALUE, Number.MAX_VALUE]) {
      const value = populatedResult(); setAt(value, path, valid); assert.equal(parseResult(value, ID), value);
    }
    for (const invalid of ['0', false, undefined, NaN, Infinity, -Infinity, {}, []]) {
      const value = populatedResult(); setAt(value, path, invalid); rejected(parseResult, value, RESULT_ERROR);
    }
  });
}

for (const path of [['data', 'bank', 'name'], ['data', 'account', 'holder'], ['data', 'transactions', 0, 'description'], ['data', 'transactions', 0, 'reference'], ['data', 'summaryText']]) {
  test(`Unicode code-point limits at ${path.join('.')}`, () => {
    for (const valid of [null, ' ', 'x'.repeat(512), '😀'.repeat(512), 'e\u0301'.repeat(256)]) {
      const value = populatedResult(); setAt(value, path, valid); assert.equal(parseResult(value, ID), value);
    }
    for (const invalid of ['', 'x'.repeat(513), '😀'.repeat(513), 'e\u0301'.repeat(256) + 'x']) {
      const value = populatedResult(); setAt(value, path, invalid); rejected(parseResult, value, RESULT_ERROR);
    }
  });
}

test('result collection and prompt-version limits are inclusive; duplicate valid warnings are allowed', () => {
  const value = result();
  value.data.transactions = Array.from({ length: 10000 }, transaction);
  value.warnings = Array.from({ length: 16 }, () => ({ code: 'LOW_CONFIDENCE' }));
  value.provenance.promptVersion = '1.0.0+' + 'x'.repeat(58);
  assert.equal(value.provenance.promptVersion.length, 64);
  assert.equal(parseResult(value, ID), value);
  value.data.transactions.push(transaction()); rejected(parseResult, value, RESULT_ERROR); value.data.transactions.pop();
  value.warnings.push({ code: 'LOW_CONFIDENCE' }); rejected(parseResult, value, RESULT_ERROR); value.warnings.pop();
  value.provenance.promptVersion += 'x'; rejected(parseResult, value, RESULT_ERROR);
});

test('all schema-defined transaction categories, warnings and account types remain valid', () => {
  for (const category of resultSchema.$defs.transaction.properties.category.enum) {
    const value = populatedResult(); value.data.transactions[0].category = category; assert.equal(parseResult(value, ID), value);
  }
  for (const code of resultSchema.$defs.warning.properties.code.enum) {
    const value = populatedResult(); value.warnings[0].code = code; assert.equal(parseResult(value, ID), value);
  }
  for (const accountType of resultSchema.$defs.bankStatementData.properties.accountType.enum) {
    const value = result(); value.data.accountType = accountType; assert.equal(parseResult(value, ID), value);
  }
});

for (const path of [['data', 'statement', 'periodStart'], ['data', 'statement', 'periodEnd'], ['data', 'transactions', 0, 'date']]) {
  test(`real nullable calendar date at ${path.join('.')}`, () => {
    for (const valid of [null, '0001-01-01', '0099-12-31', '2000-02-29', '2024-02-29', '9999-12-31']) {
      const value = populatedResult(); setAt(value, path, valid); assert.equal(parseResult(value, ID), value);
    }
    for (const invalid of ['0000-01-01', '10000-01-01', '2025-02-29', '1900-02-29', '2024-04-31', '2024-13-01', '2024-01-00', '2024-02-29\n', '2024-2-29', TIME, '', false]) {
      const value = populatedResult(); setAt(value, path, invalid); rejected(parseResult, value, RESULT_ERROR);
    }
  });
}
test('period ordering is enforced without inventing balance or transaction-period restrictions', () => {
  const value = populatedResult(); value.data.statement = { periodStart: '2024-02-29', periodEnd: '2024-02-29' };
  value.data.transactions[0].date = '2025-01-01';
  value.data.balances = { opening: 1, closing: 999, totalCredits: 0, totalDebits: 0 };
  assert.equal(parseResult(value, ID), value);
  value.data.statement.periodEnd = '2024-02-28'; rejected(parseResult, value, RESULT_ERROR);
});

for (const [parser, factory, message] of [[parseStatus, status, STATUS_ERROR], [parseResult, result, RESULT_ERROR]]) {
  test(`${message}: non-records, incomplete objects and invalid expected IDs fail with fixed errors`, () => {
    for (const input of [null, undefined, [], 'synthetic input must not be echoed', 0, false, new Date(), new Map(), { documentId: ID }]) rejected(parser, input, message);
    for (const id of ['', 'a'.repeat(31), ID.toUpperCase(), ID + '\n', null, undefined, 123]) rejected(parser, factory(), message, id);
  });
  test(`${message}: rejects accessors/inherited fields without evaluating values`, () => {
    let reads = 0;
    const value = factory(); Object.defineProperty(value, 'documentId', { enumerable: true, get() { reads++; throw new Error('must not escape'); } });
    rejected(parser, value, message); assert.equal(reads, 0);
    rejected(parser, Object.create(factory()), message);
    const symbolValue = factory(); symbolValue[Symbol('extra')] = true; rejected(parser, symbolValue, message);
    const hiddenValue = factory(); Object.defineProperty(hiddenValue, 'extra', { value: true }); rejected(parser, hiddenValue, message);
  });
  test(`${message}: accepts frozen and null-prototype JSON records without mutation`, () => {
    function freeze(value) { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; }
    const value = freeze(factory()); const before = JSON.stringify(value); assert.equal(parser(value, ID), value); assert.equal(JSON.stringify(value), before);
    const nullPrototype = Object.assign(Object.create(null), factory()); assert.equal(parser(nullPrototype, ID), nullPrototype);
  });
}
