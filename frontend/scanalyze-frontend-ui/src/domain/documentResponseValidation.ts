import {
  BANK_STATEMENT_TRANSACTION_CATEGORIES,
  BANK_STATEMENT_WARNING_CODES,
  DOCUMENT_FAILURE_DISPOSITIONS,
  DOCUMENT_JOURNEY_CONTRACT_VERSION,
  DOCUMENT_LIFECYCLES,
  DOCUMENT_PIPELINE_STAGES,
  DOCUMENT_PROCESSING_CONDITIONS,
  DOCUMENT_SAFE_FAILURE_CODES,
  DOCUMENT_STAGE_STATES,
  type BankStatementData,
  type BankStatementResult,
  type DocumentStatusResponseV2,
} from '../contracts/documentJourney.v1';

type RecordValue = Record<string, unknown>;
type Instant = { seconds: number; fraction: string };

function requireValid(condition: unknown): asserts condition {
  if (!condition) throw new Error('Invalid response');
}

// Only JSON records are accepted. No accessors are evaluated and no input is mutated.
function closedRecord(value: unknown, required: readonly string[], optional: readonly string[] = []): RecordValue {
  requireValid(typeof value === 'object' && value !== null && !Array.isArray(value));
  const prototype: unknown = Object.getPrototypeOf(value);
  requireValid(prototype === Object.prototype || prototype === null);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const allowed = new Set([...required, ...optional]);
  for (const key of Reflect.ownKeys(value)) {
    requireValid(typeof key === 'string' && allowed.has(key));
    const descriptor = descriptors[key];
    requireValid(descriptor?.enumerable && Object.hasOwn(descriptor, 'value'));
  }
  for (const key of required) requireValid(Object.hasOwn(descriptors, key));
  return value as RecordValue;
}

const present = (value: RecordValue, key: string) => Object.hasOwn(value, key);
const oneOf = (value: unknown, values: readonly string[]) => typeof value === 'string' && values.includes(value);
const finiteNumber = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value);
const nullableAmount = (value: unknown) => value === null || finiteNumber(value);

function matches(value: unknown, pattern: RegExp): value is string {
  if (typeof value !== 'string') return false;
  // JavaScript's $ also matches before a final newline; require the entire value.
  return pattern.exec(value)?.[0] === value;
}

function boundedString(value: unknown, minimum: number, maximum: number): value is string {
  if (typeof value !== 'string') return false;
  let length = 0;
  for (let index = 0; index < value.length;) {
    index += (value.codePointAt(index) ?? 0) > 0xffff ? 2 : 1;
    length += 1;
    if (length > maximum) return false;
  }
  return length >= minimum;
}

const nullableString = (value: unknown) => value === null || boundedString(value, 1, 512);
const documentId = (value: unknown) => matches(value, /^[0-9a-f]{32}$/);
const nullableMask = (value: unknown) => value === null || matches(value, /^\*{4}[0-9]{1,4}$/);

function validCalendarDate(year: number, month: number, day: number): boolean {
  if (year < 1 || year > 9999 || month < 1 || month > 12 || day < 1) return false;
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day <= days[month - 1];
}

function calendarDate(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  return match?.[0] === value && validCalendarDate(Number(match[1]), Number(match[2]), Number(match[3]));
}

// RFC3339 timezone syntax, with the public backend's real-calendar/year/second
// limits. Fractions remain strings so sub-millisecond ordering is never rounded.
function instant(value: unknown): Instant {
  requireValid(typeof value === 'string');
  const match = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([Zz]|([+-])(\d{2}):(\d{2}))$/.exec(value);
  requireValid(match !== null && match[0] === value);
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, fraction = '', zone, sign, offsetHourText, offsetMinuteText] = match;
  const [year, month, day, hour, minute, second] = [yearText, monthText, dayText, hourText, minuteText, secondText].map(Number);
  requireValid(validCalendarDate(year, month, day) && hour <= 23 && minute <= 59 && second <= 59);
  let offsetMinutes = 0;
  if (zone.toUpperCase() !== 'Z') {
    const offsetHour = Number(offsetHourText);
    const offsetMinute = Number(offsetMinuteText);
    requireValid(offsetHour <= 23 && offsetMinute <= 59);
    offsetMinutes = (offsetHour * 60 + offsetMinute) * (sign === '-' ? -1 : 1);
  }
  const date = new Date(0);
  // setUTCFullYear avoids Date.UTC's special interpretation of years 00 through 99.
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, second, 0);
  return { seconds: date.getTime() / 1000 - offsetMinutes * 60, fraction: fraction.replace(/0+$/, '') };
}

function atOrBefore(left: Instant, right: Instant): boolean {
  if (left.seconds !== right.seconds) return left.seconds < right.seconds;
  const width = Math.max(left.fraction.length, right.fraction.length);
  return left.fraction.padEnd(width, '0') <= right.fraction.padEnd(width, '0');
}

function validateProgress(value: unknown): void {
  const progress = closedRecord(value, [], ['attempt', 'completedStages', 'totalStages']);
  for (const [key, minimum, maximum] of [
    ['attempt', 0, 1000], ['completedStages', 0, 10], ['totalStages', 1, 10],
  ] as const) {
    if (present(progress, key)) {
      const count = progress[key];
      requireValid(typeof count === 'number' && Number.isInteger(count) && count >= minimum && count <= maximum);
    }
  }
  if (present(progress, 'completedStages') && present(progress, 'totalStages')) {
    requireValid((progress.completedStages as number) <= (progress.totalStages as number));
  }
}

function validateStatus(value: unknown, expectedDocumentId: string): DocumentStatusResponseV2 {
  const status = closedRecord(value, [
    'schemaVersion', 'contractVersion', 'documentId', 'lifecycle', 'currentStage',
    'stageState', 'processingCondition', 'createdAt', 'updatedAt',
  ], ['batchId', 'terminalAt', 'correlationReference', 'progress', 'failureDisposition', 'safeFailureCode']);
  requireValid(documentId(expectedDocumentId) && status.documentId === expectedDocumentId);
  requireValid(status.schemaVersion === 'scanalyze.document-status.v1' && status.contractVersion === DOCUMENT_JOURNEY_CONTRACT_VERSION);
  requireValid(oneOf(status.lifecycle, DOCUMENT_LIFECYCLES));
  requireValid(oneOf(status.currentStage, DOCUMENT_PIPELINE_STAGES));
  requireValid(oneOf(status.stageState, DOCUMENT_STAGE_STATES));
  requireValid(oneOf(status.processingCondition, DOCUMENT_PROCESSING_CONDITIONS));
  if (present(status, 'batchId')) requireValid(documentId(status.batchId));
  if (present(status, 'correlationReference')) {
    requireValid(matches(status.correlationReference, /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/));
  }
  if (present(status, 'progress')) validateProgress(status.progress);
  if (present(status, 'failureDisposition')) requireValid(oneOf(status.failureDisposition, DOCUMENT_FAILURE_DISPOSITIONS));
  if (present(status, 'safeFailureCode')) requireValid(oneOf(status.safeFailureCode, DOCUMENT_SAFE_FAILURE_CODES));

  const created = instant(status.createdAt);
  const updated = instant(status.updatedAt);
  requireValid(atOrBefore(created, updated));
  const terminal = present(status, 'terminalAt');
  const failure = present(status, 'failureDisposition');
  const failureCode = present(status, 'safeFailureCode');
  if (terminal) {
    const ended = instant(status.terminalAt);
    requireValid(atOrBefore(created, ended) && atOrBefore(ended, updated));
  }
  switch (status.lifecycle) {
    case 'UPLOAD_PENDING':
      requireValid(status.currentStage === 'INGEST' && status.stageState === 'PENDING' && status.processingCondition === 'ACTIVE');
      requireValid(!terminal && !failure && !failureCode);
      break;
    case 'SUBMITTED':
      requireValid(status.currentStage === 'INGEST' && !terminal);
      if (status.stageState === 'FAILED') {
        requireValid(status.processingCondition === 'NOT_APPLICABLE' && status.failureDisposition === 'RETRYABLE' && status.safeFailureCode === 'ENQUEUE_FAILED');
      } else {
        requireValid(oneOf(status.stageState, ['PENDING', 'RUNNING']) && status.processingCondition === 'ACTIVE');
        requireValid(!failure && !failureCode);
      }
      break;
    case 'PROCESSING':
      requireValid(status.currentStage !== 'TERMINAL' && oneOf(status.stageState, ['PENDING', 'RUNNING', 'SUCCEEDED']) && status.processingCondition === 'ACTIVE');
      requireValid(!terminal && !failure && !failureCode);
      break;
    case 'COMPLETED':
      requireValid(status.currentStage === 'TERMINAL' && status.stageState === 'SUCCEEDED' && status.processingCondition === 'NOT_APPLICABLE');
      requireValid(terminal && !failure && !failureCode);
      break;
    case 'FAILED':
      requireValid(status.currentStage === 'TERMINAL' && status.stageState === 'FAILED' && status.processingCondition === 'NOT_APPLICABLE');
      requireValid(terminal && status.failureDisposition === 'TERMINAL' && oneOf(status.safeFailureCode, ['DOCUMENT_PROCESSING_FAILED', 'OCR_FAILED']));
      break;
  }
  return value as DocumentStatusResponseV2;
}

function validateBankData(value: unknown): void {
  const data = closedRecord(value, ['bank', 'account', 'statement', 'balances', 'transactions', 'accountType', 'bankCountry', 'fees', 'interestEarned', 'interestCharged', 'summaryText']);
  const bank = closedRecord(data.bank, ['name']);
  requireValid(nullableString(bank.name));
  const account = closedRecord(data.account, ['holder', 'numberMasked', 'clabeMasked', 'currency']);
  requireValid(nullableString(account.holder) && nullableMask(account.numberMasked) && nullableMask(account.clabeMasked));
  requireValid(account.currency === null || matches(account.currency, /^[A-Z]{3}$/));
  const statement = closedRecord(data.statement, ['periodStart', 'periodEnd']);
  requireValid(statement.periodStart === null || calendarDate(statement.periodStart));
  requireValid(statement.periodEnd === null || calendarDate(statement.periodEnd));
  if (typeof statement.periodStart === 'string' && typeof statement.periodEnd === 'string') {
    requireValid(statement.periodStart <= statement.periodEnd);
  }
  const balances = closedRecord(data.balances, ['opening', 'closing', 'totalCredits', 'totalDebits']);
  for (const amount of Object.values(balances)) requireValid(nullableAmount(amount));
  requireValid(Array.isArray(data.transactions) && data.transactions.length <= 10000);
  for (const transaction of data.transactions) {
    const item = closedRecord(transaction, ['date', 'description', 'reference', 'direction', 'amount', 'balanceAfter', 'category']);
    requireValid(item.date === null || calendarDate(item.date));
    requireValid(nullableString(item.description) && nullableString(item.reference));
    requireValid(oneOf(item.direction, ['credit', 'debit']));
    requireValid(nullableAmount(item.amount) && nullableAmount(item.balanceAfter));
    requireValid(item.category === null || oneOf(item.category, BANK_STATEMENT_TRANSACTION_CATEGORIES));
  }
  const accountTypes = ['cheques', 'ahorro', 'crédito', 'inversión', 'nómina'] as const satisfies readonly NonNullable<BankStatementData['accountType']>[];
  requireValid(data.accountType === null || oneOf(data.accountType, accountTypes));
  requireValid(data.bankCountry === null || matches(data.bankCountry, /^[A-Z]{2}$/));
  if (data.fees !== null) {
    const fees = closedRecord(data.fees, ['totalFees', 'ivaOnFees']);
    requireValid(nullableAmount(fees.totalFees) && nullableAmount(fees.ivaOnFees));
  }
  requireValid(nullableAmount(data.interestEarned) && nullableAmount(data.interestCharged) && nullableString(data.summaryText));
}

function validateResult(value: unknown, expectedDocumentId: string): BankStatementResult {
  const result = closedRecord(value, ['schemaVersion', 'contractVersion', 'documentType', 'resultType', 'documentId', 'resultId', 'resultVersion', 'provenance', 'data', 'warnings', 'quality']);
  requireValid(documentId(expectedDocumentId) && result.documentId === expectedDocumentId && result.resultId === `result_${expectedDocumentId}_v1`);
  requireValid(result.schemaVersion === 'scanalyze.document-result.v1' && result.contractVersion === DOCUMENT_JOURNEY_CONTRACT_VERSION);
  requireValid(result.documentType === 'bank_statement' && result.resultType === 'bank_statement' && result.resultVersion === '1.0');
  const provenance = closedRecord(result.provenance, ['processor', 'producerSchemaVersion', 'promptVersion', 'generatedAt']);
  requireValid(provenance.processor === 'bank-extract' && provenance.producerSchemaVersion === '1.0');
  requireValid(boundedString(provenance.promptVersion, 1, 64) && matches(provenance.promptVersion, /^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$/));
  instant(provenance.generatedAt);
  validateBankData(result.data);
  requireValid(Array.isArray(result.warnings) && result.warnings.length <= 16);
  for (const warning of result.warnings) {
    const item = closedRecord(warning, ['code']);
    requireValid(oneOf(item.code, BANK_STATEMENT_WARNING_CODES));
  }
  const quality = closedRecord(result.quality, ['overallConfidence']);
  requireValid(finiteNumber(quality.overallConfidence) && quality.overallConfidence >= 0 && quality.overallConfidence <= 100);
  return value as BankStatementResult;
}

export function parseDocumentStatusResponse(value: unknown, expectedDocumentId: string): DocumentStatusResponseV2 {
  try {
    return validateStatus(value, expectedDocumentId);
  } catch {
    throw Object.assign(new Error('La respuesta de estado del documento no es válida.'), { code: 'DOCUMENT_STATUS_RESPONSE_INVALID' });
  }
}

export function parseDocumentResultResponse(value: unknown, expectedDocumentId: string): BankStatementResult {
  try {
    return validateResult(value, expectedDocumentId);
  } catch {
    throw Object.assign(new Error('La respuesta de resultado del documento no es válida.'), { code: 'DOCUMENT_RESULT_RESPONSE_INVALID' });
  }
}
