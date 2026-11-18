// Frontend dependency audit gate (`npm run audit`).
//
// `npm audit --audit-level=low` stays the source of truth. This gate adds one
// narrow, time-boxed path for advisories that have no fixed release yet:
//
// - Production dependencies get no exceptions: `npm audit --omit=dev` must
//   report no advisory at all.
// - The full tree may report only advisories listed in audit-exceptions.json.
//   Each entry names one GitHub advisory and one package, covers development
//   dependencies only, and lasts at most MAX_EXCEPTION_DAYS from the day it was
//   granted. An expired entry fails the gate.
// - Any other advisory, an npm error or an unreadable report fails the gate.
//
// Policy and current exceptions: docs/security/frontend-audit-exceptions.md.

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const MAX_EXCEPTION_DAYS = 30;
export const AUDIT_ARGS = ['audit', '--json', '--audit-level=low'];

const DAY_MS = 24 * 60 * 60 * 1000;
const ADVISORY_ID = /^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$/;
const ADVISORY_URL = /^https:\/\/github\.com\/advisories\/(GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})$/;
const PACKAGE_NAME = /^(@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/;
const COUNTED_SEVERITIES = new Set(['low', 'moderate', 'high', 'critical']);
const DOCUMENT_KEYS = ['exceptions', 'schema_version'];
const EXCEPTION_KEYS = ['advisory', 'expires', 'granted', 'package', 'reason', 'scope'];

export class AuditGateError extends Error {}

function hasExactKeys(value, keys) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify(keys)
  );
}

function parseDay(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return null;
  const time = Date.parse(`${value}T00:00:00Z`);
  if (Number.isNaN(time) || new Date(time).toISOString().slice(0, 10) !== value) return null;
  return time;
}

export function utcToday(now = new Date()) {
  return now.toISOString().slice(0, 10);
}

// Returns the usable exceptions and every problem found. An entry with any
// problem is left out, so the advisory it names fails the audit as well.
export function validateExceptions(document, today) {
  const todayTime = parseDay(today);
  if (todayTime === null) throw new AuditGateError(`invalid date for today: ${today}`);
  if (
    !hasExactKeys(document, DOCUMENT_KEYS) ||
    document.schema_version !== 1 ||
    !Array.isArray(document.exceptions)
  ) {
    return {
      exceptions: [],
      errors: ['audit-exceptions.json must be {"schema_version": 1, "exceptions": [...]}'],
    };
  }

  const exceptions = [];
  const errors = [];
  const seen = new Set();
  document.exceptions.forEach((entry, index) => {
    const where = `exception ${index + 1}`;
    if (!hasExactKeys(entry, EXCEPTION_KEYS)) {
      errors.push(`${where}: keys must be exactly ${EXCEPTION_KEYS.join(', ')}`);
      return;
    }

    const problems = [];
    if (typeof entry.advisory !== 'string' || !ADVISORY_ID.test(entry.advisory)) {
      problems.push('advisory must be a GitHub advisory ID (GHSA-xxxx-xxxx-xxxx)');
    }
    if (typeof entry.package !== 'string' || !PACKAGE_NAME.test(entry.package)) {
      problems.push('package must be an npm package name');
    }
    if (entry.scope !== 'development') {
      problems.push('scope must be "development"; production dependencies get no exceptions');
    }
    if (typeof entry.reason !== 'string' || entry.reason.trim().length < 20) {
      problems.push('reason must explain the exception');
    }
    const granted = parseDay(entry.granted);
    const expires = parseDay(entry.expires);
    if (granted === null) problems.push('granted must be a YYYY-MM-DD date');
    if (expires === null) problems.push('expires must be a YYYY-MM-DD date');
    if (granted !== null && expires !== null) {
      const days = (expires - granted) / DAY_MS;
      if (granted > todayTime) problems.push(`granted ${entry.granted} is in the future`);
      if (days < 0 || days > MAX_EXCEPTION_DAYS) {
        problems.push(`expires must be 0 to ${MAX_EXCEPTION_DAYS} days after granted (got ${days})`);
      }
      if (expires < todayTime) {
        problems.push(`expired on ${entry.expires}; fix the dependency or renew the exception through review`);
      }
    }
    const key = `${entry.advisory} ${entry.package}`;
    if (seen.has(key)) problems.push('duplicate advisory and package');
    seen.add(key);

    if (problems.length > 0) {
      errors.push(...problems.map((problem) => `${where} (${entry.advisory} ${entry.package}): ${problem}`));
      return;
    }
    exceptions.push(entry);
  });
  return { exceptions, errors };
}

// Lists the advisories in an `npm audit --json` report (auditReportVersion 2).
// Fails closed on npm errors and on reports it cannot read.
export function collectAdvisories(report, label) {
  if (report === null || typeof report !== 'object' || Array.isArray(report)) {
    throw new AuditGateError(`${label}: npm audit did not return a JSON object`);
  }
  if (report.error) {
    const detail = report.error.summary || report.error.code || 'unknown error';
    throw new AuditGateError(`${label}: npm audit failed: ${detail}`);
  }
  if (
    report.auditReportVersion !== 2 ||
    report.vulnerabilities === null ||
    typeof report.vulnerabilities !== 'object'
  ) {
    throw new AuditGateError(`${label}: expected an npm audit report with auditReportVersion 2`);
  }

  const advisories = new Map();
  for (const [name, entry] of Object.entries(report.vulnerabilities)) {
    if (entry === null || typeof entry !== 'object' || !Array.isArray(entry.via)) {
      throw new AuditGateError(`${label}: malformed entry for ${name}`);
    }
    for (const via of entry.via) {
      // A string names another vulnerable package; this one is affected only through it.
      if (typeof via === 'string') continue;
      if (via === null || typeof via !== 'object') {
        throw new AuditGateError(`${label}: malformed advisory under ${name}`);
      }
      if (!COUNTED_SEVERITIES.has(via.severity)) continue;
      const match = typeof via.url === 'string' ? ADVISORY_URL.exec(via.url) : null;
      const id = match ? match[1] : `npm advisory ${via.source ?? via.url ?? '(no id)'}`;
      const pkg = typeof via.name === 'string' ? via.name : name;
      advisories.set(`${id} ${pkg}`, { id, package: pkg, severity: via.severity, title: via.title ?? '' });
    }
  }

  const counted = Object.entries(report.metadata?.vulnerabilities ?? {})
    .filter(([severity]) => COUNTED_SEVERITIES.has(severity))
    .reduce((sum, [, count]) => sum + (Number(count) || 0), 0);
  if (counted > 0 && advisories.size === 0) {
    throw new AuditGateError(`${label}: npm audit counted ${counted} vulnerabilities but listed no advisory`);
  }
  return [...advisories.values()];
}

export function evaluateAudit({ fullReport, productionReport, exceptions }) {
  const errors = [];
  const warnings = [];
  const excepted = [];

  for (const advisory of collectAdvisories(productionReport, 'production audit (--omit=dev)')) {
    errors.push(
      `${advisory.id} in production dependencies (${advisory.package}, ${advisory.severity}): no exception applies`,
    );
  }

  const granted = new Map(exceptions.map((entry) => [`${entry.advisory} ${entry.package}`, entry]));
  const matched = new Set();
  for (const advisory of collectAdvisories(fullReport, 'full audit')) {
    const key = `${advisory.id} ${advisory.package}`;
    const entry = granted.get(key);
    if (!entry) {
      errors.push(`${advisory.id} (${advisory.package}, ${advisory.severity}) has no exception: ${advisory.title}`);
      continue;
    }
    matched.add(key);
    excepted.push({ ...advisory, expires: entry.expires });
  }

  for (const [key, entry] of granted) {
    if (!matched.has(key)) {
      warnings.push(`${entry.advisory} (${entry.package}) no longer appears in the audit; remove its exception`);
    }
  }
  return { errors, warnings, excepted };
}

function runAudit(cwd, extraArgs) {
  const args = [...AUDIT_ARGS, ...extraArgs];
  const result = spawnSync('npm', args, { cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (result.error) throw new AuditGateError(`could not run npm audit: ${result.error.message}`);
  // npm audit exits 1 whenever it finds an advisory; the JSON report decides.
  try {
    return JSON.parse(result.stdout);
  } catch {
    const stderr = (result.stderr || '').trim().split('\n').slice(-5).join('\n');
    throw new AuditGateError(`npm ${args.join(' ')} printed no JSON report (exit ${result.status}): ${stderr}`);
  }
}

export function main({
  cwd = join(dirname(fileURLToPath(import.meta.url)), '..'),
  today = utcToday(),
  log = console.log,
  error = console.error,
} = {}) {
  try {
    const document = JSON.parse(readFileSync(join(cwd, 'audit-exceptions.json'), 'utf8'));
    const checked = validateExceptions(document, today);
    const result = evaluateAudit({
      fullReport: runAudit(cwd, []),
      productionReport: runAudit(cwd, ['--omit=dev']),
      exceptions: checked.exceptions,
    });

    for (const warning of result.warnings) error(`audit gate warning: ${warning}`);
    const errors = [...checked.errors, ...result.errors];
    if (errors.length > 0) {
      for (const message of errors) error(`audit gate: ${message}`);
      error(`audit gate: FAILED (${errors.length} problem${errors.length === 1 ? '' : 's'})`);
      return 1;
    }

    for (const advisory of result.excepted) {
      log(
        `audit gate: ${advisory.id} (${advisory.package}, ${advisory.severity}) allowed in development dependencies until ${advisory.expires}`,
      );
    }
    log('audit gate: passed. No advisory in production dependencies and none outside the listed exceptions.');
    return 0;
  } catch (failure) {
    error(`audit gate: FAILED: ${failure.message}`);
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = main();
}
