import assert from 'node:assert/strict';
import test from 'node:test';

import {
  BrowserBoundaryError,
  csvCell,
  requireHttpsUrl,
  safeDownloadFilename,
} from '../../src/security/browserBoundaries.js';

test('accepts credential-free HTTPS URLs and preserves signed query data', () => {
  assert.equal(
    requireHttpsUrl('https://objects.synthetic.invalid/key?signature=synthetic'),
    'https://objects.synthetic.invalid/key?signature=synthetic',
  );
});

for (const candidate of [
  'http://objects.synthetic.invalid/key',
  'javascript:alert(1)',
  'data:text/html,synthetic',
  'https://user:password@objects.synthetic.invalid/key',
  '',
]) {
  test(`rejects unsafe external URL: ${candidate || 'empty'}`, () => {
    assert.throws(() => requireHttpsUrl(candidate), BrowserBoundaryError);
  });
}

test('quotes CSV cells and neutralizes spreadsheet formulas after leading whitespace', () => {
  assert.equal(
    csvCell('=HYPERLINK("https://synthetic.invalid")'),
    '"\'=HYPERLINK(""https://synthetic.invalid"")"',
  );
  assert.equal(csvCell('  +1+1'), '"\'  +1+1"');
  assert.equal(csvCell('synthetic,"quoted"'), '"synthetic,""quoted"""');
});

test('sanitizes untrusted download filenames and rejects traversal-only names', () => {
  assert.equal(safeDownloadFilename('../../sensitive.csv', 'export.csv'), '_.._sensitive.csv');
  assert.equal(safeDownloadFilename('á report.csv', 'export.csv'), 'a_report.csv');
  assert.equal(safeDownloadFilename('...', 'export.csv'), 'export.csv');
});
