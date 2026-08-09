import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';

const source = readFileSync(
  new URL('../../../../modules/edge/api_path_rewrite.js', import.meta.url),
  'utf8',
);
const context = {};
vm.runInNewContext(`${source}\nthis.rewriteApiPath = handler;`, context);

const rewrite = (uri) => {
  const request = {
    uri,
    method: 'POST',
    querystring: { page: { value: '2' } },
    headers: { authorization: { value: 'synthetic-redacted' } },
  };
  const stableFields = JSON.stringify({
    method: request.method,
    querystring: request.querystring,
    headers: request.headers,
  });
  const result = context.rewriteApiPath({ request });
  assert.equal(
    JSON.stringify({
      method: result.method,
      querystring: result.querystring,
      headers: result.headers,
    }),
    stableFields,
  );
  return result.uri;
};

test('maps the historical facade to v1 and preserves the explicit v2 namespace', () => {
  assert.equal(rewrite('/api'), '/api/v1');
  assert.equal(rewrite('/api/'), '/api/v1/');
  assert.equal(rewrite('/api/documents'), '/api/v1/documents');
  assert.equal(rewrite('/api/documents/item'), '/api/v1/documents/item');
  assert.equal(rewrite('/api/v2'), '/api/v2');
  assert.equal(rewrite('/api/v2/documents'), '/api/v2/documents');
  assert.equal(rewrite('/apix/documents'), '/apix/documents');
});
