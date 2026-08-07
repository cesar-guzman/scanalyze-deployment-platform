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

test('removes only the exact same-origin API prefix', () => {
  assert.equal(rewrite('/api'), '/');
  assert.equal(rewrite('/api/'), '/');
  assert.equal(rewrite('/api/documents'), '/documents');
  assert.equal(rewrite('/api/documents/item'), '/documents/item');
  assert.equal(rewrite('/apix/documents'), '/apix/documents');
});
