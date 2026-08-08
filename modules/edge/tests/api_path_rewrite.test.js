const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync(
  path.join(__dirname, "..", "api_path_rewrite.js"),
  "utf8",
);
const authorizationFixture = fs.readFileSync(
  path.join(
    __dirname,
    "..",
    "..",
    "edge-identity",
    "tests",
    "api_authorization.tftest.hcl",
  ),
  "utf8",
);
const apiGatewaySource = fs.readFileSync(
  path.join(__dirname, "..", "..", "edge-identity", "api_gateway.tf"),
  "utf8",
);
const context = {};
vm.runInNewContext(source, context, { filename: "api_path_rewrite.js" });

function rewrite(uri) {
  return context.handler({ request: { uri, headers: {} } }).uri;
}

function parseAuthorizationRoutes(fixture) {
  const marker = "api_authorization_routes = {";
  const markerIndex = fixture.indexOf(marker);
  assert.notEqual(markerIndex, -1, "authorization route fixture is missing");

  const bodyStart = markerIndex + marker.length;
  let depth = 1;
  let bodyEnd = -1;
  for (let index = bodyStart; index < fixture.length; index += 1) {
    if (fixture[index] === "{") {
      depth += 1;
    } else if (fixture[index] === "}") {
      depth -= 1;
      if (depth === 0) {
        bodyEnd = index;
        break;
      }
    }
  }
  assert.notEqual(bodyEnd, -1, "authorization route fixture is unterminated");

  const routes = new Map();
  const routePattern = /^\s*"([^"]+)"\s*=\s*\[\s*"([^"]+)"\s*,?\s*\]/gm;
  const body = fixture.slice(bodyStart, bodyEnd);
  for (const match of body.matchAll(routePattern)) {
    assert.equal(routes.has(match[1]), false, `duplicate route ${match[1]}`);
    routes.set(match[1], match[2]);
  }
  assert.notEqual(routes.size, 0, "authorization route fixture is empty");
  return routes;
}

const authorizationRoutes = parseAuthorizationRoutes(authorizationFixture);

test("preserves the canonical v2 namespace", () => {
  assert.equal(rewrite("/api/v2"), "/api/v2");
  assert.equal(rewrite("/api/v2/documents"), "/api/v2/documents");
});

test("maps only the historical same-origin facade to canonical v1", () => {
  assert.equal(rewrite("/api"), "/api/v1");
  assert.equal(rewrite("/api/"), "/api/v1/");
  assert.equal(rewrite("/api/documents"), "/api/v1/documents");
});

test("does not rewrite unrelated paths or v2 lookalikes", () => {
  assert.equal(rewrite("/assets/app.js"), "/assets/app.js");
  assert.equal(rewrite("/api-v2/documents"), "/api-v2/documents");
});

test("composes edge outputs with explicit JWT-protected API Gateway routes", () => {
  const cases = [
    ["GET", "/api/documents", "scanalyze.api.v1/read"],
    ["POST", "/api/documents", "scanalyze.api.v1/write"],
    ["POST", "/api/batches/{batch_id}/export", "scanalyze.api.v1/admin"],
    ["GET", "/api/v2/documents/{documentId}", "scanalyze.api.v1/read"],
    ["GET", "/api/v2/documents/{documentId}/result", "scanalyze.api.v1/read"],
    ["POST", "/api/v2/batches", "scanalyze.api.v1/write"],
    ["POST", "/api/v2/documents", "scanalyze.api.v1/write"],
    [
      "POST",
      "/api/v2/documents/{documentId}/submit",
      "scanalyze.api.v1/write",
    ],
    [
      "POST",
      "/api/v2/documents/{documentId}/upload-capabilities",
      "scanalyze.api.v1/write",
    ],
    [
      "POST",
      "/api/v2/operations/{operation}/reconciliation",
      "scanalyze.api.v1/write",
    ],
  ];

  for (const [method, facadeUri, scope] of cases) {
    const routeKey = `${method} ${rewrite(facadeUri)}`;
    assert.equal(
      authorizationRoutes.get(routeKey),
      scope,
      `${facadeUri} must compose to protected route ${routeKey}`,
    );
  }
  assert.equal(
    [...authorizationRoutes.keys()].filter((routeKey) =>
      routeKey.includes(" /api/v2/"),
    ).length,
    7,
    "the synthetic fixture must expose exactly the seven reviewed v2 routes",
  );

  const protectedRouteResource = apiGatewaySource.match(
    /resource\s+"aws_apigatewayv2_route"\s+"protected"\s*\{([\s\S]*?)\n\}/,
  );
  assert.ok(protectedRouteResource, "protected API Gateway route is missing");
  assert.match(
    protectedRouteResource[1],
    /for_each\s*=\s*var\.api_authorization_routes/,
  );
  assert.match(protectedRouteResource[1], /authorization_type\s*=\s*"JWT"/);
  assert.match(protectedRouteResource[1], /authorization_scopes\s*=\s*each\.value/);
});
