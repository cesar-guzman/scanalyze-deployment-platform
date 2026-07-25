# GUG-124 Threat Model Delta — Archive URI Digest Binding

> **Status**: DRAFT  
> **Date**: 2026-07-25  
> **Scope**: Release policy gate — archive artifact URI canonicalization  
> **ADR**: ADR-007, ADR-032  

---

## 1. Vulnerability Summary

The release policy gate's archive artifact verification used unsafe substring
matching (`digest_hex in artifact_uri`) to verify that an archive artifact's
content-addressed URI contained the expected digest. This permits digest
smuggling: an attacker who controls an artifact filename or parent path can
embed the expected digest string in a non-authoritative position while the
canonical `/sha256/<digest>/` path segment contains a different (attacker-
controlled) digest.

**Severity**: P0 — supply-chain authorization boundary bypass.

---

## 2. Required Invariant

An archive URI is authorized **only** when the digest extracted from the exact
canonical `/sha256/<64-lowercase-hex>/` path segment equals `artifact.digest`.

A matching digest in a filename, query parameter, fragment, or unrelated parent
path segment provides **no authority**.

---

## 3. Threat Vectors Analyzed

| # | Attack vector | Disposition | Control |
|---|---|---|---|
| 1 | Digest in filename (`frontend-<A>.zip`) | **Rejected** | Segment-based parsing; digest only from canonical marker |
| 2 | Digest in unrelated parent path | **Rejected** | Only `/sha256/<hex>/` marker is authoritative |
| 3 | Two `/sha256/<digest>/` pairs (ambiguity) | **Rejected** | Exactly one marker required; ambiguity fails closed |
| 4 | Expected digest in first pair, different in second | **Rejected** | Multiple markers fail closed regardless of order |
| 5 | Malformed or unsupported URI scheme | **Rejected** | Only `s3` and `https` accepted |
| 6 | Uppercase hex digest | **Rejected** | Exact lowercase `[a-f0-9]{64}` match required |
| 7 | Truncated digest (<64 chars) | **Rejected** | Exact 64-char regex validation |
| 8 | Overlong digest (>64 chars) | **Rejected** | Exact 64-char regex validation |
| 9 | Non-hex digest characters | **Rejected** | Hex-only regex validation |
| 10 | Empty path after digest | **Rejected** | At least one artifact path segment required |
| 11 | Redundant slashes | **Rejected** | Non-empty segment splitting eliminates empty segments |
| 12 | Percent-encoded path separators | **Rejected** | `%2F` is not a path separator after `urlsplit` |
| 13 | Query string smuggling | **Rejected** | URIs with query parameters fail closed |
| 14 | Fragment-based smuggling | **Rejected** | URIs with fragments fail closed |
| 15 | Unicode/homoglyph around `sha256` | **Rejected** | Exact string `"sha256"` comparison |
| 16 | Valid S3 content URIs | **Preserved** | Positive tests confirm acceptance |
| 17 | Valid HTTPS content URIs | **Preserved** | Positive tests confirm acceptance |
| 18 | OCI container `@sha256:` parsing | **Unchanged** | Container path is separate; not affected |

---

## 4. Schema vs. Verifier Boundary

- The JSON schema (`release.v1.schema.json`) enforces structural constraints
  on individual fields (digest format, URI presence).
- **Cross-field equality** (`uri.canonical_digest == artifact.digest`) is a
  semantic constraint that cannot be expressed in JSON Schema.
- The policy gate (`release_policy_gate.py`) enforces this semantic constraint.
- Schema validation and semantic cross-field validation are separate controls.
- No schema version change is required for this fix.

---

## 5. Evidence Boundaries

| Evidence class | Status |
|---|---|
| Documented | YES — this document |
| Implemented | YES — `tooling/release_policy_gate.py` |
| Locally validated | YES — pytest offline |
| CI validated | PENDING — requires PR CI run |
| Merged | NO |
| Main verified | NO |
| Live read-only validated | NO — GUG-125 scope |
| Live mutation validated | NO — GUG-125 scope |
| Production | NO-GO |

---

## 6. Residual Risks

1. **Live registry copy and destination digest readback** — not validated here;
   requires GUG-125 non-production live engine.
2. **Schema evolution** — future archive types must also use this canonical
   path binding. The parser is generic (not hard-coded to current archive IDs).
3. **Cryptographic signature verification** — not implemented locally
   (`pending_aws`); requires live KMS access.
