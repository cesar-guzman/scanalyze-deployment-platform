# WS8 Focused Consistency Patches — Ownership Matrix

> **Applied to**: `ADR/ARCHITECTURE_OWNERSHIP_MATRIX.md`  
> **Date**: 2026-06-28  
> **Status**: Verified — all patches already present in imported rev2

---

## Patch Verification (8.7–8.15)

| Patch | Requirement | Status | Evidence |
|---|---|---|---|
| 8.7 | 6 control-plane roles → account baseline (not global) | ✅ Already present | §2 line 59-60: explicit callout. §3: 6 roles under AccountVendingProvider |
| 8.8 | SSM contract params owned by producer layer | ✅ Already present | §4 line 209-216: session policy restricts ssm:PutParameter to producer's layer prefix |
| 8.9 | edge-identity separated from addons | ✅ Already present | §1 line 21-23: edge-identity (layer 5a) vs addons (layer 5b). §2: separate resource tables |
| 8.10 | "per-tenant" → processing_domain | ✅ Already present | §2 line 95-96: "per processing domain" used consistently |
| 8.11 | Diagnostic/StateRecovery as principals in bucket policies | ✅ Already present | §4 line 204-205: both roles documented. §6: explicit access by role |
| 8.12 | Plan artifact writer explicit | ✅ Already present | §6 line 262, 266: Plan writes plan-execution zone, distinct from immutable evidence |
| 8.13 | Apply reads upstream contracts (documented) | ✅ Already present | §5 line 244-253: consumer/producer dependency graph documented |
| 8.14 | Regional states include region | ✅ Already present | §1 line 17-23: `{dep_id}/{region}/{layer}` for all regional layers. §8: multi-region state keys |
| 8.15 | Frontend release owner explicit | ✅ Already present | §4 line 202: Promotion role owns "S3 (frontend immutable release prefix)" |
| (8.15b) | Account baseline state/owner identified | ✅ Already present | §3 line 171-189: "Bootstrap state" for all AccountVendingProvider resources |

## Additional Validation

The imported Ownership Matrix rev2 is **internally consistent** with the IMPLEMENTATION_PLAN.md corrections. No additional patches required.

### Consistency Checks Performed

1. **Bootstrap chicken-and-egg** (P0-2): §3 explicitly documents AccountVendingProvider creates all 6 roles before any deployment layer runs.
2. **Session policy enforcement** (P0-3): §4 documents session policy per layer for SSM write restriction.
3. **Plan evidence model** (P0-5): §6 documents three-prefix model (plan-execution, evidence, recovery) with distinct retention.
4. **Forbidden patterns** (§9): 13 patterns listed with detection mechanisms — consistent with IMPLEMENTATION_PLAN.
5. **Multi-region ownership** (§8): Single owner for cross-region resources, consistent with ADR-008 rev3.

No textual changes were made to `ARCHITECTURE_OWNERSHIP_MATRIX.md`.
