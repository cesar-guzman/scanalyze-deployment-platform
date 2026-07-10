"""Employee Profiles Service — main business logic.

Orchestrates:
  1. Feature-flag validation
  2. Batch document loading (read-only from existing DynamoDB)
  3. Structured artifact loading (read-only from existing S3)
  4. Person grouping & field merging
  5. Profile persistence (write to S3 structured bucket)
  6. Job status tracking

No modifications to core documents/batches.  No OCR.  No Bedrock.

S3 Layout (P0.2):
  employee-profiles/{tenantKey}/jobs/{jobId}.json
  employee-profiles/{tenantKey}/batches/{batchId}/job.json
  employee-profiles/{tenantKey}/batches/{batchId}/profiles.json
  employee-profiles/{tenantKey}/profiles/{profileId}.json
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from ..aws_clients import s3_client
from ..config import get_settings
from ..errors import AppError
from ..logging import bind_context, get_logger
from ..repositories.documents import DocumentsRepository
from .employee_profiles_grouping import (
    build_job_id,
    build_profile_id,
    derive_person_key,
    group_documents_by_person,
    merge_profile_fields,
)
from .employee_profiles_masking import mask_identifier
from .employee_profiles_utils import (
    compute_source_fingerprint,
    options_hash,
    sanitise_key,
    strip_internal_paths,
)
from .employee_profiles_eligibility import (
    filter_eligible_documents,
    is_document_relevant_for_worker_profile,
)



def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class EmployeeProfileService:
    """Stateless service — instantiate per request."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self.repo = DocumentsRepository()
        self.s3 = s3_client()
        self.logger = get_logger()

    # ─── Feature flag guard ─────────────────────────
    def _check_feature_enabled(self, tenant: str) -> None:
        if not self.settings.employee_profiles_enabled:
            raise AppError(
                code="FEATURE_DISABLED",
                message="Employee Profiles module is not enabled",
                status_code=403,
                details={},
            )
        allowed = self.settings.employee_profiles_enabled_tenants.strip()
        if not allowed:
            # P0.3: Empty default = nobody enabled
            raise AppError(
                code="FEATURE_DISABLED",
                message="Employee Profiles module has no tenants configured",
                status_code=403,
                details={},
            )
        if allowed != "*":
            tenants = [t.strip().lower() for t in allowed.split(",") if t.strip()]
            if tenant.lower() not in tenants:
                raise AppError(
                    code="FEATURE_DISABLED",
                    message="Employee Profiles module is not enabled for this tenant",
                    status_code=403,
                    details={},
                )

    def _is_tenant_enabled(self, tenant: str) -> bool:
        """Non-throwing version for status endpoint."""
        if not self.settings.employee_profiles_enabled:
            return False
        allowed = self.settings.employee_profiles_enabled_tenants.strip()
        if not allowed:
            return False
        if allowed == "*":
            return True
        tenants = [t.strip().lower() for t in allowed.split(",") if t.strip()]
        return tenant.lower() in tenants

    # ─── S3 key helpers (P0.2 layout) ──────────────
    def _tenant_key(self, tenant: str) -> str:
        return sanitise_key(tenant)

    def _batch_profiles_key(self, tenant: str, batch_id: str) -> str:
        return f"employee-profiles/{self._tenant_key(tenant)}/batches/{sanitise_key(batch_id)}/profiles.json"

    def _batch_job_key(self, tenant: str, batch_id: str) -> str:
        return f"employee-profiles/{self._tenant_key(tenant)}/batches/{sanitise_key(batch_id)}/job.json"

    def _profile_key(self, tenant: str, profile_id: str) -> str:
        return f"employee-profiles/{self._tenant_key(tenant)}/profiles/{sanitise_key(profile_id)}.json"

    def _job_key(self, tenant: str, job_id: str) -> str:
        return f"employee-profiles/{self._tenant_key(tenant)}/jobs/{sanitise_key(job_id)}.json"

    def _profiles_prefix(self, tenant: str) -> str:
        return f"employee-profiles/{self._tenant_key(tenant)}/profiles/"

    def _structured_bucket(self) -> str:
        bucket = self.settings.get_bucket("structured")
        if not bucket:
            raise AppError(
                code="CONFIG_ERROR",
                message="STRUCTURED_BUCKET is not configured",
                status_code=500,
            )
        return bucket

    def _read_s3_json(self, bucket: str, key: str) -> Optional[Any]:
        try:
            resp = self.s3.get_object(Bucket=bucket, Key=key)
            return json.loads(resp["Body"].read().decode("utf-8"))
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") in ("NoSuchKey", "404"):
                return None
            raise

    def _write_s3_json(self, bucket: str, key: str, data: Any) -> None:
        self.s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=json.dumps(data, indent=2, ensure_ascii=False, default=str).encode("utf-8"),
            ContentType="application/json",
        )

    # ─── Load structured artifact for a document ────
    def _load_structured_artifact(self, doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Read the structured extraction result for a document from S3."""
        # 1. stages.persist.artifactRef (formal contract)
        stages = doc.get("stages") or {}
        persist = stages.get("persist") or {}
        artifact_ref = persist.get("artifactRef")
        if artifact_ref and artifact_ref.get("bucket") and artifact_ref.get("key"):
            return self._read_s3_json(artifact_ref["bucket"], artifact_ref["key"])

        # 2. artifacts.structured
        artifacts = doc.get("artifacts") or {}
        structured = artifacts.get("structured")
        if structured and structured.get("bucket") and structured.get("key"):
            return self._read_s3_json(structured["bucket"], structured["key"])

        # 3. artifacts.result
        result = artifacts.get("result")
        if result and result.get("bucket") and result.get("key"):
            return self._read_s3_json(result["bucket"], result["key"])

        # 4. Top-level structured field (production docs)
        structured_top = doc.get("structured")
        if isinstance(structured_top, dict) and structured_top.get("bucket") and structured_top.get("key"):
            return self._read_s3_json(structured_top["bucket"], structured_top["key"])

        return None

    # ─── Filter eligible documents (shared eligibility helper) ──
    def _filter_eligible_docs(
        self, all_docs: List[Dict[str, Any]], tenant: str, include_incomplete: bool
    ) -> List[Dict[str, Any]]:
        """Filter batch documents using the shared eligibility helper.

        Uses the same logic as the Lambda add-on to determine eligibility
        based on classifier v1.1 metadata (subType, routeIntent,
        terminalReason, canonicalDocType, confidence).
        """
        eligible, _review, _excluded = filter_eligible_documents(
            all_docs, tenant, include_incomplete=include_incomplete,
        )
        return eligible

    # ─── Core: Generate profiles ────────────────────
    def generate_profiles(
        self,
        tenant: str,
        batch_id: str,
        requested_by: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generate employee profiles for a batch.

        Idempotent via sourceFingerprint (P0.7).
        Enforces max document limit (P0.6).
        """
        self._check_feature_enabled(tenant)
        opts = options or {}
        force = opts.get("force", False)
        include_incomplete = opts.get("includeIncomplete", False)

        bind_context(tenant=tenant)
        self.logger.info(
            "employee_profiles_generate_start",
            batchId=batch_id,
            force=force,
        )

        bucket = self._structured_bucket()
        opt_hash = options_hash(opts)
        job_id = build_job_id(tenant, batch_id, opt_hash)

        # 1. Load batch documents
        #    The BatchIndex GSI only projects a few fields (status, s3_key, etc.)
        #    We need full docs for classification route filtering & structured data.
        sparse_docs = self.repo.get_documents_by_batch(batch_id)
        all_docs = []
        for sdoc in sparse_docs:
            doc_id = sdoc.get("documentId") or sdoc.get("document_id")
            if not doc_id:
                continue
            full_doc = self.repo.get_document(doc_id)
            if full_doc:
                all_docs.append(full_doc)
            else:
                all_docs.append(sdoc)  # fallback to sparse

        eligible = self._filter_eligible_docs(all_docs, tenant, include_incomplete)

        # P0.6: Enforce max documents limit
        max_docs = self.settings.employee_profiles_max_docs_per_batch
        if len(eligible) > max_docs:
            raise AppError(
                code="EMPLOYEE_PROFILE_BATCH_TOO_LARGE",
                message=f"This batch has {len(eligible)} eligible documents. "
                        f"The synchronous v1 limit is {max_docs}.",
                status_code=400,
                details={"eligibleCount": len(eligible), "maxAllowed": max_docs},
            )

        # P0.7: Compute source fingerprint
        source_fp = compute_source_fingerprint(tenant, batch_id, opts, eligible)

        # Check existing job (idempotency via fingerprint)
        batch_job_key = self._batch_job_key(tenant, batch_id)
        if not force:
            existing_job = self._read_s3_json(bucket, batch_job_key)
            if existing_job and existing_job.get("status") in ("COMPLETED", "PARTIAL"):
                existing_fp = existing_job.get("sourceFingerprint", "")
                if existing_fp == source_fp:
                    self.logger.info(
                        "employee_profiles_generate_existing",
                        jobId=job_id,
                        profileCount=existing_job.get("profileCount", 0),
                    )
                    return {
                        "jobId": job_id,
                        "batchId": batch_id,
                        "status": existing_job["status"],
                        "mode": "sync",
                        "existing": True,
                        "stale": False,
                        "profileCount": existing_job.get("profileCount", 0),
                    }
                else:
                    # Fingerprint changed — data is stale
                    return {
                        "jobId": job_id,
                        "batchId": batch_id,
                        "status": "STALE",
                        "mode": "sync",
                        "existing": True,
                        "stale": True,
                        "profileCount": existing_job.get("profileCount", 0),
                        "message": "Source documents have changed since last generation. "
                                   "Use force=true to regenerate.",
                    }

        # Create RUNNING job
        job: Dict[str, Any] = {
            "entityType": "EMPLOYEE_PROFILE_GENERATION_JOB",
            "tenantId": tenant,
            "jobId": job_id,
            "batchId": batch_id,
            "status": "RUNNING",
            "optionsHash": opt_hash,
            "sourceFingerprint": source_fp,
            "force": force,
            "eligibleDocumentCount": len(eligible),
            "processedDocumentCount": 0,
            "profileCount": 0,
            "warningCount": 0,
            "errorMessage": None,
            "createdBy": requested_by,
            "createdAt": _utc_now_iso(),
            "updatedAt": _utc_now_iso(),
            "startedAt": _utc_now_iso(),
            "completedAt": None,
        }
        # Write batch-level job
        self._write_s3_json(bucket, batch_job_key, job)
        # Write job-level lookup (P0.2)
        self._write_s3_json(bucket, self._job_key(tenant, job_id), job)

        try:
            if not eligible:
                job["status"] = "COMPLETED"
                job["profileCount"] = 0
                job["completedAt"] = _utc_now_iso()
                job["updatedAt"] = _utc_now_iso()
                self._write_s3_json(bucket, batch_job_key, job)
                self._write_s3_json(bucket, self._job_key(tenant, job_id), job)
                self._write_s3_json(bucket, self._batch_profiles_key(tenant, batch_id), [])
                return {
                    "jobId": job_id,
                    "batchId": batch_id,
                    "status": "COMPLETED",
                    "mode": "sync",
                    "existing": False,
                    "stale": False,
                    "profileCount": 0,
                }

            # 2. Load structured artifacts
            extracted_docs: List[Dict[str, Any]] = []
            for doc in eligible:
                artifact = self._load_structured_artifact(doc)
                if artifact:
                    artifact["batchId"] = doc.get("batchId", batch_id)
                    if "documentId" not in artifact:
                        artifact["documentId"] = doc.get("documentId", "")
                    extracted_docs.append(artifact)
                else:
                    job["warningCount"] = job.get("warningCount", 0) + 1

            job["processedDocumentCount"] = len(extracted_docs)

            # 3. Group by person
            groups = group_documents_by_person(extracted_docs)

            # 4. Build profiles
            profiles: List[Dict[str, Any]] = []
            profile_ids: List[str] = []
            now = _utc_now_iso()

            for person_key, group_docs in groups.items():
                profile_id = build_profile_id(tenant, batch_id, person_key)
                merged = merge_profile_fields(group_docs, person_key)

                # Build masked identifiers
                ids = merged.get("identifiers") or {}
                masked_ids = {}
                for id_type in ("curp", "rfc", "claveElector"):
                    val = ids.get(id_type)
                    if val:
                        masked_ids[id_type] = mask_identifier(val, id_type)

                # P1.3: Strip internal S3 paths from fieldSources
                field_sources = strip_internal_paths(merged.get("fieldSources") or {})

                profile: Dict[str, Any] = {
                    "entityType": "EMPLOYEE_PROFILE",
                    "tenantId": tenant,
                    "profileId": profile_id,
                    "batchId": batch_id,
                    **merged,
                    "fieldSources": field_sources,
                    "maskedIdentifiers": masked_ids,
                    "generationJobId": job_id,
                    "generatedAt": now,
                    "generatedBy": requested_by,
                    "createdAt": now,
                    "updatedAt": now,
                }
                profiles.append(profile)
                profile_ids.append(profile_id)

            # 5. Persist — batch-level manifest
            self._write_s3_json(bucket, self._batch_profiles_key(tenant, batch_id), profiles)

            # 5b. Persist — individual profile files (P0.2)
            for profile in profiles:
                pid = profile["profileId"]
                self._write_s3_json(bucket, self._profile_key(tenant, pid), profile)

            total_warnings = sum(len(p.get("warnings") or []) for p in profiles)
            has_issues = any(p.get("status") == "NEEDS_REVIEW" for p in profiles)

            job["profileCount"] = len(profiles)
            job["profileIds"] = profile_ids
            job["warningCount"] = total_warnings + job.get("warningCount", 0)
            job["status"] = "PARTIAL" if has_issues else "COMPLETED"
            job["completedAt"] = _utc_now_iso()
            job["updatedAt"] = _utc_now_iso()

            # Persist job in both locations
            self._write_s3_json(bucket, batch_job_key, job)
            self._write_s3_json(bucket, self._job_key(tenant, job_id), job)

            self.logger.info(
                "employee_profiles_generate_completed",
                jobId=job_id,
                batchId=batch_id,
                profileCount=len(profiles),
                warningCount=total_warnings,
            )

            return {
                "jobId": job_id,
                "batchId": batch_id,
                "status": job["status"],
                "mode": "sync",
                "existing": False,
                "stale": False,
                "profileCount": len(profiles),
            }

        except AppError:
            raise
        except Exception as exc:
            job["status"] = "FAILED"
            job["errorCode"] = "EMPLOYEE_PROFILES_GENERATION_FAILED"
            job["errorType"] = type(exc).__name__
            job["updatedAt"] = _utc_now_iso()
            self._write_s3_json(bucket, batch_job_key, job)
            self._write_s3_json(bucket, self._job_key(tenant, job_id), job)
            self.logger.error("employee_profiles_generate_failed", errorType=type(exc).__name__)
            raise

    # ─── Get job status ─────────────────────────────
    def get_job(self, tenant: str, job_id: str, batch_id: Optional[str] = None) -> Dict[str, Any]:
        """Get generation job status.

        P0.2: Can look up by jobId directly (via jobs/{jobId}.json).
        Falls back to batch-level job if batchId is provided.
        """
        self._check_feature_enabled(tenant)
        bucket = self._structured_bucket()

        # Try direct job lookup first
        job = self._read_s3_json(bucket, self._job_key(tenant, job_id))
        if job and job.get("tenantId") == tenant:
            return job

        # Fallback to batch-level lookup
        if batch_id:
            job = self._read_s3_json(bucket, self._batch_job_key(tenant, batch_id))
            if job and job.get("tenantId") == tenant:
                return job

        raise AppError(code="NOT_FOUND", message="Job not found", status_code=404)

    # ─── List profiles ──────────────────────────────
    def list_profiles(
        self,
        tenant: str,
        batch_id: Optional[str] = None,
        status_filter: Optional[str] = None,
        q: Optional[str] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """List profiles, optionally filtered by batch, status, or name search.

        P0.5: q is name-only search. No PII matching.
        """
        self._check_feature_enabled(tenant)
        bucket = self._structured_bucket()

        if batch_id:
            # Load from batch manifest
            profiles_key = self._batch_profiles_key(tenant, batch_id)
            data = self._read_s3_json(bucket, profiles_key)
            if data is None:
                return {"profiles": [], "total": 0, "batchId": batch_id}
            profiles = data if isinstance(data, list) else []
        else:
            # P0.2: List from profiles/ prefix with basic pagination
            prefix = self._profiles_prefix(tenant)
            profiles = []
            try:
                resp = self.s3.list_objects_v2(
                    Bucket=bucket, Prefix=prefix, MaxKeys=min(limit * 2, 500)
                )
                for obj in resp.get("Contents", []):
                    pdata = self._read_s3_json(bucket, obj["Key"])
                    if pdata and isinstance(pdata, dict):
                        profiles.append(pdata)
            except ClientError:
                pass

        # Tenant guard
        profiles = [p for p in profiles if p.get("tenantId") == tenant]

        # Filter by status
        if status_filter:
            profiles = [p for p in profiles if p.get("status", "").upper() == status_filter.upper()]

        # P0.5: Search by NAME only (no PII matching)
        if q:
            q_upper = q.upper()
            profiles = [
                p for p in profiles
                if q_upper in (p.get("fullName") or "").upper()
            ]

        total = len(profiles)
        profiles = profiles[:limit]

        # Build list-safe response (masked identifiers, no raw PII)
        list_profiles = []
        for p in profiles:
            lp = {
                "profileId": p.get("profileId"),
                "fullName": p.get("fullName"),
                "status": p.get("status"),
                "completenessScore": p.get("completenessScore"),
                "maskedIdentifiers": p.get("maskedIdentifiers", {}),
                "sourceDocumentCount": len(p.get("sourceDocuments") or []),
                "missingFieldCount": len(p.get("missingFields") or []),
                "warningCount": len(p.get("warnings") or []),
                "generatedAt": p.get("generatedAt"),
                "batchId": p.get("batchId"),
            }
            list_profiles.append(lp)

        return {"profiles": list_profiles, "total": total, "batchId": batch_id}

    # ─── Get profile detail ─────────────────────────
    def get_profile(
        self, tenant: str, profile_id: str, batch_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get full profile detail.

        P0.2: Reads directly from profiles/{profileId}.json.
        Falls back to batch manifest if batch_id is provided.
        """
        self._check_feature_enabled(tenant)
        bucket = self._structured_bucket()

        # Try direct profile lookup (P0.2)
        profile = self._read_s3_json(bucket, self._profile_key(tenant, profile_id))
        if profile and profile.get("tenantId") == tenant:
            return profile

        # Fallback to batch manifest lookup
        if batch_id:
            profiles_key = self._batch_profiles_key(tenant, batch_id)
            data = self._read_s3_json(bucket, profiles_key)
            if data:
                profiles = data if isinstance(data, list) else []
                match = [
                    p for p in profiles
                    if p.get("profileId") == profile_id and p.get("tenantId") == tenant
                ]
                if match:
                    return match[0]

        raise AppError(code="NOT_FOUND", message="Profile not found", status_code=404)

    # ─── Feature status check (P0.4) ───────────────
    def get_status(self, tenant: str) -> Dict[str, Any]:
        """Return feature status for this tenant.

        P0.4: Requires JWT (handled by router). Does not expose tenant list.
        Returns enriched status with tenantEnabled and maxDocumentsPerBatch.
        """
        enabled = self.settings.employee_profiles_enabled
        tenant_enabled = self._is_tenant_enabled(tenant)
        return {
            "enabled": enabled,
            "mode": self.settings.employee_profiles_mode if enabled else "disabled",
            "tenantEnabled": tenant_enabled,
            "maxDocumentsPerBatch": self.settings.employee_profiles_max_docs_per_batch,
        }
