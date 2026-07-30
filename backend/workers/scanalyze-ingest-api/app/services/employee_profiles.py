"""Employee Profiles Service — main business logic.

Orchestrates:
  1. Feature-flag validation
  2. Batch document loading (read-only from existing DynamoDB)
  3. Structured artifact loading (read-only from existing S3)
  4. Person grouping & field merging
  5. Profile persistence (write to S3 structured bucket)
  6. Job status tracking

No modifications to core documents/batches.  No OCR.  No Bedrock.

S3 Layout (GUG-114):
  employee-profiles/customers/{customerId}/deployments/{deploymentId}/jobs/{jobId}.json
  employee-profiles/customers/{customerId}/deployments/{deploymentId}/batches/{batchId}/job.json
  employee-profiles/customers/{customerId}/deployments/{deploymentId}/batches/{batchId}/profiles.json
  employee-profiles/customers/{customerId}/deployments/{deploymentId}/profiles/{profileId}.json
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

from ..auth import AuthContext
from ..authorization import (
    ObjectAction,
    ObjectOwnership,
    authorize_batch,
    authorize_batch_membership,
    authorize_document,
    authorize_owned_record,
)
from ..aws_clients import s3_client
from ..config import get_settings
from ..errors import AppError
from ..logging import bind_context, get_logger
from ..repositories.batches import BatchesRepository
from ..repositories.documents import DocumentsRepository
from .documents import DocumentsService
from .employee_profiles_grouping import (
    build_job_id,
    build_profile_id,
    derive_person_key,
    group_documents_by_person,
    merge_profile_fields,
)
from .employee_profiles_masking import mask_identifier, project_masked_profile
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


_JOB_METADATA_STATUS_VALUES = frozenset(
    {"RUNNING", "COMPLETED", "PARTIAL", "FAILED"}
)
_JOB_METADATA_COUNT_FIELDS = (
    "eligibleDocumentCount",
    "processedDocumentCount",
    "profileCount",
    "warningCount",
)
_JOB_METADATA_TIMESTAMP_FIELDS = (
    "createdAt",
    "updatedAt",
    "startedAt",
    "completedAt",
)
_GENERATION_OPTION_NAMES = frozenset({"force", "includeIncomplete"})


def _normalize_generation_options(options: Any) -> Dict[str, bool]:
    """Reject free-form controls before they can affect behavior or logging."""
    if options is None:
        return {}
    if not isinstance(options, Mapping):
        raise AppError(
            code="VALIDATION_ERROR",
            message="Generation options are invalid",
            status_code=400,
            details={},
        )
    if not set(options).issubset(_GENERATION_OPTION_NAMES):
        raise AppError(
            code="VALIDATION_ERROR",
            message="Generation options are invalid",
            status_code=400,
            details={},
        )
    normalized: Dict[str, bool] = {}
    for name, value in options.items():
        if not isinstance(name, str) or type(value) is not bool:
            raise AppError(
                code="VALIDATION_ERROR",
                message="Generation options are invalid",
                status_code=400,
                details={},
            )
        normalized[name] = value
    return normalized


def _is_safe_job_timestamp(value: Any) -> bool:
    if value is None:
        return True
    if not isinstance(value, str) or len(value) > 64:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _project_job_metadata(job: Mapping[str, Any]) -> Dict[str, Any]:
    """Project a stored job onto the closed, non-identifying status contract."""
    projected: Dict[str, Any] = {
        "jobId": job.get("jobId"),
        "batchId": job.get("batchId"),
    }
    status = job.get("status")
    if not (isinstance(status, str) and status in _JOB_METADATA_STATUS_VALUES):
        raise AppError(
            code="NOT_FOUND",
            message="Employee profile job not found",
            status_code=404,
            details={},
        )
    projected["status"] = status
    for field in _JOB_METADATA_COUNT_FIELDS:
        value = job.get(field)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            projected[field] = value
    for field in _JOB_METADATA_TIMESTAMP_FIELDS:
        value = job.get(field)
        if _is_safe_job_timestamp(value):
            projected[field] = value
    if job.get("errorCode") == "EMPLOYEE_PROFILES_GENERATION_FAILED":
        projected["errorCode"] = "EMPLOYEE_PROFILES_GENERATION_FAILED"
    return projected


class EmployeeProfileService:
    """Stateless service — instantiate per request."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self.repo = DocumentsRepository()
        self.batches_repo = BatchesRepository()
        self.documents_service = DocumentsService()
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
    def _ownership_prefix(self, ownership: ObjectOwnership) -> str:
        customer_key = sanitise_key(ownership.customer_id)
        deployment_key = sanitise_key(ownership.deployment_id)
        return (
            f"employee-profiles/customers/{customer_key}/"
            f"deployments/{deployment_key}"
        )

    def _batch_profiles_key(self, ownership: ObjectOwnership, batch_id: str) -> str:
        return (
            f"{self._ownership_prefix(ownership)}/batches/"
            f"{sanitise_key(batch_id)}/profiles.json"
        )

    def _batch_job_key(self, ownership: ObjectOwnership, batch_id: str) -> str:
        return (
            f"{self._ownership_prefix(ownership)}/batches/"
            f"{sanitise_key(batch_id)}/job.json"
        )

    def _profile_key(self, ownership: ObjectOwnership, profile_id: str) -> str:
        return (
            f"{self._ownership_prefix(ownership)}/profiles/"
            f"{sanitise_key(profile_id)}.json"
        )

    def _job_key(self, ownership: ObjectOwnership, job_id: str) -> str:
        return (
            f"{self._ownership_prefix(ownership)}/jobs/"
            f"{sanitise_key(job_id)}.json"
        )

    def _profiles_prefix(self, ownership: ObjectOwnership) -> str:
        return f"{self._ownership_prefix(ownership)}/profiles/"

    def _structured_bucket(self) -> str:
        bucket = self.settings.get_bucket("structured")
        if not bucket:
            raise AppError(
                code="CONFIG_ERROR",
                message="STRUCTURED_BUCKET is not configured",
                status_code=500,
            )
        return bucket

    def _read_s3_json_with_version(
        self,
        bucket: str,
        key: str,
    ) -> Tuple[Optional[Any], Optional[str]]:
        try:
            resp = self.s3.get_object(Bucket=bucket, Key=key)
            etag = resp.get("ETag")
            if not isinstance(etag, str) or not etag:
                raise AppError(
                    code="S3_READ_FAILED",
                    message="Failed to read employee profile state",
                    status_code=502,
                    details={},
                )
            return json.loads(resp["Body"].read().decode("utf-8")), etag
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") in ("NoSuchKey", "404"):
                return None, None
            raise

    def _read_s3_json(self, bucket: str, key: str) -> Optional[Any]:
        data, _etag = self._read_s3_json_with_version(bucket, key)
        return data

    def _write_s3_json(
        self,
        bucket: str,
        key: str,
        data: Any,
        *,
        if_match: Optional[str] = None,
        if_none_match: bool = False,
    ) -> None:
        params: Dict[str, Any] = {
            "Bucket": bucket,
            "Key": key,
            "Body": json.dumps(
                data,
                indent=2,
                ensure_ascii=False,
                default=str,
            ).encode("utf-8"),
            "ContentType": "application/json",
        }
        if if_match is not None:
            params["IfMatch"] = if_match
        elif if_none_match:
            params["IfNoneMatch"] = "*"
        else:
            raise AppError(
                code="CONCURRENT_UPDATE",
                message="Employee profile state changed; retry the operation",
                status_code=409,
                details={},
            )

        try:
            self.s3.put_object(**params)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in (
                "ConditionalRequestConflict",
                "PreconditionFailed",
                "409",
                "412",
            ):
                raise AppError(
                    code="CONCURRENT_UPDATE",
                    message="Employee profile state changed; retry the operation",
                    status_code=409,
                    details={},
                ) from exc
            raise

    def _write_owned_batch_child(
        self,
        *,
        auth: AuthContext,
        ownership: ObjectOwnership,
        batch_id: str,
        bucket: str,
        key: str,
        record: Mapping[str, Any],
        object_kind: str,
        identity_field: str,
        identity_value: str,
    ) -> None:
        new_record = self._validate_batch_child(
            auth,
            record,
            ownership=ownership,
            batch_id=batch_id,
            action=ObjectAction.WRITE,
            object_kind=object_kind,
        )
        if new_record.get(identity_field) != identity_value:
            self._hide_owned_record(auth, ObjectAction.WRITE, object_kind)

        existing, etag = self._read_s3_json_with_version(bucket, key)
        if existing is not None:
            existing_record = self._validate_batch_child(
                auth,
                existing if isinstance(existing, Mapping) else None,
                ownership=ownership,
                batch_id=batch_id,
                action=ObjectAction.WRITE,
                object_kind=object_kind,
            )
            if existing_record.get(identity_field) != identity_value:
                self._hide_owned_record(auth, ObjectAction.WRITE, object_kind)

        self._write_s3_json(
            bucket,
            key,
            dict(new_record),
            if_match=etag,
            if_none_match=existing is None,
        )

    def _write_owned_batch_profiles(
        self,
        *,
        auth: AuthContext,
        ownership: ObjectOwnership,
        batch_id: str,
        bucket: str,
        profiles: List[Dict[str, Any]],
    ) -> None:
        key = self._batch_profiles_key(ownership, batch_id)
        existing, etag = self._read_s3_json_with_version(bucket, key)
        if existing is not None:
            if not isinstance(existing, list):
                self._hide_owned_record(
                    auth,
                    ObjectAction.WRITE,
                    "Employee profile",
                )
            for candidate in existing:
                self._validate_batch_child(
                    auth,
                    candidate if isinstance(candidate, Mapping) else None,
                    ownership=ownership,
                    batch_id=batch_id,
                    action=ObjectAction.WRITE,
                    object_kind="Employee profile",
                )

        validated_profiles = [
            self._validate_batch_child(
                auth,
                profile,
                ownership=ownership,
                batch_id=batch_id,
                action=ObjectAction.WRITE,
                object_kind="Employee profile",
            )
            for profile in profiles
        ]
        self._write_s3_json(
            bucket,
            key,
            validated_profiles,
            if_match=etag,
            if_none_match=existing is None,
        )

    def _write_job_records(
        self,
        *,
        auth: AuthContext,
        ownership: ObjectOwnership,
        batch_id: str,
        bucket: str,
        job: Dict[str, Any],
    ) -> None:
        job_id = job.get("jobId")
        if not isinstance(job_id, str) or not job_id:
            self._hide_owned_record(
                auth,
                ObjectAction.WRITE,
                "Employee profile job",
            )
        for key in (
            self._batch_job_key(ownership, batch_id),
            self._job_key(ownership, job_id),
        ):
            self._write_owned_batch_child(
                auth=auth,
                ownership=ownership,
                batch_id=batch_id,
                bucket=bucket,
                key=key,
                record=job,
                object_kind="Employee profile job",
                identity_field="jobId",
                identity_value=job_id,
            )

    def _hide_owned_record(
        self,
        auth: AuthContext,
        action: ObjectAction,
        object_kind: str,
    ) -> None:
        authorize_owned_record(
            auth,
            None,
            action,
            object_kind=object_kind,
        )

    def _load_batch(
        self,
        auth: AuthContext,
        batch_id: str,
        action: ObjectAction,
    ) -> Tuple[Dict[str, Any], ObjectOwnership]:
        batch = self.batches_repo.get_batch(batch_id)
        ownership = authorize_batch(auth, batch, action)
        return batch, ownership

    def _validate_batch_child(
        self,
        auth: AuthContext,
        record: Mapping[str, Any] | None,
        *,
        ownership: ObjectOwnership,
        batch_id: str,
        action: ObjectAction,
        object_kind: str,
    ) -> Dict[str, Any]:
        authorize_owned_record(
            auth,
            record,
            action,
            object_kind=object_kind,
        )
        if (
            not isinstance(record, Mapping)
            or record.get("batchId") != batch_id
            or record.get("ownership_batch_key") != ownership.batch_partition(batch_id)
        ):
            self._hide_owned_record(auth, action, object_kind)
        return dict(record)

    def _load_batch_documents(
        self,
        auth: AuthContext,
        batch: Dict[str, Any],
        ownership: ObjectOwnership,
        action: ObjectAction,
    ) -> List[Dict[str, Any]]:
        batch_id = batch.get("batchId")
        if not isinstance(batch_id, str) or not batch_id:
            authorize_batch(auth, None, action)

        sparse_docs = self.repo.get_documents_by_batch(
            batch_id,
            ownership=ownership,
        )
        authorize_batch_membership(auth, batch, sparse_docs, action)

        full_docs: List[Dict[str, Any]] = []
        for sparse in sparse_docs:
            doc_id = sparse.get("documentId") or sparse.get("document_id")
            if not isinstance(doc_id, str) or not doc_id:
                authorize_batch(auth, None, action)
            full_doc = self.repo.get_document(doc_id)
            if not isinstance(full_doc, Mapping):
                authorize_batch(auth, None, action)
            try:
                authorize_document(auth, full_doc, action)
            except AppError:
                authorize_batch(auth, None, action)
            full_docs.append(dict(full_doc))

        authorize_batch_membership(auth, batch, full_docs, action)
        return full_docs

    # ─── Load structured artifact for a document ────
    def _load_structured_artifact(
        self,
        doc: Dict[str, Any],
        ownership: ObjectOwnership,
    ) -> Optional[Dict[str, Any]]:
        """Read the structured extraction result for a document from S3."""
        document_id = doc.get("documentId")
        if not isinstance(document_id, str) or not document_id:
            raise AppError(
                code="NOT_FOUND",
                message="Document not found",
                status_code=404,
                details={},
            )

        def read_locator(locator: Any) -> Optional[Dict[str, Any]]:
            if not isinstance(locator, Mapping):
                return None
            bucket, key = self.documents_service._validate_artifact_locator(
                ownership,
                document_id,
                locator.get("bucket"),
                locator.get("key"),
            )
            data = self._read_s3_json(bucket, key)
            return data if isinstance(data, dict) else None

        # 1. stages.persist.artifactRef (formal contract)
        stages = doc.get("stages") or {}
        persist = stages.get("persist") or {}
        artifact_ref = persist.get("artifactRef")
        if artifact_ref and artifact_ref.get("bucket") and artifact_ref.get("key"):
            return read_locator(artifact_ref)

        # 2. artifacts.structured
        artifacts = doc.get("artifacts") or {}
        structured = artifacts.get("structured")
        if structured and structured.get("bucket") and structured.get("key"):
            return read_locator(structured)

        # 3. artifacts.result
        result = artifacts.get("result")
        if result and result.get("bucket") and result.get("key"):
            return read_locator(result)

        # 4. Top-level structured field (production docs)
        structured_top = doc.get("structured")
        if isinstance(structured_top, dict) and structured_top.get("bucket") and structured_top.get("key"):
            return read_locator(structured_top)

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
        auth: AuthContext,
        batch_id: str,
        requested_by: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generate employee profiles for a batch.

        Idempotent via sourceFingerprint (P0.7).
        Enforces max document limit (P0.6).
        """
        opts = _normalize_generation_options(options)
        batch, ownership = self._load_batch(auth, batch_id, ObjectAction.WRITE)
        tenant = ownership.customer_id
        self._check_feature_enabled(tenant)
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
        identity_seed = f"{ownership.customer_id}:{ownership.deployment_id}"
        job_id = build_job_id(identity_seed, batch_id, opt_hash)

        all_docs = self._load_batch_documents(
            auth,
            batch,
            ownership,
            ObjectAction.WRITE,
        )

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
        source_fp = compute_source_fingerprint(identity_seed, batch_id, opts, eligible)

        # Check and authorize existing state even for force regeneration. Force
        # changes idempotency behavior; it never bypasses object authorization.
        batch_job_key = self._batch_job_key(ownership, batch_id)
        existing_job = self._read_s3_json(bucket, batch_job_key)
        if existing_job is not None:
            existing_job = self._validate_batch_child(
                auth,
                existing_job if isinstance(existing_job, Mapping) else None,
                ownership=ownership,
                batch_id=batch_id,
                action=ObjectAction.WRITE,
                object_kind="Employee profile job",
            )
        if not force:
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
            **ownership.record_fields(),
            "ownership_batch_key": ownership.batch_partition(batch_id),
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
        self._write_job_records(
            auth=auth,
            ownership=ownership,
            batch_id=batch_id,
            bucket=bucket,
            job=job,
        )

        try:
            if not eligible:
                job["status"] = "COMPLETED"
                job["profileCount"] = 0
                job["completedAt"] = _utc_now_iso()
                job["updatedAt"] = _utc_now_iso()
                self._write_job_records(
                    auth=auth,
                    ownership=ownership,
                    batch_id=batch_id,
                    bucket=bucket,
                    job=job,
                )
                self._write_owned_batch_profiles(
                    auth=auth,
                    ownership=ownership,
                    batch_id=batch_id,
                    bucket=bucket,
                    profiles=[],
                )
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
                artifact = self._load_structured_artifact(doc, ownership)
                if artifact:
                    artifact["batchId"] = batch_id
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
                profile_id = build_profile_id(identity_seed, batch_id, person_key)
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
                    **merged,
                    "entityType": "EMPLOYEE_PROFILE",
                    "tenantId": tenant,
                    **ownership.record_fields(),
                    "ownership_batch_key": ownership.batch_partition(batch_id),
                    "profileId": profile_id,
                    "batchId": batch_id,
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

            # 5. Persist with exact owner checks and S3 version preconditions.
            self._write_owned_batch_profiles(
                auth=auth,
                ownership=ownership,
                batch_id=batch_id,
                bucket=bucket,
                profiles=profiles,
            )

            # 5b. Persist — individual profile files (P0.2)
            for profile in profiles:
                pid = profile["profileId"]
                self._write_owned_batch_child(
                    auth=auth,
                    ownership=ownership,
                    batch_id=batch_id,
                    bucket=bucket,
                    key=self._profile_key(ownership, pid),
                    record=profile,
                    object_kind="Employee profile",
                    identity_field="profileId",
                    identity_value=pid,
                )

            total_warnings = sum(len(p.get("warnings") or []) for p in profiles)
            has_issues = any(p.get("status") == "NEEDS_REVIEW" for p in profiles)

            job["profileCount"] = len(profiles)
            job["profileIds"] = profile_ids
            job["warningCount"] = total_warnings + job.get("warningCount", 0)
            job["status"] = "PARTIAL" if has_issues else "COMPLETED"
            job["completedAt"] = _utc_now_iso()
            job["updatedAt"] = _utc_now_iso()

            self._write_job_records(
                auth=auth,
                ownership=ownership,
                batch_id=batch_id,
                bucket=bucket,
                job=job,
            )

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
            self._write_job_records(
                auth=auth,
                ownership=ownership,
                batch_id=batch_id,
                bucket=bucket,
                job=job,
            )
            self.logger.error("employee_profiles_generate_failed", errorType=type(exc).__name__)
            raise

    def _load_batch_profiles(
        self,
        auth: AuthContext,
        batch_id: str,
        action: ObjectAction,
    ) -> Tuple[List[Dict[str, Any]], ObjectOwnership]:
        _batch, ownership = self._load_batch(auth, batch_id, action)
        data = self._read_s3_json(
            self._structured_bucket(),
            self._batch_profiles_key(ownership, batch_id),
        )
        if data is None:
            return [], ownership
        if not isinstance(data, list):
            self._hide_owned_record(auth, action, "Employee profile")
        profiles = [
            self._validate_batch_child(
                auth,
                record if isinstance(record, Mapping) else None,
                ownership=ownership,
                batch_id=batch_id,
                action=action,
                object_kind="Employee profile",
            )
            for record in data
        ]
        return profiles, ownership

    def get_batch_profiles(self, auth: AuthContext, batch_id: str) -> List[Dict[str, Any]]:
        """Return full profiles after batch and profile export authorization."""
        self._check_feature_enabled(auth.customer_id)
        profiles, _ownership = self._load_batch_profiles(
            auth,
            batch_id,
            ObjectAction.EXPORT,
        )
        return profiles

    # ─── Get job status ─────────────────────────────
    def get_job(
        self,
        auth: AuthContext,
        job_id: str,
        batch_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get generation job status.

        P0.2: Can look up by jobId directly (via jobs/{jobId}.json).
        Falls back to batch-level job if batchId is provided.
        """
        tenant = auth.customer_id
        self._check_feature_enabled(tenant)
        ownership = ObjectOwnership.from_auth(auth)
        bucket = self._structured_bucket()

        # Try direct job lookup first
        job = self._read_s3_json(bucket, self._job_key(ownership, job_id))
        if job is not None:
            authorize_owned_record(
                auth,
                job if isinstance(job, Mapping) else None,
                ObjectAction.READ,
                object_kind="Employee profile job",
            )
            stored_batch_id = job.get("batchId")
            if job.get("jobId") != job_id or not isinstance(stored_batch_id, str):
                self._hide_owned_record(auth, ObjectAction.READ, "Employee profile job")
            self._load_batch(auth, stored_batch_id, ObjectAction.READ)
            validated = self._validate_batch_child(
                auth,
                job,
                ownership=ownership,
                batch_id=stored_batch_id,
                action=ObjectAction.READ,
                object_kind="Employee profile job",
            )
            return _project_job_metadata(validated)

        # Fallback to batch-level lookup
        if batch_id:
            _batch, ownership = self._load_batch(auth, batch_id, ObjectAction.READ)
            job = self._read_s3_json(bucket, self._batch_job_key(ownership, batch_id))
            validated = self._validate_batch_child(
                auth,
                job if isinstance(job, Mapping) else None,
                ownership=ownership,
                batch_id=batch_id,
                action=ObjectAction.READ,
                object_kind="Employee profile job",
            )
            if validated.get("jobId") != job_id:
                self._hide_owned_record(auth, ObjectAction.READ, "Employee profile job")
            return _project_job_metadata(validated)

        self._hide_owned_record(auth, ObjectAction.READ, "Employee profile job")
        raise AssertionError("unreachable")

    # ─── List profiles ──────────────────────────────
    def list_profiles(
        self,
        auth: AuthContext,
        batch_id: Optional[str] = None,
        status_filter: Optional[str] = None,
        q: Optional[str] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """List profiles with masked identifiers and no identifying name data."""
        tenant = auth.customer_id
        self._check_feature_enabled(tenant)
        if q is not None:
            raise AppError(
                code="UNSUPPORTED_FILTER",
                message="Profile name search is not supported",
                status_code=400,
                details={},
            )
        ownership = ObjectOwnership.from_auth(auth)
        bucket = self._structured_bucket()

        if batch_id:
            profiles, ownership = self._load_batch_profiles(
                auth,
                batch_id,
                ObjectAction.EXPORT,
            )
        else:
            # P0.2: List from profiles/ prefix with basic pagination
            prefix = self._profiles_prefix(ownership)
            profiles = []
            try:
                resp = self.s3.list_objects_v2(
                    Bucket=bucket, Prefix=prefix, MaxKeys=min(limit * 2, 500)
                )
                for obj in resp.get("Contents", []):
                    record = self._read_s3_json(bucket, obj["Key"])
                    authorize_owned_record(
                        auth,
                        record if isinstance(record, Mapping) else None,
                        ObjectAction.EXPORT,
                        object_kind="Employee profile",
                    )
                    stored_batch_id = record.get("batchId")
                    if not isinstance(stored_batch_id, str):
                        self._hide_owned_record(auth, ObjectAction.EXPORT, "Employee profile")
                    self._load_batch(auth, stored_batch_id, ObjectAction.EXPORT)
                    profiles.append(
                        self._validate_batch_child(
                            auth,
                            record,
                            ownership=ownership,
                            batch_id=stored_batch_id,
                            action=ObjectAction.EXPORT,
                            object_kind="Employee profile",
                        )
                    )
            except ClientError as exc:
                self.logger.error(
                    "employee_profiles_list_failed",
                    errorType=type(exc).__name__,
                )
                raise AppError(
                    code="S3_READ_FAILED",
                    message="Failed to list employee profiles",
                    status_code=502,
                    details={},
                )

        # Filter by status
        if status_filter:
            profiles = [p for p in profiles if p.get("status", "").upper() == status_filter.upper()]

        total = len(profiles)
        profiles = profiles[:limit]

        # Build list-safe response (masked identifiers, no raw PII)
        list_profiles = []
        for p in profiles:
            list_profiles.append(project_masked_profile(p))

        return {"profiles": list_profiles, "total": total, "batchId": batch_id}

    # ─── Get profile detail ─────────────────────────
    def get_profile(
        self,
        auth: AuthContext,
        profile_id: str,
        batch_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get full profile detail.

        P0.2: Reads directly from profiles/{profileId}.json.
        Falls back to batch manifest if batch_id is provided.
        """
        tenant = auth.customer_id
        self._check_feature_enabled(tenant)
        ownership = ObjectOwnership.from_auth(auth)
        bucket = self._structured_bucket()

        # Try direct profile lookup (P0.2)
        profile = self._read_s3_json(bucket, self._profile_key(ownership, profile_id))
        if profile is not None:
            authorize_owned_record(
                auth,
                profile if isinstance(profile, Mapping) else None,
                ObjectAction.EXPORT,
                object_kind="Employee profile",
            )
            stored_batch_id = profile.get("batchId")
            if profile.get("profileId") != profile_id or not isinstance(stored_batch_id, str):
                self._hide_owned_record(auth, ObjectAction.EXPORT, "Employee profile")
            self._load_batch(auth, stored_batch_id, ObjectAction.EXPORT)
            return self._validate_batch_child(
                auth,
                profile,
                ownership=ownership,
                batch_id=stored_batch_id,
                action=ObjectAction.EXPORT,
                object_kind="Employee profile",
            )

        # Fallback to batch manifest lookup
        if batch_id:
            profiles, _ownership = self._load_batch_profiles(
                auth,
                batch_id,
                ObjectAction.EXPORT,
            )
            for candidate in profiles:
                if candidate.get("profileId") == profile_id:
                    return candidate

        self._hide_owned_record(auth, ObjectAction.EXPORT, "Employee profile")
        raise AssertionError("unreachable")

    # ─── Feature status check (P0.4) ───────────────
    def get_status(self, auth: AuthContext) -> Dict[str, Any]:
        """Return feature status for this tenant.

        P0.4: Requires JWT (handled by router). Does not expose tenant list.
        Returns enriched status with tenantEnabled and maxDocumentsPerBatch.
        """
        tenant = auth.customer_id
        enabled = self.settings.employee_profiles_enabled
        tenant_enabled = self._is_tenant_enabled(tenant)
        return {
            "enabled": enabled,
            "mode": self.settings.employee_profiles_mode if enabled else "disabled",
            "tenantEnabled": tenant_enabled,
            "maxDocumentsPerBatch": self.settings.employee_profiles_max_docs_per_batch,
        }
