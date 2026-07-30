from typing import Annotated, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator


VALIDATE_SCHEMA_VERSION = "scanalyze.validate.v2"
PERSIST_SCHEMA_VERSION = "scanalyze.persist.v2"
NOTIFY_SCHEMA_VERSION = "scanalyze.notify.v2"

NonEmptyString = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
CustomerId = Annotated[
    str,
    StringConstraints(strip_whitespace=True, pattern=r"^cust_[0-9A-HJKMNP-TV-Z]{26}$"),
]
DeploymentId = Annotated[
    str,
    StringConstraints(strip_whitespace=True, pattern=r"^dep_[0-9A-HJKMNP-TV-Z]{26}$"),
]


class OwnershipBoundMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    customer_id: CustomerId
    deployment_id: DeploymentId
    ownership_schema_version: Literal[1]
    processing_domain: Literal["bank", "personal", "gov"]


class MessageMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    correlationId: Optional[NonEmptyString] = None
    traceId: Optional[NonEmptyString] = None


class S3Location(BaseModel):
    model_config = ConfigDict(extra="forbid")
    bucket: NonEmptyString
    key: NonEmptyString


class ValidateMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")
    env: NonEmptyString
    tenant: NonEmptyString
    schema_version: NonEmptyString
    prompt_version: NonEmptyString


class ValidateMessage(OwnershipBoundMessage):
    """
    Input message for the validate queue (emitted by extract workers)
    """
    schemaVersion: Literal["scanalyze.validate.v2"] = VALIDATE_SCHEMA_VERSION
    pipeline_stage: Literal["validate"]
    documentId: NonEmptyString
    structured: S3Location
    meta: ValidateMeta
    correlationId: Optional[NonEmptyString] = None
    attempt: int = Field(default=0, ge=0)


class ValidationError(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: NonEmptyString
    message: NonEmptyString
    path: Optional[NonEmptyString] = None
    severity: Literal["ERROR", "WARNING"] = "ERROR"


class ValidationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["PASS", "FAIL"]
    errors: List[ValidationError] = Field(default_factory=list)
    validatedAt: NonEmptyString

    @model_validator(mode="after")
    def require_status_to_match_errors(self):
        has_error = any(error.severity == "ERROR" for error in self.errors)
        if self.status == "PASS" and has_error:
            raise ValueError("PASS validation cannot contain ERROR severity")
        if self.status == "FAIL" and not has_error:
            raise ValueError("FAIL validation requires at least one ERROR severity")
        return self


class PersistMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")
    env: NonEmptyString
    tenant: NonEmptyString
    schema_version: NonEmptyString
    prompt_version: NonEmptyString


class PersistMessage(OwnershipBoundMessage):
    """
    Input message for the persist queue (emitted by validate processor)
    """
    schemaVersion: Literal["scanalyze.persist.v2"] = PERSIST_SCHEMA_VERSION
    pipeline_stage: Literal["persist"]
    documentId: NonEmptyString
    structured: S3Location
    validation: ValidationResult
    meta: PersistMeta
    correlationId: Optional[NonEmptyString] = None
    attempt: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def require_artifact_for_pass(self):
        if self.validation.status == "PASS" and not (
            self.structured.bucket and self.structured.key
        ):
            raise ValueError("PASS persistence requires a complete structured pointer")
        return self


class NotifyResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finalStatus: Literal["COMPLETED", "FAILED"]
    completedAt: NonEmptyString
    validationStatus: Literal["PASS", "FAIL"]

    @model_validator(mode="after")
    def require_final_status_to_match_validation(self):
        expected = "COMPLETED" if self.validationStatus == "PASS" else "FAILED"
        if self.finalStatus != expected:
            raise ValueError("finalStatus does not match validationStatus")
        return self


class NotifyMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")
    env: NonEmptyString
    tenant: NonEmptyString


class NotifyMessage(OwnershipBoundMessage):
    """
    Input message for the notify queue (emitted by persist processor)
    """
    schemaVersion: Literal["scanalyze.notify.v2"] = NOTIFY_SCHEMA_VERSION
    pipeline_stage: Literal["notify"]
    documentId: NonEmptyString
    result: NotifyResult
    meta: NotifyMeta
    correlationId: Optional[NonEmptyString] = None
    attempt: int = Field(default=0, ge=0)
