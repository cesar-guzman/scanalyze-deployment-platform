from typing import Annotated, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator


VALIDATE_SCHEMA_VERSION = "scanalyze.validate.v1"
PERSIST_SCHEMA_VERSION = "scanalyze.persist.v1"
NOTIFY_SCHEMA_VERSION = "scanalyze.notify.v1"

NonEmptyString = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class S3Location(BaseModel):
    model_config = ConfigDict(extra="ignore")
    bucket: Optional[NonEmptyString] = None
    key: Optional[NonEmptyString] = None


class ValidateMeta(BaseModel):
    model_config = ConfigDict(extra="ignore")
    env: NonEmptyString
    tenant: NonEmptyString
    schema_version: NonEmptyString
    prompt_version: NonEmptyString


class ValidateMessage(BaseModel):
    """
    Input message for the validate queue (emitted by extract workers)
    """
    model_config = ConfigDict(extra="ignore")
    schemaVersion: Literal["scanalyze.validate.v1"] = VALIDATE_SCHEMA_VERSION
    documentId: NonEmptyString
    structured: S3Location
    meta: ValidateMeta
    correlationId: Optional[NonEmptyString] = None
    attempt: int = Field(default=0, ge=0)


class ValidationError(BaseModel):
    code: NonEmptyString
    message: NonEmptyString
    path: Optional[NonEmptyString] = None
    severity: Literal["ERROR", "WARNING"] = "ERROR"


class ValidationResult(BaseModel):
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
    model_config = ConfigDict(extra="ignore")
    env: NonEmptyString
    tenant: NonEmptyString
    schema_version: NonEmptyString
    prompt_version: NonEmptyString


class PersistMessage(BaseModel):
    """
    Input message for the persist queue (emitted by validate processor)
    """
    model_config = ConfigDict(extra="ignore")
    schemaVersion: Literal["scanalyze.persist.v1"] = PERSIST_SCHEMA_VERSION
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
    model_config = ConfigDict(extra="ignore")
    env: NonEmptyString
    tenant: NonEmptyString


class NotifyMessage(BaseModel):
    """
    Input message for the notify queue (emitted by persist processor)
    """
    model_config = ConfigDict(extra="ignore")
    schemaVersion: Literal["scanalyze.notify.v1"] = NOTIFY_SCHEMA_VERSION
    documentId: NonEmptyString
    result: NotifyResult
    meta: NotifyMeta
    correlationId: Optional[NonEmptyString] = None
    attempt: int = Field(default=0, ge=0)
