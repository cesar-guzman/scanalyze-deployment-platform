"""One-shot GUG-376 CloudFormation route broker.

The broker accepts only the content-free Lambda event ``{}``.  Every AWS
request is supplied by a sealed, closed configuration record and selected by
the exact invoked alias.  The orchestration core depends only on injectable
ports; AWS SDK modules are loaded lazily by the deployable top-level handlers.

Mutation outcomes are deliberately fail-closed.  A durable CAS moves the
ledger to ``*_ATTEMPTING`` before a provider call.  A successful one-shot
dispatch moves to ``*_DISPATCHED`` and persists the exact provider identifiers;
a later invocation of the same exact alias is a read-only continuation that
proves Change Set readiness or the terminal stack state without repeating the
mutation.  Pending or temporarily unavailable read evidence leaves the ledger
at ``*_DISPATCHED`` so only the read may be retried.  Ambiguous mutation
dispatch moves to terminal ``*_UNCERTAIN``.  No handler polls, retries a
provider mutation, or replays a completed effect.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
import re
from typing import Any, Callable, Mapping, Protocol, Sequence
from urllib.parse import parse_qs, urlsplit
import zlib


AUTHORITY_ACCOUNT_ID = "042360977644"
MANAGEMENT_ACCOUNT_ID = "839393571433"
REGION = "us-east-1"
ROUTE_BROKER_STACK_NAME = "scanalyze-platform-authority-gug376-route-broker"
CREATOR_FUNCTION_NAME = "scanalyze-platform-authority-gug376-route-creator"
EXECUTOR_FUNCTION_NAME = "scanalyze-platform-authority-gug376-route-executor"
CREATE_RECOVERY_FUNCTION_NAME = (
    "scanalyze-platform-authority-gug376-route-create-dispatch-recovery"
)
EXECUTE_RECOVERY_FUNCTION_NAME = (
    "scanalyze-platform-authority-gug376-route-execute-dispatch-recovery"
)
RECOVERY_ALIAS = "recover-v1"
AUTHORITY_CREATOR_ROLE_NAME = "ScanalyzeGug376RouteBrokerCreator"
AUTHORITY_EXECUTOR_ROLE_NAME = "ScanalyzeGug376RouteBrokerExecutor"
AUTHORITY_CREATE_RECOVERY_ROLE_NAME = (
    "ScanalyzeGug376RouteCreateDispatchRecovery"
)
AUTHORITY_EXECUTE_RECOVERY_ROLE_NAME = (
    "ScanalyzeGug376RouteExecuteDispatchRecovery"
)
MANAGEMENT_ROLE_PATH = "scanalyze/platform-authority/"
MANAGEMENT_CREATOR_ROLE_NAME = "ScanalyzeGug376RouteBrokerCreator"
MANAGEMENT_EXECUTOR_ROLE_NAME = "ScanalyzeGug376RouteBrokerExecutor"
MANAGEMENT_RECOVERY_ROLE_NAME = "ScanalyzeGug376RouteBrokerRecovery"
AUTHORITY_CREATOR_ROLE_ARN = (
    f"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:role/{AUTHORITY_CREATOR_ROLE_NAME}"
)
AUTHORITY_EXECUTOR_ROLE_ARN = (
    f"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:role/{AUTHORITY_EXECUTOR_ROLE_NAME}"
)
MANAGEMENT_CREATOR_ROLE_ARN = (
    f"arn:aws:iam::{MANAGEMENT_ACCOUNT_ID}:role/{MANAGEMENT_ROLE_PATH}"
    f"{MANAGEMENT_CREATOR_ROLE_NAME}"
)
MANAGEMENT_EXECUTOR_ROLE_ARN = (
    f"arn:aws:iam::{MANAGEMENT_ACCOUNT_ID}:role/{MANAGEMENT_ROLE_PATH}"
    f"{MANAGEMENT_EXECUTOR_ROLE_NAME}"
)
MANAGEMENT_RECOVERY_ROLE_ARN = (
    f"arn:aws:iam::{MANAGEMENT_ACCOUNT_ID}:role/{MANAGEMENT_ROLE_PATH}"
    f"{MANAGEMENT_RECOVERY_ROLE_NAME}"
)
PLAN_STACK_NAME = "scanalyze-platform-authority-state-backend"
NORMAL_PLAN_CALLER_BINDING_KEY = "normal_plan.caller_arn_digest"
TERMINAL_PARAMETERS_BINDING_PREFIX = "terminal_parameters."
NORMAL_PLAN_MAX_EVENT_AGE_SECONDS = 900
MIN_ROUTE_WINDOW_SECONDS = 3_600
MUTATION_COMPLETION_RESERVE_SECONDS = 1_800
MUTATION_DISPATCH_MIN_REMAINING_MS = 45_000
READ_CONTINUATION_MIN_REMAINING_MS = 15_000
READBACK_CAS_MIN_REMAINING_MS = 10_000
REPAIR_LEDGER_TABLE_NAME = (
    "scanalyze-platform-authority-plan-policy-repair-ledger"
)
ROUTE_LEDGER_TABLE_NAME = (
    "scanalyze-platform-authority-gug376-route-broker-ledger"
)
ROUTE_LEDGER_ID = "gug376-route-broker"
REPAIR_INVOKER_PERMISSION_SET_SENTINEL = (
    "__DERIVED_DELEGATION_REPAIR_INVOKER_PERMISSION_SET_ARN__"
)

CONFIG_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_route_broker_config.v1"
)
COMPRESSED_CONFIG_RECORD_TYPE = (
    "scanalyze.platform_authority."
    "plan_permission_repair_route_broker_config_compact_deflate_dict.v2"
)
LEDGER_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_route_broker_ledger.v1"
)
RECEIPT_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_route_broker_receipt.v1"
)
ATTEMPT_CLAIM_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_route_broker_attempt_claim.v1"
)
TERMINAL_READBACK_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_terminal_readback.v1"
)
ASSIGNMENT_READBACK_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_assignment_readback.v1"
)
CHANGE_SET_READBACK_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_change_set_readback.v1"
)
REPAIR_LEDGER_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_ledger.v1"
)
RECONCILE_ATTESTATION_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_reconcile_attestation.v1"
)
PLAN_EVENT_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_plan_cloudtrail_event.v1"
)
PLAN_PREFLIGHT_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_plan_preflight.v1"
)
CREATE_RECOVERY_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_create_dispatch_recovery.v1"
)
EXECUTE_RECOVERY_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_execute_dispatch_recovery.v1"
)

CREATOR_ALIASES = (
    "seed-revoke-create-v1",
    "delegation-create-v1",
    "pep-create-v1",
    "pep-protection-create-v1",
    "closeout-gate-v1",
    "delegation-revoke-create-v1",
    "route-revoke-create-v1",
)
EXECUTOR_ALIASES = (
    "seed-revoke-execute-v1",
    "delegation-execute-v1",
    "pep-execute-v1",
    "pep-protection-execute-v1",
    "delegation-revoke-execute-v1",
    "route-revoke-execute-v1",
)
MUTATING_CREATOR_ALIASES = tuple(
    alias for alias in CREATOR_ALIASES if alias != "closeout-gate-v1"
)
ALL_ALIASES = CREATOR_ALIASES + EXECUTOR_ALIASES
RECOVERY_RECEIPT_ALIASES = (
    "create-dispatch-recovery-v1",
    "execute-dispatch-recovery-v1",
)

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_REPAIR_ID_RE = re.compile(r"^gug376-plan-permission-repair-[0-9a-f]{64}$")
_VERSION_RE = re.compile(r"^[1-9][0-9]*$")
_ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
_INSTANCE_RE = re.compile(r"^arn:aws[a-z-]*:sso:::instance/ssoins-[A-Za-z0-9]{16}$")
_PRINCIPAL_RE = re.compile(
    r"^(?:[0-9a-f]{10}-)?[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$"
)
_PERMISSION_SET_RE = re.compile(
    r"^arn:aws[a-z-]*:sso:::permissionSet/ssoins-[A-Za-z0-9]{16}/"
    r"ps-[A-Za-z0-9]{16}$"
)
_CHANGE_SET_ARN_RE = re.compile(
    r"^arn:aws[a-z-]*:cloudformation:us-east-1:[0-9]{12}:changeSet/[^/]+/[0-9a-f-]{36}$"
)
_STACK_ARN_RE = re.compile(
    r"^arn:aws[a-z-]*:cloudformation:us-east-1:[0-9]{12}:stack/[^/]+/[0-9a-f-]{36}$"
)
_AUTHORITY_KMS_KEY_ARN_RE = re.compile(
    rf"^arn:aws[a-z-]*:kms:{REGION}:{AUTHORITY_ACCOUNT_ID}:key/"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_STACK_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,127}$")
_CHANGE_SET_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,127}$")
_CLIENT_TOKEN_RE = re.compile(r"^[A-Za-z0-9][-A-Za-z0-9]{0,127}$")
_NORMAL_PLAN_ROLE_NAME_RE = re.compile(
    r"^AWSReservedSSO_ScanalyzeAuthorityBootstrapPlan_[0-9A-Fa-f]{16}$"
)
_NORMAL_PLAN_SESSION_RE = re.compile(r"^[A-Za-z0-9+=,.@_-]{1,64}$")
_CONFIG_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "ledger_id",
        "ledger_binding_digest",
        "initialization_digest",
        "foundation_publish_binding_digest",
        "repair_id",
        "bootstrap_change_set_name",
        "identity_center_instance_arn",
        "bootstrap_principal_id",
        "route_not_before",
        "route_not_after",
        "recovery_not_after",
        "normal_plan_generated_role_arn",
        "normal_plan_generated_role_name",
        "requests",
        "creator_contracts",
        "permission_set_output_contracts",
        "terminal_expectations",
        "revocation_assignment_scopes",
        "retry_permitted",
        "production_authorized",
        "production_status",
        "config_digest",
    }
)
_COMPRESSED_CONFIG_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "encoding",
        "payload",
    }
)
_RUNTIME_CONFIG_DICTIONARY = b"""
schema_version record_type source_commit ledger_id ledger_binding_digest
initialization_digest repair_id bootstrap_change_set_name
foundation_publish_binding_digest
identity_center_instance_arn bootstrap_principal_id route_not_before
route_not_after recovery_not_after normal_plan_generated_role_arn
normal_plan_generated_role_name requests creator_contracts
permission_set_output_contracts terminal_expectations
revocation_assignment_scopes retry_permitted production_authorized
production_status config_digest StackName ChangeSetName ChangeSetType
Description Parameters ParameterKey ParameterValue Capabilities Tags
IncludeNestedStacks ResourcesToImport NotificationARNs RollbackConfiguration
MonitoringTimeInMinutes RollbackTriggers TemplateURL ClientToken
ClientRequestToken DisableRollback template_digest expected_changes action
logical_resource_id resource_type replacement scope account_id stack_name
details target_attribute target_name requires_recreation evaluation
change_source causing_entity DeletionPolicy UpdateReplacePolicy
DeletionProtectionEnabled DirectModification Static Dynamic Never
{"causing_entity":null,"change_source":"DirectModification","evaluation":"Static","requires_recreation":null,"target_attribute":"DeletionPolicy","target_name":null}
{"causing_entity":null,"change_source":"DirectModification","evaluation":"Static","requires_recreation":null,"target_attribute":"UpdateReplacePolicy","target_name":null}
{"causing_entity":null,"change_source":"DirectModification","evaluation":"Static","requires_recreation":"Never","target_attribute":"Properties","target_name":"DeletionProtectionEnabled"}
{"action":"Add","details":[],"logical_resource_id":
{"action":"Modify","details":[{"causing_entity":null,"change_source":"DirectModification","evaluation":"Static","requires_recreation":null,"target_attribute":"DeletionPolicy","target_name":null},{"causing_entity":null,"change_source":"DirectModification","evaluation":"Static","requires_recreation":null,"target_attribute":"UpdateReplacePolicy","target_name":null}],"logical_resource_id":
"replacement":"False","scope":["DeletionPolicy","UpdateReplacePolicy"]
"replacement":null,"scope":[]
[{"action":"Modify","details":[{"causing_entity":null,"change_source":"DirectModification","evaluation":"Static","requires_recreation":null,"target_attribute":"DeletionPolicy","target_name":null},{"causing_entity":null,"change_source":"DirectModification","evaluation":"Static","requires_recreation":null,"target_attribute":"UpdateReplacePolicy","target_name":null}],"logical_resource_id":"PlanLogGroup","replacement":"False","resource_type":"AWS::Logs::LogGroup","scope":["DeletionPolicy","UpdateReplacePolicy"]},{"action":"Modify","details":[{"causing_entity":null,"change_source":"DirectModification","evaluation":"Static","requires_recreation":null,"target_attribute":"DeletionPolicy","target_name":null},{"causing_entity":null,"change_source":"DirectModification","evaluation":"Static","requires_recreation":null,"target_attribute":"UpdateReplacePolicy","target_name":null}],"logical_resource_id":"ReconcileLogGroup","replacement":"False","resource_type":"AWS::Logs::LogGroup","scope":["DeletionPolicy","UpdateReplacePolicy"]},{"action":"Modify","details":[{"causing_entity":null,"change_source":"DirectModification","evaluation":"Static","requires_recreation":null,"target_attribute":"DeletionPolicy","target_name":null},{"causing_entity":null,"change_source":"DirectModification","evaluation":"Static","requires_recreation":"Never","target_attribute":"Properties","target_name":"DeletionProtectionEnabled"},{"causing_entity":null,"change_source":"DirectModification","evaluation":"Static","requires_recreation":null,"target_attribute":"UpdateReplacePolicy","target_name":null}],"logical_resource_id":"RepairLedger","replacement":"False","resource_type":"AWS::DynamoDB::Table","scope":["DeletionPolicy","Properties","UpdateReplacePolicy"]},{"action":"Modify","details":[{"causing_entity":null,"change_source":"DirectModification","evaluation":"Static","requires_recreation":null,"target_attribute":"DeletionPolicy","target_name":null},{"causing_entity":null,"change_source":"DirectModification","evaluation":"Static","requires_recreation":null,"target_attribute":"UpdateReplacePolicy","target_name":null}],"logical_resource_id":"RepairLedgerKey","replacement":"False","resource_type":"AWS::KMS::Key","scope":["DeletionPolicy","UpdateReplacePolicy"]},{"action":"Modify","details":[{"causing_entity":null,"change_source":"DirectModification","evaluation":"Static","requires_recreation":null,"target_attribute":"DeletionPolicy","target_name":null},{"causing_entity":null,"change_source":"DirectModification","evaluation":"Static","requires_recreation":null,"target_attribute":"UpdateReplacePolicy","target_name":null}],"logical_resource_id":"RepairLedgerKeyAlias","replacement":"False","resource_type":"AWS::KMS::Alias","scope":["DeletionPolicy","UpdateReplacePolicy"]},{"action":"Modify","details":[{"causing_entity":null,"change_source":"DirectModification","evaluation":"Static","requires_recreation":null,"target_attribute":"DeletionPolicy","target_name":null},{"causing_entity":null,"change_source":"DirectModification","evaluation":"Static","requires_recreation":null,"target_attribute":"UpdateReplacePolicy","target_name":null}],"logical_resource_id":"RepairLogGroup","replacement":"False","resource_type":"AWS::Logs::LogGroup","scope":["DeletionPolicy","UpdateReplacePolicy"]}]
terminal_statuses expected_resources expected_output_keys
expected_static_outputs expected_tags instance_arn permission_set_sources
source output_key AWS:: CloudFormation us-east-1
scanalyze-platform-authority-gug376 temporary route broker delegation pep
create execute revoke permissionSet arn:aws:sso:::permissionSet/ssoins-
sha256: arn:aws: cloudformation.amazonaws.com managed_by terraform
SourceCommit IdentityCenterInstanceArn RepairInvokerPermissionSetArn
ImmutableConfigurationDigest
AWS::IAM::Role AWS::SSO::PermissionSet AWS::SSO::Assignment
AWS::Lambda::Alias AWS::Lambda::EventInvokeConfig AWS::Lambda::Function
AWS::Lambda::Version AWS::Lambda::RuntimeManagementConfig
AWS::Lambda::CodeSigningConfig AWS::Logs::LogGroup AWS::DynamoDB::Table
AWS::KMS::Key AWS::KMS::Alias
ParameterKey ParameterValue UsePreviousValue logical_resource_id
resource_type replacement expected_output_keys expected_resources
expected_static_outputs expected_tags terminal_statuses output_key
permission_set_sources permission_set_output_keys required_mode_outputs
ProductionAuthorized RepairInvokerPermissionSetArn
RepairInvokerAssignmentMode BrokerInvokerAssignmentMode SeedAssignmentMode
BrokerInvokerPermissionSetArn BrokerSeedCreatorPermissionSetArn
BrokerSeedExecutorPermissionSetArn RepairPrincipalIdDigestRequired
BrokerStackName MutationServiceRole ReadbackServiceRole
RepairInvokerAssignment RepairInvokerPermissionSet PlanPermissionSetArn
IdentityCenterKmsKeyArn UPDATE_COMPLETE CREATE_COMPLETE
InvocationAuthorityInspectorRole PlanAlias PlanEventInvokeConfig
PlanExecutionRole PlanFunction PlanFunctionVersion PlanLogGroup
PlanRuntimeManagementConfig ReconcileAlias ReconcileEventInvokeConfig
ReconcileExecutionRole ReconcileFunction ReconcileFunctionVersion
ReconcileLogGroup ReconcileRuntimeManagementConfig RepairAlias
RepairCodeSigningConfig RepairEventInvokeConfig RepairExecutionRole
RepairFunction RepairFunctionVersion RepairLedger RepairLedgerKey
RepairLedgerKeyAlias RepairLogGroup RepairRuntimeManagementConfig
BrokerInvokerAssignment BrokerInvokerPermissionSet
BrokerSeedCreatorPermissionSet BrokerSeedExecutorPermissionSet
ManagementAccountId AuthorityAccountId SourceCommit
IdentityCenterInstanceArn IdentityStoreArn RepairPrincipalId
RepairPrincipalUserArn RepairInvokerAssignmentEnabled
UseIdentityCenterCustomerManagedKms BootstrapPrincipalId
SeedAssignmentsEnabled BrokerInvokerAssignmentEnabled RouteNotBefore
RouteNotAfter RouteTemplateBucket RouteTemplateKey RouteTemplateVersion
RouteTemplateUrl DelegationTemplateBucket DelegationTemplateKey
DelegationTemplateVersion DelegationTemplateUrl BrokerSeedTemplateBucket
BrokerSeedTemplateKey BrokerSeedTemplateVersion BrokerSeedTemplateUrl
BrokerCodeBucket BrokerCodeKey BrokerCodeVersion
BrokerSigningProfileVersionArn MutationServiceRoleArn ReadbackServiceRoleArn
CleanupOrder ManagementBrokerCreatorRoleArn ManagementBrokerExecutorRoleArn
ManagementBrokerCreatorRole ManagementBrokerExecutorRole
delegation-create-v1 delegation-revoke-create-v1 pep-create-v1
pep-protection-create-v1 pep-protection-execute-v1
route-revoke-create-v1 seed-revoke-create-v1
delegation-revoke-execute-v1 route-revoke-execute-v1
seed-revoke-execute-v1
scanalyze-platform-authority-bootstrap-plan-repair-delegation
scanalyze-platform-authority-gug376-temporary-change-set-route
scanalyze-platform-authority-bootstrap-plan-repair-pep
scanalyze-platform-authority-gug376-route-broker
{"logical_resource_id":"BrokerInvokerAssignment","resource_type":"AWS::SSO::Assignment"}
{"logical_resource_id":"BrokerInvokerPermissionSet","resource_type":"AWS::SSO::PermissionSet"}
{"logical_resource_id":"BrokerSeedCreatorPermissionSet","resource_type":"AWS::SSO::PermissionSet"}
{"logical_resource_id":"BrokerSeedExecutorPermissionSet","resource_type":"AWS::SSO::PermissionSet"}
{"logical_resource_id":"InvocationAuthorityInspectorRole","resource_type":"AWS::IAM::Role"}
{"logical_resource_id":"ManagementBrokerCreatorRole","resource_type":"AWS::IAM::Role"}
{"logical_resource_id":"ManagementBrokerExecutorRole","resource_type":"AWS::IAM::Role"}
{"logical_resource_id":"MutationServiceRole","resource_type":"AWS::IAM::Role"}
{"logical_resource_id":"PlanAlias","resource_type":"AWS::Lambda::Alias"}
{"logical_resource_id":"PlanEventInvokeConfig","resource_type":"AWS::Lambda::EventInvokeConfig"}
{"logical_resource_id":"PlanExecutionRole","resource_type":"AWS::IAM::Role"}
{"logical_resource_id":"PlanFunction","resource_type":"AWS::Lambda::Function"}
{"logical_resource_id":"PlanFunctionVersion","resource_type":"AWS::Lambda::Version"}
{"logical_resource_id":"PlanLogGroup","resource_type":"AWS::Logs::LogGroup"}
{"logical_resource_id":"PlanRuntimeManagementConfig","resource_type":"AWS::Lambda::RuntimeManagementConfig"}
{"logical_resource_id":"ReadbackServiceRole","resource_type":"AWS::IAM::Role"}
{"logical_resource_id":"ReconcileAlias","resource_type":"AWS::Lambda::Alias"}
{"logical_resource_id":"ReconcileEventInvokeConfig","resource_type":"AWS::Lambda::EventInvokeConfig"}
{"logical_resource_id":"ReconcileExecutionRole","resource_type":"AWS::IAM::Role"}
{"logical_resource_id":"ReconcileFunction","resource_type":"AWS::Lambda::Function"}
{"logical_resource_id":"ReconcileFunctionVersion","resource_type":"AWS::Lambda::Version"}
{"logical_resource_id":"ReconcileLogGroup","resource_type":"AWS::Logs::LogGroup"}
{"logical_resource_id":"ReconcileRuntimeManagementConfig","resource_type":"AWS::Lambda::RuntimeManagementConfig"}
{"logical_resource_id":"RepairAlias","resource_type":"AWS::Lambda::Alias"}
{"logical_resource_id":"RepairCodeSigningConfig","resource_type":"AWS::Lambda::CodeSigningConfig"}
{"logical_resource_id":"RepairEventInvokeConfig","resource_type":"AWS::Lambda::EventInvokeConfig"}
{"logical_resource_id":"RepairExecutionRole","resource_type":"AWS::IAM::Role"}
{"logical_resource_id":"RepairFunction","resource_type":"AWS::Lambda::Function"}
{"logical_resource_id":"RepairFunctionVersion","resource_type":"AWS::Lambda::Version"}
{"logical_resource_id":"RepairInvokerAssignment","resource_type":"AWS::SSO::Assignment"}
{"logical_resource_id":"RepairInvokerPermissionSet","resource_type":"AWS::SSO::PermissionSet"}
{"logical_resource_id":"RepairLedger","resource_type":"AWS::DynamoDB::Table"}
{"logical_resource_id":"RepairLedgerKey","resource_type":"AWS::KMS::Key"}
{"logical_resource_id":"RepairLedgerKeyAlias","resource_type":"AWS::KMS::Alias"}
{"logical_resource_id":"RepairLogGroup","resource_type":"AWS::Logs::LogGroup"}
{"logical_resource_id":"RepairRuntimeManagementConfig","resource_type":"AWS::Lambda::RuntimeManagementConfig"}
AWS::Lambda::Function AWS::Lambda::Alias AWS::Lambda::Version
AWS::Logs::LogGroup AWS::DynamoDB::Table AWS::KMS::Key AWS::KMS::Alias
AWS::Signer::SigningProfile AWS::Lambda::CodeSigningConfig
ManagementBrokerCreatorRole ManagementBrokerExecutorRole
BrokerSeedCreatorPermissionSet BrokerSeedExecutorPermissionSet
BrokerInvokerPermissionSet BrokerSeedCreatorAssignment
BrokerSeedExecutorAssignment BrokerInvokerAssignment MutationServiceRole
ReadbackServiceRole RepairInvokerPermissionSet RepairInvokerAssignment
PlanFunction RepairFunction ReconcileFunction PlanVersion RepairVersion
ReconcileVersion PlanAlias RepairAlias ReconcileAlias PlanPermission
RepairPermission ReconcilePermission PlanLogGroup RepairLogGroup
ReconcileLogGroup RepairLedgerKey RepairLedgerAlias RepairLedgerTable
RepairRuntimeManagementConfig ReconcileRuntimeManagementConfig
pep-protection-create-v1 pep-protection-execute-v1
gug376-plan-repair-pep-protection-enable
PEP_PROTECTION_CREATE_ATTEMPTING PEP_PROTECTION_CREATE_UNCERTAIN
PEP_PROTECTION_CREATED PEP_PROTECTION_EXECUTE_ATTEMPTING
PEP_PROTECTION_EXECUTE_UNCERTAIN PEP_PROTECTED
LedgerDeletionProtectionEnabled LedgerDeletionProtectionMode
{"ParameterKey":"LedgerDeletionProtectionEnabled","ParameterValue":"true"}
{"ParameterKey":"LedgerDeletionProtectionEnabled","UsePreviousValue":true}
ExpectedPermissionSetDescription CurrentPolicyDigest DesiredPolicyDigest
ExpectedPlanPermissionSetTagsJson BootstrapChangeSetName RepairNotBefore
RepairNotAfter PlanSamlProviderArn IdentityCenterKmsMode
IdentityCenterKmsKeyArn ExpectedBoto3Version ExpectedBotocoreVersion
ArtifactBucket ArtifactKey ArtifactVersion ArtifactCodeSha256
SigningProfileVersionArn AuthorityAccountId ManagementAccountId
IdentityStoreId PrincipalId SourceBundleDigest UsePreviousValue
SeedAssignmentsEnabled BrokerInvokerAssignmentEnabled
RepairInvokerAssignmentEnabled ProductionAuthorized AssignmentMode
PermissionSetArn CleanupOrder service work_package cloudformation GUG-376
{"account_id":"042360977644","expected_output_keys":["InvocationAuthorityInspectorRoleArn","LedgerDeletionProtectionMode","PlanExecutionRoleArn","PlanFunctionAliasArn","ProductionAuthorized","ReconcileExecutionRoleArn","ReconcileFunctionAliasArn","RepairExecutionRoleArn","RepairFunctionAliasArn","RepairLedgerKeyArn","RepairLedgerName"],"expected_resources":[{"logical_resource_id":"InvocationAuthorityInspectorRole","resource_type":"AWS::IAM::Role"},{"logical_resource_id":"PlanAlias","resource_type":"AWS::Lambda::Alias"},{"logical_resource_id":"PlanEventInvokeConfig","resource_type":"AWS::Lambda::EventInvokeConfig"},{"logical_resource_id":"PlanExecutionRole","resource_type":"AWS::IAM::Role"},{"logical_resource_id":"PlanFunction","resource_type":"AWS::Lambda::Function"},{"logical_resource_id":"PlanFunctionVersion","resource_type":"AWS::Lambda::Version"},{"logical_resource_id":"PlanLogGroup","resource_type":"AWS::Logs::LogGroup"},{"logical_resource_id":"PlanRuntimeManagementConfig","resource_type":"AWS::Lambda::RuntimeManagementConfig"},{"logical_resource_id":"ReconcileAlias","resource_type":"AWS::Lambda::Alias"},{"logical_resource_id":"ReconcileEventInvokeConfig","resource_type":"AWS::Lambda::EventInvokeConfig"},{"logical_resource_id":"ReconcileExecutionRole","resource_type":"AWS::IAM::Role"},{"logical_resource_id":"ReconcileFunction","resource_type":"AWS::Lambda::Function"},{"logical_resource_id":"ReconcileFunctionVersion","resource_type":"AWS::Lambda::Version"},{"logical_resource_id":"ReconcileLogGroup","resource_type":"AWS::Logs::LogGroup"},{"logical_resource_id":"ReconcileRuntimeManagementConfig","resource_type":"AWS::Lambda::RuntimeManagementConfig"},{"logical_resource_id":"RepairAlias","resource_type":"AWS::Lambda::Alias"},{"logical_resource_id":"RepairCodeSigningConfig","resource_type":"AWS::Lambda::CodeSigningConfig"},{"logical_resource_id":"RepairEventInvokeConfig","resource_type":"AWS::Lambda::EventInvokeConfig"},{"logical_resource_id":"RepairExecutionRole","resource_type":"AWS::IAM::Role"},{"logical_resource_id":"RepairFunction","resource_type":"AWS::Lambda::Function"},{"logical_resource_id":"RepairFunctionVersion","resource_type":"AWS::Lambda::Version"},{"logical_resource_id":"RepairLedger","resource_type":"AWS::DynamoDB::Table"},{"logical_resource_id":"RepairLedgerKey","resource_type":"AWS::KMS::Key"},{"logical_resource_id":"RepairLedgerKeyAlias","resource_type":"AWS::KMS::Alias"},{"logical_resource_id":"RepairLogGroup","resource_type":"AWS::Logs::LogGroup"},{"logical_resource_id":"RepairRuntimeManagementConfig","resource_type":"AWS::Lambda::RuntimeManagementConfig"}],"expected_static_outputs":{"LedgerDeletionProtectionMode":"true","ProductionAuthorized":"false"},"expected_tags":[{"Key":"managed_by","Value":"cloudformation"},{"Key":"service","Value":"scanalyze-platform-authority"},{"Key":"work_package","Value":"GUG-376"}],"stack_name":"scanalyze-platform-authority-bootstrap-plan-repair-pep","template_digest":"sha256:","terminal_statuses":["UPDATE_COMPLETE"]}
{"delegation":{"account_id":"839393571433","permission_set_output_keys":["RepairInvokerPermissionSetArn"],"required_mode_outputs":{"RepairInvokerAssignmentMode":"true"},"stack_name":"scanalyze-platform-authority-bootstrap-plan-repair-delegation"},"route":{"account_id":"839393571433","permission_set_output_keys":["BrokerInvokerPermissionSetArn","BrokerSeedCreatorPermissionSetArn","BrokerSeedExecutorPermissionSetArn"],"required_mode_outputs":{"BrokerInvokerAssignmentMode":"true","SeedAssignmentMode":"true"},"stack_name":"scanalyze-platform-authority-gug376-temporary-change-set-route"}}
{"delegation-revoke-execute-v1":{"account_id":"042360977644","instance_arn":"","permission_set_sources":[{"output_key":"RepairInvokerPermissionSetArn","source":"delegation"}]},"route-revoke-execute-v1":{"account_id":"042360977644","instance_arn":"","permission_set_sources":[{"output_key":"BrokerInvokerPermissionSetArn","source":"route"}]},"seed-revoke-execute-v1":{"account_id":"042360977644","instance_arn":"","permission_set_sources":[{"output_key":"BrokerSeedCreatorPermissionSetArn","source":"route"},{"output_key":"BrokerSeedExecutorPermissionSetArn","source":"route"}]}}
"""
_TERMINAL_EXPECTATION_FIELDS = frozenset(
    {
        "account_id",
        "stack_name",
        "terminal_statuses",
        "template_digest",
        "expected_resources",
        "expected_output_keys",
        "expected_static_outputs",
        "expected_tags",
    }
)
_STACK_RESOURCE_FIELDS = frozenset({"logical_resource_id", "resource_type"})
_ASSIGNMENT_SCOPE_FIELDS = frozenset(
    {"account_id", "instance_arn", "permission_set_sources"}
)
_PERMISSION_SET_SOURCE_FIELDS = frozenset({"source", "output_key"})
_OUTPUT_CONTRACT_FIELDS = frozenset(
    {
        "account_id",
        "stack_name",
        "permission_set_output_keys",
        "required_mode_outputs",
    }
)
_CREATOR_CONTRACT_FIELDS = frozenset({"template_digest", "expected_changes"})
_EXPECTED_CHANGE_FIELDS = frozenset(
    {
        "action",
        "logical_resource_id",
        "resource_type",
        "replacement",
        "scope",
        "details",
    }
)
_CHANGE_DETAIL_FIELDS = frozenset(
    {
        "target_attribute",
        "target_name",
        "requires_recreation",
        "evaluation",
        "change_source",
        "causing_entity",
    }
)
_CREATE_RESPONSE_FIELDS = frozenset(
    {"change_set_arn", "stack_id", "request_id"}
)
_EXECUTE_RESPONSE_FIELDS = frozenset({"request_id"})
_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "ledger_id_digest",
        "config_digest",
        "alias",
        "function_version",
        "state",
        "request_digest",
        "provider_digest",
        "change_set_readback_digest",
        "terminal_readback_digest",
        "assignment_readback_digest",
        "assignment_readback_count",
        "closeout_evidence_digest",
        "normal_plan_caller_arn_digest",
        "aws_mutations",
        "retry_permitted",
        "production_authorized",
        "production_status",
        "event_fields_consumed",
        "generated_at",
        "receipt_digest",
    }
)
_ATTEMPT_CLAIM_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "config_digest",
        "ledger_id_digest",
        "kind",
        "operation",
        "function_version",
        "expected_state",
        "attempting_state",
        "request",
        "request_digest",
        "claimed_at",
        "claim_digest",
    }
)
_CREATE_RECOVERY_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "account_id",
        "region",
        "operation",
        "claim_digest",
        "request_digest",
        "dispatch",
        "change_set_readback",
        "recovered_at",
        "recovery_digest",
    }
)
_EXECUTE_RECOVERY_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "account_id",
        "region",
        "operation",
        "claim_digest",
        "request_digest",
        "dispatch",
        "change_set_snapshot",
        "recovered_at",
        "recovery_digest",
    }
)
_RECOVERED_CHANGE_SET_SNAPSHOT_FIELDS = frozenset(
    {
        "stack_arn",
        "change_set_arn",
        "status",
        "execution_status",
        "creator_request_digest",
        "execute_request_digest",
        "template_digest",
        "changes_digest",
        "parameters_digest",
        "tags_digest",
        "role_arn_absent",
        "resources_to_import_absent",
        "cloudtrail_event_digest",
        "read_at",
    }
)
_CREATE_REQUEST_FIELDS = frozenset(
    {
        "StackName",
        "ChangeSetName",
        "ChangeSetType",
        "Description",
        "Parameters",
        "Capabilities",
        "Tags",
        "IncludeNestedStacks",
        "ResourcesToImport",
        "NotificationARNs",
        "RollbackConfiguration",
        "TemplateURL",
        "ClientToken",
    }
)
_CREATE_ON_FAILURE_FIELDS = _CREATE_REQUEST_FIELDS | frozenset({"OnStackFailure"})
_EXECUTE_REQUEST_FIELDS = frozenset(
    {"StackName", "ChangeSetName", "ClientRequestToken"}
)
_UPDATE_EXECUTE_REQUEST_FIELDS = _EXECUTE_REQUEST_FIELDS | frozenset(
    {"DisableRollback"}
)
_COMPACT_CREATE_REQUEST_FIELDS = frozenset(
    {"StackName", "ChangeSetName", "ChangeSetType", "Parameters", "TemplateURL"}
)
_CREATE_TO_EXECUTE = {
    "seed-revoke-create-v1": "seed-revoke-execute-v1",
    "delegation-create-v1": "delegation-execute-v1",
    "pep-create-v1": "pep-execute-v1",
    "pep-protection-create-v1": "pep-protection-execute-v1",
    "delegation-revoke-create-v1": "delegation-revoke-execute-v1",
    "route-revoke-create-v1": "route-revoke-execute-v1",
}
_EXACT_STACK_TAGS = [
    {"Key": "managed_by", "Value": "cloudformation"},
    {"Key": "service", "Value": "scanalyze-platform-authority"},
    {"Key": "work_package", "Value": "GUG-376"},
]
_CHANGE_SET_READBACK_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "operation",
        "source_commit",
        "account_id",
        "region",
        "stack_name",
        "change_set_name",
        "stack_arn",
        "change_set_arn",
        "create_request_id",
        "creation_time",
        "status",
        "execution_status",
        "role_arn_absent",
        "resources_to_import_absent",
        "request_contract_digest",
        "template_digest",
        "changes_digest",
        "terminal_parameters_digest",
        "cloudtrail_event_digest",
        "derived_permission_set_arns",
        "source_stack_digest",
        "parent_receipt_digest",
        "read_at",
        "readback_digest",
    }
)
_TERMINAL_READBACK_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "operation",
        "source_commit",
        "account_id",
        "region",
        "stack_name",
        "stack_arn",
        "execute_request_id",
        "execute_cloudtrail_event_digest",
        "stack_terminal_event_time",
        "stack_terminal_event_digest",
        "stack_last_updated_time",
        "role_arn_absent",
        "parent_id_absent",
        "root_id_absent",
        "notification_arns",
        "template_digest",
        "stack_resources_digest",
        "stack_resource_count",
        "stack_outputs_digest",
        "stack_tags_digest",
        "stack_parameters_digest",
        "live_control",
        "live_control_digest",
        "derived_permission_set_arns",
        "source_stack_digest",
        "stack_status",
        "terminal",
        "parent_receipt_digest",
        "read_at",
        "readback_digest",
    }
)
_PEP_LEDGER_LIVE_CONTROL_FIELDS = frozenset(
    {
        "table_name",
        "table_arn",
        "table_status",
        "deletion_protection_enabled",
        "sse_status",
        "sse_type",
        "kms_key_arn",
    }
)
_ASSIGNMENT_READBACK_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "operation",
        "source_commit",
        "account_id",
        "region",
        "instance_arn",
        "permission_set_arn",
        "assignment_count",
        "terminal",
        "terminal_readback_digest",
        "read_at",
        "readback_digest",
    }
)
_REPAIR_LEDGER_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "repair_id",
        "intent_digest",
        "source_commit",
        "status",
        "stage",
        "effects_attempted",
        "effects_completed",
        "planned_state_digest",
        "state_digest",
        "planned_at",
        "provider_immutable",
        "claim_condition",
        "mutation_retry_attempted",
        "retry_permitted",
        "production_authorized",
        "claimed_at",
        "updated_at",
        "ledger_digest",
    }
)
_ATTESTATION_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "repair_id",
        "base_repair_id",
        "source_commit",
        "intent_digest",
        "repair_ledger_digest",
        "observed_state_digest",
        "invocation_authority_graph_digest",
        "function_version",
        "function_qualifier",
        "status",
        "reconciled_at",
        "claim_condition",
        "retry_permitted",
        "production_authorized",
        "attestation_digest",
    }
)
_PLAN_EVENT_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "event_id",
        "event_source",
        "event_name",
        "event_time",
        "aws_region",
        "recipient_account_id",
        "read_only",
        "success",
        "caller_arn",
        "identity_type",
        "identity_account_id",
        "session_issuer_type",
        "session_issuer_arn",
        "session_issuer_account_id",
        "session_issuer_user_name",
        "stack_name",
        "event_digest",
    }
)
_PLAN_PREFLIGHT_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "account_id",
        "region",
        "stack_name",
        "stack_id",
        "stack_status",
        "role_arn_absent",
        "parent_id_absent",
        "root_id_absent",
        "notification_arns",
        "stack_resource_count",
        "stack_resources_digest",
        "active_change_set_count",
        "active_change_sets_digest",
        "change_set_page_count",
        "pagination_complete",
        "public_access_block_configuration",
        "public_access_block_digest",
        "complete",
        "normal_plan_caller_arn_digest",
        "parent_events_digest",
        "read_at",
        "readback_digest",
    }
)

_TERMINAL_STACK_STATUSES = frozenset(
    {
        "CREATE_COMPLETE",
        "UPDATE_COMPLETE",
        "DELETE_COMPLETE",
        "IMPORT_COMPLETE",
    }
)
_IN_PROGRESS_STACK_STATUSES = frozenset(
    {
        "CREATE_IN_PROGRESS",
        "REVIEW_IN_PROGRESS",
        "ROLLBACK_IN_PROGRESS",
        "DELETE_IN_PROGRESS",
        "UPDATE_IN_PROGRESS",
        "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS",
        "UPDATE_ROLLBACK_IN_PROGRESS",
        "UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS",
        "IMPORT_IN_PROGRESS",
        "IMPORT_ROLLBACK_IN_PROGRESS",
    }
)


class RouteBrokerError(RuntimeError):
    """Sanitized fail-closed broker error."""

    def __init__(
        self,
        code: str,
        *,
        uncertain: bool = False,
        retryable_read_only: bool = False,
    ) -> None:
        self.code = code
        self.uncertain = uncertain
        self.retryable_read_only = retryable_read_only
        super().__init__(f"GUG376_ROUTE_BROKER_BLOCKED:{code}")


class RouteBrokerReadOnlyPending(RuntimeError):
    """Lambda-visible marker for a continuation-only provider readback."""

    def __init__(self, code: str) -> None:
        if (
            not isinstance(code, str)
            or re.fullmatch(r"[A-Z][A-Z0-9_]{2,95}", code) is None
        ):
            raise RouteBrokerError("READ_ONLY_PENDING_CODE_INVALID")
        self.code = code
        super().__init__(f"GUG376_ROUTE_BROKER_READ_ONLY_PENDING:{code}")


class _InvocationBudget:
    """Exact Lambda remaining-time gate shared by core and AWS adapters."""

    def __init__(self, context: Any) -> None:
        remaining = getattr(context, "get_remaining_time_in_millis", None)
        if not callable(remaining):
            raise RouteBrokerError("TIME_BUDGET_INVALID")
        self._remaining = remaining

    def remaining_ms(self) -> int:
        value = self._remaining()
        if type(value) is not int or value < 0:
            raise RouteBrokerError("TIME_BUDGET_INVALID")
        return value

    def require_mutation(self) -> None:
        if self.remaining_ms() < MUTATION_DISPATCH_MIN_REMAINING_MS:
            raise RouteBrokerError("TIME_BUDGET_INSUFFICIENT")

    def require_read(self) -> None:
        if self.remaining_ms() < READ_CONTINUATION_MIN_REMAINING_MS:
            raise RouteBrokerError(
                "TIME_BUDGET_PENDING", retryable_read_only=True
            )

    def require_readback_cas(self) -> None:
        if self.remaining_ms() < READBACK_CAS_MIN_REMAINING_MS:
            raise RouteBrokerError(
                "TIME_BUDGET_PENDING", retryable_read_only=True
            )


def _lookup_cloudtrail_events(
    client: Any,
    *,
    request: Mapping[str, Any],
    error_code: str,
    retryable_read_only: bool = False,
    budget: _InvocationBudget | None = None,
) -> list[Mapping[str, Any]]:
    events: list[Mapping[str, Any]] = []
    seen_tokens: set[str] = set()
    next_token: str | None = None
    for page_number in range(1, 101):
        if budget is not None:
            budget.require_read()
        page_request = dict(request)
        if next_token is not None:
            page_request["NextToken"] = next_token
        try:
            response = client.lookup_events(**page_request)
        except Exception as exc:
            raise RouteBrokerError(
                error_code, retryable_read_only=retryable_read_only
            ) from exc
        raw_events = response.get("Events") if isinstance(response, Mapping) else None
        if not isinstance(raw_events, list) or any(
            not isinstance(item, Mapping) for item in raw_events
        ):
            raise RouteBrokerError(
                error_code, retryable_read_only=retryable_read_only
            )
        events.extend(raw_events)
        token = response.get("NextToken")
        if token is None:
            return events
        if (
            not isinstance(token, str)
            or not token
            or token in seen_tokens
            or page_number == 100
        ):
            raise RouteBrokerError(
                error_code, retryable_read_only=retryable_read_only
            )
        seen_tokens.add(token)
        next_token = token
    raise RouteBrokerError(error_code, retryable_read_only=retryable_read_only)


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def digest_value(value: Any) -> str:
    return "sha256:" + sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _text_digest(value: Any, code: str) -> str:
    if not isinstance(value, str):
        raise RouteBrokerError(code)
    return "sha256:" + sha256(value.encode("utf-8")).hexdigest()


def seal(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    result = dict(value)
    result[field] = digest_value(dict(value))
    return result


def _require_digest(value: Any, code: str = "DIGEST_INVALID") -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise RouteBrokerError(code)
    return value


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    claimed = _require_digest(value.get(field), code)
    if digest_value({key: item for key, item in value.items() if key != field}) != claimed:
        raise RouteBrokerError(code)
    return claimed


def _parse_time(value: Any, code: str = "TIME_INVALID") -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RouteBrokerError(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise RouteBrokerError(code) from exc
    if parsed.microsecond or _timestamp(parsed) != value:
        raise RouteBrokerError(code)
    return parsed


def _normal_plan_session_name(
    caller_arn: Any, *, generated_role_name: str
) -> str:
    prefix = (
        f"arn:aws:sts::{AUTHORITY_ACCOUNT_ID}:assumed-role/"
        f"{generated_role_name}/"
    )
    if not isinstance(caller_arn, str) or not caller_arn.startswith(prefix):
        raise RouteBrokerError("NORMAL_PLAN_CALLER_INVALID")
    session_name = caller_arn[len(prefix) :]
    if _NORMAL_PLAN_SESSION_RE.fullmatch(session_name) is None:
        raise RouteBrokerError("NORMAL_PLAN_CALLER_INVALID")
    return session_name


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise RouteBrokerError("TIME_INVALID")
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _json_copy(value: Any) -> Any:
    try:
        return json.loads(canonical_json(value))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RouteBrokerError("CONFIG_JSON_INVALID") from exc


def encode_runtime_config(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return the deterministic dictionary-compressed runtime envelope."""

    # Parse first so the compressed envelope can never legitimize bad config.
    BrokerConfig.from_mapping(value)
    raw = canonical_json(value).encode("utf-8")
    compressor = zlib.compressobj(
        level=9,
        method=zlib.DEFLATED,
        wbits=-zlib.MAX_WBITS,
        memLevel=9,
        strategy=zlib.Z_DEFAULT_STRATEGY,
        zdict=_RUNTIME_CONFIG_DICTIONARY,
    )
    compressed = compressor.compress(raw) + compressor.flush()
    return {
        "schema_version": 1,
        "record_type": COMPRESSED_CONFIG_RECORD_TYPE,
        "encoding": "deflate-dict-v2+base85",
        "payload": base64.b85encode(compressed).decode("ascii"),
    }


def decode_runtime_config(value: Mapping[str, Any]) -> dict[str, Any]:
    """Decode one closed envelope with an explicit 64 KiB expansion ceiling."""

    if not isinstance(value, Mapping) or set(value) != _COMPRESSED_CONFIG_FIELDS:
        raise RouteBrokerError("RUNTIME_CONFIG_ENVELOPE_INVALID")
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != COMPRESSED_CONFIG_RECORD_TYPE
        or value.get("encoding") != "deflate-dict-v2+base85"
    ):
        raise RouteBrokerError("RUNTIME_CONFIG_ENVELOPE_INVALID")
    payload = value.get("payload")
    if not isinstance(payload, str) or len(payload) > 65536:
        raise RouteBrokerError("RUNTIME_CONFIG_ENVELOPE_INVALID")
    try:
        compressed = base64.b85decode(payload)
        inflater = zlib.decompressobj(
            wbits=-zlib.MAX_WBITS,
            zdict=_RUNTIME_CONFIG_DICTIONARY,
        )
        raw = inflater.decompress(compressed, 65537)
        if (
            len(raw) > 65536
            or not inflater.eof
            or inflater.unconsumed_tail
            or inflater.unused_data
        ):
            raise ValueError("expanded config exceeds limit")
        decoded = json.loads(raw)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        raise RouteBrokerError("RUNTIME_CONFIG_ENVELOPE_INVALID") from exc
    if not isinstance(decoded, dict):
        raise RouteBrokerError("RUNTIME_CONFIG_ENVELOPE_INVALID")
    # Re-rendering rejects alternate JSON encodings hidden by compression.
    if canonical_json(decoded).encode("utf-8") != raw:
        raise RouteBrokerError("RUNTIME_CONFIG_ENVELOPE_INVALID")
    BrokerConfig.from_mapping(decoded)
    if encode_runtime_config(decoded) != dict(value):
        raise RouteBrokerError("RUNTIME_CONFIG_ENVELOPE_INVALID")
    return decoded


def validate_empty_event(event: Any) -> None:
    if type(event) is not dict or event:
        raise RouteBrokerError("NON_EMPTY_EVENT")


def _validate_create_request(request: Mapping[str, Any]) -> None:
    change_set_type = request.get("ChangeSetType")
    expected_fields = (
        _CREATE_ON_FAILURE_FIELDS
        if change_set_type == "CREATE"
        else _CREATE_REQUEST_FIELDS
    )
    if set(request) != expected_fields:
        raise RouteBrokerError("REQUEST_CONFIG_INVALID")
    if (
        _STACK_NAME_RE.fullmatch(str(request.get("StackName", ""))) is None
        or _CHANGE_SET_NAME_RE.fullmatch(str(request.get("ChangeSetName", "")))
        is None
        or _CLIENT_TOKEN_RE.fullmatch(str(request.get("ClientToken", ""))) is None
        or change_set_type not in {"CREATE", "UPDATE"}
        or (
            change_set_type == "CREATE"
            and request.get("OnStackFailure") != "DELETE"
        )
        or (change_set_type == "UPDATE" and "OnStackFailure" in request)
        or not isinstance(request.get("Description"), str)
        or not str(request.get("Description")).startswith("GUG-376 ")
        or request.get("Capabilities") != ["CAPABILITY_NAMED_IAM"]
        or request.get("IncludeNestedStacks") is not False
        or request.get("ResourcesToImport") != []
        or request.get("NotificationARNs") != []
        or request.get("RollbackConfiguration")
        != {"MonitoringTimeInMinutes": 0, "RollbackTriggers": []}
    ):
        raise RouteBrokerError("REQUEST_CONFIG_INVALID")
    parameters = request.get("Parameters")
    if not isinstance(parameters, list) or any(
        not isinstance(item, Mapping)
        or (
            set(item) == {"ParameterKey", "ParameterValue"}
            and not all(isinstance(value, str) for value in item.values())
        )
        or (
            set(item) == {"ParameterKey", "UsePreviousValue"}
            and (
                not isinstance(item.get("ParameterKey"), str)
                or item.get("UsePreviousValue") is not True
            )
        )
        or set(item)
        not in (
            {"ParameterKey", "ParameterValue"},
            {"ParameterKey", "UsePreviousValue"},
        )
        for item in parameters
    ):
        raise RouteBrokerError("REQUEST_CONFIG_INVALID")
    if len({item["ParameterKey"] for item in parameters}) != len(parameters):
        raise RouteBrokerError("REQUEST_CONFIG_INVALID")
    tags = request.get("Tags")
    if not isinstance(tags, list) or any(
        not isinstance(item, Mapping)
        or set(item) != {"Key", "Value"}
        or not all(isinstance(value, str) for value in item.values())
        for item in tags
    ):
        raise RouteBrokerError("REQUEST_CONFIG_INVALID")
    if len({item["Key"] for item in tags}) != len(tags):
        raise RouteBrokerError("REQUEST_CONFIG_INVALID")
    template_url = request.get("TemplateURL")
    if not isinstance(template_url, str):
        raise RouteBrokerError("REQUEST_CONFIG_INVALID")
    parsed = urlsplit(template_url)
    query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.hostname is None
        or re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3\.us-east-1\.amazonaws\.com", parsed.hostname)
        is None
        or not parsed.path.startswith("/")
        or parsed.path == "/"
        or set(query) != {"versionId"}
        or len(query["versionId"]) != 1
        or not query["versionId"][0]
    ):
        raise RouteBrokerError("REQUEST_CONFIG_INVALID")


def _validate_execute_request(
    request: Mapping[str, Any], *, change_set_type: str
) -> None:
    expected_fields = (
        _EXECUTE_REQUEST_FIELDS
        if change_set_type == "CREATE"
        else _UPDATE_EXECUTE_REQUEST_FIELDS
    )
    if (
        set(request) != expected_fields
        or _STACK_NAME_RE.fullmatch(str(request.get("StackName", ""))) is None
        or _CHANGE_SET_NAME_RE.fullmatch(str(request.get("ChangeSetName", "")))
        is None
        or _CLIENT_TOKEN_RE.fullmatch(str(request.get("ClientRequestToken", "")))
        is None
        or (
            change_set_type == "UPDATE"
            and request.get("DisableRollback") is not False
        )
        or (change_set_type == "CREATE" and "DisableRollback" in request)
    ):
        raise RouteBrokerError("REQUEST_CONFIG_INVALID")


def _expand_compact_requests(
    requests: Mapping[str, Any], *, repair_id: str
) -> dict[str, dict[str, Any]]:
    """Expand the sole compact wire form into exact provider requests."""

    if set(requests) != set(MUTATING_CREATOR_ALIASES):
        raise RouteBrokerError("REQUEST_CONFIG_INVALID")
    expanded: dict[str, dict[str, Any]] = {}
    for creator_alias in MUTATING_CREATOR_ALIASES:
        compact = requests.get(creator_alias)
        if not isinstance(compact, Mapping) or set(compact) != (
            _COMPACT_CREATE_REQUEST_FIELDS
        ):
            raise RouteBrokerError("REQUEST_CONFIG_INVALID")
        stem = creator_alias.removesuffix("-create-v1")
        creator = {
            **dict(compact),
            "Description": f"GUG-376 exact {stem} change set",
            "Capabilities": ["CAPABILITY_NAMED_IAM"],
            "Tags": list(_EXACT_STACK_TAGS),
            "IncludeNestedStacks": False,
            "ResourcesToImport": [],
            "NotificationARNs": [],
            "RollbackConfiguration": {
                "MonitoringTimeInMinutes": 0,
                "RollbackTriggers": [],
            },
            "ClientToken": "gug376-"
            + digest_value(
                {"repair_id": repair_id, "operation": creator_alias}
            )[7:55],
        }
        if creator["ChangeSetType"] == "CREATE":
            creator["OnStackFailure"] = "DELETE"
        _validate_create_request(creator)
        executor_alias = _CREATE_TO_EXECUTE[creator_alias]
        executor = {
            "StackName": creator["StackName"],
            "ChangeSetName": creator["ChangeSetName"],
            "ClientRequestToken": "gug376-"
            + digest_value(
                {"repair_id": repair_id, "operation": executor_alias}
            )[7:55],
        }
        if creator["ChangeSetType"] == "UPDATE":
            executor["DisableRollback"] = False
        _validate_execute_request(
            executor, change_set_type=creator["ChangeSetType"]
        )
        expanded[creator_alias] = creator
        expanded[executor_alias] = executor
    return expanded


def _change_set_parameters_match(
    response_parameters: Any,
    request_parameters: Sequence[Mapping[str, Any]],
    *,
    expected_terminal_parameters_digest: str | None = None,
) -> bool:
    """Bind explicit values and accept AWS' two prior-value readback forms."""

    if not isinstance(response_parameters, list) or len(response_parameters) != len(
        request_parameters
    ):
        return False
    observed_by_key: dict[str, Mapping[str, Any]] = {}
    requested_by_key: dict[str, Mapping[str, Any]] = {}
    for observed in response_parameters:
        if not isinstance(observed, Mapping):
            return False
        allowed_observed = {
            "ParameterKey",
            "ParameterValue",
            "UsePreviousValue",
            "ResolvedValue",
        }
        if set(observed) - allowed_observed:
            return False
        observed_key = observed.get("ParameterKey")
        if (
            not isinstance(observed_key, str)
            or not observed_key
            or observed_key in observed_by_key
            or observed.get("ResolvedValue") is not None
        ):
            return False
        observed_by_key[observed_key] = observed
    for requested in request_parameters:
        if not isinstance(requested, Mapping):
            return False
        requested_key = requested.get("ParameterKey")
        if (
            not isinstance(requested_key, str)
            or not requested_key
            or requested_key in requested_by_key
        ):
            return False
        requested_by_key[requested_key] = requested
    if set(observed_by_key) != set(requested_by_key):
        return False
    effective_values: dict[str, str] = {}
    previous_modes: set[str] = set()
    for key, requested in requested_by_key.items():
        observed = observed_by_key[key]
        if requested.get("UsePreviousValue") is True:
            if set(requested) != {"ParameterKey", "UsePreviousValue"}:
                return False
            observed_value = observed.get("ParameterValue")
            if observed.get("UsePreviousValue") is True:
                if "ParameterValue" in observed:
                    return False
                previous_modes.add("native")
            elif observed.get("UsePreviousValue") in (None, False):
                if (
                    not isinstance(observed_value, str)
                    or re.fullmatch(r"\*+", observed_value) is not None
                ):
                    return False
                previous_modes.add("resolved")
                effective_values[key] = observed_value
            else:
                return False
        elif (
            set(requested) != {"ParameterKey", "ParameterValue"}
            or not isinstance(requested.get("ParameterValue"), str)
            or observed.get("ParameterValue") != requested.get("ParameterValue")
            or observed.get("UsePreviousValue") not in (None, False)
        ):
            return False
        else:
            effective_values[key] = requested["ParameterValue"]
    if len(previous_modes) > 1:
        return False
    if previous_modes == {"resolved"}:
        if expected_terminal_parameters_digest is None:
            return False
        return digest_value(dict(sorted(effective_values.items()))) == (
            expected_terminal_parameters_digest
        )
    return True


def _stack_parameter_values(
    raw_parameters: Any, *, error_code: str
) -> dict[str, str]:
    """Return one exact unmasked value for every terminal stack parameter."""

    if not isinstance(raw_parameters, list):
        raise RouteBrokerError(error_code)
    values: dict[str, str] = {}
    allowed = {
        "ParameterKey",
        "ParameterValue",
        "UsePreviousValue",
        "ResolvedValue",
    }
    for item in raw_parameters:
        if not isinstance(item, Mapping) or set(item) - allowed:
            raise RouteBrokerError(error_code)
        key = item.get("ParameterKey")
        value = item.get("ParameterValue")
        if (
            not isinstance(key, str)
            or not key
            or key in values
            or not isinstance(value, str)
            or re.fullmatch(r"\*+", value) is not None
            or item.get("UsePreviousValue") not in (None, False)
            or item.get("ResolvedValue") is not None
        ):
            raise RouteBrokerError(error_code)
        values[key] = value
    return dict(sorted(values.items()))


def _expected_terminal_parameter_values(
    request_parameters: Sequence[Mapping[str, Any]],
    *,
    current_values: Mapping[str, str] | None,
    error_code: str,
) -> dict[str, str]:
    """Resolve explicit and UsePreviousValue parameters into one exact map."""

    expected: dict[str, str] = {}
    for item in request_parameters:
        if not isinstance(item, Mapping):
            raise RouteBrokerError(error_code)
        key = item.get("ParameterKey")
        if not isinstance(key, str) or not key or key in expected:
            raise RouteBrokerError(error_code)
        if item.get("UsePreviousValue") is True:
            if (
                set(item) != {"ParameterKey", "UsePreviousValue"}
                or current_values is None
                or key not in current_values
            ):
                raise RouteBrokerError(error_code)
            expected[key] = current_values[key]
        else:
            value = item.get("ParameterValue")
            if (
                set(item) != {"ParameterKey", "ParameterValue"}
                or not isinstance(value, str)
            ):
                raise RouteBrokerError(error_code)
            expected[key] = value
    if current_values is not None and set(expected) != set(current_values):
        raise RouteBrokerError(error_code)
    return dict(sorted(expected.items()))


def _stable_stack_projection(
    stack: Any, *, error_code: str
) -> dict[str, Any]:
    """Normalize the stack fields used by one atomic terminal readback."""

    if not isinstance(stack, Mapping):
        raise RouteBrokerError(error_code)
    parameters = _stack_parameter_values(
        stack.get("Parameters"), error_code=error_code
    )
    raw_outputs = stack.get("Outputs")
    if not isinstance(raw_outputs, list):
        raise RouteBrokerError(error_code)
    outputs: dict[str, str] = {}
    output_fields = {"OutputKey", "OutputValue", "Description", "ExportName"}
    for item in raw_outputs:
        if (
            not isinstance(item, Mapping)
            or set(item) - output_fields
            or not isinstance(item.get("OutputKey"), str)
            or not item["OutputKey"]
            or not isinstance(item.get("OutputValue"), str)
            or item["OutputKey"] in outputs
        ):
            raise RouteBrokerError(error_code)
        outputs[item["OutputKey"]] = item["OutputValue"]
    raw_tags = stack.get("Tags")
    if not isinstance(raw_tags, list):
        raise RouteBrokerError(error_code)
    tags: list[dict[str, str]] = []
    tag_keys: set[str] = set()
    for item in raw_tags:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"Key", "Value"}
            or not isinstance(item.get("Key"), str)
            or not item["Key"]
            or not isinstance(item.get("Value"), str)
            or item["Key"] in tag_keys
        ):
            raise RouteBrokerError(error_code)
        tag_keys.add(item["Key"])
        tags.append({"Key": item["Key"], "Value": item["Value"]})
    updated = stack.get("LastUpdatedTime", stack.get("CreationTime"))
    notification_arns = stack.get("NotificationARNs", [])
    if (
        not isinstance(updated, datetime)
        or not isinstance(notification_arns, list)
        or any(not isinstance(item, str) for item in notification_arns)
    ):
        raise RouteBrokerError(error_code)
    return {
        "stack_id": stack.get("StackId"),
        "stack_name": stack.get("StackName"),
        "change_set_id": stack.get("ChangeSetId"),
        "stack_status": stack.get("StackStatus"),
        "last_updated_time": _timestamp(updated),
        "role_arn_absent": "RoleARN" not in stack,
        "parent_id_absent": "ParentId" not in stack,
        "root_id_absent": "RootId" not in stack,
        "notification_arns": list(notification_arns),
        "parameters": parameters,
        "outputs": dict(sorted(outputs.items())),
        "tags": sorted(tags, key=lambda item: (item["Key"], item["Value"])),
    }


@dataclass(frozen=True, slots=True)
class BrokerConfig:
    source_commit: str
    ledger_id: str
    ledger_binding_digest: str
    initialization_digest: str
    foundation_publish_binding_digest: str
    repair_id: str
    bootstrap_change_set_name: str
    identity_center_instance_arn: str
    bootstrap_principal_id: str
    route_not_before: datetime
    route_not_after: datetime
    recovery_not_after: datetime
    normal_plan_generated_role_arn: str
    normal_plan_generated_role_name: str
    config_digest: str
    _requests_json: str
    _creator_contracts_json: str
    _permission_set_output_contracts_json: str
    _terminal_expectations_json: str
    _revocation_assignment_scopes_json: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "BrokerConfig":
        if not isinstance(value, Mapping) or set(value) != _CONFIG_FIELDS:
            raise RouteBrokerError("CONFIG_FIELDS_INVALID")
        if type(value.get("schema_version")) is not int or value.get(
            "schema_version"
        ) != 1 or value.get("record_type") != CONFIG_RECORD_TYPE:
            raise RouteBrokerError("CONFIG_TYPE_INVALID")
        config_digest = _verify_seal(value, "config_digest", "CONFIG_DIGEST_INVALID")
        source_commit = value.get("source_commit")
        ledger_id = value.get("ledger_id")
        repair_id = value.get("repair_id")
        if not isinstance(source_commit, str) or _COMMIT_RE.fullmatch(source_commit) is None:
            raise RouteBrokerError("SOURCE_COMMIT_INVALID")
        if ledger_id != ROUTE_LEDGER_ID:
            raise RouteBrokerError("LEDGER_ID_INVALID")
        if not isinstance(repair_id, str) or _REPAIR_ID_RE.fullmatch(repair_id) is None:
            raise RouteBrokerError("REPAIR_ID_INVALID")
        binding_digest = _require_digest(value.get("ledger_binding_digest"))
        initialization_digest = _require_digest(value.get("initialization_digest"))
        foundation_publish_binding_digest = _require_digest(
            value.get("foundation_publish_binding_digest")
        )
        expected_initialization_digest = digest_value(
            {
                "record_type": LEDGER_RECORD_TYPE,
                "ledger_id": ledger_id,
                "source_commit": source_commit,
                "binding_digest": binding_digest,
                "initial_state": "READY",
                "initial_version": 0,
                "retry_permitted": False,
            }
        )
        if initialization_digest != expected_initialization_digest:
            raise RouteBrokerError("INITIALIZATION_DIGEST_INVALID")
        not_before = _parse_time(value.get("route_not_before"), "ROUTE_WINDOW_INVALID")
        not_after = _parse_time(value.get("route_not_after"), "ROUTE_WINDOW_INVALID")
        recovery_not_after = _parse_time(
            value.get("recovery_not_after"), "RECOVERY_WINDOW_INVALID"
        )
        if (
            not not_before < not_after
            or not MIN_ROUTE_WINDOW_SECONDS
            <= (not_after - not_before).total_seconds()
            <= 7200
            or recovery_not_after != not_after + timedelta(hours=24)
        ):
            raise RouteBrokerError("ROUTE_WINDOW_INVALID")
        change_set_name = value.get("bootstrap_change_set_name")
        if not isinstance(change_set_name, str) or not 1 <= len(change_set_name) <= 128:
            raise RouteBrokerError("CHANGE_SET_NAME_INVALID")
        identity_center_instance_arn = value.get("identity_center_instance_arn")
        bootstrap_principal_id = value.get("bootstrap_principal_id")
        if (
            not isinstance(identity_center_instance_arn, str)
            or _INSTANCE_RE.fullmatch(identity_center_instance_arn) is None
            or not isinstance(bootstrap_principal_id, str)
            or _PRINCIPAL_RE.fullmatch(bootstrap_principal_id) is None
        ):
            raise RouteBrokerError("IDENTITY_CENTER_BINDING_INVALID")
        normal_plan_role_arn = value.get("normal_plan_generated_role_arn")
        normal_plan_role_name = value.get("normal_plan_generated_role_name")
        if (
            not isinstance(normal_plan_role_name, str)
            or _NORMAL_PLAN_ROLE_NAME_RE.fullmatch(normal_plan_role_name) is None
            or normal_plan_role_arn
            != (
                f"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:role/"
                f"aws-reserved/sso.amazonaws.com/{normal_plan_role_name}"
            )
        ):
            raise RouteBrokerError("NORMAL_PLAN_ROLE_INVALID")
        if value.get("retry_permitted") is not False:
            raise RouteBrokerError("CONFIG_RETRY_OVERCLAIM")
        if (
            value.get("production_authorized") is not False
            or value.get("production_status") != "NO-GO"
        ):
            raise RouteBrokerError("CONFIG_PRODUCTION_OVERCLAIM")

        configured_requests = value.get("requests")
        expected_requests = set(MUTATING_CREATOR_ALIASES + EXECUTOR_ALIASES)
        if not isinstance(configured_requests, Mapping) or set(
            configured_requests
        ) not in (expected_requests, set(MUTATING_CREATOR_ALIASES)):
            raise RouteBrokerError("REQUEST_CONFIG_INVALID")
        if set(configured_requests) == set(MUTATING_CREATOR_ALIASES):
            requests = _expand_compact_requests(
                configured_requests, repair_id=repair_id
            )
        else:
            requests = _json_copy(configured_requests)
            for alias, request in requests.items():
                if not isinstance(request, Mapping) or not request:
                    raise RouteBrokerError("REQUEST_CONFIG_INVALID")
                if alias in MUTATING_CREATOR_ALIASES:
                    _validate_create_request(request)
                else:
                    creator_alias = _EXECUTOR_TO_CREATOR.get(alias)
                    if creator_alias is None:
                        raise RouteBrokerError("REQUEST_CONFIG_INVALID")
                    _validate_execute_request(
                        request,
                        change_set_type=requests[creator_alias]["ChangeSetType"],
                    )
        exact_routes = {
            "seed-revoke-create-v1": (
                "scanalyze-platform-authority-gug376-temporary-change-set-route",
                "gug376-temporary-route-seed-revoke",
            ),
            "seed-revoke-execute-v1": (
                "scanalyze-platform-authority-gug376-temporary-change-set-route",
                "gug376-temporary-route-seed-revoke",
            ),
            "delegation-create-v1": (
                "scanalyze-platform-authority-bootstrap-plan-repair-delegation",
                "gug376-plan-repair-delegation-create",
            ),
            "delegation-execute-v1": (
                "scanalyze-platform-authority-bootstrap-plan-repair-delegation",
                "gug376-plan-repair-delegation-create",
            ),
            "pep-create-v1": (
                "scanalyze-platform-authority-bootstrap-plan-repair-pep",
                "gug376-plan-repair-pep-create",
            ),
            "pep-execute-v1": (
                "scanalyze-platform-authority-bootstrap-plan-repair-pep",
                "gug376-plan-repair-pep-create",
            ),
            "pep-protection-create-v1": (
                "scanalyze-platform-authority-bootstrap-plan-repair-pep",
                "gug376-plan-repair-pep-protection-enable",
            ),
            "pep-protection-execute-v1": (
                "scanalyze-platform-authority-bootstrap-plan-repair-pep",
                "gug376-plan-repair-pep-protection-enable",
            ),
            "delegation-revoke-create-v1": (
                "scanalyze-platform-authority-bootstrap-plan-repair-delegation",
                "gug376-plan-repair-delegation-revoke",
            ),
            "delegation-revoke-execute-v1": (
                "scanalyze-platform-authority-bootstrap-plan-repair-delegation",
                "gug376-plan-repair-delegation-revoke",
            ),
            "route-revoke-create-v1": (
                "scanalyze-platform-authority-gug376-temporary-change-set-route",
                "gug376-temporary-route-invoker-revoke",
            ),
            "route-revoke-execute-v1": (
                "scanalyze-platform-authority-gug376-temporary-change-set-route",
                "gug376-temporary-route-invoker-revoke",
            ),
        }
        for alias, (stack_name, exact_change_set_name) in exact_routes.items():
            request = requests[alias]
            if (
                request.get("StackName") != stack_name
                or request.get("ChangeSetName") != exact_change_set_name
            ):
                raise RouteBrokerError("REQUEST_ROUTE_INVALID")
        pep_parameters = requests["pep-create-v1"]["Parameters"]
        dynamic_pep = [
            item
            for item in pep_parameters
            if item["ParameterKey"] == "RepairInvokerPermissionSetArn"
        ]
        if dynamic_pep != [
            {
                "ParameterKey": "RepairInvokerPermissionSetArn",
                "ParameterValue": REPAIR_INVOKER_PERMISSION_SET_SENTINEL,
            }
        ]:
            raise RouteBrokerError("DYNAMIC_PARAMETER_CONTRACT_INVALID")
        for alias in MUTATING_CREATOR_ALIASES:
            if alias == "pep-create-v1":
                continue
            if any(
                item.get("ParameterValue")
                == REPAIR_INVOKER_PERMISSION_SET_SENTINEL
                for item in requests[alias]["Parameters"]
            ):
                raise RouteBrokerError("DYNAMIC_PARAMETER_CONTRACT_INVALID")

        creator_contracts = value.get("creator_contracts")
        if not isinstance(creator_contracts, Mapping) or set(
            creator_contracts
        ) != set(MUTATING_CREATOR_ALIASES):
            raise RouteBrokerError("CREATOR_CONTRACT_INVALID")
        for alias, contract in creator_contracts.items():
            if not isinstance(contract, Mapping) or set(contract) != (
                _CREATOR_CONTRACT_FIELDS
            ):
                raise RouteBrokerError("CREATOR_CONTRACT_INVALID")
            _require_digest(
                contract.get("template_digest"), "CREATOR_CONTRACT_INVALID"
            )
            changes = contract.get("expected_changes")
            if not isinstance(changes, list) or not changes:
                raise RouteBrokerError("CREATOR_CONTRACT_INVALID")
            ordering: list[tuple[str, str]] = []
            for change in changes:
                if not isinstance(change, Mapping) or set(change) != (
                    _EXPECTED_CHANGE_FIELDS
                ):
                    raise RouteBrokerError("CREATOR_CONTRACT_INVALID")
                action = change.get("action")
                logical_id = change.get("logical_resource_id")
                resource_type = change.get("resource_type")
                replacement = change.get("replacement")
                scope = change.get("scope")
                details = change.get("details")
                if (
                    action not in {"Add", "Modify", "Remove", "Import", "Dynamic"}
                    or not isinstance(logical_id, str)
                    or not logical_id
                    or not isinstance(resource_type, str)
                    or not resource_type.startswith("AWS::")
                    or replacement not in {None, "True", "False", "Conditional"}
                    or not isinstance(scope, list)
                    or any(
                        item
                        not in {
                            "Properties",
                            "Metadata",
                            "CreationPolicy",
                            "UpdatePolicy",
                            "DeletionPolicy",
                            "UpdateReplacePolicy",
                            "Tags",
                        }
                        for item in scope
                    )
                    or len(scope) != len(set(scope))
                    or scope != sorted(scope)
                    or not isinstance(details, list)
                    or any(
                        not isinstance(detail, Mapping)
                        or set(detail) != _CHANGE_DETAIL_FIELDS
                        or detail.get("target_attribute")
                        not in {
                            "CreationPolicy",
                            "DeletionPolicy",
                            "Metadata",
                            "Properties",
                            "Tags",
                            "UpdatePolicy",
                            "UpdateReplacePolicy",
                        }
                        or (
                            detail.get("target_name") is not None
                            and (
                                not isinstance(detail.get("target_name"), str)
                                or not detail.get("target_name")
                            )
                        )
                        or detail.get("requires_recreation")
                        not in {None, "Always", "Conditionally", "Never"}
                        or detail.get("evaluation") not in {"Static", "Dynamic"}
                        or detail.get("change_source")
                        not in {
                            "Automatic",
                            "DirectModification",
                            "ParameterReference",
                            "ResourceAttribute",
                            "ResourceReference",
                        }
                        or (
                            detail.get("causing_entity") is not None
                            and (
                                not isinstance(detail.get("causing_entity"), str)
                                or not detail.get("causing_entity")
                            )
                        )
                        for detail in details
                    )
                    or details
                    != sorted(
                        details,
                        key=lambda detail: (
                            str(detail["target_attribute"]),
                            str(detail["target_name"] or ""),
                            str(detail["requires_recreation"] or ""),
                            str(detail["evaluation"]),
                            str(detail["change_source"]),
                            str(detail["causing_entity"] or ""),
                        ),
                    )
                ):
                    raise RouteBrokerError("CREATOR_CONTRACT_INVALID")
                if details:
                    detail_attributes = [
                        str(detail["target_attribute"]) for detail in details
                    ]
                    if (
                        action != "Modify"
                        or replacement != "False"
                        or len(detail_attributes) != len(set(detail_attributes))
                        or scope != sorted(detail_attributes)
                        or any(
                            detail["evaluation"] != "Static"
                            or detail["change_source"] != "DirectModification"
                            or detail["causing_entity"] is not None
                            or (
                                detail["target_attribute"]
                                in {"DeletionPolicy", "UpdateReplacePolicy"}
                                and (
                                    detail["target_name"] is not None
                                    or detail["requires_recreation"] is not None
                                )
                            )
                            or (
                                detail["target_attribute"] == "Properties"
                                and (
                                    logical_id
                                    not in {"BrokerLedger", "RepairLedger"}
                                    or resource_type != "AWS::DynamoDB::Table"
                                    or detail["target_name"]
                                    != "DeletionProtectionEnabled"
                                    or detail["requires_recreation"] != "Never"
                                )
                            )
                            or detail["target_attribute"]
                            not in {
                                "DeletionPolicy",
                                "Properties",
                                "UpdateReplacePolicy",
                            }
                            for detail in details
                        )
                    ):
                        raise RouteBrokerError("CREATOR_CONTRACT_INVALID")
                elif action == "Modify":
                    raise RouteBrokerError("CREATOR_CONTRACT_INVALID")
                ordering.append((logical_id, resource_type))
            if ordering != sorted(ordering) or len(ordering) != len(set(ordering)):
                raise RouteBrokerError("CREATOR_CONTRACT_INVALID")

        output_contracts = value.get("permission_set_output_contracts")
        expected_output_contracts = {
            "route": {
                "account_id": MANAGEMENT_ACCOUNT_ID,
                "stack_name": (
                    "scanalyze-platform-authority-gug376-temporary-change-set-route"
                ),
                "permission_set_output_keys": [
                    "BrokerInvokerPermissionSetArn",
                    "BrokerSeedCreatorPermissionSetArn",
                    "BrokerSeedExecutorPermissionSetArn",
                ],
                "required_mode_outputs": {
                    "BrokerInvokerAssignmentMode": "true",
                    "SeedAssignmentMode": "true",
                },
            },
            "delegation": {
                "account_id": MANAGEMENT_ACCOUNT_ID,
                "stack_name": (
                    "scanalyze-platform-authority-bootstrap-plan-repair-delegation"
                ),
                "permission_set_output_keys": ["RepairInvokerPermissionSetArn"],
                "required_mode_outputs": {
                    "RepairInvokerAssignmentMode": "true"
                },
            },
        }
        if (
            not isinstance(output_contracts, Mapping)
            or set(output_contracts) != set(expected_output_contracts)
        ):
            raise RouteBrokerError("OUTPUT_CONTRACT_INVALID")
        for source, expected in expected_output_contracts.items():
            contract = output_contracts[source]
            if (
                not isinstance(contract, Mapping)
                or set(contract) != _OUTPUT_CONTRACT_FIELDS
                or contract != expected
            ):
                raise RouteBrokerError("OUTPUT_CONTRACT_INVALID")

        expectations = value.get("terminal_expectations")
        if not isinstance(expectations, Mapping) or set(expectations) != set(
            EXECUTOR_ALIASES
        ):
            raise RouteBrokerError("TERMINAL_CONFIG_INVALID")
        for expectation in expectations.values():
            if not isinstance(expectation, Mapping) or set(expectation) != (
                _TERMINAL_EXPECTATION_FIELDS
            ):
                raise RouteBrokerError("TERMINAL_CONFIG_INVALID")
            _require_digest(
                expectation.get("template_digest"), "TERMINAL_CONFIG_INVALID"
            )
            resources = expectation.get("expected_resources")
            if (
                not isinstance(resources, list)
                or not resources
                or any(
                    not isinstance(item, Mapping)
                    or set(item) != _STACK_RESOURCE_FIELDS
                    or not isinstance(item.get("logical_resource_id"), str)
                    or not item.get("logical_resource_id")
                    or not isinstance(item.get("resource_type"), str)
                    or not str(item.get("resource_type")).startswith("AWS::")
                    for item in resources
                )
                or resources
                != sorted(
                    resources,
                    key=lambda item: (
                        item["logical_resource_id"],
                        item["resource_type"],
                    ),
                )
            ):
                raise RouteBrokerError("TERMINAL_CONFIG_INVALID")
            output_keys = expectation.get("expected_output_keys")
            static_outputs = expectation.get("expected_static_outputs")
            expected_tags = expectation.get("expected_tags")
            if (
                not isinstance(output_keys, list)
                or output_keys != sorted(set(output_keys))
                or not isinstance(static_outputs, Mapping)
                or not set(static_outputs).issubset(output_keys)
                or any(
                    not isinstance(key, str) or not isinstance(item, str)
                    for key, item in static_outputs.items()
                )
                or not isinstance(expected_tags, list)
                or any(
                    not isinstance(item, Mapping)
                    or set(item) != {"Key", "Value"}
                    or not all(isinstance(field, str) for field in item.values())
                    for item in expected_tags
                )
            ):
                raise RouteBrokerError("TERMINAL_CONFIG_INVALID")

        for creator_alias, executor_alias in _CREATE_TO_EXECUTE.items():
            create_request = requests[creator_alias]
            execute_request = requests[executor_alias]
            expectation = expectations[executor_alias]
            if (
                create_request["StackName"] != expectation["stack_name"]
                or execute_request["StackName"] != expectation["stack_name"]
                or create_request["ChangeSetName"]
                != execute_request["ChangeSetName"]
                or expectation["account_id"] != operation_account(executor_alias)
                or create_request["ChangeSetType"]
                != (
                    "UPDATE"
                    if "revoke" in creator_alias
                    or creator_alias == "pep-protection-create-v1"
                    else "CREATE"
                )
            ):
                raise RouteBrokerError("REQUEST_BINDING_INVALID")
            statuses = expectation.get("terminal_statuses")
            if (
                not isinstance(statuses, list)
                or not statuses
                or len(statuses) != len(set(statuses))
                or not set(statuses).issubset(_TERMINAL_STACK_STATUSES)
            ):
                raise RouteBrokerError("TERMINAL_CONFIG_INVALID")
            if _ACCOUNT_RE.fullmatch(str(expectation.get("account_id", ""))) is None:
                raise RouteBrokerError("TERMINAL_CONFIG_INVALID")
            if not isinstance(expectation.get("stack_name"), str):
                raise RouteBrokerError("TERMINAL_CONFIG_INVALID")

        revocations = value.get("revocation_assignment_scopes")
        revocation_aliases = {
            "seed-revoke-execute-v1",
            "delegation-revoke-execute-v1",
            "route-revoke-execute-v1",
        }
        if not isinstance(revocations, Mapping) or set(revocations) != revocation_aliases:
            raise RouteBrokerError("ASSIGNMENT_CONFIG_INVALID")
        expected_sources = {
            "seed-revoke-execute-v1": [
                {"source": "route", "output_key": "BrokerSeedCreatorPermissionSetArn"},
                {"source": "route", "output_key": "BrokerSeedExecutorPermissionSetArn"},
            ],
            "delegation-revoke-execute-v1": [
                {"source": "delegation", "output_key": "RepairInvokerPermissionSetArn"}
            ],
            "route-revoke-execute-v1": [
                {"source": "route", "output_key": "BrokerInvokerPermissionSetArn"}
            ],
        }
        for alias, scope in revocations.items():
            if not isinstance(scope, Mapping) or set(scope) != _ASSIGNMENT_SCOPE_FIELDS:
                raise RouteBrokerError("ASSIGNMENT_CONFIG_INVALID")
            if scope.get("account_id") != AUTHORITY_ACCOUNT_ID:
                raise RouteBrokerError("ASSIGNMENT_CONFIG_INVALID")
            if scope.get("instance_arn") != identity_center_instance_arn:
                raise RouteBrokerError("ASSIGNMENT_CONFIG_INVALID")
            sources = scope.get("permission_set_sources")
            if sources != expected_sources[alias] or any(
                not isinstance(item, Mapping)
                or set(item) != _PERMISSION_SET_SOURCE_FIELDS
                for item in sources
            ):
                raise RouteBrokerError("ASSIGNMENT_CONFIG_INVALID")

        # Canonical strings make this frozen dataclass deeply immutable.
        return cls(
            source_commit=source_commit,
            ledger_id=ledger_id,
            ledger_binding_digest=binding_digest,
            initialization_digest=initialization_digest,
            foundation_publish_binding_digest=foundation_publish_binding_digest,
            repair_id=repair_id,
            bootstrap_change_set_name=change_set_name,
            identity_center_instance_arn=identity_center_instance_arn,
            bootstrap_principal_id=bootstrap_principal_id,
            route_not_before=not_before,
            route_not_after=not_after,
            recovery_not_after=recovery_not_after,
            normal_plan_generated_role_arn=normal_plan_role_arn,
            normal_plan_generated_role_name=normal_plan_role_name,
            config_digest=config_digest,
            _requests_json=canonical_json(_json_copy(requests)),
            _creator_contracts_json=canonical_json(_json_copy(creator_contracts)),
            _permission_set_output_contracts_json=canonical_json(
                _json_copy(output_contracts)
            ),
            _terminal_expectations_json=canonical_json(_json_copy(expectations)),
            _revocation_assignment_scopes_json=canonical_json(_json_copy(revocations)),
        )

    def request(self, alias: str) -> dict[str, Any]:
        return dict(json.loads(self._requests_json)[alias])

    def terminal_expectation(self, alias: str) -> dict[str, Any]:
        return dict(json.loads(self._terminal_expectations_json)[alias])

    def creator_contract(self, alias: str) -> dict[str, Any]:
        return dict(json.loads(self._creator_contracts_json)[alias])

    def output_contract(self, source: str) -> dict[str, Any]:
        return dict(json.loads(self._permission_set_output_contracts_json)[source])

    def assignment_scope(self, alias: str) -> dict[str, Any]:
        return dict(json.loads(self._revocation_assignment_scopes_json)[alias])


@dataclass(frozen=True, slots=True)
class LedgerSnapshot:
    state: str
    version: int
    binding_digest: str
    last_receipt_digest: str | None = None
    last_receipt_json: str | None = None
    attempt_claim_json: str | None = None
    dispatch_coordinates_json: str | None = None
    derived_bindings_json: str | None = None


class LedgerPort(Protocol):
    def verify_control_plane(self) -> str: ...

    def initialize(self, *, ledger_id: str) -> LedgerSnapshot: ...

    def read(self, *, ledger_id: str) -> LedgerSnapshot: ...

    def compare_and_swap(
        self,
        *,
        ledger_id: str,
        expected_version: int,
        expected_state: str,
        new_state: str,
        binding_digest: str,
        receipt_digest: str,
        occurred_at: str,
        receipt_json: str | None = None,
        attempt_claim_json: str | None = None,
        dispatch_coordinates_json: str | None = None,
        derived_bindings_json: str | None = None,
    ) -> LedgerSnapshot: ...


class EffectPort(Protocol):
    def create_change_set(
        self, *, operation: str, request: Mapping[str, Any]
    ) -> Mapping[str, Any]: ...

    def execute_change_set(
        self, *, operation: str, request: Mapping[str, Any]
    ) -> Mapping[str, Any]: ...


class EvidencePort(Protocol):
    def recover_create_dispatch(
        self,
        *,
        operation: str,
        request: Mapping[str, Any],
        claim: Mapping[str, Any],
        contract: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...

    def recover_execute_dispatch(
        self,
        *,
        operation: str,
        request: Mapping[str, Any],
        claim: Mapping[str, Any],
        create_dispatch: Mapping[str, Any],
        terminal_parameters_digest: str,
        creator_request: Mapping[str, Any],
        contract: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...

    def read_change_set_ready(
        self,
        *,
        operation: str,
        request: Mapping[str, Any],
        dispatch: Mapping[str, Any],
        contract: Mapping[str, Any],
        parent_receipt_digest: str,
    ) -> Mapping[str, Any]: ...

    def read_terminal_stack(
        self,
        *,
        operation: str,
        expectation: Mapping[str, Any],
        dispatch: Mapping[str, Any],
        parent_receipt_digest: str,
    ) -> Mapping[str, Any]: ...

    def read_assignments(
        self,
        *,
        operation: str,
        scope: Mapping[str, Any],
        terminal_readback_digest: str,
    ) -> Mapping[str, Any]: ...

    def read_repair_ledger(self, *, repair_id: str) -> Mapping[str, Any]: ...

    def read_reconcile_attestation(
        self, *, attestation_id: str
    ) -> Mapping[str, Any]: ...

    def read_plan_list_change_sets_events(
        self,
        *,
        stack_name: str,
        start_time: str,
        end_time: str,
    ) -> Sequence[Mapping[str, Any]]: ...

    def read_plan_recovery_preflight(
        self,
        *,
        normal_plan_caller_arn_digest: str,
        parent_events_digest: str,
    ) -> Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class _Stage:
    expected: str
    attempting: str
    uncertain: str
    completed: str


_CREATOR_STAGES = {
    "seed-revoke-create-v1": _Stage(
        "READY", "SEED_REVOKE_CREATE_ATTEMPTING", "SEED_REVOKE_CREATE_UNCERTAIN", "SEED_REVOKE_CREATED"
    ),
    "delegation-create-v1": _Stage(
        "SEED_REVOKED", "DELEGATION_CREATE_ATTEMPTING", "DELEGATION_CREATE_UNCERTAIN", "DELEGATION_CREATED"
    ),
    "pep-create-v1": _Stage(
        "DELEGATION_TERMINAL", "PEP_CREATE_ATTEMPTING", "PEP_CREATE_UNCERTAIN", "PEP_CREATED"
    ),
    "pep-protection-create-v1": _Stage(
        "PEP_TERMINAL",
        "PEP_PROTECTION_CREATE_ATTEMPTING",
        "PEP_PROTECTION_CREATE_UNCERTAIN",
        "PEP_PROTECTION_CREATED",
    ),
    "delegation-revoke-create-v1": _Stage(
        "CLOSEOUT_PREREQUISITES_VERIFIED",
        "DELEGATION_REVOKE_CREATE_ATTEMPTING",
        "DELEGATION_REVOKE_CREATE_UNCERTAIN",
        "DELEGATION_REVOKE_CREATED",
    ),
    "route-revoke-create-v1": _Stage(
        "DELEGATION_REVOKED",
        "ROUTE_REVOKE_CREATE_ATTEMPTING",
        "ROUTE_REVOKE_CREATE_UNCERTAIN",
        "ROUTE_REVOKE_CREATED",
    ),
}
_EXECUTOR_STAGES = {
    "seed-revoke-execute-v1": _Stage(
        "SEED_REVOKE_CREATED", "SEED_REVOKE_EXECUTE_ATTEMPTING", "SEED_REVOKE_EXECUTE_UNCERTAIN", "SEED_REVOKED"
    ),
    "delegation-execute-v1": _Stage(
        "DELEGATION_CREATED", "DELEGATION_EXECUTE_ATTEMPTING", "DELEGATION_EXECUTE_UNCERTAIN", "DELEGATION_TERMINAL"
    ),
    "pep-execute-v1": _Stage(
        "PEP_CREATED", "PEP_EXECUTE_ATTEMPTING", "PEP_EXECUTE_UNCERTAIN", "PEP_TERMINAL"
    ),
    "pep-protection-execute-v1": _Stage(
        "PEP_PROTECTION_CREATED",
        "PEP_PROTECTION_EXECUTE_ATTEMPTING",
        "PEP_PROTECTION_EXECUTE_UNCERTAIN",
        "PEP_PROTECTED",
    ),
    "delegation-revoke-execute-v1": _Stage(
        "DELEGATION_REVOKE_CREATED",
        "DELEGATION_REVOKE_EXECUTE_ATTEMPTING",
        "DELEGATION_REVOKE_EXECUTE_UNCERTAIN",
        "DELEGATION_REVOKED",
    ),
    "route-revoke-execute-v1": _Stage(
        "ROUTE_REVOKE_CREATED",
        "ROUTE_REVOKE_EXECUTE_ATTEMPTING",
        "ROUTE_REVOKE_EXECUTE_UNCERTAIN",
        "ROUTE_REVOKED",
    ),
}
_REVOCATION_ALIASES = frozenset(
    {
        "seed-revoke-execute-v1",
        "delegation-revoke-execute-v1",
        "route-revoke-execute-v1",
    }
)
_EXECUTOR_TO_CREATOR = {
    "seed-revoke-execute-v1": "seed-revoke-create-v1",
    "delegation-execute-v1": "delegation-create-v1",
    "pep-execute-v1": "pep-create-v1",
    "pep-protection-execute-v1": "pep-protection-create-v1",
    "delegation-revoke-execute-v1": "delegation-revoke-create-v1",
    "route-revoke-execute-v1": "route-revoke-create-v1",
}
_CREATE_DISPATCH_FIELDS = frozenset(
    {
        "kind",
        "operation",
        "change_set_arn",
        "stack_arn",
        "create_request_id",
        "create_request_digest",
        "dispatched_at",
    }
)
_EXECUTE_DISPATCH_FIELDS = _CREATE_DISPATCH_FIELDS | frozenset(
    {
        "execute_operation",
        "execute_request_id",
        "execute_request_digest",
        "terminal_parameters_digest",
        "executed_at",
    }
)
_OPERATION_ACCOUNTS = {
    "seed-revoke-create-v1": MANAGEMENT_ACCOUNT_ID,
    "seed-revoke-execute-v1": MANAGEMENT_ACCOUNT_ID,
    "delegation-create-v1": MANAGEMENT_ACCOUNT_ID,
    "delegation-execute-v1": MANAGEMENT_ACCOUNT_ID,
    "pep-create-v1": AUTHORITY_ACCOUNT_ID,
    "pep-execute-v1": AUTHORITY_ACCOUNT_ID,
    "pep-protection-create-v1": AUTHORITY_ACCOUNT_ID,
    "pep-protection-execute-v1": AUTHORITY_ACCOUNT_ID,
    "delegation-revoke-create-v1": MANAGEMENT_ACCOUNT_ID,
    "delegation-revoke-execute-v1": MANAGEMENT_ACCOUNT_ID,
    "route-revoke-create-v1": MANAGEMENT_ACCOUNT_ID,
    "route-revoke-execute-v1": MANAGEMENT_ACCOUNT_ID,
}


def operation_account(alias: str) -> str:
    """Return the reviewed account for an alias, never from request fields."""

    try:
        return _OPERATION_ACCOUNTS[alias]
    except KeyError as exc:
        raise RouteBrokerError("OPERATION_ACCOUNT_INVALID") from exc


def _materialize_creator_request(
    *,
    alias: str,
    request: Mapping[str, Any],
    snapshot: LedgerSnapshot,
    config: BrokerConfig,
) -> dict[str, Any]:
    result = _json_copy(request)
    if alias != "pep-create-v1":
        return result
    bindings = _derived_bindings(snapshot, config)
    key = "delegation.RepairInvokerPermissionSetArn"
    permission_set_arn = bindings.get(key)
    if permission_set_arn is None:
        raise RouteBrokerError("DYNAMIC_PARAMETER_UNAVAILABLE")
    replacements = 0
    for parameter in result["Parameters"]:
        if parameter["ParameterKey"] == "RepairInvokerPermissionSetArn":
            if parameter["ParameterValue"] != REPAIR_INVOKER_PERMISSION_SET_SENTINEL:
                raise RouteBrokerError("DYNAMIC_PARAMETER_CONTRACT_INVALID")
            parameter["ParameterValue"] = permission_set_arn
            replacements += 1
    if replacements != 1:
        raise RouteBrokerError("DYNAMIC_PARAMETER_CONTRACT_INVALID")
    try:
        from tooling.platform_authority_plan_permission_repair import (
            IMMUTABLE_CONFIGURATION_PARAMETER_KEYS,
            PlanPermissionRepairError,
            immutable_configuration_digest_from_parameters,
        )
    except ImportError as exc:
        raise RouteBrokerError("IMMUTABLE_CONFIG_RUNTIME_UNAVAILABLE") from exc
    parameter_map = {
        item["ParameterKey"]: item["ParameterValue"]
        for item in result["Parameters"]
    }
    if set(IMMUTABLE_CONFIGURATION_PARAMETER_KEYS) - set(parameter_map):
        raise RouteBrokerError("IMMUTABLE_CONFIG_PARAMETERS_INVALID")
    try:
        immutable_digest = immutable_configuration_digest_from_parameters(
            {
                key: parameter_map[key]
                for key in IMMUTABLE_CONFIGURATION_PARAMETER_KEYS
            }
        )
    except PlanPermissionRepairError as exc:
        raise RouteBrokerError("IMMUTABLE_CONFIG_PARAMETERS_INVALID") from exc
    digest_replacements = 0
    for parameter in result["Parameters"]:
        if parameter["ParameterKey"] == "ImmutableConfigurationDigest":
            parameter["ParameterValue"] = immutable_digest
            digest_replacements += 1
    if digest_replacements != 1:
        raise RouteBrokerError("IMMUTABLE_CONFIG_PARAMETERS_INVALID")
    return result


def _resolved_assignment_scopes(
    *, alias: str, snapshot: LedgerSnapshot, config: BrokerConfig
) -> list[dict[str, str]]:
    configured = config.assignment_scope(alias)
    bindings = _derived_bindings(snapshot, config)
    result: list[dict[str, str]] = []
    for source in configured["permission_set_sources"]:
        binding_key = f"{source['source']}.{source['output_key']}"
        permission_set_arn = bindings.get(binding_key)
        if permission_set_arn is None:
            raise RouteBrokerError("DYNAMIC_ASSIGNMENT_SCOPE_UNAVAILABLE")
        result.append(
            {
                "account_id": configured["account_id"],
                "instance_arn": configured["instance_arn"],
                "permission_set_arn": permission_set_arn,
            }
        )
    return result


def _validate_ledger_snapshot(
    snapshot: LedgerSnapshot,
    *,
    config: BrokerConfig,
    expected_state: str | None = None,
) -> None:
    if type(snapshot) is not LedgerSnapshot:
        raise RouteBrokerError("LEDGER_RESPONSE_INVALID")
    if (
        not isinstance(snapshot.state, str)
        or type(snapshot.version) is not int
        or snapshot.version < 0
        or snapshot.binding_digest != config.ledger_binding_digest
    ):
        raise RouteBrokerError("LEDGER_BINDING_INVALID")
    if snapshot.last_receipt_digest is not None:
        _require_digest(snapshot.last_receipt_digest, "LEDGER_RECEIPT_INVALID")
    if snapshot.last_receipt_json is not None:
        _stored_receipt(snapshot, config=config)
    if snapshot.attempt_claim_json is not None:
        _attempt_claim(snapshot, config=config)
    if snapshot.dispatch_coordinates_json is not None:
        _dispatch_coordinates(snapshot)
    if snapshot.derived_bindings_json is not None:
        _derived_bindings(snapshot, config)
    if expected_state is not None and snapshot.state != expected_state:
        if snapshot.state.endswith("_UNCERTAIN") or snapshot.state in {
            "ROUTE_REVOKED",
            "DELEGATION_REVOKED",
        }:
            raise RouteBrokerError("REPLAY_REJECTED", uncertain=snapshot.state.endswith("_UNCERTAIN"))
        raise RouteBrokerError("LEDGER_STATE_MISMATCH")


def _stored_receipt(
    snapshot: LedgerSnapshot,
    *,
    config: BrokerConfig,
    alias: str | None = None,
    function_version: str | None = None,
    state: str | None = None,
) -> dict[str, Any]:
    raw = snapshot.last_receipt_json
    if not isinstance(raw, str) or snapshot.last_receipt_digest is None:
        raise RouteBrokerError("LEDGER_RECEIPT_INVALID")
    try:
        value = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RouteBrokerError("LEDGER_RECEIPT_INVALID") from exc
    if (
        not isinstance(value, dict)
        or canonical_json(value) != raw
        or set(value) != _RECEIPT_FIELDS
        or _verify_seal(value, "receipt_digest", "LEDGER_RECEIPT_INVALID")
        != snapshot.last_receipt_digest
        or value.get("schema_version") != 1
        or value.get("record_type") != RECEIPT_RECORD_TYPE
        or value.get("source_commit") != config.source_commit
        or value.get("ledger_id_digest") != digest_value(config.ledger_id)
        or value.get("config_digest") != config.config_digest
        or value.get("alias") not in (ALL_ALIASES + RECOVERY_RECEIPT_ALIASES)
        or _VERSION_RE.fullmatch(str(value.get("function_version", ""))) is None
        or value.get("state") != snapshot.state
        or value.get("retry_permitted") is not False
        or value.get("production_authorized") is not False
        or value.get("production_status") != "NO-GO"
        or value.get("event_fields_consumed") != 0
        or value.get("aws_mutations") not in {0, 1}
    ):
        raise RouteBrokerError("LEDGER_RECEIPT_INVALID")
    generated_at = _parse_time(
        value.get("generated_at"), "LEDGER_RECEIPT_INVALID"
    )
    if not config.route_not_before <= generated_at < config.recovery_not_after:
        raise RouteBrokerError("LEDGER_RECEIPT_INVALID")
    if alias is not None and value.get("alias") != alias:
        raise RouteBrokerError("LEDGER_RECEIPT_INVALID")
    if function_version is not None and value.get("function_version") != function_version:
        raise RouteBrokerError("LEDGER_RECEIPT_INVALID")
    if state is not None and value.get("state") != state:
        raise RouteBrokerError("LEDGER_RECEIPT_INVALID")
    return value


def _build_attempt_claim(
    *,
    config: BrokerConfig,
    stage: _Stage,
    kind: str,
    operation: str,
    function_version: str,
    request: Mapping[str, Any],
    claimed_at: str,
) -> dict[str, Any]:
    request_copy = _json_copy(request)
    value = {
        "schema_version": 1,
        "record_type": ATTEMPT_CLAIM_RECORD_TYPE,
        "source_commit": config.source_commit,
        "config_digest": config.config_digest,
        "ledger_id_digest": digest_value(config.ledger_id),
        "kind": kind,
        "operation": operation,
        "function_version": function_version,
        "expected_state": stage.expected,
        "attempting_state": stage.attempting,
        "request": request_copy,
        "request_digest": digest_value(request_copy),
        "claimed_at": claimed_at,
    }
    sealed = seal(value, "claim_digest")
    probe = LedgerSnapshot(
        state=stage.attempting,
        version=0,
        binding_digest=config.ledger_binding_digest,
        attempt_claim_json=canonical_json(sealed),
    )
    _attempt_claim(probe, config=config)
    return sealed


def _attempt_claim(
    snapshot: LedgerSnapshot,
    *,
    config: BrokerConfig,
    expected_operation: str | None = None,
    expected_request: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    raw = snapshot.attempt_claim_json
    if not isinstance(raw, str):
        raise RouteBrokerError("ATTEMPT_CLAIM_INVALID")
    try:
        value = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RouteBrokerError("ATTEMPT_CLAIM_INVALID") from exc
    operation = value.get("operation") if isinstance(value, Mapping) else None
    if operation in _CREATOR_STAGES:
        stage = _CREATOR_STAGES[str(operation)]
        expected_kind = "CREATE"
    elif operation in _EXECUTOR_STAGES:
        stage = _EXECUTOR_STAGES[str(operation)]
        expected_kind = "EXECUTE"
    else:
        raise RouteBrokerError("ATTEMPT_CLAIM_INVALID")
    request = value.get("request")
    if (
        not isinstance(value, dict)
        or canonical_json(value) != raw
        or set(value) != _ATTEMPT_CLAIM_FIELDS
        or _verify_seal(value, "claim_digest", "ATTEMPT_CLAIM_INVALID")
        != value.get("claim_digest")
        or value.get("schema_version") != 1
        or value.get("record_type") != ATTEMPT_CLAIM_RECORD_TYPE
        or value.get("source_commit") != config.source_commit
        or value.get("config_digest") != config.config_digest
        or value.get("ledger_id_digest") != digest_value(config.ledger_id)
        or value.get("kind") != expected_kind
        or value.get("expected_state") != stage.expected
        or value.get("attempting_state") != stage.attempting
        or not isinstance(request, Mapping)
        or value.get("request_digest") != digest_value(_json_copy(request))
        or _VERSION_RE.fullmatch(str(value.get("function_version", ""))) is None
    ):
        raise RouteBrokerError("ATTEMPT_CLAIM_INVALID")
    claimed_at = _parse_time(value.get("claimed_at"), "ATTEMPT_CLAIM_INVALID")
    if not (
        config.route_not_before
        <= claimed_at
        < config.route_not_after
        - timedelta(seconds=MUTATION_COMPLETION_RESERVE_SECONDS)
    ):
        raise RouteBrokerError("ATTEMPT_CLAIM_INVALID")
    if expected_operation is not None and operation != expected_operation:
        raise RouteBrokerError("ATTEMPT_CLAIM_INVALID")
    if expected_request is not None and _json_copy(request) != _json_copy(
        expected_request
    ):
        raise RouteBrokerError("ATTEMPT_CLAIM_INVALID")
    return value


def _dispatch_coordinates(snapshot: LedgerSnapshot) -> dict[str, Any]:
    raw = snapshot.dispatch_coordinates_json
    if not isinstance(raw, str):
        raise RouteBrokerError("DISPATCH_COORDINATES_MISSING")
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        raise RouteBrokerError("DISPATCH_COORDINATES_INVALID") from exc
    if not isinstance(value, dict) or canonical_json(value) != raw:
        raise RouteBrokerError("DISPATCH_COORDINATES_INVALID")
    fields = set(value)
    if fields not in {_CREATE_DISPATCH_FIELDS, _EXECUTE_DISPATCH_FIELDS}:
        raise RouteBrokerError("DISPATCH_COORDINATES_INVALID")
    operation = value.get("operation")
    if operation not in MUTATING_CREATOR_ALIASES or value.get("kind") != "CREATE":
        raise RouteBrokerError("DISPATCH_COORDINATES_INVALID")
    account_id = operation_account(str(operation))
    request = {
        "StackName": str(value.get("stack_arn", "")),
        "ChangeSetName": str(value.get("change_set_arn", "")),
    }
    if (
        not request["StackName"].startswith(
            f"arn:aws:cloudformation:{REGION}:{account_id}:stack/"
        )
        or not request["ChangeSetName"].startswith(
            f"arn:aws:cloudformation:{REGION}:{account_id}:changeSet/"
        )
        or _STACK_ARN_RE.fullmatch(request["StackName"]) is None
        or _CHANGE_SET_ARN_RE.fullmatch(request["ChangeSetName"]) is None
        or _UUID_RE.fullmatch(str(value.get("create_request_id", ""))) is None
    ):
        raise RouteBrokerError("DISPATCH_COORDINATES_INVALID")
    _require_digest(
        value.get("create_request_digest"), "DISPATCH_COORDINATES_INVALID"
    )
    _parse_time(value.get("dispatched_at"), "DISPATCH_COORDINATES_INVALID")
    if fields == _EXECUTE_DISPATCH_FIELDS:
        execute_operation = value.get("execute_operation")
        if (
            execute_operation not in EXECUTOR_ALIASES
            or _EXECUTOR_TO_CREATOR[str(execute_operation)] != operation
            or _UUID_RE.fullmatch(str(value.get("execute_request_id", ""))) is None
        ):
            raise RouteBrokerError("DISPATCH_COORDINATES_INVALID")
        _require_digest(
            value.get("execute_request_digest"), "DISPATCH_COORDINATES_INVALID"
        )
        _require_digest(
            value.get("terminal_parameters_digest"),
            "DISPATCH_COORDINATES_INVALID",
        )
        _parse_time(value.get("executed_at"), "DISPATCH_COORDINATES_INVALID")
    return value


def _derived_bindings(
    snapshot: LedgerSnapshot, config: BrokerConfig
) -> dict[str, str]:
    raw = snapshot.derived_bindings_json
    if not isinstance(raw, str):
        return {}
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        raise RouteBrokerError("DERIVED_BINDINGS_INVALID") from exc
    if not isinstance(value, dict) or canonical_json(value) != raw:
        raise RouteBrokerError("DERIVED_BINDINGS_INVALID")
    allowed = {
        f"{source}.{key}"
        for source in ("route", "delegation")
        for key in config.output_contract(source)["permission_set_output_keys"]
    }
    allowed.add(NORMAL_PLAN_CALLER_BINDING_KEY)
    terminal_parameter_keys = {
        TERMINAL_PARAMETERS_BINDING_PREFIX + alias
        for alias in MUTATING_CREATOR_ALIASES
    }
    allowed.update(terminal_parameter_keys)
    if not set(value).issubset(allowed):
        raise RouteBrokerError("DERIVED_BINDINGS_INVALID")
    prefix = (
        "arn:aws:sso:::permissionSet/"
        + config.identity_center_instance_arn.rsplit("/", 1)[1]
        + "/"
    )
    for key, arn in value.items():
        if key == NORMAL_PLAN_CALLER_BINDING_KEY or key in terminal_parameter_keys:
            _require_digest(arn, "DERIVED_BINDINGS_INVALID")
            continue
        if (
            not isinstance(arn, str)
            or _PERMISSION_SET_RE.fullmatch(arn) is None
            or not arn.startswith(prefix)
        ):
            raise RouteBrokerError("DERIVED_BINDINGS_INVALID")
    return {str(key): str(item) for key, item in value.items()}


def _terminal_parameters_digest(
    *, executor_alias: str, snapshot: LedgerSnapshot, config: BrokerConfig
) -> str:
    creator_alias = _EXECUTOR_TO_CREATOR.get(executor_alias)
    if creator_alias is None:
        raise RouteBrokerError("TERMINAL_PARAMETERS_BINDING_INVALID")
    value = _derived_bindings(snapshot, config).get(
        TERMINAL_PARAMETERS_BINDING_PREFIX + creator_alias
    )
    _require_digest(value, "TERMINAL_PARAMETERS_BINDING_INVALID")
    return str(value)


def _invocation_alias(
    *, config: BrokerConfig, context: Any, function_name: str, allowed: Sequence[str]
) -> tuple[str, str]:
    del config
    arn = getattr(context, "invoked_function_arn", None)
    version = getattr(context, "function_version", None)
    if not isinstance(arn, str):
        raise RouteBrokerError("INVOCATION_BINDING_INVALID")
    prefix = f"arn:aws:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:function:{function_name}:"
    if not arn.startswith(prefix):
        raise RouteBrokerError("INVOCATION_BINDING_INVALID")
    alias = arn[len(prefix) :]
    if (
        alias not in allowed
        or not isinstance(version, str)
        or _VERSION_RE.fullmatch(version) is None
    ):
        raise RouteBrokerError("INVOCATION_BINDING_INVALID")
    return alias, version


def _validate_recovery_window(
    config: BrokerConfig, now: datetime
) -> tuple[str, bool]:
    timestamp = _timestamp(now)
    parsed = _parse_time(timestamp)
    if not config.route_not_before <= parsed < config.recovery_not_after:
        raise RouteBrokerError("ROUTE_WINDOW_CLOSED")
    admission_deadline = config.route_not_after - timedelta(
        seconds=MUTATION_COMPLETION_RESERVE_SECONDS
    )
    return timestamp, parsed < admission_deadline


def _recovery_stage(
    snapshot: LedgerSnapshot, *, kind: str
) -> tuple[str, _Stage, str]:
    stages = _CREATOR_STAGES if kind == "CREATE" else _EXECUTOR_STAGES
    matches = [
        (operation, stage)
        for operation, stage in stages.items()
        if snapshot.state in {stage.attempting, stage.uncertain}
    ]
    if len(matches) != 1:
        raise RouteBrokerError("RECOVERY_STATE_INVALID")
    operation, stage = matches[0]
    dispatched_state = stage.attempting.removesuffix("_ATTEMPTING") + "_DISPATCHED"
    return operation, stage, dispatched_state


def _runtime_ledger_preflight(
    *,
    config: BrokerConfig,
    ledger: LedgerPort,
    handler_kind: str,
    alias: str,
    now: datetime,
) -> None:
    """Gate cross-account setup on a fresh, bound authority-ledger read."""

    control_digest = ledger.verify_control_plane()
    _require_digest(control_digest, "LEDGER_CONTROL_PLANE_INVALID")
    snapshot: LedgerSnapshot | None
    try:
        snapshot = ledger.read(ledger_id=config.ledger_id)
    except RouteBrokerError as exc:
        if exc.code != "LEDGER_MISSING":
            raise
        snapshot = None
    _occurred_at, mutation_open = _validate_recovery_window(config, now)
    if snapshot is not None:
        _validate_ledger_snapshot(snapshot, config=config)
    if mutation_open:
        return
    if handler_kind == "creator" and alias in _CREATOR_STAGES:
        stage = _CREATOR_STAGES[alias]
    elif handler_kind == "executor" and alias in _EXECUTOR_STAGES:
        stage = _EXECUTOR_STAGES[alias]
    else:
        raise RouteBrokerError("ROUTE_WINDOW_CLOSED")
    dispatched_state = stage.attempting.removesuffix("_ATTEMPTING") + "_DISPATCHED"
    if snapshot is None or snapshot.state != dispatched_state:
        raise RouteBrokerError("ROUTE_WINDOW_CLOSED")


def _validate_create_response(
    value: Mapping[str, Any], *, operation: str, request: Mapping[str, Any]
) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != _CREATE_RESPONSE_FIELDS:
        raise RouteBrokerError("CREATE_RESPONSE_UNCERTAIN", uncertain=True)
    result = {key: str(value[key]) for key in _CREATE_RESPONSE_FIELDS}
    account_id = operation_account(operation)
    expected_change_set_prefix = (
        f"arn:aws:cloudformation:{REGION}:{account_id}:changeSet/"
        f"{request['ChangeSetName']}/"
    )
    expected_stack_prefix = (
        f"arn:aws:cloudformation:{REGION}:{account_id}:stack/"
        f"{request['StackName']}/"
    )
    if (
        _CHANGE_SET_ARN_RE.fullmatch(result["change_set_arn"]) is None
        or _STACK_ARN_RE.fullmatch(result["stack_id"]) is None
        or not result["change_set_arn"].startswith(expected_change_set_prefix)
        or not result["stack_id"].startswith(expected_stack_prefix)
        or _UUID_RE.fullmatch(result["request_id"]) is None
    ):
        raise RouteBrokerError("CREATE_RESPONSE_UNCERTAIN", uncertain=True)
    return result


def _validate_execute_response(value: Mapping[str, Any]) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != _EXECUTE_RESPONSE_FIELDS:
        raise RouteBrokerError("EXECUTE_RESPONSE_INVALID", uncertain=True)
    request_id = value.get("request_id")
    if not isinstance(request_id, str) or _UUID_RE.fullmatch(request_id) is None:
        raise RouteBrokerError("EXECUTE_RESPONSE_INVALID", uncertain=True)
    return {"request_id": request_id}


def _validate_create_recovery(
    value: Mapping[str, Any],
    *,
    config: BrokerConfig,
    operation: str,
    request: Mapping[str, Any],
    claim: Mapping[str, Any],
    contract: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    if not isinstance(value, Mapping) or set(value) != _CREATE_RECOVERY_FIELDS:
        raise RouteBrokerError("CREATE_RECOVERY_INVALID", uncertain=True)
    digest = _verify_seal(value, "recovery_digest", "CREATE_RECOVERY_INVALID")
    dispatch = value.get("dispatch")
    readback = value.get("change_set_readback")
    if not isinstance(dispatch, Mapping) or not isinstance(readback, Mapping):
        raise RouteBrokerError("CREATE_RECOVERY_INVALID", uncertain=True)
    dispatch_copy = _json_copy(dispatch)
    probe = LedgerSnapshot(
        state=_CREATOR_STAGES[operation].attempting.removesuffix("_ATTEMPTING")
        + "_DISPATCHED",
        version=0,
        binding_digest=config.ledger_binding_digest,
        dispatch_coordinates_json=canonical_json(dispatch_copy),
    )
    validated_dispatch = _dispatch_coordinates(probe)
    recovered_at = _parse_time(
        value.get("recovered_at"), "CREATE_RECOVERY_INVALID"
    )
    claimed_at = _parse_time(claim.get("claimed_at"), "CREATE_RECOVERY_INVALID")
    dispatched_at = _parse_time(
        validated_dispatch.get("dispatched_at"), "CREATE_RECOVERY_INVALID"
    )
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != CREATE_RECOVERY_RECORD_TYPE
        or value.get("source_commit") != config.source_commit
        or value.get("account_id") != operation_account(operation)
        or value.get("region") != REGION
        or value.get("operation") != operation
        or value.get("claim_digest") != claim.get("claim_digest")
        or value.get("request_digest") != digest_value(_json_copy(request))
        or validated_dispatch.get("operation") != operation
        or validated_dispatch.get("create_request_digest")
        != value.get("request_digest")
        or not claimed_at
        <= dispatched_at
        <= recovered_at
        < config.recovery_not_after
        or dispatched_at >= config.route_not_after
    ):
        raise RouteBrokerError("CREATE_RECOVERY_INVALID", uncertain=True)
    _validate_change_set_readback(
        readback,
        config=config,
        operation=operation,
        request=request,
        dispatch=validated_dispatch,
        contract=contract,
        parent_receipt_digest=str(claim["claim_digest"]),
    )
    return validated_dispatch, digest


def _validate_execute_recovery(
    value: Mapping[str, Any],
    *,
    config: BrokerConfig,
    operation: str,
    request: Mapping[str, Any],
    claim: Mapping[str, Any],
    create_dispatch: Mapping[str, Any],
    terminal_parameters_digest: str,
    creator_request: Mapping[str, Any],
    contract: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    if not isinstance(value, Mapping) or set(value) != _EXECUTE_RECOVERY_FIELDS:
        raise RouteBrokerError("EXECUTE_RECOVERY_INVALID", uncertain=True)
    digest = _verify_seal(value, "recovery_digest", "EXECUTE_RECOVERY_INVALID")
    dispatch = value.get("dispatch")
    snapshot = value.get("change_set_snapshot")
    if not isinstance(dispatch, Mapping) or not isinstance(snapshot, Mapping):
        raise RouteBrokerError("EXECUTE_RECOVERY_INVALID", uncertain=True)
    if set(snapshot) != _RECOVERED_CHANGE_SET_SNAPSHOT_FIELDS:
        raise RouteBrokerError("EXECUTE_RECOVERY_INVALID", uncertain=True)
    dispatch_copy = _json_copy(dispatch)
    probe = LedgerSnapshot(
        state=_EXECUTOR_STAGES[operation].attempting.removesuffix("_ATTEMPTING")
        + "_DISPATCHED",
        version=0,
        binding_digest=config.ledger_binding_digest,
        dispatch_coordinates_json=canonical_json(dispatch_copy),
    )
    validated_dispatch = _dispatch_coordinates(probe)
    recovered_at = _parse_time(
        value.get("recovered_at"), "EXECUTE_RECOVERY_INVALID"
    )
    claimed_at = _parse_time(claim.get("claimed_at"), "EXECUTE_RECOVERY_INVALID")
    executed_at = _parse_time(
        validated_dispatch.get("executed_at"), "EXECUTE_RECOVERY_INVALID"
    )
    read_at = _parse_time(snapshot.get("read_at"), "EXECUTE_RECOVERY_INVALID")
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != EXECUTE_RECOVERY_RECORD_TYPE
        or value.get("source_commit") != config.source_commit
        or value.get("account_id") != operation_account(operation)
        or value.get("region") != REGION
        or value.get("operation") != operation
        or value.get("claim_digest") != claim.get("claim_digest")
        or value.get("request_digest") != digest_value(_json_copy(request))
        or any(
            validated_dispatch.get(field) != create_dispatch.get(field)
            for field in _CREATE_DISPATCH_FIELDS
        )
        or validated_dispatch.get("execute_operation") != operation
        or validated_dispatch.get("execute_request_digest")
        != value.get("request_digest")
        or validated_dispatch.get("terminal_parameters_digest")
        != terminal_parameters_digest
        or not claimed_at
        <= executed_at
        <= read_at
        <= recovered_at
        < config.recovery_not_after
        or executed_at >= config.route_not_after
        or snapshot.get("stack_arn") != create_dispatch.get("stack_arn")
        or snapshot.get("change_set_arn") != create_dispatch.get("change_set_arn")
        or snapshot.get("status") != "CREATE_COMPLETE"
        or snapshot.get("execution_status")
        not in {"EXECUTE_IN_PROGRESS", "EXECUTE_COMPLETE", "OBSOLETE"}
        or snapshot.get("creator_request_digest")
        != digest_value(_json_copy(creator_request))
        or snapshot.get("execute_request_digest")
        != digest_value(_json_copy(request))
        or snapshot.get("template_digest") != contract.get("template_digest")
        or snapshot.get("changes_digest")
        != digest_value(contract.get("expected_changes"))
        or snapshot.get("parameters_digest")
        != digest_value(creator_request.get("Parameters"))
        or snapshot.get("tags_digest") != digest_value(creator_request.get("Tags"))
        or snapshot.get("role_arn_absent") is not True
        or snapshot.get("resources_to_import_absent") is not True
    ):
        raise RouteBrokerError("EXECUTE_RECOVERY_INVALID", uncertain=True)
    _require_digest(
        snapshot.get("cloudtrail_event_digest"), "EXECUTE_RECOVERY_INVALID"
    )
    return validated_dispatch, digest


def _validate_change_set_readback(
    value: Mapping[str, Any],
    *,
    config: BrokerConfig,
    operation: str,
    request: Mapping[str, Any],
    dispatch: Mapping[str, Any],
    contract: Mapping[str, Any],
    parent_receipt_digest: str,
) -> str:
    if not isinstance(value, Mapping) or set(value) != _CHANGE_SET_READBACK_FIELDS:
        raise RouteBrokerError("CHANGE_SET_READBACK_INVALID", uncertain=True)
    digest = _verify_seal(value, "readback_digest", "CHANGE_SET_READBACK_INVALID")
    read_at = _parse_time(value.get("read_at"), "CHANGE_SET_READBACK_INVALID")
    creation_time = _parse_time(
        value.get("creation_time"), "CHANGE_SET_READBACK_INVALID"
    )
    dispatched_at = _parse_time(
        dispatch.get("dispatched_at"), "CHANGE_SET_READBACK_INVALID"
    )
    if value.get("status") in {"CREATE_PENDING", "CREATE_IN_PROGRESS"}:
        raise RouteBrokerError(
            "CHANGE_SET_NOT_READY", retryable_read_only=True
        )
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != CHANGE_SET_READBACK_RECORD_TYPE
        or value.get("operation") != operation
        or value.get("source_commit") != config.source_commit
        or value.get("account_id") != operation_account(operation)
        or value.get("region") != REGION
        or value.get("stack_name") != request["StackName"]
        or value.get("change_set_name") != request["ChangeSetName"]
        or value.get("stack_arn") != dispatch["stack_arn"]
        or value.get("change_set_arn") != dispatch["change_set_arn"]
        or value.get("create_request_id") != dispatch["create_request_id"]
        or value.get("status") != "CREATE_COMPLETE"
        or value.get("execution_status") != "AVAILABLE"
        or value.get("role_arn_absent") is not True
        or value.get("resources_to_import_absent") is not True
        or value.get("request_contract_digest") != digest_value(request)
        or value.get("template_digest") != contract["template_digest"]
        or value.get("changes_digest") != digest_value(contract["expected_changes"])
        or value.get("parent_receipt_digest") != parent_receipt_digest
        or not config.route_not_before
        <= dispatched_at
        <= creation_time
        <= config.route_not_after
        or not creation_time <= read_at < config.recovery_not_after
    ):
        raise RouteBrokerError("CHANGE_SET_READBACK_INVALID", uncertain=True)
    _require_digest(
        value.get("cloudtrail_event_digest"), "CHANGE_SET_READBACK_INVALID"
    )
    _require_digest(
        value.get("terminal_parameters_digest"),
        "CHANGE_SET_READBACK_INVALID",
    )
    source = "route" if operation == "seed-revoke-create-v1" else None
    _validate_derived_output_readback(value, config=config, source=source)
    return digest


def _validate_terminal_readback(
    value: Mapping[str, Any],
    *,
    config: BrokerConfig,
    operation: str,
    expectation: Mapping[str, Any],
    dispatch: Mapping[str, Any],
    parent_receipt_digest: str,
) -> str:
    if not isinstance(value, Mapping) or set(value) != _TERMINAL_READBACK_FIELDS:
        raise RouteBrokerError("TERMINAL_READBACK_INVALID", uncertain=True)
    digest = _verify_seal(value, "readback_digest", "TERMINAL_READBACK_INVALID")
    read_at = _parse_time(value.get("read_at"), "TERMINAL_READBACK_INVALID")
    last_updated = _parse_time(
        value.get("stack_last_updated_time"), "TERMINAL_READBACK_INVALID"
    )
    terminal_event_time = _parse_time(
        value.get("stack_terminal_event_time"), "TERMINAL_READBACK_INVALID"
    )
    executed_at = _parse_time(
        dispatch.get("executed_at"), "TERMINAL_READBACK_INVALID"
    )
    if value.get("terminal") is False:
        raise RouteBrokerError(
            "TERMINAL_READBACK_PENDING", retryable_read_only=True
        )
    live_control = value.get("live_control")
    if operation == "pep-protection-execute-v1":
        expected_table_arn = (
            f"arn:aws:dynamodb:{REGION}:{AUTHORITY_ACCOUNT_ID}:table/"
            f"{REPAIR_LEDGER_TABLE_NAME}"
        )
        if (
            not isinstance(live_control, Mapping)
            or set(live_control) != _PEP_LEDGER_LIVE_CONTROL_FIELDS
            or live_control.get("table_name") != REPAIR_LEDGER_TABLE_NAME
            or live_control.get("table_arn") != expected_table_arn
            or live_control.get("table_status") != "ACTIVE"
            or live_control.get("deletion_protection_enabled") is not True
            or live_control.get("sse_status") != "ENABLED"
            or live_control.get("sse_type") != "KMS"
            or _AUTHORITY_KMS_KEY_ARN_RE.fullmatch(
                str(live_control.get("kms_key_arn", ""))
            )
            is None
        ):
            raise RouteBrokerError("PEP_LEDGER_CONTROL_INVALID", uncertain=True)
    elif live_control != {}:
        raise RouteBrokerError("TERMINAL_READBACK_INVALID", uncertain=True)
    if value.get("live_control_digest") != digest_value(live_control):
        raise RouteBrokerError("TERMINAL_READBACK_INVALID", uncertain=True)
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != TERMINAL_READBACK_RECORD_TYPE
        or value.get("operation") != operation
        or value.get("source_commit") != config.source_commit
        or value.get("account_id") != expectation["account_id"]
        or value.get("region") != REGION
        or value.get("stack_name") != expectation["stack_name"]
        or value.get("stack_arn") != dispatch["stack_arn"]
        or value.get("execute_request_id") != dispatch["execute_request_id"]
        or value.get("role_arn_absent") is not True
        or value.get("parent_id_absent") is not True
        or value.get("root_id_absent") is not True
        or value.get("notification_arns") != []
        or value.get("template_digest") != expectation["template_digest"]
        or value.get("stack_resources_digest")
        != digest_value(expectation["expected_resources"])
        or value.get("stack_resource_count")
        != len(expectation["expected_resources"])
        or value.get("stack_outputs_digest")
        != digest_value(
            {
                "keys": expectation["expected_output_keys"],
                "static": expectation["expected_static_outputs"],
            }
        )
        or value.get("stack_tags_digest")
        != digest_value(expectation["expected_tags"])
        or value.get("stack_parameters_digest")
        != dispatch.get("terminal_parameters_digest")
        or value.get("stack_status") not in expectation["terminal_statuses"]
        or value.get("stack_status") not in _TERMINAL_STACK_STATUSES
        or value.get("terminal") is not True
        or value.get("parent_receipt_digest") != parent_receipt_digest
        or not config.route_not_before
        <= executed_at
        <= config.route_not_after
        or not executed_at <= terminal_event_time <= read_at
        or not last_updated <= read_at < config.recovery_not_after
    ):
        raise RouteBrokerError("TERMINAL_READBACK_INVALID", uncertain=True)
    _require_digest(
        value.get("execute_cloudtrail_event_digest"),
        "TERMINAL_READBACK_INVALID",
    )
    _require_digest(
        value.get("stack_terminal_event_digest"),
        "TERMINAL_READBACK_INVALID",
    )
    _require_digest(
        value.get("stack_parameters_digest"),
        "TERMINAL_READBACK_INVALID",
    )
    source = "delegation" if operation == "delegation-execute-v1" else None
    _validate_derived_output_readback(value, config=config, source=source)
    return digest


def _validate_derived_output_readback(
    value: Mapping[str, Any], *, config: BrokerConfig, source: str | None
) -> dict[str, str]:
    outputs = value.get("derived_permission_set_arns")
    source_digest = value.get("source_stack_digest")
    if source is None:
        if outputs != {} or source_digest is not None:
            raise RouteBrokerError("DYNAMIC_OUTPUT_OVERCLAIM")
        return {}
    contract = config.output_contract(source)
    expected_keys = contract["permission_set_output_keys"]
    if not isinstance(outputs, Mapping) or set(outputs) != set(expected_keys):
        raise RouteBrokerError("DYNAMIC_OUTPUT_INVALID")
    _require_digest(source_digest, "DYNAMIC_OUTPUT_INVALID")
    prefix = (
        "arn:aws:sso:::permissionSet/"
        + config.identity_center_instance_arn.rsplit("/", 1)[1]
        + "/"
    )
    for key in expected_keys:
        arn = outputs.get(key)
        if (
            not isinstance(arn, str)
            or _PERMISSION_SET_RE.fullmatch(arn) is None
            or not arn.startswith(prefix)
        ):
            raise RouteBrokerError("DYNAMIC_OUTPUT_INVALID")
    return {f"{source}.{key}": str(outputs[key]) for key in expected_keys}


def _validate_assignment_readback(
    value: Mapping[str, Any],
    *,
    config: BrokerConfig,
    operation: str,
    scope: Mapping[str, Any],
    terminal_digest: str,
) -> str:
    if not isinstance(value, Mapping) or set(value) != _ASSIGNMENT_READBACK_FIELDS:
        raise RouteBrokerError("ASSIGNMENT_READBACK_INVALID", uncertain=True)
    digest = _verify_seal(value, "readback_digest", "ASSIGNMENT_READBACK_INVALID")
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != ASSIGNMENT_READBACK_RECORD_TYPE
        or value.get("operation") != operation
        or value.get("source_commit") != config.source_commit
        or value.get("account_id") != scope["account_id"]
        or value.get("region") != REGION
        or value.get("instance_arn") != scope["instance_arn"]
        or value.get("permission_set_arn") != scope["permission_set_arn"]
        or type(value.get("assignment_count")) is not int
        or value.get("terminal_readback_digest") != terminal_digest
    ):
        raise RouteBrokerError("ASSIGNMENT_READBACK_INVALID", uncertain=True)
    if value.get("assignment_count") != 0 or value.get("terminal") is not True:
        raise RouteBrokerError("ASSIGNMENTS_REMAIN", retryable_read_only=True)
    read_at = _parse_time(value.get("read_at"), "ASSIGNMENT_READBACK_INVALID")
    if not config.route_not_before <= read_at < config.recovery_not_after:
        raise RouteBrokerError("ASSIGNMENT_READBACK_INVALID", uncertain=True)
    return digest


def _validate_repair_ledger(value: Mapping[str, Any], config: BrokerConfig) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _REPAIR_LEDGER_FIELDS:
        raise RouteBrokerError("REPAIR_LEDGER_INVALID")
    _verify_seal(value, "ledger_digest", "REPAIR_LEDGER_INVALID")
    repair_verified = (
        value.get("status") == "REPAIR_VERIFIED"
        and value.get("stage") == "FINAL_READBACK_VERIFIED"
        and value.get("effects_attempted") == 2
        and value.get("effects_completed") == 2
    )
    uncertain_reconciled = (
        value.get("status") == "UNCERTAIN_RECONCILE_ONLY"
        and value.get("stage")
        in {
            "UNCERTAIN_PROVISION_PERMISSION_SET",
            "UNCERTAIN_PROVISION_PERMISSION_SET_LEDGER_COMMIT",
            "UNCERTAIN_FINAL_READBACK",
        }
        and value.get("effects_attempted") == 2
        and value.get("effects_completed") in {1, 2}
    )
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != REPAIR_LEDGER_RECORD_TYPE
        or value.get("repair_id") != config.repair_id
        or value.get("source_commit") != config.source_commit
        or not (repair_verified or uncertain_reconciled)
        or value.get("provider_immutable") is not True
        or value.get("claim_condition") != "attribute_not_exists(repair_id)"
        or value.get("mutation_retry_attempted") is not False
        or value.get("retry_permitted") is not False
        or value.get("production_authorized") is not False
    ):
        raise RouteBrokerError("REPAIR_NOT_VERIFIED")
    _require_digest(value.get("intent_digest"), "REPAIR_LEDGER_INVALID")
    for field in ("planned_state_digest", "state_digest"):
        _require_digest(value.get(field), "REPAIR_LEDGER_INVALID")
    planned = _parse_time(value.get("planned_at"), "REPAIR_LEDGER_INVALID")
    claimed = _parse_time(value.get("claimed_at"), "REPAIR_LEDGER_INVALID")
    updated = _parse_time(value.get("updated_at"), "REPAIR_LEDGER_INVALID")
    if not planned <= claimed <= updated:
        raise RouteBrokerError("REPAIR_LEDGER_INVALID")
    return value


def _validate_attestation(
    value: Mapping[str, Any], *, config: BrokerConfig, repair_ledger: Mapping[str, Any]
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _ATTESTATION_FIELDS:
        raise RouteBrokerError("RECONCILE_ATTESTATION_INVALID")
    _verify_seal(value, "attestation_digest", "RECONCILE_ATTESTATION_INVALID")
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != RECONCILE_ATTESTATION_RECORD_TYPE
        or value.get("repair_id") != config.repair_id + "#reconcile-v1"
        or value.get("base_repair_id") != config.repair_id
        or value.get("source_commit") != config.source_commit
        or value.get("intent_digest") != repair_ledger["intent_digest"]
        or value.get("repair_ledger_digest") != repair_ledger["ledger_digest"]
        or (
            repair_ledger.get("status") == "REPAIR_VERIFIED"
            and value.get("observed_state_digest")
            != repair_ledger["state_digest"]
        )
        or value.get("function_qualifier") != "reconcile-v1"
        or not isinstance(value.get("function_version"), str)
        or _VERSION_RE.fullmatch(str(value.get("function_version"))) is None
        or value.get("status") != "RECONCILE_VERIFIED"
        or value.get("claim_condition") != "attribute_not_exists(repair_id)"
        or value.get("retry_permitted") is not False
        or value.get("production_authorized") is not False
    ):
        raise RouteBrokerError("RECONCILE_ATTESTATION_INVALID")
    _require_digest(
        value.get("invocation_authority_graph_digest"),
        "RECONCILE_ATTESTATION_INVALID",
    )
    reconciled = _parse_time(value.get("reconciled_at"), "RECONCILE_ATTESTATION_INVALID")
    if reconciled < _parse_time(repair_ledger["updated_at"]):
        raise RouteBrokerError("RECONCILE_ATTESTATION_INVALID")
    return value


def _validate_plan_event(
    value: Mapping[str, Any],
    *,
    config: BrokerConfig,
    repaired_at: datetime,
    reconciled_at: datetime,
) -> tuple[str, datetime, str]:
    if not isinstance(value, Mapping) or set(value) != _PLAN_EVENT_FIELDS:
        raise RouteBrokerError("PLAN_CLOUDTRAIL_EVENT_INVALID")
    digest = _verify_seal(value, "event_digest", "PLAN_CLOUDTRAIL_EVENT_INVALID")
    event_time = _parse_time(value.get("event_time"), "PLAN_CLOUDTRAIL_EVENT_INVALID")
    caller_arn = value.get("caller_arn")
    try:
        _normal_plan_session_name(
            caller_arn,
            generated_role_name=config.normal_plan_generated_role_name,
        )
    except RouteBrokerError as exc:
        raise RouteBrokerError("NORMAL_PLAN_PROOF_MISSING") from exc
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != PLAN_EVENT_RECORD_TYPE
        or _UUID_RE.fullmatch(str(value.get("event_id", ""))) is None
        or value.get("event_source") != "cloudformation.amazonaws.com"
        or value.get("event_name") != "ListChangeSets"
        or value.get("aws_region") != REGION
        or value.get("recipient_account_id") != AUTHORITY_ACCOUNT_ID
        or value.get("read_only") is not True
        or value.get("success") is not True
        or value.get("identity_type") != "AssumedRole"
        or value.get("identity_account_id") != AUTHORITY_ACCOUNT_ID
        or value.get("session_issuer_type") != "Role"
        or value.get("session_issuer_arn")
        != config.normal_plan_generated_role_arn
        or value.get("session_issuer_account_id") != AUTHORITY_ACCOUNT_ID
        or value.get("session_issuer_user_name")
        != config.normal_plan_generated_role_name
        or value.get("stack_name") != PLAN_STACK_NAME
        or not repaired_at < event_time <= reconciled_at
    ):
        raise RouteBrokerError("NORMAL_PLAN_PROOF_MISSING")
    return digest, event_time, str(caller_arn)


def _validate_plan_preflight(
    value: Mapping[str, Any],
    *,
    config: BrokerConfig,
    normal_plan_caller_arn_digest: str,
    parent_events_digest: str,
    latest_event_time: datetime,
) -> tuple[str, datetime]:
    if not isinstance(value, Mapping) or set(value) != _PLAN_PREFLIGHT_FIELDS:
        raise RouteBrokerError("PLAN_PREFLIGHT_INVALID")
    digest = _verify_seal(value, "readback_digest", "PLAN_PREFLIGHT_INVALID")
    read_at = _parse_time(value.get("read_at"), "PLAN_PREFLIGHT_INVALID")
    expected_stack_prefix = (
        f"arn:aws:cloudformation:{REGION}:{AUTHORITY_ACCOUNT_ID}:stack/"
        f"{PLAN_STACK_NAME}/"
    )
    public_access_block = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }
    if (
        value.get("schema_version") != 1
        or value.get("record_type") != PLAN_PREFLIGHT_RECORD_TYPE
        or value.get("source_commit") != config.source_commit
        or value.get("account_id") != AUTHORITY_ACCOUNT_ID
        or value.get("region") != REGION
        or value.get("stack_name") != PLAN_STACK_NAME
        or _STACK_ARN_RE.fullmatch(str(value.get("stack_id", ""))) is None
        or not str(value.get("stack_id", "")).startswith(expected_stack_prefix)
        or value.get("stack_status") != "REVIEW_IN_PROGRESS"
        or value.get("role_arn_absent") is not True
        or value.get("parent_id_absent") is not True
        or value.get("root_id_absent") is not True
        or value.get("notification_arns") != []
        or type(value.get("stack_resource_count")) is not int
        or value.get("stack_resource_count") != 0
        or value.get("stack_resources_digest") != digest_value([])
        or type(value.get("active_change_set_count")) is not int
        or value.get("active_change_set_count") != 0
        or value.get("active_change_sets_digest") != digest_value([])
        or type(value.get("change_set_page_count")) is not int
        or value.get("change_set_page_count") < 1
        or value.get("pagination_complete") is not True
        or value.get("public_access_block_configuration") != public_access_block
        or value.get("public_access_block_digest") != digest_value(public_access_block)
        or value.get("complete") is not True
        or value.get("normal_plan_caller_arn_digest")
        != normal_plan_caller_arn_digest
        or value.get("parent_events_digest") != parent_events_digest
        or not latest_event_time <= read_at < config.route_not_after
    ):
        raise RouteBrokerError("PLAN_PREFLIGHT_INVALID")
    return digest, read_at


def verify_closeout_prerequisites(
    *,
    config: BrokerConfig,
    evidence: EvidencePort,
    pep_receipt_digest: str,
    pep_dispatch: Mapping[str, Any],
    verification_time: datetime,
) -> dict[str, Any]:
    """Verify PEP, repair, reconcile and post-repair normal-Plan evidence."""

    _require_digest(pep_receipt_digest, "PEP_RECEIPT_INVALID")
    expectation = config.terminal_expectation("pep-protection-execute-v1")
    terminal = evidence.read_terminal_stack(
        operation="pep-protection-execute-v1",
        expectation=expectation,
        dispatch=pep_dispatch,
        parent_receipt_digest=pep_receipt_digest,
    )
    terminal_digest = _validate_terminal_readback(
        terminal,
        config=config,
        operation="pep-protection-execute-v1",
        expectation=expectation,
        dispatch=pep_dispatch,
        parent_receipt_digest=pep_receipt_digest,
    )
    repair = _validate_repair_ledger(
        evidence.read_repair_ledger(repair_id=config.repair_id), config
    )
    attestation = _validate_attestation(
        evidence.read_reconcile_attestation(
            attestation_id=config.repair_id + "#reconcile-v1"
        ),
        config=config,
        repair_ledger=repair,
    )
    repaired_at = _parse_time(repair["updated_at"])
    reconciled_at = _parse_time(attestation["reconciled_at"])
    verified_at = _parse_time(_timestamp(verification_time))
    if not reconciled_at < verified_at < config.route_not_after:
        raise RouteBrokerError("CLOSEOUT_TIME_INVALID")
    events = evidence.read_plan_list_change_sets_events(
        stack_name=PLAN_STACK_NAME,
        start_time=attestation["reconciled_at"],
        end_time=_timestamp(verified_at),
    )
    if isinstance(events, (str, bytes, Mapping)) or not isinstance(events, Sequence):
        raise RouteBrokerError("NORMAL_PLAN_PROOF_MISSING")
    if not events:
        raise RouteBrokerError(
            "NORMAL_PLAN_PROOF_PENDING", retryable_read_only=True
        )
    validated = [
        _validate_plan_event(
            event,
            config=config,
            repaired_at=reconciled_at,
            reconciled_at=verified_at,
        )
        for event in events
    ]
    event_digests = [item[0] for item in validated]
    callers = {item[2] for item in validated}
    if len(event_digests) != len(set(event_digests)) or len(callers) != 1:
        raise RouteBrokerError("NORMAL_PLAN_PROOF_MISSING")
    latest_event_time = max(item[1] for item in validated)
    if not 0 <= (verified_at - latest_event_time).total_seconds() <= (
        NORMAL_PLAN_MAX_EVENT_AGE_SECONDS
    ):
        raise RouteBrokerError("NORMAL_PLAN_PROOF_MISSING")
    normal_plan_caller_arn = next(iter(callers))
    normal_plan_caller_arn_digest = digest_value(
        {"caller_arn": normal_plan_caller_arn}
    )
    events_digest = digest_value(sorted(event_digests))
    preflight = evidence.read_plan_recovery_preflight(
        normal_plan_caller_arn_digest=normal_plan_caller_arn_digest,
        parent_events_digest=events_digest,
    )
    preflight_digest, preflight_read_at = _validate_plan_preflight(
        preflight,
        config=config,
        normal_plan_caller_arn_digest=normal_plan_caller_arn_digest,
        parent_events_digest=events_digest,
        latest_event_time=latest_event_time,
    )
    return {
        "pep_terminal_readback_digest": terminal_digest,
        "repair_ledger_digest": str(repair["ledger_digest"]),
        "reconcile_attestation_digest": str(attestation["attestation_digest"]),
        "normal_plan_caller_arn_digest": normal_plan_caller_arn_digest,
        "normal_plan_event_count": len(event_digests),
        "normal_plan_events_digest": events_digest,
        "normal_plan_latest_event_time": _timestamp(latest_event_time),
        "normal_plan_preflight_digest": preflight_digest,
        "normal_plan_preflight_read_at": _timestamp(preflight_read_at),
    }


class RouteBroker:
    """One-shot state machine over injected ledger, effect and evidence ports."""

    def __init__(
        self,
        *,
        config: BrokerConfig,
        ledger: LedgerPort,
        effects: EffectPort,
        evidence: EvidencePort,
        clock: Callable[[], datetime],
    ) -> None:
        self._config = config
        self._ledger = ledger
        self._effects = effects
        self._evidence = evidence
        self._clock = clock
        self._budget: _InvocationBudget | None = None

    def _begin_invocation(self, context: Any) -> None:
        budget = _InvocationBudget(context)
        self._budget = budget
        for port in (self._ledger, self._evidence):
            configure = getattr(port, "set_budget", None)
            if callable(configure):
                configure(budget)

    def _require_mutation_budget(self) -> None:
        if self._budget is None:
            raise RouteBrokerError("TIME_BUDGET_INVALID")
        self._budget.require_mutation()

    def _require_read_budget(self) -> None:
        if self._budget is None:
            raise RouteBrokerError("TIME_BUDGET_INVALID")
        self._budget.require_read()

    def _require_readback_cas_budget(self) -> None:
        if self._budget is None:
            raise RouteBrokerError("TIME_BUDGET_INVALID")
        self._budget.require_readback_cas()

    def _verify_ledger_control_plane(self) -> str:
        self._require_read_budget()
        try:
            digest = self._ledger.verify_control_plane()
        except RouteBrokerError:
            raise
        except Exception as exc:
            raise RouteBrokerError("LEDGER_CONTROL_PLANE_INVALID") from exc
        return _require_digest(digest, "LEDGER_CONTROL_PLANE_INVALID")

    def _read_raw(self) -> LedgerSnapshot:
        self._require_read_budget()
        try:
            snapshot = self._ledger.read(ledger_id=self._config.ledger_id)
        except RouteBrokerError:
            raise
        except Exception as exc:
            raise RouteBrokerError("LEDGER_READ_FAILED") from exc
        _validate_ledger_snapshot(snapshot, config=self._config)
        return snapshot

    def _read(self, expected_state: str) -> LedgerSnapshot:
        snapshot = self._read_raw()
        _validate_ledger_snapshot(
            snapshot, config=self._config, expected_state=expected_state
        )
        return snapshot

    def _initialize(self) -> LedgerSnapshot:
        self._require_mutation_budget()
        try:
            snapshot = self._ledger.initialize(ledger_id=self._config.ledger_id)
        except Exception as exc:
            raise RouteBrokerError(
                "LEDGER_INITIALIZATION_UNCERTAIN", uncertain=True
            ) from exc
        _validate_ledger_snapshot(snapshot, config=self._config)
        return snapshot

    def _cas(
        self,
        snapshot: LedgerSnapshot,
        *,
        new_state: str,
        receipt_digest: str,
        occurred_at: str,
        dispatch_coordinates: Mapping[str, Any] | None = None,
        derived_bindings: Mapping[str, str] | None = None,
        receipt_payload: Mapping[str, Any] | None = None,
        attempt_claim: Mapping[str, Any] | None = None,
        after_provider_effect: bool = False,
    ) -> LedgerSnapshot:
        if not after_provider_effect:
            self._require_readback_cas_budget()
        _require_digest(receipt_digest, "LEDGER_RECEIPT_INVALID")
        receipt_json: str | None = None
        if receipt_payload is not None:
            receipt_copy = _json_copy(receipt_payload)
            if (
                not isinstance(receipt_copy, dict)
                or _verify_seal(
                    receipt_copy, "receipt_digest", "LEDGER_RECEIPT_INVALID"
                )
                != receipt_digest
            ):
                raise RouteBrokerError("LEDGER_RECEIPT_INVALID")
            receipt_json = canonical_json(receipt_copy)
        dispatch_json = (
            canonical_json(_json_copy(dispatch_coordinates))
            if dispatch_coordinates is not None
            else None
        )
        bindings_json = (
            canonical_json(_json_copy(derived_bindings))
            if derived_bindings is not None
            else None
        )
        attempt_claim_json = (
            canonical_json(_json_copy(attempt_claim))
            if attempt_claim is not None
            else None
        )
        if attempt_claim_json is not None:
            claim_probe = LedgerSnapshot(
                state=new_state,
                version=snapshot.version + 1,
                binding_digest=self._config.ledger_binding_digest,
                attempt_claim_json=attempt_claim_json,
            )
            _attempt_claim(claim_probe, config=self._config)
        try:
            changed = self._ledger.compare_and_swap(
                ledger_id=self._config.ledger_id,
                expected_version=snapshot.version,
                expected_state=snapshot.state,
                new_state=new_state,
                binding_digest=self._config.ledger_binding_digest,
                receipt_digest=receipt_digest,
                occurred_at=occurred_at,
                receipt_json=receipt_json,
                attempt_claim_json=attempt_claim_json,
                dispatch_coordinates_json=dispatch_json,
                derived_bindings_json=bindings_json,
            )
        except Exception as exc:
            raise RouteBrokerError("LEDGER_CAS_FAILED") from exc
        _validate_ledger_snapshot(changed, config=self._config, expected_state=new_state)
        if changed.version != snapshot.version + 1 or changed.last_receipt_digest != receipt_digest:
            raise RouteBrokerError("LEDGER_CAS_FAILED")
        if receipt_json is not None and changed.last_receipt_json != receipt_json:
            raise RouteBrokerError("LEDGER_CAS_FAILED")
        if (
            attempt_claim_json is not None
            and changed.attempt_claim_json != attempt_claim_json
        ):
            raise RouteBrokerError("LEDGER_CAS_FAILED")
        if dispatch_json is not None and changed.dispatch_coordinates_json != dispatch_json:
            raise RouteBrokerError("LEDGER_CAS_FAILED")
        if bindings_json is not None and changed.derived_bindings_json != bindings_json:
            raise RouteBrokerError("LEDGER_CAS_FAILED")
        return changed

    def _mark_uncertain(
        self,
        attempt: LedgerSnapshot,
        *,
        uncertain_state: str,
        alias: str,
        occurred_at: str,
    ) -> None:
        failure_digest = digest_value(
            {
                "alias": alias,
                "attempt_state": attempt.state,
                "config_digest": self._config.config_digest,
                "outcome": "UNCERTAIN_NO_RETRY",
            }
        )
        try:
            self._cas(
                attempt,
                new_state=uncertain_state,
                receipt_digest=failure_digest,
                occurred_at=occurred_at,
                after_provider_effect=True,
            )
        except RouteBrokerError:
            # Never read/retry after an effect; ATTEMPTING itself blocks replay.
            pass

    def _mark_readback_uncertain(
        self,
        snapshot: LedgerSnapshot,
        *,
        uncertain_state: str,
        alias: str,
        error_code: str,
        occurred_at: str,
    ) -> None:
        """Persist a terminal evidence contradiction without provider replay."""

        failure_digest = digest_value(
            {
                "alias": alias,
                "dispatched_state": snapshot.state,
                "config_digest": self._config.config_digest,
                "error_code": error_code,
                "outcome": "TERMINAL_READBACK_CONTRADICTION",
                "aws_mutations": 0,
            }
        )
        self._cas(
            snapshot,
            new_state=uncertain_state,
            receipt_digest=failure_digest,
            occurred_at=occurred_at,
            after_provider_effect=True,
        )

    def _receipt(
        self,
        *,
        alias: str,
        function_version: str,
        state: str,
        request_digest: str | None,
        provider_digest: str | None,
        change_set_digest: str | None,
        terminal_digest: str | None,
        assignment_digest: str | None,
        assignment_readback_count: int,
        closeout_digest: str | None,
        normal_plan_caller_arn_digest: str | None = None,
        generated_at: str,
        aws_mutations: int,
    ) -> dict[str, Any]:
        if normal_plan_caller_arn_digest is not None:
            _require_digest(
                normal_plan_caller_arn_digest,
                "NORMAL_PLAN_CALLER_INVALID",
            )
        value = {
            "schema_version": 1,
            "record_type": RECEIPT_RECORD_TYPE,
            "source_commit": self._config.source_commit,
            "ledger_id_digest": digest_value(self._config.ledger_id),
            "config_digest": self._config.config_digest,
            "alias": alias,
            "function_version": function_version,
            "state": state,
            "request_digest": request_digest,
            "provider_digest": provider_digest,
            "change_set_readback_digest": change_set_digest,
            "terminal_readback_digest": terminal_digest,
            "assignment_readback_digest": assignment_digest,
            "assignment_readback_count": assignment_readback_count,
            "closeout_evidence_digest": closeout_digest,
            "normal_plan_caller_arn_digest": normal_plan_caller_arn_digest,
            "aws_mutations": aws_mutations,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": "NO-GO",
            "event_fields_consumed": 0,
            "generated_at": generated_at,
        }
        return seal(value, "receipt_digest")

    def creator_handler(self, event: Any, context: Any) -> dict[str, Any]:
        validate_empty_event(event)
        self._begin_invocation(context)
        alias, function_version = _invocation_alias(
            config=self._config,
            context=context,
            function_name=CREATOR_FUNCTION_NAME,
            allowed=CREATOR_ALIASES,
        )
        self._verify_ledger_control_plane()
        snapshot: LedgerSnapshot | None = None
        ledger_error: RouteBrokerError | None = None
        try:
            snapshot = self._read_raw()
        except RouteBrokerError as exc:
            ledger_error = exc
        occurred_at, mutation_open = _validate_recovery_window(
            self._config, self._clock()
        )
        if alias == "closeout-gate-v1":
            if ledger_error is not None:
                raise ledger_error
            if snapshot is None:
                raise RouteBrokerError("LEDGER_MISSING")
            if (
                snapshot.state != "CLOSEOUT_PREREQUISITES_VERIFIED"
                and not mutation_open
            ):
                raise RouteBrokerError("ROUTE_WINDOW_CLOSED")
            return self._closeout(
                alias=alias,
                function_version=function_version,
                occurred_at=occurred_at,
                snapshot=snapshot,
            )
        stage = _CREATOR_STAGES[alias]
        if ledger_error is not None:
            if alias != "seed-revoke-create-v1" or ledger_error.code != "LEDGER_MISSING":
                raise ledger_error
            if not mutation_open:
                raise RouteBrokerError("ROUTE_WINDOW_CLOSED")
            snapshot = self._initialize()
        if snapshot is None:
            raise RouteBrokerError("LEDGER_MISSING")
        request = _materialize_creator_request(
            alias=alias,
            request=self._config.request(alias),
            snapshot=snapshot,
            config=self._config,
        )
        request_digest = digest_value(request)
        dispatched_state = stage.attempting.removesuffix("_ATTEMPTING") + "_DISPATCHED"
        if snapshot.state == dispatched_state:
            return self._creator_readback(
                alias=alias,
                function_version=function_version,
                stage=stage,
                snapshot=snapshot,
                request=request,
                request_digest=request_digest,
                occurred_at=occurred_at,
            )
        if not mutation_open:
            raise RouteBrokerError("ROUTE_WINDOW_CLOSED")
        _validate_ledger_snapshot(
            snapshot, config=self._config, expected_state=stage.expected
        )
        attempt_claim = _build_attempt_claim(
            config=self._config,
            stage=stage,
            kind="CREATE",
            operation=alias,
            function_version=function_version,
            request=request,
            claimed_at=occurred_at,
        )
        attempt_digest = str(attempt_claim["claim_digest"])
        self._require_mutation_budget()
        attempt = self._cas(
            snapshot,
            new_state=stage.attempting,
            receipt_digest=attempt_digest,
            occurred_at=occurred_at,
            attempt_claim=attempt_claim,
            after_provider_effect=True,
        )
        try:
            response = _validate_create_response(
                self._effects.create_change_set(
                    operation=alias, request=_json_copy(request)
                ),
                operation=alias,
                request=request,
            )
            # Preserve the pre-call boundary: the accepted mutation must have
            # begun inside the route window even if the SDK response arrives
            # after it closes.
            dispatched_at = occurred_at
            dispatch = {
                "kind": "CREATE",
                "operation": alias,
                "change_set_arn": response["change_set_arn"],
                "stack_arn": response["stack_id"],
                "create_request_id": response["request_id"],
                "create_request_digest": request_digest,
                "dispatched_at": dispatched_at,
            }
            provider_digest = digest_value(response)
            receipt = self._receipt(
                alias=alias,
                function_version=function_version,
                state=dispatched_state,
                request_digest=request_digest,
                provider_digest=provider_digest,
                change_set_digest=None,
                terminal_digest=None,
                assignment_digest=None,
                assignment_readback_count=0,
                closeout_digest=None,
                generated_at=_timestamp(self._clock()),
                aws_mutations=1,
            )
            self._cas(
                attempt,
                new_state=dispatched_state,
                receipt_digest=receipt["receipt_digest"],
                occurred_at=dispatched_at,
                receipt_payload=receipt,
                dispatch_coordinates=dispatch,
                after_provider_effect=True,
            )
            return receipt
        except Exception as exc:
            self._mark_uncertain(
                attempt,
                uncertain_state=stage.uncertain,
                alias=alias,
                occurred_at=_timestamp(self._clock()),
            )
            raise RouteBrokerError("CREATE_CHANGE_SET_UNCERTAIN", uncertain=True) from exc

    def _creator_readback(
        self,
        *,
        alias: str,
        function_version: str,
        stage: _Stage,
        snapshot: LedgerSnapshot,
        request: Mapping[str, Any],
        request_digest: str,
        occurred_at: str,
    ) -> dict[str, Any]:
        if snapshot.last_receipt_digest is None:
            raise RouteBrokerError("CREATE_DISPATCH_RECEIPT_INVALID")
        dispatch = _dispatch_coordinates(snapshot)
        if dispatch["operation"] != alias:
            raise RouteBrokerError("DISPATCH_COORDINATES_INVALID")
        contract = self._config.creator_contract(alias)
        try:
            self._require_read_budget()
            readback = self._evidence.read_change_set_ready(
                operation=alias,
                request=request,
                dispatch=dispatch,
                contract=contract,
                parent_receipt_digest=snapshot.last_receipt_digest,
            )
            readback_digest = _validate_change_set_readback(
                readback,
                config=self._config,
                operation=alias,
                request=request,
                dispatch=dispatch,
                contract=contract,
                parent_receipt_digest=snapshot.last_receipt_digest,
            )
            bindings = _derived_bindings(snapshot, self._config)
            bindings.update(
                _validate_derived_output_readback(
                    readback,
                    config=self._config,
                    source="route" if alias == "seed-revoke-create-v1" else None,
                )
            )
            bindings[TERMINAL_PARAMETERS_BINDING_PREFIX + alias] = str(
                readback["terminal_parameters_digest"]
            )
            receipt = self._receipt(
                alias=alias,
                function_version=function_version,
                state=stage.completed,
                request_digest=request_digest,
                provider_digest=None,
                change_set_digest=readback_digest,
                terminal_digest=None,
                assignment_digest=None,
                assignment_readback_count=0,
                closeout_digest=None,
                generated_at=_timestamp(self._clock()),
                aws_mutations=0,
            )
            self._cas(
                snapshot,
                new_state=stage.completed,
                receipt_digest=receipt["receipt_digest"],
                occurred_at=_timestamp(self._clock()),
                receipt_payload=receipt,
                derived_bindings=bindings,
            )
            return receipt
        except RouteBrokerError as exc:
            if not exc.retryable_read_only:
                self._mark_readback_uncertain(
                    snapshot,
                    uncertain_state=stage.uncertain,
                    alias=alias,
                    error_code=exc.code,
                    occurred_at=occurred_at,
                )
            raise
        except Exception as exc:
            raise RouteBrokerError(
                "CREATE_READBACK_PENDING", retryable_read_only=True
            ) from exc

    def executor_handler(self, event: Any, context: Any) -> dict[str, Any]:
        validate_empty_event(event)
        self._begin_invocation(context)
        alias, function_version = _invocation_alias(
            config=self._config,
            context=context,
            function_name=EXECUTOR_FUNCTION_NAME,
            allowed=EXECUTOR_ALIASES,
        )
        self._verify_ledger_control_plane()
        snapshot = self._read_raw()
        occurred_at, mutation_open = _validate_recovery_window(
            self._config, self._clock()
        )
        stage = _EXECUTOR_STAGES[alias]
        configured_request = self._config.request(alias)
        create_dispatch = _dispatch_coordinates(snapshot)
        if create_dispatch["operation"] != _EXECUTOR_TO_CREATOR[alias]:
            raise RouteBrokerError("DISPATCH_COORDINATES_INVALID")
        request = dict(configured_request)
        request["StackName"] = create_dispatch["stack_arn"]
        request["ChangeSetName"] = create_dispatch["change_set_arn"]
        request_digest = digest_value(request)
        dispatched_state = stage.attempting.removesuffix("_ATTEMPTING") + "_DISPATCHED"
        if snapshot.state == dispatched_state:
            return self._executor_readback(
                alias=alias,
                function_version=function_version,
                stage=stage,
                snapshot=snapshot,
                request_digest=request_digest,
                occurred_at=occurred_at,
            )
        if not mutation_open:
            raise RouteBrokerError("ROUTE_WINDOW_CLOSED")
        _validate_ledger_snapshot(
            snapshot, config=self._config, expected_state=stage.expected
        )
        terminal_parameters_digest = _terminal_parameters_digest(
            executor_alias=alias,
            snapshot=snapshot,
            config=self._config,
        )
        attempt_claim = _build_attempt_claim(
            config=self._config,
            stage=stage,
            kind="EXECUTE",
            operation=alias,
            function_version=function_version,
            request=request,
            claimed_at=occurred_at,
        )
        attempt_digest = str(attempt_claim["claim_digest"])
        self._require_mutation_budget()
        attempt = self._cas(
            snapshot,
            new_state=stage.attempting,
            receipt_digest=attempt_digest,
            occurred_at=occurred_at,
            attempt_claim=attempt_claim,
            after_provider_effect=True,
        )
        try:
            response = _validate_execute_response(
                self._effects.execute_change_set(
                    operation=alias, request=_json_copy(request)
                )
            )
            provider_digest = digest_value(_json_copy(response))
            # CloudFormation may stamp the stack when it accepts the request,
            # before the SDK response returns.  Preserve the pre-call attempt
            # boundary so terminal evidence can be ordered without a race.
            executed_at = occurred_at
            dispatch = dict(create_dispatch)
            dispatch.update(
                {
                    "execute_operation": alias,
                    "execute_request_id": response["request_id"],
                    "execute_request_digest": request_digest,
                    "terminal_parameters_digest": terminal_parameters_digest,
                    "executed_at": executed_at,
                }
            )
            receipt = self._receipt(
                alias=alias,
                function_version=function_version,
                state=dispatched_state,
                request_digest=request_digest,
                provider_digest=provider_digest,
                change_set_digest=None,
                terminal_digest=None,
                assignment_digest=None,
                assignment_readback_count=0,
                closeout_digest=None,
                generated_at=_timestamp(self._clock()),
                aws_mutations=1,
            )
            self._cas(
                attempt,
                new_state=dispatched_state,
                receipt_digest=receipt["receipt_digest"],
                occurred_at=executed_at,
                receipt_payload=receipt,
                dispatch_coordinates=dispatch,
                after_provider_effect=True,
            )
            return receipt
        except Exception as exc:
            self._mark_uncertain(
                attempt,
                uncertain_state=stage.uncertain,
                alias=alias,
                occurred_at=_timestamp(self._clock()),
            )
            raise RouteBrokerError("EXECUTE_CHANGE_SET_UNCERTAIN", uncertain=True) from exc

    def _executor_readback(
        self,
        *,
        alias: str,
        function_version: str,
        stage: _Stage,
        snapshot: LedgerSnapshot,
        request_digest: str,
        occurred_at: str,
    ) -> dict[str, Any]:
        if snapshot.last_receipt_digest is None:
            raise RouteBrokerError("EXECUTE_DISPATCH_RECEIPT_INVALID")
        dispatch = _dispatch_coordinates(snapshot)
        if dispatch.get("execute_operation") != alias:
            raise RouteBrokerError("DISPATCH_COORDINATES_INVALID")
        try:
            expectation = self._config.terminal_expectation(alias)
            self._require_read_budget()
            terminal = self._evidence.read_terminal_stack(
                operation=alias,
                expectation=expectation,
                dispatch=dispatch,
                parent_receipt_digest=snapshot.last_receipt_digest,
            )
            terminal_digest = _validate_terminal_readback(
                terminal,
                config=self._config,
                operation=alias,
                expectation=expectation,
                dispatch=dispatch,
                parent_receipt_digest=snapshot.last_receipt_digest,
            )
            assignment_digest = None
            assignment_digests: list[str] = []
            if alias in _REVOCATION_ALIASES:
                for scope in _resolved_assignment_scopes(
                    alias=alias, snapshot=snapshot, config=self._config
                ):
                    self._require_read_budget()
                    assignment = self._evidence.read_assignments(
                        operation=alias,
                        scope=scope,
                        terminal_readback_digest=terminal_digest,
                    )
                    assignment_digests.append(
                        _validate_assignment_readback(
                            assignment,
                            config=self._config,
                            operation=alias,
                            scope=scope,
                            terminal_digest=terminal_digest,
                        )
                    )
                assignment_digest = digest_value(assignment_digests)
            bindings = _derived_bindings(snapshot, self._config)
            bindings.update(
                _validate_derived_output_readback(
                    terminal,
                    config=self._config,
                    source="delegation" if alias == "delegation-execute-v1" else None,
                )
            )
            receipt = self._receipt(
                alias=alias,
                function_version=function_version,
                state=stage.completed,
                request_digest=request_digest,
                provider_digest=None,
                change_set_digest=None,
                terminal_digest=terminal_digest,
                assignment_digest=assignment_digest,
                assignment_readback_count=(
                    len(assignment_digests) if alias in _REVOCATION_ALIASES else 0
                ),
                closeout_digest=None,
                generated_at=_timestamp(self._clock()),
                aws_mutations=0,
            )
            self._cas(
                snapshot,
                new_state=stage.completed,
                receipt_digest=receipt["receipt_digest"],
                occurred_at=_timestamp(self._clock()),
                receipt_payload=receipt,
                derived_bindings=bindings,
            )
            return receipt
        except RouteBrokerError as exc:
            if not exc.retryable_read_only:
                self._mark_readback_uncertain(
                    snapshot,
                    uncertain_state=stage.uncertain,
                    alias=alias,
                    error_code=exc.code,
                    occurred_at=occurred_at,
                )
            raise
        except Exception as exc:
            raise RouteBrokerError(
                "EXECUTE_READBACK_PENDING", retryable_read_only=True
            ) from exc

    def create_dispatch_recovery_handler(
        self, event: Any, context: Any
    ) -> dict[str, Any]:
        validate_empty_event(event)
        self._begin_invocation(context)
        _alias, function_version = _invocation_alias(
            config=self._config,
            context=context,
            function_name=CREATE_RECOVERY_FUNCTION_NAME,
            allowed=(RECOVERY_ALIAS,),
        )
        self._verify_ledger_control_plane()
        snapshot = self._read_raw()
        _occurred_at, _mutation_open = _validate_recovery_window(
            self._config, self._clock()
        )
        claim = _attempt_claim(snapshot, config=self._config)
        operation = str(claim["operation"])
        if operation not in _CREATOR_STAGES or claim.get("kind") != "CREATE":
            raise RouteBrokerError("ATTEMPT_CLAIM_INVALID")
        stage = _CREATOR_STAGES[operation]
        dispatched_state = (
            stage.attempting.removesuffix("_ATTEMPTING") + "_DISPATCHED"
        )
        if snapshot.state == dispatched_state:
            return _stored_receipt(
                snapshot,
                config=self._config,
                alias=RECOVERY_RECEIPT_ALIASES[0],
                function_version=function_version,
                state=dispatched_state,
            )
        if snapshot.state not in {stage.attempting, stage.uncertain}:
            raise RouteBrokerError("RECOVERY_STATE_INVALID")
        request = _materialize_creator_request(
            alias=operation,
            request=self._config.request(operation),
            snapshot=snapshot,
            config=self._config,
        )
        _attempt_claim(
            snapshot,
            config=self._config,
            expected_operation=operation,
            expected_request=request,
        )
        contract = self._config.creator_contract(operation)
        self._require_read_budget()
        recovery = self._evidence.recover_create_dispatch(
            operation=operation,
            request=request,
            claim=claim,
            contract=contract,
        )
        dispatch, recovery_digest = _validate_create_recovery(
            recovery,
            config=self._config,
            operation=operation,
            request=request,
            claim=claim,
            contract=contract,
        )
        recovered_at = str(recovery["recovered_at"])
        receipt = self._receipt(
            alias=RECOVERY_RECEIPT_ALIASES[0],
            function_version=function_version,
            state=dispatched_state,
            request_digest=str(claim["request_digest"]),
            provider_digest=recovery_digest,
            change_set_digest=str(
                recovery["change_set_readback"]["readback_digest"]
            ),
            terminal_digest=None,
            assignment_digest=None,
            assignment_readback_count=0,
            closeout_digest=None,
            generated_at=recovered_at,
            aws_mutations=0,
        )
        self._cas(
            snapshot,
            new_state=dispatched_state,
            receipt_digest=receipt["receipt_digest"],
            occurred_at=recovered_at,
            receipt_payload=receipt,
            dispatch_coordinates=dispatch,
        )
        return receipt

    def execute_dispatch_recovery_handler(
        self, event: Any, context: Any
    ) -> dict[str, Any]:
        validate_empty_event(event)
        self._begin_invocation(context)
        _alias, function_version = _invocation_alias(
            config=self._config,
            context=context,
            function_name=EXECUTE_RECOVERY_FUNCTION_NAME,
            allowed=(RECOVERY_ALIAS,),
        )
        self._verify_ledger_control_plane()
        snapshot = self._read_raw()
        _occurred_at, _mutation_open = _validate_recovery_window(
            self._config, self._clock()
        )
        claim = _attempt_claim(snapshot, config=self._config)
        operation = str(claim["operation"])
        if operation not in _EXECUTOR_STAGES or claim.get("kind") != "EXECUTE":
            raise RouteBrokerError("ATTEMPT_CLAIM_INVALID")
        stage = _EXECUTOR_STAGES[operation]
        dispatched_state = (
            stage.attempting.removesuffix("_ATTEMPTING") + "_DISPATCHED"
        )
        if snapshot.state == dispatched_state:
            return _stored_receipt(
                snapshot,
                config=self._config,
                alias=RECOVERY_RECEIPT_ALIASES[1],
                function_version=function_version,
                state=dispatched_state,
            )
        if snapshot.state not in {stage.attempting, stage.uncertain}:
            raise RouteBrokerError("RECOVERY_STATE_INVALID")
        create_dispatch = _dispatch_coordinates(snapshot)
        if create_dispatch["operation"] != _EXECUTOR_TO_CREATOR[operation]:
            raise RouteBrokerError("DISPATCH_COORDINATES_INVALID")
        request = self._config.request(operation)
        request["StackName"] = create_dispatch["stack_arn"]
        request["ChangeSetName"] = create_dispatch["change_set_arn"]
        _attempt_claim(
            snapshot,
            config=self._config,
            expected_operation=operation,
            expected_request=request,
        )
        creator_operation = _EXECUTOR_TO_CREATOR[operation]
        creator_request = _materialize_creator_request(
            alias=creator_operation,
            request=self._config.request(creator_operation),
            snapshot=snapshot,
            config=self._config,
        )
        contract = self._config.creator_contract(creator_operation)
        terminal_parameters_digest = _terminal_parameters_digest(
            executor_alias=operation,
            snapshot=snapshot,
            config=self._config,
        )
        self._require_read_budget()
        recovery = self._evidence.recover_execute_dispatch(
            operation=operation,
            request=request,
            claim=claim,
            create_dispatch=create_dispatch,
            terminal_parameters_digest=terminal_parameters_digest,
            creator_request=creator_request,
            contract=contract,
        )
        dispatch, recovery_digest = _validate_execute_recovery(
            recovery,
            config=self._config,
            operation=operation,
            request=request,
            claim=claim,
            create_dispatch=create_dispatch,
            terminal_parameters_digest=terminal_parameters_digest,
            creator_request=creator_request,
            contract=contract,
        )
        recovered_at = str(recovery["recovered_at"])
        receipt = self._receipt(
            alias=RECOVERY_RECEIPT_ALIASES[1],
            function_version=function_version,
            state=dispatched_state,
            request_digest=str(claim["request_digest"]),
            provider_digest=recovery_digest,
            change_set_digest=None,
            terminal_digest=None,
            assignment_digest=None,
            assignment_readback_count=0,
            closeout_digest=None,
            generated_at=recovered_at,
            aws_mutations=0,
        )
        self._cas(
            snapshot,
            new_state=dispatched_state,
            receipt_digest=receipt["receipt_digest"],
            occurred_at=recovered_at,
            receipt_payload=receipt,
            dispatch_coordinates=dispatch,
        )
        return receipt

    def _closeout(
        self,
        *,
        alias: str,
        function_version: str,
        occurred_at: str,
        snapshot: LedgerSnapshot,
    ) -> dict[str, Any]:
        if snapshot.state == "CLOSEOUT_PREREQUISITES_VERIFIED":
            recovered = _stored_receipt(
                snapshot,
                config=self._config,
                alias=alias,
                function_version=function_version,
                state="CLOSEOUT_PREREQUISITES_VERIFIED",
            )
            if (
                recovered.get("aws_mutations") != 0
                or recovered.get("request_digest") is not None
                or recovered.get("provider_digest") is not None
                or recovered.get("closeout_evidence_digest") is None
                or recovered.get("normal_plan_caller_arn_digest") is None
            ):
                raise RouteBrokerError("LEDGER_RECEIPT_INVALID")
            return recovered
        _validate_ledger_snapshot(
            snapshot, config=self._config, expected_state="PEP_PROTECTED"
        )
        if snapshot.last_receipt_digest is None:
            raise RouteBrokerError("PEP_RECEIPT_INVALID")
        pep_dispatch = _dispatch_coordinates(snapshot)
        if pep_dispatch.get("execute_operation") != "pep-protection-execute-v1":
            raise RouteBrokerError("DISPATCH_COORDINATES_INVALID")
        try:
            self._require_read_budget()
            evidence = verify_closeout_prerequisites(
                config=self._config,
                evidence=self._evidence,
                pep_receipt_digest=snapshot.last_receipt_digest,
                pep_dispatch=pep_dispatch,
                verification_time=_parse_time(occurred_at),
            )
            closeout_completed_at = _parse_time(_timestamp(self._clock()))
            preflight_read_at = _parse_time(
                evidence["normal_plan_preflight_read_at"]
            )
            latest_event_time = _parse_time(
                evidence["normal_plan_latest_event_time"]
            )
            event_age_at_completion = (
                closeout_completed_at - latest_event_time
            ).total_seconds()
            if not (
                preflight_read_at <= closeout_completed_at
                < self._config.route_not_after
                and 0
                <= event_age_at_completion
                <= NORMAL_PLAN_MAX_EVENT_AGE_SECONDS
            ):
                raise RouteBrokerError("NORMAL_PLAN_PROOF_MISSING")
            evidence_digest = digest_value(evidence)
            normal_plan_caller_arn_digest = str(
                evidence["normal_plan_caller_arn_digest"]
            )
            bindings = _derived_bindings(snapshot, self._config)
            bindings[NORMAL_PLAN_CALLER_BINDING_KEY] = (
                normal_plan_caller_arn_digest
            )
            receipt = self._receipt(
                alias=alias,
                function_version=function_version,
                state="CLOSEOUT_PREREQUISITES_VERIFIED",
                request_digest=None,
                provider_digest=None,
                change_set_digest=None,
                terminal_digest=evidence["pep_terminal_readback_digest"],
                assignment_digest=None,
                assignment_readback_count=0,
                closeout_digest=evidence_digest,
                normal_plan_caller_arn_digest=normal_plan_caller_arn_digest,
                generated_at=_timestamp(closeout_completed_at),
                aws_mutations=0,
            )
            self._cas(
                snapshot,
                new_state="CLOSEOUT_PREREQUISITES_VERIFIED",
                receipt_digest=receipt["receipt_digest"],
                occurred_at=_timestamp(closeout_completed_at),
                receipt_payload=receipt,
                derived_bindings=bindings,
            )
            return receipt
        except RouteBrokerError:
            raise
        except Exception as exc:
            raise RouteBrokerError(
                "CLOSEOUT_EVIDENCE_PENDING", retryable_read_only=True
            ) from exc


# Top-level handlers remain directly deployable.  The production AWS adapter is
# intentionally initialized only after the exact empty event and invocation
# binding can be checked by a configured runtime factory.
_runtime_factory: Callable[[], RouteBroker] | None = None


def install_runtime_factory(factory: Callable[[], RouteBroker]) -> None:
    global _runtime_factory
    if not callable(factory):
        raise RouteBrokerError("RUNTIME_FACTORY_INVALID")
    _runtime_factory = factory


def _sdk_client_config(config_type: Any) -> Any:
    """Build the only SDK transport policy accepted by this broker."""

    return config_type(
        connect_timeout=3,
        read_timeout=8,
        retries={"total_max_attempts": 1, "mode": "standard"},
    )


_EXACT_SERVICE_ENDPOINT_HOSTS = {
    "cloudformation": f"cloudformation.{REGION}.amazonaws.com",
    "cloudtrail": f"cloudtrail.{REGION}.amazonaws.com",
    "dynamodb": f"dynamodb.{REGION}.amazonaws.com",
    "s3control": f"s3-control.{REGION}.amazonaws.com",
    "sso-admin": f"sso.{REGION}.amazonaws.com",
    "sts": f"sts.{REGION}.amazonaws.com",
}


def _client(session: Any, service: str, sdk_config: Any) -> Any:
    expected_hostname = _EXACT_SERVICE_ENDPOINT_HOSTS.get(service)
    if expected_hostname is None:
        raise RouteBrokerError("AWS_CLIENT_SERVICE_INVALID")
    client = session.client(
        service,
        region_name=REGION,
        config=sdk_config,
    )
    metadata = getattr(client, "meta", None)
    if metadata is None or getattr(metadata, "region_name", None) != REGION:
        raise RouteBrokerError("AWS_CLIENT_REGION_INVALID")
    endpoint_url = getattr(metadata, "endpoint_url", None)
    if not isinstance(endpoint_url, str):
        raise RouteBrokerError("AWS_CLIENT_ENDPOINT_INVALID")
    parsed = urlsplit(endpoint_url)
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.hostname != expected_hostname
        or parsed.port is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise RouteBrokerError("AWS_CLIENT_ENDPOINT_INVALID")
    return client


def _verify_sts_identity(
    value: Mapping[str, Any],
    *,
    account_id: str,
    role_name: str,
    session_name: str | None = None,
) -> None:
    if not isinstance(value, Mapping):
        raise RouteBrokerError("STS_IDENTITY_INVALID")
    arn = value.get("Arn")
    if (
        value.get("Account") != account_id
        or not isinstance(value.get("UserId"), str)
        or not value.get("UserId")
        or not isinstance(arn, str)
        or arn
        != (
            f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name}"
            if session_name is not None
            else arn
        )
        or (
            session_name is None
            and re.fullmatch(
                rf"arn:aws:sts::{re.escape(account_id)}:assumed-role/"
                rf"{re.escape(role_name)}/[^/]+",
                arn,
            )
            is None
        )
    ):
        raise RouteBrokerError("STS_IDENTITY_INVALID")


def _reject_ambient_endpoint_or_region() -> None:
    if any(
        key == "AWS_ENDPOINT_URL" or key.startswith("AWS_ENDPOINT_URL_")
        for key in os.environ
    ):
        raise RouteBrokerError("AMBIENT_AWS_ENDPOINT_FORBIDDEN")
    for key in ("AWS_REGION", "AWS_DEFAULT_REGION"):
        value = os.environ.get(key)
        if value is not None and value != REGION:
            raise RouteBrokerError("AMBIENT_AWS_REGION_INVALID")


def _runtime_from_environment(handler_kind: str, context: Any) -> RouteBroker:
    if _runtime_factory is not None:
        return _runtime_factory()
    # Import is deliberately local: importing this module is AWS-free.
    try:
        import boto3  # type: ignore
        from boto3.dynamodb.types import TypeDeserializer  # type: ignore
        from botocore.config import Config  # type: ignore
    except Exception as exc:  # pragma: no cover - deployment dependency gate.
        raise RouteBrokerError("AWS_SDK_UNAVAILABLE") from exc
    try:
        envelope = json.loads(os.environ["BROKER_CONFIG_JSON"])
        config_raw = decode_runtime_config(envelope)
        ledger_table_name = os.environ["LEDGER_TABLE_NAME"]
        ledger_key_arn = os.environ["BROKER_LEDGER_KEY_ARN"]
    except (KeyError, json.JSONDecodeError) as exc:
        raise RouteBrokerError("RUNTIME_CONFIG_UNAVAILABLE") from exc
    config = BrokerConfig.from_mapping(config_raw)
    if handler_kind == "creator":
        function_name = CREATOR_FUNCTION_NAME
        allowed_aliases = CREATOR_ALIASES
        authority_role_name = AUTHORITY_CREATOR_ROLE_NAME
        management_role_name = MANAGEMENT_CREATOR_ROLE_NAME
        management_role_arn = MANAGEMENT_CREATOR_ROLE_ARN
    elif handler_kind == "executor":
        function_name = EXECUTOR_FUNCTION_NAME
        allowed_aliases = EXECUTOR_ALIASES
        authority_role_name = AUTHORITY_EXECUTOR_ROLE_NAME
        management_role_name = MANAGEMENT_EXECUTOR_ROLE_NAME
        management_role_arn = MANAGEMENT_EXECUTOR_ROLE_ARN
    elif handler_kind == "create-recovery":
        function_name = CREATE_RECOVERY_FUNCTION_NAME
        allowed_aliases = (RECOVERY_ALIAS,)
        authority_role_name = AUTHORITY_CREATE_RECOVERY_ROLE_NAME
        management_role_name = MANAGEMENT_RECOVERY_ROLE_NAME
        management_role_arn = MANAGEMENT_RECOVERY_ROLE_ARN
    elif handler_kind == "execute-recovery":
        function_name = EXECUTE_RECOVERY_FUNCTION_NAME
        allowed_aliases = (RECOVERY_ALIAS,)
        authority_role_name = AUTHORITY_EXECUTE_RECOVERY_ROLE_NAME
        management_role_name = MANAGEMENT_RECOVERY_ROLE_NAME
        management_role_arn = MANAGEMENT_RECOVERY_ROLE_ARN
    else:
        raise RouteBrokerError("HANDLER_KIND_INVALID")
    alias, _function_version = _invocation_alias(
        config=config,
        context=context,
        function_name=function_name,
        allowed=allowed_aliases,
    )
    budget = _InvocationBudget(context)
    _reject_ambient_endpoint_or_region()
    sdk_config = _sdk_client_config(Config)
    session = boto3.session.Session(region_name=REGION)
    authority_sts = _client(session, "sts", sdk_config)
    budget.require_read()
    _verify_sts_identity(
        authority_sts.get_caller_identity(),
        account_id=AUTHORITY_ACCOUNT_ID,
        role_name=authority_role_name,
    )
    authority_dynamodb = _client(session, "dynamodb", sdk_config)
    ledger = _AwsLedger(
        authority_dynamodb,
        table_name=ledger_table_name,
        expected_key_arn=ledger_key_arn,
        deserializer=TypeDeserializer(),
        config=config,
    )
    ledger.set_budget(budget)
    if handler_kind in {"creator", "executor"}:
        _runtime_ledger_preflight(
            config=config,
            ledger=ledger,
            handler_kind=handler_kind,
            alias=alias,
            now=datetime.now(timezone.utc),
        )
    else:
        ledger.verify_control_plane()
    session_binding = f"gug376-{handler_kind}-{config.source_commit}"
    try:
        budget.require_read()
        assumed = authority_sts.assume_role(
            RoleArn=management_role_arn,
            RoleSessionName=session_binding,
            SourceIdentity=session_binding,
            DurationSeconds=900,
        )
        credentials = assumed["Credentials"]
        assumed_user = assumed["AssumedRoleUser"]
        access_key = credentials["AccessKeyId"]
        secret_key = credentials["SecretAccessKey"]
        session_token = credentials["SessionToken"]
    except Exception as exc:
        raise RouteBrokerError("MANAGEMENT_ROLE_ASSUME_FAILED") from exc
    expected_assumed_arn = (
        f"arn:aws:sts::{MANAGEMENT_ACCOUNT_ID}:assumed-role/"
        f"{management_role_name}/{session_binding}"
    )
    if (
        not all(
            isinstance(item, str) and item
            for item in (access_key, secret_key, session_token)
        )
        or not isinstance(assumed_user, Mapping)
        or assumed_user.get("Arn") != expected_assumed_arn
        or not isinstance(assumed_user.get("AssumedRoleId"), str)
        or not str(assumed_user["AssumedRoleId"]).endswith(":" + session_binding)
    ):
        raise RouteBrokerError("MANAGEMENT_ROLE_ASSUME_FAILED")
    management_session = boto3.session.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=REGION,
    )
    management_sts = _client(management_session, "sts", sdk_config)
    _verify_sts_identity(
        management_sts.get_caller_identity(),
        account_id=MANAGEMENT_ACCOUNT_ID,
        role_name=management_role_name,
        session_name=session_binding,
    )
    authority_cloudformation = _client(session, "cloudformation", sdk_config)
    management_cloudformation = _client(
        management_session, "cloudformation", sdk_config
    )
    authority_cloudtrail = _client(session, "cloudtrail", sdk_config)
    management_cloudtrail = _client(management_session, "cloudtrail", sdk_config)
    management_sso = _client(management_session, "sso-admin", sdk_config)
    authority_s3control = _client(session, "s3control", sdk_config)
    cloudformation_by_account = {
        AUTHORITY_ACCOUNT_ID: authority_cloudformation,
        MANAGEMENT_ACCOUNT_ID: management_cloudformation,
    }
    effects = _AwsEffects(cloudformation_by_account)
    evidence = _AwsEvidence(
        cloudformation_by_account=cloudformation_by_account,
        sso_admin=management_sso,
        dynamodb=authority_dynamodb,
        cloudtrail_by_account={
            AUTHORITY_ACCOUNT_ID: authority_cloudtrail,
            MANAGEMENT_ACCOUNT_ID: management_cloudtrail,
        },
        s3control=authority_s3control,
        repair_table_name=REPAIR_LEDGER_TABLE_NAME,
        deserializer=TypeDeserializer(),
        config=config,
    )
    return RouteBroker(
        config=config,
        ledger=ledger,
        effects=effects,
        evidence=evidence,
        clock=lambda: datetime.now(timezone.utc),
    )


def creator_handler(event: Any, context: Any) -> dict[str, Any]:
    validate_empty_event(event)
    try:
        return _runtime_from_environment("creator", context).creator_handler(
            event, context
        )
    except RouteBrokerError as exc:
        if exc.retryable_read_only:
            raise RouteBrokerReadOnlyPending(exc.code) from None
        raise


def executor_handler(event: Any, context: Any) -> dict[str, Any]:
    validate_empty_event(event)
    try:
        return _runtime_from_environment("executor", context).executor_handler(
            event, context
        )
    except RouteBrokerError as exc:
        if exc.retryable_read_only:
            raise RouteBrokerReadOnlyPending(exc.code) from None
        raise


def create_dispatch_recovery_handler(event: Any, context: Any) -> dict[str, Any]:
    validate_empty_event(event)
    try:
        return _runtime_from_environment(
            "create-recovery", context
        ).create_dispatch_recovery_handler(event, context)
    except RouteBrokerError as exc:
        if exc.retryable_read_only:
            raise RouteBrokerReadOnlyPending(exc.code) from None
        raise


def execute_dispatch_recovery_handler(event: Any, context: Any) -> dict[str, Any]:
    validate_empty_event(event)
    try:
        return _runtime_from_environment(
            "execute-recovery", context
        ).execute_dispatch_recovery_handler(event, context)
    except RouteBrokerError as exc:
        if exc.retryable_read_only:
            raise RouteBrokerReadOnlyPending(exc.code) from None
        raise


class _AwsDelegationReadbackMixin:
    _budget: _InvocationBudget | None = None

    def set_budget(self, budget: _InvocationBudget) -> None:
        if not isinstance(budget, _InvocationBudget):
            raise RouteBrokerError("TIME_BUDGET_INVALID")
        self._budget = budget

    def _require_read_budget(self) -> None:
        if self._budget is None:
            raise RouteBrokerError("TIME_BUDGET_INVALID")
        self._budget.require_read()

    def _paginate_sso(
        self,
        method: Callable[..., Mapping[str, Any]],
        *,
        request: Mapping[str, Any],
        item_key: str,
        error_code: str = "DELEGATION_PERMISSION_SET_READBACK_INVALID",
    ) -> list[Any]:
        items: list[Any] = []
        seen_tokens: set[str] = set()
        next_token: str | None = None
        for page_number in range(1, 101):
            self._require_read_budget()
            page_request = dict(request)
            if next_token is not None:
                page_request["NextToken"] = next_token
            try:
                response = method(**page_request)
            except Exception as exc:
                raise RouteBrokerError(
                    error_code, retryable_read_only=True
                ) from exc
            page = response.get(item_key) if isinstance(response, Mapping) else None
            if not isinstance(page, list):
                raise RouteBrokerError(error_code, retryable_read_only=True)
            items.extend(page)
            token = response.get("NextToken")
            if token is None:
                return items
            if (
                not isinstance(token, str)
                or not token
                or token in seen_tokens
                or page_number == 100
            ):
                raise RouteBrokerError(error_code, retryable_read_only=True)
            seen_tokens.add(token)
            next_token = token
        raise RouteBrokerError(error_code, retryable_read_only=True)

    @staticmethod
    def _repair_invoker_inline_policy() -> dict[str, Any]:
        aliases = [
            (
                f"arn:aws:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:function:"
                "scanalyze-platform-authority-plan-policy-plan:plan-v1"
            ),
            (
                f"arn:aws:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:function:"
                "scanalyze-platform-authority-plan-policy-repair:repair-v1"
            ),
            (
                f"arn:aws:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:function:"
                "scanalyze-platform-authority-plan-policy-reconcile:reconcile-v1"
            ),
        ]
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "InvokeOnlyExactPrivatePlanRepairAliases",
                    "Effect": "Allow",
                    "Action": "lambda:InvokeFunction",
                    "Resource": aliases,
                },
                {
                    "Sid": "DenyEveryOtherLambdaInvocation",
                    "Effect": "Deny",
                    "Action": "lambda:InvokeFunction",
                    "NotResource": aliases,
                },
                {
                    "Sid": "DenyAllLegacyAsyncInvocation",
                    "Effect": "Deny",
                    "Action": "lambda:InvokeAsync",
                    "Resource": "*",
                },
                {
                    "Sid": "DenyAllFunctionUrls",
                    "Effect": "Deny",
                    "Action": "lambda:InvokeFunctionUrl",
                    "Resource": "*",
                },
                {
                    "Sid": "DenyRawControlPlaneAndRelay",
                    "Effect": "Deny",
                    "Action": [
                        "identitystore:*",
                        "iam:*",
                        "sso:*",
                        "sts:AssumeRole",
                        "sts:AssumeRoleWithSAML",
                        "sts:AssumeRoleWithWebIdentity",
                        "sts:AssumeRoot",
                        "sts:GetFederationToken",
                        "sts:GetSessionToken",
                        "sts:SetContext",
                        "sts:TagSession",
                    ],
                    "Resource": "*",
                },
                {
                    "Sid": "DenyLedgerWritesAndLambdaMutation",
                    "Effect": "Deny",
                    "Action": [
                        "dynamodb:BatchWriteItem",
                        "dynamodb:DeleteItem",
                        "dynamodb:PartiQLDelete",
                        "dynamodb:PartiQLInsert",
                        "dynamodb:PartiQLUpdate",
                        "dynamodb:PutItem",
                        "dynamodb:UpdateItem",
                        "lambda:AddPermission",
                        "lambda:CreateEventSourceMapping",
                        "lambda:CreateFunction",
                        "lambda:CreateFunctionUrlConfig",
                        "lambda:DeleteEventSourceMapping",
                        "lambda:DeleteFunction",
                        "lambda:DeleteFunctionEventInvokeConfig",
                        "lambda:DeleteFunctionUrlConfig",
                        "lambda:PutFunctionEventInvokeConfig",
                        "lambda:RemovePermission",
                        "lambda:UpdateEventSourceMapping",
                        "lambda:UpdateFunctionCode",
                        "lambda:UpdateFunctionConfiguration",
                        "lambda:UpdateFunctionEventInvokeConfig",
                        "lambda:UpdateFunctionUrlConfig",
                    ],
                    "Resource": "*",
                },
            ],
        }

    @staticmethod
    def _strict_policy(value: Any) -> dict[str, Any]:
        if not isinstance(value, str):
            raise RouteBrokerError("DELEGATION_PERMISSION_SET_READBACK_INVALID")

        def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError("duplicate JSON key")
                result[key] = item
            return result

        try:
            policy = json.loads(value, object_pairs_hook=object_pairs)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RouteBrokerError(
                "DELEGATION_PERMISSION_SET_READBACK_INVALID"
            ) from exc
        if not isinstance(policy, dict):
            raise RouteBrokerError("DELEGATION_PERMISSION_SET_READBACK_INVALID")
        return policy

    @staticmethod
    def _provider_error_code(exc: Exception) -> str | None:
        response = getattr(exc, "response", None)
        if not isinstance(response, Mapping):
            return None
        error = response.get("Error")
        if not isinstance(error, Mapping):
            return None
        code = error.get("Code")
        return code if isinstance(code, str) else None

    def _delegation_permission_set_readback(
        self, *, permission_set_arn: str
    ) -> dict[str, Any]:
        instance_arn = self._config.identity_center_instance_arn
        exact_request = {
            "InstanceArn": instance_arn,
            "PermissionSetArn": permission_set_arn,
        }
        try:
            self._require_read_budget()
            permission_response = self._sso.describe_permission_set(**exact_request)
            self._require_read_budget()
            inline_response = self._sso.get_inline_policy_for_permission_set(
                **exact_request
            )
            try:
                self._require_read_budget()
                boundary_response = (
                    self._sso.get_permissions_boundary_for_permission_set(
                        **exact_request
                    )
                )
            except Exception as exc:
                if self._provider_error_code(exc) not in {
                    "ResourceNotFound",
                    "ResourceNotFoundException",
                }:
                    raise
                boundary_response = {}
        except Exception as exc:
            if isinstance(exc, RouteBrokerError):
                raise
            raise RouteBrokerError(
                "DELEGATION_PERMISSION_SET_READBACK_INVALID",
                retryable_read_only=True,
            ) from exc

        managed = self._paginate_sso(
            self._sso.list_managed_policies_in_permission_set,
            request={**exact_request, "MaxResults": 100},
            item_key="AttachedManagedPolicies",
        )
        customer = self._paginate_sso(
            self._sso.list_customer_managed_policy_references_in_permission_set,
            request={**exact_request, "MaxResults": 100},
            item_key="CustomerManagedPolicyReferences",
        )
        tags = self._paginate_sso(
            self._sso.list_tags_for_resource,
            request={
                "InstanceArn": instance_arn,
                "ResourceArn": permission_set_arn,
            },
            item_key="Tags",
        )
        accounts = self._paginate_sso(
            self._sso.list_accounts_for_provisioned_permission_set,
            request={
                **exact_request,
                "ProvisioningStatus": "LATEST_PERMISSION_SET_PROVISIONED",
                "MaxResults": 100,
            },
            item_key="AccountIds",
        )
        assignments = self._paginate_sso(
            self._sso.list_account_assignments,
            request={
                **exact_request,
                "AccountId": AUTHORITY_ACCOUNT_ID,
                "MaxResults": 100,
            },
            item_key="AccountAssignments",
        )
        pending = self._paginate_sso(
            self._sso.list_permission_set_provisioning_status,
            request={
                "InstanceArn": instance_arn,
                "Filter": {"Status": "IN_PROGRESS"},
                "MaxResults": 100,
            },
            item_key="PermissionSetsProvisioningStatus",
            error_code="DELEGATION_PROVISIONING_READBACK_INVALID",
        )
        for summary in pending:
            if (
                not isinstance(summary, Mapping)
                or summary.get("Status") != "IN_PROGRESS"
                or not isinstance(summary.get("RequestId"), str)
                or _UUID_RE.fullmatch(summary["RequestId"]) is None
            ):
                raise RouteBrokerError("DELEGATION_PROVISIONING_READBACK_INVALID")
            try:
                self._require_read_budget()
                detail_response = (
                    self._sso.describe_permission_set_provisioning_status(
                        InstanceArn=instance_arn,
                        ProvisionPermissionSetRequestId=summary["RequestId"],
                    )
                )
            except Exception as exc:
                raise RouteBrokerError(
                    "DELEGATION_PROVISIONING_READBACK_INVALID",
                    retryable_read_only=True,
                ) from exc
            detail = detail_response.get("PermissionSetProvisioningStatus")
            if (
                not isinstance(detail, Mapping)
                or detail.get("RequestId") != summary["RequestId"]
                or detail.get("Status") != "IN_PROGRESS"
                or not isinstance(detail.get("PermissionSetArn"), str)
            ):
                raise RouteBrokerError("DELEGATION_PROVISIONING_READBACK_INVALID")
            if detail["PermissionSetArn"] == permission_set_arn:
                raise RouteBrokerError(
                    "DELEGATION_PROVISIONING_PENDING", retryable_read_only=True
                )

        if (
            not isinstance(permission_response, Mapping)
            or not isinstance(inline_response, Mapping)
            or not isinstance(boundary_response, Mapping)
        ):
            raise RouteBrokerError("DELEGATION_PERMISSION_SET_READBACK_INVALID")
        permission = permission_response.get("PermissionSet")
        created = permission.get("CreatedDate") if isinstance(permission, Mapping) else None
        expected_tags = sorted(
            [
                {"Key": "component", "Value": "plan-repair-delegation"},
                {"Key": "environment", "Value": "non-production"},
                {"Key": "managed_by", "Value": "cloudformation"},
                {"Key": "production", "Value": "false"},
                {"Key": "service", "Value": "scanalyze-platform-authority"},
                {"Key": "source_commit", "Value": self._config.source_commit},
                {"Key": "work_package", "Value": "GUG-376"},
            ],
            key=lambda item: item["Key"],
        )
        expected_assignment = {
            "AccountId": AUTHORITY_ACCOUNT_ID,
            "PermissionSetArn": permission_set_arn,
            "PrincipalId": self._config.bootstrap_principal_id,
            "PrincipalType": "USER",
        }
        if (
            not isinstance(permission, Mapping)
            or set(permission).difference(
                {
                    "CreatedDate",
                    "Description",
                    "Name",
                    "PermissionSetArn",
                    "RelayState",
                    "SessionDuration",
                }
            )
            or permission.get("PermissionSetArn") != permission_set_arn
            or permission.get("Name") != "ScanalyzeBootstrapPlanRepair"
            or permission.get("Description")
            != "GUG-376 invoke-only bootstrap Plan policy repair PEP"
            or permission.get("SessionDuration") != "PT1H"
            or permission.get("RelayState") not in (None, "")
            or not isinstance(created, datetime)
            or created.tzinfo is None
            or created.utcoffset() is None
            or not self._config.route_not_before
            <= created.astimezone(timezone.utc)
            <= self._config.route_not_after
            or self._strict_policy(inline_response.get("InlinePolicy"))
            != self._repair_invoker_inline_policy()
            or managed != []
            or customer != []
            or boundary_response.get("PermissionsBoundary") is not None
            or any(
                not isinstance(item, Mapping)
                or set(item) != {"Key", "Value"}
                or not isinstance(item.get("Key"), str)
                or not item.get("Key")
                or not isinstance(item.get("Value"), str)
                for item in tags
            )
            or len(tags) != len({item["Key"] for item in tags})
            or sorted(tags, key=lambda item: str(item.get("Key", "")))
            != expected_tags
            or accounts != [AUTHORITY_ACCOUNT_ID]
            or assignments != [expected_assignment]
        ):
            raise RouteBrokerError("DELEGATION_PERMISSION_SET_READBACK_INVALID")
        return {
            "permission_set_arn": permission_set_arn,
            "name": permission["Name"],
            "description": permission["Description"],
            "session_duration": permission["SessionDuration"],
            "created_at": _timestamp(created),
            "inline_policy_digest": digest_value(
                self._repair_invoker_inline_policy()
            ),
            "managed_policy_arns": [],
            "customer_managed_policy_references": [],
            "permissions_boundary": None,
            "tags_digest": digest_value(expected_tags),
            "provisioned_account_ids": accounts,
            "assignment_digest": digest_value(expected_assignment),
            "assignment_count": 1,
            "provisioning_terminal": True,
        }

class _AwsLedger:
    def __init__(
        self,
        client: Any,
        *,
        table_name: str,
        expected_key_arn: str,
        deserializer: Any,
        config: BrokerConfig,
    ) -> None:
        if (
            table_name != ROUTE_LEDGER_TABLE_NAME
            or _AUTHORITY_KMS_KEY_ARN_RE.fullmatch(expected_key_arn) is None
        ):
            raise RouteBrokerError("LEDGER_TABLE_INVALID")
        self._client = client
        self._table = table_name
        self._expected_key_arn = expected_key_arn
        self._deserializer = deserializer
        self._config = config
        self._budget: _InvocationBudget | None = None

    def set_budget(self, budget: _InvocationBudget) -> None:
        if not isinstance(budget, _InvocationBudget):
            raise RouteBrokerError("TIME_BUDGET_INVALID")
        self._budget = budget

    def _require_read_budget(self) -> None:
        if self._budget is None:
            raise RouteBrokerError("TIME_BUDGET_INVALID")
        self._budget.require_read()

    def _require_mutation_budget(self) -> None:
        if self._budget is None:
            raise RouteBrokerError("TIME_BUDGET_INVALID")
        self._budget.require_mutation()

    def verify_control_plane(self) -> str:
        self._require_read_budget()
        response = self._client.describe_table(TableName=self._table)
        table = response.get("Table")
        expected_table_arn = (
            f"arn:aws:dynamodb:{REGION}:{AUTHORITY_ACCOUNT_ID}:table/{self._table}"
        )
        if not isinstance(table, Mapping):
            raise RouteBrokerError("LEDGER_CONTROL_PLANE_INVALID")
        sse = table.get("SSEDescription")
        projection = {
            "table_name": table.get("TableName"),
            "table_arn": table.get("TableArn"),
            "table_status": table.get("TableStatus"),
            "deletion_protection_enabled": table.get(
                "DeletionProtectionEnabled"
            ),
            "sse_status": sse.get("Status") if isinstance(sse, Mapping) else None,
            "sse_type": sse.get("SSEType") if isinstance(sse, Mapping) else None,
            "kms_key_arn": (
                sse.get("KMSMasterKeyArn") if isinstance(sse, Mapping) else None
            ),
        }
        if projection != {
            "table_name": self._table,
            "table_arn": expected_table_arn,
            "table_status": "ACTIVE",
            "deletion_protection_enabled": True,
            "sse_status": "ENABLED",
            "sse_type": "KMS",
            "kms_key_arn": self._expected_key_arn,
        }:
            raise RouteBrokerError("LEDGER_CONTROL_PLANE_INVALID")
        return digest_value(projection)

    def _decode(self, item: Mapping[str, Any]) -> dict[str, Any]:
        return {key: self._deserializer.deserialize(value) for key, value in item.items()}

    def _snapshot(self, item: Mapping[str, Any]) -> LedgerSnapshot:
        value = self._decode(item)
        if (
            value.get("record_type") != LEDGER_RECORD_TYPE
            or value.get("source_commit") != self._config.source_commit
            or value.get("initialization_digest") != self._config.initialization_digest
            or value.get("retry_permitted") is not False
        ):
            raise RouteBrokerError("LEDGER_TYPE_INVALID")
        return LedgerSnapshot(
            state=str(value.get("state", "")),
            version=int(value.get("version", -1)),
            binding_digest=str(value.get("binding_digest", "")),
            last_receipt_digest=(
                str(value["last_receipt_digest"])
                if "last_receipt_digest" in value
                else None
            ),
            last_receipt_json=(
                str(value["last_receipt_json"])
                if "last_receipt_json" in value
                else None
            ),
            attempt_claim_json=(
                str(value["attempt_claim_json"])
                if "attempt_claim_json" in value
                else None
            ),
            dispatch_coordinates_json=(
                str(value["dispatch_coordinates_json"])
                if "dispatch_coordinates_json" in value
                else None
            ),
            derived_bindings_json=(
                str(value["derived_bindings_json"])
                if "derived_bindings_json" in value
                else None
            ),
        )

    def initialize(self, *, ledger_id: str) -> LedgerSnapshot:
        self._require_read_budget()
        response = self._client.get_item(
            TableName=self._table,
            Key={"ledger_id": {"S": ledger_id}},
            ConsistentRead=True,
        )
        item = response.get("Item")
        if isinstance(item, Mapping):
            return self._snapshot(item)
        initial = {
                "ledger_id": {"S": ledger_id},
                "record_type": {"S": LEDGER_RECORD_TYPE},
                "source_commit": {"S": self._config.source_commit},
                "state": {"S": "READY"},
                "version": {"N": "0"},
                "binding_digest": {"S": self._config.ledger_binding_digest},
                "initialization_digest": {"S": self._config.initialization_digest},
                "retry_permitted": {"BOOL": False},
                "updated_at": {"S": _timestamp(datetime.now(timezone.utc))},
        }
        try:
            self._require_mutation_budget()
            self._client.put_item(
                TableName=self._table,
                Item=initial,
                ConditionExpression="attribute_not_exists(ledger_id)",
            )
        except Exception as exc:
            raise RouteBrokerError(
                "LEDGER_INITIALIZATION_UNCERTAIN", uncertain=True
            ) from exc
        return LedgerSnapshot(
            state="READY",
            version=0,
            binding_digest=self._config.ledger_binding_digest,
            last_receipt_digest=None,
            last_receipt_json=None,
            attempt_claim_json=None,
            dispatch_coordinates_json=None,
            derived_bindings_json=None,
        )

    def read(self, *, ledger_id: str) -> LedgerSnapshot:
        self._require_read_budget()
        response = self._client.get_item(
            TableName=self._table,
            Key={"ledger_id": {"S": ledger_id}},
            ConsistentRead=True,
        )
        item = response.get("Item")
        if not isinstance(item, Mapping):
            raise RouteBrokerError("LEDGER_MISSING")
        return self._snapshot(item)

    def compare_and_swap(
        self,
        *,
        ledger_id: str,
        expected_version: int,
        expected_state: str,
        new_state: str,
        binding_digest: str,
        receipt_digest: str,
        occurred_at: str,
        receipt_json: str | None = None,
        attempt_claim_json: str | None = None,
        dispatch_coordinates_json: str | None = None,
        derived_bindings_json: str | None = None,
    ) -> LedgerSnapshot:
        update_expression = (
            "SET #state = :new_state, #version = :new_version, "
            "last_receipt_digest = :receipt, updated_at = :updated"
        )
        expression_values: dict[str, Any] = {
            ":expected_state": {"S": expected_state},
            ":expected_version": {"N": str(expected_version)},
            ":binding": {"S": binding_digest},
            ":new_state": {"S": new_state},
            ":new_version": {"N": str(expected_version + 1)},
            ":receipt": {"S": receipt_digest},
            ":updated": {"S": occurred_at},
        }
        if dispatch_coordinates_json is not None:
            probe = LedgerSnapshot(
                state=new_state,
                version=expected_version + 1,
                binding_digest=binding_digest,
                last_receipt_digest=receipt_digest,
                dispatch_coordinates_json=dispatch_coordinates_json,
            )
            _dispatch_coordinates(probe)
            update_expression += ", dispatch_coordinates_json = :dispatch"
            expression_values[":dispatch"] = {"S": dispatch_coordinates_json}
        if receipt_json is not None:
            try:
                receipt_value = json.loads(receipt_json)
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise RouteBrokerError("LEDGER_RECEIPT_INVALID") from exc
            if (
                not isinstance(receipt_value, dict)
                or canonical_json(receipt_value) != receipt_json
                or _verify_seal(
                    receipt_value, "receipt_digest", "LEDGER_RECEIPT_INVALID"
                )
                != receipt_digest
            ):
                raise RouteBrokerError("LEDGER_RECEIPT_INVALID")
            update_expression += ", last_receipt_json = :receipt_json"
            expression_values[":receipt_json"] = {"S": receipt_json}
        if attempt_claim_json is not None:
            claim_probe = LedgerSnapshot(
                state=new_state,
                version=expected_version + 1,
                binding_digest=binding_digest,
                attempt_claim_json=attempt_claim_json,
            )
            _attempt_claim(claim_probe, config=self._config)
            update_expression += ", attempt_claim_json = :attempt_claim"
            expression_values[":attempt_claim"] = {"S": attempt_claim_json}
        if derived_bindings_json is not None:
            binding_probe = LedgerSnapshot(
                state=new_state,
                version=expected_version + 1,
                binding_digest=binding_digest,
                last_receipt_digest=receipt_digest,
                derived_bindings_json=derived_bindings_json,
            )
            _derived_bindings(binding_probe, self._config)
            update_expression += ", derived_bindings_json = :derived"
            expression_values[":derived"] = {"S": derived_bindings_json}
        if receipt_json is None:
            update_expression += " REMOVE last_receipt_json"
        response = self._client.update_item(
            TableName=self._table,
            Key={"ledger_id": {"S": ledger_id}},
            ConditionExpression=(
                "#state = :expected_state AND #version = :expected_version "
                "AND binding_digest = :binding"
            ),
            UpdateExpression=update_expression,
            ExpressionAttributeNames={"#state": "state", "#version": "version"},
            ExpressionAttributeValues=expression_values,
            ReturnValues="ALL_NEW",
        )
        item = response.get("Attributes")
        if not isinstance(item, Mapping):
            raise RouteBrokerError("LEDGER_CAS_FAILED")
        value = self._decode(item)
        return LedgerSnapshot(
            state=str(value.get("state", "")),
            version=int(value.get("version", -1)),
            binding_digest=str(value.get("binding_digest", "")),
            last_receipt_digest=str(value.get("last_receipt_digest", "")),
            last_receipt_json=(
                str(value["last_receipt_json"])
                if "last_receipt_json" in value
                else None
            ),
            attempt_claim_json=(
                str(value["attempt_claim_json"])
                if "attempt_claim_json" in value
                else None
            ),
            dispatch_coordinates_json=(
                str(value["dispatch_coordinates_json"])
                if "dispatch_coordinates_json" in value
                else None
            ),
            derived_bindings_json=(
                str(value["derived_bindings_json"])
                if "derived_bindings_json" in value
                else None
            ),
        )


class _AwsEffects:
    def __init__(self, cloudformation_by_account: Mapping[str, Any]) -> None:
        if set(cloudformation_by_account) != {
            AUTHORITY_ACCOUNT_ID,
            MANAGEMENT_ACCOUNT_ID,
        }:
            raise RouteBrokerError("AWS_CLIENT_ACCOUNT_MAP_INVALID")
        self._cloudformation = dict(cloudformation_by_account)

    def create_change_set(
        self, *, operation: str, request: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        response = self._cloudformation[operation_account(operation)].create_change_set(
            **dict(request)
        )
        metadata = response.get("ResponseMetadata", {})
        return {
            "change_set_arn": response.get("Id"),
            "stack_id": response.get("StackId"),
            "request_id": metadata.get("RequestId"),
        }

    def execute_change_set(
        self, *, operation: str, request: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        response = self._cloudformation[operation_account(operation)].execute_change_set(
            **dict(request)
        )
        metadata = response.get("ResponseMetadata", {})
        request_id = metadata.get("RequestId")
        if not isinstance(request_id, str):
            raise RouteBrokerError("EXECUTE_RESPONSE_INVALID", uncertain=True)
        return {"request_id": request_id}


class _AwsEvidence(_AwsDelegationReadbackMixin):
    """Bounded single-read AWS projection adapter; it never polls or retries."""

    def __init__(
        self,
        *,
        cloudformation_by_account: Mapping[str, Any],
        sso_admin: Any,
        dynamodb: Any,
        cloudtrail_by_account: Mapping[str, Any],
        s3control: Any,
        repair_table_name: str,
        deserializer: Any,
        config: BrokerConfig,
    ) -> None:
        if set(cloudformation_by_account) != {
            AUTHORITY_ACCOUNT_ID,
            MANAGEMENT_ACCOUNT_ID,
        }:
            raise RouteBrokerError("AWS_CLIENT_ACCOUNT_MAP_INVALID")
        self._cloudformation = dict(cloudformation_by_account)
        self._sso = sso_admin
        self._dynamodb = dynamodb
        if set(cloudtrail_by_account) != {
            AUTHORITY_ACCOUNT_ID,
            MANAGEMENT_ACCOUNT_ID,
        }:
            raise RouteBrokerError("AWS_CLIENT_ACCOUNT_MAP_INVALID")
        self._cloudtrail = dict(cloudtrail_by_account)
        self._s3control = s3control
        self._repair_table = repair_table_name
        self._deserializer = deserializer
        self._config = config

    def _decode(self, item: Mapping[str, Any]) -> dict[str, Any]:
        return {key: self._deserializer.deserialize(value) for key, value in item.items()}

    @staticmethod
    def _change_projection(response: Mapping[str, Any]) -> list[dict[str, Any]]:
        raw_changes = response.get("Changes")
        if not isinstance(raw_changes, list):
            raise RouteBrokerError("CHANGE_SET_READBACK_INVALID")
        result: list[dict[str, Any]] = []
        for item in raw_changes:
            if not isinstance(item, Mapping) or item.get("Type") != "Resource":
                raise RouteBrokerError("CHANGE_SET_READBACK_INVALID")
            resource = item.get("ResourceChange")
            if not isinstance(resource, Mapping):
                raise RouteBrokerError("CHANGE_SET_READBACK_INVALID")
            scope = resource.get("Scope", [])
            raw_details = resource.get("Details", [])
            if not isinstance(scope, list) or not isinstance(raw_details, list):
                raise RouteBrokerError("CHANGE_SET_READBACK_INVALID")
            details: list[dict[str, Any]] = []
            for raw_detail in raw_details:
                if not isinstance(raw_detail, Mapping) or set(raw_detail) - {
                    "Target",
                    "Evaluation",
                    "ChangeSource",
                    "CausingEntity",
                }:
                    raise RouteBrokerError("CHANGE_SET_READBACK_INVALID")
                target = raw_detail.get("Target")
                if not isinstance(target, Mapping) or set(target) - {
                    "Attribute",
                    "Name",
                    "RequiresRecreation",
                }:
                    raise RouteBrokerError("CHANGE_SET_READBACK_INVALID")
                detail = {
                    "target_attribute": target.get("Attribute"),
                    "target_name": target.get("Name"),
                    "requires_recreation": target.get("RequiresRecreation"),
                    "evaluation": raw_detail.get("Evaluation"),
                    "change_source": raw_detail.get("ChangeSource"),
                    "causing_entity": raw_detail.get("CausingEntity"),
                }
                if (
                    detail["target_attribute"]
                    not in {
                        "CreationPolicy",
                        "DeletionPolicy",
                        "Metadata",
                        "Properties",
                        "Tags",
                        "UpdatePolicy",
                        "UpdateReplacePolicy",
                    }
                    or (
                        detail["target_name"] is not None
                        and (
                            not isinstance(detail["target_name"], str)
                            or not detail["target_name"]
                        )
                    )
                    or detail["requires_recreation"]
                    not in {None, "Always", "Conditionally", "Never"}
                    or detail["evaluation"] not in {"Static", "Dynamic"}
                    or detail["change_source"]
                    not in {
                        "Automatic",
                        "DirectModification",
                        "ParameterReference",
                        "ResourceAttribute",
                        "ResourceReference",
                    }
                    or (
                        detail["causing_entity"] is not None
                        and (
                            not isinstance(detail["causing_entity"], str)
                            or not detail["causing_entity"]
                        )
                    )
                ):
                    raise RouteBrokerError("CHANGE_SET_READBACK_INVALID")
                details.append(detail)
            details.sort(
                key=lambda detail: (
                    str(detail["target_attribute"]),
                    str(detail["target_name"] or ""),
                    str(detail["requires_recreation"] or ""),
                    str(detail["evaluation"]),
                    str(detail["change_source"]),
                    str(detail["causing_entity"] or ""),
                )
            )
            result.append(
                {
                    "action": resource.get("Action"),
                    "logical_resource_id": resource.get("LogicalResourceId"),
                    "resource_type": resource.get("ResourceType"),
                    "replacement": resource.get("Replacement"),
                    "scope": sorted(scope),
                    "details": details,
                }
            )
        return sorted(
            result,
            key=lambda item: (str(item["logical_resource_id"]), str(item["resource_type"])),
        )

    def _create_event_digest(
        self,
        *,
        account_id: str,
        operation: str,
        request: Mapping[str, Any],
        dispatch: Mapping[str, Any],
        end_time: datetime,
    ) -> str:
        events = _lookup_cloudtrail_events(
            self._cloudtrail[account_id],
            request={
                "LookupAttributes": [
                {"AttributeKey": "EventName", "AttributeValue": "CreateChangeSet"}
                ],
                "StartTime": self._config.route_not_before,
                "EndTime": end_time,
                "MaxResults": 50,
            },
            error_code="CREATE_CLOUDTRAIL_PENDING",
            retryable_read_only=True,
            budget=self._budget,
        )
        matches: list[dict[str, Any]] = []
        expected_role = (
            AUTHORITY_CREATOR_ROLE_NAME
            if account_id == AUTHORITY_ACCOUNT_ID
            else MANAGEMENT_CREATOR_ROLE_NAME
        )
        expected_params = {
            "stackName": request["StackName"],
            "changeSetName": request["ChangeSetName"],
            "changeSetType": request["ChangeSetType"],
            "description": request["Description"],
            "templateURL": request["TemplateURL"],
            # CloudFormation intentionally omits ParameterValue in CloudTrail.
            # DescribeChangeSet below binds the exact sealed values.
            "parameters": [
                {"parameterKey": item["ParameterKey"]}
                for item in request["Parameters"]
            ],
            "capabilities": request["Capabilities"],
            "tags": [
                {"key": item["Key"], "value": item["Value"]}
                for item in request["Tags"]
            ],
            "includeNestedStacks": False,
            "notificationARNs": [],
            "rollbackConfiguration": {
                "rollbackTriggers": [],
                "monitoringTimeInMinutes": 0,
            },
            "clientToken": request["ClientToken"],
        }
        if request["ChangeSetType"] == "CREATE":
            expected_params["onStackFailure"] = "DELETE"
        for envelope in events:
            raw = envelope.get("CloudTrailEvent")
            if not isinstance(raw, str):
                raise RouteBrokerError("CREATE_CLOUDTRAIL_INVALID")
            event = json.loads(raw)
            params = event.get("requestParameters") or {}
            identity = event.get("userIdentity") or {}
            result = event.get("responseElements") or {}
            arn = identity.get("arn")
            if event.get("requestID") != dispatch["create_request_id"]:
                continue
            if (
                event.get("eventSource") != "cloudformation.amazonaws.com"
                or event.get("eventName") != "CreateChangeSet"
                or event.get("awsRegion") != REGION
                or event.get("recipientAccountId") != account_id
                or event.get("readOnly") is not False
                or event.get("errorCode") is not None
                or event.get("errorMessage") is not None
                or not isinstance(arn, str)
                or re.fullmatch(
                    rf"arn:aws:sts::{account_id}:assumed-role/"
                    rf"{re.escape(expected_role)}/[^/]+",
                    arn,
                )
                is None
                or params != expected_params
                or "roleARN" in params
                or result.get("id") != dispatch["change_set_arn"]
                or result.get("stackId") != dispatch["stack_arn"]
            ):
                raise RouteBrokerError("CREATE_CLOUDTRAIL_INVALID")
            matches.append(
                {
                    "event_id": event.get("eventID"),
                    "event_time": event.get("eventTime"),
                    "request_id": event.get("requestID"),
                    "caller_arn": arn,
                    "operation": operation,
                    "request_contract_digest": digest_value(request),
                    "cloudtrail_parameters_digest": digest_value(params),
                    "change_set_arn": dispatch["change_set_arn"],
                    "stack_arn": dispatch["stack_arn"],
                }
            )
        if len(matches) != 1 or _UUID_RE.fullmatch(str(matches[0]["event_id"])) is None:
            raise RouteBrokerError(
                "CREATE_CLOUDTRAIL_PENDING", retryable_read_only=True
            )
        _parse_time(matches[0]["event_time"], "CREATE_CLOUDTRAIL_INVALID")
        return digest_value(matches[0])

    @staticmethod
    def _create_cloudtrail_parameters(
        request: Mapping[str, Any],
    ) -> dict[str, Any]:
        parameters: dict[str, Any] = {
            "stackName": request["StackName"],
            "changeSetName": request["ChangeSetName"],
            "changeSetType": request["ChangeSetType"],
            "description": request["Description"],
            "templateURL": request["TemplateURL"],
            # CloudFormation intentionally omits ParameterValue in CloudTrail.
            # DescribeChangeSet below binds every exact sealed value.
            "parameters": [
                {"parameterKey": item["ParameterKey"]}
                for item in request["Parameters"]
            ],
            "capabilities": request["Capabilities"],
            "tags": [
                {"key": item["Key"], "value": item["Value"]}
                for item in request["Tags"]
            ],
            "includeNestedStacks": False,
            "notificationARNs": [],
            "rollbackConfiguration": {
                "rollbackTriggers": [],
                "monitoringTimeInMinutes": 0,
            },
            "clientToken": request["ClientToken"],
        }
        if request["ChangeSetType"] == "CREATE":
            parameters["onStackFailure"] = "DELETE"
        return parameters

    @staticmethod
    def _execute_cloudtrail_parameters(
        request: Mapping[str, Any],
    ) -> dict[str, Any]:
        parameters = {
            "stackName": request["StackName"],
            "changeSetName": request["ChangeSetName"],
            "clientRequestToken": request["ClientRequestToken"],
        }
        if "DisableRollback" in request:
            parameters["disableRollback"] = request["DisableRollback"]
        return parameters

    @staticmethod
    def _cloudtrail_event(
        envelope: Mapping[str, Any], *, code: str
    ) -> dict[str, Any]:
        raw = envelope.get("CloudTrailEvent")
        if not isinstance(raw, str):
            raise RouteBrokerError(code)
        try:
            value = json.loads(raw)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RouteBrokerError(code) from exc
        if not isinstance(value, dict):
            raise RouteBrokerError(code)
        return value

    @staticmethod
    def _expected_assumed_role_pattern(
        *, account_id: str, role_name: str
    ) -> re.Pattern[str]:
        return re.compile(
            rf"arn:aws:sts::{re.escape(account_id)}:assumed-role/"
            rf"{re.escape(role_name)}/[^/]+"
        )

    def _execute_event_digest(
        self,
        *,
        account_id: str,
        operation: str,
        request: Mapping[str, Any],
        dispatch: Mapping[str, Any],
        end_time: datetime,
    ) -> str:
        executed_at = _parse_time(
            dispatch.get("executed_at"), "EXECUTE_CLOUDTRAIL_INVALID"
        )
        events = _lookup_cloudtrail_events(
            self._cloudtrail[account_id],
            request={
                "LookupAttributes": [
                    {
                        "AttributeKey": "EventName",
                        "AttributeValue": "ExecuteChangeSet",
                    }
                ],
                "StartTime": executed_at,
                "EndTime": end_time,
                "MaxResults": 50,
            },
            error_code="EXECUTE_CLOUDTRAIL_PENDING",
            retryable_read_only=True,
            budget=self._budget,
        )
        expected_role = (
            AUTHORITY_EXECUTOR_ROLE_NAME
            if account_id == AUTHORITY_ACCOUNT_ID
            else MANAGEMENT_EXECUTOR_ROLE_NAME
        )
        expected_params = {
            "stackName": request["StackName"],
            "changeSetName": request["ChangeSetName"],
            "clientRequestToken": request["ClientRequestToken"],
        }
        if "DisableRollback" in request:
            expected_params["disableRollback"] = request["DisableRollback"]
        matches: list[dict[str, Any]] = []
        for envelope in events:
            raw = envelope.get("CloudTrailEvent")
            if not isinstance(raw, str):
                raise RouteBrokerError("EXECUTE_CLOUDTRAIL_INVALID")
            try:
                event = json.loads(raw)
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise RouteBrokerError("EXECUTE_CLOUDTRAIL_INVALID") from exc
            params = event.get("requestParameters") or {}
            identity = event.get("userIdentity") or {}
            arn = identity.get("arn")
            if event.get("requestID") != dispatch["execute_request_id"]:
                continue
            event_time = _parse_time(
                event.get("eventTime"), "EXECUTE_CLOUDTRAIL_INVALID"
            )
            if (
                event.get("eventSource") != "cloudformation.amazonaws.com"
                or event.get("eventName") != "ExecuteChangeSet"
                or event.get("awsRegion") != REGION
                or event.get("recipientAccountId") != account_id
                or event.get("readOnly") is not False
                or event.get("errorCode") is not None
                or event.get("errorMessage") is not None
                or event.get("responseElements") is not None
                or not isinstance(arn, str)
                or re.fullmatch(
                    rf"arn:aws:sts::{account_id}:assumed-role/"
                    rf"{re.escape(expected_role)}/[^/]+",
                    arn,
                )
                is None
                or params != expected_params
                or not executed_at <= event_time <= end_time
            ):
                raise RouteBrokerError("EXECUTE_CLOUDTRAIL_INVALID")
            matches.append(
                {
                    "event_id": event.get("eventID"),
                    "event_time": event.get("eventTime"),
                    "request_id": event.get("requestID"),
                    "caller_arn": arn,
                    "operation": operation,
                    "request_contract_digest": digest_value(request),
                    "cloudtrail_parameters_digest": digest_value(params),
                    "change_set_arn": dispatch["change_set_arn"],
                    "stack_arn": dispatch["stack_arn"],
                }
            )
        if (
            len(matches) != 1
            or _UUID_RE.fullmatch(str(matches[0]["event_id"])) is None
        ):
            raise RouteBrokerError(
                "EXECUTE_CLOUDTRAIL_PENDING", retryable_read_only=True
            )
        return digest_value(matches[0])

    def recover_create_dispatch(
        self,
        *,
        operation: str,
        request: Mapping[str, Any],
        claim: Mapping[str, Any],
        contract: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Recover one causally claimed CreateChangeSet without replaying it."""

        account_id = operation_account(operation)
        claimed_at = _parse_time(
            claim.get("claimed_at"), "CREATE_RECOVERY_INVALID"
        )
        expected_parameters = self._create_cloudtrail_parameters(request)
        expected_role = (
            AUTHORITY_CREATOR_ROLE_NAME
            if account_id == AUTHORITY_ACCOUNT_ID
            else MANAGEMENT_CREATOR_ROLE_NAME
        )
        role_pattern = self._expected_assumed_role_pattern(
            account_id=account_id, role_name=expected_role
        )
        events = _lookup_cloudtrail_events(
            self._cloudtrail[account_id],
            request={
                "LookupAttributes": [
                    {
                        "AttributeKey": "EventName",
                        "AttributeValue": "CreateChangeSet",
                    }
                ],
                "StartTime": claimed_at,
                "EndTime": datetime.now(timezone.utc),
                "MaxResults": 50,
            },
            error_code="CREATE_RECOVERY_PENDING",
            retryable_read_only=True,
            budget=self._budget,
        )
        matches: list[tuple[dict[str, Any], datetime]] = []
        for envelope in events:
            event = self._cloudtrail_event(
                envelope, code="CREATE_RECOVERY_CLOUDTRAIL_INVALID"
            )
            parameters = event.get("requestParameters")
            if not isinstance(parameters, Mapping):
                continue
            # The client token is the immutable effect identity. Other events
            # in Event History are irrelevant and cannot poison recovery.
            if parameters.get("clientToken") != request["ClientToken"]:
                continue
            identity = event.get("userIdentity")
            response = event.get("responseElements")
            event_time = _parse_time(
                event.get("eventTime"), "CREATE_RECOVERY_CLOUDTRAIL_INVALID"
            )
            change_set_arn = (
                response.get("id") if isinstance(response, Mapping) else None
            )
            stack_arn = (
                response.get("stackId") if isinstance(response, Mapping) else None
            )
            expected_change_set_prefix = (
                f"arn:aws:cloudformation:{REGION}:{account_id}:changeSet/"
                f"{request['ChangeSetName']}/"
            )
            expected_stack_prefix = (
                f"arn:aws:cloudformation:{REGION}:{account_id}:stack/"
                f"{request['StackName']}/"
            )
            caller_arn = (
                identity.get("arn") if isinstance(identity, Mapping) else None
            )
            if (
                event.get("eventSource") != "cloudformation.amazonaws.com"
                or event.get("eventName") != "CreateChangeSet"
                or event.get("awsRegion") != REGION
                or event.get("recipientAccountId") != account_id
                or event.get("readOnly") is not False
                or event.get("errorCode") is not None
                or event.get("errorMessage") is not None
                or parameters != expected_parameters
                or "roleARN" in parameters
                or not isinstance(caller_arn, str)
                or role_pattern.fullmatch(caller_arn) is None
                or _UUID_RE.fullmatch(str(event.get("eventID", ""))) is None
                or _UUID_RE.fullmatch(str(event.get("requestID", ""))) is None
                or not isinstance(change_set_arn, str)
                or _CHANGE_SET_ARN_RE.fullmatch(change_set_arn) is None
                or not change_set_arn.startswith(expected_change_set_prefix)
                or not isinstance(stack_arn, str)
                or _STACK_ARN_RE.fullmatch(stack_arn) is None
                or not stack_arn.startswith(expected_stack_prefix)
                or not claimed_at <= event_time < self._config.route_not_after
            ):
                raise RouteBrokerError("CREATE_RECOVERY_CLOUDTRAIL_INVALID")
            matches.append((event, event_time))
        if not matches:
            raise RouteBrokerError(
                "CREATE_RECOVERY_PENDING", retryable_read_only=True
            )
        if len(matches) != 1:
            raise RouteBrokerError("CREATE_RECOVERY_AMBIGUOUS")
        event, event_time = matches[0]
        response = event["responseElements"]
        dispatch = {
            "kind": "CREATE",
            "operation": operation,
            "change_set_arn": response["id"],
            "stack_arn": response["stackId"],
            "create_request_id": event["requestID"],
            "create_request_digest": digest_value(_json_copy(request)),
            "dispatched_at": _timestamp(event_time),
        }
        readback = self.read_change_set_ready(
            operation=operation,
            request=request,
            dispatch=dispatch,
            contract=contract,
            parent_receipt_digest=str(claim["claim_digest"]),
        )
        recovered_at = datetime.now(timezone.utc)
        value = {
            "schema_version": 1,
            "record_type": CREATE_RECOVERY_RECORD_TYPE,
            "source_commit": self._config.source_commit,
            "account_id": account_id,
            "region": REGION,
            "operation": operation,
            "claim_digest": claim["claim_digest"],
            "request_digest": digest_value(_json_copy(request)),
            "dispatch": dispatch,
            "change_set_readback": readback,
            "recovered_at": _timestamp(recovered_at),
        }
        return seal(value, "recovery_digest")

    def recover_execute_dispatch(
        self,
        *,
        operation: str,
        request: Mapping[str, Any],
        claim: Mapping[str, Any],
        create_dispatch: Mapping[str, Any],
        terminal_parameters_digest: str,
        creator_request: Mapping[str, Any],
        contract: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Recover one causally claimed ExecuteChangeSet without replaying it."""

        _require_digest(
            terminal_parameters_digest, "EXECUTE_RECOVERY_READBACK_INVALID"
        )
        account_id = operation_account(operation)
        claimed_at = _parse_time(
            claim.get("claimed_at"), "EXECUTE_RECOVERY_INVALID"
        )
        expected_parameters = self._execute_cloudtrail_parameters(request)
        expected_role = (
            AUTHORITY_EXECUTOR_ROLE_NAME
            if account_id == AUTHORITY_ACCOUNT_ID
            else MANAGEMENT_EXECUTOR_ROLE_NAME
        )
        role_pattern = self._expected_assumed_role_pattern(
            account_id=account_id, role_name=expected_role
        )
        events = _lookup_cloudtrail_events(
            self._cloudtrail[account_id],
            request={
                "LookupAttributes": [
                    {
                        "AttributeKey": "EventName",
                        "AttributeValue": "ExecuteChangeSet",
                    }
                ],
                "StartTime": claimed_at,
                "EndTime": datetime.now(timezone.utc),
                "MaxResults": 50,
            },
            error_code="EXECUTE_RECOVERY_PENDING",
            retryable_read_only=True,
            budget=self._budget,
        )
        matches: list[tuple[dict[str, Any], datetime]] = []
        for envelope in events:
            event = self._cloudtrail_event(
                envelope, code="EXECUTE_RECOVERY_CLOUDTRAIL_INVALID"
            )
            parameters = event.get("requestParameters")
            if not isinstance(parameters, Mapping):
                continue
            if (
                parameters.get("clientRequestToken")
                != request["ClientRequestToken"]
            ):
                continue
            identity = event.get("userIdentity")
            caller_arn = (
                identity.get("arn") if isinstance(identity, Mapping) else None
            )
            event_time = _parse_time(
                event.get("eventTime"), "EXECUTE_RECOVERY_CLOUDTRAIL_INVALID"
            )
            if (
                event.get("eventSource") != "cloudformation.amazonaws.com"
                or event.get("eventName") != "ExecuteChangeSet"
                or event.get("awsRegion") != REGION
                or event.get("recipientAccountId") != account_id
                or event.get("readOnly") is not False
                or event.get("errorCode") is not None
                or event.get("errorMessage") is not None
                or event.get("responseElements") is not None
                or parameters != expected_parameters
                or not isinstance(caller_arn, str)
                or role_pattern.fullmatch(caller_arn) is None
                or _UUID_RE.fullmatch(str(event.get("eventID", ""))) is None
                or _UUID_RE.fullmatch(str(event.get("requestID", ""))) is None
                or not claimed_at <= event_time < self._config.route_not_after
            ):
                raise RouteBrokerError("EXECUTE_RECOVERY_CLOUDTRAIL_INVALID")
            matches.append((event, event_time))
        if not matches:
            raise RouteBrokerError(
                "EXECUTE_RECOVERY_PENDING", retryable_read_only=True
            )
        if len(matches) != 1:
            raise RouteBrokerError("EXECUTE_RECOVERY_AMBIGUOUS")
        event, event_time = matches[0]
        dispatch = {
            **{field: create_dispatch[field] for field in _CREATE_DISPATCH_FIELDS},
            "execute_operation": operation,
            "execute_request_id": event["requestID"],
            "execute_request_digest": digest_value(_json_copy(request)),
            "terminal_parameters_digest": terminal_parameters_digest,
            "executed_at": _timestamp(event_time),
        }

        self._require_read_budget()
        response = self._cloudformation[account_id].describe_change_set(
            StackName=create_dispatch["stack_arn"],
            ChangeSetName=create_dispatch["change_set_arn"],
        )
        if response.get("NextToken") is not None:
            raise RouteBrokerError("EXECUTE_RECOVERY_READBACK_INVALID")
        changes = self._change_projection(response)
        execution_status = response.get("ExecutionStatus")
        if (
            response.get("ChangeSetId") != create_dispatch["change_set_arn"]
            or response.get("StackId") != create_dispatch["stack_arn"]
            or response.get("StackName") != creator_request["StackName"]
            or response.get("ChangeSetName") != creator_request["ChangeSetName"]
            or response.get("Description") != creator_request["Description"]
            or response.get("ChangeSetType") != creator_request["ChangeSetType"]
            or not _change_set_parameters_match(
                response.get("Parameters"),
                creator_request["Parameters"],
                expected_terminal_parameters_digest=terminal_parameters_digest,
            )
            or response.get("Capabilities", []) != creator_request["Capabilities"]
            or response.get("Tags", []) != creator_request["Tags"]
            or response.get("IncludeNestedStacks", False)
            != creator_request["IncludeNestedStacks"]
            or response.get("NotificationARNs", [])
            != creator_request["NotificationARNs"]
            or response.get("RollbackConfiguration", {})
            != creator_request["RollbackConfiguration"]
            or response.get("OnStackFailure")
            != creator_request.get("OnStackFailure")
            or response.get("Status") != "CREATE_COMPLETE"
            or execution_status
            not in {"EXECUTE_IN_PROGRESS", "EXECUTE_COMPLETE", "OBSOLETE"}
            or "RoleARN" in response
            or "ResourcesToImport" in response
            or changes != contract["expected_changes"]
        ):
            raise RouteBrokerError("EXECUTE_RECOVERY_READBACK_INVALID")
        self._require_read_budget()
        template = self._cloudformation[account_id].get_template(
            ChangeSetName=create_dispatch["change_set_arn"],
            TemplateStage="Original",
        )
        template_digest = _text_digest(
            template.get("TemplateBody"), "EXECUTE_RECOVERY_READBACK_INVALID"
        )
        if template_digest != contract["template_digest"]:
            raise RouteBrokerError("EXECUTE_RECOVERY_READBACK_INVALID")
        read_at = datetime.now(timezone.utc)
        event_projection = {
            "event_id": event["eventID"],
            "event_time": event["eventTime"],
            "request_id": event["requestID"],
            "caller_arn": event["userIdentity"]["arn"],
            "operation": operation,
            "request_contract_digest": digest_value(_json_copy(request)),
            "cloudtrail_parameters_digest": digest_value(expected_parameters),
            "change_set_arn": create_dispatch["change_set_arn"],
            "stack_arn": create_dispatch["stack_arn"],
        }
        snapshot = {
            "stack_arn": create_dispatch["stack_arn"],
            "change_set_arn": create_dispatch["change_set_arn"],
            "status": response["Status"],
            "execution_status": execution_status,
            "creator_request_digest": digest_value(_json_copy(creator_request)),
            "execute_request_digest": digest_value(_json_copy(request)),
            "template_digest": template_digest,
            "changes_digest": digest_value(changes),
            "parameters_digest": digest_value(creator_request["Parameters"]),
            "tags_digest": digest_value(creator_request["Tags"]),
            "role_arn_absent": "RoleARN" not in response,
            "resources_to_import_absent": "ResourcesToImport" not in response,
            "cloudtrail_event_digest": digest_value(event_projection),
            "read_at": _timestamp(read_at),
        }
        value = {
            "schema_version": 1,
            "record_type": EXECUTE_RECOVERY_RECORD_TYPE,
            "source_commit": self._config.source_commit,
            "account_id": account_id,
            "region": REGION,
            "operation": operation,
            "claim_digest": claim["claim_digest"],
            "request_digest": digest_value(_json_copy(request)),
            "dispatch": dispatch,
            "change_set_snapshot": snapshot,
            "recovered_at": _timestamp(datetime.now(timezone.utc)),
        }
        return seal(value, "recovery_digest")

    def _permission_set_outputs(
        self, *, source: str
    ) -> tuple[dict[str, str], str]:
        contract = self._config.output_contract(source)
        account_id = contract["account_id"]
        self._require_read_budget()
        response = self._cloudformation[account_id].describe_stacks(
            StackName=contract["stack_name"]
        )
        stacks = response.get("Stacks")
        if not isinstance(stacks, list) or len(stacks) != 1 or response.get("NextToken"):
            raise RouteBrokerError("DYNAMIC_OUTPUT_PENDING", retryable_read_only=True)
        stack = stacks[0]
        stack_id = stack.get("StackId")
        expected_prefix = (
            f"arn:aws:cloudformation:{REGION}:{account_id}:stack/"
            f"{contract['stack_name']}/"
        )
        outputs_raw = stack.get("Outputs")
        if (
            not isinstance(stack_id, str)
            or _STACK_ARN_RE.fullmatch(stack_id) is None
            or not stack_id.startswith(expected_prefix)
            or stack.get("StackName") != contract["stack_name"]
            or stack.get("StackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
            or "RoleARN" in stack
            or "ParentId" in stack
            or "RootId" in stack
            or stack.get("NotificationARNs", []) != []
            or not isinstance(outputs_raw, list)
        ):
            raise RouteBrokerError("DYNAMIC_OUTPUT_INVALID")
        outputs: dict[str, str] = {}
        for item in outputs_raw:
            if (
                not isinstance(item, Mapping)
                or set(item).difference({"OutputKey", "OutputValue", "Description", "ExportName"})
                or not isinstance(item.get("OutputKey"), str)
                or not isinstance(item.get("OutputValue"), str)
                or item["OutputKey"] in outputs
            ):
                raise RouteBrokerError("DYNAMIC_OUTPUT_INVALID")
            outputs[item["OutputKey"]] = item["OutputValue"]
        for key, expected in contract["required_mode_outputs"].items():
            if outputs.get(key) != expected:
                raise RouteBrokerError("DYNAMIC_OUTPUT_INVALID")
        permission_sets = {
            key: outputs.get(key, "")
            for key in contract["permission_set_output_keys"]
        }
        projection = {
            "source": source,
            "account_id": account_id,
            "stack_id": stack_id,
            "stack_status": stack["StackStatus"],
            "outputs": outputs,
            "permission_set_arns": permission_sets,
        }
        if source == "delegation":
            projection["identity_center_readback"] = (
                self._delegation_permission_set_readback(
                    permission_set_arn=permission_sets[
                        "RepairInvokerPermissionSetArn"
                    ]
                )
            )
        return permission_sets, digest_value(projection)

    def _current_stack_parameter_values(
        self,
        *,
        account_id: str,
        stack_arn: str,
        stack_name: str,
        change_set_creation_time: datetime,
    ) -> dict[str, str]:
        """Read one stable pre-execution parameter baseline for an UPDATE."""

        self._require_read_budget()
        response = self._cloudformation[account_id].describe_stacks(
            StackName=stack_arn
        )
        stacks = response.get("Stacks")
        if (
            not isinstance(stacks, list)
            or len(stacks) != 1
            or response.get("NextToken") is not None
        ):
            raise RouteBrokerError("CHANGE_SET_PARAMETER_BASELINE_INVALID")
        stack = stacks[0]
        if not isinstance(stack, Mapping):
            raise RouteBrokerError("CHANGE_SET_PARAMETER_BASELINE_INVALID")
        observed_at = stack.get("LastUpdatedTime", stack.get("CreationTime"))
        if (
            stack.get("StackId") != stack_arn
            or stack.get("StackName") != stack_name
            or stack.get("StackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
            or not isinstance(observed_at, datetime)
            or observed_at > change_set_creation_time
            or "RoleARN" in stack
            or "ParentId" in stack
            or "RootId" in stack
            or stack.get("NotificationARNs", []) != []
        ):
            raise RouteBrokerError("CHANGE_SET_PARAMETER_BASELINE_INVALID")
        return _stack_parameter_values(
            stack.get("Parameters"),
            error_code="CHANGE_SET_PARAMETER_BASELINE_INVALID",
        )

    def read_change_set_ready(
        self,
        *,
        operation: str,
        request: Mapping[str, Any],
        dispatch: Mapping[str, Any],
        contract: Mapping[str, Any],
        parent_receipt_digest: str,
    ) -> Mapping[str, Any]:
        account_id = operation_account(operation)
        self._require_read_budget()
        response = self._cloudformation[account_id].describe_change_set(
            StackName=dispatch["stack_arn"],
            ChangeSetName=dispatch["change_set_arn"],
        )
        if response.get("NextToken") is not None:
            raise RouteBrokerError("CHANGE_SET_READBACK_INVALID")
        if response.get("Status") in {"CREATE_PENDING", "CREATE_IN_PROGRESS"}:
            raise RouteBrokerError(
                "CHANGE_SET_READBACK_PENDING", retryable_read_only=True
            )
        creation_time = response.get("CreationTime")
        if not isinstance(creation_time, datetime):
            raise RouteBrokerError("CHANGE_SET_READBACK_INVALID")
        current_values: Mapping[str, str] | None = None
        if request.get("ChangeSetType") == "UPDATE":
            current_values = self._current_stack_parameter_values(
                account_id=account_id,
                stack_arn=dispatch["stack_arn"],
                stack_name=request["StackName"],
                change_set_creation_time=creation_time,
            )
        elif request.get("ChangeSetType") != "CREATE":
            raise RouteBrokerError("CHANGE_SET_READBACK_INVALID")
        terminal_parameter_values = _expected_terminal_parameter_values(
            request["Parameters"],
            current_values=current_values,
            error_code="CHANGE_SET_PARAMETER_BASELINE_INVALID",
        )
        terminal_parameters_digest = digest_value(terminal_parameter_values)
        changes = self._change_projection(response)
        if (
            response.get("ChangeSetId") != dispatch["change_set_arn"]
            or response.get("StackId") != dispatch["stack_arn"]
            or response.get("StackName") != request["StackName"]
            or response.get("ChangeSetName") != request["ChangeSetName"]
            or response.get("Description") != request["Description"]
            or response.get("ChangeSetType") != request["ChangeSetType"]
            or not _change_set_parameters_match(
                response.get("Parameters"),
                request["Parameters"],
                expected_terminal_parameters_digest=terminal_parameters_digest,
            )
            or response.get("Capabilities", []) != request["Capabilities"]
            or response.get("Tags", []) != request["Tags"]
            or response.get("IncludeNestedStacks", False)
            != request["IncludeNestedStacks"]
            or response.get("NotificationARNs", []) != request["NotificationARNs"]
            or response.get("RollbackConfiguration", {})
            != request["RollbackConfiguration"]
            or response.get("OnStackFailure")
            != request.get("OnStackFailure")
            or "RoleARN" in response
            or "ResourcesToImport" in response
            or changes != contract["expected_changes"]
        ):
            raise RouteBrokerError("CHANGE_SET_READBACK_INVALID")
        self._require_read_budget()
        template = self._cloudformation[account_id].get_template(
            ChangeSetName=dispatch["change_set_arn"], TemplateStage="Original"
        )
        template_digest = _text_digest(
            template.get("TemplateBody"), "CHANGE_SET_TEMPLATE_INVALID"
        )
        if template_digest != contract["template_digest"]:
            raise RouteBrokerError("CHANGE_SET_TEMPLATE_INVALID")
        now = datetime.now(timezone.utc)
        cloudtrail_digest = self._create_event_digest(
            account_id=account_id,
            operation=operation,
            request=request,
            dispatch=dispatch,
            end_time=now,
        )
        derived_outputs: dict[str, str] = {}
        source_stack_digest: str | None = None
        if operation == "seed-revoke-create-v1":
            derived_outputs, source_stack_digest = self._permission_set_outputs(
                source="route"
            )
        value = {
            "schema_version": 1,
            "record_type": CHANGE_SET_READBACK_RECORD_TYPE,
            "operation": operation,
            "source_commit": self._config.source_commit,
            "account_id": account_id,
            "region": REGION,
            "stack_name": response.get("StackName"),
            "change_set_name": response.get("ChangeSetName"),
            "stack_arn": response.get("StackId"),
            "change_set_arn": response.get("ChangeSetId"),
            "create_request_id": dispatch["create_request_id"],
            "creation_time": _timestamp(creation_time),
            "status": response.get("Status"),
            "execution_status": response.get("ExecutionStatus"),
            "role_arn_absent": "RoleARN" not in response,
            "resources_to_import_absent": "ResourcesToImport" not in response,
            "request_contract_digest": digest_value(request),
            "template_digest": template_digest,
            "changes_digest": digest_value(changes),
            "terminal_parameters_digest": terminal_parameters_digest,
            "cloudtrail_event_digest": cloudtrail_digest,
            "derived_permission_set_arns": derived_outputs,
            "source_stack_digest": source_stack_digest,
            "parent_receipt_digest": parent_receipt_digest,
            "read_at": _timestamp(now),
        }
        return seal(value, "readback_digest")

    def _terminal_stack_event(
        self,
        *,
        account_id: str,
        expectation: Mapping[str, Any],
        dispatch: Mapping[str, Any],
        stack_status: str,
        execute_request: Mapping[str, Any],
        end_time: datetime,
    ) -> tuple[str, str]:
        """Bind the terminal root event to the exact ExecuteChangeSet token."""

        executed_at = _parse_time(
            dispatch.get("executed_at"), "TERMINAL_STACK_EVENT_INVALID"
        )
        expected_token = execute_request.get("ClientRequestToken")
        if not isinstance(expected_token, str) or not expected_token:
            raise RouteBrokerError("TERMINAL_STACK_EVENT_INVALID", uncertain=True)
        matches: list[dict[str, Any]] = []
        seen_tokens: set[str] = set()
        next_token: str | None = None
        for _ in range(100):
            self._require_read_budget()
            request: dict[str, Any] = {"StackName": dispatch["stack_arn"]}
            if next_token is not None:
                request["NextToken"] = next_token
            try:
                response = self._cloudformation[account_id].describe_stack_events(
                    **request
                )
            except Exception as exc:
                raise RouteBrokerError(
                    "TERMINAL_STACK_EVENT_PENDING", retryable_read_only=True
                ) from exc
            events = response.get("StackEvents") if isinstance(response, Mapping) else None
            if not isinstance(events, list):
                raise RouteBrokerError(
                    "TERMINAL_STACK_EVENT_INVALID", uncertain=True
                )
            for event in events:
                if not isinstance(event, Mapping):
                    raise RouteBrokerError(
                        "TERMINAL_STACK_EVENT_INVALID", uncertain=True
                    )
                if (
                    event.get("ClientRequestToken") != expected_token
                    or event.get("StackId") != dispatch["stack_arn"]
                    or event.get("StackName") != expectation["stack_name"]
                    or event.get("LogicalResourceId") != expectation["stack_name"]
                    or event.get("PhysicalResourceId") != dispatch["stack_arn"]
                    or event.get("ResourceType") != "AWS::CloudFormation::Stack"
                    or event.get("ResourceStatus") != stack_status
                ):
                    continue
                event_id = event.get("EventId")
                timestamp = event.get("Timestamp")
                if (
                    not isinstance(event_id, str)
                    or not event_id
                    or len(event_id) > 1024
                    or not isinstance(timestamp, datetime)
                    or timestamp.tzinfo is None
                    or timestamp.utcoffset() is None
                    or not executed_at <= timestamp <= end_time
                ):
                    raise RouteBrokerError(
                        "TERMINAL_STACK_EVENT_INVALID", uncertain=True
                    )
                matches.append(
                    {
                        "event_id": event_id,
                        "stack_id": event["StackId"],
                        "stack_name": event["StackName"],
                        "logical_resource_id": event["LogicalResourceId"],
                        "physical_resource_id": event["PhysicalResourceId"],
                        "resource_type": event["ResourceType"],
                        "resource_status": event["ResourceStatus"],
                        "client_request_token": event["ClientRequestToken"],
                        "timestamp": _timestamp(timestamp),
                    }
                )
            token = response.get("NextToken")
            if token is None:
                break
            if (
                not isinstance(token, str)
                or not token
                or token in seen_tokens
            ):
                raise RouteBrokerError(
                    "TERMINAL_STACK_EVENT_INVALID", uncertain=True
                )
            seen_tokens.add(token)
            next_token = token
        else:
            raise RouteBrokerError("TERMINAL_STACK_EVENT_INVALID", uncertain=True)
        if not matches:
            raise RouteBrokerError(
                "TERMINAL_STACK_EVENT_PENDING", retryable_read_only=True
            )
        if len(matches) != 1:
            raise RouteBrokerError("TERMINAL_STACK_EVENT_INVALID", uncertain=True)
        projection = matches[0]
        return projection["timestamp"], digest_value(projection)

    def read_terminal_stack(
        self,
        *,
        operation: str,
        expectation: Mapping[str, Any],
        dispatch: Mapping[str, Any],
        parent_receipt_digest: str,
    ) -> Mapping[str, Any]:
        account_id = operation_account(operation)
        if expectation.get("account_id") != account_id:
            raise RouteBrokerError("OPERATION_ACCOUNT_INVALID", uncertain=True)
        self._require_read_budget()
        response = self._cloudformation[account_id].describe_stacks(
            StackName=dispatch["stack_arn"]
        )
        stacks = response.get("Stacks")
        if not isinstance(stacks, list) or len(stacks) != 1 or response.get("NextToken"):
            raise RouteBrokerError(
                "TERMINAL_READBACK_PENDING", retryable_read_only=True
            )
        stack = stacks[0]
        if not isinstance(stack, Mapping):
            raise RouteBrokerError("TERMINAL_READBACK_INVALID", uncertain=True)
        stack_status = stack.get("StackStatus")
        if stack_status not in expectation["terminal_statuses"]:
            if stack_status in _IN_PROGRESS_STACK_STATUSES:
                raise RouteBrokerError(
                    "TERMINAL_READBACK_PENDING", retryable_read_only=True
                )
            raise RouteBrokerError(
                "TERMINAL_READBACK_INVALID", uncertain=True
            )
        stack_projection = _stable_stack_projection(
            stack, error_code="TERMINAL_READBACK_INVALID"
        )
        if (
            stack_projection["stack_id"] != dispatch["stack_arn"]
            or stack_projection["stack_name"] != expectation["stack_name"]
            or stack_projection["change_set_id"] != dispatch["change_set_arn"]
            or stack_projection["role_arn_absent"] is not True
            or stack_projection["parent_id_absent"] is not True
            or stack_projection["root_id_absent"] is not True
            or stack_projection["notification_arns"] != []
        ):
            raise RouteBrokerError("TERMINAL_READBACK_INVALID", uncertain=True)
        stack_parameters_digest = digest_value(stack_projection["parameters"])
        if stack_parameters_digest != dispatch.get("terminal_parameters_digest"):
            raise RouteBrokerError("TERMINAL_PARAMETERS_INVALID", uncertain=True)
        self._require_read_budget()
        resources_response = self._cloudformation[account_id].list_stack_resources(
            StackName=dispatch["stack_arn"]
        )
        raw_resources = resources_response.get("StackResourceSummaries")
        if not isinstance(raw_resources, list) or resources_response.get("NextToken"):
            raise RouteBrokerError("TERMINAL_READBACK_INCOMPLETE")
        resources = sorted(
            [
                {
                    "logical_resource_id": item.get("LogicalResourceId"),
                    "resource_type": item.get("ResourceType"),
                }
                for item in raw_resources
                if isinstance(item, Mapping)
            ],
            key=lambda item: (
                str(item["logical_resource_id"]), str(item["resource_type"])
            ),
        )
        if resources != expectation["expected_resources"]:
            raise RouteBrokerError("TERMINAL_RESOURCE_INVENTORY_INVALID")
        self._require_read_budget()
        template = self._cloudformation[account_id].get_template(
            StackName=dispatch["stack_arn"], TemplateStage="Original"
        )
        template_digest = _text_digest(
            template.get("TemplateBody"), "TERMINAL_TEMPLATE_INVALID"
        )
        if template_digest != expectation["template_digest"]:
            raise RouteBrokerError("TERMINAL_TEMPLATE_INVALID")
        outputs = stack_projection["outputs"]
        if (
            sorted(outputs) != expectation["expected_output_keys"]
            or any(
                outputs.get(key) != expected
                for key, expected in expectation["expected_static_outputs"].items()
            )
        ):
            raise RouteBrokerError("TERMINAL_OUTPUTS_INVALID")
        tags = stack_projection["tags"]
        if tags != expectation["expected_tags"]:
            raise RouteBrokerError("TERMINAL_TAGS_INVALID")
        live_control: dict[str, Any] = {}
        if operation == "pep-protection-execute-v1":
            table_name = outputs.get("RepairLedgerName")
            key_arn = outputs.get("RepairLedgerKeyArn")
            if (
                table_name != REPAIR_LEDGER_TABLE_NAME
                or not isinstance(key_arn, str)
                or _AUTHORITY_KMS_KEY_ARN_RE.fullmatch(key_arn) is None
            ):
                raise RouteBrokerError("PEP_LEDGER_CONTROL_INVALID")
            self._require_read_budget()
            table_response = self._dynamodb.describe_table(TableName=table_name)
            table = table_response.get("Table")
            if not isinstance(table, Mapping):
                raise RouteBrokerError("PEP_LEDGER_CONTROL_INVALID")
            sse = table.get("SSEDescription")
            live_control = {
                "table_name": table.get("TableName"),
                "table_arn": table.get("TableArn"),
                "table_status": table.get("TableStatus"),
                "deletion_protection_enabled": table.get(
                    "DeletionProtectionEnabled"
                ),
                "sse_status": (
                    sse.get("Status") if isinstance(sse, Mapping) else None
                ),
                "sse_type": (
                    sse.get("SSEType") if isinstance(sse, Mapping) else None
                ),
                "kms_key_arn": (
                    sse.get("KMSMasterKeyArn")
                    if isinstance(sse, Mapping)
                    else None
                ),
            }
            expected_table_arn = (
                f"arn:aws:dynamodb:{REGION}:{AUTHORITY_ACCOUNT_ID}:table/"
                f"{REPAIR_LEDGER_TABLE_NAME}"
            )
            if live_control != {
                "table_name": REPAIR_LEDGER_TABLE_NAME,
                "table_arn": expected_table_arn,
                "table_status": "ACTIVE",
                "deletion_protection_enabled": True,
                "sse_status": "ENABLED",
                "sse_type": "KMS",
                "kms_key_arn": key_arn,
            }:
                raise RouteBrokerError("PEP_LEDGER_CONTROL_INVALID")
        derived_outputs: dict[str, str] = {}
        source_stack_digest: str | None = None
        if operation == "delegation-execute-v1":
            derived_outputs, source_stack_digest = self._permission_set_outputs(
                source="delegation"
            )
        execute_request = self._config.request(operation)
        execute_request["StackName"] = dispatch["stack_arn"]
        execute_request["ChangeSetName"] = dispatch["change_set_arn"]
        if digest_value(execute_request) != dispatch.get("execute_request_digest"):
            raise RouteBrokerError("EXECUTE_REQUEST_BINDING_INVALID")
        event_end_time = datetime.now(timezone.utc)
        execute_cloudtrail_event_digest = self._execute_event_digest(
            account_id=account_id,
            operation=operation,
            request=execute_request,
            dispatch=dispatch,
            end_time=event_end_time,
        )
        stack_terminal_event_time, stack_terminal_event_digest = (
            self._terminal_stack_event(
                account_id=account_id,
                expectation=expectation,
                dispatch=dispatch,
                stack_status=stack_status,
                execute_request=execute_request,
                end_time=event_end_time,
            )
        )
        self._require_read_budget()
        final_response = self._cloudformation[account_id].describe_stacks(
            StackName=dispatch["stack_arn"]
        )
        final_stacks = final_response.get("Stacks")
        if (
            not isinstance(final_stacks, list)
            or len(final_stacks) != 1
            or final_response.get("NextToken") is not None
        ):
            raise RouteBrokerError("TERMINAL_SNAPSHOT_CHANGED", uncertain=True)
        final_projection = _stable_stack_projection(
            final_stacks[0], error_code="TERMINAL_SNAPSHOT_CHANGED"
        )
        if final_projection != stack_projection:
            raise RouteBrokerError("TERMINAL_SNAPSHOT_CHANGED", uncertain=True)
        read_at = datetime.now(timezone.utc)
        value = {
            "schema_version": 1,
            "record_type": TERMINAL_READBACK_RECORD_TYPE,
            "operation": operation,
            "source_commit": self._config.source_commit,
            "account_id": expectation["account_id"],
            "region": REGION,
            "stack_name": stack_projection["stack_name"],
            "stack_arn": stack_projection["stack_id"],
            "execute_request_id": dispatch["execute_request_id"],
            "execute_cloudtrail_event_digest": execute_cloudtrail_event_digest,
            "stack_terminal_event_time": stack_terminal_event_time,
            "stack_terminal_event_digest": stack_terminal_event_digest,
            "stack_last_updated_time": stack_projection["last_updated_time"],
            "role_arn_absent": stack_projection["role_arn_absent"],
            "parent_id_absent": stack_projection["parent_id_absent"],
            "root_id_absent": stack_projection["root_id_absent"],
            "notification_arns": stack_projection["notification_arns"],
            "template_digest": template_digest,
            "stack_resources_digest": digest_value(resources),
            "stack_resource_count": len(resources),
            "stack_outputs_digest": digest_value(
                {
                    "keys": expectation["expected_output_keys"],
                    "static": expectation["expected_static_outputs"],
                }
            ),
            "stack_tags_digest": digest_value(tags),
            "stack_parameters_digest": stack_parameters_digest,
            "live_control": live_control,
            "live_control_digest": digest_value(live_control),
            "derived_permission_set_arns": derived_outputs,
            "source_stack_digest": source_stack_digest,
            "stack_status": stack_status,
            "terminal": True,
            "parent_receipt_digest": parent_receipt_digest,
            "read_at": _timestamp(read_at),
        }
        return seal(value, "readback_digest")

    def read_assignments(
        self,
        *,
        operation: str,
        scope: Mapping[str, Any],
        terminal_readback_digest: str,
    ) -> Mapping[str, Any]:
        assignments: list[Any] = []
        seen_tokens: set[str] = set()
        next_token: str | None = None
        while True:
            self._require_read_budget()
            request = {
                "InstanceArn": scope["instance_arn"],
                "AccountId": scope["account_id"],
                "PermissionSetArn": scope["permission_set_arn"],
                "MaxResults": 100,
            }
            if next_token is not None:
                request["NextToken"] = next_token
            response = self._sso.list_account_assignments(**request)
            page = response.get("AccountAssignments")
            if not isinstance(page, list):
                raise RouteBrokerError("ASSIGNMENT_READBACK_INVALID")
            assignments.extend(page)
            token = response.get("NextToken")
            if token is None:
                break
            if (
                not isinstance(token, str)
                or not token
                or token in seen_tokens
                or len(seen_tokens) >= 99
            ):
                raise RouteBrokerError("ASSIGNMENT_READBACK_INVALID")
            seen_tokens.add(token)
            next_token = token
        value = {
            "schema_version": 1,
            "record_type": ASSIGNMENT_READBACK_RECORD_TYPE,
            "operation": operation,
            "source_commit": self._config.source_commit,
            "account_id": scope["account_id"],
            "region": REGION,
            "instance_arn": scope["instance_arn"],
            "permission_set_arn": scope["permission_set_arn"],
            "assignment_count": len(assignments),
            "terminal": True,
            "terminal_readback_digest": terminal_readback_digest,
            "read_at": _timestamp(datetime.now(timezone.utc)),
        }
        return seal(value, "readback_digest")

    def _get_repair_item(self, repair_id: str) -> Mapping[str, Any]:
        self._require_read_budget()
        response = self._dynamodb.get_item(
            TableName=self._repair_table,
            Key={"repair_id": {"S": repair_id}},
            ConsistentRead=True,
        )
        item = response.get("Item")
        if not isinstance(item, Mapping):
            raise RouteBrokerError("REPAIR_EVIDENCE_MISSING")
        return self._decode(item)

    def read_repair_ledger(self, *, repair_id: str) -> Mapping[str, Any]:
        return self._get_repair_item(repair_id)

    def read_reconcile_attestation(self, *, attestation_id: str) -> Mapping[str, Any]:
        return self._get_repair_item(attestation_id)

    def read_plan_list_change_sets_events(
        self,
        *,
        stack_name: str,
        start_time: str,
        end_time: str,
    ) -> Sequence[Mapping[str, Any]]:
        events = _lookup_cloudtrail_events(
            self._cloudtrail[AUTHORITY_ACCOUNT_ID],
            request={
                "LookupAttributes": [
                {"AttributeKey": "EventName", "AttributeValue": "ListChangeSets"}
                ],
                "StartTime": _parse_time(start_time),
                "EndTime": _parse_time(end_time),
                "MaxResults": 50,
            },
            error_code="PLAN_CLOUDTRAIL_INCOMPLETE",
            retryable_read_only=True,
            budget=self._budget,
        )
        projected: list[Mapping[str, Any]] = []
        for envelope in events:
            raw = envelope.get("CloudTrailEvent")
            if not isinstance(raw, str):
                raise RouteBrokerError("PLAN_CLOUDTRAIL_EVENT_INVALID")
            event = json.loads(raw)
            request_value = event.get("requestParameters")
            request = request_value if isinstance(request_value, Mapping) else {}
            identity_value = event.get("userIdentity")
            identity = identity_value if isinstance(identity_value, Mapping) else {}
            session_context_value = identity.get("sessionContext")
            session_context = (
                session_context_value
                if isinstance(session_context_value, Mapping)
                else {}
            )
            issuer_value = session_context.get("sessionIssuer")
            issuer = issuer_value if isinstance(issuer_value, Mapping) else {}
            if (
                event.get("eventSource") != "cloudformation.amazonaws.com"
                or event.get("eventName") != "ListChangeSets"
                or request.get("stackName") != stack_name
            ):
                continue
            try:
                _normal_plan_session_name(
                    identity.get("arn"),
                    generated_role_name=(
                        self._config.normal_plan_generated_role_name
                    ),
                )
            except RouteBrokerError:
                # Other roles may inspect the same stack. They are not normal-Plan
                # proof and must not poison a later read-only closeout retry.
                continue
            value = {
                "schema_version": 1,
                "record_type": PLAN_EVENT_RECORD_TYPE,
                "event_id": event.get("eventID"),
                "event_source": event.get("eventSource"),
                "event_name": event.get("eventName"),
                "event_time": event.get("eventTime"),
                "aws_region": event.get("awsRegion"),
                "recipient_account_id": event.get("recipientAccountId"),
                "read_only": event.get("readOnly"),
                "success": not bool(event.get("errorCode") or event.get("errorMessage")),
                "caller_arn": identity.get("arn"),
                "identity_type": identity.get("type"),
                "identity_account_id": identity.get("accountId"),
                "session_issuer_type": issuer.get("type"),
                "session_issuer_arn": issuer.get("arn"),
                "session_issuer_account_id": issuer.get("accountId"),
                "session_issuer_user_name": issuer.get("userName"),
                "stack_name": request.get("stackName"),
            }
            projected.append(seal(value, "event_digest"))
        return projected

    def read_plan_recovery_preflight(
        self,
        *,
        normal_plan_caller_arn_digest: str,
        parent_events_digest: str,
    ) -> Mapping[str, Any]:
        authority_cloudformation = self._cloudformation[AUTHORITY_ACCOUNT_ID]
        self._require_read_budget()
        stack_response = authority_cloudformation.describe_stacks(
            StackName=PLAN_STACK_NAME
        )
        stacks = stack_response.get("Stacks")
        if (
            not isinstance(stacks, list)
            or len(stacks) != 1
            or stack_response.get("NextToken")
        ):
            raise RouteBrokerError("PLAN_PREFLIGHT_INVALID")
        stack = stacks[0]
        self._require_read_budget()
        resources_response = authority_cloudformation.list_stack_resources(
            StackName=PLAN_STACK_NAME
        )
        resources = resources_response.get("StackResourceSummaries")
        summaries: list[Any] = []
        seen_tokens: set[str] = set()
        next_token: str | None = None
        page_count = 0
        while True:
            self._require_read_budget()
            request: dict[str, Any] = {"StackName": PLAN_STACK_NAME}
            if next_token is not None:
                request["NextToken"] = next_token
            change_sets_response = authority_cloudformation.list_change_sets(**request)
            page_count += 1
            page = change_sets_response.get("Summaries")
            if not isinstance(page, list):
                raise RouteBrokerError("PLAN_PREFLIGHT_INVALID")
            summaries.extend(page)
            token = change_sets_response.get("NextToken")
            if token is None:
                break
            if (
                not isinstance(token, str)
                or not token
                or token in seen_tokens
                or len(seen_tokens) >= 99
            ):
                raise RouteBrokerError("PLAN_PREFLIGHT_INVALID")
            seen_tokens.add(token)
            next_token = token
        self._require_read_budget()
        pab_response = self._s3control.get_public_access_block(
            AccountId=AUTHORITY_ACCOUNT_ID
        )
        public_access_block = pab_response.get("PublicAccessBlockConfiguration")
        expected_pab = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
        if (
            not isinstance(resources, list)
            or resources_response.get("NextToken") is not None
            or public_access_block != expected_pab
        ):
            raise RouteBrokerError("PLAN_PREFLIGHT_INVALID")
        stack_id = stack.get("StackId")
        expected_stack_prefix = (
            f"arn:aws:cloudformation:{REGION}:{AUTHORITY_ACCOUNT_ID}:stack/"
            f"{PLAN_STACK_NAME}/"
        )
        if (
            not isinstance(stack_id, str)
            or _STACK_ARN_RE.fullmatch(stack_id) is None
            or not stack_id.startswith(expected_stack_prefix)
            or stack.get("StackName") != PLAN_STACK_NAME
            or "RoleARN" in stack
            or "ParentId" in stack
            or "RootId" in stack
            or stack.get("NotificationARNs", []) != []
        ):
            raise RouteBrokerError("PLAN_PREFLIGHT_INVALID")
        value = {
            "schema_version": 1,
            "record_type": PLAN_PREFLIGHT_RECORD_TYPE,
            "source_commit": self._config.source_commit,
            "account_id": AUTHORITY_ACCOUNT_ID,
            "region": REGION,
            "stack_name": stack.get("StackName"),
            "stack_id": stack_id,
            "stack_status": stack.get("StackStatus"),
            "role_arn_absent": "RoleARN" not in stack,
            "parent_id_absent": "ParentId" not in stack,
            "root_id_absent": "RootId" not in stack,
            "notification_arns": stack.get("NotificationARNs", []),
            "stack_resource_count": len(resources),
            "stack_resources_digest": digest_value(resources),
            "active_change_set_count": len(summaries),
            "active_change_sets_digest": digest_value(summaries),
            "change_set_page_count": page_count,
            "pagination_complete": True,
            "public_access_block_configuration": public_access_block,
            "public_access_block_digest": digest_value(public_access_block),
            "complete": True,
            "normal_plan_caller_arn_digest": normal_plan_caller_arn_digest,
            "parent_events_digest": parent_events_digest,
            "read_at": _timestamp(datetime.now(timezone.utc)),
        }
        return seal(value, "readback_digest")


__all__ = [
    "ASSIGNMENT_READBACK_RECORD_TYPE",
    "ATTEMPT_CLAIM_RECORD_TYPE",
    "AUTHORITY_ACCOUNT_ID",
    "AUTHORITY_CREATE_RECOVERY_ROLE_NAME",
    "AUTHORITY_CREATOR_ROLE_ARN",
    "AUTHORITY_CREATOR_ROLE_NAME",
    "AUTHORITY_EXECUTE_RECOVERY_ROLE_NAME",
    "AUTHORITY_EXECUTOR_ROLE_ARN",
    "AUTHORITY_EXECUTOR_ROLE_NAME",
    "BrokerConfig",
    "CHANGE_SET_READBACK_RECORD_TYPE",
    "CONFIG_RECORD_TYPE",
    "COMPRESSED_CONFIG_RECORD_TYPE",
    "CREATE_RECOVERY_FUNCTION_NAME",
    "CREATE_RECOVERY_RECORD_TYPE",
    "CREATOR_ALIASES",
    "CREATOR_FUNCTION_NAME",
    "EXECUTOR_ALIASES",
    "EXECUTOR_FUNCTION_NAME",
    "EXECUTE_RECOVERY_FUNCTION_NAME",
    "EXECUTE_RECOVERY_RECORD_TYPE",
    "EffectPort",
    "EvidencePort",
    "LEDGER_RECORD_TYPE",
    "LedgerPort",
    "LedgerSnapshot",
    "MANAGEMENT_ACCOUNT_ID",
    "MANAGEMENT_CREATOR_ROLE_ARN",
    "MANAGEMENT_CREATOR_ROLE_NAME",
    "MANAGEMENT_EXECUTOR_ROLE_ARN",
    "MANAGEMENT_EXECUTOR_ROLE_NAME",
    "MANAGEMENT_RECOVERY_ROLE_ARN",
    "MANAGEMENT_RECOVERY_ROLE_NAME",
    "MANAGEMENT_ROLE_PATH",
    "MUTATION_COMPLETION_RESERVE_SECONDS",
    "MUTATION_DISPATCH_MIN_REMAINING_MS",
    "NORMAL_PLAN_CALLER_BINDING_KEY",
    "NORMAL_PLAN_MAX_EVENT_AGE_SECONDS",
    "PLAN_EVENT_RECORD_TYPE",
    "PLAN_PREFLIGHT_RECORD_TYPE",
    "PLAN_STACK_NAME",
    "RECEIPT_RECORD_TYPE",
    "RECONCILE_ATTESTATION_RECORD_TYPE",
    "RECOVERY_ALIAS",
    "RECOVERY_RECEIPT_ALIASES",
    "REGION",
    "REPAIR_LEDGER_RECORD_TYPE",
    "ROUTE_LEDGER_TABLE_NAME",
    "ROUTE_LEDGER_ID",
    "ROUTE_BROKER_STACK_NAME",
    "RouteBroker",
    "RouteBrokerError",
    "RouteBrokerReadOnlyPending",
    "TERMINAL_READBACK_RECORD_TYPE",
    "canonical_json",
    "create_dispatch_recovery_handler",
    "creator_handler",
    "decode_runtime_config",
    "digest_value",
    "executor_handler",
    "encode_runtime_config",
    "execute_dispatch_recovery_handler",
    "install_runtime_factory",
    "operation_account",
    "seal",
    "validate_empty_event",
    "verify_closeout_prerequisites",
]
