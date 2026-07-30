import axios from 'axios';
import { getApiClient } from './client';
import {
  recordLifecycleUiEvent,
  type LifecycleUiOperation,
  type LifecycleUiResult,
} from '../telemetry/lifecycleTelemetry.js';

export type EnterpriseRole =
  | 'auditor'
  | 'customer_admin'
  | 'document_operator'
  | 'document_reviewer';
export type MembershipState = 'invited' | 'active' | 'suspended' | 'expired' | 'revoked';

export interface Membership {
  readonly membershipReference: string;
  readonly state: MembershipState;
  readonly roleId: EnterpriseRole;
  readonly membershipVersion: string;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly invitationExpiresAt: string | null;
}

export interface LifecycleAuditEvent {
  readonly eventReference: string;
  readonly timestamp: string;
  readonly action: string;
  readonly decision: 'allow' | 'deny';
  readonly reasonCode: string;
  readonly principalReference: string;
  readonly correlationReference: string;
  readonly beforeMembershipVersion: string;
  readonly afterMembershipVersion: string;
}

export interface TransitionInput {
  readonly expectedMembershipVersion: number;
  readonly approvalReference: string;
  readonly reasonCode: string;
  readonly replacementMembershipReference?: string | null;
}

export interface RoleChangeInput extends TransitionInput {
  readonly roleId: EnterpriseRole;
}

export interface InvitationInput {
  readonly principalLocator: string;
  readonly roleId: EnterpriseRole;
  readonly expiresInSeconds: number;
  readonly approvalReference: string;
}

export interface InvitationResendInput extends TransitionInput {
  readonly expiresInSeconds: number;
}

export type LifecycleErrorKind =
  | 'denied'
  | 'conflict'
  | 'invalid'
  | 'session_expired'
  | 'rate_limited'
  | 'degraded';

export class LifecycleApiError extends Error {
  readonly kind: LifecycleErrorKind;
  readonly correlationReference: string | null;

  constructor(kind: LifecycleErrorKind, correlationReference: string | null) {
    super('LIFECYCLE_REQUEST_FAILED');
    this.name = 'LifecycleApiError';
    this.kind = kind;
    this.correlationReference = correlationReference;
  }
}

const REFERENCE = /^ref_[0-9a-f]{24,64}$/u;
const MEMBERSHIP_REFERENCE = /^mbr_[0-9a-f]{32,64}$/u;
const VERSION = /^[1-9][0-9]*$/u;
const REASON = /^[a-z][a-z0-9_]{2,63}$/u;
const ROLES = new Set<EnterpriseRole>([
  'auditor', 'customer_admin', 'document_operator', 'document_reviewer',
]);
const STATES = new Set<MembershipState>([
  'invited', 'active', 'suspended', 'expired', 'revoked',
]);

const isRecord = (value: unknown): value is Record<string, unknown> => (
  value !== null && typeof value === 'object' && !Array.isArray(value)
);

const exactKeys = (value: Record<string, unknown>, expected: readonly string[]) => (
  Object.keys(value).length === expected.length
  && Object.keys(value).every((key) => expected.includes(key))
);

const timestamp = (value: unknown): value is string => (
  typeof value === 'string' && value.length <= 64 && !Number.isNaN(Date.parse(value))
);

const parseMembership = (value: unknown): Membership => {
  const keys = [
    'membershipReference', 'state', 'roleId', 'membershipVersion',
    'createdAt', 'updatedAt', 'invitationExpiresAt',
  ] as const;
  if (!isRecord(value) || !exactKeys(value, keys)) throw new LifecycleApiError('degraded', null);
  if (
    typeof value.membershipReference !== 'string'
    || !MEMBERSHIP_REFERENCE.test(value.membershipReference)
    || typeof value.state !== 'string'
    || !STATES.has(value.state as MembershipState)
    || typeof value.roleId !== 'string'
    || !ROLES.has(value.roleId as EnterpriseRole)
    || typeof value.membershipVersion !== 'string'
    || !VERSION.test(value.membershipVersion)
    || !timestamp(value.createdAt)
    || !timestamp(value.updatedAt)
    || (value.invitationExpiresAt !== null && !timestamp(value.invitationExpiresAt))
    || ((value.state === 'invited') !== (value.invitationExpiresAt !== null))
  ) throw new LifecycleApiError('degraded', null);
  return value as unknown as Membership;
};

const parsePage = <T>(
  value: unknown,
  parseItem: (item: unknown) => T,
): { items: readonly T[]; nextCursor: string | null } => {
  if (!isRecord(value) || !exactKeys(value, ['items', 'nextCursor']) || !Array.isArray(value.items)) {
    throw new LifecycleApiError('degraded', null);
  }
  if (
    value.nextCursor !== null
    && (typeof value.nextCursor !== 'string' || !/^cur_[A-Za-z0-9_-]{16,256}$/u.test(value.nextCursor))
  ) throw new LifecycleApiError('degraded', null);
  return Object.freeze({
    items: Object.freeze(value.items.map(parseItem)),
    nextCursor: value.nextCursor as string | null,
  });
};

const parseAuditEvent = (value: unknown): LifecycleAuditEvent => {
  const keys = [
    'eventReference', 'timestamp', 'action', 'decision', 'reasonCode',
    'principalReference', 'correlationReference', 'beforeMembershipVersion',
    'afterMembershipVersion',
  ] as const;
  if (!isRecord(value) || !exactKeys(value, keys)) throw new LifecycleApiError('degraded', null);
  if (
    typeof value.eventReference !== 'string' || !REFERENCE.test(value.eventReference)
    || !timestamp(value.timestamp)
    || typeof value.action !== 'string' || !/^membership\.[a-z_]{3,64}$/u.test(value.action)
    || (value.decision !== 'allow' && value.decision !== 'deny')
    || typeof value.reasonCode !== 'string' || !REASON.test(value.reasonCode)
    || typeof value.principalReference !== 'string' || !REFERENCE.test(value.principalReference)
    || typeof value.correlationReference !== 'string' || !REFERENCE.test(value.correlationReference)
    || typeof value.beforeMembershipVersion !== 'string' || !/^[0-9]+$/u.test(value.beforeMembershipVersion)
    || typeof value.afterMembershipVersion !== 'string' || !/^[0-9]+$/u.test(value.afterMembershipVersion)
  ) throw new LifecycleApiError('degraded', null);
  return value as unknown as LifecycleAuditEvent;
};

const responseCorrelation = (headers: unknown): string | null => {
  if (!isRecord(headers)) return null;
  const getHeader = headers.get;
  const candidate = typeof getHeader === 'function'
    ? getHeader.call(headers, 'x-correlation-id')
    : headers['x-correlation-id'];
  return typeof candidate === 'string' && REFERENCE.test(candidate) ? candidate : null;
};

const classify = (error: unknown): LifecycleApiError => {
  if (error instanceof LifecycleApiError) return error;
  if (!axios.isAxiosError(error)) return new LifecycleApiError('degraded', null);
  const status = error.response?.status;
  const correlation = responseCorrelation(error.response?.headers);
  if (status === 401) return new LifecycleApiError('session_expired', correlation);
  if (status === 403 || status === 404) return new LifecycleApiError('denied', correlation);
  if (status === 409) return new LifecycleApiError('conflict', correlation);
  if (status === 400 || status === 422) return new LifecycleApiError('invalid', correlation);
  if (status === 429) return new LifecycleApiError('rate_limited', correlation);
  return new LifecycleApiError('degraded', correlation);
};

const resultFor = (error: LifecycleApiError): LifecycleUiResult => error.kind;

const request = async <T>(
  operation: LifecycleUiOperation,
  execute: () => Promise<{ data: unknown; headers: unknown }>,
  parse: (value: unknown) => T,
): Promise<T> => {
  try {
    const response = await execute();
    const parsed = parse(response.data);
    recordLifecycleUiEvent({
      operation,
      result: 'success',
      correlationReference: responseCorrelation(response.headers),
    });
    return parsed;
  } catch (error: unknown) {
    const classified = classify(error);
    recordLifecycleUiEvent({
      operation,
      result: resultFor(classified),
      correlationReference: classified.correlationReference,
    });
    throw classified;
  }
};

const idempotencyKey = () => {
  const bytes = new Uint8Array(24);
  globalThis.crypto.getRandomValues(bytes);
  const encoded = btoa(String.fromCharCode(...bytes))
    .replace(/\+/gu, '-').replace(/\//gu, '_').replace(/=+$/gu, '');
  return `idem_${encoded}`;
};

const mutationBody = (input: TransitionInput) => ({
  expected_membership_version: input.expectedMembershipVersion,
  approval_reference: input.approvalReference,
  reason_code: input.reasonCode,
  replacement_membership_reference: input.replacementMembershipReference ?? null,
});

const parseOutcome = (value: unknown) => {
  if (
    !isRecord(value)
    || !exactKeys(value, ['status', 'operationReference'])
    || value.status !== 'completed'
    || typeof value.operationReference !== 'string'
    || !/^op_[0-9a-f]{32}$/u.test(value.operationReference)
  ) throw new LifecycleApiError('degraded', null);
  return Object.freeze({ status: 'completed' as const, operationReference: value.operationReference });
};

export const readRoleCatalog = () => request(
  'roles.read',
  async () => getApiClient().get('/api/v1/admin/roles'),
  (value) => {
    if (!isRecord(value) || !exactKeys(value, ['schemaVersion', 'roles'])
      || value.schemaVersion !== 'enterprise-roles.v1' || !Array.isArray(value.roles)
      || value.roles.length === 0 || value.roles.some((role) => typeof role !== 'string' || !ROLES.has(role as EnterpriseRole))) {
      throw new LifecycleApiError('degraded', null);
    }
    return Object.freeze([...(value.roles as EnterpriseRole[])]);
  },
);

export const listMemberships = (state: MembershipState | null) => request(
  'memberships.list',
  async () => getApiClient().get('/api/v1/admin/memberships', {
    params: { limit: 50, ...(state === null ? {} : { state }) },
  }),
  (value) => parsePage(value, parseMembership),
);

export const listLifecycleAuditEvents = () => request(
  'audit.read',
  async () => getApiClient().get('/api/v1/admin/audit-events', { params: { limit: 50 } }),
  (value) => parsePage(value, parseAuditEvent),
);

const post = <T>(operation: LifecycleUiOperation, path: string, body: unknown) => request(
  operation,
  async () => getApiClient().post(path, body, { headers: { 'Idempotency-Key': idempotencyKey() } }),
  parseOutcome,
) as Promise<T>;

export const inviteUser = (input: InvitationInput) => post(
  'invitations.create', '/api/v1/admin/invitations', {
    principal_locator: input.principalLocator,
    role_id: input.roleId,
    expires_in_seconds: input.expiresInSeconds,
    approval_reference: input.approvalReference,
  },
);

export const resendInvitation = (reference: string, input: InvitationResendInput) => post(
  'invitations.resend', `/api/v1/admin/memberships/${reference}/invitation-resends`, {
    ...mutationBody(input), expires_in_seconds: input.expiresInSeconds,
  },
);

const transition = (
  operation: LifecycleUiOperation,
  reference: string,
  suffix: string,
  input: TransitionInput | RoleChangeInput,
) => post(operation, `/api/v1/admin/memberships/${reference}/${suffix}`, {
  ...mutationBody(input),
  ...('roleId' in input ? { role_id: input.roleId } : {}),
});

export const activateMembership = (reference: string, input: TransitionInput) => transition('membership.activate', reference, 'activations', input);
export const changeMembershipRole = (reference: string, input: RoleChangeInput) => transition('membership.change_role', reference, 'role-changes', input);
export const suspendMembership = (reference: string, input: TransitionInput) => transition('membership.suspend', reference, 'suspensions', input);
export const reactivateMembership = (reference: string, input: TransitionInput) => transition('membership.reactivate', reference, 'reactivations', input);
export const revokeMembership = (reference: string, input: TransitionInput) => transition('membership.revoke', reference, 'revocations', input);
export const revokeMembershipSessions = (reference: string, input: TransitionInput) => transition('sessions.revoke', reference, 'session-revocations', input);
