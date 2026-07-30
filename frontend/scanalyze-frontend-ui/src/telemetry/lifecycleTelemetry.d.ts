export type LifecycleUiOperation =
  | 'roles.read' | 'memberships.list' | 'invitations.create' | 'invitations.resend'
  | 'membership.activate' | 'membership.change_role' | 'membership.suspend'
  | 'membership.reactivate' | 'membership.revoke' | 'sessions.revoke' | 'audit.read';
export type LifecycleUiResult =
  | 'success' | 'denied' | 'conflict' | 'invalid' | 'session_expired'
  | 'degraded' | 'rate_limited';
export interface LifecycleUiEvent {
  readonly schemaVersion: 'lifecycle-ui-event.v1';
  readonly operation: LifecycleUiOperation;
  readonly result: LifecycleUiResult;
  readonly correlationReference: string | null;
  readonly timestamp: string;
}
export function recordLifecycleUiEvent(input: {
  operation: LifecycleUiOperation;
  result: LifecycleUiResult;
  correlationReference?: string | null;
  now?: () => string;
}): LifecycleUiEvent;
export function lifecycleTelemetrySnapshot(): LifecycleUiEvent[];
export function clearLifecycleTelemetryForTest(): void;
