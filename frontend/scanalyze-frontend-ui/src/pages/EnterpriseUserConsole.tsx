import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useAuth } from 'react-oidc-context';
import { getConfig } from '../config';
import { resolveEnterpriseUxAuthorizationFromSession } from '../security/enterpriseUxAuthorization.js';
import {
  activateMembership,
  changeMembershipRole,
  inviteUser,
  LifecycleApiError,
  listLifecycleAuditEvents,
  listMemberships,
  readRoleCatalog,
  reactivateMembership,
  resendInvitation,
  revokeMembership,
  revokeMembershipSessions,
  suspendMembership,
  type EnterpriseRole,
  type LifecycleAuditEvent,
  type Membership,
  type MembershipState,
  type TransitionInput,
} from '../api/userLifecycleApi';

type Action =
  | 'activate' | 'change_role' | 'resend' | 'suspend'
  | 'reactivate' | 'revoke' | 'revoke_sessions';

const ACTION_LABEL: Record<Action, string> = {
  activate: 'activación',
  change_role: 'cambio de rol',
  resend: 'reenvío de invitación',
  suspend: 'suspensión',
  reactivate: 'reactivación',
  revoke: 'revocación',
  revoke_sessions: 'revocación de sesiones',
};

const ROLE_LABEL: Record<EnterpriseRole, string> = {
  auditor: 'Auditor',
  customer_admin: 'Administrador de cliente',
  document_operator: 'Operador de documentos',
  document_reviewer: 'Revisor de documentos',
};

const errorMessage = (error: unknown) => {
  if (!(error instanceof LifecycleApiError)) return 'El servicio no está disponible temporalmente.';
  const messages = {
    denied: 'La operación no está disponible para esta sesión.',
    conflict: 'La membresía cambió; actualiza e intenta nuevamente.',
    invalid: 'Revisa los datos de la solicitud.',
    session_expired: 'La sesión expiró. Inicia sesión nuevamente.',
    rate_limited: 'Hay demasiadas solicitudes. Espera e intenta nuevamente.',
    degraded: 'El servicio no está disponible temporalmente.',
  } as const;
  return `${messages[error.kind]}${error.correlationReference ? ` Referencia: ${error.correlationReference}` : ''}`;
};

const StateBadge: React.FC<{ state: MembershipState }> = ({ state }) => (
  <span className="inline-flex rounded-full border border-slate-700 bg-slate-800 px-2 py-1 text-xs font-medium text-slate-200">
    {state}
  </span>
);

export const EnterpriseUserConsole: React.FC = () => {
  const auth = useAuth();
  const config = getConfig();
  const capabilities = useMemo(() => {
    if (config.features.user_administration !== true) return null;
    try {
      return resolveEnterpriseUxAuthorizationFromSession(auth.user, config);
    } catch {
      return null;
    }
  }, [auth.user, config]);
  const canManage = capabilities?.canManageUsers === true;
  const canAudit = capabilities?.canReadAudit === true;

  const [memberships, setMemberships] = useState<readonly Membership[]>([]);
  const [auditEvents, setAuditEvents] = useState<readonly LifecycleAuditEvent[]>([]);
  const [roles, setRoles] = useState<readonly EnterpriseRole[]>([]);
  const [stateFilter, setStateFilter] = useState<MembershipState | ''>('');
  const [membershipsState, setMembershipsState] = useState<'idle' | 'loading' | 'ready' | 'failed'>('idle');
  const [auditState, setAuditState] = useState<'idle' | 'loading' | 'ready' | 'failed'>('idle');
  const [feedback, setFeedback] = useState('');
  const [selected, setSelected] = useState<{ member: Membership; action: Action } | null>(null);
  const [showInvite, setShowInvite] = useState(false);

  const loadMembershipData = async (filter: MembershipState | '') => {
    if (!canManage) return;
    setMembershipsState('loading');
    setFeedback('');
    try {
      const [catalog, page] = await Promise.all([
        roles.length > 0 ? Promise.resolve(roles) : readRoleCatalog(),
        listMemberships(filter || null),
      ]);
      setRoles(catalog);
      setMemberships(page.items);
      setMembershipsState('ready');
    } catch (error: unknown) {
      setMemberships([]);
      setMembershipsState('failed');
      setFeedback(errorMessage(error));
    }
  };

  const loadAuditData = async () => {
    if (!canAudit) return;
    setAuditState('loading');
    try {
      const page = await listLifecycleAuditEvents();
      setAuditEvents(page.items);
      setAuditState('ready');
    } catch (error: unknown) {
      setAuditEvents([]);
      setAuditState('failed');
      setFeedback(errorMessage(error));
    }
  };

  useEffect(() => {
    if (canManage) void loadMembershipData(stateFilter);
    if (canAudit) void loadAuditData();
    // Capability changes are tied to a new access token. Filter changes are handled explicitly.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [canManage, canAudit]);

  const onFilter = (value: MembershipState | '') => {
    setStateFilter(value);
    void loadMembershipData(value);
  };

  const refresh = async () => {
    await Promise.all([
      canManage ? loadMembershipData(stateFilter) : Promise.resolve(),
      canAudit ? loadAuditData() : Promise.resolve(),
    ]);
  };

  if (!canManage && !canAudit) {
    return (
      <section className="mx-auto w-full max-w-2xl rounded-2xl border border-amber-500/30 bg-slate-900 p-8 text-left">
        <h1 className="mb-3 text-2xl">Acceso no disponible</h1>
        <p className="m-0 text-slate-400">
          Esta sesión no tiene una membresía activa y vinculada a este despliegue para usar la consola.
        </p>
      </section>
    );
  }

  return (
    <div className="flex w-full flex-col gap-8 text-left">
      {feedback && (
        <div role="alert" className="rounded-xl border border-amber-500/40 bg-amber-950/30 p-4 text-amber-100">
          {feedback}
        </div>
      )}

      {canManage && (
        <section aria-labelledby="user-admin-heading" className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-xl">
          <div className="mb-6 flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
            <div>
              <h1 id="user-admin-heading" className="m-0 text-2xl">Administración de usuarios</h1>
              <p className="mb-0 mt-2 text-sm text-slate-400">Las referencias son opacas; la API vuelve a autorizar cada operación.</p>
            </div>
            <button className="btn btn-primary" onClick={() => setShowInvite(true)}>Invitar usuario</button>
          </div>

          <div className="mb-4 flex flex-wrap items-end gap-4">
            <label className="flex flex-col gap-2 text-sm text-slate-300">
              Filtrar por estado
              <select
                className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2"
                value={stateFilter}
                onChange={(event) => onFilter(event.target.value as MembershipState | '')}
              >
                <option value="">Todos</option>
                <option value="invited">Invitados</option>
                <option value="active">Activos</option>
                <option value="suspended">Suspendidos</option>
                <option value="expired">Expirados</option>
                <option value="revoked">Revocados</option>
              </select>
            </label>
            <button className="btn btn-outline" onClick={() => void refresh()}>Actualizar</button>
          </div>

          {membershipsState === 'loading' && <p role="status">Cargando membresías…</p>}
          {membershipsState === 'failed' && <p className="text-slate-400">No fue posible cargar la lista.</p>}
          {membershipsState === 'ready' && memberships.length === 0 && <p className="text-slate-400">No hay membresías para este filtro.</p>}
          {memberships.length > 0 && (
            <div className="overflow-x-auto">
              <table aria-label="Membresías enterprise" className="w-full border-collapse text-sm">
                <thead>
                  <tr className="border-b border-slate-700 text-slate-400">
                    <th className="px-3 py-3 text-left">Referencia</th>
                    <th className="px-3 py-3 text-left">Estado</th>
                    <th className="px-3 py-3 text-left">Rol</th>
                    <th className="px-3 py-3 text-left">Versión</th>
                    <th className="px-3 py-3 text-left">Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  {memberships.map((member) => (
                    <tr key={member.membershipReference} className="border-b border-slate-800 align-top">
                      <td className="px-3 py-4 font-mono text-xs">{member.membershipReference}</td>
                      <td className="px-3 py-4"><StateBadge state={member.state} /></td>
                      <td className="px-3 py-4">{ROLE_LABEL[member.roleId]}</td>
                      <td className="px-3 py-4">{member.membershipVersion}</td>
                      <td className="px-3 py-4">
                        <div className="flex flex-wrap gap-2">
                          {member.state === 'invited' && <ActionButton label="Reenviar invitación" onClick={() => setSelected({ member, action: 'resend' })} />}
                          {member.state === 'invited' && <ActionButton label="Activar" onClick={() => setSelected({ member, action: 'activate' })} />}
                          {member.state === 'active' && <ActionButton label="Cambiar rol" onClick={() => setSelected({ member, action: 'change_role' })} />}
                          {member.state === 'active' && <ActionButton label="Suspender" onClick={() => setSelected({ member, action: 'suspend' })} />}
                          {member.state === 'suspended' && <ActionButton label="Reactivar" onClick={() => setSelected({ member, action: 'reactivate' })} />}
                          {(member.state === 'active' || member.state === 'suspended') && <ActionButton label="Revocar sesiones" onClick={() => setSelected({ member, action: 'revoke_sessions' })} />}
                          {member.state === 'active' && <ActionButton label="Revocar membresía" danger onClick={() => setSelected({ member, action: 'revoke' })} />}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {canAudit && (
        <section aria-labelledby="audit-heading" className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-xl">
          <h2 id="audit-heading" className="m-0 text-xl">Auditoría de lifecycle</h2>
          <p className="mt-2 text-sm text-slate-400">Evidencia sanitaria y vinculada al despliegue; no contiene identidad ni payloads.</p>
          {auditState === 'loading' && <p role="status">Cargando auditoría…</p>}
          {auditState === 'failed' && <p className="text-slate-400">La auditoría está temporalmente degradada.</p>}
          {auditState === 'ready' && auditEvents.length === 0 && <p className="text-slate-400">No hay eventos recientes.</p>}
          {auditEvents.length > 0 && (
            <ul className="m-0 grid list-none gap-3 p-0">
              {auditEvents.map((event) => (
                <li key={event.eventReference} className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                  <div className="flex flex-wrap justify-between gap-2">
                    <strong>{event.action}</strong>
                    <time dateTime={event.timestamp}>{new Date(event.timestamp).toLocaleString()}</time>
                  </div>
                  <p className="mb-0 mt-2 font-mono text-xs text-slate-400">{event.correlationReference}</p>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      {selected && (
        <ActionDialog
          member={selected.member}
          action={selected.action}
          roles={roles}
          onClose={() => setSelected(null)}
          onComplete={async () => {
            setSelected(null);
            setFeedback('Operación completada.');
            await refresh();
          }}
          onError={(error) => setFeedback(errorMessage(error))}
        />
      )}
      {showInvite && (
        <InviteDialog
          roles={roles}
          onClose={() => setShowInvite(false)}
          onComplete={async () => {
            setShowInvite(false);
            setFeedback('Invitación creada.');
            await refresh();
          }}
          onError={(error) => setFeedback(errorMessage(error))}
        />
      )}
    </div>
  );
};

const ActionButton: React.FC<{ label: string; onClick: () => void; danger?: boolean }> = ({ label, onClick, danger = false }) => (
  <button className={`btn ${danger ? 'btn-danger' : 'btn-outline'} px-3 py-1 text-xs`} onClick={onClick}>{label}</button>
);

interface DialogCallbacks {
  readonly onClose: () => void;
  readonly onComplete: () => Promise<void>;
  readonly onError: (error: unknown) => void;
}

const ActionDialog: React.FC<DialogCallbacks & {
  member: Membership;
  action: Action;
  roles: readonly EnterpriseRole[];
}> = ({ member, action, roles, onClose, onComplete, onError }) => {
  const closeButton = useRef<HTMLButtonElement>(null);
  const [approval, setApproval] = useState('');
  const [reason, setReason] = useState('');
  const [replacement, setReplacement] = useState('');
  const [role, setRole] = useState<EnterpriseRole>(roles[0] ?? 'document_operator');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    closeButton.current?.focus();
    const escape = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose(); };
    window.addEventListener('keydown', escape);
    return () => window.removeEventListener('keydown', escape);
  }, [onClose]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    const input: TransitionInput = {
      expectedMembershipVersion: Number(member.membershipVersion),
      approvalReference: approval,
      reasonCode: reason,
      replacementMembershipReference: replacement || null,
    };
    try {
      if (action === 'activate') await activateMembership(member.membershipReference, input);
      if (action === 'change_role') await changeMembershipRole(member.membershipReference, { ...input, roleId: role });
      if (action === 'resend') await resendInvitation(member.membershipReference, { ...input, expiresInSeconds: 3600 });
      if (action === 'suspend') await suspendMembership(member.membershipReference, input);
      if (action === 'reactivate') await reactivateMembership(member.membershipReference, input);
      if (action === 'revoke') await revokeMembership(member.membershipReference, input);
      if (action === 'revoke_sessions') await revokeMembershipSessions(member.membershipReference, input);
      await onComplete();
    } catch (error: unknown) {
      onError(error);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4">
      <section role="dialog" aria-modal="true" aria-label={`Confirmar ${ACTION_LABEL[action]}`} className="w-full max-w-lg rounded-2xl border border-slate-700 bg-slate-900 p-6 shadow-2xl">
        <h2 className="mt-0">Confirmar {ACTION_LABEL[action]}</h2>
        <p className="break-all font-mono text-xs text-slate-400">{member.membershipReference}</p>
        <form className="grid gap-4" onSubmit={(event) => void submit(event)}>
          <label className="grid gap-2">Referencia de aprobación
            <input required pattern="apr_[A-Za-z0-9][A-Za-z0-9_-]{15,63}" className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2" value={approval} onChange={(event) => setApproval(event.target.value)} />
          </label>
          <label className="grid gap-2">Código de motivo
            <input required pattern="[a-z][a-z0-9_]{2,63}" className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2" value={reason} onChange={(event) => setReason(event.target.value)} />
          </label>
          {action === 'change_role' && (
            <label className="grid gap-2">Nuevo rol
              <select className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2" value={role} onChange={(event) => setRole(event.target.value as EnterpriseRole)}>
                {roles.map((item) => <option key={item} value={item}>{ROLE_LABEL[item]}</option>)}
              </select>
            </label>
          )}
          {(action === 'suspend' || action === 'revoke' || action === 'change_role') && (
            <label className="grid gap-2">Membresía administradora de reemplazo (si aplica)
              <input className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2" value={replacement} onChange={(event) => setReplacement(event.target.value)} />
            </label>
          )}
          <div className="flex justify-end gap-3">
            <button ref={closeButton} type="button" className="btn btn-outline" onClick={onClose}>Cancelar</button>
            <button type="submit" className="btn btn-primary" disabled={busy}>{busy ? 'Procesando…' : 'Confirmar acción'}</button>
          </div>
        </form>
      </section>
    </div>
  );
};

const InviteDialog: React.FC<DialogCallbacks & { roles: readonly EnterpriseRole[] }> = ({ roles, onClose, onComplete, onError }) => {
  const closeButton = useRef<HTMLButtonElement>(null);
  const [locator, setLocator] = useState('');
  const [approval, setApproval] = useState('');
  const [role, setRole] = useState<EnterpriseRole>(roles[0] ?? 'document_operator');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    closeButton.current?.focus();
    const escape = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose(); };
    window.addEventListener('keydown', escape);
    return () => window.removeEventListener('keydown', escape);
  }, [onClose]);
  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    try {
      await inviteUser({ principalLocator: locator, roleId: role, expiresInSeconds: 3600, approvalReference: approval });
      await onComplete();
    } catch (error: unknown) {
      onError(error);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4">
      <section role="dialog" aria-modal="true" aria-label="Invitar usuario" className="w-full max-w-lg rounded-2xl border border-slate-700 bg-slate-900 p-6 shadow-2xl">
        <h2 className="mt-0">Invitar usuario</h2>
        <form className="grid gap-4" onSubmit={(event) => void submit(event)}>
          <label className="grid gap-2">Correo corporativo
            <input required type="email" autoComplete="off" className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2" value={locator} onChange={(event) => setLocator(event.target.value)} />
          </label>
          <label className="grid gap-2">Rol
            <select className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2" value={role} onChange={(event) => setRole(event.target.value as EnterpriseRole)}>
              {roles.map((item) => <option key={item} value={item}>{ROLE_LABEL[item]}</option>)}
            </select>
          </label>
          <label className="grid gap-2">Referencia de aprobación
            <input required pattern="apr_[A-Za-z0-9][A-Za-z0-9_-]{15,63}" className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2" value={approval} onChange={(event) => setApproval(event.target.value)} />
          </label>
          <div className="flex justify-end gap-3">
            <button ref={closeButton} type="button" className="btn btn-outline" onClick={onClose}>Cancelar</button>
            <button type="submit" className="btn btn-primary" disabled={busy}>{busy ? 'Procesando…' : 'Crear invitación'}</button>
          </div>
        </form>
      </section>
    </div>
  );
};
