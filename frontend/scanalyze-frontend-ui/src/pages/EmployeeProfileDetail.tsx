import React, { useEffect, useState, useMemo } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { createEmployeeProfilesApi, type ProfileDetail } from '../api/employeeProfilesApi';
import { useAddonsRegistry } from '../hooks/useAddonsRegistry';

export const EmployeeProfileDetail: React.FC = () => {
  const { profileId } = useParams<{ profileId: string }>();
  const [searchParams] = useSearchParams();
  const batchId = searchParams.get('batchId') || '';

  // Registry-aware API
  const { getApiBasePath } = useAddonsRegistry();
  const epApi = useMemo(
    () => createEmployeeProfilesApi(getApiBasePath('employee-profiles')),
    [getApiBasePath],
  );

  const [profile, setProfile] = useState<ProfileDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showRawJson, setShowRawJson] = useState(false);
  const [exportingJson, setExportingJson] = useState(false);

  useEffect(() => {
    const fetchProfile = async () => {
      if (!profileId || !batchId) return;
      try {
        setLoading(true);
        const data = await epApi.getProfile(profileId, batchId);
        setProfile(data);
      } catch {
        setError('Error al cargar la ficha');
      } finally {
        setLoading(false);
      }
    };
    fetchProfile();
  }, [profileId, batchId, epApi]);

  const handleExportJson = async () => {
    if (!profileId || !batchId) return;
    setExportingJson(true);
    try {
      await epApi.exportJson(profileId, batchId);
    } catch {
      setError('No fue posible exportar la ficha.');
    }
    setExportingJson(false);
  };

  const statusColor = (status: string) => {
    switch (status) {
      case 'COMPLETE': return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/20';
      case 'PARTIAL': return 'bg-amber-500/20 text-amber-400 border-amber-500/20';
      case 'NEEDS_REVIEW': return 'bg-red-500/20 text-red-400 border-red-500/20';
      default: return 'bg-slate-600/20 text-slate-400 border-slate-600/20';
    }
  };

  const severityColor = (sev: string) => {
    switch (sev) {
      case 'ERROR': return 'text-red-400';
      case 'WARN': return 'text-amber-400';
      default: return 'text-blue-400';
    }
  };

  const checklistIcon = (status: string) => {
    switch (status) {
      case 'FOUND':
        return <svg className="w-4 h-4 text-emerald-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>;
      case 'FOUND_VIA_SIGNAL':
        return <svg className="w-4 h-4 text-cyan-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /><circle cx="18" cy="6" r="3" fill="currentColor" /></svg>;
      case 'NEEDS_REVIEW':
        return <svg className="w-4 h-4 text-amber-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" /></svg>;
      case 'CONFLICT':
        return <svg className="w-4 h-4 text-red-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>;
      case 'COMPOSITE_REVIEW_REQUIRED':
        return <svg className="w-4 h-4 text-purple-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>;
      case 'MISSING':
      default:
        return <svg className="w-4 h-4 text-slate-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>;
    }
  };

  const checklistColor = (status: string) => {
    switch (status) {
      case 'FOUND': return 'border-emerald-500/30 bg-emerald-500/5 text-emerald-300';
      case 'FOUND_VIA_SIGNAL': return 'border-cyan-500/30 bg-cyan-500/5 text-cyan-300';
      case 'NEEDS_REVIEW': return 'border-amber-500/30 bg-amber-500/5 text-amber-300';
      case 'CONFLICT': return 'border-red-500/30 bg-red-500/5 text-red-300';
      case 'COMPOSITE_REVIEW_REQUIRED': return 'border-purple-500/30 bg-purple-500/5 text-purple-300';
      default: return 'border-slate-700/50 bg-slate-800/30 text-slate-500';
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center p-20 gap-4 glass-card">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-amber-500" />
        <p className="text-slate-400">Cargando ficha de trabajador...</p>
      </div>
    );
  }

  if (error || !profile) {
    return (
      <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-6 text-center">
        <p className="text-red-400 mb-2 font-semibold">Error cargando ficha</p>
        <p className="text-slate-400 text-sm">{error}</p>
        <Link to={`/employee-profiles?batchId=${batchId}`} className="text-amber-400 hover:underline text-sm mt-4 inline-block">← Volver al listado</Link>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-8 w-full animate-fade-in">
      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between md:items-end gap-4">
        <div className="flex flex-col gap-2">
          <div className="flex gap-2 items-center">
            <Link to={`/employee-profiles?batchId=${batchId}`} className="text-slate-400 hover:text-amber-400 transition-colors">
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" /></svg>
            </Link>
            <h2 className="text-3xl font-bold m-0 text-slate-50">{profile.fullName || 'Ficha sin nombre'}</h2>
          </div>
          <div className="flex items-center gap-3">
            <span className={`px-3 py-1 text-xs rounded-full border ${statusColor(profile.status)}`}>{profile.status}</span>
            <span className="text-slate-500 text-xs">Completitud: {Math.round(profile.completenessScore * 100)}%</span>
            <span className="text-slate-600 text-xs font-mono">{profile.profileId.substring(0, 12)}...</span>
          </div>
        </div>

        <div className="flex gap-2">
          <button
            onClick={handleExportJson}
            disabled={exportingJson}
            className="btn-outline text-xs px-3 py-2 border-amber-500/50 text-amber-400 hover:bg-amber-500/10 flex items-center gap-2 disabled:opacity-40"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" /></svg>
            {exportingJson ? 'Exportando...' : 'Export JSON'}
          </button>
          <button
            onClick={() => profileId && epApi.exportCsvIndividual(profileId, batchId)}
            className="btn-outline text-xs px-3 py-2 border-amber-500/50 text-amber-400 hover:bg-amber-500/10 flex items-center gap-2"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" /></svg>
            Export CSV
          </button>
        </div>
      </div>

      {/* ── Composite Review Banner ── */}
      {profile.requiresComponentReview && (
        <div className="bg-purple-500/10 border border-purple-500/30 rounded-xl p-4 flex items-start gap-3">
          <svg className="w-6 h-6 text-purple-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>
          <div>
            <p className="text-purple-300 font-semibold text-sm m-0">PDF Compuesto Detectado</p>
            <p className="text-purple-400/80 text-xs mt-1 m-0">
              Este perfil contiene documentos multi-página con múltiples tipos de documento detectados.
              Los datos extraídos pueden corresponder a distintas personas. Revisa los componentes detectados abajo.
            </p>
          </div>
        </div>
      )}

      {/* Info Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Personal Info */}
        <div className="glass-card p-6">
          <h3 className="text-lg font-semibold text-slate-100 mb-4 flex items-center gap-2">
            <svg className="w-5 h-5 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>
            Información Personal
          </h3>
          <dl className="flex flex-col gap-3">
            <InfoRow label="Nombre completo" value={profile.fullName} />
            <InfoRow label="Nombres" value={profile.firstNames} />
            <InfoRow label="Apellidos" value={profile.lastNames} />
            <InfoRow label="Fecha de nacimiento" value={profile.birthDate} />
            <InfoRow label="Sexo" value={profile.sex} />
            <InfoRow label="Nacionalidad" value={profile.nationality} />
            {profile.phone && <InfoRow label="Teléfono" value={profile.maskedIdentifiers?.phone || '•••••'} mono />}
            {profile.email && <InfoRow label="Email" value={profile.maskedIdentifiers?.email || '•••••'} mono />}
          </dl>
        </div>

        {/* Identifiers — masked by default (no PII) */}
        <div className="glass-card p-6">
          <h3 className="text-lg font-semibold text-slate-100 mb-4 flex items-center gap-2">
            <svg className="w-5 h-5 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V8a2 2 0 00-2-2h-5m-4 0V5a2 2 0 114 0v1m-4 0a2 2 0 104 0m-5 8a2 2 0 100-4 2 2 0 000 4zm0 0c1.306 0 2.417.835 2.83 2M9 14a3.001 3.001 0 00-2.83 2M15 11h3m-3 4h2" /></svg>
            Identificadores
            <span className="text-xs text-slate-500 font-normal ml-auto">enmascarados</span>
          </h3>
          <dl className="flex flex-col gap-3">
            <InfoRow label="CURP" value={profile.maskedIdentifiers?.curp} mono />
            <InfoRow label="RFC" value={profile.maskedIdentifiers?.rfc} mono />
            <InfoRow label="RFC Empleador" value={profile.maskedIdentifiers?.employerRfc} mono />
            <InfoRow label="Clave de Elector" value={profile.maskedIdentifiers?.claveElector} mono />
            <InfoRow label="NSS" value={profile.maskedIdentifiers?.nss} mono />
            <InfoRow label="CLABE" value={profile.maskedIdentifiers?.clabe} mono />
            <InfoRow label="CIC" value={profile.maskedIdentifiers?.cic} mono />
          </dl>
        </div>

        {/* Address */}
        {profile.address && (
          <div className="glass-card p-6">
            <h3 className="text-lg font-semibold text-slate-100 mb-4 flex items-center gap-2">
              <svg className="w-5 h-5 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 11a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
              Dirección
            </h3>
            <p className="text-slate-300 text-sm leading-relaxed">{profile.address}</p>
          </div>
        )}

        {/* Source Documents */}
        <div className="glass-card p-6">
          <h3 className="text-lg font-semibold text-slate-100 mb-4 flex items-center gap-2">
            <svg className="w-5 h-5 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
            Documentos Fuente ({profile.sourceDocuments?.length || 0})
          </h3>
          {profile.sourceDocuments?.length ? (
            <div className="flex flex-col gap-2">
              {profile.sourceDocuments.map((sd, i) => (
                <div key={i} className="flex items-center justify-between p-3 bg-slate-950/50 rounded-lg border border-slate-800/50">
                  <div>
                    <span className="text-slate-200 text-sm font-mono">{sd.documentId.substring(0, 12)}...</span>
                    <span className="text-slate-500 text-xs ml-2">{sd.documentType}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-500">{sd.usedFields?.length || 0} campos</span>
                    <Link to={`/document/${sd.documentId}`} className="text-indigo-400 hover:text-indigo-300 text-xs underline">Ver</Link>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-slate-500 text-sm">Sin documentos fuente</p>
          )}
        </div>
      </div>

      {/* Document Checklist — expanded with all statuses */}
      {profile.documentChecklist && Object.keys(profile.documentChecklist).length > 0 && (
        <div className="glass-card p-6">
          <h3 className="text-lg font-semibold text-slate-100 mb-4 flex items-center gap-2">
            <svg className="w-5 h-5 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" /></svg>
            Checklist de Documentos
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
            {Object.entries(profile.documentChecklist).map(([docType, status]) => (
              <div key={docType} className={`flex items-center gap-2 p-2.5 rounded-lg border ${checklistColor(status)}`}>
                {checklistIcon(status)}
                <div className="flex flex-col min-w-0">
                  <span className="text-xs font-medium truncate">{docType.replace(/_/g, ' ')}</span>
                  <span className="text-[10px] opacity-60">{status.replace(/_/g, ' ')}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Merge Evidence */}
      {profile.mergeEvidence && profile.mergeEvidence.length > 0 && (
        <div className="glass-card p-6">
          <h3 className="text-lg font-semibold text-slate-100 mb-4 flex items-center gap-2">
            <svg className="w-5 h-5 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" /></svg>
            Evidencia de Merge ({profile.mergeEvidence.length})
          </h3>
          <div className="flex flex-col gap-2">
            {profile.mergeEvidence.map((ev, i) => (
              <div key={i} className="flex items-center gap-3 p-3 bg-slate-950/50 rounded-lg border border-slate-800/50">
                <span className="text-xs text-emerald-400 font-mono">{ev.type}</span>
                <span className="text-xs text-slate-400">{ev.documents?.length || 0} documentos</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Document Components */}
      {profile.documentComponents && profile.documentComponents.length > 0 && (
        <div className="glass-card p-6">
          <h3 className="text-lg font-semibold text-slate-100 mb-4 flex items-center gap-2">
            <svg className="w-5 h-5 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>
            Componentes Detectados (OCR) ({profile.documentComponents.length})
          </h3>
          <p className="text-slate-500 text-xs mb-3">Documentos lógicos detectados dentro de PDFs multi-página mediante análisis OCR.</p>
          <div className="flex flex-col gap-2">
            {profile.documentComponents.map((comp, i: number) => (
              <div key={i} className="flex items-center justify-between p-3 bg-slate-950/50 rounded-lg border border-slate-800/50">
                <div className="flex items-center gap-3">
                  <span className="text-xs text-slate-500 font-mono w-12">p.{comp.pageStart}</span>
                  <span className="text-slate-200 text-sm">{comp.detectedType?.replace(/_/g, ' ')}</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all ${comp.confidence >= 0.8 ? 'bg-emerald-500' : comp.confidence >= 0.5 ? 'bg-amber-500' : 'bg-red-500'}`}
                      style={{ width: `${Math.round(comp.confidence * 100)}%` }}
                    />
                  </div>
                  <span className="text-xs text-slate-500 w-10 text-right">{Math.round(comp.confidence * 100)}%</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Warnings */}
      {profile.warnings && profile.warnings.length > 0 && (
        <div className="glass-card p-6">
          <h3 className="text-lg font-semibold text-slate-100 mb-4 flex items-center gap-2">
            <svg className="w-5 h-5 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" /></svg>
            Advertencias ({profile.warnings.length})
          </h3>
          <div className="flex flex-col gap-2">
            {profile.warnings.map((w, i) => (
              <div key={i} className="flex items-start gap-3 p-3 bg-slate-950/50 rounded-lg border border-slate-800/50">
                <span className={`text-xs font-semibold ${severityColor(w.severity)} mt-0.5`}>{w.severity}</span>
                <div>
                  <span className="text-slate-200 text-sm font-mono">{w.code}</span>
                  <p className="text-slate-400 text-xs mt-1 m-0">{w.message}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Missing Fields */}
      {profile.missingFields && profile.missingFields.length > 0 && (
        <div className="glass-card p-6">
          <h3 className="text-lg font-semibold text-slate-100 mb-4">Campos Faltantes</h3>
          <div className="flex flex-wrap gap-2">
            {profile.missingFields.map((f) => (
              <span key={f} className="bg-slate-800 text-slate-400 px-3 py-1 rounded-full text-xs border border-slate-700">{f}</span>
            ))}
          </div>
        </div>
      )}

      {/* Raw JSON */}
      <div className="glass-card p-6">
        <button
          onClick={() => setShowRawJson(!showRawJson)}
          className="flex items-center gap-2 text-slate-400 hover:text-slate-200 transition-colors text-sm font-semibold"
        >
          <svg className={`w-4 h-4 transition-transform ${showRawJson ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
          JSON Raw {showRawJson ? '(ocultar)' : '(mostrar)'}
        </button>
        {showRawJson && (
          <pre className="mt-4 bg-slate-950 p-4 rounded-lg text-xs text-slate-300 overflow-x-auto max-h-96 border border-slate-800">
            {JSON.stringify(profile, null, 2)}
          </pre>
        )}
      </div>

      {/* Metadata */}
      <div className="glass-card p-6">
        <h3 className="text-sm font-semibold text-slate-500 mb-3 uppercase tracking-wider">Metadata de Generación</h3>
        <div className="flex flex-wrap gap-6 text-xs text-slate-400">
          <span>Generado: {profile.generatedAt ? new Date(profile.generatedAt).toLocaleString() : '—'}</span>
          <span>Por: {profile.generatedBy || '—'}</span>
          <span>Batch: <Link to={`/batch/${profile.batchId}`} className="text-indigo-400 hover:underline">{profile.batchId.substring(0, 12)}...</Link></span>
        </div>
      </div>
    </div>
  );
};

// Reusable info row component
const InfoRow: React.FC<{ label: string; value?: string | null; mono?: boolean }> = ({ label, value, mono }) => (
  <div className="flex justify-between items-center">
    <dt className="text-slate-500 text-sm">{label}</dt>
    <dd className={`text-slate-200 text-sm m-0 ${mono ? 'font-mono' : ''}`}>{value || <span className="text-slate-600">—</span>}</dd>
  </div>
);
