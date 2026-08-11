import React, { useEffect, useState, useMemo, useCallback } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { createEmployeeProfilesApi, type ProfileListItem } from '../api/employeeProfilesApi';
import { useAddonsRegistry } from '../hooks/useAddonsRegistry';

export const EmployeeProfiles: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const batchId = searchParams.get('batchId') || '';
  const [batchInput, setBatchInput] = useState(batchId);
  const [statusFilter, setStatusFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [profiles, setProfiles] = useState<ProfileListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);

  // Registry-aware API
  const { getApiBasePath } = useAddonsRegistry();
  const epApi = useMemo(
    () => createEmployeeProfilesApi(getApiBasePath('employee-profiles')),
    [getApiBasePath],
  );

  const fetchProfiles = useCallback(async (bid?: string) => {
    const batch = bid || batchInput;
    if (!batch) return;
    setLoading(true);
    setError(null);
    try {
      const resp = await epApi.listProfiles({
        batchId: batch,
        status: statusFilter || undefined,
        q: searchQuery || undefined,
        limit: 100,
      });
      setProfiles(resp.profiles);
      setTotal(resp.total);
    } catch {
      setError('Error al cargar fichas');
      setProfiles([]);
    }
    setLoading(false);
  }, [batchInput, statusFilter, searchQuery, epApi]);

  useEffect(() => {
    if (batchId) {
      const timeout = window.setTimeout(() => {
        setBatchInput(batchId);
        void fetchProfiles(batchId);
      }, 0);
      return () => window.clearTimeout(timeout);
    }
  }, [batchId, fetchProfiles]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (batchInput) {
      setSearchParams({ batchId: batchInput });
      fetchProfiles(batchInput);
    }
  };

  const handleExportCsv = async () => {
    if (!batchInput) return;
    setExporting(true);
    try {
      await epApi.exportCsv(batchInput);
    } catch {
      setError('No fue posible exportar las fichas.');
    }
    setExporting(false);
  };

  const statusColor = (status: string) => {
    switch (status) {
      case 'COMPLETE': return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/20';
      case 'PARTIAL': return 'bg-amber-500/20 text-amber-400 border-amber-500/20';
      case 'NEEDS_REVIEW': return 'bg-red-500/20 text-red-400 border-red-500/20';
      default: return 'bg-slate-600/20 text-slate-400 border-slate-600/20';
    }
  };

  const completenessBar = (score: number) => {
    const pct = Math.round(score * 100);
    const color = pct >= 80 ? 'bg-emerald-500' : pct >= 50 ? 'bg-amber-500' : 'bg-red-500';
    return (
      <div className="flex items-center gap-2">
        <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
          <div className={`h-full ${color} rounded-full transition-all`} style={{ width: `${pct}%` }} />
        </div>
        <span className="text-xs text-slate-400">{pct}%</span>
      </div>
    );
  };

  return (
    <div className="flex flex-col gap-8 w-full animate-fade-in">
      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between md:items-end gap-4">
        <div className="flex flex-col gap-2">
          <div className="flex gap-2 items-center">
            <Link to="/dashboard" className="text-slate-400 hover:text-amber-400 transition-colors">
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" /></svg>
            </Link>
            <h2 className="text-3xl font-bold m-0 text-slate-50">Fichas de Trabajadores</h2>
          </div>
          <p className="text-slate-400 m-0 text-sm">Perfiles laborales consolidados a partir de documentos personales procesados.</p>
        </div>

        {batchInput && profiles.length > 0 && (
          <button
            onClick={handleExportCsv}
            disabled={exporting}
            className="btn-outline text-xs px-4 py-2 border-amber-500/50 text-amber-400 hover:bg-amber-500/10 flex items-center gap-2 self-start disabled:opacity-40"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" /></svg>
            {exporting ? 'Exportando...' : 'Exportar CSV'}
          </button>
        )}
      </div>

      {/* Filters */}
      <form onSubmit={handleSearch} className="glass-card p-6 flex flex-col md:flex-row gap-4 items-end">
        <div className="flex-1">
          <label className="block text-slate-300 text-xs font-semibold mb-2 uppercase tracking-wider">Batch ID</label>
          <input
            type="text"
            value={batchInput}
            onChange={(e) => setBatchInput(e.target.value)}
            placeholder="ID del lote..."
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-slate-100 focus:outline-none focus:border-amber-500/50 text-sm"
          />
        </div>
        <div className="w-40">
          <label className="block text-slate-300 text-xs font-semibold mb-2 uppercase tracking-wider">Estado</label>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-slate-100 focus:outline-none focus:border-amber-500/50 text-sm"
          >
            <option value="">Todos</option>
            <option value="COMPLETE">Completo</option>
            <option value="PARTIAL">Parcial</option>
            <option value="NEEDS_REVIEW">Revisión</option>
          </select>
        </div>
        <div className="flex-1">
          <label className="block text-slate-300 text-xs font-semibold mb-2 uppercase tracking-wider">Buscar por nombre</label>
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Buscar por nombre del trabajador..."
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-slate-100 focus:outline-none focus:border-amber-500/50 text-sm"
          />
        </div>
        <button
          type="submit"
          className="px-6 py-2.5 rounded-lg font-semibold bg-amber-500/10 text-amber-400 hover:bg-amber-500 hover:text-white border border-amber-500/20 hover:border-amber-500 transition-all text-sm"
        >
          Buscar
        </button>
      </form>

      {/* Results */}
      {loading ? (
        <div className="flex flex-col items-center justify-center p-20 gap-4 glass-card">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-amber-500" />
          <p className="text-slate-400">Cargando fichas...</p>
        </div>
      ) : error ? (
        <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-6 text-center">
          <p className="text-red-400 mb-2 font-semibold">Error</p>
          <p className="text-slate-400 text-sm">{error}</p>
        </div>
      ) : !batchId && profiles.length === 0 ? (
        <div className="glass-card p-12 text-center">
          <div className="w-16 h-16 rounded-full bg-amber-500/10 text-amber-400 flex items-center justify-center mx-auto mb-4">
            <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" /></svg>
          </div>
          <h3 className="text-slate-200 text-lg font-semibold mb-2">Ingresa un Batch ID</h3>
          <p className="text-slate-400 text-sm">Busca fichas de trabajadores por ID de lote. Primero genera las fichas desde el detalle del lote.</p>
        </div>
      ) : profiles.length === 0 && batchId ? (
        <div className="glass-card p-12 text-center">
          <p className="text-slate-400">No se encontraron fichas para este lote. ¿Ya generaste las fichas desde el detalle del lote?</p>
          <Link to={`/batch/${batchId}`} className="text-amber-400 hover:underline text-sm mt-4 inline-block">← Ir al detalle del lote</Link>
        </div>
      ) : (
        <div className="glass-card p-6 flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-slate-100 m-0">
              {total} {total === 1 ? 'ficha' : 'fichas'} encontradas
            </h3>
          </div>

          <div className="bg-slate-950/50 rounded-lg border border-slate-800/50 overflow-hidden">
            <table className="w-full text-sm text-left text-slate-300">
              <thead className="text-xs text-slate-400 bg-slate-900/50 border-b border-slate-800/50">
                <tr>
                  <th className="px-4 py-3">Nombre</th>
                  <th className="px-4 py-3">CURP</th>
                  <th className="px-4 py-3">RFC</th>
                  <th className="px-4 py-3">Docs</th>
                  <th className="px-4 py-3">Completitud</th>
                  <th className="px-4 py-3">Estado</th>
                  <th className="px-4 py-3">Generado</th>
                  <th className="px-4 py-3 text-right">Acciones</th>
                </tr>
              </thead>
              <tbody>
                {profiles.map((p) => (
                  <tr key={p.profileId} className="border-b border-slate-800/50 last:border-0 hover:bg-slate-800/20">
                    <td className="px-4 py-3 font-medium text-slate-200">{p.fullName || '—'}</td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-400">{p.maskedIdentifiers?.curp || '—'}</td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-400">{p.maskedIdentifiers?.rfc || '—'}</td>
                    <td className="px-4 py-3 text-center">
                      <span className="bg-indigo-500/10 text-indigo-400 px-2 py-0.5 rounded-full text-xs border border-indigo-500/20">{p.sourceDocumentCount}</span>
                    </td>
                    <td className="px-4 py-3">{completenessBar(p.completenessScore)}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-1 text-xs rounded-full border ${statusColor(p.status)}`}>{p.status}</span>
                    </td>
                    <td className="px-4 py-3 text-slate-400 text-xs">{p.generatedAt ? new Date(p.generatedAt).toLocaleDateString() : '—'}</td>
                    <td className="px-4 py-3 text-right">
                      <Link
                        to={`/employee-profiles/${p.profileId}?batchId=${p.batchId}`}
                        className="text-amber-400 hover:text-amber-300 underline text-xs"
                      >
                        Ver ficha
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
