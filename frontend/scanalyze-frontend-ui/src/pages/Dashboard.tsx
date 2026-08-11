import React, { useCallback, useEffect, useState } from 'react';
import { useAuth } from 'react-oidc-context';
import { getApiClient } from '../api/client';
import { Link } from 'react-router-dom';
import { employeeProfilesApi } from '../api/employeeProfilesApi';

interface IneDoc {
  documentId: string;
  createdAt: string;
  status: string;
  filename: string;
  classificationRoute: string;
  batchId?: string;
}

interface BatchSummary {
  batchId: string;
  createdAt: string;
  status: string;
  metadata: Record<string, unknown>;
  createdByDisplayName: string;
}

export const Dashboard: React.FC = () => {
  const auth = useAuth();
  const [healthStatus, setHealthStatus] = useState<string>('Comprobando conectividad...');
  const [showIneModal, setShowIneModal] = useState<boolean>(false);
  const [ineFilters, setIneFilters] = useState({ startDate: '', endDate: '', userId: '' });
  const [ineTab, setIneTab] = useState<'filters' | 'manual' | 'batch'>('filters');
  const [ineDocs, setIneDocs] = useState<IneDoc[]>([]);
  const [selectedDocIds, setSelectedDocIds] = useState<Set<string>>(new Set());
  const [loadingDocs, setLoadingDocs] = useState(false);
  const [downloading, setDownloading] = useState(false);

  // Batch tab state
  const [batches, setBatches] = useState<BatchSummary[]>([]);
  const [loadingBatches, setLoadingBatches] = useState(false);
  const [selectedBatchId, setSelectedBatchId] = useState<string>('');
  const [batchDocCount, setBatchDocCount] = useState<number | null>(null);
  const [loadingBatchPreview, setLoadingBatchPreview] = useState(false);

  // Employee Profiles feature flag
  const [epEnabled, setEpEnabled] = useState(false);

  const fetchIneDocs = useCallback(async (batchId?: string) => {
    setLoadingDocs(true);
    try {
      const client = getApiClient();
      const params = batchId ? `?batchId=${batchId}` : '';
      const resp = await client.get(`/analytics/ine-docs${params}`);
      setIneDocs(resp.data?.documents || []);
    } catch {
      setIneDocs([]);
    }
    setLoadingDocs(false);
  }, []);

  const fetchBatches = useCallback(async () => {
    setLoadingBatches(true);
    try {
      const client = getApiClient();
      const resp = await client.get('/analytics/batches');
      setBatches(resp.data || []);
    } catch {
      setBatches([]);
    }
    setLoadingBatches(false);
  }, []);

  const previewBatchDocs = useCallback(async (batchId: string) => {
    setLoadingBatchPreview(true);
    try {
      const client = getApiClient();
      const resp = await client.get(`/analytics/ine-docs?batchId=${batchId}`);
      setBatchDocCount(resp.data?.total ?? 0);
    } catch {
      setBatchDocCount(null);
    }
    setLoadingBatchPreview(false);
  }, []);

  const toggleDocId = (id: string) => {
    setSelectedDocIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleAll = () => {
    if (selectedDocIds.size === ineDocs.length) {
      setSelectedDocIds(new Set());
    } else {
      setSelectedDocIds(new Set(ineDocs.map(d => d.documentId)));
    }
  };

  const handleIneDownload = async () => {
    setDownloading(true);
    try {
      const client = getApiClient();
      const params = new URLSearchParams();

      if (ineTab === 'batch' && selectedBatchId) {
        params.append('batchId', selectedBatchId);
      } else if (ineTab === 'manual' && selectedDocIds.size > 0) {
        params.append('documentIds', Array.from(selectedDocIds).join(','));
      } else {
        if (ineFilters.startDate) params.append('startDate', ineFilters.startDate);
        if (ineFilters.endDate) params.append('endDate', ineFilters.endDate);
        if (ineFilters.userId) params.append('userId', ineFilters.userId);
      }

      const response = await client.get('/analytics/export-ine', {
        params: Object.fromEntries(params.entries()),
        responseType: 'blob',
      });
      const objectUrl = window.URL.createObjectURL(response.data);
      const a = document.createElement('a');
      a.href = objectUrl;
      const filename = ineTab === 'batch' && selectedBatchId
        ? `ine_export_${selectedBatchId.substring(0, 12)}.csv`
        : 'ine_export.csv';
      a.download = filename;
      a.click();
      window.URL.revokeObjectURL(objectUrl);
      setShowIneModal(false);
    } catch {
      // The API error remains intentionally generic at the browser boundary.
    } finally {
      setDownloading(false);
    }
  };

  useEffect(() => {
    const checkApi = async () => {
      try {
        const client = getApiClient();
        const response = await client.get('/health');
        setHealthStatus(response.data?.status || 'API Operacional');
      } catch {
        setHealthStatus('API no disponible');
      }
    };
    if (auth.isAuthenticated) {
      void checkApi();
    }
  }, [auth.isAuthenticated]);

  useEffect(() => {
    if (auth.isAuthenticated) {
      employeeProfilesApi.getStatus().then(s => setEpEnabled(s.tenantEnabled)).catch(() => setEpEnabled(false));
    }
  }, [auth.isAuthenticated]);

  useEffect(() => {
    const timeout = window.setTimeout(() => {
      if (showIneModal && ineTab === 'manual' && ineDocs.length === 0) {
        void fetchIneDocs();
      }
      if (showIneModal && ineTab === 'batch' && batches.length === 0) {
        void fetchBatches();
      }
    }, 0);
    return () => window.clearTimeout(timeout);
  }, [batches.length, fetchBatches, fetchIneDocs, ineDocs.length, ineTab, showIneModal]);

  useEffect(() => {
    const timeout = window.setTimeout(() => {
      if (selectedBatchId) {
        void previewBatchDocs(selectedBatchId);
      } else {
        setBatchDocCount(null);
      }
    }, 0);
    return () => window.clearTimeout(timeout);
  }, [previewBatchDocs, selectedBatchId]);

  const getDownloadLabel = () => {
    if (downloading) return 'Descargando...';
    if (ineTab === 'batch') {
      if (!selectedBatchId) return 'Selecciona un lote';
      if (loadingBatchPreview) return 'Verificando...';
      return batchDocCount !== null ? `Descargar Lote (${batchDocCount} INEs)` : 'Descargar Lote';
    }
    if (ineTab === 'manual') return `Descargar (${selectedDocIds.size})`;
    return 'Descargar CSV';
  };

  const isDownloadDisabled = () => {
    if (downloading) return true;
    if (ineTab === 'batch') return !selectedBatchId || loadingBatchPreview;
    if (ineTab === 'manual') return selectedDocIds.size === 0;
    return false;
  };

  return (
    <div className="flex flex-col gap-8 w-full">

        <div className="flex flex-col gap-2 mb-4 animate-fade-in">
          <h2 className="text-3xl font-bold m-0 text-slate-50">Resumen General</h2>
          <p className="text-slate-400 m-0 text-lg">Inicia extracciones y monitorea el estado integral del sistema AI.</p>
        </div>

        {/* Dashboard Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-2 xl:grid-cols-4 gap-6">

          {/* Create New Document Tile */}
          <Link to="/upload" className="glass-card flex flex-col items-center justify-center p-10 gap-6 text-center transition-all duration-300 hover:-translate-y-1 hover:shadow-2xl hover:border-indigo-500/50 group no-underline">
            <div className="w-16 h-16 rounded-full bg-indigo-500/10 text-indigo-400 flex items-center justify-center group-hover:bg-indigo-500/20 group-hover:text-indigo-300 transition-colors">
              <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" /></svg>
            </div>
            <div>
              <h3 className="text-slate-100 text-xl font-semibold mb-2 m-0 group-hover:text-white transition-colors">Nuevo Espacio de Trabajo (Subida)</h3>
              <p className="text-slate-400 m-0 text-sm">Sube un documento y extrae la inteligencia instantáneamente.</p>
            </div>
            <div className="mt-2 text-indigo-400 font-medium flex items-center gap-1 group-hover:text-indigo-300 transition-colors">
              Comenzar flujo
              <svg className="w-4 h-4 transition-transform group-hover:translate-x-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
            </div>
          </Link>

          {/* Bulk Upload Tile */}
          <Link to="/bulk-upload" className="glass-card flex flex-col items-center justify-center p-10 gap-6 text-center transition-all duration-300 hover:-translate-y-1 hover:shadow-2xl hover:border-indigo-500/50 group no-underline">
            <div className="w-16 h-16 rounded-full bg-indigo-500/10 text-indigo-400 flex items-center justify-center group-hover:bg-indigo-500/20 group-hover:text-indigo-300 transition-colors">
              <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" /></svg>
            </div>
            <div>
              <h3 className="text-slate-100 text-xl font-semibold mb-2 m-0 group-hover:text-white transition-colors">Carga Masiva (Lote)</h3>
              <p className="text-slate-400 m-0 text-sm">Sube múltiples documentos simultáneamente para su procesamiento automático.</p>
            </div>
            <div className="mt-2 text-indigo-400 font-medium flex items-center gap-1 group-hover:text-indigo-300 transition-colors">
              Comenzar lote
              <svg className="w-4 h-4 transition-transform group-hover:translate-x-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
            </div>
          </Link>

          {/* System Health Tile */}
          <div className="glass-card p-8 flex flex-col justify-between">
            <div className="flex items-center gap-4 mb-6">
              <div className="w-12 h-12 rounded-xl bg-emerald-500/10 text-emerald-400 flex items-center justify-center">
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
              </div>
              <h3 className="m-0 text-slate-100 text-lg font-semibold">Estado del Sistema</h3>
            </div>

            <div className="bg-slate-950/50 p-6 rounded-xl border border-slate-800/50 flex flex-col justify-center flex-1">
              <div className="flex items-center justify-between mb-4">
                <span className="text-slate-400 text-sm">Backend API</span>
                <span className="bg-emerald-500/20 text-emerald-400 px-3 py-1 rounded-full text-xs font-semibold border border-emerald-500/20">
                  En Línea
                </span>
              </div>
              <p className="m-0 text-slate-300 text-sm break-all leading-relaxed">
                <strong className="block text-slate-500 text-xs uppercase tracking-wider mb-1">Respuesta `/health`:</strong>
                {healthStatus}
              </p>
            </div>
          </div>

          {/* Cost Control Tile */}
          <Link to="/costs" className="glass-card flex flex-col items-center justify-center p-10 gap-6 text-center transition-all duration-300 hover:-translate-y-1 hover:shadow-2xl hover:border-emerald-500/50 group no-underline">
            <div className="w-16 h-16 rounded-full bg-emerald-500/10 text-emerald-400 flex items-center justify-center group-hover:bg-emerald-500/20 group-hover:text-emerald-300 transition-colors">
              <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
            </div>
            <div>
              <h3 className="text-slate-100 text-xl font-semibold mb-2 m-0 group-hover:text-white transition-colors">Cost Control AWS</h3>
              <p className="text-slate-400 m-0 text-sm">Auditoria financiera precisa. Visualiza el costo detallado de procesamiento por tenant.</p>
            </div>
            <div className="mt-2 text-emerald-400 font-medium flex items-center gap-1 group-hover:text-emerald-300 transition-colors">
              Ver reporte financiero
              <svg className="w-4 h-4 transition-transform group-hover:translate-x-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
            </div>
          </Link>

          {/* Analytics Tile */}
          <Link to="/analytics" className="glass-card flex flex-col items-center justify-center p-10 gap-6 text-center transition-all duration-300 hover:-translate-y-1 hover:shadow-2xl hover:border-indigo-500/50 group no-underline">
            <div className="w-16 h-16 rounded-full bg-indigo-500/10 text-indigo-400 flex items-center justify-center group-hover:bg-indigo-500/20 group-hover:text-indigo-300 transition-colors">
              <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" /></svg>
            </div>
            <div>
              <h3 className="text-slate-100 text-xl font-semibold mb-2 m-0 group-hover:text-white transition-colors">Uso y Analíticas</h3>
              <p className="text-slate-400 m-0 text-sm">Visualiza métricas del uso general, páginas escaneadas y KPIs del sistema.</p>
            </div>
            <div className="mt-2 text-indigo-400 font-medium flex items-center gap-1 group-hover:text-indigo-300 transition-colors">
              Ver Dashboard
              <svg className="w-4 h-4 transition-transform group-hover:translate-x-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
            </div>
          </Link>

          {/* INE Export Tile */}
          <div onClick={() => setShowIneModal(true)} className="glass-card flex flex-col items-center justify-center p-10 gap-6 text-center transition-all duration-300 hover:-translate-y-1 hover:shadow-2xl hover:border-pink-500/50 group cursor-pointer">
            <div className="w-16 h-16 rounded-full bg-pink-500/10 text-pink-400 flex items-center justify-center group-hover:bg-pink-500/20 group-hover:text-pink-300 transition-colors">
              <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V8a2 2 0 00-2-2h-5m-4 0V5a2 2 0 114 0v1m-4 0a2 2 0 104 0m-5 8a2 2 0 100-4 2 2 0 000 4zm0 0c1.306 0 2.417.835 2.83 2M9 14a3.001 3.001 0 00-2.83 2M15 11h3m-3 4h2" /></svg>
            </div>
            <div>
              <h3 className="text-slate-100 text-xl font-semibold mb-2 m-0 group-hover:text-white transition-colors">Datos Personales y KYC</h3>
              <p className="text-slate-400 m-0 text-sm">Descarga de INEs y documentos oficiales procesados. Exportación estructurada en lote.</p>
            </div>
            <div className="mt-2 text-pink-400 font-medium flex items-center gap-1 group-hover:text-pink-300 transition-colors">
              Descargar Reporte INE
              <svg className="w-4 h-4 transition-transform group-hover:translate-x-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
            </div>
          </div>


          {/* Bank Statements Tile */}
          <Link to="/bank-statements" className="glass-card flex flex-col items-center justify-center p-10 gap-6 text-center transition-all duration-300 hover:-translate-y-1 hover:shadow-2xl hover:border-cyan-500/50 group no-underline">
            <div className="w-16 h-16 rounded-full bg-cyan-500/10 text-cyan-400 flex items-center justify-center group-hover:bg-cyan-500/20 group-hover:text-cyan-300 transition-colors">
              <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" /></svg>
            </div>
            <div>
              <h3 className="text-slate-100 text-xl font-semibold mb-2 m-0 group-hover:text-white transition-colors">Estados de Cuenta</h3>
              <p className="text-slate-400 m-0 text-sm">Extrae transacciones, saldos y datos bancarios de estados de cuenta de cualquier banco.</p>
            </div>
            <div className="mt-2 text-cyan-400 font-medium flex items-center gap-1 group-hover:text-cyan-300 transition-colors">
              Ir al módulo bancario
              <svg className="w-4 h-4 transition-transform group-hover:translate-x-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
            </div>
          </Link>

          {/* Employee Profiles Tile — only shown when feature is enabled */}
          {epEnabled && (
            <Link to="/employee-profiles" className="glass-card flex flex-col items-center justify-center p-10 gap-6 text-center transition-all duration-300 hover:-translate-y-1 hover:shadow-2xl hover:border-amber-500/50 group no-underline">
              <div className="w-16 h-16 rounded-full bg-amber-500/10 text-amber-400 flex items-center justify-center group-hover:bg-amber-500/20 group-hover:text-amber-300 transition-colors">
                <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" /></svg>
              </div>
              <div>
                <h3 className="text-slate-100 text-xl font-semibold mb-2 m-0 group-hover:text-white transition-colors">Fichas de Trabajadores</h3>
                <p className="text-slate-400 m-0 text-sm">Genera perfiles laborales consolidados a partir de lotes de documentos personales.</p>
              </div>
              <div className="mt-2 text-amber-400 font-medium flex items-center gap-1 group-hover:text-amber-300 transition-colors">
                Ver fichas
                <svg className="w-4 h-4 transition-transform group-hover:translate-x-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
              </div>
            </Link>
          )}

        </div>

        {/* INE Modal */}
        {showIneModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-fade-in">
            <div className="bg-slate-900 border border-slate-700 p-8 rounded-2xl shadow-2xl w-full max-w-lg">
              <h3 className="text-2xl font-bold text-white mb-2">Exportación INE / KYC</h3>
              <p className="text-slate-400 text-sm mb-6">Selecciona el modo de exportación: filtros, selección manual o por lote.</p>

              {/* Tabs — 3 options now */}
              <div className="flex gap-2 mb-6">
                {(['filters', 'manual', 'batch'] as const).map(tab => {
                  const labels = { filters: 'Filtros', manual: 'Manual', batch: 'Por Lote' };
                  const icons = {
                    filters: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z" /></svg>,
                    manual: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" /></svg>,
                    batch: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>
                  };
                  return (
                    <button
                      key={tab}
                      onClick={() => setIneTab(tab)}
                      className={`flex-1 py-2.5 rounded-lg font-semibold text-sm transition-all flex items-center justify-center gap-2 ${
                        ineTab === tab
                          ? 'bg-pink-500/20 text-pink-400 border border-pink-500/30'
                          : 'bg-slate-800/50 text-slate-400 border border-slate-700 hover:border-slate-600'
                      }`}
                    >
                      {icons[tab]}
                      {labels[tab]}
                    </button>
                  );
                })}
              </div>

              {/* Tab: Filters */}
              {ineTab === 'filters' && (
                <div className="flex flex-col gap-4 mb-6">
                  <div>
                    <label className="block text-slate-300 text-sm font-semibold mb-2">Fecha de Inicio</label>
                    <input type="date" value={ineFilters.startDate} onChange={e => setIneFilters({...ineFilters, startDate: e.target.value})} className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-slate-100 focus:outline-none focus:border-pink-500/50" />
                  </div>
                  <div>
                    <label className="block text-slate-300 text-sm font-semibold mb-2">Fecha de Fin</label>
                    <input type="date" value={ineFilters.endDate} onChange={e => setIneFilters({...ineFilters, endDate: e.target.value})} className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-slate-100 focus:outline-none focus:border-pink-500/50" />
                  </div>
                  <div>
                    <label className="block text-slate-300 text-sm font-semibold mb-2">Revisor (Opcional)</label>
                    <input type="text" placeholder="ID de Usuario / Email" value={ineFilters.userId} onChange={e => setIneFilters({...ineFilters, userId: e.target.value})} className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-slate-100 focus:outline-none focus:border-pink-500/50" />
                  </div>
                </div>
              )}

              {/* Tab: Manual */}
              {ineTab === 'manual' && (
                <div className="mb-6">
                  {loadingDocs ? (
                    <div className="flex items-center justify-center py-8">
                      <div className="w-6 h-6 border-2 border-pink-400 border-t-transparent rounded-full animate-spin mr-3"></div>
                      <span className="text-slate-400 text-sm">Cargando documentos INE...</span>
                    </div>
                  ) : ineDocs.length === 0 ? (
                    <div className="bg-slate-950/50 py-8 rounded-xl border border-slate-800/50 text-center">
                      <p className="text-slate-400 text-sm m-0">No se encontraron documentos INE procesados.</p>
                      <button onClick={() => fetchIneDocs()} className="mt-3 text-pink-400 text-sm hover:text-pink-300 transition-colors">Reintentar</button>
                    </div>
                  ) : (
                    <div className="max-h-64 overflow-y-auto">
                      <div className="flex items-center justify-between mb-3 px-1">
                        <span className="text-slate-400 text-xs">{selectedDocIds.size} de {ineDocs.length} seleccionados</span>
                        <button onClick={toggleAll} className="text-pink-400 text-xs hover:text-pink-300 transition-colors">
                          {selectedDocIds.size === ineDocs.length ? 'Deseleccionar todos' : 'Seleccionar todos'}
                        </button>
                      </div>
                      <div className="flex flex-col gap-2">
                        {ineDocs.map(doc => (
                          <label
                            key={doc.documentId}
                            className={`flex items-center gap-3 p-3 rounded-lg border cursor-pointer transition-all ${
                              selectedDocIds.has(doc.documentId)
                                ? 'bg-pink-500/10 border-pink-500/30'
                                : 'bg-slate-950/50 border-slate-800/50 hover:border-slate-700'
                            }`}
                          >
                            <input
                              type="checkbox"
                              checked={selectedDocIds.has(doc.documentId)}
                              onChange={() => toggleDocId(doc.documentId)}
                              className="w-4 h-4 accent-pink-500"
                            />
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2">
                                <span className="text-slate-200 text-sm font-medium truncate">{doc.filename || doc.documentId.substring(0, 12) + '...'}</span>
                                <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                                  doc.status.includes('FAILED') ? 'bg-amber-500/20 text-amber-400' :
                                  doc.status === 'COMPLETED' ? 'bg-emerald-500/20 text-emerald-400' :
                                  'bg-slate-600/20 text-slate-400'
                                }`}>{doc.status}</span>
                              </div>
                              <span className="text-slate-500 text-xs">{doc.createdAt ? new Date(doc.createdAt).toLocaleString() : ''}</span>
                            </div>
                          </label>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Tab: Batch */}
              {ineTab === 'batch' && (
                <div className="mb-6">
                  {loadingBatches ? (
                    <div className="flex items-center justify-center py-8">
                      <div className="w-6 h-6 border-2 border-pink-400 border-t-transparent rounded-full animate-spin mr-3"></div>
                      <span className="text-slate-400 text-sm">Cargando lotes disponibles...</span>
                    </div>
                  ) : batches.length === 0 ? (
                    <div className="bg-slate-950/50 py-8 rounded-xl border border-slate-800/50 text-center">
                      <p className="text-slate-400 text-sm m-0">No se encontraron lotes disponibles.</p>
                      <button onClick={fetchBatches} className="mt-3 text-pink-400 text-sm hover:text-pink-300 transition-colors">Reintentar</button>
                    </div>
                  ) : (
                    <div className="flex flex-col gap-3">
                      <label className="block text-slate-300 text-sm font-semibold mb-1">Selecciona un lote</label>
                      <div className="max-h-64 overflow-y-auto flex flex-col gap-2">
                        {batches.map(batch => {
                          const isSelected = selectedBatchId === batch.batchId;
                          const batchLabel = (batch.metadata as Record<string, unknown>)?.name as string
                            || batch.createdByDisplayName
                            || batch.batchId.substring(0, 12) + '...';
                          return (
                            <button
                              key={batch.batchId}
                              onClick={() => setSelectedBatchId(isSelected ? '' : batch.batchId)}
                              className={`flex items-center gap-3 p-4 rounded-lg border text-left transition-all ${
                                isSelected
                                  ? 'bg-pink-500/15 border-pink-500/40 shadow-lg shadow-pink-500/5'
                                  : 'bg-slate-950/50 border-slate-800/50 hover:border-slate-600'
                              }`}
                            >
                              <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center flex-shrink-0 transition-all ${
                                isSelected ? 'border-pink-400 bg-pink-500/20' : 'border-slate-600'
                              }`}>
                                {isSelected && <div className="w-2.5 h-2.5 rounded-full bg-pink-400"></div>}
                              </div>
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2">
                                  <span className="text-slate-200 text-sm font-medium truncate">{batchLabel}</span>
                                  <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                                    batch.status === 'COMPLETED' ? 'bg-emerald-500/20 text-emerald-400' :
                                    batch.status === 'OPEN' ? 'bg-blue-500/20 text-blue-400' :
                                    'bg-slate-600/20 text-slate-400'
                                  }`}>{batch.status}</span>
                                </div>
                                <div className="flex items-center gap-3 mt-1">
                                  <span className="text-slate-500 text-xs">{batch.createdAt ? new Date(batch.createdAt).toLocaleString() : ''}</span>
                                  <span className="text-slate-600 text-xs font-mono">{batch.batchId.substring(0, 12)}...</span>
                                </div>
                              </div>
                            </button>
                          );
                        })}
                      </div>

                      {/* Batch preview */}
                      {selectedBatchId && (
                        <div className="mt-3 bg-slate-950/50 p-4 rounded-xl border border-slate-800/50">
                          <div className="flex items-center gap-2">
                            <svg className="w-4 h-4 text-pink-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                            {loadingBatchPreview ? (
                              <span className="text-slate-400 text-sm">Contando documentos INE en este lote...</span>
                            ) : batchDocCount !== null ? (
                              <span className="text-slate-300 text-sm">
                                <strong className="text-pink-400">{batchDocCount}</strong> documento{batchDocCount !== 1 ? 's' : ''} INE encontrado{batchDocCount !== 1 ? 's' : ''} en este lote
                              </span>
                            ) : (
                              <span className="text-slate-400 text-sm">Error al contar documentos</span>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              <div className="flex justify-end gap-4 mt-8">
                <button onClick={() => { setShowIneModal(false); setSelectedDocIds(new Set()); setSelectedBatchId(''); }} className="px-5 py-2.5 rounded-lg font-semibold bg-transparent text-slate-300 hover:text-white hover:bg-slate-800 transition-colors">Cancelar</button>
                <button
                  onClick={handleIneDownload}
                  disabled={isDownloadDisabled()}
                  className="px-5 py-2.5 rounded-lg font-semibold bg-pink-500/10 text-pink-400 hover:bg-pink-500 hover:text-white border border-pink-500/20 hover:border-pink-500 transition-all shadow-lg flex items-center gap-2 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  {downloading ? (
                    <div className="w-5 h-5 border-2 border-pink-400 border-t-transparent rounded-full animate-spin"></div>
                  ) : (
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
                  )}
                  {getDownloadLabel()}
                </button>
              </div>
            </div>
          </div>
        )}
    </div>
  );
};
