import React, { useCallback, useEffect, useState } from 'react';
import { useAuth } from 'react-oidc-context';
import { analyticsApi, type DashboardResponse, type DashboardFilters } from '../api/analyticsApi';
import { Link } from 'react-router-dom';
import { csvCell } from '../security/browserBoundaries.js';

export const AnalyticsDashboard: React.FC = () => {
  const auth = useAuth();

  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [data, setData] = useState<DashboardResponse | null>(null);

  // Filters State
  const [filterDocType, setFilterDocType] = useState<string>('ALL');
  const [filterDateRange, setFilterDateRange] = useState<string>('ALL');
  const [filterBatch, setFilterBatch] = useState<string>('');
  const [filterStatus, setFilterStatus] = useState<string>('ALL');

  const fetchAnalytics = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      const filters: DashboardFilters = {};

      // Calculate dates for filterDateRange
      if (filterDateRange !== 'ALL') {
        const d = new Date();
        if (filterDateRange === '7D') {
          d.setDate(d.getDate() - 7);
        } else if (filterDateRange === '30D') {
          d.setDate(d.getDate() - 30);
        }
        filters.startDate = d.toISOString();
      }

      if (filterDocType !== 'ALL') filters.docType = filterDocType;
      if (filterBatch.trim()) filters.batchId = filterBatch.trim();
      if (filterStatus !== 'ALL') filters.status = filterStatus;

      const res = await analyticsApi.getDashboard(filters);
      setData(res);
    } catch {
      setError('Error cargando analíticas');
    } finally {
      setLoading(false);
    }
  }, [filterBatch, filterDateRange, filterDocType, filterStatus]);

  useEffect(() => {
    if (auth.isAuthenticated) {
      void fetchAnalytics();
    }
  }, [auth.isAuthenticated, fetchAnalytics]);

  const handleExportCsv = () => {
    if (!data?.byUser || data.byUser.length === 0) return;

    // Create CSV content
    const headers = ['Usuario (ID/Nombre)', 'Documentos', 'Páginas Escaneadas'];
    const rows = data.byUser.map(u => [
      csvCell(u.displayName || u.userId),
      csvCell(u.documentsCount),
      csvCell(u.pagesScanned)
    ]);
    const csvContent = [headers.map(csvCell).join(','), ...rows.map(r => r.join(','))].join('\n');

    // Download
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `pages_by_user_${new Date().toISOString().split('T')[0]}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col gap-8 w-full animate-fade-in">

      {/* Header */}
      <div className="flex flex-col gap-2">
        <h2 className="text-3xl font-bold m-0 text-slate-50">Usage & Analytics</h2>
        <p className="text-slate-400 m-0 text-lg">Métricas de adopción y uso del sistema AI por tenant.</p>
      </div>

      {/* Filter Bar */}
      <div className="glass-card p-4 flex flex-col md:flex-row gap-4 items-center flex-wrap">
        <div className="flex items-center gap-2 w-full md:w-auto">
          <span className="text-slate-400 text-sm font-medium">Tenant:</span>
          <span className="px-3 py-1 bg-slate-800 rounded-lg text-slate-200 text-sm font-mono border border-slate-700">Actual</span>
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto">
          <span className="text-slate-400 text-sm font-medium">Rango:</span>
          <select
            className="input-field py-1 px-3 text-sm min-w-[140px] m-0"
            value={filterDateRange}
            onChange={e => setFilterDateRange(e.target.value)}
          >
             <option value="ALL">Todo el tiempo</option>
             <option value="7D">Últimos 7 días</option>
             <option value="30D">Últimos 30 días</option>
          </select>
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto">
          <span className="text-slate-400 text-sm font-medium">DocType:</span>
          <select
            className="input-field py-1 px-3 text-sm min-w-[140px] m-0"
            value={filterDocType}
            onChange={e => setFilterDocType(e.target.value)}
          >
             <option value="ALL">Todos</option>
             {data?.byDocType.map(d => (
               <option key={d.docType} value={d.docType}>{d.docType || 'Desconocido'}</option>
             ))}
          </select>
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto">
          <span className="text-slate-400 text-sm font-medium">Status:</span>
          <select
            className="input-field py-1 px-3 text-sm min-w-[140px] m-0"
            value={filterStatus}
            onChange={e => setFilterStatus(e.target.value)}
          >
             <option value="ALL">Todos</option>
             <option value="COMPLETED">Completados/Éxito</option>
             <option value="ERROR">Fallidos/Error</option>
          </select>
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto flex-1">
          <span className="text-slate-400 text-sm font-medium">Batch:</span>
          <input
            type="text"
            placeholder="Filtrar por Batch ID..."
            className="input-field py-1 px-3 text-sm flex-1 m-0 min-w-[120px]"
            value={filterBatch}
            onBlur={e => setFilterBatch(e.target.value)} // Only filter on blur to avoid excessive calls
            onChange={e => setFilterBatch(e.target.value)}
          />
        </div>
      </div>

      {loading && !data && (
        <div className="flex flex-col items-center justify-center p-20 gap-4 glass-card">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-500"></div>
          <p className="text-slate-400">Calculando métricas de servidor...</p>
        </div>
      )}

      {error && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-6 text-center">
          <p className="text-red-400 mb-2 font-semibold">Error Server-Side</p>
          <p className="text-slate-400 text-sm">{error}</p>
        </div>
      )}

      {!loading && data && (
        <>
          {/* KPI Cards */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <div className="glass-card p-4 flex flex-col gap-1">
              <span className="text-slate-400 text-xs uppercase tracking-wider">Docs Subidos</span>
              <span className="text-2xl font-bold text-slate-100">{data.overview.documentsUploaded}</span>
            </div>
            <div className="glass-card p-4 flex flex-col gap-1">
              <span className="text-slate-400 text-xs uppercase tracking-wider">Completados</span>
              <span className="text-2xl font-bold text-emerald-400">{data.overview.documentsCompleted}</span>
            </div>
            <div className="glass-card p-4 flex flex-col gap-1">
              <span className="text-slate-400 text-xs uppercase tracking-wider">Fallidos</span>
              <span className="text-2xl font-bold text-red-400">{data.overview.documentsFailed}</span>
            </div>
            <div className="glass-card p-4 flex flex-col gap-1">
              <span className="text-slate-400 text-xs uppercase tracking-wider">Páginas Totales</span>
              <span className="text-2xl font-bold text-indigo-400">{data.overview.pagesScanned}</span>
            </div>
            <div className="glass-card p-4 flex flex-col gap-1">
              <span className="text-slate-400 text-xs uppercase tracking-wider">Promedio Pag/Doc</span>
              <span className="text-2xl font-bold text-violet-400">
                {data.overview.documentsCompleted > 0
                  ? (data.overview.pagesScanned / data.overview.documentsCompleted).toFixed(1)
                  : '0'}
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

            {/* Pages Scanned by User (Demo Ready) */}
            <div className="glass-card p-6 flex flex-col gap-4">
              <div className="flex justify-between items-center">
                <h3 className="text-lg font-semibold text-slate-100 m-0">Top Consumo por Usuario</h3>
                <button onClick={handleExportCsv} className="btn btn-secondary text-xs px-3 py-1 bg-slate-800">
                  Exportar CSV
                </button>
              </div>
              <div className="bg-slate-950/50 rounded-lg border border-slate-800/50 overflow-hidden">
                <table className="w-full text-sm text-left text-slate-300">
                  <thead className="text-xs text-slate-400 bg-slate-900/50 border-b border-slate-800/50">
                    <tr>
                      <th scope="col" className="px-6 py-3">Usuario (Nombre / ID)</th>
                      <th scope="col" className="px-6 py-3 text-right">Documentos</th>
                      <th scope="col" className="px-6 py-3 text-right">Páginas Escaneadas</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.byUser.length === 0 ? (
                      <tr><td colSpan={3} className="px-6 py-8 text-center text-slate-500">Sin datos en este filtro</td></tr>
                    ) : (
                      data.byUser.map((row, i) => (
                        <tr key={i} className="border-b border-slate-800/50 last:border-0 hover:bg-slate-800/20">
                          <td className="px-6 py-4 font-medium text-slate-200">{row.displayName || row.userId || 'Desconocido'}</td>
                          <td className="px-6 py-4 text-right text-emerald-400 font-medium">{row.documentsCount}</td>
                          <td className="px-6 py-4 text-right text-indigo-400 font-medium">{row.pagesScanned}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Drill Down Batches */}
            <div className="glass-card p-6 flex flex-col gap-4">
              <h3 className="text-lg font-semibold text-slate-100 m-0">Documentos por Lote (Batch)</h3>
              <div className="bg-slate-950/50 rounded-lg border border-slate-800/50 overflow-hidden">
                <table className="w-full text-sm text-left text-slate-300">
                  <thead className="text-xs text-slate-400 bg-slate-900/50 border-b border-slate-800/50">
                    <tr>
                      <th scope="col" className="px-6 py-3">Lote ID</th>
                      <th scope="col" className="px-6 py-3 text-right">Documentos</th>
                      <th scope="col" className="px-6 py-3 text-right">Páginas Escaneadas</th>
                      <th scope="col" className="px-6 py-3 text-right">Acción</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.byBatch.length === 0 ? (
                      <tr><td colSpan={4} className="px-6 py-8 text-center text-slate-500">Sin datos en este filtro</td></tr>
                    ) : (
                      data.byBatch.map((row, i) => (
                        <tr key={i} className="border-b border-slate-800/50 last:border-0 hover:bg-slate-800/20">
                          <td className="px-6 py-4 font-mono text-xs text-slate-200 truncate max-w-[150px]">
                            {row.batchId || 'Sin Lote'}
                          </td>
                          <td className="px-6 py-4 text-right text-emerald-400 font-medium">{row.documentsCount}</td>
                          <td className="px-6 py-4 text-right text-indigo-400 font-medium">{row.pagesScanned}</td>
                          <td className="px-6 py-4 text-right">
                             {row.batchId && row.batchId !== 'Unknown' && row.batchId !== 'none' && (
                               <Link to={`/batch/${row.batchId}`} className="text-indigo-400 hover:text-indigo-300 underline text-xs">
                                 Ver Documentos
                               </Link>
                             )}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Usage by Date */}
            <div className="glass-card p-6 flex flex-col gap-4">
              <h3 className="text-lg font-semibold text-slate-100 m-0">Consumo por Día</h3>
              <div className="bg-slate-950/50 rounded-lg border border-slate-800/50 overflow-hidden">
                <table className="w-full text-sm text-left text-slate-300">
                  <thead className="text-xs text-slate-400 bg-slate-900/50 border-b border-slate-800/50">
                    <tr>
                      <th scope="col" className="px-6 py-3">Día</th>
                      <th scope="col" className="px-6 py-3 text-right">Documentos</th>
                      <th scope="col" className="px-6 py-3 text-right">Páginas Escaneadas</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.byDay.length === 0 ? (
                      <tr><td colSpan={3} className="px-6 py-8 text-center text-slate-500">Sin datos</td></tr>
                    ) : (
                      data.byDay.map((row, i) => (
                        <tr key={i} className="border-b border-slate-800/50 last:border-0 hover:bg-slate-800/20">
                          <td className="px-6 py-4 font-medium">{row.day}</td>
                          <td className="px-6 py-4 text-right text-emerald-400 font-medium">{row.documentsCount}</td>
                          <td className="px-6 py-4 text-right text-indigo-400 font-medium">{row.pagesScanned}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Usage by Doc Type */}
            <div className="glass-card p-6 flex flex-col gap-4">
              <h3 className="text-lg font-semibold text-slate-100 m-0">Por Tipo de Documento</h3>
              <div className="bg-slate-950/50 rounded-lg border border-slate-800/50 overflow-hidden">
                <table className="w-full text-sm text-left text-slate-300">
                  <thead className="text-xs text-slate-400 bg-slate-900/50 border-b border-slate-800/50">
                    <tr>
                      <th scope="col" className="px-6 py-3">Tipo</th>
                      <th scope="col" className="px-6 py-3 text-right">Documentos</th>
                      <th scope="col" className="px-6 py-3 text-right">Páginas Escaneadas</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.byDocType.length === 0 ? (
                      <tr><td colSpan={3} className="px-6 py-8 text-center text-slate-500">Sin datos</td></tr>
                    ) : (
                      data.byDocType.map((row, i) => (
                        <tr key={i} className="border-b border-slate-800/50 last:border-0 hover:bg-slate-800/20">
                          <td className="px-6 py-4 font-medium uppercase">{row.docType || 'Desconocido'}</td>
                          <td className="px-6 py-4 text-right text-emerald-400 font-medium">{row.documentsCount}</td>
                          <td className="px-6 py-4 text-right text-indigo-400 font-medium">{row.pagesScanned}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>

          </div>
        </>
      )}

    </div>
  );
};
