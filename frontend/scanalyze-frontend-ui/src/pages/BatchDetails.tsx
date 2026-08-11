import React, { useEffect, useState, useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useAuth } from 'react-oidc-context';
import { batchApi, type BatchDocumentResponse, type BatchResponse } from '../api/batchApi';
import { createEmployeeProfilesApi } from '../api/employeeProfilesApi';
import { documentApi } from '../api/documentApi';
import { useAddonsRegistry } from '../hooks/useAddonsRegistry';
import {
  openExternalHttpsUrl,
  requireHttpsUrl,
  safeDownloadFilename,
} from '../security/browserBoundaries.js';

export const BatchDetails: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const auth = useAuth();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [batch, setBatch] = useState<BatchResponse | null>(null);
  const [documents, setDocuments] = useState<BatchDocumentResponse[]>([]);

  // Add-on registry for EP base path
  const { getApiBasePath } = useAddonsRegistry();
  const epApi = useMemo(
    () => createEmployeeProfilesApi(getApiBasePath('employee-profiles')),
    [getApiBasePath],
  );

  // Employee profiles state
  const [epEnabled, setEpEnabled] = useState(false);
  const [epGenerating, setEpGenerating] = useState(false);
  const [epResult, setEpResult] = useState<{ status: string; profileCount: number } | null>(null);
  const [epError, setEpError] = useState<string | null>(null);

  useEffect(() => {
    const fetchBatch = async () => {
      try {
        setLoading(true);
        if (!id) return;
        const [batchData, docsData] = await Promise.all([
          batchApi.getBatch(id),
          batchApi.getBatchDocuments(id)
        ]);
        setBatch(batchData);
        setDocuments(docsData);
      } catch {
        setError('Error al cargar el lote.');
      } finally {
        setLoading(false);
      }
    };

    if (auth.isAuthenticated && id) {
      void fetchBatch();
      epApi.getStatus().then(s => setEpEnabled(s.tenantEnabled)).catch(() => {});
    }
  }, [id, auth.isAuthenticated, epApi]);



  const handleGenerateProfiles = async () => {
    if (!id) return;
    setEpGenerating(true);
    setEpError(null);
    try {
      const result = await epApi.generate({ batchId: id });
      setEpResult({ status: result.status, profileCount: result.profileCount });
    } catch {
      setEpError('Error al generar fichas');
    }
    setEpGenerating(false);
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center p-20 gap-4 glass-card">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-500"></div>
        <p className="text-slate-400">Cargando lote {id}...</p>
      </div>
    );
  }

  if (error || !batch) {
    return (
      <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-6 text-center">
        <p className="text-red-400 mb-2 font-semibold">Error cargando lote</p>
        <p className="text-slate-400 text-sm">{error}</p>
        <Link to="/analytics" className="text-indigo-400 hover:underline text-sm mt-4 inline-block">← Volver a Analytics</Link>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-8 w-full animate-fade-in">

      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between md:items-end gap-4 mb-2">
        <div className="flex flex-col gap-2">
          <div className="flex gap-2 items-center">
            <Link to="/analytics" className="text-slate-400 hover:text-indigo-400 transition-colors">
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" /></svg>
            </Link>
            <h2 className="text-3xl font-bold m-0 text-slate-50">Lote: {batch.batchId}</h2>
          </div>
          <p className="text-slate-400 m-0 text-sm">Creado el {new Date(batch.createdAt).toLocaleString()}</p>
        </div>

        {/* EXPORTACIONES */}
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => batchApi.downloadManifest(batch.batchId)}
            className="btn-outline text-xs px-3 py-2 border-indigo-500/50 text-indigo-400 hover:bg-indigo-500/10 flex items-center gap-2"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
            Manifest
          </button>
          <button
            onClick={() => batchApi.downloadJson(batch.batchId)}
            className="btn-outline text-xs px-3 py-2 border-indigo-500/50 text-indigo-400 hover:bg-indigo-500/10 flex items-center gap-2"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
            JSON
          </button>
          <button
            onClick={() => batchApi.downloadCsv(batch.batchId)}
            className="btn-outline text-xs px-3 py-2 border-indigo-500/50 text-indigo-400 hover:bg-indigo-500/10 flex items-center gap-2"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
            CSV
          </button>
          <button
            onClick={() => batchApi.downloadZip(batch.batchId)}
            className="btn-outline text-xs px-3 py-2 border-indigo-500/50 text-indigo-400 hover:bg-indigo-500/10 flex items-center gap-2"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
            ZIP
          </button>
          </div>

          {/* Employee Profiles action */}
          {epEnabled && (
            <div className="flex items-center gap-2">
              {epResult ? (
                <Link
                  to={`/employee-profiles?batchId=${batch.batchId}`}
                  className="btn-outline text-xs px-3 py-2 border-amber-500/50 text-amber-400 hover:bg-amber-500/10 flex items-center gap-2"
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
                  Ver {epResult.profileCount} fichas
                </Link>
              ) : (
                <button
                  onClick={handleGenerateProfiles}
                  disabled={epGenerating}
                  className="btn-outline text-xs px-3 py-2 border-amber-500/50 text-amber-400 hover:bg-amber-500/10 flex items-center gap-2 disabled:opacity-40"
                >
                  {epGenerating ? (
                    <div className="w-3 h-3 border-2 border-amber-400 border-t-transparent rounded-full animate-spin" />
                  ) : (
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
                  )}
                  {epGenerating ? 'Generando...' : 'Generar Fichas'}
                </button>
              )}
              {epError && <span className="text-red-400 text-xs">{epError}</span>}
            </div>
          )}
      </div>

      <div className="glass-card p-6 flex flex-col gap-4">
        <h3 className="text-lg font-semibold text-slate-100 m-0">Documentos en Lote ({documents.length})</h3>

        <div className="bg-slate-950/50 rounded-lg border border-slate-800/50 overflow-hidden">
          <table className="w-full text-sm text-left text-slate-300">
            <thead className="text-xs text-slate-400 bg-slate-900/50 border-b border-slate-800/50">
              <tr>
                <th scope="col" className="px-4 py-3">Document ID</th>
                <th scope="col" className="px-4 py-3">Nombre</th>
                <th scope="col" className="px-4 py-3">Tipo</th>
                <th scope="col" className="px-4 py-3">Fecha</th>
                <th scope="col" className="px-4 py-3">Estado</th>
                <th scope="col" className="px-4 py-3 text-right">Acciones</th>
              </tr>
            </thead>
            <tbody>
              {documents.length === 0 ? (
                <tr><td colSpan={6} className="px-6 py-8 text-center text-slate-500">Sin documentos</td></tr>
              ) : (
                documents.map((doc, i) => {
                  const ct = doc.input?.contentType || '';
                  const isImage = ct.startsWith('image/');
                  const isPdf = ct === 'application/pdf';
                  const isPreviewable = isImage || isPdf;

                  return (
                    <tr key={i} className="border-b border-slate-800/50 last:border-0 hover:bg-slate-800/20">
                      <td className="px-4 py-3 font-mono text-xs text-slate-200">{doc.documentId?.substring(0,12)}...</td>
                      <td className="px-4 py-3 truncate max-w-[180px] text-slate-300" title={doc.input?.filename}>{doc.input?.filename || 'Sin nombre'}</td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 text-xs rounded-md ${isImage ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' : 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20'}`}>
                          {ct.split('/').pop()?.toUpperCase() || '—'}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-slate-400 text-xs">{doc.createdAt ? new Date(doc.createdAt).toLocaleDateString() : '—'}</td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-1 text-xs rounded-full border ${
                          ['COMPLETED', 'SUCCESS', 'OCR_COMPLETED'].includes(doc.status ?? '') ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' :
                          ['ERROR', 'FAILED', 'OCR_FAILED'].includes(doc.status ?? '') ? 'bg-red-500/10 text-red-400 border-red-500/20' :
                          'bg-indigo-500/10 text-indigo-400 border-indigo-500/20'
                        }`}>
                          {doc.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <div className="flex justify-end gap-2">
                          {isPreviewable && (
                            <button
                              onClick={async () => {
                                try {
                                  if (!doc.documentId) throw new Error('DOCUMENT_REFERENCE_MISSING');
                                  const url = await documentApi.getArtifactDownloadUrl(doc.documentId, 'raw');
                                  openExternalHttpsUrl(url);
                                } catch { setError('No fue posible abrir el documento.'); }
                              }}
                              className="text-amber-400 hover:text-amber-300 transition-colors p-1"
                              title="Previsualizar archivo original"
                            >
                              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" /></svg>
                            </button>
                          )}
                          <button
                              onClick={async () => {
                                try {
                                  if (!doc.documentId) throw new Error('DOCUMENT_REFERENCE_MISSING');
                                  const url = await documentApi.getArtifactDownloadUrl(doc.documentId, 'raw');
                                const res = await fetch(requireHttpsUrl(url), {
                                  credentials: 'omit',
                                  referrerPolicy: 'no-referrer',
                                });
                                if (!res.ok) throw new Error('ARTIFACT_DOWNLOAD_FAILED');
                                const blob = await res.blob();
                                const blobUrl = URL.createObjectURL(blob);
                                const a = document.createElement('a');
                                a.href = blobUrl;
                                a.download = safeDownloadFilename(
                                  doc.input?.filename,
                                  `doc-${doc.documentId}`,
                                );
                                document.body.appendChild(a);
                                a.click();
                                a.remove();
                                URL.revokeObjectURL(blobUrl);
                              } catch { setError('No fue posible descargar el documento.'); }
                            }}
                            className="text-indigo-400 hover:text-indigo-300 transition-colors p-1"
                            title="Descargar archivo original"
                          >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
                          </button>
                          <Link to={`/document/${doc.documentId}`} className="text-indigo-400 hover:text-indigo-300 underline text-xs flex items-center">
                            Detalle
                          </Link>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
