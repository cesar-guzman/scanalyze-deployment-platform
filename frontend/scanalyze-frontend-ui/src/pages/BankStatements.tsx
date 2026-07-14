import React, { useState, useRef, useEffect, useCallback } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import axios from 'axios';
import { documentApi } from '../api/documentApi';
import { batchApi } from '../api/batchApi';
import type { BatchResponse } from '../api/batchApi';
import { uploadFileToPresignedUrl } from '../api/uploadApi';
import { getApiClient } from '../api/client';
import { requireHttpsUrl, safeDownloadFilename } from '../security/browserBoundaries.js';

/* ────────────────────────── Types ────────────────────────── */
interface UploadTask {
  id: string;
  file: File;
  status: 'PENDING' | 'UPLOADING' | 'WAITING_SERVER' | 'SUCCESS' | 'ERROR';
  progress: number;
  errorMsg?: string;
  documentId?: string;
}

interface BankDoc {
  documentId: string;
  status: string;
  filename?: string;
  createdAt?: string;
  batchId?: string;
  docType?: string;
  classificationRoute?: string;
}

interface BankTransaction {
  date?: string;
  description?: string;
  reference?: string;
  direction: string;
  amount?: number;
  balanceAfter?: number;
  category?: string;
}

interface BankResult {
  bank?: { name?: string };
  account?: { holder?: string; numberMasked?: string; clabeMasked?: string; currency?: string };
  statement?: { periodStart?: string; periodEnd?: string };
  balances?: { opening?: number; closing?: number; totalCredits?: number; totalDebits?: number };
  transactions: BankTransaction[];
  accountType?: string;
  bankCountry?: string;
  fees?: { totalFees?: number; ivaOnFees?: number };
  interestEarned?: number;
  interestCharged?: number;
  summaryText?: string;
}

const MAX_CONCURRENT = 3;
const ALLOWED_TYPES = ['application/pdf', 'image/jpeg', 'image/png', 'image/tiff'];
const isRecord = (value: unknown): value is Record<string, unknown> => (
  value !== null && typeof value === 'object' && !Array.isArray(value)
);

/* ────────────────────────── Page ────────────────────────── */
export const BankStatements: React.FC = () => {
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);

  /* View state */
  const [activeView, setActiveView] = useState<'upload' | 'list'>('upload');

  /* Upload state */
  const [tasks, setTasks] = useState<UploadTask[]>([]);
  const [batch, setBatch] = useState<BatchResponse | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [batchStatus, setBatchStatus] = useState<'IDLE' | 'CREATING' | 'PROCESSING' | 'COMPLETED' | 'ERROR'>('IDLE');
  const [batchErrorMsg, setBatchErrorMsg] = useState<string | null>(null);

  /* List & detail state */
  const [bankDocs, setBankDocs] = useState<BankDoc[]>([]);
  const [loadingDocs, setLoadingDocs] = useState(false);
  const [selectedDoc, setSelectedDoc] = useState<BankDoc | null>(null);
  const [resultData, setResultData] = useState<BankResult | null>(null);
  const [loadingResult, setLoadingResult] = useState(false);
  const [txnFilter, setTxnFilter] = useState<'all' | 'credit' | 'debit'>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState('');

  /* ──── Upload helpers (reuse BulkUpload pattern) ──── */
  const addFiles = (selectedFiles: FileList | File[]) => {
    const newTasks: UploadTask[] = [];
    Array.from(selectedFiles).forEach(file => {
      if (ALLOWED_TYPES.includes(file.type)) {
        newTasks.push({ id: crypto.randomUUID(), file, status: 'PENDING', progress: 0 });
      }
    });
    if (newTasks.length > 0) setTasks(prev => [...prev, ...newTasks]);
  };

  const updateTask = useCallback((id: string, u: Partial<UploadTask>) => {
    setTasks(prev => prev.map(t => t.id === id ? { ...t, ...u } : t));
  }, []);

  const processSingleTask = useCallback(async (task: UploadTask, batchId: string) => {
    updateTask(task.id, { status: 'WAITING_SERVER', progress: 0 });
    try {
      const ik = crypto.randomUUID();
      const res = await documentApi.createDocument(task.file, ik, batchId);
      updateTask(task.id, { documentId: res.id });
      if (!res.upload) throw new Error('Sin instrucciones de subida.');
      updateTask(task.id, { status: 'UPLOADING' });
      await uploadFileToPresignedUrl(task.file, res.upload, p => updateTask(task.id, { progress: p }));
      updateTask(task.id, { status: 'WAITING_SERVER' });
      await documentApi.submitDocument(res.id);
      updateTask(task.id, { status: 'SUCCESS', progress: 100 });
    } catch (err: unknown) {
      const errorMsg = axios.isAxiosError(err)
        ? 'Error de red S3 / API'
        : 'No fue posible procesar el documento.';
      updateTask(task.id, { status: 'ERROR', errorMsg });
    }
  }, [updateTask]);

  useEffect(() => {
    if (batchStatus !== 'PROCESSING' || !batch) return;
    const pending = tasks.filter(t => t.status === 'PENDING');
    const running = tasks.filter(t => t.status === 'UPLOADING' || t.status === 'WAITING_SERVER');
    if (pending.length === 0 && running.length === 0) { setBatchStatus('COMPLETED'); return; }
    const slots = MAX_CONCURRENT - running.length;
    if (slots > 0) pending.slice(0, slots).forEach(t => void processSingleTask(t, batch.batchId));
  }, [tasks, batchStatus, batch, processSingleTask]);

  const handleStartBatch = async () => {
    if (tasks.length === 0) return;
    try {
      setBatchStatus('CREATING');
      setBatchErrorMsg(null);
      const newBatch = await batchApi.createBatch({ description: `Estados de Cuenta – ${tasks.length} archivos` });
      setBatch(newBatch);
      setBatchStatus('PROCESSING');
    } catch {
      setBatchStatus('ERROR');
      setBatchErrorMsg('Error creando lote');
    }
  };

  /* ──── List tab ──── */
  const fetchBankDocs = useCallback(async () => {
    setLoadingDocs(true);
    try {
      const client = getApiClient();
      const resp = await client.get('/analytics/docs?classRoute=bank-extract');
      const docs: BankDoc[] = resp.data?.documents || [];
      setBankDocs(docs);
    } catch {
      setBankDocs([]);
    }
    setLoadingDocs(false);
  }, []);

  useEffect(() => {
    if (activeView === 'list') void fetchBankDocs();
  }, [activeView, fetchBankDocs]);

  /* ──── Detail view ──── */
  const openDetail = async (doc: BankDoc) => {
    setSelectedDoc(doc);
    setResultData(null);
    setLoadingResult(true);
    setTxnFilter('all');
    setCategoryFilter('all');
    setSearchTerm('');
    try {
      const data = await documentApi.getDocumentResult(doc.documentId);
      const downloadUrl = typeof data.downloadUrl === 'string' ? data.downloadUrl : null;
      let raw: unknown = null;
      if (downloadUrl) {
        const jsonResp = await fetch(requireHttpsUrl(downloadUrl), {
          credentials: 'omit',
          referrerPolicy: 'no-referrer',
        });
        if (!jsonResp.ok) throw new Error('RESULT_DOWNLOAD_FAILED');
        raw = await jsonResp.json();
      } else {
        raw = data;
      }
      if (!isRecord(raw)) throw new Error('RESULT_INVALID');
      const transactions = Array.isArray(raw.transactions) ? raw.transactions : [];
      const normalizedTransactions: BankTransaction[] = transactions
        .filter(isRecord)
        .map((transaction) => ({
          date: typeof transaction.date === 'string' ? transaction.date : undefined,
          description: typeof transaction.description === 'string' ? transaction.description : '',
          reference: typeof transaction.reference === 'string' ? transaction.reference : undefined,
          direction: typeof transaction.direction === 'string' ? transaction.direction : 'unknown',
          amount: Number(transaction.amount) || 0,
          balanceAfter: transaction.balanceAfter == null ? undefined : Number(transaction.balanceAfter),
          category: typeof transaction.category === 'string' ? transaction.category : undefined,
        }));
      setResultData({ ...(raw as Partial<BankResult>), transactions: normalizedTransactions });
    } catch {
      setResultData(null);
    }
    setLoadingResult(false);
  };

  /* ──── Computed ──── */
  const filteredTxns = (resultData?.transactions ?? []).filter(t => {
    if (txnFilter !== 'all' && t.direction !== txnFilter) return false;
    if (categoryFilter !== 'all' && t.category !== categoryFilter) return false;
    if (searchTerm && !t.description?.toLowerCase().includes(searchTerm.toLowerCase())) return false;
    return true;
  });

  const categories = [...new Set((resultData?.transactions ?? []).map(t => t.category).filter(Boolean))];
  const totalCompleted = tasks.filter(t => t.status === 'SUCCESS').length;
  const totalFailed = tasks.filter(t => t.status === 'ERROR').length;
  const getOverallProgress = () => {
    if (tasks.length === 0) return 0;
    return Math.floor(tasks.reduce((a, t) => a + (t.status === 'SUCCESS' ? 100 : t.progress), 0) / tasks.length);
  };

  /* ──── CSV Download ──── */
  const [downloadingCsv, setDownloadingCsv] = useState(false);

  const handleDownloadCsv = async (docId: string) => {
    setDownloadingCsv(true);
    try {
      const client = getApiClient();
      const res = await client.get('/analytics/export-bank', {
        params: { documentIds: docId },
        responseType: 'blob',
      });
      const disposition = res.headers['content-disposition'] || '';
      const filenameMatch = disposition.match(/filename=([^;]+)/i);
      const fallback = `estado_cuenta_${docId.substring(0, 12)}.csv`;
      const filename = safeDownloadFilename(
        filenameMatch ? filenameMatch[1].replace(/"/g, '').trim() : null,
        fallback,
      );
      const objectUrl = window.URL.createObjectURL(res.data);
      const a = document.createElement('a');
      a.href = objectUrl;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(objectUrl);
    } catch {
      setBatchErrorMsg('No fue posible descargar el reporte CSV.');
    }
    setDownloadingCsv(false);
  };

  const fmtMoney = (v?: number | null, cur?: string) =>
    v != null ? `${cur === 'USD' ? '$' : cur === 'MXN' ? '$' : ''}${v.toLocaleString('en-US', { minimumFractionDigits: 2 })} ${cur || ''}` : '—';

  /* ────────────────────────── RENDER ────────────────────────── */
  return (
    <div className="flex flex-col gap-8 w-full max-w-6xl mx-auto">

      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 animate-fade-in">
        <div>
          <h2 className="text-3xl font-bold m-0 text-slate-50">
            <span className="inline-flex items-center gap-3">
              <span className="w-10 h-10 rounded-xl bg-cyan-500/10 text-cyan-400 flex items-center justify-center">
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" /></svg>
              </span>
              Estados de Cuenta Bancarios
            </span>
          </h2>
          <p className="text-slate-400 m-0 mt-2 text-base">Sube y analiza estados de cuenta de cualquier banco — México e internacional.</p>
        </div>
        <div className="flex gap-2">
          {(['upload', 'list'] as const).map(v => (
            <button key={v} onClick={() => { setActiveView(v); setSelectedDoc(null); }}
              className={`px-4 py-2 rounded-lg text-sm font-semibold transition-all flex items-center gap-2 ${
                activeView === v
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                  : 'bg-slate-800/50 text-slate-400 border border-slate-700 hover:border-slate-600'
              }`}>
              {v === 'upload' ? (
                <><svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" /></svg>Subir</>
              ) : (
                <><svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" /></svg>Historial</>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* ════════════════════ UPLOAD TAB ════════════════════ */}
      {activeView === 'upload' && (
        <div className="flex flex-col gap-6">
          {batchStatus === 'IDLE' && (
            <div onDragOver={e => { e.preventDefault(); setIsDragging(true); }}
                 onDragLeave={e => { e.preventDefault(); setIsDragging(false); }}
                 onDrop={e => { e.preventDefault(); setIsDragging(false); if (e.dataTransfer.files?.length) addFiles(e.dataTransfer.files); }}
                 className={`border-2 border-dashed p-10 text-center rounded-2xl transition-all min-h-[200px] flex flex-col items-center justify-center ${isDragging ? 'border-cyan-500 bg-cyan-500/5' : 'border-slate-700 bg-slate-900/50'}`}>
              <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-cyan-500/20 to-blue-500/20 flex items-center justify-center mb-4 border border-cyan-500/20">
                <svg className="w-7 h-7 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" /></svg>
              </div>
              <h3 className="m-0 mb-1 text-lg font-semibold text-slate-50">Arrastra estados de cuenta</h3>
              <p className="text-slate-400 text-sm mb-4">PDF, JPG, PNG o TIFF — de cualquier banco</p>
              <div className="flex flex-wrap gap-2 justify-center mb-4">
                {['BBVA', 'Banorte', 'Santander', 'Banamex', 'HSBC', 'Scotiabank', 'Chase', 'BofA'].map(b => (
                  <span key={b} className="text-xs bg-slate-800/80 text-slate-400 px-2.5 py-1 rounded-full border border-slate-700/50">{b}</span>
                ))}
              </div>
              <button onClick={() => fileInputRef.current?.click()} className="btn-outline text-sm mt-2">Seleccionar Archivos</button>
              <input type="file" multiple ref={fileInputRef} className="hidden" accept={ALLOWED_TYPES.join(',')} onChange={e => e.target.files && addFiles(e.target.files)} />
            </div>
          )}

          {/* Batch progress */}
          {batchStatus !== 'IDLE' && (
            <div className="glass-card p-6 flex flex-col gap-4">
              <div className="flex justify-between items-center">
                <div>
                  <h3 className="m-0 text-lg font-semibold text-slate-50">Procesando Estados de Cuenta</h3>
                  {batch && <p className="text-xs text-slate-400 m-0 mt-1">Lote: {batch.batchId.substring(0, 12)}…</p>}
                </div>
                <div className="text-right">
                  <div className="text-2xl font-bold text-cyan-400">{getOverallProgress()}%</div>
                  <div className="text-xs text-slate-400">{totalCompleted} ok · {totalFailed} error · {tasks.length} total</div>
                </div>
              </div>
              <div className="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
                <div className="bg-gradient-to-r from-cyan-500 to-blue-500 h-full transition-all duration-300" style={{ width: `${getOverallProgress()}%` }} />
              </div>
              {batchErrorMsg && <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded-md text-sm text-rose-400">{batchErrorMsg}</div>}
              {batchStatus === 'COMPLETED' && (
                <div className="flex gap-3 items-center mt-2">
                  <button onClick={() => navigate(`/batch/${batch?.batchId}`)} className="btn-outline text-sm px-4 py-2 border-cyan-500/40 text-cyan-400 hover:bg-cyan-500/10">Ver Lote</button>
                  <button onClick={() => { setActiveView('list'); fetchBankDocs(); }} className="btn-outline text-sm px-4 py-2 border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/10">Ver Resultados</button>
                </div>
              )}
            </div>
          )}

          {/* File list */}
          {tasks.length > 0 && (
            <div className="flex flex-col gap-3">
              <div className="flex justify-between items-center">
                <h4 className="m-0 text-slate-200 font-medium">{tasks.length} archivo{tasks.length !== 1 ? 's' : ''}</h4>
                {batchStatus === 'IDLE' && <button onClick={handleStartBatch} className="btn-primary text-sm px-5 py-2.5">🏦 Iniciar Procesamiento</button>}
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {tasks.map(t => (
                  <div key={t.id} className={`glass-card p-4 flex flex-col gap-2 transition-colors ${t.status === 'ERROR' ? 'border-rose-500/30' : t.status === 'SUCCESS' ? 'border-emerald-500/30' : ''}`}>
                    <div className="flex justify-between items-start">
                      <div className="flex items-center truncate">
                        <div className={`w-8 h-8 rounded shrink-0 flex items-center justify-center mr-3 ${t.status === 'SUCCESS' ? 'bg-emerald-500/10 text-emerald-400' : t.status === 'ERROR' ? 'bg-rose-500/10 text-rose-400' : 'bg-cyan-500/10 text-cyan-400'}`}>
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" /><polyline points="14 2 14 8 20 8" /></svg>
                        </div>
                        <div className="truncate pr-2">
                          <h5 className="m-0 text-sm font-medium text-slate-200 truncate">{t.file.name}</h5>
                          <span className="text-xs text-slate-500">{(t.file.size / 1024 / 1024).toFixed(2)} MB</span>
                        </div>
                      </div>
                      {batchStatus === 'IDLE' && <button onClick={() => setTasks(prev => prev.filter(x => x.id !== t.id))} className="text-slate-500 hover:text-slate-300 bg-transparent border-none cursor-pointer p-1">✕</button>}
                    </div>
                    {batchStatus !== 'IDLE' && (
                      <div>
                        <span className={`text-xs font-medium ${t.status === 'SUCCESS' ? 'text-emerald-400' : t.status === 'ERROR' ? 'text-rose-400' : 'text-cyan-400'}`}>
                          {t.status === 'PENDING' && 'En cola…'}{t.status === 'WAITING_SERVER' && 'Sincronizando…'}{t.status === 'UPLOADING' && `Subiendo ${t.progress}%`}{t.status === 'SUCCESS' && '✓ Completado'}{t.status === 'ERROR' && '✕ Error'}
                        </span>
                        <div className="w-full bg-slate-800 rounded-full h-1 mt-1 overflow-hidden">
                          <div className={`h-full transition-all ${t.status === 'ERROR' ? 'bg-rose-500' : t.status === 'SUCCESS' ? 'bg-emerald-500' : 'bg-cyan-500'}`} style={{ width: `${t.progress}%` }} />
                        </div>
                        {t.errorMsg && <p className="m-0 mt-1 text-xs text-rose-400 truncate">{t.errorMsg}</p>}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ════════════════════ LIST / DETAIL TAB ════════════════════ */}
      {activeView === 'list' && !selectedDoc && (
        <div className="flex flex-col gap-4">
          <div className="flex justify-between items-center">
            <h3 className="m-0 text-xl font-semibold text-slate-100">Documentos Bancarios Procesados</h3>
            <button onClick={fetchBankDocs} disabled={loadingDocs} className="btn-outline text-xs px-3 py-1.5 border-cyan-500/40 text-cyan-400">
              {loadingDocs ? 'Cargando…' : '↻ Actualizar'}
            </button>
          </div>

          {loadingDocs ? (
            <div className="flex items-center justify-center py-16">
              <div className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin mr-3" />
              <span className="text-slate-400">Cargando estados de cuenta…</span>
            </div>
          ) : bankDocs.length === 0 ? (
            <div className="glass-card p-12 text-center">
              <div className="w-16 h-16 rounded-2xl bg-slate-800 flex items-center justify-center mx-auto mb-4 border border-slate-700">
                <svg className="w-8 h-8 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" /></svg>
              </div>
              <p className="text-slate-400 mb-4">Aún no hay estados de cuenta bancarios procesados.</p>
              <button onClick={() => setActiveView('upload')} className="btn-outline text-sm px-4 py-2 border-cyan-500/40 text-cyan-400">Subir Estado de Cuenta</button>
            </div>
          ) : (
            <div className="grid gap-3">
              {bankDocs.map(doc => (
                <button key={doc.documentId} onClick={() => openDetail(doc)}
                  className="glass-card p-4 text-left flex items-center gap-4 transition-all hover:-translate-y-0.5 hover:border-cyan-500/30 cursor-pointer w-full bg-transparent">
                  <div className="w-10 h-10 rounded-xl bg-cyan-500/10 text-cyan-400 flex items-center justify-center shrink-0">
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" /></svg>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-slate-200 truncate">{doc.filename || doc.documentId.substring(0, 16) + '…'}</span>
                      <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${doc.status?.includes('COMPLETED') || doc.status?.includes('EXTRACTED') ? 'bg-emerald-500/20 text-emerald-400' : doc.status?.includes('FAIL') ? 'bg-rose-500/20 text-rose-400' : 'bg-amber-500/20 text-amber-400'}`}>{doc.status}</span>
                    </div>
                    <span className="text-xs text-slate-500">{doc.createdAt ? new Date(doc.createdAt).toLocaleString() : ''}</span>
                  </div>
                  <svg className="w-4 h-4 text-slate-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ════════════════════ DETAIL VIEW ════════════════════ */}
      {activeView === 'list' && selectedDoc && (
        <div className="flex flex-col gap-6">
          <div className="flex items-center justify-between w-full">
            <button onClick={() => setSelectedDoc(null)} className="flex items-center gap-2 text-sm text-slate-400 hover:text-slate-200 transition-colors bg-transparent border-none cursor-pointer p-0">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" /></svg>
              Volver a la lista
            </button>
            {resultData && (
              <button
                onClick={() => handleDownloadCsv(selectedDoc.documentId)}
                disabled={downloadingCsv}
                className="flex items-center gap-2 px-4 py-2 rounded-lg font-semibold text-sm bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500 hover:text-white border border-cyan-500/20 hover:border-cyan-500 transition-all shadow-lg disabled:opacity-40 disabled:cursor-not-allowed"
              >
                {downloadingCsv ? (
                  <div className="w-4 h-4 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
                ) : (
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
                )}
                {downloadingCsv ? 'Descargando...' : 'Exportar CSV'}
              </button>
            )}
          </div>

          {loadingResult ? (
            <div className="flex items-center justify-center py-16">
              <div className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin mr-3" />
              <span className="text-slate-400">Cargando resultado de extracción…</span>
            </div>
          ) : !resultData ? (
            <div className="glass-card p-12 text-center">
              <p className="text-slate-400">No se encontró resultado de extracción para este documento.</p>
              <Link to={`/document/${selectedDoc.documentId}`} className="text-cyan-400 text-sm mt-2 inline-block hover:text-cyan-300">Ver detalle del documento →</Link>
            </div>
          ) : (
            <>
              {/* Header summary */}
              <div className="glass-card p-6">
                <div className="flex flex-wrap items-start justify-between gap-4 mb-4">
                  <div>
                    <div className="flex items-center gap-3 mb-2">
                      <span className="text-2xl font-bold text-white">{resultData.bank?.name || 'Banco no detectado'}</span>
                      {resultData.bankCountry && <span className="text-xs bg-slate-700 px-2 py-0.5 rounded-full text-slate-300">{resultData.bankCountry}</span>}
                      {resultData.accountType && <span className="text-xs bg-cyan-500/20 text-cyan-400 px-2 py-0.5 rounded-full border border-cyan-500/20">{resultData.accountType}</span>}
                    </div>
                    {resultData.account?.holder && <p className="text-slate-300 text-sm m-0">{resultData.account.holder}</p>}
                    {resultData.account?.numberMasked && <p className="text-slate-500 text-xs m-0 mt-1">Cuenta: {resultData.account.numberMasked}</p>}
                    {resultData.account?.clabeMasked && <p className="text-slate-500 text-xs m-0">CLABE: {resultData.account.clabeMasked}</p>}
                    {resultData.summaryText && <p className="text-slate-400 text-xs m-0 mt-2 italic">{resultData.summaryText}</p>}
                  </div>
                  <div className="text-right">
                    <p className="text-xs text-slate-400 m-0">Periodo</p>
                    <p className="text-sm font-medium text-slate-200 m-0">{resultData.statement?.periodStart || '?'} → {resultData.statement?.periodEnd || '?'}</p>
                    <p className="text-xs text-slate-400 m-0 mt-1">Moneda: <strong className="text-slate-200">{resultData.account?.currency || '?'}</strong></p>
                  </div>
                </div>

                {/* Balance cards */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4">
                  {[
                    { label: 'Saldo Inicial', value: resultData.balances?.opening, color: 'text-slate-200' },
                    { label: 'Saldo Final', value: resultData.balances?.closing, color: 'text-white font-bold' },
                    { label: 'Total Créditos', value: resultData.balances?.totalCredits, color: 'text-emerald-400' },
                    { label: 'Total Débitos', value: resultData.balances?.totalDebits, color: 'text-rose-400' },
                  ].map(({ label, value, color }) => (
                    <div key={label} className="bg-slate-800/50 rounded-xl p-4 border border-slate-700/50">
                      <p className="text-xs text-slate-400 m-0 mb-1">{label}</p>
                      <p className={`text-lg m-0 ${color}`}>{fmtMoney(value, resultData.account?.currency)}</p>
                    </div>
                  ))}
                </div>

                {/* Interest & fees */}
                {(resultData.fees || resultData.interestEarned || resultData.interestCharged) && (
                  <div className="flex flex-wrap gap-4 mt-4 pt-4 border-t border-slate-800">
                    {resultData.fees?.totalFees != null && (
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-slate-400">Comisiones:</span>
                        <span className="text-sm text-amber-400 font-medium">{fmtMoney(resultData.fees.totalFees, resultData.account?.currency)}</span>
                        {resultData.fees.ivaOnFees != null && <span className="text-xs text-slate-500">(IVA: {fmtMoney(resultData.fees.ivaOnFees)})</span>}
                      </div>
                    )}
                    {resultData.interestEarned != null && (
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-slate-400">Intereses Ganados:</span>
                        <span className="text-sm text-emerald-400 font-medium">{fmtMoney(resultData.interestEarned, resultData.account?.currency)}</span>
                      </div>
                    )}
                    {resultData.interestCharged != null && (
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-slate-400">Intereses Cobrados:</span>
                        <span className="text-sm text-rose-400 font-medium">{fmtMoney(resultData.interestCharged, resultData.account?.currency)}</span>
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Filters */}
              <div className="flex flex-wrap items-center gap-3">
                <div className="flex bg-slate-800/80 rounded-lg border border-slate-700/50 p-0.5">
                  {(['all', 'credit', 'debit'] as const).map(f => (
                    <button key={f} onClick={() => setTxnFilter(f)}
                      className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${txnFilter === f ? 'bg-cyan-500/20 text-cyan-400' : 'text-slate-400 hover:text-slate-200'}`}>
                      {f === 'all' ? 'Todos' : f === 'credit' ? '↑ Créditos' : '↓ Débitos'}
                    </button>
                  ))}
                </div>
                {categories.length > 0 && (
                  <select value={categoryFilter} onChange={e => setCategoryFilter(e.target.value)}
                    className="bg-slate-800/80 border border-slate-700/50 text-slate-300 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:border-cyan-500/50">
                    <option value="all">Todas las categorías</option>
                    {categories.map(c => <option key={c} value={c!}>{c}</option>)}
                  </select>
                )}
                <input type="text" placeholder="Buscar descripción…" value={searchTerm} onChange={e => setSearchTerm(e.target.value)}
                  className="bg-slate-800/80 border border-slate-700/50 text-slate-300 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:border-cyan-500/50 flex-1 min-w-[150px]" />
                <span className="text-xs text-slate-500">{filteredTxns.length} de {(resultData?.transactions ?? []).length} transacciones</span>
              </div>

              {/* Transactions table */}
              <div className="glass-card overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-slate-800">
                      <th className="text-left p-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">Fecha</th>
                      <th className="text-left p-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">Descripción</th>
                      <th className="text-left p-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">Categoría</th>
                      <th className="text-left p-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">Referencia</th>
                      <th className="text-right p-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">Monto</th>
                      <th className="text-right p-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">Saldo</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredTxns.map((t, i) => (
                      <tr key={i} className="border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors">
                        <td className="p-3 text-slate-300 whitespace-nowrap font-mono text-xs">{t.date || '—'}</td>
                        <td className="p-3 text-slate-200 max-w-xs truncate" title={t.description}>{t.description || '—'}</td>
                        <td className="p-3">
                          {t.category ? (
                            <span className="text-xs px-2 py-0.5 rounded-full bg-slate-700/50 text-slate-300 border border-slate-600/30">{t.category}</span>
                          ) : '—'}
                        </td>
                        <td className="p-3 text-slate-500 text-xs font-mono">{t.reference || '—'}</td>
                        <td className={`p-3 text-right font-medium whitespace-nowrap ${t.direction === 'credit' ? 'text-emerald-400' : 'text-rose-400'}`}>
                          {t.direction === 'credit' ? '+' : '−'} {typeof t.amount === 'number' ? t.amount.toLocaleString('en-US', { minimumFractionDigits: 2 }) : '—'}
                        </td>
                        <td className="p-3 text-right text-slate-400 text-xs whitespace-nowrap">{typeof t.balanceAfter === 'number' ? t.balanceAfter.toLocaleString('en-US', { minimumFractionDigits: 2 }) : '—'}</td>
                      </tr>
                    ))}
                    {filteredTxns.length === 0 && (
                      <tr><td colSpan={6} className="p-8 text-center text-slate-500 text-sm">No hay transacciones que coincidan con los filtros.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>

              {/* Link to full detail */}
              <div className="flex gap-3">
                <Link to={`/document/${selectedDoc.documentId}`} className="btn-outline text-xs px-3 py-1.5 border-cyan-500/40 text-cyan-400 hover:bg-cyan-500/10 no-underline">
                  Ver Document Page completa →
                </Link>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
};
