import React, { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useDocumentPolling } from '../hooks/useDocumentPolling';
import { documentApi } from '../api/documentApi';
import type { DocumentArtifact } from '../api/documentApi';
import type { StageTimelineItem } from '../domain/documents';
import {
  openExternalHttpsUrl,
  requireHttpsUrl,
  safeDownloadFilename,
} from '../security/browserBoundaries.js';

interface ResultDataProps {
  docType?: string;
  subType?: string;
  resultType?: string;
  model?: {
    provider?: string;
    modelId?: string;
  };
  processor?: {
    engine?: string;
    model?: string;
  };
}

interface ArtifactView extends DocumentArtifact {
  id: string;
}

const isRecord = (value: unknown): value is Record<string, unknown> => (
  value !== null && typeof value === 'object' && !Array.isArray(value)
);

type TabView = 'TIMELINE' | 'RESULT' | 'JSON' | 'ARTIFACTS' | 'LOGS';

const STAGE_ICONS: Record<string, string> = {
  RECEIVED: 'check_circle',
  UPLOADED: 'cloud_done',
  OCR: 'memory',
  CLASSIFIED: 'category',
  EXTRACTED: 'psychology',
  VALIDATED: 'shield',
  COMPLETED: 'task_alt',
};

export const DocumentPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const { data, error, isPolling, refetch } = useDocumentPolling({ documentId: id || '' });
  const [activeTab, setActiveTab] = useState<TabView>('TIMELINE');

  const [resultData, setResultData] = useState<(Record<string, unknown> & ResultDataProps) | null>(null);
  const [loadingResult, setLoadingResult] = useState(false);

  const [artifacts, setArtifacts] = useState<ArtifactView[]>([]);
  const [loadingArtifacts, setLoadingArtifacts] = useState(false);
  const [downloadingArtifact, setDownloadingArtifact] = useState<string | null>(null);
  const [operationError, setOperationError] = useState<string | null>(null);

  const status = data?.status;
  const overall = status?.overallStatus || 'PROCESSING';
  const timeline = status?.timeline || [];

  const handleLoadResult = async () => {
    if (!id) return;
    setLoadingResult(true);
    setOperationError(null);
    try {
      const res = await documentApi.getDocumentResult(id);
      if (typeof res.downloadUrl === 'string') {
        const jsonRes = await fetch(requireHttpsUrl(res.downloadUrl), {
          credentials: 'omit',
          referrerPolicy: 'no-referrer',
        });
        if (!jsonRes.ok) throw new Error('RESULT_DOWNLOAD_FAILED');
        const downloaded: unknown = await jsonRes.json();
        if (!isRecord(downloaded)) throw new Error('RESULT_INVALID');
        setResultData(downloaded);
      } else {
        setResultData(res);
      }
    } catch {
      setOperationError('No fue posible cargar el resultado.');
    } finally {
      setLoadingResult(false);
    }
  };

  const handleLoadArtifacts = async () => {
    if (!id) return;
    setLoadingArtifacts(true);
    setOperationError(null);
    try {
      const res = await documentApi.listDocumentArtifacts(id);
      if (res.artifacts) {
        setArtifacts(res.artifacts.map((a) => ({
          ...a,
          id: a.artifactId || a.bucketAlias || 'unknown'
        })));
      }
    } catch {
      setOperationError('No fue posible cargar los artefactos.');
    } finally {
      setLoadingArtifacts(false);
    }
  };

  const handleDownloadArtifact = async (artifactId: string, filename?: string) => {
    if (!id) return;
    setDownloadingArtifact(artifactId);
    setOperationError(null);
    try {
      const url = await documentApi.getArtifactDownloadUrl(id, artifactId);
      const fileRes = await fetch(requireHttpsUrl(url), {
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
      });
      if (!fileRes.ok) throw new Error('ARTIFACT_DOWNLOAD_FAILED');
      const blob = await fileRes.blob();
      const blobUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = blobUrl;
      a.download = safeDownloadFilename(filename, `artifact-${artifactId}.json`);
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(blobUrl);
    } catch {
      setOperationError('No fue posible descargar el artefacto.');
    } finally {
      setDownloadingArtifact(null);
    }
  };

  const handleDownloadJson = () => {
    if (!resultData) return;
    const blob = new Blob([JSON.stringify(resultData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scanalyze-result-${id}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen bg-obsidian text-slate-100 p-8">
        <h1 className="text-red-400 text-xl font-bold mb-4">Connection Error</h1>
        <p className="text-slate-400 mb-6">{error.message}</p>
        <button onClick={refetch} className="px-6 py-2 bg-accent-blue text-white rounded-lg font-semibold shadow-lg hover:bg-blue-600 transition-colors">Force Refresh</button>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen">
        <div className="animate-pulse flex flex-col items-center gap-4">
           <span className="material-symbols-outlined text-indigo-400 text-4xl">hourglass_empty</span>
           <p className="text-sm font-semibold tracking-widest uppercase text-indigo-400/60">Cargando Estado del Documento</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col w-full max-w-6xl mx-auto gap-8 pb-12">
      {operationError && (
        <p role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300">
          {operationError}
        </p>
      )}
      {/* TABS */}
      <div className="flex border-b border-slate-800 w-full overflow-x-auto custom-scrollbar">
        {(['TIMELINE', 'LOGS', 'RESULT', 'JSON', 'ARTIFACTS'] as TabView[]).map((tab) => {
           const isActive = activeTab === tab;
           return (
              <button
                key={tab}
                className={`flex-1 min-w-[80px] flex flex-col items-center py-3 relative cursor-pointer font-display transition-opacity duration-200 hover:opacity-100 ${isActive ? 'opacity-100' : 'opacity-40'}`}
                onClick={() => {
                  setActiveTab(tab);
                  if (tab === 'JSON' || tab === 'RESULT') {
                    if (!resultData && overall === 'COMPLETED') handleLoadResult();
                  }
                  if (tab === 'ARTIFACTS') {
                    if (artifacts.length === 0 && overall === 'COMPLETED') handleLoadArtifacts();
                  }
                }}
              >
                <span className={`text-sm md:text-base font-semibold tracking-wide ${isActive ? 'text-indigo-400' : 'text-slate-400'}`}>
                   {tab === 'LOGS' ? 'Live Logs' : tab}
                </span>
                {isActive && <div className="absolute bottom-0 w-full h-0.5 bg-indigo-500 shadow-[0_0_10px_#6366f1]"></div>}
              </button>
           )
        })}
      </div>

      <div className="flex-1 overflow-visible space-y-8 z-0">

        {/* SUMMARY BADGE CARD */}
        <div className="glass-card p-6 flex gap-6 items-center relative overflow-hidden group">
          <div className="absolute top-0 right-0 w-32 h-32 bg-indigo-500/5 rounded-full blur-3xl -mr-16 -mt-16"></div>

          <div className="relative w-16 h-20 bg-slate-950/40 rounded-lg flex flex-col items-center justify-center border border-slate-800 shrink-0 shadow-inner">
            <span className="material-symbols-outlined text-indigo-400/50 text-3xl">description</span>
            <div className="absolute bottom-1 left-1 right-1 h-1 bg-slate-800 rounded-full overflow-hidden">
              <div className={`h-full bg-indigo-500 ${overall === 'COMPLETED' ? 'w-full' : 'w-2/3 animate-pulse'}`}></div>
            </div>
          </div>

          <div className="flex flex-col min-w-0 z-10 w-full">
            <div className="flex justify-between items-start mb-1 w-full">
               <div className="flex items-center gap-3">
                 <span className={`px-2 py-1 rounded-md text-xs font-bold uppercase tracking-wider ${overall === 'FAILED' ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20' : overall === 'COMPLETED' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20'}`}>
                   {overall}
                 </span>
                 <span className="text-slate-500 text-xs font-medium truncate">ID: {id?.substring(0,8)}</span>
               </div>
            </div>
            <h1 className="text-slate-100 text-xl m-0 mt-2 font-bold truncate">Detalles del Documento</h1>
            <p className="text-slate-400 text-sm m-0 mt-1">
               {isPolling ? 'Polling cluster active...' : 'Processing finalized'}
            </p>
          </div>
        </div>

        {/* TAB CONTENT: TIMELINE */}
        {activeTab === 'TIMELINE' && (
           <div className="relative pl-2">
             {/* Tracks background */}
             <div className="absolute left-[19px] top-4 bottom-4 w-[1px] bg-slate-800"></div>

              {/* Track progress */}
             {(overall === 'PROCESSING' || overall === 'COMPLETED') && (
               <div className={`absolute left-[19px] top-4 w-0.5 bg-gradient-to-b from-emerald-500 via-indigo-500 to-indigo-500 shadow-[0_0_8px_rgba(99,102,241,0.4)] transition-all duration-1000 ${overall === 'COMPLETED' ? 'bottom-4' : 'h-1/2'}`}></div>
             )}

             <div className="space-y-10">
                {timeline.map((item: StageTimelineItem, i: number) => {
                  const isSucceeded = item.state === 'SUCCEEDED';
                  const isRunning = item.state === 'RUNNING';
                  const isFailed = item.state === 'FAILED';
                  const isPending = item.state === 'PENDING' || item.state === 'SKIPPED';
                  const iconName = STAGE_ICONS[item.stage] || 'radio_button_checked';

                  return (
                    <div key={i} className={`relative flex gap-5 items-start ${isPending ? 'opacity-30' : 'opacity-100'}`}>
                      {/* Icon Container */}
                      {isRunning && item.stage === 'EXTRACTED' ? (
                         <div className="relative z-10 flex h-10 w-10 shrink-0 items-center justify-center">
                           <svg className="absolute inset-0 w-10 h-10 -rotate-90">
                             <circle cx="20" cy="20" fill="none" r="18" stroke="rgba(255,255,255,0.05)" strokeWidth="2.5"></circle>
                             <circle className="animate-[pulse-glow_2s_infinite]" cx="20" cy="20" fill="none" r="18" stroke="#6366f1" strokeDasharray="113.1" strokeDashoffset="39.6" strokeWidth="2.5"></circle>
                           </svg>
                           <div className="w-8 h-8 rounded-full bg-indigo-500/10 flex items-center justify-center">
                             <span className="material-symbols-outlined text-indigo-400 text-base">{iconName}</span>
                           </div>
                         </div>
                      ) : (
                         <div className={`z-10 flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-slate-900 shadow-sm ${
                           isSucceeded ? 'border-2 border-emerald-500 text-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.2)]' :
                           isRunning ? 'border-2 border-indigo-500 text-indigo-400 shadow-[0_0_15px_rgba(99,102,241,0.2)]' :
                           isFailed ? 'border-2 border-rose-500 text-rose-500 shadow-[0_0_15px_rgba(244,63,94,0.2)]' :
                           'border-2 border-slate-700 text-slate-500'
                         }`}>
                            <span className="material-symbols-outlined text-lg">{iconName}</span>
                         </div>
                      )}

                      {/* Content */}
                      <div className="flex flex-col pt-1 flex-1">
                         <div className="flex justify-between items-center">
                           <p className={`text-xs font-bold tracking-tight ${isRunning && item.stage === 'EXTRACTED' ? 'text-primary uppercase tracking-widest' : isFailed ? 'text-red-400' : 'text-white'}`}>
                             {item.stage === 'EXTRACTED' ? 'Data Extraction' : item.stage}
                           </p>
                           {isRunning && <span className="text-[12px] font-black text-primary">In Prog.</span>}
                         </div>
                         <p className={`${isRunning && item.stage === 'EXTRACTED' ? 'text-slate-400 text-[10px] mt-1 italic' : 'text-slate-500 text-[10px] mt-0.5'}`}>
                           {item.state} {item.message ? `- ${item.message}` : ''}
                         </p>

                         {/* Pulse loaders for running state */}
                         {isRunning && (
                           <div className="mt-3 flex gap-1">
                             <div className="h-[2px] flex-1 bg-primary/40 animate-pulse"></div>
                             <div className="h-[2px] flex-1 bg-primary/40 animate-pulse" style={{ animationDelay: '150ms' }}></div>
                             <div className="h-[2px] flex-1 bg-primary/10 animate-pulse" style={{ animationDelay: '300ms' }}></div>
                           </div>
                         )}
                      </div>
                    </div>
                  );
                })}
             </div>

             {/* Error Fallback Panel */}
             {overall === 'FAILED' && (
                <div className="mt-8 bg-rose-500/10 p-6 rounded-xl border border-rose-500/30 flex flex-col gap-3 relative overflow-hidden">
                   <div className="absolute top-0 left-0 w-1 h-full bg-rose-500"></div>
                   <h3 className="text-rose-400 font-bold text-lg m-0 flex items-center gap-2">
                     <span className="material-symbols-outlined text-xl">warning</span> Error Crítico
                   </h3>
                   <p className="text-slate-300 text-sm m-0">The document processor encountered an unrecoverable error during the pipeline execution.</p>
                   <Link to="/upload" className="self-start mt-4 btn-danger py-2 text-sm font-bold no-underline">
                     <span>Procesar Nuevo Documento</span>
                     <span className="material-symbols-outlined text-sm">refresh</span>
                   </Link>
                </div>
             )}
           </div>
        )}

        {/* TAB CONTENT: JSON */}
        {activeTab === 'JSON' && (
          <div className="glass-card p-8">
            <div className="flex justify-between items-center mb-6">
               <h2 className="text-lg font-bold m-0 flex items-center gap-2 text-slate-100">
                 <span className="material-symbols-outlined text-indigo-400">data_object</span>
                 Raw JSON Payload
               </h2>
               {overall === 'COMPLETED' && (
                 <button onClick={handleDownloadJson} className="btn-outline text-sm">
                   ⬇ Download JSON
                 </button>
               )}
            </div>

            <div className="relative rounded-xl overflow-hidden border border-slate-800 bg-slate-950/80">
               {overall !== 'COMPLETED' ? (
                 <div className="p-12 text-center flex flex-col items-center justify-center gap-4">
                    <span className="material-symbols-outlined text-slate-600 text-4xl">lock</span>
                    <p className="text-slate-500 m-0 text-sm">Processing must complete to view extracted struct.</p>
                 </div>
               ) : loadingResult ? (
                 <div className="p-12 text-center flex flex-col justify-center items-center gap-4">
                    <span className="material-symbols-outlined text-indigo-400 animate-spin text-3xl">refresh</span>
                    <p className="text-slate-400 m-0 text-sm">Fetching payload from Vault...</p>
                 </div>
               ) : resultData ? (
                 <pre className="p-5 text-[#10b981] text-[11px] overflow-x-auto font-mono custom-scrollbar">
                   {JSON.stringify(resultData, null, 2)}
                 </pre>
               ) : (
                 <div className="p-8 text-center">
                   <p className="text-red-400 text-xs">Failed to fetch result chunk.</p>
                 </div>
               )}
            </div>
          </div>
        )}

        {/* TAB CONTENT: RESULT */}
        {activeTab === 'RESULT' && (
          <div className="glass-card p-8">
             <h2 className="text-lg font-bold text-slate-100 mb-8 m-0 flex items-center gap-2">
               <span className="material-symbols-outlined text-indigo-400">view_list</span>
               Extracted Metadata
             </h2>

             {overall !== 'COMPLETED' ? (
                <div className="p-12 border border-slate-800 rounded-xl bg-slate-950/80 text-center">
                  <p className="text-slate-500 text-sm m-0">Data node inactive. Awaiting extraction phase.</p>
                </div>
             ) : loadingResult ? (
                <div className="p-12 text-center text-slate-400 text-sm animate-pulse">
                  Synchronizing metadata...
                </div>
             ) : resultData ? (
               <div className="text-sm space-y-6">
                 <div className="flex flex-col gap-2 pb-6 border-b border-slate-800">
                   <span className="text-slate-500 text-xs uppercase font-bold tracking-wider">Classification Type</span>
                   <span className="text-slate-100 text-base font-medium">Type: {resultData.docType || resultData.subType || resultData.resultType || 'N/A'}</span>
                 </div>
                 <div className="flex flex-col gap-2 pb-6 border-b border-slate-800">
                   <span className="text-slate-500 text-xs uppercase font-bold tracking-wider">Inference Engine</span>
                   <span className="text-slate-100 text-base font-medium flex items-center gap-3">
                     {resultData.model?.provider || resultData.processor?.engine || 'Unknown'}
                     <span className="text-indigo-400 rounded-md bg-indigo-500/10 px-2 py-1 text-xs border border-indigo-500/20">{resultData.model?.modelId || resultData.processor?.model || 'v1'}</span>
                   </span>
                 </div>
                 <p className="text-slate-500 text-[10px] mt-6 flex items-center gap-1">
                   <span className="material-symbols-outlined text-sm">info</span> Use the JSON tab for full multidimensional schema projection.
                 </p>
               </div>
             ) : (
                <p className="text-xs text-red-400">Node data unavailable.</p>
             )}
          </div>
        )}

        {/* TAB CONTENT: ARTIFACTS */}
        {activeTab === 'ARTIFACTS' && (
          <div className="glass-card p-8">
             <h2 className="text-lg font-bold text-slate-100 mb-2 m-0 flex items-center gap-2">
               <span className="material-symbols-outlined text-indigo-400">inventory_2</span>
               Artefactos del Documento
             </h2>
             <p className="text-slate-400 text-sm mb-8 m-0">Archivos originales y resultados generados por el pipeline de procesamiento.</p>

             {overall === 'COMPLETED' || artifacts.length > 0 ? (
                <div className="space-y-4">
                   {loadingArtifacts ? (
                     <div className="p-12 text-center text-slate-400 text-sm animate-pulse">Cargando artefactos...</div>
                   ) : artifacts.map((artifact, idx: number) => {
                      const isRaw = artifact.id === 'raw';
                      const ct = artifact.contentType || '';
                      const isImage = ct.startsWith('image/');
                      const isPdf = ct === 'application/pdf';
                      const isPreviewable = isRaw && (isImage || isPdf);
                      const fname = artifact.filename || `artifact-${artifact.id}`;

                      const iconName = isRaw ? 'attach_file' : artifact.id === 'ocr' ? 'text_snippet' : artifact.id === 'structured' ? 'data_object' : 'draft';
                      const label = isRaw ? `📎 Archivo Original` : artifact.id === 'ocr' ? '🔍 OCR (Texto Extraído)' : artifact.id === 'structured' ? '📊 Resultado Estructurado' : artifact.id;
                      const sublabel = isRaw ? `${fname} • ${ct}` : artifact.id === 'ocr' ? 'Textract output (JSON)' : artifact.id === 'structured' ? 'Datos extraídos por IA (JSON)' : '';

                      return (
                        <div key={idx} className={`flex flex-col bg-slate-950/80 border rounded-xl overflow-hidden hover:border-indigo-500/50 transition-colors ${isRaw ? 'border-amber-500/30' : 'border-slate-800'}`}>
                          <div className="flex justify-between items-center p-4">
                            <div className="flex items-center gap-4 min-w-0">
                              <div className={`w-10 h-10 rounded-lg flex items-center justify-center shrink-0 ${isRaw ? 'bg-amber-500/10' : 'bg-indigo-500/10'}`}>
                                <span className={`material-symbols-outlined text-xl ${isRaw ? 'text-amber-400' : 'text-indigo-400'}`}>{iconName}</span>
                              </div>
                              <div className="min-w-0">
                                <span className="text-slate-200 text-sm font-semibold block">{label}</span>
                                {sublabel && <span className="text-slate-500 text-xs truncate block">{sublabel}</span>}
                              </div>
                            </div>
                            <div className="flex gap-2 shrink-0 ml-4">
                              {isPreviewable && (
                                <button
                                  onClick={async () => {
                                    if (!id) return;
                                    try {
                                      const url = await documentApi.getArtifactDownloadUrl(id, artifact.id);
                                      openExternalHttpsUrl(url);
                                    } catch { setOperationError('No fue posible previsualizar el artefacto.'); }
                                  }}
                                  className="btn-outline px-3 py-1.5 text-amber-400 border-amber-500/30 hover:bg-amber-500/10 flex items-center gap-1.5"
                                  title="Previsualizar archivo original"
                                >
                                  <span className="material-symbols-outlined text-sm">visibility</span>
                                  <span className="text-xs hidden sm:inline">Preview</span>
                                </button>
                              )}
                              <button
                                onClick={() => handleDownloadArtifact(artifact.id, fname)}
                                className={`btn-outline px-3 py-1.5 flex items-center gap-1.5 ${downloadingArtifact === artifact.id ? 'opacity-50 cursor-not-allowed' : ''}`}
                                title="Descargar artefacto"
                                disabled={downloadingArtifact === artifact.id}
                              >
                                <span className={`${downloadingArtifact === artifact.id ? "animate-spin" : ""} material-symbols-outlined text-sm`}>
                                  {downloadingArtifact === artifact.id ? 'refresh' : 'download'}
                                </span>
                                <span className="text-xs hidden sm:inline">Descargar</span>
                              </button>
                            </div>
                          </div>


                        </div>
                      );
                   })}
                   {artifacts.length === 0 && !loadingArtifacts && (
                     <div className="p-8 text-center border border-slate-800 rounded-xl bg-slate-950/50">
                       <p className="text-slate-500 text-sm italic m-0">No se encontraron artefactos.</p>
                     </div>
                   )}
                </div>
             ) : (
                <div className="p-12 border border-slate-800 rounded-xl bg-slate-950/80 text-center">
                  <p className="text-slate-500 text-sm m-0">Almacenamiento bloqueado. El procesamiento aún no ha completado.</p>
                </div>
             )}
          </div>
        )}

        {/* TAB CONTENT: LOGS */}
        {activeTab === 'LOGS' && (
          <div className="glass-card p-8">
            <h2 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
              <span className="material-symbols-outlined text-primary">terminal</span>
              Live Pipeline Logs
            </h2>
            <div className="bg-black/80 rounded-lg p-4 font-mono text-[11px] min-h-[16rem] max-h-[24rem] overflow-y-auto border border-white/5 custom-scrollbar break-all">
              {timeline.length === 0 && <p className="text-slate-500 italic">Waiting for pipeline events...</p>}
              {timeline.map((item: StageTimelineItem, i: number) => {
                const timeStr = new Date(item.startedAt || new Date()).toLocaleTimeString();
                let colorClass = "text-slate-300";
                if (item.state === 'FAILED') colorClass = "text-red-400";
                if (item.state === 'SUCCEEDED') colorClass = "text-[#10b981]";

                return (
                  <div key={i} className="mb-2 leading-relaxed">
                    <span className="text-slate-500">[{timeStr}]</span>{' '}
                    <span className="text-primary font-bold">[{item.stage.toUpperCase()}]</span>{' '}
                    <span className={colorClass}>{item.state}</span>
                    {item.message && <span className="text-slate-400"> - {item.message}</span>}
                    {item.error && <span className="text-red-400 bg-red-500/10 inline-block px-1 mt-1 border border-red-500/20 rounded-sm">Error: {item.error.message}</span>}
                  </div>
                );
              })}
              {overall === 'PROCESSING' && (
                <div className="flex gap-2 items-center mt-4 text-slate-500 opacity-80">
                  <div className="w-1.5 h-3 bg-primary animate-pulse"></div>
                  Polling network streams...
                </div>
              )}
            </div>
          </div>
        )}

      </div>
    </div>
  );
};
