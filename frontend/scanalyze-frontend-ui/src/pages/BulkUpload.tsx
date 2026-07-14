import React, { useCallback, useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { documentApi } from '../api/documentApi';
import { batchApi } from '../api/batchApi';
import type { BatchResponse } from '../api/batchApi';
import { uploadFileToPresignedUrl } from '../api/uploadApi';

interface UploadTask {
  id: string;
  file: File;
  status: 'PENDING' | 'UPLOADING' | 'WAITING_SERVER' | 'SUCCESS' | 'ERROR';
  progress: number;
  errorMsg?: string;
  documentId?: string;
}

const MAX_CONCURRENT_UPLOADS = 3;

export const BulkUpload: React.FC = () => {
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [tasks, setTasks] = useState<UploadTask[]>([]);
  const [batch, setBatch] = useState<BatchResponse | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  // Overall batch state
  const [batchStatus, setBatchStatus] = useState<'IDLE' | 'CREATING' | 'PROCESSING' | 'COMPLETED' | 'ERROR'>('IDLE');
  const [batchErrorMsg, setBatchErrorMsg] = useState<string | null>(null);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const ALLOWED_TYPES = ['application/pdf', 'image/jpeg', 'image/png', 'image/tiff'];
  const ACCEPT_STRING = ALLOWED_TYPES.join(',');

  const addFiles = (selectedFiles: FileList | File[]) => {
    const newTasks: UploadTask[] = [];
    Array.from(selectedFiles).forEach((file) => {
      if (ALLOWED_TYPES.includes(file.type)) {
        newTasks.push({
          id: crypto.randomUUID(),
          file,
          status: 'PENDING',
          progress: 0,
        });
      }
    });

    if (newTasks.length > 0) {
      setTasks(prev => [...prev, ...newTasks]);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      addFiles(e.dataTransfer.files);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      addFiles(e.target.files);
    }
  };

  const removeTask = (id: string) => {
    setTasks(prev => prev.filter(t => t.id !== id));
  };

  const updateTask = useCallback((id: string, updates: Partial<UploadTask>) => {
    setTasks(prev => prev.map(t => t.id === id ? { ...t, ...updates } : t));
  }, []);

  const processSingleTask = useCallback(async (task: UploadTask, currentBatchId: string) => {
    updateTask(task.id, { status: 'WAITING_SERVER', progress: 0, errorMsg: undefined });
    try {
      // 1. Create Document
      const idempotencyKey = crypto.randomUUID();
      const createRes = await documentApi.createDocument(task.file, idempotencyKey, currentBatchId);

      const documentId = createRes.id;
      const instruction = createRes.upload;
      updateTask(task.id, { documentId });

      if (!instruction) {
        throw new Error('El backend no respondió con instrucciones de subida.');
      }

      // 2. Upload to S3
      updateTask(task.id, { status: 'UPLOADING' });
      await uploadFileToPresignedUrl(task.file, instruction, (percent) => {
        updateTask(task.id, { progress: percent });
      });

      // 3. Submit for Processing
      updateTask(task.id, { status: 'WAITING_SERVER' });
      await documentApi.submitDocument(documentId);

      updateTask(task.id, { status: 'SUCCESS', progress: 100 });
    } catch (err: unknown) {
      let errorMsg = 'No fue posible procesar el documento.';
      if (axios.isAxiosError(err)) {
          errorMsg = 'Error de red S3 / API';
      }
      updateTask(task.id, { status: 'ERROR', errorMsg });
    }
  }, [updateTask]);

  // Upload runner effect
  useEffect(() => {
    if (batchStatus !== 'PROCESSING') return;
    if (!batch) return;

    const pendingTasks = tasks.filter(t => t.status === 'PENDING');
    const runningTasks = tasks.filter(t => t.status === 'UPLOADING' || t.status === 'WAITING_SERVER');

    // Si terminamos de procesar todos
    if (pendingTasks.length === 0 && runningTasks.length === 0) {
      setBatchStatus('COMPLETED');
      return;
    }

    // Spawn new tasks up to concurrency limit
    const availableSlots = MAX_CONCURRENT_UPLOADS - runningTasks.length;
    if (availableSlots > 0 && pendingTasks.length > 0) {
      const tasksToStart = pendingTasks.slice(0, availableSlots);
      tasksToStart.forEach(task => {
        void processSingleTask(task, batch.batchId);
      });
    }
  }, [tasks, batchStatus, batch, processSingleTask]);

  const handleStartBatch = async () => {
    if (tasks.length === 0) return;

    try {
      setBatchStatus('CREATING');
      setBatchErrorMsg(null);
      // Create batch
      const newBatch = await batchApi.createBatch({
        description: `Batch con ${tasks.length} archivos`
      });
      setBatch(newBatch);
      setBatchStatus('PROCESSING');
    } catch {
      setBatchStatus('ERROR');
      setBatchErrorMsg('Error creando el lote');
    }
  };

  const handleRetryFailed = () => {
    setTasks(prev => prev.map(t => t.status === 'ERROR' ? { ...t, status: 'PENDING', errorMsg: undefined, progress: 0 } : t));
    setBatchStatus('PROCESSING');
  };

  const getOverallProgress = () => {
    if (tasks.length === 0) return 0;
    const totalProgress = tasks.reduce((acc, t) => {
      if (t.status === 'SUCCESS') return acc + 100;
      if (t.status === 'ERROR') return acc; // No aporta al progreso total
      return acc + t.progress;
    }, 0);
    return Math.floor(totalProgress / tasks.length);
  };

  const totalCompleted = tasks.filter(t => t.status === 'SUCCESS').length;
  const totalFailed = tasks.filter(t => t.status === 'ERROR').length;
  const isFinished = batchStatus === 'COMPLETED';

  return (
    <div className="flex flex-col gap-8 w-full max-w-5xl mx-auto">
      <div className="flex flex-col gap-2 mb-2 animate-fade-in">
        <h2 className="text-3xl font-bold m-0 text-slate-50">Carga Masiva de Documentos</h2>
        <p className="text-slate-400 m-0 text-lg">Procesa decenas de archivos (PDF, JPG, PNG, TIFF) en paralelo asignados a un mismo lote.</p>
      </div>

      {batchStatus === 'IDLE' && (
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          className={`border-2 border-dashed p-10 text-center rounded-2xl transition-all duration-200 min-h-[200px] flex flex-col items-center justify-center
            ${isDragging ? 'border-indigo-500 bg-indigo-500/5' : 'border-slate-700 bg-slate-900/50'}`}
        >
          <div className="w-12 h-12 rounded-xl bg-slate-800 flex items-center justify-center mb-4 border border-slate-700 shadow-sm">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#818cf8" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="12" y1="18" x2="12" y2="12"></line><line x1="9" y1="15" x2="15" y2="15"></line></svg>
          </div>
          <h3 className="m-0 mb-1 text-lg font-semibold text-slate-50">Arrastra múltiples documentos</h3>
          <p className="text-slate-400 text-sm mb-6">Soporta PDF, JPG, PNG y TIFF.</p>

          <button
            onClick={() => fileInputRef.current?.click()}
            className="btn-outline text-sm"
          >
            Seleccionar Archivos
          </button>
          <input type="file" multiple ref={fileInputRef} className="hidden" accept={ACCEPT_STRING} onChange={handleFileChange} />
        </div>
      )}

      {batchStatus !== 'IDLE' && (
        <div className="glass-card p-6 flex flex-col gap-4">
          <div className="flex justify-between items-center mb-2">
            <div>
              <h3 className="m-0 text-lg font-semibold text-slate-50">Progreso del Lote</h3>
              {batch && <p className="text-xs text-slate-400 m-0 mt-1">ID: {batch.batchId}</p>}
            </div>
            <div className="text-right">
              <div className="text-2xl font-bold text-indigo-400">{getOverallProgress()}%</div>
              <div className="text-xs text-slate-400">
                {totalCompleted} completados, {totalFailed} fallidos de {tasks.length}
              </div>
            </div>
          </div>
          <div className="w-full bg-slate-800 rounded-full h-2 overflow-hidden shadow-inner">
             <div className="bg-indigo-500 h-full transition-all duration-300" style={{ width: `${getOverallProgress()}%`, boxShadow: '0 0 10px #6366f1' }} />
          </div>

          {batchErrorMsg && (
            <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded-md text-sm text-rose-400">
              Error: {batchErrorMsg}
            </div>
          )}

          {isFinished && (
             <div className="flex flex-col gap-4 mt-2">
               <div className="p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-lg flex items-center justify-between">
                 <div className="flex items-center gap-3 text-emerald-400 font-medium">
                   <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                   Lote Finalizado
                 </div>
                 <div className="flex gap-3">
                   {totalFailed > 0 && (
                     <button onClick={handleRetryFailed} className="btn-outline text-xs px-3 py-1.5 border-amber-500/50 text-amber-500 hover:bg-amber-500/10">
                       Reintentar Fallidos ({totalFailed})
                     </button>
                   )}
                   <button onClick={() => navigate('/dashboard')} className="btn-outline text-xs px-3 py-1.5 border-emerald-500/50 text-emerald-500 hover:bg-emerald-500/10">
                     Volver al Dashboard
                   </button>
                 </div>
               </div>

               <div className="p-4 bg-slate-800/50 border border-slate-700/50 rounded-lg flex flex-col gap-3">
                 <h4 className="text-sm font-semibold text-slate-200 m-0">Exportar Resultados del Lote</h4>
                 <div className="flex flex-wrap gap-3">
                    <button
                      onClick={() => batch?.batchId && batchApi.downloadManifest(batch.batchId)}
                      className="btn-outline text-xs px-3 py-2 border-indigo-500/50 text-indigo-400 hover:bg-indigo-500/10 flex items-center gap-2"
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                      Manifest
                    </button>
                    <button
                      onClick={() => batch?.batchId && batchApi.downloadJson(batch.batchId)}
                      className="btn-outline text-xs px-3 py-2 border-indigo-500/50 text-indigo-400 hover:bg-indigo-500/10 flex items-center gap-2"
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                      JSON Consolidado
                    </button>
                    <button
                      onClick={() => batch?.batchId && batchApi.downloadCsv(batch.batchId)}
                      className="btn-outline text-xs px-3 py-2 border-indigo-500/50 text-indigo-400 hover:bg-indigo-500/10 flex items-center gap-2"
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                      CSV Resumen
                    </button>
                    <button
                      onClick={() => batch?.batchId && batchApi.downloadZip(batch.batchId)}
                      className="btn-outline text-xs px-3 py-2 border-indigo-500/50 text-indigo-400 hover:bg-indigo-500/10 flex items-center gap-2"
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                      Paquete ZIP
                    </button>
                 </div>
               </div>
             </div>
          )}
        </div>
      )}

      {tasks.length > 0 && (
        <div className="flex flex-col gap-3 mt-2">
          <div className="flex justify-between items-center mb-2">
            <h4 className="m-0 text-slate-200 font-medium">Archivos Seleccionados ({tasks.length})</h4>
            {batchStatus === 'IDLE' && (
              <button onClick={handleStartBatch} className="btn-primary text-sm px-4 py-2">
                🚀 Iniciar Lote
              </button>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {tasks.map(task => (
              <div key={task.id} className={`glass-card p-4 flex flex-col gap-3 transition-colors ${
                task.status === 'ERROR' ? 'border-rose-500/30' :
                task.status === 'SUCCESS' ? 'border-emerald-500/30' : 'border-slate-800'
              }`}>
                <div className="flex justify-between items-start overflow-hidden">
                  <div className="flex items-center text-left truncate">
                    <div className={`w-8 h-8 rounded shrink-0 flex items-center justify-center mr-3
                      ${task.status === 'SUCCESS' ? 'bg-emerald-500/10 text-emerald-400' :
                        task.status === 'ERROR' ? 'bg-rose-500/10 text-rose-400' :
                        'bg-indigo-500/10 text-indigo-400'}`}>
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
                    </div>
                    <div className="truncate pr-2">
                       <h5 className="m-0 text-sm font-medium text-slate-200 truncate" title={task.file.name}>{task.file.name}</h5>
                       <span className="text-xs text-slate-500">{(task.file.size / 1024 / 1024).toFixed(2)} MB</span>
                    </div>
                  </div>

                  {batchStatus === 'IDLE' && (
                    <button onClick={() => removeTask(task.id)} className="text-slate-500 hover:text-slate-300 transition-colors p-1 bg-transparent border-none cursor-pointer">✕</button>
                  )}
                </div>

                {batchStatus !== 'IDLE' && (
                  <div>
                    <div className="flex justify-between text-xs mb-1.5">
                      <span className={`font-medium ${
                         task.status === 'SUCCESS' ? 'text-emerald-400' :
                         task.status === 'ERROR' ? 'text-rose-400' : 'text-indigo-400'
                      }`}>
                         {task.status === 'PENDING' && 'En cola...'}
                         {task.status === 'WAITING_SERVER' && 'Sincronizando con backend...'}
                         {task.status === 'UPLOADING' && `Subiendo ${task.progress}%`}
                         {task.status === 'SUCCESS' && 'Completado'}
                         {task.status === 'ERROR' && 'Fallido'}
                      </span>
                    </div>
                    <div className="w-full bg-slate-800 rounded-full h-1 overflow-hidden">
                      <div className={`h-full transition-all duration-200 ${
                         task.status === 'ERROR' ? 'bg-rose-500' :
                         task.status === 'SUCCESS' ? 'bg-emerald-500' : 'bg-indigo-500'
                      }`} style={{ width: `${task.progress}%` }} />
                    </div>
                    {task.errorMsg && (
                      <p className="m-0 mt-2 text-xs text-rose-400 truncate" title={task.errorMsg}>{task.errorMsg}</p>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
