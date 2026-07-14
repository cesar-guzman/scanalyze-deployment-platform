import React, { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { documentApi } from '../api/documentApi';
import { uploadFileToPresignedUrl } from '../api/uploadApi';
import type { UiStage } from '../domain/documents';

const steps = [
  { id: 'create', label: 'Crear' },
  { id: 'upload', label: 'Subir' },
  { id: 'submit', label: 'Enviar' },
  { id: 'process', label: 'Procesar' }
];

export const Upload: React.FC = () => {
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [file, setFile] = useState<File | null>(null);
  const [stage, setStage] = useState<UiStage>('IDLE');
  const [progress, setProgress] = useState(0);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  // Stepper logic
  const currentStepIndex = () => {
    switch (stage) {
      case 'IDLE': return 0;
      case 'WAITING_SERVER': return progress === 0 ? 0 : 2; // Create or Submit
      case 'UPLOADING': return 1;
      case 'PROCESSING_ACTIVE': return 3;
      case 'SUCCESS': return 3;
      default: return 0;
    }
  };

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

  const processFile = (selectedFile: File) => {
    if (!ALLOWED_TYPES.includes(selectedFile.type)) {
      setErrorMsg('Formato inválido. Se admiten: PDF, JPG, PNG, TIFF.');
      setFile(null);
      return;
    }
    setFile(selectedFile);
    setErrorMsg(null);
    setStage('IDLE');
    setProgress(0);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      processFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      processFile(e.target.files[0]);
    }
  };

  const handleUploadClick = async () => {
    if (!file) return;
    try {
      setStage('WAITING_SERVER');
      setProgress(0);
      setErrorMsg(null);

      // 1. Create Document
      const idempotencyKey = crypto.randomUUID();
      const createRes = await documentApi.createDocument(file, idempotencyKey);

      const documentId = createRes.id;
      const instruction = createRes.upload;

      if (!instruction) {
        throw new Error('El backend no respondió con instrucciones de subida.');
      }

      // 2. Upload to S3
      setStage('UPLOADING');
      await uploadFileToPresignedUrl(file, instruction, (percent) => {
        setProgress(percent);
      });

      // 3. Submit for Processing
      setStage('WAITING_SERVER');
      await documentApi.submitDocument(documentId);

      // 4. Navigate
      navigate(`/document/${documentId}`);

    } catch (err: unknown) {
      setStage('ERROR');
      if (axios.isAxiosError(err)) {
          setErrorMsg('Error de red S3 / API');
      } else {
          setErrorMsg('No fue posible procesar el documento.');
      }
    }
  };

  return (
    <div className="flex flex-col gap-10 w-full max-w-4xl mx-auto">
      {/* Horizontal Stepper */}
      <div className="flex justify-between mb-8 relative">
        <div className="absolute top-3 inset-x-0 h-0.5 bg-slate-800 z-0"></div>
        {steps.map((step, index) => {
          const isActive = index === currentStepIndex();
          const isCompleted = index < currentStepIndex();

          return (
            <div key={step.id} className="flex flex-col items-center z-10 relative">
              <div className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-semibold shadow-sm transition-all duration-300
                ${isActive ? 'bg-indigo-600 border-2 border-indigo-400 text-white shadow-[0_0_15px_rgba(79,70,229,0.4)]' :
                  (isCompleted ? 'bg-emerald-500 border-2 border-emerald-400 text-white' : 'bg-slate-900 border-2 border-slate-700 text-slate-400')}`}>
                {isCompleted ? '✓' : index + 1}
              </div>
              <span className={`mt-2 text-xs ${isActive ? 'font-semibold text-slate-50' : 'font-normal text-slate-500'}`}>
                {step.label}
              </span>
            </div>
          );
        })}
      </div>

      {/* Drag and Drop Zone */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`border-2 border-dashed p-12 text-center rounded-2xl transition-all duration-200 min-h-[280px] flex flex-col items-center justify-center
          ${isDragging ? 'border-indigo-500 bg-indigo-500/5' : 'border-slate-700 bg-slate-900/50'}`}
      >
        {stage === 'IDLE' && !file && (
          <>
            <div className="w-16 h-16 rounded-2xl bg-slate-800 flex items-center justify-center mb-6 border border-slate-700 shadow-sm">
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#818cf8" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="12" y1="18" x2="12" y2="12"></line><line x1="9" y1="15" x2="15" y2="15"></line></svg>
            </div>
            <h3 className="m-0 mb-2 text-xl font-semibold text-slate-50">Arrastra un documento</h3>
            <p className="text-slate-400 text-sm mb-8">Soporta PDF, JPG, PNG y TIFF hasta 25MB.</p>

            <button
              onClick={() => fileInputRef.current?.click()}
              className="btn-outline"
            >
              Seleccionar Documento
            </button>
            <input type="file" ref={fileInputRef} className="hidden" accept={ACCEPT_STRING} onChange={handleFileChange} />
          </>
        )}

        {/* Active File Card / Glassmorphism */}
        {file && (
          <div className={`w-full max-w-lg glass-card p-6 ${stage === 'ERROR' ? 'border-rose-500/50' : 'border-indigo-500/30'}`}>

            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center text-left max-w-full overflow-hidden">
                <div className={`w-10 h-10 min-w-10 shrink-0 rounded-lg flex items-center justify-center mr-4
                  ${stage === 'ERROR' ? 'bg-rose-500/10 text-rose-500' : 'bg-indigo-500/10 text-indigo-400'}`}>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
                </div>
                <div className="min-w-0 flex-1">
                  <h4 className="m-0 text-sm font-medium text-slate-50 truncate w-full">{file.name}</h4>
                  <span className="text-xs text-slate-400">{(file.size / 1024 / 1024).toFixed(2)} MB</span>
                </div>
              </div>

              {stage === 'IDLE' && (
                <button onClick={() => setFile(null)} className="ml-2 bg-transparent border-none text-slate-500 hover:text-slate-300 cursor-pointer p-1 transition-colors">
                  ✕
                </button>
              )}
            </div>

            {stage === 'UPLOADING' && (
               <div className="mt-6">
                 <div className="flex justify-between text-xs text-slate-400 mb-2">
                   <span>Sincronizando...</span>
                   <span className="font-semibold text-indigo-400">{progress}%</span>
                 </div>
                 <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                   <div className="bg-indigo-500 h-full transition-all duration-200" style={{ width: `${progress}%`, boxShadow: '0 0 8px #6366f1' }} />
                 </div>
               </div>
            )}

            {stage === 'WAITING_SERVER' && (
              <div className="mt-4 flex items-center text-indigo-400 text-sm font-medium">
                <div className="w-4 h-4 border-2 border-indigo-500/30 border-t-indigo-500 rounded-full animate-spin mr-3"></div>
                Procesando el documento...
              </div>
            )}

            {stage === 'ERROR' && (
               <div className="mt-4 p-4 bg-rose-500/10 rounded-lg border border-rose-500/20 flex items-start text-left">
                 <span className="text-rose-500 mr-3 text-lg leading-none mt-0.5">⚠️</span>
                 <div className="flex-1">
                   <span className="text-rose-400 text-sm font-semibold">La subida falló.</span>
                   <p className="m-0 mt-1 text-rose-500 text-xs break-words"><strong>Error:</strong> {errorMsg}</p>
                 </div>
                 <button
                   onClick={handleUploadClick}
                   className="ml-3 self-center px-3 py-1.5 bg-rose-500/10 text-rose-400 border border-rose-500/20 rounded-md cursor-pointer text-xs font-semibold hover:bg-rose-500/20 transition-colors whitespace-nowrap"
                 >
                   🔄 Reintentar Subida
                 </button>
               </div>
            )}

          </div>
        )}

        {stage === 'IDLE' && file && (
          <button
            onClick={handleUploadClick}
            className="btn-primary mt-8 w-full max-w-lg py-3 text-lg"
          >
            🚀 Iniciar Subida
          </button>
        )}

      </div>
    </div>
  );
};
