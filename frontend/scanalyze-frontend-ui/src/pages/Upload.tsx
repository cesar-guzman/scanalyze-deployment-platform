import { useState, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { documentApi } from '../api/documentApi';
import { uploadFileToPresignedUrl } from '../api/uploadApi';
import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import { DocumentIcon, ArrowUpTrayIcon, XCircleIcon, CheckCircleIcon } from '@heroicons/react/24/outline';
import type { UiStage } from '../domain/documents';

export default function UploadPage() {
  const [file, setFile] = useState<File | null>(null);
  const [stage, setStage] = useState<UiStage>('IDLE');
  const [progress, setProgress] = useState(0);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      setFile(e.dataTransfer.files[0]);
    }
  }, []);

  const resetForm = () => {
    setFile(null);
    setStage('IDLE');
    setProgress(0);
    setErrorMsg(null);
  };

  const handleUpload = async () => {
    if (!file) return;

    setStage('WAITING_SERVER');
    setErrorMsg(null);
    setProgress(0);
    const idempotencyKey = uuidv4();

    try {
      // 1. Create document (idempotent, gets durable result and upload capability)
      const createResponse = await documentApi.createDocument(file, idempotencyKey);
      
      const { durableResponse, uploadCapability } = createResponse;
      const documentId = durableResponse.documentId;

      if (!uploadCapability && durableResponse.status !== 'UPLOAD_PENDING') {
         // It might have been an exact replay that already finished upload
         // or it's a conflict state. Assuming normal flow.
         if(durableResponse.status !== 'UPLOAD_PENDING') {
             navigate(`/document/${documentId}`);
             return;
         }
      }

      if (uploadCapability) {
        setStage('UPLOADING');
        
        // 2. Upload the file to S3/Cloud Storage
        await uploadFileToPresignedUrl(file, uploadCapability, (p) => {
          setProgress(p);
        });
      }

      setStage('PROCESSING_ACTIVE');

      // 3. Submit for processing
      await documentApi.submitDocument(documentId);

      // 4. Redirect to document tracking view
      setStage('SUCCESS');
      navigate(`/document/${documentId}`);

    } catch (err: unknown) {
      setStage('ERROR');
      if (axios.isAxiosError(err)) {
        if (err.response?.data?.message) {
          setErrorMsg(err.response.data.message);
          return;
        }
      }
      if (err instanceof Error) {
        setErrorMsg(err.message || 'Se produjo un error durante la carga.');
      } else {
        setErrorMsg('Se produjo un error durante la carga.');
      }
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 text-white flex flex-col items-center justify-center p-6">
      <div className="w-full max-w-2xl bg-white/10 backdrop-blur-lg rounded-2xl shadow-2xl border border-white/20 p-8">
        
        <div className="text-center mb-8">
          <h1 className="text-4xl font-extrabold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-teal-400 to-blue-500">
            Scanalyze Upload
          </h1>
          <p className="mt-2 text-slate-300 text-sm">
            Sube tu estado de cuenta para extraer y validar los datos de forma segura.
          </p>
        </div>

        <div
          onDragOver={handleDragOver}
          onDrop={handleDrop}
          className={`border-2 border-dashed rounded-xl p-10 flex flex-col items-center justify-center transition-all ${
            file ? 'border-teal-400 bg-teal-400/5' : 'border-white/30 hover:border-white/50 bg-white/5 hover:bg-white/10'
          }`}
        >
          {file ? (
            <div className="flex flex-col items-center space-y-4">
              <DocumentIcon className="w-16 h-16 text-teal-400" />
              <div className="text-center">
                <p className="font-medium text-lg">{file.name}</p>
                <p className="text-sm text-slate-400">{(file.size / 1024 / 1024).toFixed(2)} MB</p>
              </div>
              <button
                onClick={resetForm}
                className="text-xs text-red-400 hover:text-red-300 font-semibold"
                disabled={stage !== 'IDLE' && stage !== 'ERROR'}
              >
                Cambiar archivo
              </button>
            </div>
          ) : (
            <div className="flex flex-col items-center space-y-4 text-slate-300 cursor-pointer" onClick={() => fileInputRef.current?.click()}>
              <ArrowUpTrayIcon className="w-16 h-16 opacity-75" />
              <p className="font-medium text-lg">Arrastra tu archivo aquí</p>
              <p className="text-sm opacity-75">PDF, PNG, JPEG o TIFF hasta 500MB</p>
              <button className="mt-4 px-6 py-2 rounded-full bg-white/10 hover:bg-white/20 font-semibold transition-colors">
                Explorar archivos
              </button>
            </div>
          )}
          <input
            type="file"
            ref={fileInputRef}
            className="hidden"
            accept="application/pdf,image/jpeg,image/png,image/tiff"
            onChange={(e) => {
              if (e.target.files && e.target.files.length > 0) {
                setFile(e.target.files[0]);
              }
            }}
          />
        </div>

        {stage === 'ERROR' && (
          <div className="mt-6 p-4 rounded-lg bg-red-500/20 border border-red-500/50 flex items-start space-x-3">
            <XCircleIcon className="w-6 h-6 text-red-400 shrink-0" />
            <div>
              <h3 className="font-semibold text-red-400">Error de carga</h3>
              <p className="text-sm text-red-200 mt-1">{errorMsg}</p>
            </div>
          </div>
        )}

        {['WAITING_SERVER', 'UPLOADING', 'PROCESSING_ACTIVE'].includes(stage) && (
          <div className="mt-6">
            <div className="flex justify-between text-sm mb-2 font-medium">
              <span className="text-teal-300">
                {stage === 'WAITING_SERVER' && 'Preparando subida...'}
                {stage === 'UPLOADING' && 'Subiendo archivo seguro...'}
                {stage === 'PROCESSING_ACTIVE' && 'Enviando a procesamiento...'}
              </span>
              <span className="text-teal-300">{progress}%</span>
            </div>
            <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-teal-400 to-blue-500 transition-all duration-300 ease-out"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>
        )}

        {stage === 'SUCCESS' && (
          <div className="mt-6 p-4 rounded-lg bg-green-500/20 border border-green-500/50 flex items-center justify-center space-x-3 text-green-400">
            <CheckCircleIcon className="w-6 h-6" />
            <span className="font-semibold">¡Carga exitosa! Redirigiendo...</span>
          </div>
        )}

        <div className="mt-8 flex justify-end">
          <button
            onClick={handleUpload}
            disabled={!file || ['WAITING_SERVER', 'UPLOADING', 'PROCESSING_ACTIVE', 'SUCCESS'].includes(stage)}
            className="px-8 py-3 rounded-full bg-gradient-to-r from-teal-500 to-blue-600 hover:from-teal-400 hover:to-blue-500 font-bold text-white shadow-lg disabled:opacity-50 disabled:cursor-not-allowed transition-all"
          >
            Subir Documento
          </button>
        </div>
      </div>
    </div>
  );
}
