import { useState, useCallback, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from 'react-oidc-context';
import { documentApi } from '../api/documentApi';
import { uploadFileToPresignedUrl } from '../api/uploadApi';
import { v4 as uuidv4 } from 'uuid';
import { DocumentIcon, ArrowUpTrayIcon, XCircleIcon, CheckCircleIcon } from '@heroicons/react/24/outline';
import type { UiStage } from '../domain/documents';
import { DOCUMENT_JOURNEY_CONTRACT_VERSION } from '../contracts/documentJourney.v1';
import {
  clearUploadIntent, fingerprintUpload, readUploadIntent, requireDurableDocument,
  safeUploadError, statusAllowsSubmit, uploadStorageKey, UploadRecoveryError, requireUploadSession,
  writeUploadIntent, type UploadIntent,
} from '../domain/uploadRecovery';

export default function UploadPage() {
  const [file, setFile] = useState<File | null>(null);
  const [stage, setStage] = useState<UiStage>('IDLE');
  const [progress, setProgress] = useState(0);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [intent, setIntent] = useState<UploadIntent | null>(null);
  const [storageKey, setStorageKey] = useState<string | null>(null);
  const [retryDelayed, setRetryDelayed] = useState(false);
  const navigate = useNavigate();
  const auth = useAuth();
  const active = useRef(false);
  const mounted = useRef(false);
  const retryTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);

  useEffect(() => {
    let cancelled = false;
    uploadStorageKey(auth.user?.profile.sub).then(key => {
      const saved = readUploadIntent(key);
      if (cancelled) return;
      setStorageKey(key);
      setIntent(saved);
    }).catch(error => {
      if (cancelled) return;
      setErrorMsg(safeUploadError(error).message);
      setStage('ERROR');
    });
    return () => { cancelled = true; };
  }, [auth.user?.profile.sub]);

  useEffect(() => () => clearTimeout(retryTimer.current), []);

  const chooseFile = useCallback((selected: File | undefined) => {
    if (selected && !active.current) setFile(selected);
  }, []);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      chooseFile(e.dataTransfer.files[0]);
    }
  }, [chooseFile]);

  const resetForm = () => {
    if (intent || active.current) return;
    setFile(null);
    setStage('IDLE');
    setProgress(0);
    setErrorMsg(null);
  };

  const handleUpload = async () => {
    if (!storageKey || active.current || retryDelayed || intent?.phase === 'STOPPED') return;
    if (!intent && !file) return;

    active.current = true;
    setStage('WAITING_SERVER');
    setErrorMsg(null);
    setProgress(0);
    try {
      const subject = auth.user?.profile.sub;
      const requireView = () => {
        if (!mounted.current) throw new UploadRecoveryError('La vista de carga cambió. Recupera la operación desde la página de carga.');
      };
      const requireContext = () => {
        requireView();
        requireUploadSession(subject);
      };
      if (await uploadStorageKey(auth.user?.profile.sub) !== storageKey) {
        throw new UploadRecoveryError('La sesión cambió. Vuelve a abrir la página de carga.');
      }
      requireContext();
      // Read again at action time: another mounted view must not replace an intent.
      let current = readUploadIntent(storageKey);
      if (current?.key !== intent?.key) {
        throw new UploadRecoveryError('El estado de recuperación cambió. Vuelve a abrir la página de carga antes de continuar.');
      }
      const save = (next: UploadIntent) => {
        requireView();
        writeUploadIntent(storageKey, next, current?.key ?? null);
        current = next;
        setIntent(next);
      };
      let capability;
      if (!current) {
        if (!file) return;
        const fileDigest = await fingerprintUpload(file);
        requireContext();
        save({ version: 1, key: uuidv4(), fileDigest, phase: 'CREATE_UNKNOWN' });
        // Persist the original key before the first possible write. A lost
        // response is recovered through reconciliation, never another CREATE.
        const created = await documentApi.createDocument(file, current!.key, undefined, subject);
        const documentId = requireDurableDocument(created.durableResponse);
        save({ ...current!, documentId, phase: 'UPLOAD_PENDING' });
        capability = created.uploadCapability;
      } else if (current.phase === 'CREATE_UNKNOWN') {
        requireContext();
        const recovered = await documentApi.reconcileCreate(current.key, subject);
        if (recovered.schemaVersion !== 'scanalyze.reconciliation.v1'
            || recovered.contractVersion !== DOCUMENT_JOURNEY_CONTRACT_VERSION
            || recovered.operation !== 'documents.create') {
          throw new UploadRecoveryError('La reconciliación no es válida. Conserva esta pestaña y solicita revisión.');
        }
        if (recovered.ledgerState === 'SUCCEEDED') {
          save({ ...current, documentId: requireDurableDocument(recovered.durableResponse), phase: 'UPLOAD_PENDING' });
        } else if (recovered.ledgerState === 'PENDING') {
          throw new UploadRecoveryError('La creación sigue pendiente. Espera unos segundos y vuelve a consultar la misma carga.');
        } else {
          // FAILED_RETRYABLE currently has no executable client retry contract.
          // Unknown, expired and terminal records must never cause a new CREATE.
          save({ ...current, phase: 'STOPPED' });
          throw new UploadRecoveryError('La operación requiere revisión antes de continuar. Conserva esta pestaña; no vuelvas a crear la carga.');
        }
      }

      if (!current?.documentId || current.phase === 'STOPPED') {
        throw new UploadRecoveryError('La carga requiere revisión antes de continuar.');
      }
      const documentId = current.documentId;
      if (!capability) {
        requireContext();
        const status = await documentApi.getDocumentStatus(documentId, subject);
        requireContext();
        if (!statusAllowsSubmit(status, documentId)) {
          clearUploadIntent(storageKey, current.key);
          navigate(`/document/${documentId}`);
          return;
        }
        if (current.phase === 'UPLOAD_PENDING' && status.lifecycle === 'SUBMITTED') {
          // A prior tab may have completed the upload and reached enqueue failure.
          save({ ...current, phase: 'UPLOADED' });
        }
      }

      if (current.phase === 'UPLOAD_PENDING') {
        if (!file) throw new UploadRecoveryError('Selecciona el archivo original para continuar la misma carga.');
        if (await fingerprintUpload(file) !== current.fileDigest) {
          throw new UploadRecoveryError('El archivo no coincide con la carga original. Selecciona exactamente el mismo archivo.');
        }
        requireContext();
        if (!capability) {
          const refreshed = await documentApi.refreshUploadCapability(documentId, subject);
          if (refreshed.documentId !== documentId || refreshed.schemaVersion !== 'scanalyze.upload-capability.v1'
              || refreshed.contractVersion !== DOCUMENT_JOURNEY_CONTRACT_VERSION) {
            throw new UploadRecoveryError('No se pudo confirmar el permiso para continuar esta carga.');
          }
          capability = refreshed.uploadCapability;
        }
        if (!capability) throw new UploadRecoveryError('No hay un permiso de carga disponible. Vuelve a consultar la misma operación.');
        requireContext();
        setStage('UPLOADING');
        await uploadFileToPresignedUrl(file, capability, setProgress);
        save({ ...current, phase: 'UPLOADED' });
      }

      requireContext();
      setStage('PROCESSING_ACTIVE');
      save({ ...current, phase: 'SUBMIT_UNKNOWN' });
      await documentApi.submitDocument(documentId, subject);
      requireContext();
      clearUploadIntent(storageKey, current.key);
      setStage('SUCCESS');
      navigate(`/document/${documentId}`);
    } catch (err: unknown) {
      if (!mounted.current) return;
      setStage('ERROR');
      const safe = safeUploadError(err);
      setErrorMsg(safe.message);
      setRetryDelayed(true);
      retryTimer.current = setTimeout(() => setRetryDelayed(false), Math.max(1000, safe.retryAfterMs));
    } finally {
      active.current = false;
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

        {intent && (
          <p role="status" className="mb-4 text-sm text-teal-200">
            Hay una carga guardada en esta pestaña. Recupera su estado para continuar sin duplicarla.
            Si falta el archivo, vuelve a seleccionar el original. Conserva esta pestaña hasta terminar.
          </p>
        )}

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
                onClick={intent ? () => fileInputRef.current?.click() : resetForm}
                className="text-xs text-red-400 hover:text-red-300 font-semibold"
                disabled={stage !== 'IDLE' && stage !== 'ERROR'}
              >
                {intent ? 'Seleccionar archivo original' : 'Cambiar archivo'}
              </button>
            </div>
          ) : (
            <div className="flex flex-col items-center space-y-4 text-slate-300 cursor-pointer" onClick={() => fileInputRef.current?.click()}>
              <ArrowUpTrayIcon className="w-16 h-16 opacity-75" />
              <p className="font-medium text-lg">Arrastra tu archivo aquí</p>
              <p className="text-sm opacity-75">PDF, PNG, JPEG o TIFF hasta 512 MiB</p>
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
                chooseFile(e.target.files[0]);
              }
            }}
          />
        </div>

        {stage === 'ERROR' && (
          <div role="alert" className="mt-6 p-4 rounded-lg bg-red-500/20 border border-red-500/50 flex items-start space-x-3">
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
            disabled={!storageKey || (!file && !intent) || intent?.phase === 'STOPPED' || retryDelayed || ['WAITING_SERVER', 'UPLOADING', 'PROCESSING_ACTIVE', 'SUCCESS'].includes(stage)}
            className="px-8 py-3 rounded-full bg-gradient-to-r from-teal-500 to-blue-600 hover:from-teal-400 hover:to-blue-500 font-bold text-white shadow-lg disabled:opacity-50 disabled:cursor-not-allowed transition-all"
          >
            {intent ? 'Recuperar carga' : 'Subir Documento'}
          </button>
        </div>
      </div>
    </div>
  );
}
