import { useParams, useNavigate } from 'react-router-dom';
import { useDocumentJourney } from '../hooks/useDocumentJourney';
import { useState, useEffect } from 'react';
import { documentApi } from '../api/documentApi';
import type { DocumentResultResponse } from '../domain/documents';
import { 
  CheckCircleIcon, 
  ExclamationCircleIcon, 
  ArrowPathIcon,
  DocumentTextIcon
} from '@heroicons/react/24/outline';

export default function DocumentPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const { data: status, error: pollingError, isPolling } = useDocumentJourney({
    documentId: id!,
    intervalMs: 2000
  });

  const [result, setResult] = useState<DocumentResultResponse | null>(null);
  const [resultError, setResultError] = useState<string | null>(null);

  useEffect(() => {
    if (status?.lifecycle === 'COMPLETED') {
      // Fetch the result
      documentApi.getDocumentResult(id!)
        .then(res => setResult(res))
        .catch(err => setResultError(err.message || 'Error fetching results'));
    }
  }, [status?.lifecycle, id]);

  const STAGES = [
    { id: 'INGEST', label: 'Ingestión' },
    { id: 'OCR', label: 'Reconocimiento (OCR)' },
    { id: 'CLASSIFY', label: 'Clasificación' },
    { id: 'BANK_EXTRACT', label: 'Extracción Bancaria' },
    { id: 'VALIDATE', label: 'Validación' }
  ];

  const getStageStatus = (stageId: string) => {
    if (!status) return 'pending';
    
    // Si la etapa falló, la etapa actual debe coincidir para mostrar el error,
    // o podríamos inferir que falló antes.
    if (status.lifecycle === 'FAILED') {
      if (status.currentStage === stageId || (status.currentStage === 'TERMINAL' && status.safeFailureCode?.includes(stageId))) return 'error';
    }

    const currentIndex = STAGES.findIndex(s => s.id === status.currentStage);
    const thisIndex = STAGES.findIndex(s => s.id === stageId);

    if (status.lifecycle === 'COMPLETED') return 'success';
    
    if (thisIndex < currentIndex) return 'success';
    if (thisIndex === currentIndex) {
      if (status.stageState === 'RUNNING') return 'running';
      if (status.stageState === 'SUCCEEDED') return 'success';
      if (status.stageState === 'FAILED') return 'error';
      return 'pending';
    }
    return 'pending';
  };

  const renderTimeline = () => {
    return (
      <div className="relative">
        <div className="absolute top-0 bottom-0 left-6 w-0.5 bg-slate-700" />
        <ul className="space-y-6">
          {STAGES.map((stage, idx) => {
            const st = getStageStatus(stage.id);
            return (
              <li key={stage.id} className="relative flex items-center space-x-4">
                <div className={`relative z-10 flex items-center justify-center w-12 h-12 rounded-full border-2 
                  ${st === 'success' ? 'bg-green-500/20 border-green-500 text-green-400' : 
                    st === 'running' ? 'bg-blue-500/20 border-blue-500 text-blue-400' :
                    st === 'error' ? 'bg-red-500/20 border-red-500 text-red-400' :
                    'bg-slate-800 border-slate-600 text-slate-500'}`}
                >
                  {st === 'success' && <CheckCircleIcon className="w-6 h-6" />}
                  {st === 'running' && <ArrowPathIcon className="w-6 h-6 animate-spin" />}
                  {st === 'error' && <ExclamationCircleIcon className="w-6 h-6" />}
                  {st === 'pending' && <span className="text-sm font-semibold">{idx + 1}</span>}
                </div>
                <div className="flex-1">
                  <h3 className={`font-semibold text-lg ${st === 'pending' ? 'text-slate-500' : 'text-white'}`}>
                    {stage.label}
                  </h3>
                  {st === 'running' && <p className="text-sm text-blue-300">Procesando...</p>}
                  {st === 'error' && <p className="text-sm text-red-300">Error durante esta etapa.</p>}
                </div>
              </li>
            );
          })}
        </ul>
      </div>
    );
  };

  const renderResult = () => {
    if (resultError) {
      return (
        <div className="p-4 bg-red-500/20 border border-red-500 rounded-lg text-red-400">
          <p>No se pudo cargar el resultado: {resultError}</p>
        </div>
      );
    }

    if (!result) return null;

    return (
      <div className="mt-8 bg-white/5 p-6 rounded-xl border border-white/10 shadow-inner">
        <div className="flex items-center justify-between mb-6 border-b border-white/10 pb-4">
          <h2 className="text-2xl font-bold text-teal-400">Resultados de Extracción</h2>
          {result.quality && (
            <div className="text-sm bg-teal-500/20 text-teal-300 px-3 py-1 rounded-full border border-teal-500/30">
              Confianza: {(result.quality.overall_confidence * 100).toFixed(0)}%
            </div>
          )}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
          <div className="space-y-2">
            <p className="text-sm text-slate-400">Titular</p>
            <p className="text-lg font-medium text-white">{result.data.account_holder_name || 'No encontrado'}</p>
          </div>
          <div className="space-y-2">
            <p className="text-sm text-slate-400">Banco</p>
            <p className="text-lg font-medium text-white">{result.data.bank_name || 'No encontrado'}</p>
          </div>
          <div className="space-y-2">
            <p className="text-sm text-slate-400">Cuenta</p>
            <p className="font-mono text-lg text-white">{result.data.account_number_mask || '****'}</p>
          </div>
          <div className="space-y-2">
            <p className="text-sm text-slate-400">Fecha de Corte</p>
            <p className="text-lg text-white">{result.data.statement_date || 'No encontrada'}</p>
          </div>
        </div>

        {result.warnings && result.warnings.length > 0 && (
          <div className="mb-6 p-4 bg-yellow-500/20 border border-yellow-500/50 rounded-lg">
            <h4 className="font-semibold text-yellow-400 mb-2">Advertencias</h4>
            <ul className="list-disc pl-5 text-yellow-200 text-sm space-y-1">
              {result.warnings.map((w, i) => <li key={i}>{w.message}</li>)}
            </ul>
          </div>
        )}

        {result.data.transactions && result.data.transactions.length > 0 && (
          <div>
            <h3 className="text-lg font-semibold text-white mb-4">Transacciones Extraídas ({result.data.transactions.length})</h3>
            <div className="overflow-x-auto rounded-lg border border-slate-700">
              <table className="min-w-full text-sm text-left">
                <thead className="text-xs text-slate-400 uppercase bg-slate-800/50">
                  <tr>
                    <th className="px-4 py-3">Fecha</th>
                    <th className="px-4 py-3">Descripción</th>
                    <th className="px-4 py-3 text-right">Monto</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/50">
                  {result.data.transactions.map((tx, i) => (
                    <tr key={i} className="hover:bg-slate-700/20">
                      <td className="px-4 py-3 text-slate-300">{tx.date}</td>
                      <td className="px-4 py-3 text-white">{tx.description}</td>
                      <td className={`px-4 py-3 text-right font-mono ${tx.type === 'CREDIT' ? 'text-green-400' : 'text-slate-300'}`}>
                        {tx.type === 'CREDIT' ? '+' : '-'}${tx.amount.toFixed(2)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
        
        <div className="mt-8 flex gap-4">
          <button 
            onClick={() => navigate('/upload')}
            className="flex-1 py-3 bg-white/5 hover:bg-white/10 rounded-full font-semibold transition-colors border border-white/10"
          >
            Subir Otro Documento
          </button>
        </div>
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-slate-900 text-white p-6 md:p-12">
      <div className="max-w-4xl mx-auto space-y-8">
        
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-teal-400 to-blue-500">
              Rastreo de Documento
            </h1>
            <p className="text-sm text-slate-400 font-mono mt-2">ID: {id}</p>
          </div>
          {isPolling && (
            <div className="flex items-center space-x-2 text-blue-400 bg-blue-500/10 px-4 py-2 rounded-full border border-blue-500/20">
              <ArrowPathIcon className="w-5 h-5 animate-spin" />
              <span className="text-sm font-semibold uppercase tracking-wider">Polling Activo</span>
            </div>
          )}
        </div>

        {pollingError && (
          <div className="p-4 bg-red-500/10 border border-red-500 rounded-lg flex items-center space-x-3 text-red-400">
            <ExclamationCircleIcon className="w-6 h-6 shrink-0" />
            <p>Se perdió la conexión para el rastreo del documento.</p>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <div className="lg:col-span-1 bg-white/5 backdrop-blur-sm p-6 rounded-2xl border border-white/10">
            <h2 className="text-xl font-bold mb-6 text-slate-200">Progreso</h2>
            {renderTimeline()}
          </div>
          
          <div className="lg:col-span-2">
            {status?.lifecycle === 'COMPLETED' ? (
              renderResult()
            ) : status?.lifecycle === 'FAILED' ? (
              <div className="bg-red-500/10 border border-red-500/30 p-8 rounded-2xl text-center">
                <ExclamationCircleIcon className="w-16 h-16 text-red-400 mx-auto mb-4" />
                <h2 className="text-2xl font-bold text-red-400 mb-2">Error de Procesamiento</h2>
                <p className="text-red-200 mb-6">
                  {status.safeFailureCode || 'Ha ocurrido un error inesperado al procesar el documento.'}
                </p>
                <button 
                  onClick={() => navigate('/upload')}
                  className="px-6 py-2 bg-red-500 hover:bg-red-600 text-white rounded-full font-semibold transition-colors"
                >
                  Intentar de nuevo
                </button>
              </div>
            ) : (
              <div className="bg-white/5 backdrop-blur-sm p-12 rounded-2xl border border-white/10 flex flex-col items-center justify-center h-full min-h-[400px] text-center">
                <DocumentTextIcon className="w-24 h-24 text-slate-600 mb-6 animate-pulse" />
                <h2 className="text-2xl font-bold text-slate-300 mb-2">Analizando Documento</h2>
                <p className="text-slate-400 max-w-sm">
                  Nuestro motor de inteligencia artificial está extrayendo y validando la información. Esto puede tomar unos segundos.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
