import { useState, useEffect, useCallback, useRef } from 'react';
import { documentApi } from '../api/documentApi';
import type { DocumentStatusResponse } from '../domain/documents';

interface PollingOptions {
  documentId: string;
  intervalMs?: number;
  maxRetries?: number;
}

export const useDocumentPolling = ({
  documentId,
  intervalMs = 3000,
  maxRetries = 3,
}: PollingOptions) => {
  const [data, setData] = useState<DocumentStatusResponse | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [isPolling, setIsPolling] = useState(false);
  const retryCount = useRef(0);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const fetchStatus = useCallback(async function internalFetch() {
    if (!isPolling) return;

    // Si la pestaña no está visible, programamos el reintento pero no lo llamamos a la API
    if (document.hidden) {
      timerRef.current = setTimeout(internalFetch, intervalMs);
      return;
    }

    try {
      const response = await documentApi.getDocumentStatus(documentId);
      setData(response);
      retryCount.current = 0; // Reset reintentos si hubo éxito
      setError(null);

      // Evaluar terminal states (COMPLETED / FAILED) para detener
      const { overallStatus } = response.status;
      if (overallStatus === 'COMPLETED' || overallStatus === 'FAILED') {
        setIsPolling(false);
        return; // Detener chain de setTimeout
      }

      // Chain next call
      if (isPolling) {
        timerRef.current = setTimeout(internalFetch, intervalMs);
      }
    } catch {
      retryCount.current += 1;

      if (retryCount.current >= maxRetries) {
        setError(new Error('DOCUMENT_STATUS_UNAVAILABLE'));
        setIsPolling(false);
      } else {
        // Exponential backoff
        const backoffMs = intervalMs * Math.pow(2, retryCount.current);
        if (isPolling) {
          timerRef.current = setTimeout(internalFetch, backoffMs);
        }
      }
    }
  }, [documentId, maxRetries, intervalMs, isPolling]);

  const startPolling = useCallback(() => {
    if (timerRef.current) return;
    setIsPolling(true);
  }, []);

  useEffect(() => {
    if (isPolling) {
      fetchStatus();
    }
  }, [isPolling, fetchStatus]);

  const stopPolling = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    setIsPolling(false);
  }, []);

  useEffect(() => {
    if (documentId) {
      startPolling();
    }
    return () => {
      stopPolling();
    };
  }, [documentId, startPolling, stopPolling]);

  // Manejo de Page Visibility para pausar el polling real (el interval sigue, pero esquiva fetch)
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (!document.hidden && isPolling) {
        // Ejecuta uno inmediato al volver
        fetchStatus();
      }
    };
    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => document.removeEventListener('visibilitychange', handleVisibilityChange);
  }, [fetchStatus, isPolling]);

  return { data, error, isPolling, startPolling, stopPolling, refetch: fetchStatus };
};
