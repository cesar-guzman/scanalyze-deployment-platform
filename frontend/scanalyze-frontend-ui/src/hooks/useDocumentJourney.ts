import { useState, useEffect, useCallback, useRef } from 'react';
import { documentApi } from '../api/documentApi';
import type { DocumentStatusResponse } from '../domain/documents';

interface PollingOptions {
  documentId: string;
  intervalMs?: number;
  maxRetries?: number;
}

export const useDocumentJourney = ({
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

    // Pausar si la pestaña no está visible
    if (document.hidden) {
      timerRef.current = setTimeout(internalFetch, intervalMs);
      return;
    }

    try {
      const response = await documentApi.getDocumentStatus(documentId);
      setData(response);
      retryCount.current = 0;
      setError(null);

      const { lifecycle, failureDisposition } = response;
      
      // Detener si es un estado terminal
      if (lifecycle === 'COMPLETED' || lifecycle === 'FAILED') {
        // En un escenario de error FAILED + RETRYABLE podríamos continuar o reintentar
        // Pero típicamente aquí el backend detiene su proceso.
        if (lifecycle === 'FAILED' && failureDisposition === 'RETRYABLE') {
           // Aquí la UX podría permitir al usuario reenviar.
        }
        setIsPolling(false);
        return;
      }

      if (isPolling) {
        timerRef.current = setTimeout(internalFetch, intervalMs);
      }
    } catch {
      retryCount.current += 1;

      if (retryCount.current >= maxRetries) {
        setError(new Error('DOCUMENT_STATUS_UNAVAILABLE'));
        setIsPolling(false);
      } else {
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

  const stopPolling = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    setIsPolling(false);
  }, []);

  useEffect(() => {
    if (isPolling) {
      fetchStatus();
    }
  }, [isPolling, fetchStatus]);

  useEffect(() => {
    if (documentId) {
      startPolling();
    }
    return () => stopPolling();
  }, [documentId, startPolling, stopPolling]);

  useEffect(() => {
    const handleVisibilityChange = () => {
      if (!document.hidden && isPolling) {
        fetchStatus();
      }
    };
    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => document.removeEventListener('visibilitychange', handleVisibilityChange);
  }, [fetchStatus, isPolling]);

  return { data, error, isPolling, startPolling, stopPolling, refetch: fetchStatus };
};
