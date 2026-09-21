import { useState, useEffect, useCallback, useRef } from 'react';
import { documentApi } from '../api/documentApi';
import type { DocumentStatusResponse } from '../domain/documents';

interface PollingOptions {
  documentId: string;
  intervalMs?: number;
  maxRetries?: number;
}

interface JourneyState {
  documentId: string;
  data: DocumentStatusResponse | null;
  error: Error | null;
  isPolling: boolean;
}

interface PollingControls {
  start: () => void;
  stop: () => void;
  refetch: () => Promise<void>;
}

const MAX_TIMER_MS = 2 ** 31 - 1;

export const useDocumentJourney = ({
  documentId,
  intervalMs: requestedInterval = 3000,
  maxRetries: requestedRetries = 3,
}: PollingOptions) => {
  const intervalMs = Number.isSafeInteger(requestedInterval) && requestedInterval >= 1 && requestedInterval <= MAX_TIMER_MS
    ? requestedInterval : 3000;
  const maxRetries = Number.isSafeInteger(requestedRetries) && requestedRetries >= 1
    ? requestedRetries : 3;
  const [state, setState] = useState<JourneyState>({
    documentId, data: null, error: null, isPolling: false,
  });
  const controls = useRef<PollingControls | null>(null);
  // Option changes retain reads already in flight for this hook and document.
  const activeReads = useRef(new Map<string, Promise<void>>());
  const pollingIntent = useRef({ documentId, running: true });

  useEffect(() => {
    if (pollingIntent.current.documentId !== documentId) {
      pollingIntent.current = { documentId, running: true };
    }
    let disposed = false;
    let running = false;
    let generation = 0;
    let failures = 0;
    let dueAt = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let pending: Promise<void> | undefined;
    let startupPending = pollingIntent.current.running;
    const reads = activeReads.current;

    const clearTimer = () => {
      if (timer !== undefined) clearTimeout(timer);
      timer = undefined;
    };
    const publish = (patch: Partial<Omit<JourneyState, 'documentId'>>) => {
      if (disposed) return;
      setState(previous => ({
        ...(previous.documentId === documentId
          ? previous
          : { documentId, data: null, error: null, isPolling: false }),
        ...patch,
      }));
    };
    const armTimer = (delay: number) => {
      clearTimer();
      if (disposed || !running || document.hidden) return;
      timer = setTimeout(() => {
        timer = undefined;
        void wake();
      }, Math.min(MAX_TIMER_MS, Math.max(0, delay)));
    };
    const stop = () => {
      if (disposed) return;
      pollingIntent.current.running = false;
      startupPending = false;
      running = false;
      generation += 1;
      clearTimer();
      // An outstanding read retains its lease until it settles.
      publish({ isPolling: false });
    };
    async function wake(): Promise<void> {
      if (disposed || !running || document.hidden) return;
      if (pending) return pending;
      const inheritedRead = reads.get(documentId);
      if (inheritedRead) {
        pending = inheritedRead.finally(() => {
          pending = undefined;
          if (!disposed && running) armTimer(Math.max(0, dueAt - performance.now()));
        });
        return pending;
      }
      const remaining = dueAt - performance.now();
      if (remaining > 0) {
        armTimer(remaining);
        return;
      }
      clearTimer();
      const ownGeneration = generation;
      const operation: Promise<void> = Promise.resolve().then(async () => {
        if (disposed || !running || ownGeneration !== generation) return;
        try {
          const response = await documentApi.getDocumentStatus(documentId);
          if (disposed || !running || ownGeneration !== generation) return;
          if (response.documentId !== documentId) throw new Error('DOCUMENT_REFERENCE_MISMATCH');
          failures = 0;
          publish({ data: response, error: null });
          if (response.lifecycle === 'COMPLETED' || response.lifecycle === 'FAILED') {
            stop();
          } else {
            dueAt = performance.now() + intervalMs;
          }
        } catch {
          if (disposed || !running || ownGeneration !== generation) return;
          failures += 1;
          if (failures >= maxRetries) {
            publish({ error: new Error('DOCUMENT_STATUS_UNAVAILABLE') });
            stop();
          } else {
            const backoff = Math.min(MAX_TIMER_MS, intervalMs * 2 ** Math.min(failures, 31));
            dueAt = performance.now() + backoff;
          }
        }
      }).finally(() => {
        if (reads.get(documentId) === operation) reads.delete(documentId);
        pending = undefined;
        if (disposed || !running) return;
        armTimer(Math.max(0, dueAt - performance.now()));
      });
      pending = operation;
      reads.set(documentId, operation);
      return pending;
    }
    const start = () => {
      startupPending = false;
      if (disposed || running || !documentId) return;
      pollingIntent.current.running = true;
      running = true;
      generation += 1;
      failures = 0;
      dueAt = 0;
      publish({ error: null, isPolling: true });
      void wake();
    };
    const controller: PollingControls = { start, stop, refetch: wake };
    controls.current = controller;
    const visibilityChanged = () => {
      clearTimer();
      if (!document.hidden) void wake();
    };
    document.addEventListener('visibilitychange', visibilityChanged);
    // StrictMode's discarded setup must not launch a request.
    void Promise.resolve().then(() => {
      if (disposed || !startupPending) return;
      publish({ data: null, error: null, isPolling: false });
      start();
    });
    return () => {
      disposed = true;
      running = false;
      generation += 1;
      clearTimer();
      document.removeEventListener('visibilitychange', visibilityChanged);
      if (controls.current === controller) controls.current = null;
    };
  }, [documentId, intervalMs, maxRetries]);

  const startPolling = useCallback(() => controls.current?.start(), []);
  const stopPolling = useCallback(() => controls.current?.stop(), []);
  const refetch = useCallback(() => controls.current?.refetch() ?? Promise.resolve(), []);
  const current = state.documentId === documentId
    ? state
    : { data: null, error: null, isPolling: false };
  return { data: current.data, error: current.error, isPolling: current.isPolling, startPolling, stopPolling, refetch };
};
