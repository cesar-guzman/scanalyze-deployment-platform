import { useCallback, useEffect, useRef, useState } from 'react';
import { useAuth } from 'react-oidc-context';
import { BulkUploadRecovery, type BulkUploadSnapshot, type BulkUploadTask } from '../domain/bulkUploadRecovery';
import { safeUploadError } from '../domain/uploadRecovery';
import { isSupportedUploadType } from '../domain/uploadTypes';

/** Shared upload-only state for the bulk and bank pages. No requests on mount:
 * recovery starts only after the user chooses to continue the saved operation.
 */
export function useBulkUploadRecovery() {
  const subject = useAuth().user?.profile.sub;
  const [tasks, setTasks] = useState<BulkUploadTask[]>([]);
  const [batch, setBatch] = useState<{ batchId: string } | null>(null);
  const [batchStatus, setBatchStatus] = useState<'IDLE' | 'CREATING' | 'PROCESSING' | 'COMPLETED' | 'ERROR'>('IDLE');
  const [batchErrorMsg, setBatchErrorMsg] = useState<string | null>(null);
  const [recovering, setRecovering] = useState(false);
  const coordinator = useRef<BulkUploadRecovery | null>(null);
  const busy = useRef(false);
  const generation = useRef(0);

  const apply = useCallback((snapshot: BulkUploadSnapshot) => {
    setTasks(snapshot.tasks);
    setBatch(snapshot.batchId ? { batchId: snapshot.batchId } : null);
    setRecovering(true);
  }, []);

  useEffect(() => {
    let active = true;
    const epoch = ++generation.current;
    coordinator.current = null;
    busy.current = false;
    // Asynchronous initialization avoids work during StrictMode's probe mount.
    void Promise.resolve().then(async () => {
      if (!active) return;
      setTasks([]);
      setBatch(null);
      setRecovering(false);
      setBatchStatus('IDLE');
      setBatchErrorMsg(null);
      try {
        const controller = await BulkUploadRecovery.open(subject, () => active && generation.current === epoch);
        if (!active) return;
        coordinator.current = controller;
        const saved = controller.snapshot();
        if (saved) {
          apply(saved);
          const complete = saved.tasks.every(task => task.status === 'SUCCESS');
          setBatchStatus(complete ? 'COMPLETED' : 'ERROR');
          if (!complete) setBatchErrorMsg('Hay envíos pendientes de confirmar. Recupera la misma operación.');
        }
      } catch (error) {
        if (!active) return;
        setBatchStatus('ERROR');
        setBatchErrorMsg(safeUploadError(error).message);
      }
    });
    return () => { active = false; };
  }, [subject, apply]);

  const addFiles = async (selectedFiles: FileList | File[]) => {
    if (busy.current || !coordinator.current) return;
    const files = Array.from(selectedFiles);
    if (!files.length) return;
    if (files.some(file => !isSupportedUploadType(file.type))) {
      setBatchErrorMsg('Selecciona archivos PDF, JPEG, PNG o TIFF.');
      return;
    }
    const epoch = generation.current;
    busy.current = true;
    try {
      if (coordinator.current.snapshot()) {
        const snapshot = await coordinator.current.attach(files);
        if (generation.current === epoch) apply(snapshot);
      } else {
        setTasks(previous => [...previous, ...files.map(file => ({
          id: crypto.randomUUID(), file, status: 'PENDING' as const, progress: 0,
        }))]);
      }
      if (generation.current === epoch) setBatchErrorMsg(null);
    } catch (error) {
      if (generation.current === epoch) setBatchErrorMsg(safeUploadError(error).message);
    } finally {
      if (generation.current === epoch) busy.current = false;
    }
  };

  const execute = async () => {
    const controller = coordinator.current;
    if (!controller || busy.current) return;
    busy.current = true; // Synchronous guard before state updates or any await.
    const epoch = generation.current;
    const current = () => generation.current === epoch && coordinator.current === controller;
    try {
      setBatchErrorMsg(null);
      if (!controller.snapshot()) {
        if (!tasks.length) return;
        setBatchStatus('CREATING');
        const files = tasks.map(task => task.file);
        if (files.some(file => !file)) return;
        const snapshot = await controller.create(files as File[]);
        if (!current()) return;
        apply(snapshot);
      }
      if (!current()) return;
      setBatchStatus('PROCESSING');
      const snapshot = await controller.run(next => { if (current()) apply(next); });
      if (!current()) return;
      apply(snapshot);
      const complete = snapshot.tasks.every(task => task.status === 'SUCCESS');
      setBatchStatus(complete ? 'COMPLETED' : 'ERROR');
      if (!complete) setBatchErrorMsg('Hay envíos pendientes de confirmar. Revisa el aviso de cada archivo y recupera la misma operación.');
    } catch (error) {
      if (!current()) return;
      setBatchErrorMsg(safeUploadError(error).message);
      let hasJournal = true;
      try {
        const snapshot = controller.snapshot();
        if (snapshot) apply(snapshot);
        else hasJournal = false;
      } catch { /* Keep the last view; corrupt or changed storage is never reset. */ }
      // Only a successful read proving that no journal exists can restore the
      // editable draft. Uncertain or corrupt recovery remains fail-closed.
      setBatchStatus(hasJournal ? 'ERROR' : 'IDLE');
    } finally {
      if (current()) busy.current = false;
    }
  };

  const removeTask = (id: string) => {
    if (recovering || busy.current) return;
    setTasks(previous => previous.filter(task => task.id !== id));
  };

  const handleNewBatch = async () => {
    const controller = coordinator.current;
    if (!controller || busy.current) return;
    busy.current = true;
    const epoch = generation.current;
    try {
      await controller.clearCompleted();
      if (generation.current !== epoch) return;
      setTasks([]);
      setBatch(null);
      setRecovering(false);
      setBatchStatus('IDLE');
      setBatchErrorMsg(null);
    } catch (error) {
      if (generation.current === epoch) setBatchErrorMsg(safeUploadError(error).message);
    } finally { if (generation.current === epoch) busy.current = false; }
  };

  return { tasks, batch, batchStatus, batchErrorMsg, setBatchErrorMsg, recovering,
    addFiles, removeTask, handleStartBatch: execute, handleRetryFailed: execute, handleNewBatch };
}
