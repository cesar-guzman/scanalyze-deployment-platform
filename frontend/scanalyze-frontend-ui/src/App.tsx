import React, { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router';
import { useAuth } from 'react-oidc-context';
import { Login } from './pages/Login';
import { Dashboard } from './pages/Dashboard';
import { Upload } from './pages/Upload';
import { BulkUpload } from './pages/BulkUpload';
import { loadConfig, RuntimeConfigError } from './config';
import { AuthProvider } from './auth/AuthProvider';
import { PageLayout } from './components/PageLayout';
import { AnalyticsDashboard } from './pages/AnalyticsDashboard';
import { BatchDetails } from './pages/BatchDetails';
import { DocumentPage } from './pages/DocumentPage';
import CostsDashboard from './pages/CostsDashboard';
import { BankStatements } from './pages/BankStatements';
import { EmployeeProfiles } from './pages/EmployeeProfiles';
import { EmployeeProfileDetail } from './pages/EmployeeProfileDetail';
import { EnterpriseUserConsole } from './pages/EnterpriseUserConsole';
import {
  callbackErrorCode,
  preflightAuthCallback,
  scrubAuthCallbackUrl,
  useOperationTimeout,
} from './auth/bootstrap';

const SafeAuthFailure: React.FC<{ code: string }> = ({ code }) => (
  <main className="flex justify-center items-center min-h-screen w-full bg-slate-950 text-slate-200">
    <section className="max-w-lg rounded-xl border border-red-500/40 bg-slate-900 p-8 text-center">
      <h1 className="mb-3 text-xl font-semibold">No fue posible completar la autenticación</h1>
      <p className="mb-4 text-slate-400">La operación se detuvo de forma segura. Vuelve a iniciar sesión.</p>
      <p className="font-mono text-sm text-red-300" role="alert">{code}</p>
      <button
        className="btn-outline mt-6 w-full py-3"
        onClick={() => window.location.replace('/login')}
      >
        Volver a iniciar sesión
      </button>
    </section>
  </main>
);

const CallbackHandler: React.FC = () => {
  const auth = useAuth();
  const parameters = new URLSearchParams(window.location.search);
  const hasResponse = parameters.has('code') || parameters.has('error');
  const invalidEnvelope = hasResponse && !parameters.has('state');
  const timedOut = useOperationTimeout(auth.isLoading && !invalidEnvelope);
  const failureCode = invalidEnvelope
    ? 'AUTH_CALLBACK_INVALID'
    : auth.error
      ? callbackErrorCode(auth.error)
      : timedOut
        ? 'AUTH_CALLBACK_TIMEOUT'
        : !auth.isLoading && !auth.isAuthenticated
          ? 'AUTH_CALLBACK_INVALID'
          : null;

  useEffect(() => {
    if (failureCode !== null) scrubAuthCallbackUrl();
  }, [failureCode]);

  if (failureCode !== null) return <SafeAuthFailure code={failureCode} />;
  if (auth.isAuthenticated) return <Navigate to="/upload" replace />;

  return (
    <div className="flex justify-center items-center min-h-screen w-full bg-slate-950">
      <div className="flex items-center gap-4 animate-fade-in">
        <div className="w-10 h-10 border-4 border-indigo-500/10 border-t-indigo-500 rounded-full animate-spin"></div>
        <p className="text-slate-400 font-medium m-0">Procesando inicio de sesión...</p>
      </div>
    </div>
  );
};

// Layout for simple protected routes without nested routes (for backward compat)
const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const auth = useAuth();
  const timedOut = useOperationTimeout(auth.isLoading);

  if (timedOut) return <SafeAuthFailure code="OIDC_BOOTSTRAP_TIMEOUT" />;
  if (auth.isLoading) {
    return <div className="flex items-center justify-center min-h-screen bg-slate-950 text-slate-300">Verificando sesión segura...</div>;
  }

  if (!auth.isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <PageLayout>{children}</PageLayout>;
};

const AppRoutes = () => {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route path="/login" element={<Login />} />
      <Route path="/callback" element={<CallbackHandler />} />

      {/* Protected routes */}
      <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
      <Route path="/upload" element={<ProtectedRoute><Upload /></ProtectedRoute>} />
      <Route path="/bulk-upload" element={<ProtectedRoute><BulkUpload /></ProtectedRoute>} />
      <Route path="/analytics" element={<ProtectedRoute><AnalyticsDashboard /></ProtectedRoute>} />
      <Route path="/costs" element={<ProtectedRoute><CostsDashboard /></ProtectedRoute>} />
      <Route path="/batch/:id" element={<ProtectedRoute><BatchDetails /></ProtectedRoute>} />
      <Route path="/document/:id" element={<ProtectedRoute><DocumentPage /></ProtectedRoute>} />
      <Route path="/bank-statements" element={<ProtectedRoute><BankStatements /></ProtectedRoute>} />
      <Route path="/employee-profiles" element={<ProtectedRoute><EmployeeProfiles /></ProtectedRoute>} />
      <Route path="/employee-profiles/:profileId" element={<ProtectedRoute><EmployeeProfileDetail /></ProtectedRoute>} />
      <Route path="/admin/users" element={<ProtectedRoute><EnterpriseUserConsole /></ProtectedRoute>} />

      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
};

export const App: React.FC = () => {
  const [configState, setConfigState] = useState<'loading' | 'ready' | 'failed'>('loading');
  const [failureCode, setFailureCode] = useState('RUNTIME_CONFIG_INVALID');
  const [authBootstrapFailure, setAuthBootstrapFailure] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    void loadConfig()
      .then((loadedConfig) => {
        if (!active) return;
        const callbackFailure = preflightAuthCallback(loadedConfig);
        if (callbackFailure !== null) setAuthBootstrapFailure(callbackFailure);
        setConfigState('ready');
      })
      .catch((error: unknown) => {
        if (!active) return;
        if (window.location.pathname === '/callback') {
          const callbackParameters = new URLSearchParams(window.location.search);
          if (callbackParameters.has('code') || callbackParameters.has('error')) {
            scrubAuthCallbackUrl();
          }
        }
        setFailureCode(
          error instanceof RuntimeConfigError ? error.code : 'RUNTIME_CONFIG_INVALID',
        );
        setConfigState('failed');
      });
    return () => {
      active = false;
    };
  }, []);

  if (configState === 'failed') {
    return (
      <main className="flex justify-center items-center min-h-screen w-full bg-slate-950 text-slate-200">
        <section className="max-w-lg rounded-xl border border-red-500/40 bg-slate-900 p-8 text-center">
          <h1 className="mb-3 text-xl font-semibold">Configuración no disponible</h1>
          <p className="mb-4 text-slate-400">
            La aplicación permanece bloqueada porque no pudo validar su configuración de despliegue.
          </p>
          <p className="font-mono text-sm text-red-300" role="alert">{failureCode}</p>
          <button
            className="btn-outline mt-6 w-full py-3"
            onClick={() => window.location.reload()}
          >
            Recargar configuración
          </button>
        </section>
      </main>
    );
  }

  if (configState === 'loading') {
    return (
      <div className="flex justify-center items-center min-h-screen w-full bg-slate-950">
        <div className="flex flex-col items-center gap-4 animate-fade-in">
          <div className="w-10 h-10 border-4 border-indigo-500/10 border-t-indigo-500 rounded-full animate-spin"></div>
          <p className="text-slate-400 font-medium m-0">Cargando configuración de inicio...</p>
        </div>
      </div>
    );
  }

  if (authBootstrapFailure !== null) {
    return <SafeAuthFailure code={authBootstrapFailure} />;
  }

  return (
    <AuthProvider>
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
    </AuthProvider>
  );
};

export default App;
