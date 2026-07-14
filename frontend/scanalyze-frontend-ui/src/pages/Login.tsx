import React from 'react';
import { useAuth } from 'react-oidc-context';
import { Navigate } from 'react-router-dom';

export const Login: React.FC = () => {
  const auth = useAuth();

  if (auth.isLoading) {
    return (
      <div className="flex justify-center items-center min-h-screen w-full bg-slate-950">
        <div className="flex flex-col items-center gap-4 animate-fade-in">
          <div className="w-10 h-10 border-4 border-indigo-500/10 border-t-indigo-500 rounded-full animate-spin"></div>
          <p className="text-slate-400 font-medium">Verificando sesión segura...</p>
        </div>
      </div>
    );
  }

  if (auth.error) {
    return (
      <div className="flex justify-center items-center min-h-screen w-full bg-slate-950">
        <div className="glass-card animate-fade-in p-10 text-center max-w-md w-11/12">
          <div className="text-5xl mb-4">⚠️</div>
          <h2 className="text-2xl font-bold mb-4 text-slate-100">Error de Autenticación</h2>
          <p className="text-rose-400 mb-8 text-sm">AUTHENTICATION_FAILED</p>
          <button className="btn-outline w-full py-3" onClick={() => void auth.signinRedirect()}>
            Intentar nuevamente
          </button>
        </div>
      </div>
    );
  }

  if (auth.isAuthenticated) {
    return <Navigate to="/upload" replace />;
  }

  return (
    <div className="flex flex-col justify-center items-center min-h-screen w-full relative overflow-hidden bg-slate-950">
      <div className="glass-card animate-fade-in p-12 text-center max-w-md w-11/12 relative z-10">

        <div className="mb-8 flex justify-center">
          <div className="w-20 h-20 bg-gradient-to-br from-indigo-500 to-indigo-700 rounded-2xl flex items-center justify-center shadow-[0_10px_25px_-5px_rgba(99,102,241,0.4)] text-white text-4xl font-bold border border-indigo-400/20">
            Sz
          </div>
        </div>

        <h1 className="text-3xl mb-2 font-bold tracking-tight text-slate-100">
          Scanalyze Studio
        </h1>
        <p className="text-slate-400 text-base mb-10 leading-relaxed">
          Tu plataforma de análisis inteligente de documentos corporativos.
        </p>

        <button
          className="btn-primary w-full py-3.5 text-lg flex items-center justify-center gap-2 transition-transform hover:-translate-y-0.5"
          onClick={() => void auth.signinRedirect()}
        >
          Iniciar Sesión
          <svg className="w-5 h-5 ml-1" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" /></svg>
        </button>

      </div>

      {/* Decorative background elements */}
      <div className="absolute top-[-10%] right-[-5%] w-[500px] h-[500px] bg-indigo-500/10 rounded-full blur-[80px] pointer-events-none"></div>
      <div className="absolute bottom-[-20%] left-[-10%] w-[600px] h-[600px] bg-indigo-600/5 rounded-full blur-[100px] pointer-events-none"></div>
    </div>
  );
};
