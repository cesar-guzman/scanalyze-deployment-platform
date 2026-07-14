import React from 'react';
import { useAuth } from 'react-oidc-context';
import { Link, useLocation } from 'react-router-dom';

export const PageLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const auth = useAuth();
  const location = useLocation();
  const isDashboard = location.pathname === '/dashboard';

  return (
    <div className="flex flex-col min-h-screen w-full relative overflow-hidden bg-slate-950 text-slate-200">
      {/* Decorative background elements for depth */}
      <div className="absolute -top-[15%] right-[10%] w-[40vmax] h-[40vmax] bg-indigo-600/10 blur-[80px] rounded-full -z-10 pointer-events-none"></div>
      <div className="absolute -bottom-[10%] -left-[5%] w-[50vmax] h-[50vmax] bg-blue-600/5 blur-[100px] rounded-full -z-10 pointer-events-none"></div>

      <header className="flex flex-col sm:flex-row justify-between items-center px-6 py-4 mx-4 sm:mx-8 mt-6 sm:mt-8 bg-slate-900/80 backdrop-blur-md border border-slate-800 rounded-2xl shadow-lg z-10 animate-fade-in gap-4 sm:gap-0">
        <div className="flex items-center gap-4 w-full sm:w-auto">
          <Link to="/dashboard" className="flex items-center justify-center min-w-[40px] w-10 h-10 bg-indigo-600 rounded-xl text-white font-bold hover:bg-indigo-500 transition-colors shadow-md">
            Sz
          </Link>
          <div className="flex-1">
            <h1 className="m-0 text-xl font-semibold tracking-tight text-white leading-tight">Scanalyze Workspace</h1>
            {!isDashboard && (
              <p className="m-0 mt-0.5 text-xs sm:text-sm text-slate-400">Secure Enterprise Document Ingestion</p>
            )}
          </div>
        </div>

        <div className="flex items-center gap-4 sm:gap-6 w-full sm:w-auto justify-between sm:justify-end">
          {!isDashboard && (
             <Link to="/dashboard" className="text-sm font-medium text-slate-400 hover:text-slate-200 transition-colors flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-800 bg-white/5 hover:bg-white/10">
               <span>&larr;</span> Dashboard
             </Link>
          )}
          <div className="items-end hidden sm:flex flex-col">
            <span className="text-xs text-slate-400">Usuario Conectado</span>
            <span className="font-medium text-slate-200 text-sm">{auth.user?.profile?.email || 'Admin'}</span>
          </div>
          <button
            className="btn btn-outline text-sm py-1.5 px-3 whitespace-nowrap"
            onClick={() => void auth.signoutRedirect()}
          >
            Cerrar Sesión
          </button>
        </div>
      </header>

      <main className="flex-1 w-full max-w-7xl mx-auto p-4 sm:p-8 lg:p-12 box-border z-10 animate-slide-up flex flex-col">
        {children}
      </main>
    </div>
  );
};
