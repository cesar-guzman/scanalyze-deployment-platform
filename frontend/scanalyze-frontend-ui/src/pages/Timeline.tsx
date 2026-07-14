import React from 'react';
import { Link } from 'react-router-dom';

export const Timeline: React.FC = () => {
  return (
    <div style={{ padding: '2rem', fontFamily: 'sans-serif' }}>
      <header style={{ borderBottom: '1px solid #eee', paddingBottom: '1rem', marginBottom: '2rem' }}>
        <Link to="/dashboard" style={{ textDecoration: 'none', color: '#4f46e5', marginRight: '1rem' }}>&larr; Volver al Dashboard</Link>
        <h1 style={{ display: 'inline', margin: 0 }}>Historial / Timeline</h1>
      </header>
      <main>
        <ul style={{ listStyle: 'none', padding: 0 }}>
          <li style={{ padding: '1rem', border: '1px solid #eee', marginBottom: '1rem', borderRadius: '4px' }}>
            <div style={{ fontWeight: 'bold' }}>Documento de prueba 1</div>
            <div style={{ fontSize: '0.85rem', color: '#6b7280' }}>Estado: Procesado - Fecha: 2026-03-10</div>
            <Link to="/results?id=1" style={{ color: '#4f46e5', textDecoration: 'none', fontSize: '0.9rem' }}>Ver Resultados</Link>
          </li>
          <li style={{ padding: '1rem', border: '1px solid #eee', marginBottom: '1rem', borderRadius: '4px' }}>
            <div style={{ fontWeight: 'bold' }}>Documento de prueba 2</div>
            <div style={{ fontSize: '0.85rem', color: '#6b7280' }}>Estado: En progreso - Fecha: 2026-03-11</div>
            <span style={{ color: '#9ca3af', fontSize: '0.9rem' }}>Ver Resultados</span>
          </li>
        </ul>
      </main>
    </div>
  );
};
