import React from 'react';
import { Link } from 'react-router-dom';

export const ResultViewer: React.FC = () => {
  return (
    <div style={{ padding: '2rem', fontFamily: 'sans-serif' }}>
      <header style={{ borderBottom: '1px solid #eee', paddingBottom: '1rem', marginBottom: '2rem' }}>
        <Link to="/timeline" style={{ textDecoration: 'none', color: '#4f46e5', marginRight: '1rem' }}>&larr; Volver al Timeline</Link>
        <h1 style={{ display: 'inline', margin: 0 }}>Visor de Resultados</h1>
      </header>
      <main style={{ display: 'flex', gap: '2rem' }}>
        <div style={{ flex: 1, border: '1px solid #eee', padding: '1rem', borderRadius: '4px', minHeight: '60vh', backgroundColor: '#f9fafb' }}>
          <p style={{ textAlign: 'center', color: '#6b7280', marginTop: '20vh' }}>Visor del documento PDF</p>
        </div>
        <div style={{ flex: 1, border: '1px solid #eee', padding: '1rem', borderRadius: '4px' }}>
          <h3>Datos Extraídos</h3>
          <pre style={{ backgroundColor: '#f3f4f6', padding: '1rem', borderRadius: '4px', overflowX: 'auto' }}>
{JSON.stringify({
  tipo: 'INE',
  nombre: 'JUAN PEREZ',
  fecha_nacimiento: '1990-01-01',
  confianza: 0.98
}, null, 2)}
          </pre>
        </div>
      </main>
    </div>
  );
};
