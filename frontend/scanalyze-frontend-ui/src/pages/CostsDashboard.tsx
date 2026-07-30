import React, { useEffect, useState } from 'react';
import type { CostsDashboardResponse } from '../api/analyticsApi';
import { analyticsApi } from '../api/analyticsApi';

const CostsDashboard: React.FC = () => {
    const [data, setData] = useState<CostsDashboardResponse | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(false);

    useEffect(() => {
        const fetchCosts = async () => {
            try {
                const response = await analyticsApi.getCosts();
                setData(response);
            } catch {
                setError(true);
            } finally {
                setLoading(false);
            }
        };
        void fetchCosts();
    }, []);

    if (error) {
        return <p role="alert" className="p-8 text-center text-red-300">No fue posible cargar el reporte.</p>;
    }

    if (loading || !data) {
        return (
            <div className="flex justify-center items-center min-h-screen bg-[#101522]">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-[#2b5bee]"></div>
                <div className="ml-4 text-white text-lg font-medium">Cargando reporte...</div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-[#101522] overflow-x-hidden relative pb-16">
            {/* Header simple for layout replacement */}
            <div className="bg-[#191b24] border-b border-white/5 py-4 px-6 md:px-12 mb-8 flex items-center justify-between">
                <div className="flex items-center gap-3">
                    <div className="p-2 bg-[#2b5bee]/20 text-[#2b5bee] rounded-lg">
                        <span className="material-symbols-outlined">analytics</span>
                    </div>
                    <div>
                        <h1 className="text-xl font-bold text-white tracking-tight">Reporte Textract</h1>
                        <p className="text-xs text-slate-400 font-medium tracking-wide uppercase">Dashboard de Costos</p>
                    </div>
                </div>
            </div>

            <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-[#2b5bee]/20 blur-[120px] rounded-full -z-10 pointer-events-none"></div>
            <div className="absolute bottom-[-10%] right-[-10%] w-[30%] h-[30%] bg-[#2b5bee]/10 blur-[100px] rounded-full -z-10 pointer-events-none"></div>

            <div className="max-w-7xl mx-auto px-6">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                        <div className="relative overflow-hidden p-6 rounded-3xl border border-white/5 bg-[#191b24] shadow-sm transform hover:-translate-y-1 transition-transform">
                            <div className="relative z-10 flex items-center justify-between mb-2">
                                <span className="text-sm font-medium text-slate-400">Costo Total Estimado</span>
                                <span className="material-symbols-outlined text-[#2b5bee] text-lg">payments</span>
                            </div>
                            <div className="relative z-10 text-3xl font-extrabold text-white tracking-tight">${data.summary.total_cost.toFixed(2)}</div>
                        </div>
                        <div className="relative overflow-hidden p-6 rounded-3xl border border-white/5 bg-[#191b24] shadow-sm transform hover:-translate-y-1 transition-transform">
                            <div className="relative z-10 flex items-center justify-between mb-2">
                                <span className="text-sm font-medium text-slate-400">Documentos Procesados</span>
                                <span className="material-symbols-outlined text-white/50 text-lg">description</span>
                            </div>
                            <div className="relative z-10 text-3xl font-bold text-white tracking-tight">{data.summary.total_documents}</div>
                        </div>
                        <div className="relative overflow-hidden p-6 rounded-3xl border border-white/5 bg-[#191b24] shadow-sm transform hover:-translate-y-1 transition-transform">
                            <div className="relative z-10 flex items-center justify-between mb-2">
                                <span className="text-sm font-medium text-slate-400">Promedio Costo/Doc</span>
                                <span className="material-symbols-outlined text-emerald-400 text-lg">trending_flat</span>
                            </div>
                            <div className="relative z-10 text-3xl font-bold text-white tracking-tight">${data.summary.average_cost_per_doc.toFixed(2)}</div>
                        </div>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        <section className="bg-[#191b24] rounded-3xl overflow-hidden shadow-[0_4px_24px_rgba(0,0,0,0.2)]">
                            <div className="p-6 flex items-center justify-between border-b border-white/5">
                                <h3 className="text-lg font-bold text-white">Costo por Inquilino</h3>
                            </div>
                            <div className="overflow-x-auto">
                                <table className="w-full text-left">
                                    <thead>
                                        <tr className="bg-white/5">
                                            <th className="px-6 py-4 text-[10px] font-extrabold text-slate-500 uppercase tracking-widest">Inquilino / Tenant</th>
                                            <th className="px-6 py-4 text-[10px] font-extrabold text-slate-500 uppercase tracking-widest text-center">Páginas Procesadas</th>
                                            <th className="px-6 py-4 text-[10px] font-extrabold text-slate-500 uppercase tracking-widest text-right">Costo Estimado ($)</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-white/5">
                                        {data.cost_by_tenant.map((tenant, i) => (
                                            <tr key={i} className="hover:bg-white/[0.03] transition-colors">
                                                <td className="px-6 py-4">
                                                    <div className="flex items-center gap-3">
                                                        <div className="h-8 w-8 rounded-full bg-[#2d313e] flex items-center justify-center text-xs font-bold text-slate-300">
                                                            {tenant.tenant_id.substring(0, 2).toUpperCase()}
                                                        </div>
                                                        <span className="text-sm font-medium text-white">{tenant.tenant_id}</span>
                                                    </div>
                                                </td>
                                                <td className="px-6 py-4 text-center">
                                                    <span className="text-sm font-medium text-slate-300">{tenant.total_pages}</span>
                                                </td>
                                                <td className="px-6 py-4 text-right">
                                                    <span className="text-sm font-bold text-white">${tenant.total_cost.toFixed(2)}</span>
                                                </td>
                                            </tr>
                                        ))}
                                        {data.cost_by_tenant.length === 0 && (
                                            <tr>
                                                <td colSpan={3} className="px-6 py-8 text-center text-slate-400">No hay datos de facturación</td>
                                            </tr>
                                        )}
                                    </tbody>
                                </table>
                            </div>
                        </section>

                        <section className="bg-[#191b24] rounded-3xl overflow-hidden shadow-[0_4px_24px_rgba(0,0,0,0.2)]">
                            <div className="p-6 flex items-center justify-between border-b border-white/5">
                                <h3 className="text-lg font-bold text-white">Costo por Tipo de Documento</h3>
                                <div className="h-8 w-8 rounded-full bg-[#2b5bee]/10 flex items-center justify-center text-[#2b5bee]">
                                    <span className="material-symbols-outlined text-sm">pie_chart</span>
                                </div>
                            </div>
                            <div className="overflow-x-auto">
                                <table className="w-full text-left">
                                    <thead>
                                        <tr className="bg-white/5">
                                            <th className="px-6 py-4 text-[10px] font-extrabold text-slate-500 uppercase tracking-widest">Tipo de Documento</th>
                                            <th className="px-6 py-4 text-[10px] font-extrabold text-slate-500 uppercase tracking-widest text-center">Páginas Procesadas</th>
                                            <th className="px-6 py-4 text-[10px] font-extrabold text-slate-500 uppercase tracking-widest text-right">Costo Estimado ($)</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-white/5">
                                        {data.cost_by_doc_type.map((doc, i) => {
                                            const colors = ['bg-[#2b5bee] text-white', 'bg-emerald-500 text-white', 'bg-amber-400 text-slate-900', 'bg-rose-500 text-white', 'bg-slate-400 text-white'];
                                            const colorClass = colors[i % colors.length];
                                            return (
                                            <tr key={i} className="hover:bg-white/[0.03] transition-colors">
                                                <td className="px-6 py-4">
                                                    <div className="flex items-center gap-3">
                                                        <div className={`h-6 px-3 rounded flex items-center justify-center text-[10px] font-bold ${colorClass}`}>
                                                            {doc.document_type}
                                                        </div>
                                                    </div>
                                                </td>
                                                <td className="px-6 py-4 text-center">
                                                    <span className="text-sm font-medium text-slate-300">{doc.total_pages}</span>
                                                </td>
                                                <td className="px-6 py-4 text-right">
                                                    <span className="text-sm font-bold text-white">${doc.total_cost.toFixed(2)}</span>
                                                </td>
                                            </tr>
                                            )
                                        })}
                                        {data.cost_by_doc_type.length === 0 && (
                                            <tr>
                                                <td colSpan={3} className="px-6 py-8 text-center text-slate-400">No hay datos de facturación</td>
                                            </tr>
                                        )}
                                    </tbody>
                                </table>
                            </div>
                        </section>
                    </div>

                    <div className="mt-8 p-1 rounded-2xl border border-white/5 flex flex-col md:flex-row items-center gap-4 bg-gradient-to-r from-emerald-500/10 to-transparent">
                        <div className="p-4 bg-emerald-500 rounded-xl m-2 opacity-90">
                            <span className="material-symbols-outlined text-white" style={{fontVariationSettings: "'FILL' 1"}}>lightbulb</span>
                        </div>
                        <div className="flex-1 py-4 px-2">
                            <h4 className="text-emerald-400 font-bold text-sm">Tarifa Activa de AWS Textract</h4>
                            <p className="text-slate-400 text-xs">Los costos se calculan multiplicando el total de páginas reportadas por la API de Usage Metering contra la tarifa actual de ${data.calculation_details.rate_per_page.toFixed(4)} {data.calculation_details.currency} por página configurada en AWS Systems Manager Parameter Store.</p>
                        </div>
                    </div>
                </div>
            </div>
    );
};

export default CostsDashboard;
