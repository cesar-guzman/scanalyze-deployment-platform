import { getApiClient } from './client';

export interface AnalyticsOverview {
  documentsUploaded: number;
  documentsCompleted: number;
  documentsFailed: number;
  pagesScanned: number;
}

export interface UserAnalytics {
  userId: string;
  displayName: string;
  pagesScanned: number;
  documentsCount: number;
}

export interface DayAnalytics {
  day: string;
  pagesScanned: number;
  documentsCount: number;
}

export interface DocTypeAnalytics {
  docType: string;
  pagesScanned: number;
  documentsCount: number;
}

export interface BatchAnalytics {
  batchId: string;
  pagesScanned: number;
  documentsCount: number;
}

export interface DashboardResponse {
  overview: AnalyticsOverview;
  byUser: UserAnalytics[];
  byDay: DayAnalytics[];
  byDocType: DocTypeAnalytics[];
  byBatch: BatchAnalytics[];
}

export interface DashboardFilters {
  startDate?: string;
  endDate?: string;
  docType?: string;
  batchId?: string;
  status?: string;
}

export const analyticsApi = {
  getDashboard: async (filters: DashboardFilters = {}): Promise<DashboardResponse> => {
    const client = getApiClient();
    const params = new URLSearchParams();
    if (filters.startDate && filters.startDate !== 'ALL') params.append('startDate', filters.startDate);
    if (filters.endDate && filters.endDate !== 'ALL') params.append('endDate', filters.endDate);
    if (filters.docType && filters.docType !== 'ALL') params.append('docType', filters.docType);
    if (filters.batchId && filters.batchId.trim() !== '') params.append('batchId', filters.batchId.trim());
    if (filters.status && filters.status !== 'ALL') params.append('status', filters.status);

    const response = await client.get(`/analytics/dashboard?${params.toString()}`);
    return response.data as DashboardResponse;
  },

  getCosts: async (): Promise<CostsDashboardResponse> => {
    const client = getApiClient();
    const response = await client.get(`/analytics/costs`);
    return response.data as CostsDashboardResponse;
  }
};

export interface CostsDashboardResponse {
  summary: {
    total_documents: number;
    total_cost: number;
    average_cost_per_doc: number;
  };
  cost_by_tenant: {
    tenant_id: string;
    total_pages: number;
    total_cost: number;
  }[];
  cost_by_doc_type: {
    document_type: string;
    total_pages: number;
    total_cost: number;
  }[];
  calculation_details: {
    rate_per_page: number;
    currency: string;
  };
}
