/**
 * VulnForge Frontend API Client
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

function getAuthToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem('vulnforge_token');
}

export async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const token = getAuthToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const url = endpoint.startsWith('http') ? endpoint : `${API_BASE}${endpoint}`;
  const response = await fetch(url, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let errorMsg = `API Error ${response.status}: ${response.statusText}`;
    try {
      const errJson = await response.json();
      if (errJson.detail) {
        errorMsg = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail);
      } else if (errJson.error && errJson.error.message) {
        errorMsg = errJson.error.message;
      }
    } catch {
      // ignore
    }
    throw new Error(errorMsg);
  }

  return response.json();
}

export const api = {
  // Generic HTTP helpers
  get: <T = any>(url: string) => request<T>(url, { method: 'GET' }),
  post: <T = any>(url: string, body?: any) => request<T>(url, { method: 'POST', body: JSON.stringify(body) }),
  put: <T = any>(url: string, body?: any) => request<T>(url, { method: 'PUT', body: JSON.stringify(body) }),
  patch: <T = any>(url: string, body?: any) => request<T>(url, { method: 'PATCH', body: JSON.stringify(body) }),
  delete: <T = any>(url: string) => request<T>(url, { method: 'DELETE' }),

  // Auth
  login: (data: any) => request<any>('/api/auth/login', { method: 'POST', body: JSON.stringify(data) }),
  register: (data: any) => request<any>('/api/auth/register', { method: 'POST', body: JSON.stringify(data) }),
  getMe: () => request<any>('/api/auth/me'),

  // Organizations
  getOrganizations: () => request<any[]>('/api/organizations'),
  createOrganization: (data: any) => request<any>('/api/organizations', { method: 'POST', body: JSON.stringify(data) }),
  getOrgMembers: (orgId: string) => request<any[]>(`/api/organizations/${orgId}/members`),

  // Projects
  getProjects: (orgId: string) => request<any[]>(`/api/organizations/${orgId}/projects`),
  createProject: (orgId: string, data: any) => request<any>(`/api/organizations/${orgId}/projects`, { method: 'POST', body: JSON.stringify(data) }),
  getProject: (id: string) => request<any>(`/api/projects/${id}`),
  deleteProject: (id: string) => request<any>(`/api/projects/${id}`, { method: 'DELETE' }),

  // Assets
  getAssets: (projectId: string) => request<any[]>(`/api/projects/${projectId}/assets`),
  createAsset: (projectId: string, data: any) => request<any>(`/api/projects/${projectId}/assets`, { method: 'POST', body: JSON.stringify(data) }),
  deleteAsset: (assetId: string) => request<any>(`/api/assets/${assetId}`, { method: 'DELETE' }),

  // Scope & Authorization
  getScope: (projectId: string) => request<any>(`/api/projects/${projectId}/scope`),
  updateScope: (projectId: string, data: any) => request<any>(`/api/projects/${projectId}/scope`, { method: 'PUT', body: JSON.stringify(data) }),
  validateScope: (data: any) => request<any[]>('/api/scope/validate', { method: 'POST', body: JSON.stringify(data) }),
  confirmAuthorization: (data: any) => request<any>('/api/scope/confirm-authorization', { method: 'POST', body: JSON.stringify(data) }),

  // Assessments
  getAssessments: (projectId: string) => request<any[]>(`/api/projects/${projectId}/assessments`),
  createAssessment: (data: any) => request<any>('/api/assessments', { method: 'POST', body: JSON.stringify(data) }),
  getAssessment: (id: string) => request<any>(`/api/assessments/${id}`),
  cancelAssessment: (id: string) => request<any>(`/api/assessments/${id}/cancel`, { method: 'POST' }),
  getAssessmentLogs: (id: string) => request<any[]>(`/api/assessments/${id}/logs`),
  compareAssessments: (projectId: string, baseId: string, targetId: string) =>
    request<any>(`/api/projects/${projectId}/assessments/compare?base_id=${baseId}&target_id=${targetId}`),

  // Findings & Prioritization
  getFindings: (projectId: string, params: Record<string, string> = {}) => {
    const q = new URLSearchParams(params).toString();
    return request<any[]>(`/api/projects/${projectId}/findings${q ? `?${q}` : ''}`);
  },
  getPrioritizedFindings: (projectId: string, limit: number = 5) =>
    request<any>(`/api/projects/${projectId}/findings/prioritized?limit=${limit}`),
  getFinding: (id: string) => request<any>(`/api/findings/${id}`),
  updateFindingStatus: (id: string, data: { status: string; reason: string; remediation_notes?: string }) =>
    request<any>(`/api/findings/${id}/status`, { method: 'PATCH', body: JSON.stringify(data) }),

  // Remediation
  getRemediationTasks: (projectId: string) => request<any[]>(`/api/projects/${projectId}/remediation`),
  createRemediationTask: (data: any) => request<any>('/api/remediation', { method: 'POST', body: JSON.stringify(data) }),
  updateRemediationStatus: (taskId: string, status: string) =>
    request<any>(`/api/remediation/${taskId}?status_update=${status}`, { method: 'PATCH' }),

  // Reports
  generateReport: (data: any) => request<any>('/api/reports/generate', { method: 'POST', body: JSON.stringify(data) }),
  getReports: (projectId: string) => request<any[]>(`/api/projects/${projectId}/reports`),

  // Schedules
  getSchedules: (projectId: string) => request<any[]>(`/api/projects/${projectId}/schedules`),
  createSchedule: (projectId: string, data: any) => request<any>(`/api/projects/${projectId}/schedules`, { method: 'POST', body: JSON.stringify(data) }),
  deleteSchedule: (id: string) => request<any>(`/api/schedules/${id}`, { method: 'DELETE' }),

  // AI Security Copilot
  copilotChat: (data: { project_id: string; assessment_id?: string; finding_id?: string; message: string; chat_history?: any[] }) =>
    request<any>('/api/copilot/chat', { method: 'POST', body: JSON.stringify(data) }),
  explainFinding: (findingId: string) =>
    request<any>(`/api/copilot/explain-finding`, { method: 'POST', body: JSON.stringify({ finding_id: findingId }) }),

  // System Observability & Health
  getSystemStatus: () => request<any>('/api/system/status'),
  getDetailedHealth: () => request<any>('/api/system/health/detailed'),
  getScannerHealth: () => request<any[]>('/api/system/scanners'),

  // API Keys & Webhooks
  getApiKeys: (orgId: string) => request<any[]>(`/api/organizations/${orgId}/api-keys`),
  createApiKey: (orgId: string, data: any) => request<any>(`/api/organizations/${orgId}/api-keys`, { method: 'POST', body: JSON.stringify(data) }),
  deleteApiKey: (id: string) => request<any>(`/api/api-keys/${id}`, { method: 'DELETE' }),
  getAuditLogs: (orgId: string) => request<any[]>(`/api/organizations/${orgId}/audit-logs`),
  getWebhooks: (orgId: string) => request<any[]>(`/api/organizations/${orgId}/webhooks`),
  createWebhook: (orgId: string, data: any) => request<any>(`/api/organizations/${orgId}/webhooks`, { method: 'POST', body: JSON.stringify(data) }),
};
