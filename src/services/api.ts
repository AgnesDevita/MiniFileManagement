import { Document, DocumentRequest, ApiResponse, User } from '../types/document';

const API_BASE_URL = '/api/v1';

class ApiService {
  private token: string | null = null;

  setToken(token: string) {
    this.token = token;
    localStorage.setItem('dms_token', token);
  }

  getToken(): string | null {
    if (!this.token) {
      this.token = localStorage.getItem('dms_token');
    }
    return this.token;
  }

  clearToken() {
    this.token = null;
    localStorage.removeItem('dms_token');
  }

  private async makeRequest<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<ApiResponse<T>> {
    const token = this.getToken();
    const headers: HeadersInit = {
      ...options.headers,
    };

    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }

    if (!(options.body instanceof FormData)) {
      headers['Content-Type'] = 'application/json';
    }

    try {
      const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        ...options,
        headers,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Request failed');
      }

      return data;
    } catch (error) {
      console.error('API request failed:', error);
      throw error;
    }
  }

  async login(email: string, password: string): Promise<ApiResponse<{ token: string; user: User }>> {
    const response = await this.makeRequest<{ token: string; user: User }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });

    if (response.success && response.data?.token) {
      this.setToken(response.data.token);
    }

    return response;
  }

  async registerDocument(documentData: DocumentRequest): Promise<ApiResponse<Document>> {
    const formData = new FormData();
    formData.append('documentTitle', documentData.documentTitle);
    formData.append('physicalLocation', JSON.stringify(documentData.physicalLocation));
    formData.append('documentType', documentData.documentType);

    if (documentData.file) {
      formData.append('file', documentData.file);
    }

    return this.makeRequest<Document>('/documents', {
      method: 'POST',
      body: formData,
    });
  }

  async getDocuments(): Promise<ApiResponse<Document[]>> {
    return this.makeRequest<Document[]>('/documents');
  }

  async getDocument(id: string): Promise<ApiResponse<Document>> {
    return this.makeRequest<Document>(`/documents/${id}`);
  }

  async checkHealth(): Promise<ApiResponse<any>> {
    return fetch('/api/health')
      .then(res => res.json())
      .catch(() => ({ success: false, error: 'API unavailable' }));
  }
}

export const apiService = new ApiService();