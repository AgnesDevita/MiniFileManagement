export interface PhysicalLocation {
  locationType: string;
  locationId: string;
  floor: string;
  additionalInfo?: string;
}

export interface Document {
  documentId: string;
  documentTitle: string;
  physicalLocation: PhysicalLocation;
  documentType: 'DIGITAL_ONLY' | 'PHYSICAL_ONLY' | 'BOTH';
  fileUrl?: string;
  fileName?: string;
  fileSize?: number;
  createdAt: string;
  updatedAt: string;
}

export interface DocumentRequest {
  documentTitle: string;
  physicalLocation: PhysicalLocation;
  documentType: 'DIGITAL_ONLY' | 'PHYSICAL_ONLY' | 'BOTH';
  file?: File;
}

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  message?: string;
  error?: string;
}

export interface User {
  id: string;
  email: string;
  name: string;
  role: 'admin' | 'user';
}