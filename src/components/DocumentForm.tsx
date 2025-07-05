import React, { useState } from 'react';
import { Upload, FileText, MapPin, AlertCircle, CheckCircle, X } from 'lucide-react';
import { DocumentRequest, PhysicalLocation } from '../types/document';
import { apiService } from '../services/api';

interface DocumentFormProps {
  onSuccess: () => void;
  onClose: () => void;
}

const DocumentForm: React.FC<DocumentFormProps> = ({ onSuccess, onClose }) => {
  const [formData, setFormData] = useState<DocumentRequest>({
    documentTitle: '',
    physicalLocation: {
      locationType: 'Shelf',
      locationId: '',
      floor: '',
      additionalInfo: ''
    },
    documentType: 'BOTH',
    file: undefined
  });

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);

  const handleInputChange = (field: keyof DocumentRequest, value: any) => {
    setFormData(prev => ({
      ...prev,
      [field]: value
    }));
  };

  const handlePhysicalLocationChange = (field: keyof PhysicalLocation, value: string) => {
    setFormData(prev => ({
      ...prev,
      physicalLocation: {
        ...prev.physicalLocation,
        [field]: value
      }
    }));
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    setFormData(prev => ({
      ...prev,
      file
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setError('');
    setSuccess(false);

    try {
      const response = await apiService.registerDocument(formData);
      if (response.success) {
        setSuccess(true);
        setTimeout(() => {
          onSuccess();
        }, 1500);
      } else {
        setError(response.error || 'Registration failed');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Registration failed');
    } finally {
      setIsSubmitting(false);
    }
  };

  const locationTypes = ['Shelf', 'Cabinet', 'Box', 'Folder'];
  const documentTypes = [
    { value: 'DIGITAL_ONLY', label: 'Digital Only' },
    { value: 'PHYSICAL_ONLY', label: 'Physical Only' },
    { value: 'BOTH', label: 'Both Digital & Physical' }
  ];

  if (success) {
    return (
      <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
        <div className="bg-white rounded-lg shadow-xl max-w-md w-full p-6">
          <div className="text-center">
            <div className="mx-auto h-12 w-12 bg-green-100 rounded-full flex items-center justify-center mb-4">
              <CheckCircle className="h-6 w-6 text-green-600" />
            </div>
            <h3 className="text-lg font-medium text-gray-900 mb-2">
              Document Registered Successfully!
            </h3>
            <p className="text-sm text-gray-600">
              Your document has been registered and is now available in the system.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-6 border-b">
          <h2 className="text-xl font-semibold text-gray-900">Register New Document</h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 transition-colors"
          >
            <X className="h-6 w-6" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-6">
          {/* Document Title */}
          <div>
            <label htmlFor="documentTitle" className="block text-sm font-medium text-gray-700 mb-1">
              Document Title *
            </label>
            <input
              type="text"
              id="documentTitle"
              required
              minLength={3}
              maxLength={100}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
              placeholder="Enter document title (3-100 characters)"
              value={formData.documentTitle}
              onChange={(e) => handleInputChange('documentTitle', e.target.value)}
            />
          </div>

          {/* Document Type */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Document Type *
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              {documentTypes.map((type) => (
                <label key={type.value} className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="radio"
                    name="documentType"
                    value={type.value}
                    checked={formData.documentType === type.value}
                    onChange={(e) => handleInputChange('documentType', e.target.value)}
                    className="text-indigo-600 focus:ring-indigo-500"
                  />
                  <span className="text-sm text-gray-700">{type.label}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Physical Location */}
          <div className="bg-gray-50 p-4 rounded-lg">
            <h3 className="flex items-center text-sm font-medium text-gray-700 mb-3">
              <MapPin className="h-4 w-4 mr-2" />
              Physical Location
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Location Type *
                </label>
                <select
                  required
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                  value={formData.physicalLocation.locationType}
                  onChange={(e) => handlePhysicalLocationChange('locationType', e.target.value)}
                >
                  {locationTypes.map((type) => (
                    <option key={type} value={type}>{type}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Location ID *
                </label>
                <input
                  type="text"
                  required
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                  placeholder="e.g., A, 3, Archive"
                  value={formData.physicalLocation.locationId}
                  onChange={(e) => handlePhysicalLocationChange('locationId', e.target.value)}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Floor *
                </label>
                <input
                  type="text"
                  required
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                  placeholder="e.g., 1st, Ground, Basement"
                  value={formData.physicalLocation.floor}
                  onChange={(e) => handlePhysicalLocationChange('floor', e.target.value)}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Additional Info
                </label>
                <input
                  type="text"
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                  placeholder="Optional details"
                  value={formData.physicalLocation.additionalInfo}
                  onChange={(e) => handlePhysicalLocationChange('additionalInfo', e.target.value)}
                />
              </div>
            </div>
          </div>

          {/* File Upload */}
          {formData.documentType !== 'PHYSICAL_ONLY' && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Document File {formData.documentType === 'DIGITAL_ONLY' ? '*' : ''}
              </label>
              <div className="mt-1 flex justify-center px-6 pt-5 pb-6 border-2 border-gray-300 border-dashed rounded-md hover:border-gray-400 transition-colors">
                <div className="space-y-1 text-center">
                  <Upload className="mx-auto h-12 w-12 text-gray-400" />
                  <div className="flex text-sm text-gray-600">
                    <label
                      htmlFor="file-upload"
                      className="relative cursor-pointer bg-white rounded-md font-medium text-indigo-600 hover:text-indigo-500 focus-within:outline-none focus-within:ring-2 focus-within:ring-offset-2 focus-within:ring-indigo-500"
                    >
                      <span>Upload a file</span>
                      <input
                        id="file-upload"
                        name="file-upload"
                        type="file"
                        className="sr-only"
                        accept=".pdf,.docx,.xlsx,.jpg,.jpeg"
                        onChange={handleFileChange}
                        required={formData.documentType === 'DIGITAL_ONLY'}
                      />
                    </label>
                    <p className="pl-1">or drag and drop</p>
                  </div>
                  <p className="text-xs text-gray-500">
                    PDF, DOCX, XLSX, JPG up to 10MB
                  </p>
                  {formData.file && (
                    <p className="text-sm text-green-600">
                      Selected: {formData.file.name}
                    </p>
                  )}
                </div>
              </div>
            </div>
          )}

          {error && (
            <div className="flex items-center space-x-2 text-red-600 text-sm bg-red-50 p-3 rounded-md">
              <AlertCircle className="h-4 w-4" />
              <span>{error}</span>
            </div>
          )}

          <div className="flex justify-end space-x-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-md transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-4 py-2 text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 rounded-md disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {isSubmitting ? 'Registering...' : 'Register Document'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default DocumentForm;