import React, { useState, useEffect } from 'react';
import { FileText, MapPin, Calendar, ExternalLink, Search, Filter } from 'lucide-react';
import { Document } from '../types/document';
import { apiService } from '../services/api';

interface DocumentListProps {
  refreshTrigger: number;
}

const DocumentList: React.FC<DocumentListProps> = ({ refreshTrigger }) => {
  const [documents, setDocuments] = useState<Document[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState<string>('ALL');
  const [error, setError] = useState('');

  const fetchDocuments = async () => {
    try {
      setLoading(true);
      const response = await apiService.getDocuments();
      if (response.success && response.data) {
        setDocuments(response.data);
      } else {
        setError(response.error || 'Failed to fetch documents');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch documents');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDocuments();
  }, [refreshTrigger]);

  const filteredDocuments = documents.filter(doc => {
    const matchesSearch = doc.documentTitle.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         doc.physicalLocation.locationId.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         doc.physicalLocation.floor.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesFilter = filterType === 'ALL' || doc.documentType === filterType;
    
    return matchesSearch && matchesFilter;
  });

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getDocumentTypeColor = (type: string) => {
    switch (type) {
      case 'DIGITAL_ONLY':
        return 'bg-blue-100 text-blue-800';
      case 'PHYSICAL_ONLY':
        return 'bg-green-100 text-green-800';
      case 'BOTH':
        return 'bg-purple-100 text-purple-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Search and Filter */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
          <input
            type="text"
            placeholder="Search documents..."
            className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
        <div className="relative">
          <Filter className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
          <select
            className="pl-10 pr-8 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
          >
            <option value="ALL">All Types</option>
            <option value="DIGITAL_ONLY">Digital Only</option>
            <option value="PHYSICAL_ONLY">Physical Only</option>
            <option value="BOTH">Both</option>
          </select>
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-md p-4">
          <p className="text-red-600">{error}</p>
        </div>
      )}

      {/* Documents Grid */}
      {filteredDocuments.length === 0 ? (
        <div className="text-center py-12">
          <FileText className="mx-auto h-12 w-12 text-gray-400 mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">No documents found</h3>
          <p className="text-gray-500">
            {searchTerm || filterType !== 'ALL' 
              ? 'Try adjusting your search or filter criteria.'
              : 'Get started by registering your first document.'}
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredDocuments.map((document) => (
            <div
              key={document.documentId}
              className="bg-white rounded-lg shadow-md border border-gray-200 hover:shadow-lg transition-shadow"
            >
              <div className="p-6">
                {/* Header */}
                <div className="flex items-start justify-between mb-4">
                  <h3 className="text-lg font-semibold text-gray-900 line-clamp-2">
                    {document.documentTitle}
                  </h3>
                  <span className={`px-2 py-1 text-xs font-medium rounded-full ${getDocumentTypeColor(document.documentType)}`}>
                    {document.documentType.replace('_', ' ')}
                  </span>
                </div>

                {/* Physical Location */}
                <div className="flex items-center text-sm text-gray-600 mb-3">
                  <MapPin className="h-4 w-4 mr-2" />
                  <span>
                    {document.physicalLocation.locationType} {document.physicalLocation.locationId}, 
                    Floor {document.physicalLocation.floor}
                  </span>
                </div>

                {/* File Info */}
                {document.fileUrl && (
                  <div className="flex items-center justify-between text-sm text-gray-600 mb-3">
                    <span className="flex items-center">
                      <FileText className="h-4 w-4 mr-2" />
                      {document.fileName}
                    </span>
                    <a
                      href={`http://localhost:3001${document.fileUrl}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-indigo-600 hover:text-indigo-800 transition-colors"
                    >
                      <ExternalLink className="h-4 w-4" />
                    </a>
                  </div>
                )}

                {/* Additional Info */}
                {document.physicalLocation.additionalInfo && (
                  <div className="text-sm text-gray-600 mb-3">
                    <span className="font-medium">Note:</span> {document.physicalLocation.additionalInfo}
                  </div>
                )}

                {/* File Size */}
                {document.fileSize && (
                  <div className="text-xs text-gray-500 mb-3">
                    File size: {(document.fileSize / 1024 / 1024).toFixed(2)} MB
                  </div>
                )}

                {/* Footer */}
                <div className="flex items-center text-xs text-gray-500 pt-3 border-t border-gray-100">
                  <Calendar className="h-3 w-3 mr-1" />
                  <span>Created {formatDate(document.createdAt)}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default DocumentList;