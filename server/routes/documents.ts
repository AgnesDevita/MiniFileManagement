import express from 'express';
import rateLimit from 'express-rate-limit';
import { authenticateToken, AuthRequest } from '../middleware/auth';
import { upload } from '../middleware/upload';
import { validateDocument, handleValidationErrors } from '../middleware/validation';
import { documentDB } from '../database/documents';
import { Document } from '../../src/types/document';
import path from 'path';

const router = express.Router();

// Rate limiting: 10 requests per minute per IP
const documentUploadLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10,
  message: {
    success: false,
    error: 'Too many document uploads. Please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// POST /api/v1/documents - Register new document
router.post(
  '/',
  documentUploadLimiter,
  authenticateToken,
  upload.single('file'),
  validateDocument,
  handleValidationErrors,
  async (req: AuthRequest, res) => {
    try {
      const { documentTitle, physicalLocation, documentType } = req.body;
      const file = req.file;

      // Parse physicalLocation if it's a string
      let parsedPhysicalLocation;
      try {
        parsedPhysicalLocation = typeof physicalLocation === 'string' 
          ? JSON.parse(physicalLocation) 
          : physicalLocation;
      } catch (error) {
        return res.status(400).json({
          success: false,
          error: 'Invalid physical location format'
        });
      }

      // Validate document type and file requirements
      if (documentType === 'DIGITAL_ONLY' && !file) {
        return res.status(400).json({
          success: false,
          error: 'File is required for digital documents'
        });
      }

      if (documentType === 'PHYSICAL_ONLY' && file) {
        return res.status(400).json({
          success: false,
          error: 'File should not be provided for physical-only documents'
        });
      }

      // Check if document title already exists
      if (documentDB.isTitleExists(documentTitle)) {
        return res.status(409).json({
          success: false,
          error: 'Document title already exists'
        });
      }

      // Create document record
      const documentData: Omit<Document, 'documentId' | 'createdAt' | 'updatedAt'> = {
        documentTitle,
        physicalLocation: parsedPhysicalLocation,
        documentType,
        fileUrl: file ? `/uploads/${file.filename}` : undefined,
        fileName: file?.originalname,
        fileSize: file?.size
      };

      const document = await documentDB.create(documentData);

      // Set security headers
      res.set({
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block'
      });

      res.status(201).json({
        success: true,
        data: {
          documentId: document.documentId,
          documentTitle: document.documentTitle,
          physicalLocation: document.physicalLocation,
          fileUrl: document.fileUrl,
          createdAt: document.createdAt
        }
      });

    } catch (error) {
      console.error('Document registration error:', error);
      
      if (error instanceof Error) {
        if (error.message.includes('File too large')) {
          return res.status(413).json({
            success: false,
            error: 'File too large. Maximum size is 10MB.'
          });
        }
        
        if (error.message.includes('Unsupported file type')) {
          return res.status(415).json({
            success: false,
            error: 'Unsupported file type. Only PDF, DOCX, XLSX, and JPG files are allowed.'
          });
        }
      }

      res.status(500).json({
        success: false,
        error: 'Internal server error'
      });
    }
  }
);

// GET /api/v1/documents - Get all documents
router.get('/', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const documents = await documentDB.findAll();
    res.json({
      success: true,
      data: documents
    });
  } catch (error) {
    console.error('Get documents error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

// GET /api/v1/documents/:id - Get document by ID
router.get('/:id', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const document = await documentDB.findById(req.params.id);
    if (!document) {
      return res.status(404).json({
        success: false,
        error: 'Document not found'
      });
    }
    res.json({
      success: true,
      data: document
    });
  } catch (error) {
    console.error('Get document error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

export default router;