import { Document } from '../../src/types/document';
import { v4 as uuidv4 } from 'uuid';

// In-memory database for demo purposes
// In production, replace with a proper database like PostgreSQL, MongoDB, etc.
class DocumentDatabase {
  private documents: Map<string, Document> = new Map();
  private titleIndex: Set<string> = new Set();

  async create(document: Omit<Document, 'documentId' | 'createdAt' | 'updatedAt'>): Promise<Document> {
    const documentId = uuidv4();
    const now = new Date().toISOString();
    
    const newDocument: Document = {
      ...document,
      documentId,
      createdAt: now,
      updatedAt: now
    };

    this.documents.set(documentId, newDocument);
    this.titleIndex.add(document.documentTitle.toLowerCase());
    
    return newDocument;
  }

  async findByTitle(title: string): Promise<Document | null> {
    for (const doc of this.documents.values()) {
      if (doc.documentTitle.toLowerCase() === title.toLowerCase()) {
        return doc;
      }
    }
    return null;
  }

  async findById(id: string): Promise<Document | null> {
    return this.documents.get(id) || null;
  }

  async findAll(): Promise<Document[]> {
    return Array.from(this.documents.values());
  }

  async update(id: string, updates: Partial<Document>): Promise<Document | null> {
    const document = this.documents.get(id);
    if (!document) return null;

    const updatedDocument = {
      ...document,
      ...updates,
      updatedAt: new Date().toISOString()
    };

    this.documents.set(id, updatedDocument);
    return updatedDocument;
  }

  async delete(id: string): Promise<boolean> {
    const document = this.documents.get(id);
    if (!document) return false;

    this.titleIndex.delete(document.documentTitle.toLowerCase());
    return this.documents.delete(id);
  }

  isTitleExists(title: string): boolean {
    return this.titleIndex.has(title.toLowerCase());
  }
}

export const documentDB = new DocumentDatabase();