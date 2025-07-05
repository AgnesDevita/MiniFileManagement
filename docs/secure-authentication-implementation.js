/**
 * Secure Authentication Implementation Examples
 * These examples demonstrate secure coding practices
 */

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const validator = require('validator');
const crypto = require('crypto');

// 1. Secure Password Hashing
class SecurePasswordManager {
  static async hashPassword(password) {
    // Use bcrypt with appropriate cost factor
    const saltRounds = 12; // Adjust based on your security requirements
    return await bcrypt.hash(password, saltRounds);
  }
  
  static async verifyPassword(password, hash) {
    return await bcrypt.compare(password, hash);
  }
  
  static validatePasswordStrength(password) {
    const minLength = 8;
    const maxLength = 128;
    
    const checks = {
      length: password.length >= minLength && password.length <= maxLength,
      uppercase: /[A-Z]/.test(password),
      lowercase: /[a-z]/.test(password),
      numbers: /\d/.test(password),
      specialChars: /[!@#$%^&*(),.?":{}|<>]/.test(password),
      noCommonPatterns: !this.isCommonPassword(password)
    };
    
    const score = Object.values(checks).filter(Boolean).length;
    
    return {
      isValid: score >= 5,
      score,
      checks,
      suggestions: this.getPasswordSuggestions(checks)
    };
  }
  
  static isCommonPassword(password) {
    const commonPasswords = [
      'password', '123456', '123456789', 'qwerty', 'abc123',
      'password123', 'admin', 'letmein', 'welcome', 'monkey'
    ];
    return commonPasswords.includes(password.toLowerCase());
  }
  
  static getPasswordSuggestions(checks) {
    const suggestions = [];
    if (!checks.length) suggestions.push('Use at least 8 characters');
    if (!checks.uppercase) suggestions.push('Include uppercase letters');
    if (!checks.lowercase) suggestions.push('Include lowercase letters');
    if (!checks.numbers) suggestions.push('Include numbers');
    if (!checks.specialChars) suggestions.push('Include special characters');
    if (!checks.noCommonPatterns) suggestions.push('Avoid common passwords');
    return suggestions;
  }
}

// 2. Secure JWT Implementation
class SecureJWTManager {
  constructor() {
    this.secret = process.env.JWT_SECRET || this.generateSecureSecret();
    this.issuer = 'document-management-system';
    this.audience = 'dms-users';
  }
  
  generateSecureSecret() {
    // Generate a cryptographically secure random secret
    return crypto.randomBytes(64).toString('hex');
  }
  
  generateToken(user) {
    const payload = {
      sub: user.id,
      email: user.email,
      role: user.role,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24), // 24 hours
      iss: this.issuer,
      aud: this.audience,
      jti: crypto.randomUUID() // Unique token ID for revocation
    };
    
    return jwt.sign(payload, this.secret, {
      algorithm: 'HS256',
      issuer: this.issuer,
      audience: this.audience
    });
  }
  
  verifyToken(token) {
    try {
      return jwt.verify(token, this.secret, {
        algorithms: ['HS256'],
        issuer: this.issuer,
        audience: this.audience,
        clockTolerance: 30 // 30 seconds clock tolerance
      });
    } catch (error) {
      throw new Error(`Token verification failed: ${error.message}`);
    }
  }
  
  refreshToken(token) {
    try {
      const decoded = this.verifyToken(token);
      
      // Check if token is close to expiry (within 1 hour)
      const timeUntilExpiry = decoded.exp - Math.floor(Date.now() / 1000);
      if (timeUntilExpiry > 3600) {
        return null; // Token doesn't need refresh yet
      }
      
      // Generate new token with same user data
      return this.generateToken({
        id: decoded.sub,
        email: decoded.email,
        role: decoded.role
      });
    } catch (error) {
      throw new Error('Token refresh failed');
    }
  }
}

// 3. Rate Limiting and Brute Force Protection
class BruteForceProtection {
  constructor() {
    this.attempts = new Map();
    this.blockedIPs = new Map();
  }
  
  // Create rate limiter middleware
  createRateLimiter(windowMs = 15 * 60 * 1000, max = 5) {
    return rateLimit({
      windowMs,
      max,
      message: {
        success: false,
        error: 'Too many authentication attempts. Please try again later.',
        retryAfter: Math.ceil(windowMs / 1000)
      },
      standardHeaders: true,
      legacyHeaders: false,
      handler: (req, res) => {
        this.logSuspiciousActivity(req.ip, 'Rate limit exceeded');
        res.status(429).json({
          success: false,
          error: 'Too many requests',
          retryAfter: Math.ceil(windowMs / 1000)
        });
      }
    });
  }
  
  // Track failed login attempts
  recordFailedAttempt(identifier, ip) {
    const key = `${identifier}:${ip}`;
    const attempts = this.attempts.get(key) || { count: 0, firstAttempt: Date.now() };
    
    attempts.count++;
    attempts.lastAttempt = Date.now();
    
    // Progressive delays
    if (attempts.count >= 5) {
      const blockDuration = Math.min(attempts.count * 60 * 1000, 30 * 60 * 1000); // Max 30 minutes
      this.blockedIPs.set(ip, Date.now() + blockDuration);
      this.logSuspiciousActivity(ip, `Account locked after ${attempts.count} failed attempts`);
    }
    
    this.attempts.set(key, attempts);
  }
  
  // Check if IP or account is blocked
  isBlocked(identifier, ip) {
    const key = `${identifier}:${ip}`;
    const attempts = this.attempts.get(key);
    const ipBlock = this.blockedIPs.get(ip);
    
    // Check IP block
    if (ipBlock && Date.now() < ipBlock) {
      return { blocked: true, reason: 'IP temporarily blocked', retryAfter: ipBlock };
    }
    
    // Check account attempts
    if (attempts && attempts.count >= 5) {
      const blockTime = attempts.lastAttempt + (attempts.count * 60 * 1000);
      if (Date.now() < blockTime) {
        return { blocked: true, reason: 'Account temporarily locked', retryAfter: blockTime };
      }
    }
    
    return { blocked: false };
  }
  
  // Reset attempts on successful login
  resetAttempts(identifier, ip) {
    const key = `${identifier}:${ip}`;
    this.attempts.delete(key);
    this.blockedIPs.delete(ip);
  }
  
  // Log suspicious activity
  logSuspiciousActivity(ip, reason) {
    console.warn(`[SECURITY] Suspicious activity from ${ip}: ${reason}`);
    // In production, send to security monitoring system
  }
  
  // Cleanup old entries
  cleanup() {
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours
    
    for (const [key, attempts] of this.attempts.entries()) {
      if (now - attempts.firstAttempt > maxAge) {
        this.attempts.delete(key);
      }
    }
    
    for (const [ip, blockTime] of this.blockedIPs.entries()) {
      if (now > blockTime) {
        this.blockedIPs.delete(ip);
      }
    }
  }
}

// 4. Input Validation and Sanitization
class InputValidator {
  static validateEmail(email) {
    if (!email || typeof email !== 'string') {
      return { valid: false, error: 'Email is required' };
    }
    
    if (!validator.isEmail(email)) {
      return { valid: false, error: 'Invalid email format' };
    }
    
    if (email.length > 254) {
      return { valid: false, error: 'Email too long' };
    }
    
    return { valid: true, sanitized: validator.normalizeEmail(email) };
  }
  
  static validatePassword(password) {
    if (!password || typeof password !== 'string') {
      return { valid: false, error: 'Password is required' };
    }
    
    const strength = SecurePasswordManager.validatePasswordStrength(password);
    if (!strength.isValid) {
      return {
        valid: false,
        error: 'Password does not meet security requirements',
        suggestions: strength.suggestions
      };
    }
    
    return { valid: true };
  }
  
  static sanitizeInput(input) {
    if (typeof input !== 'string') return input;
    
    // Remove null bytes and control characters
    return input.replace(/[\x00-\x1F\x7F]/g, '');
  }
  
  static validateLoginRequest(req) {
    const { email, password } = req.body;
    const errors = [];
    
    const emailValidation = this.validateEmail(email);
    if (!emailValidation.valid) {
      errors.push(emailValidation.error);
    }
    
    const passwordValidation = this.validatePassword(password);
    if (!passwordValidation.valid) {
      errors.push(passwordValidation.error);
    }
    
    return {
      valid: errors.length === 0,
      errors,
      sanitizedData: {
        email: emailValidation.sanitized || email,
        password: this.sanitizeInput(password)
      }
    };
  }
}

// 5. Secure Session Management
class SecureSessionManager {
  constructor() {
    this.activeSessions = new Map();
  }
  
  createSession(user, req) {
    const sessionId = crypto.randomUUID();
    const session = {
      id: sessionId,
      userId: user.id,
      email: user.email,
      role: user.role,
      createdAt: new Date(),
      lastActivity: new Date(),
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      isActive: true
    };
    
    this.activeSessions.set(sessionId, session);
    return sessionId;
  }
  
  validateSession(sessionId, req) {
    const session = this.activeSessions.get(sessionId);
    
    if (!session || !session.isActive) {
      return { valid: false, error: 'Invalid session' };
    }
    
    // Check session timeout (24 hours)
    const maxAge = 24 * 60 * 60 * 1000;
    if (Date.now() - session.createdAt.getTime() > maxAge) {
      this.invalidateSession(sessionId);
      return { valid: false, error: 'Session expired' };
    }
    
    // Check for session hijacking
    if (session.ip !== req.ip) {
      this.invalidateSession(sessionId);
      this.logSecurityEvent('Session hijacking attempt', { sessionId, originalIP: session.ip, newIP: req.ip });
      return { valid: false, error: 'Session security violation' };
    }
    
    // Update last activity
    session.lastActivity = new Date();
    
    return { valid: true, session };
  }
  
  invalidateSession(sessionId) {
    const session = this.activeSessions.get(sessionId);
    if (session) {
      session.isActive = false;
    }
    this.activeSessions.delete(sessionId);
  }
  
  invalidateAllUserSessions(userId) {
    for (const [sessionId, session] of this.activeSessions.entries()) {
      if (session.userId === userId) {
        this.invalidateSession(sessionId);
      }
    }
  }
  
  logSecurityEvent(event, details) {
    console.warn(`[SECURITY EVENT] ${event}:`, details);
    // In production, send to security monitoring system
  }
}

// 6. Complete Secure Authentication Middleware
class SecureAuthenticationSystem {
  constructor() {
    this.passwordManager = new SecurePasswordManager();
    this.jwtManager = new SecureJWTManager();
    this.bruteForceProtection = new BruteForceProtection();
    this.sessionManager = new SecureSessionManager();
    this.validator = new InputValidator();
  }
  
  // Login endpoint with all security measures
  async login(req, res) {
    try {
      // 1. Input validation
      const validation = InputValidator.validateLoginRequest(req);
      if (!validation.valid) {
        return res.status(400).json({
          success: false,
          error: 'Invalid input',
          details: validation.errors
        });
      }
      
      const { email, password } = validation.sanitizedData;
      
      // 2. Check brute force protection
      const blockCheck = this.bruteForceProtection.isBlocked(email, req.ip);
      if (blockCheck.blocked) {
        return res.status(429).json({
          success: false,
          error: blockCheck.reason,
          retryAfter: Math.ceil((blockCheck.retryAfter - Date.now()) / 1000)
        });
      }
      
      // 3. Authenticate user (replace with your user lookup logic)
      const user = await this.authenticateUser(email, password);
      if (!user) {
        this.bruteForceProtection.recordFailedAttempt(email, req.ip);
        return res.status(401).json({
          success: false,
          error: 'Invalid credentials'
        });
      }
      
      // 4. Reset brute force attempts on successful login
      this.bruteForceProtection.resetAttempts(email, req.ip);
      
      // 5. Generate secure token
      const token = this.jwtManager.generateToken(user);
      
      // 6. Create session
      const sessionId = this.sessionManager.createSession(user, req);
      
      // 7. Set secure cookie
      res.cookie('sessionId', sessionId, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
      });
      
      // 8. Return success response
      res.json({
        success: true,
        data: {
          token,
          user: {
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.role
          }
        }
      });
      
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({
        success: false,
        error: 'Internal server error'
      });
    }
  }
  
  // Authentication middleware
  authenticate(req, res, next) {
    try {
      const authHeader = req.headers.authorization;
      const token = authHeader && authHeader.split(' ')[1];
      
      if (!token) {
        return res.status(401).json({
          success: false,
          error: 'Access token required'
        });
      }
      
      const decoded = this.jwtManager.verifyToken(token);
      req.user = decoded;
      next();
      
    } catch (error) {
      return res.status(403).json({
        success: false,
        error: 'Invalid or expired token'
      });
    }
  }
  
  // Placeholder for user authentication logic
  async authenticateUser(email, password) {
    // Replace with your actual user lookup and password verification
    // This is just a placeholder
    const users = [
      { id: '1', email: 'admin@dms.com', name: 'Admin', role: 'admin' },
      { id: '2', email: 'user@dms.com', name: 'User', role: 'user' }
    ];
    
    return users.find(u => u.email === email);
  }
}

module.exports = {
  SecurePasswordManager,
  SecureJWTManager,
  BruteForceProtection,
  InputValidator,
  SecureSessionManager,
  SecureAuthenticationSystem
};