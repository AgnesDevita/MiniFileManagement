# Authentication Security Testing Guide

## Overview

This guide provides a comprehensive approach to testing authentication vulnerabilities in your personal test environment. It focuses on defensive security testing methods, common vulnerabilities, and secure coding practices.

## Table of Contents

1. [Environment Setup](#environment-setup)
2. [Common Authentication Vulnerabilities](#common-authentication-vulnerabilities)
3. [Testing Methodologies](#testing-methodologies)
4. [Secure Implementation Examples](#secure-implementation-examples)
5. [Defensive Measures](#defensive-measures)
6. [Tools and Techniques](#tools-and-techniques)

## Environment Setup

### Prerequisites
- Isolated test environment (never test on production)
- Local development setup
- Network isolation or VPN
- Proper documentation and logging

### Legal and Ethical Considerations
- Only test systems you own or have explicit permission to test
- Document all testing activities
- Follow responsible disclosure practices
- Comply with local laws and regulations

## Common Authentication Vulnerabilities

### 1. Weak Password Policies

**Vulnerability Description:**
Systems that allow weak passwords or don't enforce complexity requirements.

**Testing Methods:**
```bash
# Test common passwords
curl -X POST http://localhost:3001/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@dms.com","password":"password"}'

# Test empty passwords
curl -X POST http://localhost:3001/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@dms.com","password":""}'
```

**Secure Implementation:**
```javascript
// Password validation middleware
const validatePassword = (password) => {
  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
  
  return password.length >= minLength && 
         hasUpperCase && 
         hasLowerCase && 
         hasNumbers && 
         hasSpecialChar;
};
```

### 2. Brute Force Attacks

**Vulnerability Description:**
Lack of rate limiting allows attackers to attempt multiple login combinations.

**Testing Methods:**
```bash
# Test rate limiting
for i in {1..10}; do
  curl -X POST http://localhost:3001/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@dms.com","password":"wrong'$i'"}' &
done
wait
```

**Secure Implementation:**
```javascript
// Rate limiting implementation
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: 'Too many login attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/v1/auth/login', loginLimiter);
```

### 3. Session Management Issues

**Vulnerability Description:**
Improper session handling, including session fixation and hijacking.

**Testing Methods:**
```javascript
// Test session fixation
// 1. Get initial session
fetch('/api/v1/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: 'user@dms.com', password: 'test' })
})
.then(response => {
  // Check if session ID changes after login
  console.log('Session cookies:', response.headers.get('set-cookie'));
});
```

**Secure Implementation:**
```javascript
// Secure session configuration
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    httpOnly: true, // Prevent XSS
    maxAge: 1000 * 60 * 60 * 24, // 24 hours
    sameSite: 'strict' // CSRF protection
  },
  genid: () => {
    return require('crypto').randomBytes(32).toString('hex');
  }
}));
```

### 4. JWT Token Vulnerabilities

**Vulnerability Description:**
Weak JWT implementation, including algorithm confusion and weak secrets.

**Testing Methods:**
```javascript
// Test JWT algorithm confusion
const jwt = require('jsonwebtoken');

// Try to decode without verification
const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...';
const decoded = jwt.decode(token, { complete: true });
console.log('JWT Header:', decoded.header);
console.log('JWT Payload:', decoded.payload);

// Test weak secret
const weakSecrets = ['secret', '123456', 'password', 'jwt-secret'];
weakSecrets.forEach(secret => {
  try {
    const verified = jwt.verify(token, secret);
    console.log('Weak secret found:', secret);
  } catch (err) {
    // Secret didn't work
  }
});
```

**Secure Implementation:**
```javascript
// Secure JWT implementation
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Generate strong secret
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

// Token generation with proper claims
const generateToken = (user) => {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
      role: user.role,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24), // 24 hours
      iss: 'document-management-system',
      aud: 'dms-users'
    },
    JWT_SECRET,
    { algorithm: 'HS256' }
  );
};

// Token verification middleware
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: 'document-management-system',
      audience: 'dms-users'
    });
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};
```

### 5. SQL Injection in Authentication

**Vulnerability Description:**
Improper input sanitization allowing SQL injection in login queries.

**Testing Methods:**
```bash
# Test SQL injection payloads
curl -X POST http://localhost:3001/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@dms.com'\'' OR 1=1 --","password":"anything"}'

# Test time-based blind SQL injection
curl -X POST http://localhost:3001/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@dms.com'\'' AND (SELECT SLEEP(5)) --","password":"test"}'
```

**Secure Implementation:**
```javascript
// Using parameterized queries (example with PostgreSQL)
const { Pool } = require('pg');
const pool = new Pool();

const authenticateUser = async (email, password) => {
  // Parameterized query prevents SQL injection
  const query = 'SELECT * FROM users WHERE email = $1 AND password_hash = $2';
  const hashedPassword = await bcrypt.hash(password, 10);
  
  try {
    const result = await pool.query(query, [email, hashedPassword]);
    return result.rows[0];
  } catch (error) {
    console.error('Database error:', error);
    throw new Error('Authentication failed');
  }
};
```

## Testing Methodologies

### 1. Manual Testing Approach

**Step-by-Step Process:**

1. **Reconnaissance**
   ```bash
   # Identify authentication endpoints
   curl -I http://localhost:3001/api/v1/auth/login
   curl -I http://localhost:3001/api/v1/auth/logout
   ```

2. **Input Validation Testing**
   ```bash
   # Test various input formats
   curl -X POST http://localhost:3001/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email":"<script>alert(1)</script>","password":"test"}'
   ```

3. **Response Analysis**
   ```bash
   # Analyze error messages for information disclosure
   curl -v -X POST http://localhost:3001/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email":"nonexistent@test.com","password":"test"}'
   ```

### 2. Automated Testing Tools

**Burp Suite Configuration:**
```
1. Configure proxy settings
2. Set up target scope
3. Use Intruder for brute force testing
4. Analyze responses for vulnerabilities
```

**OWASP ZAP Testing:**
```bash
# Start ZAP in daemon mode
zap.sh -daemon -port 8080

# Run automated scan
curl "http://localhost:8080/JSON/ascan/action/scan/?url=http://localhost:3001&recurse=true"
```

## Defensive Measures

### 1. Multi-Factor Authentication (MFA)

**Implementation Example:**
```javascript
const speakeasy = require('speakeasy');

// Generate MFA secret for user
const generateMFASecret = (user) => {
  return speakeasy.generateSecret({
    name: `DMS (${user.email})`,
    issuer: 'Document Management System'
  });
};

// Verify MFA token
const verifyMFAToken = (token, secret) => {
  return speakeasy.totp.verify({
    secret: secret,
    encoding: 'base32',
    token: token,
    window: 2
  });
};
```

### 2. Account Lockout Mechanisms

**Implementation:**
```javascript
const accountLockout = {
  attempts: new Map(),
  
  recordFailedAttempt(email) {
    const attempts = this.attempts.get(email) || { count: 0, lockedUntil: null };
    attempts.count++;
    
    if (attempts.count >= 5) {
      attempts.lockedUntil = Date.now() + (30 * 60 * 1000); // 30 minutes
    }
    
    this.attempts.set(email, attempts);
  },
  
  isLocked(email) {
    const attempts = this.attempts.get(email);
    if (!attempts || !attempts.lockedUntil) return false;
    
    if (Date.now() > attempts.lockedUntil) {
      this.attempts.delete(email);
      return false;
    }
    
    return true;
  }
};
```

### 3. Secure Password Storage

**Implementation:**
```javascript
const bcrypt = require('bcrypt');
const argon2 = require('argon2');

// Using bcrypt (good)
const hashPasswordBcrypt = async (password) => {
  const saltRounds = 12;
  return await bcrypt.hash(password, saltRounds);
};

// Using Argon2 (better)
const hashPasswordArgon2 = async (password) => {
  return await argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 2 ** 16, // 64 MB
    timeCost: 3,
    parallelism: 1,
  });
};
```

### 4. Input Validation and Sanitization

**Implementation:**
```javascript
const validator = require('validator');
const xss = require('xss');

const validateLoginInput = (email, password) => {
  const errors = [];
  
  // Email validation
  if (!email || !validator.isEmail(email)) {
    errors.push('Valid email is required');
  }
  
  // Password validation
  if (!password || password.length < 8) {
    errors.push('Password must be at least 8 characters');
  }
  
  // Sanitize inputs
  const sanitizedEmail = validator.normalizeEmail(email);
  const sanitizedPassword = xss(password);
  
  return {
    isValid: errors.length === 0,
    errors,
    sanitizedEmail,
    sanitizedPassword
  };
};
```

## Tools and Techniques

### 1. Security Testing Tools

**Burp Suite Professional:**
- Automated vulnerability scanning
- Manual testing capabilities
- Session management testing

**OWASP ZAP:**
- Free and open-source
- Automated scanning
- API testing capabilities

**Postman/Newman:**
- API testing and automation
- Security test collections
- CI/CD integration

### 2. Code Analysis Tools

**Static Analysis:**
```bash
# ESLint with security rules
npm install eslint-plugin-security
```

**Dynamic Analysis:**
```bash
# Node Security Platform
npm audit

# Snyk vulnerability scanning
npx snyk test
```

### 3. Monitoring and Logging

**Implementation:**
```javascript
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'security.log' })
  ]
});

// Log authentication events
const logAuthEvent = (event, email, ip, success) => {
  logger.info({
    event,
    email,
    ip,
    success,
    timestamp: new Date().toISOString()
  });
};
```

## Conclusion

This guide provides a foundation for testing authentication security in your personal test environment. Remember to:

1. Always test in isolated environments
2. Document all findings
3. Implement fixes based on discoveries
4. Regularly update and review security measures
5. Stay informed about new vulnerabilities and attack techniques

## Additional Resources

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)
- [JWT Security Best Practices](https://tools.ietf.org/html/rfc8725)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)