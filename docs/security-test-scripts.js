/**
 * Security Testing Scripts for Authentication
 * Use these scripts in your personal test environment only
 */

// Test 1: Brute Force Protection
async function testBruteForceProtection() {
  console.log('Testing brute force protection...');
  
  const attempts = [];
  for (let i = 0; i < 10; i++) {
    attempts.push(
      fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'admin@dms.com',
          password: `wrong_password_${i}`
        })
      })
    );
  }
  
  try {
    const responses = await Promise.all(attempts);
    const statusCodes = responses.map(r => r.status);
    
    console.log('Response status codes:', statusCodes);
    
    // Check if rate limiting is working
    const rateLimited = statusCodes.some(code => code === 429);
    console.log('Rate limiting active:', rateLimited);
    
  } catch (error) {
    console.error('Brute force test error:', error);
  }
}

// Test 2: Input Validation
async function testInputValidation() {
  console.log('Testing input validation...');
  
  const maliciousInputs = [
    { email: '<script>alert("xss")</script>', password: 'test' },
    { email: 'admin@dms.com\'; DROP TABLE users; --', password: 'test' },
    { email: '../../../etc/passwd', password: 'test' },
    { email: 'admin@dms.com', password: '\x00\x01\x02' },
    { email: 'a'.repeat(1000), password: 'test' }
  ];
  
  for (const input of maliciousInputs) {
    try {
      const response = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input)
      });
      
      const result = await response.text();
      console.log(`Input: ${JSON.stringify(input)}`);
      console.log(`Status: ${response.status}`);
      console.log(`Response: ${result.substring(0, 100)}...`);
      console.log('---');
      
    } catch (error) {
      console.error('Input validation test error:', error);
    }
  }
}

// Test 3: Session Management
async function testSessionManagement() {
  console.log('Testing session management...');
  
  try {
    // First login
    const loginResponse = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'user@dms.com',
        password: 'test'
      })
    });
    
    const loginData = await loginResponse.json();
    const token = loginData.data?.token;
    
    if (!token) {
      console.log('No token received');
      return;
    }
    
    console.log('Token received:', token.substring(0, 20) + '...');
    
    // Test token validation
    const protectedResponse = await fetch('/api/v1/documents', {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    
    console.log('Protected endpoint status:', protectedResponse.status);
    
    // Test token without Bearer prefix
    const invalidAuthResponse = await fetch('/api/v1/documents', {
      headers: { 'Authorization': token }
    });
    
    console.log('Invalid auth format status:', invalidAuthResponse.status);
    
  } catch (error) {
    console.error('Session management test error:', error);
  }
}

// Test 4: JWT Token Analysis
function analyzeJWTToken(token) {
  console.log('Analyzing JWT token...');
  
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      console.log('Invalid JWT format');
      return;
    }
    
    // Decode header and payload (without verification)
    const header = JSON.parse(atob(parts[0]));
    const payload = JSON.parse(atob(parts[1]));
    
    console.log('JWT Header:', header);
    console.log('JWT Payload:', payload);
    
    // Check for security issues
    if (header.alg === 'none') {
      console.warn('⚠️  WARNING: Algorithm is set to "none"');
    }
    
    if (payload.exp) {
      const expDate = new Date(payload.exp * 1000);
      const now = new Date();
      console.log('Token expires:', expDate);
      console.log('Is expired:', now > expDate);
    }
    
    if (!payload.iat) {
      console.warn('⚠️  WARNING: No issued at (iat) claim');
    }
    
  } catch (error) {
    console.error('JWT analysis error:', error);
  }
}

// Test 5: Password Policy Testing
async function testPasswordPolicy() {
  console.log('Testing password policy...');
  
  const weakPasswords = [
    '',
    '123',
    'password',
    '12345678',
    'qwerty',
    'admin',
    'test'
  ];
  
  for (const password of weakPasswords) {
    try {
      const response = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'user@dms.com',
          password: password
        })
      });
      
      console.log(`Password "${password}": Status ${response.status}`);
      
    } catch (error) {
      console.error('Password policy test error:', error);
    }
  }
}

// Test 6: Error Message Analysis
async function testErrorMessages() {
  console.log('Testing error message disclosure...');
  
  const testCases = [
    { email: 'nonexistent@test.com', password: 'test', description: 'Non-existent user' },
    { email: 'user@dms.com', password: 'wrongpassword', description: 'Wrong password' },
    { email: '', password: 'test', description: 'Empty email' },
    { email: 'user@dms.com', password: '', description: 'Empty password' },
    { email: 'invalid-email', password: 'test', description: 'Invalid email format' }
  ];
  
  for (const testCase of testCases) {
    try {
      const response = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: testCase.email,
          password: testCase.password
        })
      });
      
      const result = await response.text();
      console.log(`${testCase.description}:`);
      console.log(`Status: ${response.status}`);
      console.log(`Response: ${result}`);
      console.log('---');
      
    } catch (error) {
      console.error('Error message test error:', error);
    }
  }
}

// Main test runner
async function runSecurityTests() {
  console.log('🔒 Starting Authentication Security Tests');
  console.log('⚠️  Only run these tests in your personal test environment');
  console.log('=====================================\n');
  
  await testBruteForceProtection();
  console.log('\n');
  
  await testInputValidation();
  console.log('\n');
  
  await testSessionManagement();
  console.log('\n');
  
  await testPasswordPolicy();
  console.log('\n');
  
  await testErrorMessages();
  console.log('\n');
  
  console.log('🔒 Security tests completed');
}

// Export functions for individual testing
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    testBruteForceProtection,
    testInputValidation,
    testSessionManagement,
    analyzeJWTToken,
    testPasswordPolicy,
    testErrorMessages,
    runSecurityTests
  };
}

// Auto-run if in browser console
if (typeof window !== 'undefined') {
  console.log('Security testing functions loaded. Run runSecurityTests() to start.');
}