# Security-Hardened HTTPS Server

A comprehensive security-hardened HTTPS application built with Express.js and enterprise-grade security middleware. This project transforms a basic HTTP server into a production-ready secure web service with multiple layers of protection against common web vulnerabilities.

## 🔒 Security Features

### Transport Layer Security
- **HTTPS/TLS 1.2+**: All communications encrypted with modern TLS protocols
- **Automatic HTTP→HTTPS redirect**: Ensures secure connections in production
- **Self-signed certificates**: Included for development environments
- **Production CA support**: Ready for trusted certificate authority integration

### Security Headers (via Helmet.js)
- **Content Security Policy (CSP)**: Prevents XSS and code injection attacks
- **HTTP Strict Transport Security (HSTS)**: Enforces HTTPS connections
- **X-Frame-Options**: Protects against clickjacking attacks
- **X-Content-Type-Options**: Prevents MIME-type sniffing vulnerabilities
- **X-Powered-By removal**: Obscures server technology details
- **15+ additional security headers**: Comprehensive protection suite

### Request Protection
- **Rate Limiting**: Configurable request throttling per IP address
- **Input Validation**: Comprehensive validation and sanitization via express-validator
- **CORS Control**: Granular cross-origin resource sharing policies
- **DoS Protection**: Request limiting prevents abuse and denial-of-service attacks

### Security Compliance
- **OWASP ASVS Level 1**: Transport security requirements satisfied
- **ISO 27001 A.10.1**: Partial compliance through cryptographic controls
- **"A" Grade Security Headers**: Achieves top security audit ratings
- **Defense-in-Depth**: Multiple coordinated security layers

## 📋 Prerequisites

- **Node.js**: Version 14.x or higher (required for Express v4.21.2 and security middleware compatibility)
- **npm**: Node Package Manager (included with Node.js)
- **OpenSSL**: For SSL certificate generation (pre-installed on most systems)

### Verify Prerequisites

```bash
# Check Node.js version (must be ≥14.x)
node --version

# Check npm availability
npm --version

# Check OpenSSL installation
openssl version
```

## 🚀 Quick Start

### 1. Install Dependencies

```bash
# Navigate to project directory
cd /path/to/your/project

# Install security-focused dependencies
npm install
```

### 2. Generate SSL Certificates

```bash
# Generate self-signed certificates for HTTPS
npm run generate-cert
```

**Note**: This creates `server.cert` and `server.key` files required for HTTPS. These files are automatically excluded from version control for security.

### 3. Start the Server

```bash
# Start the HTTPS server
npm start
# or
node server.js
```

### 4. Verify Operation

```bash
# Test HTTPS endpoint (ignore certificate warning for self-signed cert)
curl -k https://localhost:3000

# Expected response: Hello, World!
```

## 🔧 Configuration

### Security Middleware Configuration

The security middleware stack executes in the following order:

1. **Helmet.js** → Security headers injection
2. **CORS** → Cross-origin resource sharing control
3. **Express Rate Limit** → Request throttling
4. **Express JSON** → Request parsing
5. **Express Validator** → Input validation
6. **Route Handlers** → Business logic

### Rate Limiting Configuration

Default rate limiting settings:
- **Window**: 15 minutes
- **Max Requests**: 100 per IP per window
- **Headers**: Includes both legacy and modern rate limit headers
- **Response**: 429 status when limit exceeded

### CORS Configuration

Default CORS settings:
- **Allowed Origins**: Configurable (localhost for development)
- **Allowed Methods**: GET, POST, PUT, DELETE, OPTIONS
- **Allowed Headers**: Standard headers plus custom API headers
- **Credentials**: Configurable based on requirements

### Input Validation

All incoming requests are validated for:
- **Data Types**: Ensures correct parameter types
- **Format Validation**: Email, URL, date format verification
- **Sanitization**: XSS prevention and injection attack mitigation
- **Length Limits**: Prevents oversized payload attacks

## 🌐 Usage

### Accessing the HTTPS Server

**Development Environment:**
```bash
# Access via HTTPS (will show certificate warning)
https://localhost:3000

# Using curl (ignore self-signed certificate)
curl -k https://localhost:3000
```

**Browser Access:**
1. Navigate to `https://localhost:3000`
2. **Certificate Warning**: Accept the security warning for self-signed certificate
3. **Expected Response**: "Hello, World!" message with security headers

### Security Headers Verification

Check security headers in browser developer tools:
```
Strict-Transport-Security: max-age=15552000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-DNS-Prefetch-Control: off
Content-Security-Policy: default-src 'self'
```

### Rate Limiting Testing

Test rate limiting functionality:
```bash
# Rapid requests to trigger rate limiting
for i in {1..101}; do curl -k https://localhost:3000; done

# Expected: First 100 succeed, 101st returns 429 Too Many Requests
```

## 🏗️ Architecture

### Security Middleware Pipeline

```
HTTPS Request
    ↓
Express.js Application
    ↓
helmet() → Security Headers
    ↓
cors() → Origin Validation
    ↓
express-rate-limit → Request Throttling
    ↓
express.json() → Request Parsing
    ↓
express-validator → Input Validation
    ↓
Route Handler → Business Logic
    ↓
Encrypted Response with Security Headers
```

### File Structure

```
├── server.js                 # Main HTTPS server with Express.js
├── package.json              # Security-focused dependencies
├── package-lock.json         # Dependency lockfile
├── middleware/
│   ├── security.js          # Helmet, CORS, rate limiting config
│   └── validation.js        # Input validation schemas
├── config/
│   └── https.js             # TLS/SSL configuration
├── server.cert              # SSL certificate (generated)
├── server.key               # Private key (generated)
├── .gitignore               # Excludes certificates from version control
└── README.md                # This file
```

### Dependencies

Core security-focused dependencies:
- **express** (^4.21.2): Web framework and middleware architecture
- **helmet** (^8.0.0): Security headers management
- **express-rate-limit** (^7.5.0): Request throttling and DoS protection
- **cors** (^2.8.5): Cross-origin resource sharing control
- **express-validator** (^7.2.1): Input validation and sanitization

## 🛡️ Security Best Practices

### Development Environment

1. **Certificate Warnings**: Accept self-signed certificate warnings in development
2. **Local Testing**: Use `curl -k` flag to ignore certificate validation
3. **Port Configuration**: Default HTTPS port 443, configurable to 3000 for development
4. **Localhost Binding**: Server binds to 127.0.0.1 for local development only

### Production Deployment

1. **Trusted Certificates**: Replace self-signed certificates with CA-issued certificates
2. **Environment Variables**: Configure sensitive settings via environment variables
3. **Port 443**: Bind to standard HTTPS port 443 for production
4. **Security Headers**: Customize CSP and other headers for your application
5. **Rate Limits**: Adjust rate limiting based on expected traffic patterns

### Security Monitoring

1. **Header Audits**: Regularly test security headers with online scanners
2. **Dependency Updates**: Keep security middleware updated to latest versions
3. **Certificate Expiry**: Monitor SSL certificate expiration dates
4. **Access Logs**: Implement comprehensive request logging for security analysis

## 🔍 Troubleshooting

### Common Issues

**Certificate Errors:**
```bash
# If certificate generation fails
npm run generate-cert

# Manually generate certificates
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.cert -days 365 -nodes
```

**Port Already in Use:**
```bash
# Find process using port 3000
lsof -ti:3000

# Kill process if needed
kill -9 $(lsof -ti:3000)
```

**Permission Errors (Port 443):**
```bash
# Run with elevated privileges for port 443
sudo node server.js
```

### Security Testing

**Security Header Verification:**
- Use [securityheaders.com](https://securityheaders.com) for online header analysis
- Browser developer tools → Network tab → Response headers
- `curl -I -k https://localhost:3000` for command-line header inspection

**Rate Limiting Verification:**
- Monitor `X-RateLimit-Limit` and `X-RateLimit-Remaining` headers
- Test with multiple rapid requests to trigger 429 responses
- Verify rate limit window reset behavior

## 📚 Future Enhancements

This security-hardened server provides a foundation for:

- **Authentication System**: JWT or session-based user authentication
- **Authorization Framework**: Role-based access control (RBAC)
- **Machine Learning Integration**: Secure ML model endpoints
- **Comprehensive Logging**: Security event monitoring and alerting
- **Advanced Monitoring**: Real-time threat detection capabilities

## 📜 License

This project serves as a security reference implementation and backpropagation integration testbed.
