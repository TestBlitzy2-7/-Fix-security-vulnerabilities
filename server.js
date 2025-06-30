const express = require('express');
const https = require('https');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
const fs = require('fs');
const path = require('path');

// Import custom security and configuration modules
const securityConfig = require('./middleware/security');
const validationConfig = require('./middleware/validation');
const httpsConfig = require('./config/https');

// Create Express application instance
const app = express();

// Configuration constants
const hostname = '127.0.0.1';
const port = 3000;

// Security middleware stack - order is critical for proper functioning
// 1. Helmet.js - Must be first to set security headers early
app.use(helmet(securityConfig.helmetConfig));

// 2. CORS - Must precede route handlers to handle preflight requests
app.use(cors(securityConfig.corsConfig));

// 3. Rate limiting - Must precede routes to count all requests
const limiter = rateLimit(securityConfig.rateLimitConfig);
app.use(limiter);

// 4. Body parser - Must precede validation
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 5. Global error handling middleware for validation errors
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Validation failed',
      details: errors.array().map(err => ({
        field: err.path || err.param,
        message: err.msg,
        value: err.value
      }))
    });
  }
  next();
};

// Main route - maintains backward compatibility with "Hello, World!" response
// Apply validation middleware to demonstrate input validation capability
app.get('/', 
  validationConfig.basicGetValidation,
  handleValidationErrors,
  (req, res) => {
    // Set additional security headers for this specific route
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Type', 'text/plain');
    
    // Maintain original response for backward compatibility
    res.status(200).send('Hello, World!\n');
  }
);

// Health check endpoint with validation
app.get('/health', 
  validationConfig.basicGetValidation,
  handleValidationErrors,
  (req, res) => {
    res.status(200).json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      security: {
        https: true,
        headers: 'enabled',
        rateLimit: 'active',
        validation: 'enabled'
      }
    });
  }
);

// POST endpoint example with comprehensive input validation
app.post('/data',
  validationConfig.postDataValidation,
  handleValidationErrors,
  (req, res) => {
    // Demonstrate validated and sanitized input processing
    const { name, email, message } = req.body;
    
    res.status(200).json({
      success: true,
      message: 'Data received and validated successfully',
      receivedData: {
        name: name,
        email: email,
        message: message,
        processedAt: new Date().toISOString()
      }
    });
  }
);

// Catch-all route for undefined endpoints
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: `The requested endpoint ${req.originalUrl} does not exist`,
    availableEndpoints: [
      'GET /',
      'GET /health',
      'POST /data'
    ]
  });
});

// Global error handling middleware
app.use((err, req, res, next) => {
  console.error('Server Error:', err.stack);
  
  // Don't leak error details in production
  const isDevelopment = process.env.NODE_ENV !== 'production';
  
  res.status(err.status || 500).json({
    error: 'Internal Server Error',
    message: isDevelopment ? err.message : 'Something went wrong',
    ...(isDevelopment && { stack: err.stack })
  });
});

// HTTPS server configuration and startup
const startServer = async () => {
  try {
    // Load SSL certificates
    const serverOptions = httpsConfig.getServerOptions();
    
    // Verify certificates exist
    if (!fs.existsSync(serverOptions.cert) || !fs.existsSync(serverOptions.key)) {
      console.error('SSL certificates not found. Please ensure server.cert and server.key exist.');
      console.error('Run: npm run generate-cert to create self-signed certificates for development.');
      process.exit(1);
    }
    
    // Read certificate files
    const httpsOptions = {
      key: fs.readFileSync(serverOptions.key),
      cert: fs.readFileSync(serverOptions.cert),
      // Additional TLS security options
      ciphers: httpsConfig.secureConfig.ciphers,
      honorCipherOrder: true,
      secureProtocol: httpsConfig.secureConfig.secureProtocol,
      // Disable insecure protocols
      secureOptions: httpsConfig.secureConfig.secureOptions
    };
    
    // Create HTTPS server
    const server = https.createServer(httpsOptions, app);
    
    // Enhanced server startup with comprehensive logging
    server.listen(port, hostname, () => {
      console.log('🚀 Security-Hardened HTTPS Server Started');
      console.log('=====================================');
      console.log(`🔒 HTTPS Server running at https://${hostname}:${port}/`);
      console.log(`🛡️  Security Features Enabled:`);
      console.log(`   ✓ TLS 1.2+ Encryption`);
      console.log(`   ✓ Security Headers (Helmet.js)`);
      console.log(`   ✓ Rate Limiting Protection`);
      console.log(`   ✓ Input Validation & Sanitization`);
      console.log(`   ✓ CORS Policy Enforcement`);
      console.log(`   ✓ Content Security Policy`);
      console.log(`📊 Available Endpoints:`);
      console.log(`   GET  /        - Hello World (backward compatible)`);
      console.log(`   GET  /health  - System health check`);
      console.log(`   POST /data    - Validated data processing`);
      console.log('=====================================');
      console.log('⚠️  Development Mode: Using self-signed certificates');
      console.log('   Your browser will show security warnings - this is expected');
      console.log('   For production, replace with CA-signed certificates');
      console.log('=====================================');
    });
    
    // Enhanced error handling for server startup
    server.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        console.error(`❌ Port ${port} is already in use`);
        console.error('Please stop other processes using this port or choose a different port');
      } else if (err.code === 'EACCES') {
        console.error(`❌ Permission denied to bind to port ${port}`);
        console.error('Try using a port number greater than 1024 or run with appropriate permissions');
      } else {
        console.error('❌ Server startup error:', err.message);
      }
      process.exit(1);
    });
    
    // Graceful shutdown handling
    const shutdown = (signal) => {
      console.log(`\n📤 Received ${signal}. Shutting down gracefully...`);
      server.close((err) => {
        if (err) {
          console.error('❌ Error during server shutdown:', err);
          process.exit(1);
        }
        console.log('✅ HTTPS server shut down successfully');
        process.exit(0);
      });
    };
    
    // Register signal handlers
    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    
    // Handle uncaught exceptions and unhandled rejections
    process.on('uncaughtException', (err) => {
      console.error('❌ Uncaught Exception:', err);
      console.error('Server will shut down to prevent unstable state');
      process.exit(1);
    });
    
    process.on('unhandledRejection', (reason, promise) => {
      console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
      console.error('Server will shut down to prevent unstable state');
      process.exit(1);
    });
    
  } catch (error) {
    console.error('❌ Failed to start HTTPS server:', error.message);
    
    // Provide helpful error messages for common issues
    if (error.code === 'ENOENT') {
      console.error('📋 SSL certificate files not found. Please ensure:');
      console.error('   1. server.cert and server.key exist in the project root');
      console.error('   2. Run: npm run generate-cert (if available)');
      console.error('   3. Or create certificates manually using OpenSSL');
    } else if (error.code === 'EACCES') {
      console.error('📋 Permission error. Please ensure:');
      console.error('   1. Certificate files are readable');
      console.error('   2. Process has appropriate file permissions');
    }
    
    process.exit(1);
  }
};

// Start the server
startServer();

// Export app for testing purposes
module.exports = app;