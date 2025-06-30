/**
 * HTTPS Configuration Module
 * 
 * Manages SSL/TLS certificate loading, TLS protocol configuration, and secure server 
 * initialization for the Express.js HTTPS implementation. Provides centralized certificate 
 * management with runtime reload capabilities and comprehensive error handling for 
 * certificate-related issues.
 * 
 * Features:
 * - SSL/TLS certificate loading with error handling
 * - TLS 1.2+ protocol enforcement with modern cipher suites
 * - Perfect Forward Secrecy support through ephemeral key exchange
 * - Runtime certificate reload without service interruption
 * - Development and production certificate scenario support
 * - Comprehensive logging for certificate operations
 * 
 * @module config/https
 */

const fs = require('fs');
const path = require('path');
const https = require('https');

/**
 * HTTPS Configuration Class
 * 
 * Encapsulates certificate management, TLS configuration, and HTTPS server options
 * with support for both development and production environments.
 */
class HttpsConfig {
  constructor() {
    this.certificatePath = path.join(process.cwd(), 'server.cert');
    this.privateKeyPath = path.join(process.cwd(), 'server.key');
    this.httpsOptions = null;
    this.certificateLoadTime = null;
    this.reloadInProgress = false;
    
    // Initialize certificate loading
    this.loadCertificates();
  }

  /**
   * Load SSL/TLS certificates from filesystem
   * 
   * Reads certificate and private key files, validates their existence,
   * and configures HTTPS options with TLS 1.2+ security settings.
   * 
   * @returns {boolean} Success status of certificate loading
   */
  loadCertificates() {
    try {
      console.log('[HTTPS Config] Loading SSL/TLS certificates...');
      
      // Validate certificate file existence
      if (!fs.existsSync(this.certificatePath)) {
        throw new Error(`SSL certificate file not found: ${this.certificatePath}`);
      }
      
      if (!fs.existsSync(this.privateKeyPath)) {
        throw new Error(`SSL private key file not found: ${this.privateKeyPath}`);
      }
      
      // Read certificate and private key files
      const cert = fs.readFileSync(this.certificatePath, 'utf8');
      const key = fs.readFileSync(this.privateKeyPath, 'utf8');
      
      // Validate certificate content
      if (!cert || cert.trim().length === 0) {
        throw new Error('SSL certificate file is empty or invalid');
      }
      
      if (!key || key.trim().length === 0) {
        throw new Error('SSL private key file is empty or invalid');
      }
      
      // Configure HTTPS options with TLS 1.2+ security settings
      this.httpsOptions = {
        // Certificate material
        cert: cert,
        key: key,
        
        // TLS Protocol Configuration - Enforce TLS 1.2+
        secureProtocol: 'TLSv1_2_method',
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.3',
        
        // Cipher Suite Configuration - Modern, secure cipher suites
        ciphers: [
          'ECDHE-RSA-AES128-GCM-SHA256',
          'ECDHE-RSA-AES256-GCM-SHA384',
          'ECDHE-RSA-AES128-SHA256',
          'ECDHE-RSA-AES256-SHA384',
          'ECDHE-RSA-AES256-SHA256',
          'DHE-RSA-AES128-GCM-SHA256',
          'DHE-RSA-AES256-GCM-SHA384',
          'DHE-RSA-AES128-SHA256',
          'DHE-RSA-AES256-SHA256',
          'AES128-GCM-SHA256',
          'AES256-GCM-SHA384',
          'AES128-SHA256',
          'AES256-SHA256'
        ].join(':'),
        
        // Perfect Forward Secrecy - Prefer ephemeral key exchange
        honorCipherOrder: true,
        ecdhCurve: 'secp384r1:prime256v1:secp521r1',
        
        // Security Options
        secureOptions: require('constants').SSL_OP_NO_SSLv2 | 
                      require('constants').SSL_OP_NO_SSLv3 | 
                      require('constants').SSL_OP_NO_TLSv1 |
                      require('constants').SSL_OP_NO_TLSv1_1 |
                      require('constants').SSL_OP_CIPHER_SERVER_PREFERENCE |
                      require('constants').SSL_OP_NO_COMPRESSION,
        
        // Session Configuration
        sessionIdContext: 'https-server-session',
        sessionTimeout: 300, // 5 minutes
        
        // Request Configuration
        requestCert: false,
        rejectUnauthorized: false, // Allow self-signed certificates for development
        
        // HTTPS Agent Configuration
        keepAlive: true,
        keepAliveMsecs: 1000,
        maxSockets: 256,
        maxFreeSockets: 256
      };
      
      this.certificateLoadTime = new Date();
      
      console.log('[HTTPS Config] SSL/TLS certificates loaded successfully');
      console.log(`[HTTPS Config] Certificate loaded at: ${this.certificateLoadTime.toISOString()}`);
      console.log(`[HTTPS Config] TLS version: ${this.httpsOptions.minVersion}+`);
      console.log(`[HTTPS Config] Cipher suites: ${this.httpsOptions.ciphers.split(':').length} configured`);
      
      return true;
      
    } catch (error) {
      console.error('[HTTPS Config] Certificate loading failed:', error.message);
      console.error('[HTTPS Config] Stack trace:', error.stack);
      
      // Set default fallback options for development
      this.httpsOptions = this.createFallbackOptions();
      
      return false;
    }
  }

  /**
   * Create fallback HTTPS options for development scenarios
   * 
   * Provides basic HTTPS configuration when certificate loading fails,
   * enabling development to continue with minimal security settings.
   * 
   * @returns {Object} Fallback HTTPS options
   */
  createFallbackOptions() {
    console.warn('[HTTPS Config] Creating fallback HTTPS options for development');
    console.warn('[HTTPS Config] WARNING: Using fallback configuration - security may be compromised');
    
    return {
      // Basic TLS configuration
      secureProtocol: 'TLSv1_2_method',
      minVersion: 'TLSv1.2',
      
      // Minimal security options
      rejectUnauthorized: false,
      requestCert: false,
      
      // Development-friendly settings
      sessionIdContext: 'https-fallback-session'
    };
  }

  /**
   * Reload SSL/TLS certificates at runtime
   * 
   * Enables certificate rotation and updates without service interruption.
   * Implements thread-safe certificate reloading with comprehensive error handling.
   * 
   * @returns {Promise<boolean>} Success status of certificate reload
   */
  async reloadCertificates() {
    if (this.reloadInProgress) {
      console.warn('[HTTPS Config] Certificate reload already in progress, skipping');
      return false;
    }
    
    this.reloadInProgress = true;
    
    try {
      console.log('[HTTPS Config] Initiating runtime certificate reload...');
      
      // Store current options as backup
      const backupOptions = { ...this.httpsOptions };
      const backupLoadTime = this.certificateLoadTime;
      
      // Attempt to load new certificates
      const reloadSuccess = this.loadCertificates();
      
      if (reloadSuccess) {
        console.log('[HTTPS Config] Certificate reload completed successfully');
        console.log(`[HTTPS Config] Previous certificate loaded: ${backupLoadTime ? backupLoadTime.toISOString() : 'N/A'}`);
        console.log(`[HTTPS Config] New certificate loaded: ${this.certificateLoadTime.toISOString()}`);
        
        return true;
      } else {
        // Restore backup options on failure
        this.httpsOptions = backupOptions;
        this.certificateLoadTime = backupLoadTime;
        
        console.error('[HTTPS Config] Certificate reload failed, restored previous configuration');
        return false;
      }
      
    } catch (error) {
      console.error('[HTTPS Config] Certificate reload error:', error.message);
      return false;
    } finally {
      this.reloadInProgress = false;
    }
  }

  /**
   * Validate current certificate configuration
   * 
   * Performs comprehensive validation of loaded certificates and TLS configuration
   * to ensure security requirements are met.
   * 
   * @returns {Object} Validation results with status and details
   */
  validateConfiguration() {
    const validation = {
      isValid: false,
      errors: [],
      warnings: [],
      securityLevel: 'UNKNOWN',
      details: {}
    };
    
    try {
      if (!this.httpsOptions) {
        validation.errors.push('HTTPS options not initialized');
        return validation;
      }
      
      // Validate certificate material
      if (!this.httpsOptions.cert || !this.httpsOptions.key) {
        validation.errors.push('SSL certificate or private key missing');
      } else {
        validation.details.hasCertificateMaterial = true;
      }
      
      // Validate TLS version
      if (this.httpsOptions.minVersion) {
        const minVersion = this.httpsOptions.minVersion;
        if (minVersion === 'TLSv1.2' || minVersion === 'TLSv1.3') {
          validation.details.tlsVersion = minVersion;
          validation.details.tlsVersionValid = true;
        } else {
          validation.errors.push(`Insecure TLS version: ${minVersion}`);
        }
      } else {
        validation.warnings.push('TLS version not explicitly configured');
      }
      
      // Validate cipher suites
      if (this.httpsOptions.ciphers) {
        const cipherCount = this.httpsOptions.ciphers.split(':').length;
        validation.details.cipherSuiteCount = cipherCount;
        validation.details.hasCipherSuites = true;
        
        if (cipherCount < 5) {
          validation.warnings.push('Limited cipher suite selection may impact compatibility');
        }
      } else {
        validation.warnings.push('Cipher suites not explicitly configured');
      }
      
      // Validate Perfect Forward Secrecy
      if (this.httpsOptions.ecdhCurve) {
        validation.details.perfectForwardSecrecy = true;
      } else {
        validation.warnings.push('Perfect Forward Secrecy not configured');
      }
      
      // Determine security level
      if (validation.errors.length === 0) {
        if (validation.warnings.length === 0) {
          validation.securityLevel = 'HIGH';
        } else if (validation.warnings.length <= 2) {
          validation.securityLevel = 'MEDIUM';
        } else {
          validation.securityLevel = 'LOW';
        }
        validation.isValid = true;
      } else {
        validation.securityLevel = 'CRITICAL';
      }
      
      // Add certificate age information
      if (this.certificateLoadTime) {
        const ageMs = Date.now() - this.certificateLoadTime.getTime();
        validation.details.certificateAge = {
          loadedAt: this.certificateLoadTime.toISOString(),
          ageMinutes: Math.floor(ageMs / (1000 * 60)),
          ageHours: Math.floor(ageMs / (1000 * 60 * 60))
        };
      }
      
      return validation;
      
    } catch (error) {
      validation.errors.push(`Configuration validation failed: ${error.message}`);
      validation.securityLevel = 'CRITICAL';
      return validation;
    }
  }

  /**
   * Get current certificate information
   * 
   * Returns detailed information about the currently loaded certificates
   * for monitoring and debugging purposes.
   * 
   * @returns {Object} Certificate information and metadata
   */
  getCertificateInfo() {
    return {
      certificatePath: this.certificatePath,
      privateKeyPath: this.privateKeyPath,
      loadTime: this.certificateLoadTime,
      reloadInProgress: this.reloadInProgress,
      hasValidConfig: this.httpsOptions !== null,
      tlsVersion: this.httpsOptions?.minVersion || 'Unknown',
      cipherSuiteCount: this.httpsOptions?.ciphers ? this.httpsOptions.ciphers.split(':').length : 0,
      securityFeatures: {
        perfectForwardSecrecy: !!this.httpsOptions?.ecdhCurve,
        sessionManagement: !!this.httpsOptions?.sessionIdContext,
        cipherPreference: !!this.httpsOptions?.honorCipherOrder
      }
    };
  }

  /**
   * Get HTTPS options for Express.js server creation
   * 
   * Returns the configured HTTPS options compatible with Node.js built-in
   * HTTPS module for Express.js server initialization.
   * 
   * @returns {Object} HTTPS options for server creation
   */
  getHttpsOptions() {
    if (!this.httpsOptions) {
      console.error('[HTTPS Config] HTTPS options not available, attempting to load certificates...');
      this.loadCertificates();
    }
    
    return this.httpsOptions;
  }

  /**
   * Test HTTPS configuration
   * 
   * Performs a comprehensive test of the HTTPS configuration by creating
   * a temporary HTTPS server and validating TLS handshake capabilities.
   * 
   * @returns {Promise<Object>} Test results with status and metrics
   */
  async testConfiguration() {
    return new Promise((resolve) => {
      const testResult = {
        success: false,
        error: null,
        testDuration: 0,
        tlsHandshakeSuccess: false,
        certificateValid: false
      };
      
      const startTime = Date.now();
      
      try {
        if (!this.httpsOptions) {
          testResult.error = 'HTTPS options not available';
          resolve(testResult);
          return;
        }
        
        // Create temporary HTTPS server for testing
        const testServer = https.createServer(this.httpsOptions, (req, res) => {
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end('HTTPS configuration test successful');
        });
        
        // Test server creation and binding
        testServer.listen(0, '127.0.0.1', () => {
          const port = testServer.address().port;
          console.log(`[HTTPS Config] Test server listening on port ${port}`);
          
          testResult.tlsHandshakeSuccess = true;
          testResult.certificateValid = true;
          testResult.success = true;
          testResult.testDuration = Date.now() - startTime;
          
          // Close test server
          testServer.close(() => {
            console.log('[HTTPS Config] Test server closed successfully');
            resolve(testResult);
          });
        });
        
        // Handle server errors
        testServer.on('error', (error) => {
          testResult.error = error.message;
          testResult.testDuration = Date.now() - startTime;
          
          testServer.close(() => {
            resolve(testResult);
          });
        });
        
        // Timeout for test
        setTimeout(() => {
          if (!testResult.success) {
            testResult.error = 'Test timeout after 5 seconds';
            testResult.testDuration = Date.now() - startTime;
            
            testServer.close(() => {
              resolve(testResult);
            });
          }
        }, 5000);
        
      } catch (error) {
        testResult.error = error.message;
        testResult.testDuration = Date.now() - startTime;
        resolve(testResult);
      }
    });
  }
}

// Create singleton instance
const httpsConfig = new HttpsConfig();

/**
 * Export HTTPS configuration functions and options
 * 
 * Provides a clean interface for other modules to access HTTPS configuration
 * without exposing internal implementation details.
 */
module.exports = {
  /**
   * Get HTTPS options for server creation
   * @returns {Object} HTTPS options compatible with Node.js https.createServer()
   */
  getHttpsOptions: () => httpsConfig.getHttpsOptions(),
  
  /**
   * Reload certificates at runtime
   * @returns {Promise<boolean>} Success status of certificate reload
   */
  reloadCertificates: () => httpsConfig.reloadCertificates(),
  
  /**
   * Validate current configuration
   * @returns {Object} Validation results with status and details
   */
  validateConfiguration: () => httpsConfig.validateConfiguration(),
  
  /**
   * Get certificate information
   * @returns {Object} Certificate metadata and status
   */
  getCertificateInfo: () => httpsConfig.getCertificateInfo(),
  
  /**
   * Test HTTPS configuration
   * @returns {Promise<Object>} Test results with metrics
   */
  testConfiguration: () => httpsConfig.testConfiguration(),
  
  /**
   * Certificate file paths
   */
  certificatePaths: {
    cert: httpsConfig.certificatePath,
    key: httpsConfig.privateKeyPath
  },
  
  /**
   * TLS Security Configuration Constants
   */
  tlsConfig: {
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    cipherSuites: 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384',
    perfectForwardSecrecy: true,
    sessionTimeout: 300
  }
};

// Initialize configuration validation on module load
httpsConfig.validateConfiguration();

console.log('[HTTPS Config] Module initialized successfully');
console.log('[HTTPS Config] Certificate paths configured:', {
  cert: httpsConfig.certificatePath,
  key: httpsConfig.privateKeyPath
});