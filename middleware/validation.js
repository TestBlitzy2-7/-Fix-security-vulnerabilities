/**
 * Input Validation and Sanitization Middleware
 * 
 * Implements comprehensive input validation and sanitization using express-validator
 * to protect against injection attacks and ensure data integrity. This middleware
 * forms a critical security layer in the request processing pipeline.
 * 
 * Security Features:
 * - XSS prevention through HTML entity encoding
 * - SQL injection protection via input sanitization
 * - Path traversal prevention with file path validation
 * - Data format enforcement with strict type checking
 * - Comprehensive error handling with structured responses
 * 
 * @requires express-validator - Validation and sanitization library
 * @version 1.0.0
 * @security-critical This module is essential for preventing injection attacks
 */

const { body, query, param, validationResult, matchedData } = require('express-validator');

/**
 * Security Configuration Constants
 * 
 * These constants define security boundaries and limits for input validation
 * to prevent various attack vectors while maintaining usability.
 */
const SECURITY_LIMITS = {
    // String length limits to prevent buffer overflow attacks
    MAX_STRING_LENGTH: 1000,
    MAX_TEXT_LENGTH: 5000,
    MAX_NAME_LENGTH: 100,
    MAX_EMAIL_LENGTH: 254, // RFC 5321 compliant
    
    // Numeric limits for resource protection
    MAX_INTEGER: 2147483647, // 32-bit signed integer limit
    MIN_INTEGER: -2147483648,
    MAX_FLOAT_PRECISION: 10,
    
    // Array and object limits to prevent DoS attacks
    MAX_ARRAY_LENGTH: 100,
    MAX_OBJECT_KEYS: 50,
    
    // URL and path security limits
    MAX_URL_LENGTH: 2048,
    MAX_PATH_LENGTH: 260, // Windows path limit for compatibility
    
    // Rate limiting for validation-intensive operations
    MAX_VALIDATION_ERRORS: 20 // Limit error responses to prevent information disclosure
};

/**
 * Common Validation Patterns
 * 
 * Pre-defined regular expressions for common validation scenarios
 * with security-first approach to prevent regex-based attacks.
 */
const VALIDATION_PATTERNS = {
    // Alphanumeric with safe special characters
    SAFE_STRING: /^[a-zA-Z0-9\s\-_.,:;!?()[\]{}'"]+$/,
    
    // Strict alphanumeric for identifiers
    IDENTIFIER: /^[a-zA-Z0-9_-]+$/,
    
    // Safe filename pattern (no path traversal)
    SAFE_FILENAME: /^[a-zA-Z0-9_.-]+$/,
    
    // Version number pattern
    VERSION: /^\d+\.\d+\.\d+$/,
    
    // Hex color code
    HEX_COLOR: /^#[0-9A-Fa-f]{6}$/,
    
    // UUID pattern
    UUID: /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
};

/**
 * Sanitization Functions
 * 
 * Custom sanitization functions that go beyond basic express-validator
 * sanitizers to provide enhanced security protection.
 */
const sanitizers = {
    /**
     * Comprehensive HTML sanitization
     * Removes all HTML tags and dangerous characters while preserving text content
     */
    sanitizeHTML: (value) => {
        if (typeof value !== 'string') return value;
        
        return value
            .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // Remove script tags
            .replace(/<[^>]*>/g, '') // Remove all HTML tags
            .replace(/javascript:/gi, '') // Remove javascript: protocol
            .replace(/on\w+\s*=/gi, '') // Remove event handlers
            .replace(/&lt;/g, '<').replace(/&gt;/g, '>') // Decode HTML entities
            .trim();
    },
    
    /**
     * Path traversal prevention
     * Removes dangerous path components that could lead to directory traversal
     */
    sanitizePath: (value) => {
        if (typeof value !== 'string') return value;
        
        return value
            .replace(/\.\./g, '') // Remove parent directory references
            .replace(/[<>:"|?*]/g, '') // Remove dangerous filename characters
            .replace(/^\/+|\/+$/g, '') // Remove leading/trailing slashes
            .trim();
    },
    
    /**
     * SQL injection prevention
     * Escapes common SQL injection patterns
     */
    sanitizeSQL: (value) => {
        if (typeof value !== 'string') return value;
        
        return value
            .replace(/'/g, "''") // Escape single quotes
            .replace(/;/g, '') // Remove semicolons
            .replace(/--/g, '') // Remove SQL comments
            .replace(/\/\*/g, '').replace(/\*\//g, '') // Remove block comments
            .replace(/\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b/gi, '') // Remove SQL keywords
            .trim();
    },
    
    /**
     * NoSQL injection prevention
     * Sanitizes input to prevent NoSQL injection attacks
     */
    sanitizeNoSQL: (value) => {
        if (typeof value === 'object' && value !== null) {
            // Remove dangerous MongoDB operators
            const dangerousKeys = ['$where', '$regex', '$gt', '$lt', '$ne', '$in', '$nin'];
            const sanitized = { ...value };
            dangerousKeys.forEach(key => delete sanitized[key]);
            return sanitized;
        }
        return value;
    }
};

/**
 * Validation Schema Builders
 * 
 * Factory functions for creating validation chains with consistent
 * security policies and error handling.
 */
const validationSchemas = {
    /**
     * Basic string validation with XSS protection
     */
    safeString: (fieldName, options = {}) => {
        const {
            maxLength = SECURITY_LIMITS.MAX_STRING_LENGTH,
            minLength = 0,
            required = true,
            pattern = VALIDATION_PATTERNS.SAFE_STRING
        } = options;
        
        let validator = body(fieldName)
            .custom(sanitizers.sanitizeHTML)
            .trim()
            .escape(); // HTML entity encoding
        
        if (required) {
            validator = validator.notEmpty()
                .withMessage(`${fieldName} is required`);
        }
        
        return validator
            .isLength({ min: minLength, max: maxLength })
            .withMessage(`${fieldName} must be between ${minLength} and ${maxLength} characters`)
            .matches(pattern)
            .withMessage(`${fieldName} contains invalid characters`);
    },
    
    /**
     * Email validation with comprehensive security checks
     */
    email: (fieldName = 'email') => {
        return body(fieldName)
            .trim()
            .normalizeEmail({
                gmail_remove_dots: false,
                gmail_remove_subaddress: false,
                outlookdotcom_remove_subaddress: false,
                yahoo_remove_subaddress: false,
                icloud_remove_subaddress: false
            })
            .isEmail()
            .withMessage('Invalid email format')
            .isLength({ max: SECURITY_LIMITS.MAX_EMAIL_LENGTH })
            .withMessage(`Email must not exceed ${SECURITY_LIMITS.MAX_EMAIL_LENGTH} characters`)
            .custom((value) => {
                // Additional email security checks
                if (value.includes('..')) {
                    throw new Error('Email contains consecutive dots');
                }
                if (value.match(/[<>]/)) {
                    throw new Error('Email contains invalid characters');
                }
                return true;
            });
    },
    
    /**
     * URL validation with protocol and content security
     */
    url: (fieldName = 'url') => {
        return body(fieldName)
            .trim()
            .isURL({
                protocols: ['http', 'https'],
                require_protocol: true,
                require_valid_protocol: true,
                allow_underscores: false,
                allow_trailing_dot: false,
                allow_protocol_relative_urls: false
            })
            .withMessage('Invalid URL format - must be http or https')
            .isLength({ max: SECURITY_LIMITS.MAX_URL_LENGTH })
            .withMessage(`URL must not exceed ${SECURITY_LIMITS.MAX_URL_LENGTH} characters`)
            .custom((value) => {
                // Prevent javascript: and data: protocol injection
                if (value.match(/^(javascript|data|vbscript):/i)) {
                    throw new Error('URL contains dangerous protocol');
                }
                return true;
            });
    },
    
    /**
     * Integer validation with range checking
     */
    integer: (fieldName, options = {}) => {
        const {
            min = SECURITY_LIMITS.MIN_INTEGER,
            max = SECURITY_LIMITS.MAX_INTEGER,
            required = true
        } = options;
        
        let validator = body(fieldName)
            .trim();
        
        if (required) {
            validator = validator.notEmpty()
                .withMessage(`${fieldName} is required`);
        }
        
        return validator
            .isInt({ min, max })
            .withMessage(`${fieldName} must be an integer between ${min} and ${max}`)
            .toInt(); // Convert to integer
    },
    
    /**
     * Array validation with length and content security
     */
    array: (fieldName, options = {}) => {
        const {
            maxLength = SECURITY_LIMITS.MAX_ARRAY_LENGTH,
            minLength = 0,
            required = true,
            itemValidator = null
        } = options;
        
        let validator = body(fieldName);
        
        if (required) {
            validator = validator.notEmpty()
                .withMessage(`${fieldName} is required`);
        }
        
        validator = validator
            .isArray({ min: minLength, max: maxLength })
            .withMessage(`${fieldName} must be an array with ${minLength} to ${maxLength} items`);
        
        // Apply item-level validation if provided
        if (itemValidator) {
            validator = validator.custom((array) => {
                if (!Array.isArray(array)) return true; // Let isArray handle this
                
                array.forEach((item, index) => {
                    try {
                        itemValidator(item);
                    } catch (error) {
                        throw new Error(`Item at index ${index}: ${error.message}`);
                    }
                });
                return true;
            });
        }
        
        return validator;
    },
    
    /**
     * File upload validation with security checks
     */
    filename: (fieldName = 'filename') => {
        return body(fieldName)
            .trim()
            .custom(sanitizers.sanitizePath)
            .matches(VALIDATION_PATTERNS.SAFE_FILENAME)
            .withMessage('Filename contains invalid characters')
            .isLength({ min: 1, max: 255 })
            .withMessage('Filename must be between 1 and 255 characters')
            .custom((value) => {
                // Prevent dangerous file extensions
                const dangerousExtensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.com', '.js', '.vbs', '.jar'];
                const extension = value.toLowerCase().substring(value.lastIndexOf('.'));
                
                if (dangerousExtensions.includes(extension)) {
                    throw new Error('File type not allowed');
                }
                return true;
            });
    }
};

/**
 * Validation Error Handler Middleware
 * 
 * Processes validation errors and returns structured, security-conscious
 * error responses that provide useful information without exposing
 * sensitive system details.
 */
const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    
    if (!errors.isEmpty()) {
        // Limit the number of errors returned to prevent information disclosure
        const errorArray = errors.array().slice(0, SECURITY_LIMITS.MAX_VALIDATION_ERRORS);
        
        // Structure errors for consistent API responses
        const formattedErrors = errorArray.map(error => ({
            field: error.path || error.param,
            message: error.msg,
            value: typeof error.value === 'string' && error.value.length > 50
                ? error.value.substring(0, 50) + '...' // Truncate long values
                : error.value,
            location: error.location
        }));
        
        // Log validation failures for security monitoring
        console.log(`Validation failed for ${req.method} ${req.path}:`, {
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            errors: formattedErrors.map(e => ({ field: e.field, message: e.message }))
        });
        
        return res.status(400).json({
            success: false,
            error: 'Validation failed',
            message: 'The request contains invalid or malformed data',
            errors: formattedErrors,
            timestamp: new Date().toISOString(),
            requestId: req.id || 'unknown'
        });
    }
    
    next();
};

/**
 * Sanitized Data Extractor
 * 
 * Extracts only validated and sanitized data from the request,
 * providing an additional security layer by ensuring only
 * validated data is processed by route handlers.
 */
const extractValidatedData = (req, res, next) => {
    // Extract only validated data to prevent parameter pollution
    req.validatedData = matchedData(req);
    next();
};

/**
 * Request Size Limiter
 * 
 * Middleware to prevent large request attacks by limiting
 * the size of request bodies and parameter counts.
 */
const limitRequestSize = (req, res, next) => {
    // Check parameter count to prevent parameter pollution
    const paramCount = Object.keys(req.body || {}).length + 
                      Object.keys(req.query || {}).length + 
                      Object.keys(req.params || {}).length;
    
    if (paramCount > SECURITY_LIMITS.MAX_OBJECT_KEYS) {
        return res.status(413).json({
            success: false,
            error: 'Request too large',
            message: 'Request contains too many parameters',
            timestamp: new Date().toISOString()
        });
    }
    
    next();
};

/**
 * Common Validation Chains
 * 
 * Pre-built validation chains for common use cases that can be
 * easily reused across different routes and endpoints.
 */
const commonValidations = {
    // Basic health check validation (for endpoints that accept no input)
    noInput: [
        // Ensure no body parameters
        body().custom((value, { req }) => {
            if (Object.keys(req.body || {}).length > 0) {
                throw new Error('This endpoint does not accept request body');
            }
            return true;
        }),
        
        // Ensure no query parameters
        query().custom((value, { req }) => {
            if (Object.keys(req.query || {}).length > 0) {
                throw new Error('This endpoint does not accept query parameters');
            }
            return true;
        })
    ],
    
    // Basic API key validation (for future authentication)
    apiKey: [
        body('apiKey')
            .optional()
            .isAlphanumeric()
            .isLength({ min: 32, max: 64 })
            .withMessage('API key must be alphanumeric and 32-64 characters long')
    ],
    
    // Pagination validation
    pagination: [
        query('page')
            .optional()
            .isInt({ min: 1, max: 10000 })
            .withMessage('Page must be a positive integer up to 10000')
            .toInt(),
        
        query('limit')
            .optional()
            .isInt({ min: 1, max: 100 })
            .withMessage('Limit must be between 1 and 100')
            .toInt()
    ]
};

/**
 * Security Headers for Validation Responses
 * 
 * Middleware to add security headers to validation error responses
 * to prevent information disclosure and enhance security posture.
 */
const addSecurityHeaders = (req, res, next) => {
    // Add security headers to all validation responses
    res.set({
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
    });
    
    next();
};

/**
 * Module Exports
 * 
 * Provides a comprehensive validation API for use across the application
 * with consistent security policies and error handling.
 */
module.exports = {
    // Core validation functions
    validationSchemas,
    handleValidationErrors,
    extractValidatedData,
    limitRequestSize,
    addSecurityHeaders,
    
    // Common validation chains
    commonValidations,
    
    // Utility functions
    sanitizers,
    
    // Constants for external use
    SECURITY_LIMITS,
    VALIDATION_PATTERNS,
    
    // Express-validator re-exports for convenience
    body,
    query,
    param,
    validationResult,
    matchedData,
    
    // Complete validation middleware stack
    validationMiddleware: [
        addSecurityHeaders,
        limitRequestSize,
        extractValidatedData
    ],
    
    // Quick validation for common scenarios
    validateAndHandle: (validationChain) => [
        ...validationChain,
        handleValidationErrors
    ]
};