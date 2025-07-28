const { fork } = require('node:child_process');
const crypto = require('crypto');

const n = 32768;
const validRequests = ['generateSecureKeypair', 'checkSecureHeapEnabled', 'readInPassword', 'getDecryptedPassword', 'verifyExpectedAllocation'];
const validChildMessageTypes = validRequests.map(request => `${request}:result`);

class SecureHeapProcessManager {
    constructor() {
        this.msgId = 0;
        
        this.child = fork('./secure-worker.js', [], {
            execArgv: [`--secure-heap=${n}`, '--expose-gc']
        });
        this.pending = new Map();

        this.child.on('message', (msg) => {
            const pending = this.pending.get(msg.id);
            if (!pending) {
                console.error(`Pending msg not found: ${msg.id}`);
                return;
            }

            if (msg.type.endsWith(':result') && validChildMessageTypes.includes(msg.type)) {
                this.pending.delete(msg.id);
                
                // Handle Buffer deserialization - IPC automatically serializes Buffers
                let data = msg.data;
                if (data?.type === 'Buffer' && Array.isArray(data.data)) {
                    data = Buffer.from(data.data);
                }
                pending.resolve(data);
            } else if (msg.type.endsWith(':error')) {
                this.pending.delete(msg.id);
                const err = new Error(msg.error?.message || 'Unknown error from child');
                err.stack = msg.error?.stack;
                pending.reject(err);
            } else {
                console.error('Unexpected message from child', msg.type);
            }
        });

        // Register shutdown handlers for the main process
        this.#registerShutdownHandlers();
        
        // ✅ SECURITY: Initialize console sanitization
        this.#initializeConsoleSanitization();
    }

    /**
     * Initialize console output sanitization to prevent password exposure
     * @private
     */
    #initializeConsoleSanitization() {
        const originalConsoleLog = console.log;
        const originalConsoleError = console.error;
        const originalConsoleWarn = console.warn;
        const originalConsoleInfo = console.info;
        
        // Pattern to detect potential password-like strings
        const suspiciousPatterns = [
            /password/i,
            /passwd/i,
            /secret/i,
            /key/i,
            /token/i
        ];
        
        const sanitizeOutput = (args) => {
            return args.map(arg => {
                if (typeof arg === 'string') {
                    // Check if string contains suspicious patterns and is long enough to be a password
                    const containsSuspiciousPattern = suspiciousPatterns.some(pattern => pattern.test(arg));
                    if (containsSuspiciousPattern && arg.length > 8) {
                        return '[REDACTED: Potentially sensitive data]';
                    }
                    
                    // Redact very long strings that might be passwords/keys
                    if (arg.length > 32 && /^[A-Za-z0-9+/=]+$/.test(arg)) {
                        return `[REDACTED: ${arg.length} character string]`;
                    }
                }
                
                // Handle Buffer objects
                if (Buffer.isBuffer(arg)) {
                    return `[Buffer: ${arg.length} bytes - CONTENT REDACTED]`;
                }
                
                return arg;
            });
        };
        
        console.log = (...args) => originalConsoleLog(...sanitizeOutput(args));
        console.error = (...args) => originalConsoleError(...sanitizeOutput(args));
        console.warn = (...args) => originalConsoleWarn(...sanitizeOutput(args));
        console.info = (...args) => originalConsoleInfo(...sanitizeOutput(args));
        
        // Store originals for potential restoration
        this._originalConsole = {
            log: originalConsoleLog,
            error: originalConsoleError,
            warn: originalConsoleWarn,
            info: originalConsoleInfo
        };
    }

    /**
     * Disable console sanitization (for debugging purposes only)
     * ⚠️ WARNING: Only use this in development environments
     */
    disableConsoleSanitization() {
        if (this._originalConsole) {
            console.log = this._originalConsole.log;
            console.error = this._originalConsole.error;
            console.warn = this._originalConsole.warn;
            console.info = this._originalConsole.info;
        }
    }

    /**
     * 
     * @param {string} type 
     * @param {Object} params - Additional parameters for the request
     */
    handleRequest(type, params = {}) {
        if (!validRequests.includes(type)) {
            return Promise.reject(new Error(`Invalid request type: ${type}`));
        }

        return new Promise((resolve, reject) => {
            const id = ++this.msgId;
            this.pending.set(id, { resolve, reject });
            this.child.send({ type, id, ...params });
        })
    }

    /**
     * Execute a callback with guaranteed access to the decrypted password
     * The password buffer is automatically sanitized after the callback completes
     * 
     * @param {Function} callback - Function that receives the password buffer
     * @returns {Promise<any>} Result of the callback
     */
    async withDecryptedPassword(callback) {
        if (typeof callback !== 'function') {
            throw new Error('Callback must be a function');
        }

        // Get the decrypted password buffer
        const passwordBuffer = await this.handleRequest('getDecryptedPassword');
        
        // ✅ SECURITY: Override toString() to prevent accidental string creation
        const originalToString = passwordBuffer.toString;
        passwordBuffer.toString = function(...args) {
            throw new Error('SECURITY ERROR: Converting password buffer to string is forbidden. This prevents accidental creation of immutable string copies.');
        };
        
        // ✅ SECURITY: Override other methods that could create strings
        const originalToJSON = passwordBuffer.toJSON;
        passwordBuffer.toJSON = function() {
            throw new Error('SECURITY ERROR: Converting password buffer to JSON is forbidden.');
        };
        
        // ✅ SECURITY: Override inspect to prevent console exposure
        const originalInspect = passwordBuffer[Symbol.for('nodejs.util.inspect.custom')];
        passwordBuffer[Symbol.for('nodejs.util.inspect.custom')] = function() {
            return '[SecureBuffer: *** REDACTED ***]';
        };
        
        try {
            // Execute the callback with the password
            const result = await callback(passwordBuffer);
            return result;
        } finally {
            // ✅ GUARANTEED CLEANUP: Buffer is always sanitized
            if (Buffer.isBuffer(passwordBuffer)) {
                // Restore original methods before sanitization (in case needed for cleanup)
                passwordBuffer.toString = originalToString;
                passwordBuffer.toJSON = originalToJSON;
                passwordBuffer[Symbol.for('nodejs.util.inspect.custom')] = originalInspect;
                
                crypto.randomFillSync(passwordBuffer);
                console.log('SecureHeapProcessManager: Password buffer sanitized in main process');
            }
            
            // Force garbage collection if available
            if (global.gc) {
                global.gc();
            }
        }
    }

    /**
     * Registers shutdown handlers for the main process
     */
    #registerShutdownHandlers() {
        const shutdownHandler = (signal) => {
            console.log(`SecureHeapProcessManager: Received ${signal}, shutting down...`);
            this.stop();
            process.exit(0);
        };

        process.once('SIGINT', shutdownHandler);
        process.once('SIGTERM', shutdownHandler);
        process.once('SIGHUP', shutdownHandler);
        
        process.once('beforeExit', () => {
            console.log('SecureHeapProcessManager: Process exiting, stopping child...');
            this.stop();
        });
    }

    stop() {
        console.log('SecureHeapProcessManager stopping');
        
        // ✅ SECURITY: Send graceful shutdown signal to child process
        if (this.child && !this.child.killed) {
            console.log('SecureHeapProcessManager: Sending SIGTERM to child process...');
            this.child.kill('SIGTERM');
            
            // Give child process time to shutdown gracefully
            setTimeout(() => {
                if (this.child && !this.child.killed) {
                    console.log('SecureHeapProcessManager: Child process did not exit gracefully, forcing kill...');
                    this.child.kill('SIGKILL');
                }
            }, 5000); // 5 second timeout for graceful shutdown
        }
        
        // Clear any pending requests
        for (const [id, pending] of this.pending) {
            pending.reject(new Error('SecureHeapProcessManager is shutting down'));
        }
        this.pending.clear();
        
        console.log('SecureHeapProcessManager child killed');
    }
}

module.exports = SecureHeapProcessManager;