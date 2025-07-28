const { fork } = require('node:child_process');
const crypto = require('crypto');

const n = 32768;
const validRequests = ['generateSecureKeypair', 'checkSecureHeapEnabled', 'readInPassword', 'getDecryptedPassword', 'verifyExpectedAllocation'];
const validChildMessageTypes = validRequests.map(request => `${request}:result`);

class SecureHeapProcessManager {
    constructor() {
        this.msgId = 0;
        
        this.child = fork('./secure-worker.js', [], {
            execArgv: [`--secure-heap=${n} --expose-gc`]
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
}

module.exports = SecureHeapProcessManager;