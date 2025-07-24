const { fork } = require('node:child_process');

const n = 32768; // should be power of 2, will check w/o power of 2 soon.
const validRequests = ['checkSecureHeapUsage', 'decryptPassword'];
const validChildMessageTypes = validRequests.map(request => `${request}:result`);

class SecureHeapProcessManager {
    constructor() {
        this.msgId = 0;
        
        this.child = fork('./secure-worker.js', [], {
            execArgv: [`--secure-heap=${n}`]
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
    }

    /**
     * 
     * @param {string} type 
     */
    handleRequest(type) {
        if (!validRequests.includes(type)) {
            return Promise.reject(new Error(`Invalid request type: ${type}`));
        }

        return new Promise((resolve, reject) => {
            const id = ++this.msgId;
            this.pending.set(id, { resolve, reject });
            this.child.send({ type, id });
        })
    }

    stop() {
        console.log('SecureHeapProcessManager stopping');
        this.child.kill();
        console.log('SecureHeapProcessManager child killed');
    }
}

module.exports = SecureHeapProcessManager;