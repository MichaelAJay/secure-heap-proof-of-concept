const crypto = require('crypto');
const { SecureHeapSecretManager } = require('./secure-heap-secret-manager');

/** @type {SecureHeapSecretManager} */
const secureHeapSecretManager = new SecureHeapSecretManager();

let decryptedPasswordBuffer = null;

// ✅ SECURITY: Register graceful shutdown for the worker process
process.once('SIGTERM', () => {
    console.log('Secure worker: Received SIGTERM, shutting down gracefully...');
    if (secureHeapSecretManager) {
        secureHeapSecretManager.shutdown();
    }
    process.exit(0);
});

process.once('SIGINT', () => {
    console.log('Secure worker: Received SIGINT, shutting down gracefully...');
    if (secureHeapSecretManager) {
        secureHeapSecretManager.shutdown();
    }
    process.exit(0);
});

process.on('message', async (msg) => {
    const outboundMsg = { type: `${msg.type}:result`, id: msg.id };
    try {
        // ✅ SECURITY: Check if manager is shut down
        if (secureHeapSecretManager.isShutDown()) {
            throw new Error('SecureHeapSecretManager has been shut down');
        }
        
        switch (msg.type) {
            case 'generateSecureKeypair':
                console.log('Secure worker generateSecureKeypair');
                await secureHeapSecretManager.generateSecureKeypair();
                const isExpectedAllocationVerified = secureHeapSecretManager.verifyExpectedAllocation();
                outboundMsg.data = { isExpectedAllocationVerified };
                break;
            case 'checkSecureHeapEnabled':
                console.log('Secure worker checkSecureHeapEnabled');
                const secureHeapUsage = secureHeapSecretManager.getSecureHeapUsage();
                outboundMsg.data = { isSecureHeapUsed: secureHeapUsage.total > 0 };
                break;
            case 'readInPassword':
                console.log('Secure heap readInPassword');
                await secureHeapSecretManager.readInPassword();
                break;
            case 'verifyExpectedAllocation':
                console.log('Secure worker verifyExpectedAllocation');
                const allocationVerified = secureHeapSecretManager.verifyExpectedAllocation();
                outboundMsg.data = { isExpectedAllocationVerified: allocationVerified };
                break;
            case 'getDecryptedPassword':
                console.log('Secure heap getDecryptedPassword');

                console.log('Verifying secure heap allocation...');
                secureHeapSecretManager.verifyExpectedAllocation();

                // ✅ OPTIMIZATION: Minimize exposure window by immediate assignment and send
                decryptedPasswordBuffer = secureHeapSecretManager.getDecryptedPassword();
                
                // ✅ SECURITY: Store reference for post-IPC cleanup
                // The buffer will be sanitized in the callback after IPC send
                outboundMsg.data = decryptedPasswordBuffer;
                break;
            default:
                console.error('Unknown message type:', msg.type);
        }
    } catch (err) {
        outboundMsg.type = `${msg.type}:error`;
        outboundMsg.error = { message: err.message, stack: err.stack };
    }
    
    // Send message and clean up buffer in callback
    process.send(outboundMsg, (error) => {
        console.log('Callback');
        if (Buffer.isBuffer(decryptedPasswordBuffer)) {
            crypto.randomFillSync(decryptedPasswordBuffer);
            
            // ✅ SECURITY: Remove from tracking after sanitization
            if (secureHeapSecretManager && !secureHeapSecretManager.isShutDown()) {
                secureHeapSecretManager.removeFromTracking(decryptedPasswordBuffer);
            }
            
            decryptedPasswordBuffer = null;
        }
        
        if (error) {
            console.error('Failed to send message:', error);
        }
    });
})