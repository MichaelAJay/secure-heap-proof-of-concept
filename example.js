const crypto = require('crypto');
const SecureHeapProcessManager = require('./secure-heap-process-manager');

// Configurable wait time between getDecryptedPassword calls (in milliseconds)
const LOOP_WAIT_MS = 15000;

(async() => {
    const manager = new SecureHeapProcessManager();

    console.log('=== Testing Secure Heap Status ===');
    const secureHeapUsed = await manager.handleRequest('checkSecureHeapEnabled');
    console.log('Secure heap status:', secureHeapUsed);

    console.log('\n=== Testing Secure Keypair Generation ===');
    const keypairResult = await manager.handleRequest('generateSecureKeypair');
    console.log('Keypair generation result:', keypairResult);

    console.log('\n=== Testing Password Input ===');
    await manager.handleRequest('readInPassword');
    console.log('Password read and encrypted');

    console.log('\n=== Starting Infinite Loop for getDecryptedPassword ===');
    console.log(`Loop interval: ${LOOP_WAIT_MS}ms`);
    
    let loopCount = 0;
    while (true) {
        try {
            loopCount++;
            console.log(`\n--- Loop iteration ${loopCount} ---`);
            
            // Get the decrypted password
            const decryptedPassword = await manager.handleRequest('getDecryptedPassword');
            
            // ✅ OPTIMIZATION: Use try/finally to guarantee immediate sanitization
            try {
                console.log('Decrypted password is buffer:', Buffer.isBuffer(decryptedPassword));
                // ❌ REMOVED: console.log('Decrypted password content:', decryptedPassword.toString());
                // ✅ SECURITY: Never convert buffer to string - keeps password mutable for sanitization
                console.log('Decrypted password length:', decryptedPassword ? decryptedPassword.length : 0);
                
                // ✅ CRITICAL: Any actual password usage would go here
                // Exposure window is now minimized to this specific block
                
            } finally {
                // ✅ GUARANTEED: Buffer sanitized immediately after use, even if exceptions occur
                if (Buffer.isBuffer(decryptedPassword)) {
                    crypto.randomFillSync(decryptedPassword);
                    console.log('Application: Password buffer sanitized in finally block');
                }
                
                // ✅ OPTIMIZATION: Force immediate garbage collection to clear any copies
                if (global.gc) {
                    global.gc();
                }
            }
            
            // Wait before next iteration
            await new Promise(resolve => setTimeout(resolve, LOOP_WAIT_MS));
            
        } catch (error) {
            console.error('Error in loop iteration:', error);
            // Continue the loop even if there's an error
            await new Promise(resolve => setTimeout(resolve, LOOP_WAIT_MS));
        }
    }
    
    // This code will never be reached due to infinite loop
    // manager.stop();
})()