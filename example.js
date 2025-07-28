const crypto = require('crypto');
const SecureHeapProcessManager = require('./secure-heap-process-manager');

// Configurable wait time between getDecryptedPassword calls (in milliseconds)
const LOOP_WAIT_MS = 15000;

let manager = null;

// ✅ SECURITY: Graceful shutdown handler
const gracefulShutdown = (signal) => {
    console.log(`\nExample: Received ${signal}, shutting down gracefully...`);
    if (manager) {
        manager.stop();
    }
    process.exit(0);
};

// Register shutdown handlers
process.once('SIGINT', gracefulShutdown);
process.once('SIGTERM', gracefulShutdown);

(async() => {
    manager = new SecureHeapProcessManager();

    console.log('=== Testing Secure Heap Status ===');
    const secureHeapUsed = await manager.handleRequest('checkSecureHeapEnabled');
    console.log('Secure heap status:', secureHeapUsed);

    console.log('\n=== Testing Secure Keypair Generation ===');
    const keypairResult = await manager.handleRequest('generateSecureKeypair');
    console.log('Keypair generation result:', keypairResult);

    console.log('\n=== Testing Password Input ===');
    await manager.handleRequest('readInPassword');
    console.log('Password read and encrypted');

    console.log('\n=== Starting Infinite Loop with Guaranteed Cleanup ===');
    console.log(`Loop interval: ${LOOP_WAIT_MS}ms`);
    
    let loopCount = 0;
    while (true) {
        try {
            loopCount++;
            console.log(`\n--- Loop iteration ${loopCount} ---`);
            
            // Verify secure heap allocation before decrypting
            console.log('Verifying secure heap allocation...');
            const allocationResult = await manager.handleRequest('verifyExpectedAllocation');
            console.log('Allocation verification result:', allocationResult);
            
            // ✅ NEW: Use withDecryptedPassword for guaranteed cleanup
            await manager.withDecryptedPassword((passwordBuffer) => {
                console.log('✅ Password accessed with guaranteed cleanup');
                
                // ✅ CRITICAL: Use the password for your operations here
                // For example, unlocking a wallet:
                // const wallet = new Wallet(walletData);
                // wallet.unlock(passwordBuffer);
                
                // ✅ SECURITY DEMONSTRATION: toString() is now blocked!
                try {
                    const passwordString = passwordBuffer.toString();
                    console.log('This should never be reached!');
                } catch (error) {
                    console.log('✅ SECURITY: toString() blocked -', error.message);
                }
                
                // ✅ SECURITY DEMONSTRATION: Console logging of buffer is sanitized
                console.log('Buffer in console:', passwordBuffer);
                
                // ✅ SECURITY DEMONSTRATION: JSON conversion is also blocked
                try {
                    JSON.stringify(passwordBuffer);
                    console.log('This should never be reached!');
                } catch (error) {
                    console.log('✅ SECURITY: JSON conversion blocked -', error.message);
                }
                
                console.log('✅ Password operations completed');
                // NO MANUAL CLEANUP NEEDED - it's guaranteed by the framework!
            });
            
            console.log('✅ Callback completed - password automatically sanitized');
            
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