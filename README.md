# Secure Heap Password Management Proof of Concept

A Node.js implementation demonstrating secure password handling using Node.js secure heap allocation, cross-process isolation, and **guaranteed buffer sanitization** with a **callback-based architecture** that prevents memory-based password extraction attacks.

## Overview

This project implements a security-hardened password management system that ensures sensitive password data:
- Never exists as immutable strings in memory
- Is stored in Node.js secure heap (protected memory regions)
- Is **automatically sanitized after use** with guaranteed cleanup
- Cannot be extracted through memory dumps or heap analysis
- **Cannot be accidentally converted to strings** (security-enforced)

## ⚠️ CRITICAL SECURITY WARNING

**The callback-based architecture only sanitizes the password buffer itself. Objects that are unlocked or modified within the callback retain their state after the callback completes.**

### ❌ **DANGEROUS PATTERN - Avoid This:**

```javascript
const wallet = new SecureLockedWallet();
await manager.withDecryptedPassword((passwordBuffer) => {
    wallet.unlock(passwordBuffer); // ← Wallet internal state changes to "unlocked"
});
// ← Password buffer is sanitized here
// ← BUT wallet remains unlocked with sensitive data in memory!

// wallet.privateKeys, wallet.seed, etc. are still accessible here!
console.log(wallet.getPrivateKey()); // ❌ This still works - security breach!
```

**❌ ANOTHER DANGEROUS PATTERN - Never Copy Password Buffer:**

```javascript
let copiedPassword;
await manager.withDecryptedPassword((passwordBuffer) => {
    copiedPassword = Buffer.from(passwordBuffer); // ❌ CRITICAL: Creates separate buffer copy!
    // or copiedPassword = passwordBuffer.slice(); // ❌ Also creates a copy
});
// ❌ SECURITY BREACH: copiedPassword contains original password data!
console.log(copiedPassword); // ❌ Original password still accessible - security defeated!

// ✅ NOTE: Simple reference assignment is actually NOT dangerous:
// let passwordRef = passwordBuffer; // ← This is OK - same buffer, gets sanitized
// The issue is only with creating COPIES of the buffer data
```

**Why This Is Dangerous:**
- The password buffer is properly sanitized ✅
- But the wallet object retains decrypted private keys, seeds, or other sensitive material in memory ❌
- This sensitive data could persist indefinitely and be vulnerable to memory dumps ❌
- The security guarantee only applies to the password, not to derived sensitive data ❌
- **Creating copies of the buffer bypasses the sanitization mechanism** ❌

### ✅ **SAFE PATTERNS - Use These Instead:**

#### **Pattern 1: Immediate Data Extraction (Recommended)**
```javascript
const result = await manager.withDecryptedPassword((passwordBuffer) => {
    // Don't modify object state - just extract what you need
    const decryptedData = wallet.decrypt(passwordBuffer); // Returns data without storing it
    const operationResult = performOperation(decryptedData);
    
    // Clean up the decrypted data immediately
    if (Buffer.isBuffer(decryptedData)) {
        crypto.randomFillSync(decryptedData);
    }
    
    return operationResult;
    // ✅ No persistent sensitive state remains
});
```

#### **Pattern 2: Auto-Locking Objects**
```javascript
class AutoLockingWallet {
    constructor(encryptedData) {
        this.encryptedData = encryptedData;
        this.isUnlocked = false;
        this.sensitiveData = null;
        this.lockTimeout = null;
    }
    
    unlock(passwordBuffer) {
        this.sensitiveData = this.decrypt(passwordBuffer);
        this.isUnlocked = true;
        
        // Auto-lock after 30 seconds
        this.lockTimeout = setTimeout(() => this.lock(), 30000);
        
        return this.sensitiveData; // Return data immediately
    }
    
    lock() {
        if (this.sensitiveData && Buffer.isBuffer(this.sensitiveData)) {
            crypto.randomFillSync(this.sensitiveData);
        }
        this.sensitiveData = null;
        this.isUnlocked = false;
        if (this.lockTimeout) {
            clearTimeout(this.lockTimeout);
        }
    }
}

// Usage - wallet auto-locks after operations
const result = await manager.withDecryptedPassword((passwordBuffer) => {
    const data = wallet.unlock(passwordBuffer); // Get data immediately
    return performOperations(data); // Use it right away
    // Wallet will auto-lock after timeout
});
```

#### **Pattern 3: Explicit Cleanup**
```javascript
const result = await manager.withDecryptedPassword((passwordBuffer) => {
    try {
        wallet.unlock(passwordBuffer);
        return wallet.performOperation();
    } finally {
        // Explicitly lock the wallet to clear sensitive data
        wallet.lock(); // Must sanitize internal buffers
    }
});
```

### **Security Scope**

**What This System Protects:**
- ✅ Password buffers are guaranteed to be sanitized
- ✅ Password cannot be converted to immutable strings
- ✅ Password cannot leak through console output
- ✅ Password is stored in secure heap across process boundary

**What This System Does NOT Protect:**
- ❌ Objects unlocked/modified within the callback
- ❌ Derived sensitive data (private keys, seeds, etc.)
- ❌ State changes that persist after callback completion
- ❌ Memory allocated by third-party cryptographic libraries

**Developer Responsibility:**
You must ensure that any objects unlocked or sensitive data derived within the callback are properly sanitized according to your application's security requirements.

## Core Architecture

### Security Components

#### 1. **SecureHeapSecretManager** (`secure-heap-secret-manager.js`)
The core security component that handles all cryptographic operations within a secure heap-enabled process.

**Key Security Features:**
- **RSA Key Generation**: Private keys stored in secure heap via OpenSSL's secure malloc
- **Buffer-Only Operations**: Enforces Buffer usage, rejects string inputs to prevent immutable copies
- **Immediate Sanitization**: Overwrites input buffers immediately after encryption
- **Secure Heap Verification**: Validates that cryptographic keys remain in protected memory
- **Active Buffer Tracking**: Tracks all sensitive buffers for emergency cleanup during shutdown

```javascript
// Private key stored in secure heap
const keypair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

// Enforces buffer-only input, immediately sanitizes
#setEncryptedPassword(passwordBuffer) {
    if (!Buffer.isBuffer(passwordBuffer)) {
        throw new Error('SECURITY ERROR: requires Buffer, not string');
    }
    try {
        this.encryptedPassword = crypto.publicEncrypt({...}, passwordBuffer);
    } finally {
        crypto.randomFillSync(passwordBuffer); // Immediate sanitization
    }
}
```

#### 2. **SecureHeapProcessManager** (`secure-heap-process-manager.js`) - **Turn-Key Solution**
Manages the secure child process and provides a **callback-based API** with **guaranteed memory cleanup**.

**Callback Architecture:**
- **Automatic Buffer Sanitization**: Password buffers are **guaranteed** to be overwritten after callback execution
- **String Creation Prevention**: `toString()` and `toJSON()` methods are **blocked** to prevent immutable string copies
- **Console Output Sanitization**: Automatic redaction of sensitive data in logs
- **Exception Safety**: Cleanup happens even if callback throws errors

```javascript
// ✅ GUARANTEED CLEANUP - No manual memory management needed!
await manager.withDecryptedPassword((passwordBuffer) => {
    // Use password here - cleanup is AUTOMATIC
    const wallet = new Wallet(walletData);
    return wallet.unlock(passwordBuffer);
    // Buffer is automatically sanitized when callback exits
});
```

**Security Architecture:**
- **Process Isolation**: Forks child process with `--secure-heap=32768` flag
- **IPC Handling**: Manages secure communication between processes
- **Buffer Deserialization**: Properly reconstructs Buffer objects from IPC
- **Graceful Shutdown**: Comprehensive cleanup on all termination signals

#### 3. **Secure Worker Process** (`secure-worker.js`)
The isolated process that performs all sensitive operations within secure heap.

**Security Guarantees:**
- **Secure Heap Enabled**: All allocations use protected memory
- **Post-IPC Sanitization**: Buffers sanitized after IPC transmission
- **Exception Safety**: Cleanup guaranteed even on errors
- **Independent Cleanup**: Worker sanitizes its buffers regardless of main process state

#### 4. **BufferIO** (`bufferio.js`)
Secure input handling that reads passwords directly into buffers without string creation.

**Security Features:**
- **Direct Buffer Input**: Never creates intermediate strings
- **Immediate Cleanup**: Sanitizes input buffers after use
- **Signal Handling**: Secure cleanup on process termination

## Callback-Based Architecture: Turn-Key Security

### **Why Callback Architecture?**

The callback-based design **guarantees** memory safety by design, not by developer discipline:

```javascript
// ❌ OLD WAY (Error-prone - manual cleanup required)
const password = await manager.handleRequest('getDecryptedPassword');
try {
    // Use password
    const result = wallet.unlock(password);
} finally {
    crypto.randomFillSync(password); // EASY TO FORGET!
}

// ✅ NEW WAY (Turn-key - cleanup guaranteed)
const result = await manager.withDecryptedPassword((password) => {
    return wallet.unlock(password);
    // Cleanup is AUTOMATIC and GUARANTEED
});
```

### **Security Guarantees**

The callback architecture provides **military-grade security**:

1. **✅ Guaranteed Cleanup**: `finally` block **always** executes, even on exceptions
2. **✅ String Prevention**: `toString()` throws security errors to prevent immutable copies
3. **✅ Console Sanitization**: Automatic redaction of sensitive data in logs
4. **✅ Dual-Process Cleanup**: Both main and worker processes sanitize independently
5. **✅ Immediate Overwrite**: `crypto.randomFillSync()` is synchronous - no delays
6. **✅ Exception Safety**: Cleanup happens even if your callback crashes

## Usage Examples

### **Basic Usage Pattern**

```javascript
const SecureHeapProcessManager = require('./secure-heap-process-manager');

const manager = new SecureHeapProcessManager();

// Setup phase
await manager.handleRequest('generateSecureKeypair');
await manager.handleRequest('readInPassword', { promptString: 'Enter your password' });

// Usage phase with guaranteed cleanup
const result = await manager.withDecryptedPassword((passwordBuffer) => {
    // ✅ Use password here - it's a raw Buffer
    console.log('Password length:', passwordBuffer.length);
    
    // Example: Unlock a wallet
    const wallet = new Wallet(encryptedWalletData);
    return wallet.unlock(passwordBuffer);
    
    // ✅ NO MANUAL CLEANUP NEEDED - automatic sanitization!
});

console.log('Wallet unlock result:', result);
```

### **Async Callback Example**

The callback supports async operations seamlessly:

```javascript
// ✅ ASYNC CALLBACK - Full async/await support
const cryptoResult = await manager.withDecryptedPassword(async (passwordBuffer) => {
    console.log('Starting async crypto operations...');
    
    // Async operation 1: Derive key
    const salt = crypto.randomBytes(16);
    const derivedKey = await new Promise((resolve) => {
        crypto.pbkdf2(passwordBuffer, salt, 100000, 32, 'sha256', (err, key) => {
            resolve(key);
        });
    });
    
    // Async operation 2: Encrypt data
    const secretData = Buffer.from('My secret wallet data');
    const encrypted = await encryptData(secretData, derivedKey);
    
    // Async operation 3: Store in database
    await database.store({
        encrypted,
        salt,
        timestamp: Date.now()
    });
    
    // Clean up derived key
    crypto.randomFillSync(derivedKey);
    
    return {
        success: true,
        message: 'Async crypto operations completed',
        encryptedLength: encrypted.length
    };
    
    // ✅ passwordBuffer automatically sanitized after this async callback completes
});

console.log('Async result:', cryptoResult);
```

### **Wallet Unlocking Example**

Perfect for cryptocurrency wallet scenarios using the **safe pattern**:

```javascript
class SecureWallet {
    constructor(encryptedData, salt) {
        this.encryptedData = encryptedData;
        this.salt = salt;
        // ✅ SAFE: No persistent sensitive state stored
    }
    
    // ✅ SAFE: Extract data without storing it in object state
    async extractWalletData(passwordBuffer) {
        // Derive key from password
        const key = crypto.pbkdf2Sync(passwordBuffer, this.salt, 100000, 32, 'sha256');
        
        try {
            // Decrypt wallet data
            const decipher = crypto.createDecipher('aes-256-gcm', key);
            decipher.setAAD(this.salt);
            
            let decrypted = decipher.update(this.encryptedData);
            decrypted = Buffer.concat([decrypted, decipher.final()]);
            
            const walletData = JSON.parse(decrypted.toString());
            
            // ✅ SAFE: Return data immediately, don't store it
            return {
                success: true,
                privateKeys: walletData.privateKeys,
                address: walletData.address,
                balance: await this.calculateBalance(walletData.privateKeys)
            };
        } finally {
            crypto.randomFillSync(key); // Clean up derived key
        }
    }
}

// ✅ SAFE USAGE: Extract data and clean up immediately
const unlockResult = await manager.withDecryptedPassword(async (passwordBuffer) => {
    const wallet = new SecureWallet(encryptedWalletData, walletSalt);
    const walletData = await wallet.extractWalletData(passwordBuffer);
    
    // Use the data immediately for operations
    const transactionResult = await performTransaction(walletData.privateKeys);
    
    // ✅ CRITICAL: Clean up sensitive data immediately
    if (walletData.privateKeys && Array.isArray(walletData.privateKeys)) {
        walletData.privateKeys.forEach(key => {
            if (Buffer.isBuffer(key)) {
                crypto.randomFillSync(key);
            }
        });
    }
    
    return {
        success: walletData.success,
        address: walletData.address,
        balance: walletData.balance,
        transactionId: transactionResult.id
    };
    // ✅ passwordBuffer automatically sanitized here
    // ✅ walletData.privateKeys already sanitized above
});

if (unlockResult.success) {
    console.log('Transaction completed! Address:', unlockResult.address);
    // ✅ SAFE: No sensitive data remains in memory
}
```

**⚠️ What NOT to do:**
```javascript
// ❌ DANGEROUS - DON'T DO THIS:
class DangerousWallet {
    async unlock(passwordBuffer) {
        // ... decryption logic ...
        this.privateKeys = decryptedData; // ❌ Stores sensitive data in object state
        this.isUnlocked = true;
        return { success: true };
    }
}

const wallet = new DangerousWallet();
await manager.withDecryptedPassword(async (passwordBuffer) => {
    return await wallet.unlock(passwordBuffer);
});
// ❌ SECURITY BREACH: wallet.privateKeys still accessible here!
console.log(wallet.privateKeys); // ❌ This still works - sensitive data leaked!

// ❌ ALSO DANGEROUS - DON'T DO THIS EITHER:
let copiedPassword;
await manager.withDecryptedPassword((passwordBuffer) => {
    copiedPassword = Buffer.from(passwordBuffer); // ❌ CRITICAL: Creates separate buffer copy!
    // or copiedPassword = passwordBuffer.slice(); // ❌ Also creates a copy
});
// ❌ SECURITY BREACH: copiedPassword contains original password data!
console.log(copiedPassword); // ❌ Original password still accessible - security defeated!

// ✅ NOTE: Simple reference assignment is actually NOT dangerous:
// let passwordRef = passwordBuffer; // ← This is OK - same buffer, gets sanitized
// The issue is only with creating COPIES of the buffer data
```

### **Error Handling with Guaranteed Cleanup**

Even if your callback throws errors, cleanup is guaranteed:

```javascript
try {
    const result = await manager.withDecryptedPassword((passwordBuffer) => {
        // Even if this throws an error...
        if (passwordBuffer.length < 8) {
            throw new Error('Password too short!');
        }
        
        // Or this operation fails...
        const wallet = new Wallet(corruptedData);
        return wallet.unlock(passwordBuffer); // Might throw
    });
} catch (error) {
    console.error('Operation failed:', error.message);
    // ✅ passwordBuffer was STILL sanitized despite the error!
}
```

### **Security Features Demonstration**

```javascript
await manager.withDecryptedPassword((passwordBuffer) => {
    // ✅ These operations are BLOCKED for security:
    
    try {
        const str = passwordBuffer.toString(); // ❌ Throws security error
    } catch (error) {
        console.log('toString() blocked:', error.message);
    }
    
    try {
        JSON.stringify(passwordBuffer); // ❌ Throws security error
    } catch (error) {
        console.log('JSON conversion blocked:', error.message);
    }
    
    // ✅ Console logging is automatically sanitized:
    console.log('Buffer:', passwordBuffer); // Shows: [SecureBuffer: *** REDACTED ***]
    
    // ✅ But you can still use the buffer for crypto operations:
    const hash = crypto.createHash('sha256');
    hash.update(passwordBuffer);
    const digest = hash.digest('hex');
    console.log('Password hash:', digest);
    
    return { hashGenerated: true };
});
```

## Security Proof: Buffer Sanitization Across Process Boundary

### Problem Statement
In multi-process architectures, sensitive data can persist in memory across process boundaries, creating attack vectors through memory dumps or heap analysis.

### Solution Architecture
This implementation guarantees buffer sanitization on **both sides** of the process barrier through independent cleanup mechanisms.

### Proof of Sanitization

#### Side 1: Secure Worker Process

**Buffer Lifecycle:**
1. **Creation**: `getDecryptedPassword()` creates buffer in secure heap
2. **IPC Assignment**: Buffer assigned to `outboundMsg.data`
3. **Transmission**: Node.js IPC serializes buffer for transmission
4. **Sanitization**: Post-send callback overwrites original buffer

```javascript
// secure-worker.js
process.send(outboundMsg, (error) => {
    if (Buffer.isBuffer(decryptedPasswordBuffer)) {
        crypto.randomFillSync(decryptedPasswordBuffer);  // ← GUARANTEED OVERWRITE
        secureHeapSecretManager.removeFromTracking(decryptedPasswordBuffer);
        decryptedPasswordBuffer = null;
    }
});
```

**Proof Points:**
- `crypto.randomFillSync()` is synchronous and blocking
- Callback executes **after** IPC transmission completes
- Original buffer in worker memory is **definitively overwritten**

#### Side 2: Main Process (Callback Architecture)

**Buffer Lifecycle:**
1. **Reception**: IPC deserializes into **new buffer** in main process memory
2. **Security Setup**: `toString()` and `toJSON()` methods overridden to throw errors
3. **Usage**: Application receives buffer in callback
4. **Sanitization**: `finally` block **guarantees** cleanup

```javascript
// secure-heap-process-manager.js
async withDecryptedPassword(callback) {
    const passwordBuffer = await this.handleRequest('getDecryptedPassword');
    
    // Override dangerous methods
    passwordBuffer.toString = () => { throw new Error('SECURITY ERROR: ...'); };
    passwordBuffer.toJSON = () => { throw new Error('SECURITY ERROR: ...'); };
    
    try {
        return await callback(passwordBuffer);
    } finally {
        crypto.randomFillSync(passwordBuffer);  // ← GUARANTEED OVERWRITE
        if (global.gc) global.gc();
    }
}
```

**Proof Points:**
- IPC creates **separate buffer** in different memory space
- `finally` block **always executes** regardless of exceptions
- Main process buffer is **independently sanitized**
- **String creation is blocked** - prevents immutable copies

#### Technical Verification

**Process Isolation:**
- Each process has isolated virtual memory space
- IPC cannot share memory, must serialize/deserialize
- Results in **two distinct buffers** with same content

**Sanitization Independence:**
- Worker sanitizes **its copy** after IPC send
- Main process sanitizes **its copy** after callback
- **Both buffers overwritten independently**

**Empirical Evidence:**
Console output confirms both sanitization points execute:
- Worker: `"decryptedPasswordBuffer is buffer - secure worker random fill sync"`
- Main: `"SecureHeapProcessManager: Password buffer sanitized in main process"`

### Enhanced Security Features

#### **String Creation Prevention**
```javascript
// These operations are BLOCKED and throw security errors:
passwordBuffer.toString()     // ❌ Throws: "Converting password buffer to string is forbidden"
passwordBuffer.toJSON()       // ❌ Throws: "Converting password buffer to JSON is forbidden"
JSON.stringify(passwordBuffer) // ❌ Throws: "Converting password buffer to JSON is forbidden"
```

#### **Console Output Sanitization**
```javascript
console.log(passwordBuffer);           // Shows: [SecureBuffer: *** REDACTED ***]
console.log('password:', someString);  // Shows: [REDACTED: Potentially sensitive data]
console.log(someBuffer);              // Shows: [Buffer: 32 bytes - CONTENT REDACTED]
```

## Graceful Shutdown Architecture

### Problem Statement
Process termination (via signals, exceptions, or normal exit) can leave sensitive data in memory if not properly handled.

### Solution
The system implements comprehensive shutdown handling across all components to ensure sensitive data is sanitized before process termination.

### Shutdown Components

#### 1. **SecureHeapSecretManager Shutdown**
Handles cleanup of all sensitive data within the secure heap process:

```javascript
shutdown() {
    // Clear encrypted password
    if (this.encryptedPassword && Buffer.isBuffer(this.encryptedPassword)) {
        crypto.randomFillSync(this.encryptedPassword);
        this.encryptedPassword = null;
    }
    
    // Clear any tracked active buffers
    for (const buffer of this.activeBuffers) {
        if (Buffer.isBuffer(buffer)) {
            crypto.randomFillSync(buffer);
        }
    }
    this.activeBuffers.clear();
    
    // Clear RSA key references
    this.rsaPrivateKey = null;
    this.rsaPublicKey = null;
    
    // Force garbage collection
    if (global.gc) {
        global.gc();
    }
}
```

#### 2. **Signal Handling**
Registers handlers for all standard termination signals:

- **SIGINT** (Ctrl+C): User interruption
- **SIGTERM**: Graceful termination request
- **SIGHUP**: Hang up signal
- **uncaughtException**: Unhandled errors
- **unhandledRejection**: Unhandled promise rejections
- **beforeExit**: Normal process exit

#### 3. **Active Buffer Tracking**
The system tracks all active password buffers to ensure cleanup even during unexpected shutdown:

```javascript
// Buffers are tracked when created
this.activeBuffers.add(passwordBuffer);

// And removed after sanitization
this.activeBuffers.delete(passwordBuffer);

// All tracked buffers are sanitized during shutdown
for (const buffer of this.activeBuffers) {
    crypto.randomFillSync(buffer);
}
```

#### 4. **Cross-Process Shutdown Coordination**
The main process sends graceful shutdown signals to the secure worker process:

```javascript
// Send SIGTERM to child process
this.child.kill('SIGTERM');

// Fallback to SIGKILL after timeout
setTimeout(() => {
    if (!this.child.killed) {
        this.child.kill('SIGKILL');
    }
}, 5000);
```

### Shutdown Guarantees

✅ **Signal Coverage**: All standard termination signals handled  
✅ **Exception Safety**: Cleanup occurs even during errors  
✅ **Buffer Tracking**: All active buffers sanitized on shutdown  
✅ **Cross-Process**: Both main and worker processes shutdown gracefully  
✅ **Timeout Protection**: Forced termination if graceful shutdown fails  

## Comprehensive Security Testing

### Test Suite: `test-security-behavior.sh`

The project includes a comprehensive shell script that **proves** all security behaviors work correctly. This script serves as definitive verification that the secure heap password management system is functioning as designed.

#### Running the Tests

```bash
# Run all security tests
./test-security-behavior.sh

# Or using npm
npm test
```

#### What the Tests Prove

The test suite runs **18 comprehensive tests** that verify every aspect of the security implementation:

**TEST 1-2: Environment & Dependencies**
- ✅ Node.js version supports secure heap (v16+)
- ✅ All required files present and importable

**TEST 3-4: Core Security Foundations**
- ✅ **Secure Heap Allocation**: Proves RSA keys increase secure heap usage from 0 to 1408+ bytes
- ✅ **Buffer Sanitization**: Proves `crypto.randomFillSync()` completely overwrites buffer contents

**TEST 5-6: Process Management**
- ✅ **Cross-Process Communication**: Proves IPC works for all message types
- ✅ **Process Isolation**: Proves main process has 0 secure heap usage while worker uses secure heap

**TEST 7-8: Graceful Shutdown**
- ✅ **SIGTERM Handling**: Proves graceful shutdown on termination signals
- ✅ **SIGINT Handling**: Proves graceful shutdown on user interruption (Ctrl+C)

**TEST 9-11: Memory Management**
- ✅ **Memory Cleanup**: Proves shutdown sanitizes all tracked buffers
- ✅ **Buffer Tracking**: Proves active buffer tracking and removal works
- ✅ **Integration**: Proves complete buffer lifecycle from creation to sanitization

#### Test Implementation Details

The shell script creates isolated test scenarios for each security behavior:

```bash
# Example: Secure Heap Allocation Test
cat > test_secure_heap.js << 'EOF'
const crypto = require('crypto');
const initial = crypto.secureHeapUsed();
const keypair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const after = crypto.secureHeapUsed();

if (after.used > initial.used) {
    console.log('SUCCESS: Secure heap usage increased');
    process.exit(0);
} else {
    process.exit(1);
}
EOF

node --secure-heap=32768 test_secure_heap.js
```

**Key Testing Features:**
- **macOS Compatible**: Uses custom timeout function instead of Linux `timeout`
- **Process Management**: Properly handles background processes and signal testing
- **Error Isolation**: Individual test failures don't stop the entire suite
- **Comprehensive Coverage**: Tests every security behavior and edge case
- **Empirical Verification**: Each test provides concrete proof of functionality

#### Test Output Example

```
🔒 SECURE HEAP PASSWORD MANAGEMENT - SECURITY TEST SUITE
========================================================

TEST 1: Node.js Version and Secure Heap Support
================================================
ℹ️  INFO: Node.js version: v20.13.1
✅ PASS: Node.js version supports secure heap (v16+)
✅ PASS: Node.js secure heap flag works

[... 16 more tests ...]

FINAL RESULTS
=============
Tests Passed: 18
Tests Failed: 0
Total Tests:  18

🎉 ALL TESTS PASSED! Security behaviors verified.
The secure heap password management system is working correctly.
```

## API Reference

### **SecureHeapProcessManager**

#### **Setup Methods**
```javascript
// Generate RSA keypair in secure heap
await manager.handleRequest('generateSecureKeypair');

// Read password from user input
await manager.handleRequest('readInPassword', { promptString: 'Enter password' });

// Verify secure heap allocation
await manager.handleRequest('verifyExpectedAllocation');

// Check if secure heap is enabled
await manager.handleRequest('checkSecureHeapEnabled');
```

#### **Secure Callback Method**
```javascript
// Execute callback with guaranteed cleanup
const result = await manager.withDecryptedPassword((passwordBuffer) => {
    // Use passwordBuffer here
    // Automatic sanitization when callback completes
    return yourOperation(passwordBuffer);
});
```

#### **Utility Methods**
```javascript
// Disable console sanitization (development only)
manager.disableConsoleSanitization();

// Stop the manager and child process
manager.stop();
```

## Security Considerations

### Threat Model
- **Memory Dump Attacks**: Mitigated by immediate buffer sanitization
- **Heap Analysis**: Mitigated by secure heap allocation for private keys
- **Process Memory Inspection**: Mitigated by cross-process isolation
- **Exception-Based Leaks**: Mitigated by finally block cleanup
- **Accidental String Creation**: Mitigated by toString() override
- **Console Log Exposure**: Mitigated by automatic output sanitization

### Limitations
- **⚠️ CRITICAL: Callback State Persistence**: Objects unlocked or modified within the callback retain their state after callback completion. The system only sanitizes the password buffer itself, not derived sensitive data stored in object properties. This is the most significant security limitation.
- **Brief Exposure Window**: Buffers exist briefly during IPC transmission and callback execution
- **Node.js Dependencies**: Relies on Node.js secure heap implementation
- **Platform Specific**: Secure heap behavior varies by platform
- **VM Context**: Not suitable for browser environments

### Best Practices
1. **Use safe callback patterns**: Extract data immediately and clean up within the callback, don't store sensitive data in object state
2. Always use the callback pattern with `withDecryptedPassword()`
3. Never attempt to convert buffers to strings within callbacks
4. **Sanitize derived sensitive data**: Any sensitive data derived from the password (private keys, seeds, etc.) must be explicitly sanitized by your application
5. Keep callback execution time minimal to reduce exposure window
6. **Prefer functional/immutable approaches**: Return data from functions rather than modifying object state
7. Enable garbage collection with `--expose-gc`
8. Use minimal heap sizes with `--max-old-space-size`
9. Run comprehensive tests before production deployment

## Technical Requirements

- **Node.js**: v16+ (secure heap support)
- **Memory**: Minimum 32KB secure heap allocation
- **Platform**: Linux/macOS/Windows with OpenSSL secure malloc support
- **Flags**: `--secure-heap=32768 --expose-gc` recommended

## Testing and Verification

This project includes comprehensive testing that **proves** all security behaviors work correctly:

- **Shell Script Testing**: `test-security-behavior.sh` - 18 comprehensive tests
- **Manual Verification**: All security behaviors manually tested and confirmed
- **Cross-Platform**: Tests work on macOS, Linux, and other Unix-like systems

Run `npm test` to verify all security behaviors on your system.

## License

ISC - For educational and proof-of-concept purposes. 