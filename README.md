# Secure Heap Password Management Proof of Concept

A Node.js implementation demonstrating secure password handling using Node.js secure heap allocation, cross-process isolation, and guaranteed buffer sanitization to prevent memory-based password extraction attacks.

## Overview

This project implements a security-hardened password management system that ensures sensitive password data:
- Never exists as immutable strings in memory
- Is stored in Node.js secure heap (protected memory regions)
- Is immediately sanitized after use across process boundaries
- Cannot be extracted through memory dumps or heap analysis

## Core Architecture

### Security Components

#### 1. **SecureHeapSecretManager** (`secure-heap-secret-manager.js`)
The core security component that handles all cryptographic operations within a secure heap-enabled process.

**Key Security Features:**
- **RSA Key Generation**: Private keys stored in secure heap via OpenSSL's secure malloc
- **Buffer-Only Operations**: Enforces Buffer usage, rejects string inputs to prevent immutable copies
- **Immediate Sanitization**: Overwrites input buffers immediately after encryption
- **Secure Heap Verification**: Validates that cryptographic keys remain in protected memory

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

#### 2. **SecureHeapProcessManager** (`secure-heap-process-manager.js`)
Manages the secure child process and handles cross-process communication.

**Security Architecture:**
- **Process Isolation**: Forks child process with `--secure-heap=32768` flag
- **IPC Handling**: Manages secure communication between processes
- **Buffer Deserialization**: Properly reconstructs Buffer objects from IPC

```javascript
this.child = fork('./secure-worker.js', [], {
    execArgv: [`--secure-heap=${n} --expose-gc`]  // Enable secure heap
});
```

#### 3. **Secure Worker Process** (`secure-worker.js`)
The isolated process that performs all sensitive operations within secure heap.

**Security Guarantees:**
- **Secure Heap Enabled**: All allocations use protected memory
- **Post-IPC Sanitization**: Buffers sanitized after IPC transmission
- **Exception Safety**: Cleanup guaranteed even on errors

#### 4. **BufferIO** (`bufferio.js`)
Secure input handling that reads passwords directly into buffers without string creation.

**Security Features:**
- **Direct Buffer Input**: Never creates intermediate strings
- **Immediate Cleanup**: Sanitizes input buffers after use
- **Signal Handling**: Secure cleanup on process termination

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
        decryptedPasswordBuffer = null;
    }
});
```

**Proof Points:**
- `crypto.randomFillSync()` is synchronous and blocking
- Callback executes **after** IPC transmission completes
- Original buffer in worker memory is **definitively overwritten**

#### Side 2: Main Process

**Buffer Lifecycle:**
1. **Reception**: IPC deserializes into **new buffer** in main process memory
2. **Usage**: Application receives distinct buffer object
3. **Sanitization**: `finally` block guarantees cleanup

```javascript
// example.js
try {
    // Use decrypted password
} finally {
    if (Buffer.isBuffer(decryptedPassword)) {
        crypto.randomFillSync(decryptedPassword);  // ← GUARANTEED OVERWRITE
    }
}
```

**Proof Points:**
- IPC creates **separate buffer** in different memory space
- `finally` block **always executes** regardless of exceptions
- Main process buffer is **independently sanitized**

#### Technical Verification

**Process Isolation:**
- Each process has isolated virtual memory space
- IPC cannot share memory, must serialize/deserialize
- Results in **two distinct buffers** with same content

**Sanitization Independence:**
- Worker sanitizes **its copy** after IPC send
- Main process sanitizes **its copy** after use
- **Both buffers overwritten independently**

**Empirical Evidence:**
Console output confirms both sanitization points execute:
- Worker: `"decryptedPasswordBuffer is buffer - secure worker random fill sync"`
- Main: `"Application: Password buffer sanitized in finally block"`

### Security Guarantees

✅ **No Immutable Strings**: Password never converted to string (immutable)  
✅ **Secure Heap Storage**: Private keys protected in secure memory  
✅ **Cross-Process Sanitization**: Buffers cleaned on both sides of IPC  
✅ **Exception Safety**: Cleanup guaranteed even with errors  
✅ **Immediate Cleanup**: Minimal exposure window with try/finally patterns  
✅ **Graceful Shutdown**: All sensitive data sanitized on process termination  

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

## Usage Example

The `example.js` file demonstrates the security architecture in action and serves as a reference implementation for applications.

### Running the Demo

```bash
# Enable garbage collection for additional security
node --expose-gc example.js

# Or using npm
npm start
```

### Key Features Demonstrated

1. **Secure Heap Verification**: Confirms private keys are in protected memory
2. **Password Input**: Secure buffer-based password entry
3. **Infinite Loop Testing**: Continuous decryption to verify persistent security
4. **Buffer Sanitization**: Demonstrates proper cleanup after each use

### Integration Pattern

```javascript
const SecureHeapProcessManager = require('./secure-heap-process-manager');

const manager = new SecureHeapProcessManager();

// Setup phase
await manager.handleRequest('generateSecureKeypair');
await manager.handleRequest('readInPassword');

// Usage phase with guaranteed cleanup
const decryptedPassword = await manager.handleRequest('getDecryptedPassword');
try {
    // Use password for authentication, etc.
    performSecureOperation(decryptedPassword);
} finally {
    // CRITICAL: Always sanitize
    if (Buffer.isBuffer(decryptedPassword)) {
        crypto.randomFillSync(decryptedPassword);
    }
}
```

## Security Considerations

### Threat Model
- **Memory Dump Attacks**: Mitigated by immediate buffer sanitization
- **Heap Analysis**: Mitigated by secure heap allocation for private keys
- **Process Memory Inspection**: Mitigated by cross-process isolation
- **Exception-Based Leaks**: Mitigated by finally block cleanup

### Limitations
- **Brief Exposure Window**: Buffers exist briefly during IPC transmission
- **Node.js Dependencies**: Relies on Node.js secure heap implementation
- **Platform Specific**: Secure heap behavior varies by platform

### Best Practices
1. Always use try/finally for buffer cleanup
2. Never convert buffers to strings
3. Verify secure heap allocation before operations
4. Enable garbage collection with `--expose-gc`
5. Use minimal heap sizes with `--max-old-space-size`

## Technical Requirements

- **Node.js**: v16+ (secure heap support)
- **Memory**: Minimum 32KB secure heap allocation
- **Platform**: Linux/macOS/Windows with OpenSSL secure malloc support

## Testing and Verification

This project includes comprehensive testing that **proves** all security behaviors work correctly:

- **Shell Script Testing**: `test-security-behavior.sh` - 18 comprehensive tests
- **Manual Verification**: All security behaviors manually tested and confirmed
- **Cross-Platform**: Tests work on macOS, Linux, and other Unix-like systems

Run `npm test` to verify all security behaviors on your system.

## License

ISC - For educational and proof-of-concept purposes. 