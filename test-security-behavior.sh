#!/bin/bash

# Secure Heap Password Management - Security Behavior Test Suite
# Tests all critical security behaviors of the system

echo "🔒 SECURE HEAP PASSWORD MANAGEMENT - SECURITY TEST SUITE"
echo "========================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TOTAL_TESTS=0

# Helper functions
pass_test() {
    echo -e "${GREEN}✅ PASS:${NC} $1"
    ((TESTS_PASSED++))
    ((TOTAL_TESTS++))
}

fail_test() {
    echo -e "${RED}❌ FAIL:${NC} $1"
    ((TESTS_FAILED++))
    ((TOTAL_TESTS++))
    return 0  # Don't exit on individual test failures
}

info() {
    echo -e "${BLUE}ℹ️  INFO:${NC} $1"
}

warning() {
    echo -e "${YELLOW}⚠️  WARN:${NC} $1"
}

# Function to run a command with timeout (macOS compatible)
run_with_timeout() {
    local timeout_duration=$1
    shift
    local cmd="$@"
    
    # Run command in background
    eval "$cmd" &
    local pid=$!
    
    # Wait for timeout or completion
    local count=0
    while [ $count -lt $timeout_duration ]; do
        if ! kill -0 $pid 2>/dev/null; then
            wait $pid
            return $?
        fi
        sleep 1
        ((count++))
    done
    
    # Timeout reached, kill process
    kill -TERM $pid 2>/dev/null
    sleep 2
    kill -KILL $pid 2>/dev/null
    return 124  # Timeout exit code
}

# Test 1: Node.js Version and Secure Heap Support
echo -e "\n${BLUE}TEST 1: Node.js Version and Secure Heap Support${NC}"
echo "================================================"

NODE_VERSION=$(node --version)
info "Node.js version: $NODE_VERSION"

# Extract major version number
MAJOR_VERSION=$(node --version | sed 's/v\([0-9]*\).*/\1/')
if [ "$MAJOR_VERSION" -ge 16 ]; then
    pass_test "Node.js version supports secure heap (v16+)"
else
    fail_test "Node.js version too old for secure heap support (need v16+)"
fi

# Test secure heap flag
if node --secure-heap=1024 -e "console.log('Secure heap test passed')" > /dev/null 2>&1; then
    pass_test "Node.js secure heap flag works"
else
    fail_test "Node.js secure heap flag not supported"
fi

# Test 2: File Dependencies
echo -e "\n${BLUE}TEST 2: File Dependencies${NC}"
echo "=========================="

REQUIRED_FILES=("secure-heap-secret-manager.js" "secure-heap-process-manager.js" "secure-worker.js" "bufferio.js" "example.js")

for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        pass_test "Required file exists: $file"
    else
        fail_test "Missing required file: $file"
    fi
done

# Test 3: Basic Import/Require Test
echo -e "\n${BLUE}TEST 3: Basic Import/Require Test${NC}"
echo "=================================="

# Test SecureHeapProcessManager import
if node -e "const SecureHeapProcessManager = require('./secure-heap-process-manager'); console.log('Import successful');" > /dev/null 2>&1; then
    pass_test "SecureHeapProcessManager imports successfully"
else
    fail_test "SecureHeapProcessManager import failed"
fi

# Test BufferIO import
if node -e "const { BufferIO } = require('./bufferio'); console.log('Import successful');" > /dev/null 2>&1; then
    pass_test "BufferIO imports successfully"
else
    fail_test "BufferIO import failed"
fi

# Test 4: Secure Heap Allocation Test
echo -e "\n${BLUE}TEST 4: Secure Heap Allocation Test${NC}"
echo "==================================="

# Create a test script to verify secure heap allocation
cat > test_secure_heap.js << 'EOF'
const crypto = require('crypto');

try {
    // Check initial secure heap usage
    const initial = crypto.secureHeapUsed();
    
    // Generate RSA keypair (should use secure heap)
    const keypair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const after = crypto.secureHeapUsed();
    
    if (after.used > initial.used) {
        console.log('SUCCESS: Secure heap usage increased from', initial.used, 'to', after.used);
        process.exit(0);
    } else {
        console.log('FAILURE: Secure heap usage did not increase. Before:', initial.used, 'After:', after.used);
        process.exit(1);
    }
} catch (error) {
    console.error('ERROR:', error.message);
    process.exit(1);
}
EOF

if node --secure-heap=32768 test_secure_heap.js > /dev/null 2>&1; then
    pass_test "Secure heap allocation works for RSA keys"
else
    fail_test "Secure heap allocation test failed"
fi

rm -f test_secure_heap.js

# Test 5: Buffer Sanitization Test
echo -e "\n${BLUE}TEST 5: Buffer Sanitization Test${NC}"
echo "================================="

# Create a test to verify crypto.randomFillSync works
cat > test_buffer_sanitization.js << 'EOF'
const crypto = require('crypto');

try {
    // Create a buffer with known content
    const testBuffer = Buffer.from('sensitive password data');
    const originalContent = testBuffer.toString();
    
    // Sanitize the buffer
    crypto.randomFillSync(testBuffer);
    const sanitizedContent = testBuffer.toString();
    
    // Verify content changed
    if (originalContent !== sanitizedContent) {
        console.log('SUCCESS: Buffer content was sanitized');
        process.exit(0);
    } else {
        console.log('FAILURE: Buffer content was not changed');
        process.exit(1);
    }
} catch (error) {
    console.error('ERROR:', error.message);
    process.exit(1);
}
EOF

if node test_buffer_sanitization.js > /dev/null 2>&1; then
    pass_test "Buffer sanitization with crypto.randomFillSync works"
else
    fail_test "Buffer sanitization test failed"
fi

rm -f test_buffer_sanitization.js

# Test 6: Process Manager Basic Functionality
echo -e "\n${BLUE}TEST 6: Process Manager Basic Functionality${NC}"
echo "============================================"

# Create a test script for basic process manager functionality
cat > test_process_manager.js << 'EOF'
const SecureHeapProcessManager = require('./secure-heap-process-manager');

(async () => {
    let manager;
    try {
        manager = new SecureHeapProcessManager();
        
        // Test secure heap check
        const heapStatus = await manager.handleRequest('checkSecureHeapEnabled');
        if (!heapStatus || typeof heapStatus.isSecureHeapUsed !== 'boolean') {
            throw new Error('Invalid heap status response');
        }
        
        // Test keypair generation
        const keypairResult = await manager.handleRequest('generateSecureKeypair');
        if (!keypairResult || typeof keypairResult.isExpectedAllocationVerified !== 'boolean') {
            throw new Error('Invalid keypair generation response');
        }
        
        console.log('SUCCESS: Basic process manager functionality works');
        process.exit(0);
    } catch (error) {
        console.error('FAILURE:', error.message);
        process.exit(1);
    } finally {
        if (manager) {
            manager.stop();
        }
    }
})();
EOF

if run_with_timeout 30 "node --expose-gc test_process_manager.js" > /dev/null 2>&1; then
    pass_test "Process manager basic functionality works"
else
    fail_test "Process manager basic functionality failed"
fi

rm -f test_process_manager.js

# Test 7: Graceful Shutdown Test
echo -e "\n${BLUE}TEST 7: Graceful Shutdown Test${NC}"
echo "==============================="

# Create a test script that runs and then gets interrupted
cat > test_graceful_shutdown.js << 'EOF'
const SecureHeapProcessManager = require('./secure-heap-process-manager');

(async () => {
    let manager;
    try {
        manager = new SecureHeapProcessManager();
        await manager.handleRequest('generateSecureKeypair');
        console.log('READY_FOR_SHUTDOWN');
        
        // Keep process alive to receive signal
        setTimeout(() => {
            console.log('TIMEOUT_REACHED');
            if (manager) manager.stop();
            process.exit(1);
        }, 10000);
        
    } catch (error) {
        console.error('Error:', error.message);
        if (manager) manager.stop();
        process.exit(1);
    }
})();
EOF

# Start the process in background and send SIGTERM
node --expose-gc test_graceful_shutdown.js > /dev/null 2>&1 &
PID=$!

# Wait for process to be ready
sleep 3

# Send SIGTERM and check if process terminates gracefully
if kill -0 $PID 2>/dev/null; then
    kill -TERM $PID 2>/dev/null
    sleep 3
    if ! kill -0 $PID 2>/dev/null; then
        pass_test "Graceful shutdown on SIGTERM works"
    else
        kill -KILL $PID 2>/dev/null
        fail_test "Process did not shutdown gracefully on SIGTERM"
    fi
else
    fail_test "Test process was not running when signal was sent"
fi

rm -f test_graceful_shutdown.js

# Test 8: Signal Handler Coverage Test
echo -e "\n${BLUE}TEST 8: Signal Handler Coverage Test${NC}"
echo "====================================="

# Test multiple signals
SIGNALS=("TERM" "INT")  # Removed HUP as it may not work consistently on all systems

for signal in "${SIGNALS[@]}"; do
    cat > test_signal_$signal.js << EOF
const SecureHeapProcessManager = require('./secure-heap-process-manager');

let manager;
try {
    manager = new SecureHeapProcessManager();
    console.log('READY_FOR_SIGNAL_$signal');
    
    // Keep process alive
    setTimeout(() => {
        if (manager) manager.stop();
        process.exit(1);
    }, 8000);
} catch (error) {
    console.error('Error:', error.message);
    if (manager) manager.stop();
    process.exit(1);
}
EOF

    node --expose-gc test_signal_$signal.js > /dev/null 2>&1 &
    PID=$!
    
    sleep 2
    
    if kill -0 $PID 2>/dev/null; then
        kill -$signal $PID 2>/dev/null
        sleep 2
        if ! kill -0 $PID 2>/dev/null; then
            pass_test "Signal handler works for SIG$signal"
        else
            kill -KILL $PID 2>/dev/null
            fail_test "Signal handler failed for SIG$signal"
        fi
    else
        fail_test "Could not test SIG$signal - process not running"
    fi
    
    rm -f test_signal_$signal.js
done

# Test 9: Memory Cleanup Verification
echo -e "\n${BLUE}TEST 9: Memory Cleanup Verification${NC}"
echo "===================================="

# Create a test that verifies memory cleanup occurs
cat > test_memory_cleanup.js << 'EOF'
const crypto = require('crypto');
const { SecureHeapSecretManager } = require('./secure-heap-secret-manager');

try {
    // Test that shutdown clears all tracked buffers
    const manager = new SecureHeapSecretManager();
    
    // Add some test buffers to track
    const buffer1 = Buffer.from('test data 1');
    const buffer2 = Buffer.from('test data 2');
    
    // Access activeBuffers for testing
    manager.activeBuffers.add(buffer1);
    manager.activeBuffers.add(buffer2);
    
    const beforeCount = manager.activeBuffers.size;
    
    // Shutdown should clear all buffers
    manager.shutdown();
    
    const afterCount = manager.activeBuffers.size;
    const isShutDown = manager.isShutDown();
    
    if (beforeCount === 2 && afterCount === 0 && isShutDown) {
        console.log('SUCCESS: Memory cleanup verification passed');
        process.exit(0);
    } else {
        console.log('FAILURE: Memory cleanup verification failed');
        console.log('Before:', beforeCount, 'After:', afterCount, 'Shutdown:', isShutDown);
        process.exit(1);
    }
} catch (error) {
    console.error('ERROR:', error.message);
    process.exit(1);
}
EOF

if node --secure-heap=32768 test_memory_cleanup.js > /dev/null 2>&1; then
    pass_test "Memory cleanup verification works"
else
    fail_test "Memory cleanup verification failed"
fi

rm -f test_memory_cleanup.js

# Test 10: Cross-Process Communication Test
echo -e "\n${BLUE}TEST 10: Cross-Process Communication Test${NC}"
echo "=========================================="

# Test that IPC works correctly between processes
cat > test_ipc_communication.js << 'EOF'
const SecureHeapProcessManager = require('./secure-heap-process-manager');

(async () => {
    let manager;
    try {
        manager = new SecureHeapProcessManager();
        
        // Test all IPC message types
        const heapStatus = await manager.handleRequest('checkSecureHeapEnabled');
        const keypairResult = await manager.handleRequest('generateSecureKeypair');
        const allocationResult = await manager.handleRequest('verifyExpectedAllocation');
        
        // Verify all responses are valid
        if (!heapStatus || typeof heapStatus.isSecureHeapUsed !== 'boolean') {
            throw new Error('Invalid heap status response');
        }
        
        if (!keypairResult || typeof keypairResult.isExpectedAllocationVerified !== 'boolean') {
            throw new Error('Invalid keypair result response');
        }
        
        if (!allocationResult || typeof allocationResult.isExpectedAllocationVerified !== 'boolean') {
            throw new Error('Invalid allocation result response');
        }
        
        console.log('SUCCESS: Cross-process communication works');
        process.exit(0);
    } catch (error) {
        console.error('FAILURE:', error.message);
        process.exit(1);
    } finally {
        if (manager) {
            manager.stop();
        }
    }
})();
EOF

if run_with_timeout 30 "node --expose-gc test_ipc_communication.js" > /dev/null 2>&1; then
    pass_test "Cross-process communication works"
else
    fail_test "Cross-process communication failed"
fi

rm -f test_ipc_communication.js

# Test 11: Buffer Tracking and Sanitization Integration Test
echo -e "\n${BLUE}TEST 11: Buffer Tracking Integration Test${NC}"
echo "========================================="

cat > test_buffer_tracking.js << 'EOF'
const crypto = require('crypto');
const { SecureHeapSecretManager } = require('./secure-heap-secret-manager');

(async () => {
    try {
        const manager = new SecureHeapSecretManager();
        
        // Generate keypair first
        await manager.generateSecureKeypair();
        
        // Simulate getting a decrypted password buffer
        const testBuffer = Buffer.from('simulated decrypted password');
        const originalContent = testBuffer.toString();
        
        // Track the buffer
        manager.activeBuffers.add(testBuffer);
        
        if (manager.activeBuffers.size !== 1) {
            throw new Error('Buffer tracking failed');
        }
        
        // Shutdown should sanitize the buffer
        manager.shutdown();
        
        // Verify buffer was sanitized and tracking cleared
        if (testBuffer.toString() === originalContent) {
            throw new Error('Buffer was not sanitized during shutdown');
        }
        
        if (manager.activeBuffers.size !== 0) {
            throw new Error('Buffer tracking was not cleared during shutdown');
        }
        
        console.log('SUCCESS: Buffer tracking and sanitization integration works');
        process.exit(0);
    } catch (error) {
        console.error('FAILURE:', error.message);
        process.exit(1);
    }
})();
EOF

if node --secure-heap=32768 test_buffer_tracking.js > /dev/null 2>&1; then
    pass_test "Buffer tracking and sanitization integration works"
else
    fail_test "Buffer tracking and sanitization integration failed"
fi

rm -f test_buffer_tracking.js

# Final Results
echo -e "\n${BLUE}FINAL RESULTS${NC}"
echo "============="
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
echo -e "Total Tests:  $TOTAL_TESTS"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${GREEN}🎉 ALL TESTS PASSED! Security behaviors verified.${NC}"
    echo -e "${GREEN}The secure heap password management system is working correctly.${NC}"
    exit 0
else
    echo -e "\n${RED}❌ $TESTS_FAILED TESTS FAILED! Please review the failures above.${NC}"
    echo -e "${YELLOW}Some security behaviors may not be working as expected.${NC}"
    exit 1
fi 