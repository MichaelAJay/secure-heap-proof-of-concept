const SecureHeapProcessManager = require('./secure-heap-process-manager');

(async() => {
    const manager = new SecureHeapProcessManager();

    const iterations = 10;
    const timings = [];

    for (let i = 0; i < iterations; i++) {
        const start = Date.now();
        const secureHeapUsed = await manager.handleRequest('checkSecureHeapUsage');
        const decryptedPassword = await manager.handleRequest('decryptPassword');
        const end = Date.now();

        timings.push(end - start);
        console.log('secureHeapUsed is buffer', Buffer.isBuffer(secureHeapUsed), secureHeapUsed);
        console.log('decryptedPassword is buffer', Buffer.isBuffer(decryptedPassword), decryptedPassword.toString());
    }

    manager.stop();
    console.log(timings);
})()