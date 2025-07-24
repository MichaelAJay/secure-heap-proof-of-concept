const crypto = require('crypto');

process.on('message', async (msg) => {
    const outboundMsg = { type: `${msg.type}:result`, id: msg.id };
    try {
        switch (msg.type) {
            case 'checkSecureHeapUsage':
                const secureHeapUsed = crypto.secureHeapUsed();
                outboundMsg.data = secureHeapUsed;
                break;
            case 'decryptPassword':
                const decryptedPassword = Buffer.from('password:decrypted');
                outboundMsg.data = decryptedPassword;
                break;
            default:
                console.error('Unknown message type:', msg.type);
        }
    } catch (err) {
        outboundMsg.type = `${msg.type}:error`;
        outboundMsg.error = { message: err.message, stack: err.stack };
    }
    process.send(outboundMsg);
})