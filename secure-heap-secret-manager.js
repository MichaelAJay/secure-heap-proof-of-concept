'use strict';

const crypto = require('crypto');

class SecureHeapSecretManager {
  constructor() {
    this.rsaPrivateKey = null;
    this.rsaPublicKey = null;
    this.crypto = {
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    };
    this.encryptedPassword = null;
  }

  getSecureHeapUsage() {
    return crypto.secureHeapUsed();
  }

  /**
   * Generates RSA keypair and stores private key in secure heap
   * @returns {Promise<void>}
   */
  async generateSecureKeypair() {
    // Ensure secure heap allocation settles before getting secure heap allocation baseline
    await new Promise(resolve => setTimeout(resolve, 500));

    const { used: allocationBefore } = crypto.secureHeapUsed();

    // Validate allocation measurement is a valid number
    if (typeof allocationBefore !== 'number' || allocationBefore < 0) {
      throw new Error(`Invalid secure heap allocation measurement: ${allocationBefore}`);
    }

    // Generate RSA key pair - private key bignums are stored in secure heap (see https://docs.openssl.org/3.0/man3/OPENSSL_secure_malloc/#description)
    const keypair = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048
    });
    if (!keypair || !keypair.privateKey || !keypair.publicKey) {
      console.error('CRITICAL: RSA key generation failed');
      process.exit(1);
    }
    this.rsaPrivateKey = keypair.privateKey;
    this.rsaPublicKey = keypair.publicKey;

    // Ensure secure heap allocation settles before getting secure heap allocation after key creation
    await new Promise(resolve => setTimeout(resolve, 500));
    const { used: allocationAfter } = crypto.secureHeapUsed();

    // Validate allocation measurement is a valid number
    if (typeof allocationAfter !== 'number' || allocationAfter < 0) {
      throw new Error(`Invalid secure heap allocation measurement: ${allocationAfter}`);
    }

    // Ensure we actually allocated secure heap memory for the keypair
    if (allocationAfter <= allocationBefore) {
      throw new Error(`RSA keypair may not be stored in secure heap. Before: ${allocationBefore}, After: ${allocationAfter}`);
    }

    this.secureHeapAllocationBaseline = allocationAfter - allocationBefore;
  }

  /**
     * Used to determine if RSA keys still in secure heap
     * @throws {Error} If current allocation is less than baseline
     */
  verifyExpectedAllocation() {
    const { used: currentAllocation } = crypto.secureHeapUsed();

    // Validate allocation measurement is a valid number
    if (typeof currentAllocation !== 'number' || currentAllocation < 0) {
      throw new Error(`Invalid secure heap allocation measurement: ${currentAllocation}`);
    }

    // Validate baseline was properly set
    if (typeof this.secureHeapAllocationBaseline !== 'number' || this.secureHeapAllocationBaseline <= 0) {
      throw new Error(`Invalid secure heap baseline: ${this.secureHeapAllocationBaseline}`);
    }

    const isVerified = currentAllocation >= this.secureHeapAllocationBaseline;
    // @TODO maybe throwing here isn't the move
    if (!isVerified) {
      throw new Error(`Secure heap utilization expectation not met. Expected ${this.secureHeapAllocationBaseline} - Actual ${currentAllocation}`);
    }
    console.log(`Secure heap allocation check passed. Baseline: ${this.secureHeapAllocationBaseline} bytes, Actual: ${currentAllocation} bytes`);
    return isVerified;
  }

  /**
   * Reads password from stdin into a buffer and encrypts it
   * @param {string} [promptString='Enter password'] - Prompt to display to user
   * @returns {Promise<void>}
   */
  async readInPassword(promptString = 'Enter password') {
    const { BufferIO } = require('./bufferio.js');
    const bufferIO = new BufferIO();

    let passwordBuffer;
    try {
      // Get password directly into buffer - no string creation
      passwordBuffer = await bufferIO.readIn(promptString);

      // Immediately encrypt the buffer - is automatically overwritten by setEncryptedPassword
      this.#setEncryptedPassword(passwordBuffer);
    } catch (err) {
      // BufferIO handles its own cleanup, but ensure any local buffer is cleared
      if (passwordBuffer) {
        crypto.randomFillSync(passwordBuffer);
      }
      throw err;
    } finally {
      if (global.gc) {
        global.gc();
      }
    }
  }

  /**
   * Sets the encrypted password from a buffer. The buffer will be immediately
   * overwritten with random data after encryption to prevent memory leakage.
   *
   * SECURITY REQUIREMENTS:
   * - passwordBuffer MUST be a Buffer (not a string)
   * - passwordBuffer will be MUTATED (overwritten) by this method
   * - passwordBuffer MUST NOT be used after calling this method
   *
   * @private
   * @param {Buffer} passwordBuffer - Buffer containing the password (will be overwritten)
   * @returns {void}
   * @throws {Error} If passwordBuffer is not a Buffer
   */
  #setEncryptedPassword(passwordBuffer) {
    // Enforce buffer-only input
    if (!Buffer.isBuffer(passwordBuffer)) {
      throw new Error('SECURITY ERROR: setEncryptedPassword requires a Buffer, not a string or other type');
    }

    try {
      // Encrypt the password
      const encryptedPassword = crypto.publicEncrypt({
        key: this.rsaPublicKey,
        ...this.crypto
      }, passwordBuffer);

      // Store the encrypted result
      this.encryptedPassword = encryptedPassword;
    } finally {
      // IMMEDIATELY overwrite the input buffer to prevent memory leakage
      crypto.randomFillSync(passwordBuffer);
    }
  }

  /**
   * Decrypts password
   *
   * SECURITY REQUIREMENTS:
   * - Output MUST be randomFilled (crypto.randomFillSync) as soon as possible after use
   * 
   * @returns {Buffer} Decrypted password as a Buffer
   */
  getDecryptedPassword() {
    const decryptedPassword = crypto.privateDecrypt({
      key: this.rsaPrivateKey,
      ...this.crypto
    }, this.encryptedPassword);
    return decryptedPassword;
  }
}

module.exports = { SecureHeapSecretManager };

/**
 * Clean-up process (for buffers)
 * crypto.randomFillSync(buffer) - Buffer.fill(0) execution may be skipped in certain optimization scenarios
 */
