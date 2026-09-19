/**
 * Toggle Password Manager - Cryptographic Core Engine
 * Standard: AES-256-GCM with PBKDF2 (SHA-256, 600,000 iterations)
 * Zero-knowledge, zero-telemetry client-side encryption.
 */

export class CryptoEngine {
  static PBKDF2_ITERATIONS = 600000;
  static SALT_LENGTH = 16; // 128 bits
  static IV_LENGTH = 12;   // 96 bits for AES-GCM

  /**
   * Generates cryptographically secure random bytes
   */
  static getRandomBytes(length) {
    const bytes = new Uint8Array(length);
    const cryptoObj = typeof crypto !== 'undefined' ? crypto : window.crypto;
    cryptoObj.getRandomValues(bytes);
    return bytes;
  }

  /**
   * Converts Uint8Array to Hex string
   */
  static bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Converts Hex string to Uint8Array
   */
  static hexToBuffer(hexString) {
    const match = hexString.match(/.{1,2}/g);
    return new Uint8Array(match ? match.map(byte => parseInt(byte, 16)) : []);
  }

  /**
   * Converts Uint8Array to Base64
   */
  static bufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return typeof btoa !== 'undefined' ? btoa(binary) : Buffer.from(binary, 'binary').toString('base64');
  }

  /**
   * Converts Base64 to Uint8Array
   */
  static base64ToBuffer(base64) {
    const binary = typeof atob !== 'undefined' ? atob(base64) : Buffer.from(base64, 'base64').toString('binary');
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /**
   * Derives an AES-GCM CryptoKey from a master password and salt using PBKDF2
   */
  static async deriveKey(password, saltUint8, iterations = this.PBKDF2_ITERATIONS) {
    const cryptoObj = typeof crypto !== 'undefined' ? crypto : window.crypto;
    const enc = new TextEncoder();
    const passwordKey = await cryptoObj.subtle.importKey(
      'raw',
      enc.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    return await cryptoObj.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltUint8,
        iterations: iterations,
        hash: 'SHA-256'
      },
      passwordKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Generates a SHA-256 hash for verifying master password without storing raw text
   */
  static async hashString(input, saltHex = '') {
    const cryptoObj = typeof crypto !== 'undefined' ? crypto : window.crypto;
    const enc = new TextEncoder();
    const data = enc.encode(input + saltHex);
    const hash = await cryptoObj.subtle.digest('SHA-256', data);
    return this.bufferToHex(hash);
  }

  /**
   * Encrypts plaintext string using AES-256-GCM
   * Returns: { ciphertext: base64, iv: hex }
   */
  static async encrypt(plaintext, key) {
    const cryptoObj = typeof crypto !== 'undefined' ? crypto : window.crypto;
    const iv = this.getRandomBytes(this.IV_LENGTH);
    const enc = new TextEncoder();
    const encodedData = enc.encode(plaintext);

    const ciphertextBuffer = await cryptoObj.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      key,
      encodedData
    );

    return {
      ciphertext: this.bufferToBase64(ciphertextBuffer),
      iv: this.bufferToHex(iv)
    };
  }

  /**
   * Decrypts ciphertext using AES-256-GCM
   */
  static async decrypt(ciphertextBase64, ivHex, key) {
    try {
      const cryptoObj = typeof crypto !== 'undefined' ? crypto : window.crypto;
      const ciphertextBuffer = this.base64ToBuffer(ciphertextBase64);
      const iv = this.hexToBuffer(ivHex);

      const decryptedBuffer = await cryptoObj.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv
        },
        key,
        ciphertextBuffer
      );

      const dec = new TextDecoder();
      return dec.decode(decryptedBuffer);
    } catch (err) {
      throw new Error('Decryption failed: Invalid master password or corrupted payload');
    }
  }

  /**
   * Generates a 12-word Emergency Recovery Phrase
   */
  static generateRecoveryPhrase() {
    const wordList = [
      'abandon', 'ability', 'absent', 'absorb', 'abstract', 'access', 'accident', 'account',
      'action', 'active', 'actor', 'adapt', 'advance', 'afford', 'agent', 'agree', 'ahead',
      'alarm', 'album', 'alert', 'alien', 'allied', 'alpha', 'always', 'amaze', 'amber',
      'anchor', 'ancient', 'angel', 'angry', 'animal', 'ankle', 'announce', 'annual', 'answer',
      'antenna', 'antique', 'anxiety', 'apart', 'apology', 'appeal', 'apple', 'approve', 'april',
      'arcade', 'arctic', 'arena', 'argue', 'armor', 'aroma', 'arrange', 'arrow', 'aspect',
      'assault', 'asset', 'assist', 'assume', 'athlete', 'atlas', 'atom', 'attack', 'attend',
      'attitude', 'auction', 'audio', 'audit', 'august', 'aunt', 'author', 'auto', 'autumn',
      'avatar', 'average', 'avocado', 'avoid', 'awake', 'aware', 'awesome', 'axis', 'baby',
      'bachelor', 'bacon', 'badge', 'bagel', 'balance', 'balcony', 'bamboo', 'banana', 'banner',
      'barbell', 'barely', 'bargain', 'barrel', 'barrier', 'basket', 'battery', 'battle', 'beach',
      'beacon', 'beam', 'beauty', 'because', 'become', 'before', 'begin', 'behave', 'behind',
      'belief', 'belong', 'beloved', 'bench', 'benefit', 'berry', 'beyond', 'bicycle', 'binary',
      'biology', 'bird', 'birth', 'biscuit', 'black', 'blade', 'blame', 'blanket', 'blaster',
      'bleach', 'blend', 'bless', 'blind', 'block', 'blonde', 'bloom', 'blossom', 'blueberry'
    ];

    const phraseWords = [];
    const randomBytes = this.getRandomBytes(12);
    for (let i = 0; i < 12; i++) {
      const index = randomBytes[i] % wordList.length;
      phraseWords.push(wordList[index]);
    }
    return phraseWords.join(' ');
  }
}
