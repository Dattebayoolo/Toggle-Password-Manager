/**
 * Toggle Password Manager - Cryptographic Core Engine
 * Standard: AES-256-GCM with PBKDF2 (SHA-256, 600,000 iterations)
 * Zero-knowledge, zero-telemetry client-side encryption.
 */

// Cache crypto reference once at module level — avoids repeated typeof checks on every call
const _crypto = globalThis.crypto ?? window.crypto;

export class CryptoEngine {
  static PBKDF2_ITERATIONS = 600000;
  static SALT_LENGTH = 16; // 128 bits
  static IV_LENGTH = 12;   // 96 bits for AES-GCM

  /**
   * Generates cryptographically secure random bytes
   */
  static getRandomBytes(length) {
    const bytes = new Uint8Array(length);
    _crypto.getRandomValues(bytes);
    return bytes;
  }

  /**
   * Converts Uint8Array / ArrayBuffer to Hex string
   * Avoids Array.from() intermediate allocation — iterates Uint8Array directly.
   */
  static bufferToHex(buffer) {
    const bytes = new Uint8Array(buffer);
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, '0');
    }
    return hex;
  }

  /**
   * Converts Hex string to Uint8Array
   */
  static hexToBuffer(hexString) {
    const match = hexString.match(/.{1,2}/g);
    return new Uint8Array(match ? match.map(byte => parseInt(byte, 16)) : []);
  }

  /**
   * Converts Uint8Array / ArrayBuffer to Base64
   * Uses chunked spread to avoid call-stack limits on large buffers while
   * still avoiding the slow character-by-character string concatenation.
   */
  static bufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    const CHUNK = 8192;
    let binary = '';
    for (let i = 0; i < bytes.length; i += CHUNK) {
      binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
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
   * Derives an AES-GCM CryptoKey from a master password and salt using PBKDF2.
   * Defaults to non-extractable for in-memory session keys — pass extractable=true
   * only when you need to export the key (e.g. exportKeyRaw).
   */
  static async deriveKey(password, saltUint8, iterations = this.PBKDF2_ITERATIONS, extractable = false) {
    const enc = new TextEncoder();
    const passwordKey = await _crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    return await _crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltUint8,
        iterations: iterations,
        hash: 'SHA-256'
      },
      passwordKey,
      { name: 'AES-GCM', length: 256 },
      extractable,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Exports an extractable CryptoKey to Base64 raw key bytes
   */
  static async exportKeyRaw(key) {
    const raw = await _crypto.subtle.exportKey('raw', key);
    return this.bufferToBase64(raw);
  }

  /**
   * Imports a raw Base64 key into an AES-GCM CryptoKey
   */
  static async importKeyRaw(base64Raw, extractable = true) {
    const buffer = this.base64ToBuffer(base64Raw);
    return await _crypto.subtle.importKey(
      'raw',
      buffer,
      { name: 'AES-GCM', length: 256 },
      extractable,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Generates a SHA-1 hash (uppercase hex) for k-Anonymity HaveIBeenPwned queries
   */
  static async hashSHA1(input) {
    const enc = new TextEncoder();
    const data = enc.encode(input);
    const hash = await _crypto.subtle.digest('SHA-1', data);
    return this.bufferToHex(hash).toUpperCase();
  }

  /**
   * Generates a SHA-256 hash for verifying master password without storing raw text
   */
  static async hashString(input, saltHex = '') {
    const enc = new TextEncoder();
    const data = enc.encode(input + saltHex);
    const hash = await _crypto.subtle.digest('SHA-256', data);
    return this.bufferToHex(hash);
  }

  /**
   * Encrypts plaintext string using AES-256-GCM
   * Returns: { ciphertext: base64, iv: hex }
   */
  static async encrypt(plaintext, key) {
    const iv = this.getRandomBytes(this.IV_LENGTH);
    const enc = new TextEncoder();
    const encodedData = enc.encode(plaintext);

    const ciphertextBuffer = await _crypto.subtle.encrypt(
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
      const ciphertextBuffer = this.base64ToBuffer(ciphertextBase64);
      const iv = this.hexToBuffer(ivHex);

      const decryptedBuffer = await _crypto.subtle.decrypt(
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
   * Generates a 12-word Emergency Recovery Phrase.
   * Uses Uint16Array to minimise modulo bias across the ~130-word list.
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

    // Uint16Array (0–65535 range) minimises modulo bias for lists ≤ 256 entries.
    // Rejection-sample any value that would cause bias.
    const MAX_UNBIASED = Math.floor(65536 / wordList.length) * wordList.length;
    const phraseWords = [];
    while (phraseWords.length < 12) {
      const buf = new Uint16Array(12);
      _crypto.getRandomValues(buf);
      for (let i = 0; i < buf.length && phraseWords.length < 12; i++) {
        if (buf[i] < MAX_UNBIASED) {
          phraseWords.push(wordList[buf[i] % wordList.length]);
        }
      }
    }
    return phraseWords.join(' ');
  }
}
