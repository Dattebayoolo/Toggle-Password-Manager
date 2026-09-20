/**
 * Toggle Password Manager - Two-Factor Authentication (TOTP) Engine
 * Implements RFC 6238 (TOTP) and RFC 4226 (HOTP) using standard Web Crypto API.
 */

// Cache crypto reference once at module level — avoids repeated typeof checks on every call
const _crypto = globalThis.crypto ?? window.crypto;

export class TOTPEngine {
  static DEFAULT_PERIOD = 30;
  static DEFAULT_DIGITS = 6;
  static BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  /**
   * Precomputed O(1) Base32 character lookup table.
   * Replaces the O(32) indexOf call in base32ToBuffer per character.
   */
  static #base32Lookup = (() => {
    const table = new Uint8Array(256).fill(0xff); // 0xff = invalid
    const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    for (let i = 0; i < alpha.length; i++) {
      table[alpha.charCodeAt(i)] = i;
    }
    return table;
  })();

  /**
   * Decodes a RFC 4648 Base32 string into a Uint8Array byte buffer.
   * Uses a precomputed lookup table for O(1) character resolution.
   */
  static base32ToBuffer(base32Str) {
    if (!base32Str || typeof base32Str !== 'string') {
      throw new Error('Invalid Base32 input');
    }

    // Clean whitespace, dashes, and padding
    const clean = base32Str.toUpperCase().replace(/[\s\-=]/g, '');
    if (clean.length === 0) {
      throw new Error('Base32 secret is empty');
    }

    let bits = 0;
    let value = 0;
    const output = [];

    for (let i = 0; i < clean.length; i++) {
      const idx = this.#base32Lookup[clean.charCodeAt(i)];
      if (idx === 0xff) {
        throw new Error(`Invalid character "${clean[i]}" in Base32 secret`);
      }

      value = (value << 5) | idx;
      bits += 5;

      if (bits >= 8) {
        output.push((value >>> (bits - 8)) & 255);
        bits -= 8;
      }
    }

    return new Uint8Array(output);
  }

  /**
   * Parses standard otpauth:// URI into its component parameters
   * e.g. otpauth://totp/Google:alice@gmail.com?secret=JBSWY3DPEHPK3PXP&issuer=Google
   */
  static parseOTPAuth(uri) {
    if (!uri || typeof uri !== 'string') return null;
    const trimmed = uri.trim();

    if (!trimmed.toLowerCase().startsWith('otpauth://')) {
      // Treat as raw Base32 secret key
      return {
        type: 'totp',
        secret: trimmed.replace(/\s+/g, '').toUpperCase(),
        issuer: '',
        account: '',
        digits: this.DEFAULT_DIGITS,
        period: this.DEFAULT_PERIOD,
        algorithm: 'SHA-1'
      };
    }

    try {
      const url = new URL(trimmed);
      const params = url.searchParams;

      const secret = (params.get('secret') || '').replace(/\s+/g, '').toUpperCase();
      if (!secret) return null;

      const digits = parseInt(params.get('digits') || `${this.DEFAULT_DIGITS}`, 10);
      const period = parseInt(params.get('period') || `${this.DEFAULT_PERIOD}`, 10);
      const algorithm = (params.get('algorithm') || 'SHA-1').toUpperCase();
      const issuer = params.get('issuer') || '';

      // Path format is usually /totp/Issuer:account or /totp/account
      let account = decodeURIComponent(url.pathname.replace(/^\/[^/]+\//, ''));
      if (account.includes(':')) {
        const parts = account.split(':');
        account = parts.slice(1).join(':').trim();
      }

      return {
        type: url.host.toLowerCase() || 'totp',
        secret,
        issuer,
        account,
        digits: isNaN(digits) ? this.DEFAULT_DIGITS : digits,
        period: isNaN(period) ? this.DEFAULT_PERIOD : period,
        algorithm
      };
    } catch {
      return null;
    }
  }

  /**
   * Generates a standard RFC 6238 TOTP code (e.g. "492019")
   */
  static async generateTOTP(secretInput, timestamp = Date.now(), period = this.DEFAULT_PERIOD, digits = this.DEFAULT_DIGITS) {
    // If input is an otpauth URI, extract the secret and parameters
    let secret = secretInput;
    if (typeof secretInput === 'string' && secretInput.trim().toLowerCase().startsWith('otpauth://')) {
      const parsed = this.parseOTPAuth(secretInput);
      if (parsed && parsed.secret) {
        secret = parsed.secret;
        period = parsed.period || period;
        digits = parsed.digits || digits;
      }
    }

    const keyBytes = this.base32ToBuffer(secret);
    const epochSeconds = Math.floor(timestamp / 1000);
    const counter = Math.floor(epochSeconds / period);

    // Convert 64-bit integer counter to 8-byte big-endian ArrayBuffer
    const counterBuffer = new ArrayBuffer(8);
    const counterView = new DataView(counterBuffer);
    counterView.setUint32(0, Math.floor(counter / 0x100000000), false); // High 32 bits
    counterView.setUint32(4, counter >>> 0, false);                      // Low 32 bits

    // Import HMAC key
    const hmacKey = await _crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: { name: 'SHA-1' } },
      false,
      ['sign']
    );

    // Calculate HMAC-SHA-1
    const hmacResult = await _crypto.subtle.sign('HMAC', hmacKey, counterBuffer);
    const hmacBytes = new Uint8Array(hmacResult);

    // RFC 4226 Dynamic Truncation
    const offset = hmacBytes[hmacBytes.length - 1] & 0x0f;
    const binary =
      ((hmacBytes[offset] & 0x7f) << 24) |
      ((hmacBytes[offset + 1] & 0xff) << 16) |
      ((hmacBytes[offset + 2] & 0xff) << 8) |
      (hmacBytes[offset + 3] & 0xff);

    // Use ** operator instead of Math.pow for integer exponentiation
    const modulo = 10 ** digits;
    const token = binary % modulo;

    return token.toString().padStart(digits, '0');
  }

  /**
   * Returns real-time countdown info for the current TOTP cycle
   */
  static getCountdown(timestamp = Date.now(), period = this.DEFAULT_PERIOD) {
    const epochSeconds = Math.floor(timestamp / 1000);
    const secondsRemaining = period - (epochSeconds % period);
    const ratio = secondsRemaining / period;

    let status = 'safe';
    if (secondsRemaining <= 5) {
      status = 'danger';
    } else if (secondsRemaining <= 10) {
      status = 'warning';
    }

    return {
      secondsRemaining,
      period,
      ratio,
      status
    };
  }

  /**
   * Validates if a secret or URI string is syntactically valid
   */
  static isValid(input) {
    if (!input || typeof input !== 'string') return false;
    try {
      let secret = input.trim();
      if (secret.toLowerCase().startsWith('otpauth://')) {
        const parsed = this.parseOTPAuth(secret);
        if (!parsed || !parsed.secret) return false;
        secret = parsed.secret;
      }
      const buffer = this.base32ToBuffer(secret);
      return buffer.byteLength >= 4; // minimum sensible HMAC key length
    } catch {
      return false;
    }
  }
}
