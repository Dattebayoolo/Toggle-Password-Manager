/**
 * Toggle Password Manager - Persistent IndexedDB Storage Engine
 * Stores encrypted vault items, cryptographic salts, and local preferences.
 */

import { CryptoEngine } from './crypto.js';

export class StorageEngine {
  static DB_NAME = 'ToggleVaultDB';
  static DB_VERSION = 1;

  static async getDB() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.DB_NAME, this.DB_VERSION);

      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains('vault_meta')) {
          db.createObjectStore('vault_meta', { keyPath: 'id' });
        }
        if (!db.objectStoreNames.contains('vault_data')) {
          db.createObjectStore('vault_data', { keyPath: 'id' });
        }
        if (!db.objectStoreNames.contains('preferences')) {
          db.createObjectStore('preferences', { keyPath: 'id' });
        }
      };

      request.onsuccess = (event) => resolve(event.target.result);
      request.onerror = (event) => reject(event.target.error);
    });
  }

  /**
   * Check if user has already configured a vault
   */
  static async isInitialized() {
    try {
      const db = await this.getDB();
      return new Promise((resolve) => {
        const tx = db.transaction('vault_meta', 'readonly');
        const store = tx.objectStore('vault_meta');
        const req = store.get('meta');
        req.onsuccess = () => resolve(!!req.result);
        req.onerror = () => resolve(false);
      });
    } catch (e) {
      return false;
    }
  }

  /**
   * Initialize a new vault with master password and recovery phrase
   */
  static async initializeVault(masterPassword, recoveryPhrase) {
    const salt = CryptoEngine.getRandomBytes(CryptoEngine.SALT_LENGTH);
    const saltHex = CryptoEngine.bufferToHex(salt);

    // Verifier hash used to confirm password correctness without decrypting entire payload
    const verifierHash = await CryptoEngine.hashString(masterPassword, saltHex);
    const recoveryHash = await CryptoEngine.hashString(recoveryPhrase, saltHex);

    const key = await CryptoEngine.deriveKey(masterPassword, salt);
    
    // Initial empty vault array
    const emptyVault = [];
    const encrypted = await CryptoEngine.encrypt(JSON.stringify(emptyVault), key);
    const encryptedRecoveryPhrase = await CryptoEngine.encrypt(recoveryPhrase, key);

    const db = await this.getDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(['vault_meta', 'vault_data', 'preferences'], 'readwrite');
      
      tx.objectStore('vault_meta').put({
        id: 'meta',
        saltHex: saltHex,
        verifierHash: verifierHash,
        recoveryHash: recoveryHash,
        encryptedRecoveryPhrase: encryptedRecoveryPhrase,
        createdAt: new Date().toISOString(),
        version: 1
      });

      tx.objectStore('vault_data').put({
        id: 'vault_payload',
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        lastUpdated: new Date().toISOString()
      });

      tx.objectStore('preferences').put({
        id: 'prefs',
        autoLockMinutes: 5,
        theme: 'dark',
        autoClearClipboardSec: 30
      });

      tx.oncomplete = () => resolve({ key, saltHex });
      tx.onerror = (e) => reject(e.target.error);
    });
  }

  /**
   * Validate master password and derive working key
   */
  static async unlockVault(masterPassword) {
    const db = await this.getDB();
    const meta = await new Promise((resolve, reject) => {
      const tx = db.transaction('vault_meta', 'readonly');
      const req = tx.objectStore('vault_meta').get('meta');
      req.onsuccess = () => resolve(req.result);
      req.onerror = (e) => reject(e.target.error);
    });

    if (!meta) {
      throw new Error('Vault not found.');
    }

    const computedHash = await CryptoEngine.hashString(masterPassword, meta.saltHex);
    if (computedHash !== meta.verifierHash) {
      throw new Error('Incorrect Master Password');
    }

    const salt = CryptoEngine.hexToBuffer(meta.saltHex);
    const key = await CryptoEngine.deriveKey(masterPassword, salt);
    return key;
  }

  /**
   * Unlock with Recovery Phrase
   */
  static async unlockWithRecovery(recoveryPhrase, newMasterPassword) {
    const db = await this.getDB();
    const meta = await new Promise((resolve, reject) => {
      const tx = db.transaction('vault_meta', 'readonly');
      const req = tx.objectStore('vault_meta').get('meta');
      req.onsuccess = () => resolve(req.result);
      req.onerror = (e) => reject(e.target.error);
    });

    if (!meta) throw new Error('Vault not initialized');

    const cleanPhrase = recoveryPhrase.trim().toLowerCase().replace(/\s+/g, ' ');
    const computedRecoveryHash = await CryptoEngine.hashString(cleanPhrase, meta.saltHex);

    if (computedRecoveryHash !== meta.recoveryHash) {
      throw new Error('Invalid Recovery Phrase');
    }

    // Generate new master password credentials
    const newSalt = CryptoEngine.getRandomBytes(CryptoEngine.SALT_LENGTH);
    const newSaltHex = CryptoEngine.bufferToHex(newSalt);
    const newVerifierHash = await CryptoEngine.hashString(newMasterPassword, newSaltHex);
    const newRecoveryHash = await CryptoEngine.hashString(cleanPhrase, newSaltHex);

    const newKey = await CryptoEngine.deriveKey(newMasterPassword, newSalt);

    // Load existing data with old key isn't possible directly from recovery without saving recovery encrypted key or reset.
    // For local security best-practice: if user lost master password, prompt to re-encrypt or start fresh.
    // Here we update meta with new master password:
    await new Promise((resolve, reject) => {
      const tx = db.transaction(['vault_meta'], 'readwrite');
      meta.saltHex = newSaltHex;
      meta.verifierHash = newVerifierHash;
      meta.recoveryHash = newRecoveryHash;
      tx.objectStore('vault_meta').put(meta);
      tx.oncomplete = () => resolve();
      tx.onerror = (e) => reject(e.target.error);
    });

    return newKey;
  }

  /**
   * Save items into encrypted vault
   */
  static async saveVaultItems(items, key) {
    const encrypted = await CryptoEngine.encrypt(JSON.stringify(items), key);
    const db = await this.getDB();

    return new Promise((resolve, reject) => {
      const tx = db.transaction('vault_data', 'readwrite');
      tx.objectStore('vault_data').put({
        id: 'vault_payload',
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        lastUpdated: new Date().toISOString()
      });
      tx.oncomplete = () => resolve();
      tx.onerror = (e) => reject(e.target.error);
    });
  }

  /**
   * Load and decrypt items from vault
   */
  static async loadVaultItems(key) {
    const db = await this.getDB();
    const payload = await new Promise((resolve, reject) => {
      const tx = db.transaction('vault_data', 'readonly');
      const req = tx.objectStore('vault_data').get('vault_payload');
      req.onsuccess = () => resolve(req.result);
      req.onerror = (e) => reject(e.target.error);
    });

    if (!payload) return [];

    const jsonString = await CryptoEngine.decrypt(payload.ciphertext, payload.iv, key);
    return JSON.parse(jsonString || '[]');
  }

  /**
   * Get user preferences
   */
  static async getPreferences() {
    try {
      const db = await this.getDB();
      return new Promise((resolve) => {
        const tx = db.transaction('preferences', 'readonly');
        const req = tx.objectStore('preferences').get('prefs');
        req.onsuccess = () => resolve(req.result || { autoLockMinutes: 5, theme: 'dark', autoClearClipboardSec: 30 });
        req.onerror = () => resolve({ autoLockMinutes: 5, theme: 'dark', autoClearClipboardSec: 30 });
      });
    } catch {
      return { autoLockMinutes: 5, theme: 'dark', autoClearClipboardSec: 30 };
    }
  }

  /**
   * Save user preferences
   */
  static async savePreferences(prefs) {
    const db = await this.getDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('preferences', 'readwrite');
      tx.objectStore('preferences').put({ id: 'prefs', ...prefs });
      tx.oncomplete = () => resolve();
      tx.onerror = (e) => reject(e.target.error);
    });
  }

  /**
   * Retrieve vault metadata (creation date, salts, verifiers)
   */
  static async getVaultMeta() {
    try {
      const db = await this.getDB();
      return new Promise((resolve) => {
        const tx = db.transaction('vault_meta', 'readonly');
        const req = tx.objectStore('vault_meta').get('meta');
        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => resolve(null);
      });
    } catch {
      return null;
    }
  }

  /**
   * Save biometric platform credential metadata & wrapped vault key
   */
  static async saveBiometricData(credentialId, wrappedPayload) {
    const db = await this.getDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('vault_meta', 'readwrite');
      tx.objectStore('vault_meta').put({
        id: 'biometric_auth',
        credentialId: credentialId,
        ciphertext: wrappedPayload.ciphertext,
        iv: wrappedPayload.iv,
        saltHex: wrappedPayload.saltHex,
        enabled: true,
        updatedAt: new Date().toISOString()
      });
      tx.oncomplete = () => resolve();
      tx.onerror = (e) => reject(e.target.error);
    });
  }

  /**
   * Retrieve biometric platform credential metadata
   */
  static async getBiometricData() {
    try {
      const db = await this.getDB();
      return new Promise((resolve, reject) => {
        const tx = db.transaction('vault_meta', 'readonly');
        const req = tx.objectStore('vault_meta').get('biometric_auth');
        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => resolve(null);
      });
    } catch {
      return null;
    }
  }

  /**
   * Remove biometric platform credential metadata
   */
  static async removeBiometricData() {
    try {
      const db = await this.getDB();
      return new Promise((resolve, reject) => {
        const tx = db.transaction('vault_meta', 'readwrite');
        const req = tx.objectStore('vault_meta').delete('biometric_auth');
        req.onsuccess = () => resolve();
        req.onerror = () => resolve();
      });
    } catch {
      return;
    }
  }

  /**
   * Erase all local vault data completely (Factory Reset)
   */
  static async wipeAllData() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.deleteDatabase(this.DB_NAME);
      req.onsuccess = () => resolve();
      req.onerror = (e) => reject(e.target.error);
      req.onblocked = () => resolve();
    });
  }
}
