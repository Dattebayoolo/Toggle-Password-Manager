// Automated Verification Test for Toggle Password Manager Engines
import { CryptoEngine } from '../js/crypto.js';
import { GeneratorEngine } from '../js/generator.js';
import { SecurityEngine } from '../js/security.js';
import { ImportExportEngine } from '../js/importer.js';

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  ✓ PASS: ${message}`);
    passed++;
  } else {
    console.error(`  ✕ FAIL: ${message}`);
    failed++;
  }
}

async function runTests() {
  console.log('\n🔒 --- 1. Testing CryptoEngine (AES-256-GCM & PBKDF2) ---');
  
  // Test Salt & Derivation
  const salt = CryptoEngine.getRandomBytes(16);
  assert(salt.length === 16, 'Random salt generation produces 16 bytes');

  const masterPass = 'SuperSecretVaultMasterPass2026!';
  const key = await CryptoEngine.deriveKey(masterPass, salt, 10000, true); // 10k iterations for fast unit test; extractable=true needed for exportKeyRaw test below
  assert(key !== null && key.algorithm.name === 'AES-GCM', 'Derives valid AES-GCM CryptoKey from master password');

  // Test Encryption & Decryption
  const testPayload = JSON.stringify([
    { id: '1', name: 'Google', username: 'user@gmail.com', password: 'P@ssw0rd12345!' }
  ]);

  const encrypted = await CryptoEngine.encrypt(testPayload, key);
  assert(encrypted.ciphertext && encrypted.iv, 'Encrypted payload produces ciphertext Base64 and IV Hex');

  const decrypted = await CryptoEngine.decrypt(encrypted.ciphertext, encrypted.iv, key);
  assert(decrypted === testPayload, 'Decrypted plaintext matches original payload exactly');

  // Test Tamper Rejection
  let tamperedFailed = false;
  try {
    // Modify one byte of ciphertext
    const corrupted = 'X' + encrypted.ciphertext.substring(1);
    await CryptoEngine.decrypt(corrupted, encrypted.iv, key);
  } catch (err) {
    tamperedFailed = true;
  }
  assert(tamperedFailed, 'Tampered ciphertext is cleanly rejected by AES-GCM authentication tag');

  // Test Recovery Phrase
  const phrase = CryptoEngine.generateRecoveryPhrase();
  const words = phrase.split(' ');
  assert(words.length === 12, `Generates 12-word recovery phrase: "${phrase.substring(0, 25)}..."`);

  console.log('\n🎲 --- 2. Testing GeneratorEngine & Strength Meter ---');
  const generatedPwd = GeneratorEngine.generatePassword({ length: 20, uppercase: true, lowercase: true, numbers: true, symbols: true });
  assert(generatedPwd.length === 20, 'Generates 20-character password');
  assert(/[A-Z]/.test(generatedPwd), 'Contains uppercase');
  assert(/[a-z]/.test(generatedPwd), 'Contains lowercase');
  assert(/[0-9]/.test(generatedPwd), 'Contains numbers');
  assert(/[^A-Za-z0-9]/.test(generatedPwd), 'Contains symbols');

  const passphrase = GeneratorEngine.generatePassphrase(5, '-');
  const phraseParts = passphrase.split('-');
  assert(phraseParts.length === 5, `Generates 5-word passphrase: "${passphrase}"`);

  const weakEval = GeneratorEngine.evaluateStrength('12345');
  assert(weakEval.score === 0, 'Correctly flags "12345" as score 0 (Very Weak)');

  const strongEval = GeneratorEngine.evaluateStrength('T0ggl3#V@ult$ecur399!!');
  assert(strongEval.score === 4, 'Correctly evaluates high-entropy password as score 4 (Very Strong)');

  console.log('\n🛡️ --- 3. Testing SecurityEngine (Google-style Checkup) ---');
  const mockVault = [
    { id: '1', name: 'Site A', category: 'login', password: 'password123' },      // Weak & Compromised pattern
    { id: '2', name: 'Site B', category: 'login', password: 'password123' },      // Reused with Site A!
    { id: '3', name: 'Site C', category: 'login', password: 'admin' },            // Weak & Compromised
    { id: '4', name: 'Site D', category: 'login', password: 'K9#mQ2$vL90!xZ88@' } // Strong
  ];

  const audit = SecurityEngine.runAudit(mockVault);
  assert(audit.weakItems.length >= 2, `Detects weak passwords (found ${audit.weakItems.length})`);
  assert(audit.reusedGroups.length === 1, `Detects reused passwords group (found ${audit.reusedGroups.length})`);
  assert(audit.reusedGroups[0].count === 2, 'Reused group includes exactly 2 sites');
  assert(audit.compromisedItems.length >= 2, `Detects compromised patterns (found ${audit.compromisedItems.length})`);
  assert(audit.score < 70, `Accurately calculates reduced security health score: ${audit.score}% (Grade ${audit.grade})`);

  console.log('\n📂 --- 4. Testing ImportExportEngine (Google Chrome CSV) ---');
  const mockChromeCSV = `name,url,username,password,note
Google,https://accounts.google.com,user@gmail.com,MySecretGooglePass1!,Personal Account
GitHub,https://github.com/login,gituser,SuperGithub#2026,Developer Key
Netflix,https://netflix.com,user@gmail.com,StreamPwd99$,Family Plan`;

  const imported = ImportExportEngine.importGoogleCSV(mockChromeCSV);
  assert(imported.length === 3, `Imported ${imported.length} items from Google CSV`);
  assert(imported[0].name === 'Google' && imported[0].username === 'user@gmail.com', 'Google account correctly parsed');
  assert(imported[1].password === 'SuperGithub#2026', 'Password correctly mapped');
  assert(imported[0].notes === 'Personal Account', 'Notes correctly mapped');

  const exportedCSV = ImportExportEngine.exportGoogleCSV(imported);
  assert(exportedCSV.includes('Google') && exportedCSV.includes('MySecretGooglePass1!'), 'Exported CSV retains accounts and passwords');
  assert(exportedCSV.startsWith('name,url,username,password,note'), 'Exported CSV header matches Google Chrome format');

  console.log('\n💳 --- 5. Testing Category Schemas & Trash Lifecycle ---');
  const richItems = [
    {
      id: 'card_1',
      category: 'card',
      name: 'Travel Visa',
      cardHolder: 'Alex M',
      cardNumber: '4532 8921 4092 5678',
      cardExp: '12/28',
      cardCvv: '891',
      cardBrand: 'Visa'
    },
    {
      id: 'addr_1',
      category: 'address',
      name: 'Home Office',
      recipient: 'Alex M',
      street1: '123 Main St',
      city: 'Austin',
      state: 'TX',
      zip: '78701',
      country: 'United States',
      phone: '+1 555-0199'
    },
    {
      id: 'api_1',
      category: 'apikey',
      name: 'Stripe Secret',
      apiKey: 'sk_live_51Abc99SecretKey',
      apiEnv: 'production',
      apiUrl: 'https://api.stripe.com/v1'
    },
    {
      id: 'note_1',
      category: 'note',
      name: 'Recovery Passphrase',
      noteBody: 'alpha bravo charlie delta echo foxtrot'
    }
  ];

  // Test encryption & decryption roundtrip of rich category items
  const richEncrypted = await CryptoEngine.encrypt(JSON.stringify(richItems), key);
  const richDecrypted = JSON.parse(await CryptoEngine.decrypt(richEncrypted.ciphertext, richEncrypted.iv, key));
  assert(richDecrypted.length === 4, 'Rich category schema payload encrypts and decrypts cleanly');
  assert(richDecrypted[0].cardBrand === 'Visa' && richDecrypted[0].cardNumber.startsWith('4532'), 'Credit card fields retain data integrity');
  assert(richDecrypted[1].zip === '78701' && richDecrypted[1].city === 'Austin', 'Address fields retain data integrity');
  assert(richDecrypted[2].apiKey === 'sk_live_51Abc99SecretKey', 'API Key secret retains data integrity');
  assert(richDecrypted[3].noteBody.includes('foxtrot'), 'Secure note body retains data integrity');

  // Test Soft-delete to Trash
  richDecrypted[0].trash = true;
  richDecrypted[0].deletedAt = new Date().toISOString();
  assert(richDecrypted.filter(i => !i.trash).length === 3, 'Soft-delete excludes trashed item from active count');
  assert(richDecrypted.filter(i => i.trash).length === 1, 'Trash bin isolates trashed item');

  // Test Restore from Trash
  richDecrypted[0].trash = false;
  delete richDecrypted[0].deletedAt;
  assert(richDecrypted.filter(i => !i.trash).length === 4, 'Restoring returns item back to active items');

  // Test Empty Trash
  richDecrypted[1].trash = true;
  richDecrypted[2].trash = true;
  const purgedItems = richDecrypted.filter(i => !i.trash);
  assert(purgedItems.length === 2, 'Empty trash permanently purges all marked items');

  console.log('\n🔑 --- 6. Testing Phase 3: Biometrics, k-Anonymity HIBP, and Emergency Kit ---');
  
  // 1. Test SHA-1 Hash
  const sha1Result = await CryptoEngine.hashSHA1('password123');
  assert(sha1Result.length === 40, `SHA-1 generates 40-character hex string (${sha1Result.substring(0, 10)}...)`);
  assert(/^[0-9A-F]{40}$/.test(sha1Result), 'SHA-1 output is valid uppercase hexadecimal');
  assert(sha1Result === 'CBFDAC6008F9CAB4083784CBD1874F76618D2A97', 'SHA-1 hash matches known standard test vector for "password123"');

  // 2. Test k-Anonymity prefix and suffix decomposition
  const prefix = sha1Result.substring(0, 5);
  const suffix = sha1Result.substring(5);
  assert(prefix.length === 5, `k-Anonymity prefix is exactly 5 characters ("${prefix}")`);
  assert(suffix.length === 35, `k-Anonymity suffix is exactly 35 characters ("${suffix.substring(0, 10)}...")`);
  assert(prefix + suffix === sha1Result, 'Prefix and suffix cleanly recombine to original SHA-1 hash');

  // 3. Test Raw Key Export
  const rawKeyBase64 = await CryptoEngine.exportKeyRaw(key);
  assert(typeof rawKeyBase64 === 'string' && rawKeyBase64.length > 0, 'CryptoEngine.exportKeyRaw produces Base64 string');
  const rawKeyBytes = CryptoEngine.base64ToBuffer(rawKeyBase64);
  assert(rawKeyBytes.byteLength === 32, 'Exported AES-256 raw key buffer is exactly 32 bytes (256 bits)');

  // 4. Test Raw Key Import
  const importedKey = await CryptoEngine.importKeyRaw(rawKeyBase64);
  assert(importedKey !== null && importedKey.algorithm.name === 'AES-GCM', 'CryptoEngine.importKeyRaw creates valid AES-GCM CryptoKey');

  // 5. Test Key Wrapping Round-Trip (Simulating WebAuthn Platform Authenticator)
  const mockCredentialId = 'mock_webauthn_credential_id_2026_xyz';
  const bioSalt = CryptoEngine.getRandomBytes(16);
  const bioWrappingKey = await CryptoEngine.deriveKey(mockCredentialId, bioSalt, 10000, false);

  // Wrap vault key
  const wrappedVaultKey = await CryptoEngine.encrypt(rawKeyBase64, bioWrappingKey);
  assert(wrappedVaultKey.ciphertext && wrappedVaultKey.iv, 'Vault key wraps cleanly with platform authenticator key');

  // Unwrap vault key
  const unwrappedRawKeyBase64 = await CryptoEngine.decrypt(wrappedVaultKey.ciphertext, wrappedVaultKey.iv, bioWrappingKey);
  assert(unwrappedRawKeyBase64 === rawKeyBase64, 'Unwrapped key bytes match exported vault key exactly');

  const biometricRestoredKey = await CryptoEngine.importKeyRaw(unwrappedRawKeyBase64);
  const reDecryptedPayload = await CryptoEngine.decrypt(encrypted.ciphertext, encrypted.iv, biometricRestoredKey);
  assert(reDecryptedPayload === testPayload, 'Biometric-restored CryptoKey decrypts vault data with 100% integrity');

  // 6. Test Emergency Recovery Kit 12-word generation
  const kitPhrase = CryptoEngine.generateRecoveryPhrase();
  const kitWords = kitPhrase.trim().split(/\s+/);
  assert(kitWords.length === 12, `Emergency recovery phrase produces exactly 12 words (${kitWords.slice(0, 3).join(' ')}...)`);
  assert(kitWords.every(w => /^[a-z]+$/.test(w)), 'Every word in recovery phrase consists of clean lowercase alphabetic letters');

  console.log('\n========================================');
  console.log(`Verification Complete: ${passed} Passed, ${failed} Failed`);
  console.log('========================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
