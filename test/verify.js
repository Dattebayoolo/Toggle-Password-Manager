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
  const key = await CryptoEngine.deriveKey(masterPass, salt, 10000); // 10k iterations for fast unit test
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
