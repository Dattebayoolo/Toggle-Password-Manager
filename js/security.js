/**
 * Toggle Password Manager - Security Checkup Engine
 * Direct local alternative to Google Password Manager's Checkup feature.
 * Detects weak passwords, reused passwords, compromised patterns, and calculates vault health.
 * Includes k-Anonymity HaveIBeenPwned live breach scanning (zero-knowledge).
 */

import { GeneratorEngine } from './generator.js';
import { CryptoEngine } from './crypto.js';

// Pre-extracted constant to avoid repeated arithmetic in the hot audit loop
const DAY_MS = 24 * 60 * 60 * 1000;
const NINETY_DAYS_MS = 90 * DAY_MS;

export class SecurityEngine {
  static COMMON_COMPROMISED_PATTERNS = [
    'password', '123456', '12345678', '123456789', 'qwerty', '111111',
    'welcome', 'admin', 'login', 'football', 'monkey', 'dragon',
    'master', 'iloveyou', 'sunshine', 'princess', 'starwars'
  ];

  /**
   * Performs complete local security audit on all vault items
   */
  static runAudit(items = []) {
    const logins = items.filter(item => item.category === 'login' || !item.category);
    
    const weakItems = [];
    const reusedMap = new Map(); // password -> array of items
    const compromisedItems = [];
    const oldItems = [];

    const now = Date.now();

    logins.forEach(item => {
      const pwd = item.password || '';
      if (!pwd) return;

      // Check for known compromised patterns
      const lowerPwd = pwd.toLowerCase();
      let matchedPattern = null;
      for (const pattern of this.COMMON_COMPROMISED_PATTERNS) {
        if (lowerPwd.includes(pattern)) {
          matchedPattern = pattern;
          break;
        }
      }

      // 1. Weakness Check: low score, short length (<10), or compromised dictionary word
      const strength = GeneratorEngine.evaluateStrength(pwd);
      if (strength.score <= 1 || pwd.length < 10 || matchedPattern) {
        weakItems.push({
          item,
          reason: matchedPattern
            ? `Contains common compromised pattern "${matchedPattern}"`
            : pwd.length < 8
              ? 'Critically short (less than 8 characters)'
              : 'Weak entropy - easily crackable',
          strength
        });
      }

      // 2. Reused Check
      if (!reusedMap.has(pwd)) {
        reusedMap.set(pwd, []);
      }
      reusedMap.get(pwd).push(item);

      // 3. Known Compromised Patterns
      if (matchedPattern) {
        compromisedItems.push({
          item,
          reason: `Contains common compromised keyword "${matchedPattern}"`
        });
      }

      // 4. Stale / Old Passwords
      if (item.updatedAt) {
        const itemDate = new Date(item.updatedAt).getTime();
        if (now - itemDate > NINETY_DAYS_MS) {
          const daysOld = Math.floor((now - itemDate) / DAY_MS);
          oldItems.push({
            item,
            daysOld
          });
        }
      }
    });

    // Format reused passwords
    const reusedGroups = [];
    reusedMap.forEach((matchedItems, pwd) => {
      if (matchedItems.length > 1) {
        reusedGroups.push({
          passwordPreview: pwd.slice(0, 2) + '••••' + pwd.slice(-1),
          count: matchedItems.length,
          items: matchedItems
        });
      }
    });

    // Calculate Health Score (0 - 100)
    let score = 100;
    const totalLogins = logins.length;

    if (totalLogins > 0) {
      const weakPenalty = (weakItems.length / totalLogins) * 35;
      const reusedTotalAccounts = reusedGroups.reduce((acc, g) => acc + g.items.length, 0);
      const reusedPenalty = (reusedTotalAccounts / totalLogins) * 35;
      const compPenalty = (compromisedItems.length / totalLogins) * 20;
      const oldPenalty = (oldItems.length / totalLogins) * 10;

      score = Math.max(0, Math.round(100 - (weakPenalty + reusedPenalty + compPenalty + oldPenalty)));
    }

    let grade = 'A+';
    let statusLabel = 'Exceptional Security';
    let statusClass = 'safe';

    if (score < 50) {
      grade = 'F';
      statusLabel = 'Critical Attention Needed';
      statusClass = 'danger';
    } else if (score < 65) {
      grade = 'D';
      statusLabel = 'Poor Security';
      statusClass = 'danger';
    } else if (score < 80) {
      grade = 'C';
      statusLabel = 'Fair - Needs Improvement';
      statusClass = 'warning';
    } else if (score < 90) {
      grade = 'B';
      statusLabel = 'Good Security';
      statusClass = 'safe';
    } else if (score < 98) {
      grade = 'A';
      statusLabel = 'Very Secure';
      statusClass = 'safe';
    }

    return {
      score,
      grade,
      statusLabel,
      statusClass,
      totalLogins,
      weakItems,
      reusedGroups,
      compromisedItems,
      oldItems
    };
  }

  /**
   * Privacy-Preserving k-Anonymity Breach Check via HaveIBeenPwned Pwned Passwords API.
   * 
   * Algorithm:
   *  1. SHA-1 hash the password locally (never stored or sent)
   *  2. Send ONLY the first 5 hex characters (the "prefix") to HIBP
   *  3. HIBP returns a list of all hash suffixes (35 chars) for that prefix
   *  4. Match the remaining 35 chars of our hash 100% in browser memory
   * 
   * @param {string} password - plaintext password to check
   * @returns {Promise<number>} - breach exposure count (0 = not found)
   */
  static async checkPwnedPassword(password) {
    try {
      const sha1Hex = await CryptoEngine.hashSHA1(password);
      const prefix = sha1Hex.slice(0, 5);
      // Ensure local suffix is uppercase to match HIBP response format
      const suffix = sha1Hex.slice(5).toUpperCase();

      const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
        method: 'GET',
        headers: { 'Add-Padding': 'true' }  // HIBP privacy padding
      });

      if (!response.ok) {
        throw new Error(`HIBP API error: ${response.status}`);
      }

      const text = await response.text();
      const lines = text.split('\r\n');

      for (const line of lines) {
        const [hashSuffix, countStr] = line.split(':');
        if (hashSuffix && hashSuffix === suffix) {
          return parseInt(countStr, 10) || 0;
        }
      }

      return 0; // Not found in breached database
    } catch (err) {
      // Network failure or API unavailable — return -1 to signal "couldn't check"
      if (err.name === 'TypeError' && err.message.includes('fetch')) {
        return -1; // Offline / network error
      }
      throw err;
    }
  }

  /**
   * Batch live breach scanner — asynchronously evaluates all login passwords
   * against HaveIBeenPwned using k-Anonymity, with real-time progress callbacks.
   * 
   * Deduplicates by password value before scanning: if multiple accounts share
   * the same password, only ONE API call is made and the result is propagated to
   * all matching items. This can drastically reduce scan time and API usage.
   * 
   * @param {Array} items - vault items (filters to logins with passwords)
   * @param {Function} onProgress - callback({current, total, item, breachCount})
   * @returns {Promise<Array>} - array of {item, breachCount} for items found in breaches
   */
  static async runLiveBreachScan(items = [], onProgress = () => {}) {
    const logins = items.filter(i => (i.category === 'login' || !i.category) && i.password && !i.trash);
    const breachedItems = [];
    const THROTTLE_MS = 150; // Respect HIBP rate limit (max ~10 req/sec)

    // Deduplicate passwords — map unique password -> [items using it]
    const passwordMap = new Map();
    for (const item of logins) {
      if (!passwordMap.has(item.password)) {
        passwordMap.set(item.password, []);
      }
      passwordMap.get(item.password).push(item);
    }

    const uniquePasswords = [...passwordMap.keys()];
    let processed = 0;

    for (let i = 0; i < uniquePasswords.length; i++) {
      const pwd = uniquePasswords[i];
      const matchingItems = passwordMap.get(pwd);

      // Throttle requests to avoid HIBP rate limiting
      if (i > 0) {
        await new Promise(resolve => setTimeout(resolve, THROTTLE_MS));
      }

      const breachCount = await this.checkPwnedPassword(pwd);

      // Report progress for each item sharing this password
      for (const item of matchingItems) {
        processed++;
        onProgress({
          current: processed,
          total: logins.length,
          item,
          breachCount
        });

        if (breachCount > 0) {
          breachedItems.push({ item, breachCount });
        }
      }
    }

    return breachedItems;
  }
}
