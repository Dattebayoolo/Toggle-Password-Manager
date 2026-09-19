/**
 * Toggle Password Manager - Security Checkup Engine
 * Direct local alternative to Google Password Manager's Checkup feature.
 * Detects weak passwords, reused passwords, compromised patterns, and calculates vault health.
 */

import { GeneratorEngine } from './generator.js';

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
    const NINETY_DAYS_MS = 90 * 24 * 60 * 60 * 1000;

    logins.forEach(item => {
      const pwd = item.password || '';
      if (!pwd) return;

      // 1. Weakness Check
      const strength = GeneratorEngine.evaluateStrength(pwd);
      if (strength.score <= 1 || pwd.length < 10) {
        weakItems.push({
          item,
          reason: pwd.length < 8 ? 'Critically short (less than 8 characters)' : 'Weak entropy - easily crackable',
          strength
        });
      }

      // 2. Reused Check
      if (!reusedMap.has(pwd)) {
        reusedMap.set(pwd, []);
      }
      reusedMap.get(pwd).push(item);

      // 3. Known Compromised Patterns
      const lowerPwd = pwd.toLowerCase();
      for (const pattern of this.COMMON_COMPROMISED_PATTERNS) {
        if (lowerPwd.includes(pattern)) {
          compromisedItems.push({
            item,
            reason: `Contains common compromised keyword "${pattern}"`
          });
          break;
        }
      }

      // 4. Stale / Old Passwords
      if (item.updatedAt) {
        const itemDate = new Date(item.updatedAt).getTime();
        if (now - itemDate > NINETY_DAYS_MS) {
          const daysOld = Math.floor((now - itemDate) / (24 * 60 * 60 * 1000));
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
}
