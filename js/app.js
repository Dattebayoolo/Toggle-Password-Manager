/**
 * Toggle Password Manager - Main Application Controller
 */

import { CryptoEngine } from './crypto.js';
import { StorageEngine } from './storage.js';
import { GeneratorEngine } from './generator.js';
import { SecurityEngine } from './security.js';
import { ImportExportEngine } from './importer.js';
import { TOTPEngine } from './totp.js';
import { UI } from './ui.js';

class ToggleApp {
  constructor() {
    this.vaultKey = null;
    this.vaultItems = [];
    this.currentCategory = 'all';
    this.searchQuery = '';
    this.sortBy = 'recent';
    this.activeItem = null;
    this.revealedPasswords = new Set(); // item IDs with password currently toggled visible

    this.prefs = {
      autoLockMinutes: 5,
      theme: 'dark',
      autoClearClipboardSec: 30
    };

    this.inactivitySecondsRemaining = 300;
    this.inactivityIntervalId = null;

    this.totpIntervalId = null;
    this.currentDrawerTotpCode = '';
  }

  async init() {
    this.bindGlobalEvents();
    this.bindAuthEvents();
    this.bindGeneratorEvents();
    this.bindDrawerEvents();
    this.bindSettingsEvents();
    this.startTOTPTicker();

    this.prefs = await StorageEngine.getPreferences();
    const cachedTheme = localStorage.getItem('toggle_theme');
    if (cachedTheme) {
      this.prefs.theme = cachedTheme;
    }
    this.applyTheme(this.prefs.theme);

    const initialized = await StorageEngine.isInitialized();
    if (!initialized) {
      this.showSetupScreen();
    } else {
      this.showUnlockScreen();
    }
  }

  /* =========================================================
     1. Authentication & Vault Lifecycle
     ========================================================= */
  showSetupScreen() {
    document.getElementById('auth-screen').classList.remove('hidden');
    document.getElementById('setup-view').style.display = 'block';
    document.getElementById('unlock-view').style.display = 'none';
    document.getElementById('recovery-view').style.display = 'none';

    // Generate fresh recovery phrase for setup
    const phrase = CryptoEngine.generateRecoveryPhrase();
    const recoveryBox = document.getElementById('generated-recovery-phrase');
    if (recoveryBox) {
      recoveryBox.textContent = phrase;
      recoveryBox.dataset.phrase = phrase;
    }
  }

  showUnlockScreen() {
    document.getElementById('auth-screen').classList.remove('hidden');
    document.getElementById('setup-view').style.display = 'none';
    document.getElementById('unlock-view').style.display = 'block';
    document.getElementById('recovery-view').style.display = 'none';

    const unlockInput = document.getElementById('unlock-password');
    if (unlockInput) {
      unlockInput.value = '';
      setTimeout(() => unlockInput.focus(), 100);
    }

    this.checkAndShowBiometricButton();
  }

  showRecoveryScreen() {
    document.getElementById('setup-view').style.display = 'none';
    document.getElementById('unlock-view').style.display = 'none';
    document.getElementById('recovery-view').style.display = 'block';
  }

  async handleSetupSubmit(e) {
    e.preventDefault();
    const password = document.getElementById('setup-password').value;
    const confirm = document.getElementById('setup-confirm').value;
    const phrase = document.getElementById('generated-recovery-phrase').dataset.phrase;
    const confirmedCheckbox = document.getElementById('setup-ack-phrase');

    if (!password || password.length < 8) {
      UI.showToast('Master password must be at least 8 characters.', 'danger');
      return;
    }

    if (password !== confirm) {
      UI.showToast('Passwords do not match.', 'danger');
      return;
    }

    if (!confirmedCheckbox.checked) {
      UI.showToast('Please confirm you have safely saved your recovery phrase.', 'danger');
      return;
    }

    try {
      const { key } = await StorageEngine.initializeVault(password, phrase);
      sessionStorage.setItem('toggle_setup_phrase', phrase);
      this.vaultKey = key;
      this.vaultItems = [];
      this.finishUnlock();
      UI.showToast('Vault created and secured with AES-256-GCM!', 'success');
    } catch (err) {
      UI.showToast('Setup error: ' + err.message, 'danger');
    }
  }

  async handleUnlockSubmit(e) {
    e.preventDefault();
    const password = document.getElementById('unlock-password').value;
    if (!password) return;

    try {
      const key = await StorageEngine.unlockVault(password);
      this.vaultKey = key;
      this.vaultItems = await StorageEngine.loadVaultItems(key);
      this.finishUnlock();
      UI.showToast('Vault unlocked successfully', 'success');
    } catch (err) {
      UI.showToast(err.message, 'danger');
      const input = document.getElementById('unlock-password');
      input.classList.add('input-error');
      setTimeout(() => input.classList.remove('input-error'), 800);
    }
  }

  finishUnlock() {
    document.getElementById('auth-screen').classList.add('hidden');
    this.startInactivityWatcher();
    this.renderNavigation();
    this.renderMainView();
  }

  lockVault() {
    this.vaultKey = null;
    this.vaultItems = [];
    this.revealedPasswords.clear();
    this.activeItem = null;
    clearInterval(this.inactivityIntervalId);
    UI.clearClipboardNow();

    // Close any open drawers/modals
    this.closeDrawer();
    document.querySelectorAll('.modal-overlay').forEach(m => m.classList.remove('active'));

    this.showUnlockScreen();
    UI.showToast('Vault locked', 'info');
  }

  /* =========================================================
     2. Inactivity Watcher (Auto-Lock)
     ========================================================= */
  startInactivityWatcher() {
    clearInterval(this.inactivityIntervalId);
    const timeoutMinutes = this.prefs.autoLockMinutes || 5;
    if (timeoutMinutes <= 0) return; // Never lock

    this.inactivitySecondsRemaining = timeoutMinutes * 60;
    this.updateLockTimerDisplay();

    this.inactivityIntervalId = setInterval(() => {
      this.inactivitySecondsRemaining--;
      this.updateLockTimerDisplay();

      if (this.inactivitySecondsRemaining <= 0) {
        this.lockVault();
      }
    }, 1000);
  }

  resetInactivityTimer() {
    const timeoutMinutes = this.prefs.autoLockMinutes || 5;
    this.inactivitySecondsRemaining = timeoutMinutes * 60;
    this.updateLockTimerDisplay();
  }

  updateLockTimerDisplay() {
    const badge = document.getElementById('lock-timer-text');
    if (!badge) return;

    if (!this.prefs.autoLockMinutes || this.prefs.autoLockMinutes <= 0) {
      badge.textContent = 'Lock: Manual';
      return;
    }

    const mins = Math.floor(this.inactivitySecondsRemaining / 60);
    const secs = this.inactivitySecondsRemaining % 60;
    badge.textContent = `Auto-lock: ${mins}:${secs.toString().padStart(2, '0')}`;
  }

  /* =========================================================
     3. Navigation & Filtering
     ========================================================= */
  renderNavigation() {
    const counts = {
      all: this.vaultItems.filter(i => !i.trash).length,
      login: this.vaultItems.filter(i => (i.category === 'login' || !i.category) && !i.trash).length,
      note: this.vaultItems.filter(i => i.category === 'note' && !i.trash).length,
      card: this.vaultItems.filter(i => i.category === 'card' && !i.trash).length,
      passkey: this.vaultItems.filter(i => i.category === 'passkey' && !i.trash).length,
      address: this.vaultItems.filter(i => i.category === 'address' && !i.trash).length,
      apikey: this.vaultItems.filter(i => i.category === 'apikey' && !i.trash).length,
      favorites: this.vaultItems.filter(i => i.favorite && !i.trash).length,
      trash: this.vaultItems.filter(i => i.trash).length
    };

    document.querySelectorAll('.sidebar-nav .nav-item').forEach(item => {
      const cat = item.dataset.category;
      if (counts[cat] !== undefined) {
        const countSpan = item.querySelector('.nav-count');
        if (countSpan) countSpan.textContent = counts[cat];
      }

      if (cat === this.currentCategory) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });
  }

  /* =========================================================
     4. Main View Renderer (Cards & Views)
     ========================================================= */
  renderMainView() {
    this.renderNavigation();

    const vaultView = document.getElementById('vault-view-container');
    const checkupView = document.getElementById('checkup-view-container');
    const settingsView = document.getElementById('settings-view-container');

    if (this.currentCategory === 'checkup') {
      vaultView.style.display = 'none';
      checkupView.style.display = 'block';
      settingsView.style.display = 'none';
      this.renderSecurityCheckup();
      return;
    }

    if (this.currentCategory === 'settings') {
      vaultView.style.display = 'none';
      checkupView.style.display = 'none';
      settingsView.style.display = 'block';
      this.renderSettings();
      return;
    }

    // Default: Vault View
    vaultView.style.display = 'block';
    checkupView.style.display = 'none';
    settingsView.style.display = 'none';

    this.renderStatsRow();
    this.renderVaultCards();
  }

  renderStatsRow() {
    const activeLogins = this.vaultItems.filter(i => (i.category === 'login' || !i.category) && !i.trash);
    const audit = SecurityEngine.runAudit(activeLogins);

    document.getElementById('stat-total-logins').textContent = activeLogins.length;
    document.getElementById('stat-security-score').textContent = activeLogins.length === 0 ? '100%' : `${audit.score}%`;
    document.getElementById('stat-weak-count').textContent = audit.weakItems.length;
    document.getElementById('stat-reused-count').textContent = audit.reusedGroups.reduce((acc, g) => acc + g.items.length, 0);
  }

  renderVaultCards() {
    const listContainer = document.getElementById('vault-cards-list');
    const emptyContainer = document.getElementById('vault-empty-state');
    const viewTitle = document.getElementById('current-view-title');

    // Update Title
    const titles = {
      all: 'All Passwords',
      login: 'Logins & Credentials',
      note: 'Secure Notes',
      card: 'Payment Cards',
      passkey: 'Passkeys & Identities',
      address: 'Addresses & Shipping',
      apikey: 'API Keys & Secrets',
      favorites: 'Starred & Favorites',
      trash: 'Trash'
    };
    viewTitle.textContent = titles[this.currentCategory] || 'Vault Items';

    // Show/hide Empty Trash button in toolbar
    const emptyTrashBtn = document.getElementById('btn-empty-trash');
    const hasTrashItems = this.vaultItems.some(i => i.trash);
    if (emptyTrashBtn) {
      emptyTrashBtn.style.display = (this.currentCategory === 'trash' && hasTrashItems) ? 'inline-flex' : 'none';
    }

    // Filter Items
    let filtered = this.vaultItems.filter(item => {
      // Trash filter
      if (this.currentCategory === 'trash') {
        return !!item.trash;
      }
      if (item.trash) return false;

      // Category filter
      if (this.currentCategory === 'favorites') {
        if (!item.favorite) return false;
      } else if (this.currentCategory !== 'all') {
        if (this.currentCategory === 'login' && (!item.category || item.category === 'login')) {
          // match login
        } else if (item.category !== this.currentCategory) {
          return false;
        }
      }

      // Search Query filter
      if (this.searchQuery) {
        const q = this.searchQuery.toLowerCase();
        const matchName = (item.name || '').toLowerCase().includes(q);
        const matchUser = (item.username || '').toLowerCase().includes(q);
        const matchUrl = (item.url || '').toLowerCase().includes(q);
        const matchNotes = (item.notes || '').toLowerCase().includes(q);
        const matchCard = (item.cardNumber || '').replace(/\s+/g, '').includes(q);
        const matchCity = (item.city || '').toLowerCase().includes(q);
        return matchName || matchUser || matchUrl || matchNotes || matchCard || matchCity;
      }

      return true;
    });

    // Sort Items
    filtered.sort((a, b) => {
      if (this.sortBy === 'name') {
        return (a.name || '').localeCompare(b.name || '');
      }
      if (this.sortBy === 'score') {
        const scoreA = GeneratorEngine.evaluateStrength(a.password || '').score;
        const scoreB = GeneratorEngine.evaluateStrength(b.password || '').score;
        return scoreA - scoreB;
      }
      // default: recent
      return new Date(b.updatedAt || 0) - new Date(a.updatedAt || 0);
    });

    if (filtered.length === 0) {
      listContainer.innerHTML = '';
      emptyContainer.style.display = 'flex';
      return;
    }

    emptyContainer.style.display = 'none';

    listContainer.innerHTML = filtered.map(item => {
      const isRevealed = this.revealedPasswords.has(item.id);
      const isTrash = !!item.trash;

      let badgeHTML = '';
      let subtitle = UI.escapeHTML(item.username || item.url || 'No account detail');
      let centerContent = '';
      let actionButtons = '';

      if (isTrash) {
        badgeHTML = `<span class="badge badge-danger">Trash</span>`;
      } else if (item.category === 'card') {
        const brand = item.cardBrand || this.detectCardBrand(item.cardNumber);
        badgeHTML = `<span class="badge badge-info">${brand}</span>`;
        const last4 = item.cardNumber ? item.cardNumber.replace(/\s+/g, '').slice(-4) : '';
        subtitle = (last4 ? `•••• •••• •••• ${last4}` : 'No card number') + (item.cardExp ? ` • Exp ${item.cardExp}` : '');
      } else if (item.category === 'address') {
        badgeHTML = `<span class="badge badge-info">Address</span>`;
        const loc = [item.city, item.state, item.zip, item.country].filter(Boolean).join(', ');
        subtitle = loc || item.street1 || item.recipient || 'Shipping address';
      } else if (item.category === 'apikey') {
        badgeHTML = `<span class="badge badge-info">${(item.apiEnv || 'API').toUpperCase()}</span>`;
        subtitle = item.apiUrl || item.name || 'API Token';
      } else if (item.category === 'note') {
        badgeHTML = `<span class="badge badge-info">Note</span>`;
        subtitle = item.noteBody ? (item.noteBody.substring(0, 45).replace(/\n/g, ' ') + (item.noteBody.length > 45 ? '...' : '')) : (item.notes || 'Secure note');
      } else if (item.category === 'passkey') {
        badgeHTML = `<span class="badge badge-safe">Passkey</span>`;
        subtitle = item.passkeyUser || item.username || item.passkeyRp || 'FIDO2 Credential';
      } else {
        const strength = GeneratorEngine.evaluateStrength(item.password || '');
        if (strength.score <= 1 && item.password) {
          badgeHTML = `<span class="badge badge-danger">Weak</span>`;
        }
      }

      // Center content (preview / tactile toggle)
      if (item.category === 'card') {
        const cardNum = item.cardNumber ? item.cardNumber.replace(/\s+/g, '') : '';
        const displayCard = isRevealed ? (item.cardNumber || '••••••••') : (cardNum ? `•••• •••• •••• ${cardNum.slice(-4)}` : '•••• •••• •••• ••••');
        centerContent = `
          <div class="vault-password-preview font-mono" id="pwd-preview-${item.id}">
            ${UI.escapeHTML(displayCard)}
          </div>
          <label class="toggle-switch mini" title="Reveal Full Card Number">
            <input type="checkbox" class="password-reveal-toggle" data-id="${item.id}" ${isRevealed ? 'checked' : ''} />
            <span class="toggle-slider"></span>
          </label>
        `;
      } else if (item.category === 'apikey') {
        const keyVal = item.apiKey || item.password || '';
        const displayKey = isRevealed ? keyVal : (keyVal ? keyVal.slice(0, 7) + '••••••••' : '••••••••••••');
        centerContent = `
          <div class="vault-password-preview font-mono" id="pwd-preview-${item.id}">
            ${UI.escapeHTML(displayKey)}
          </div>
          <label class="toggle-switch mini" title="Reveal API Key">
            <input type="checkbox" class="password-reveal-toggle" data-id="${item.id}" ${isRevealed ? 'checked' : ''} />
            <span class="toggle-slider"></span>
          </label>
        `;
      } else if (item.category === 'note') {
        centerContent = `
          <div style="font-size:0.775rem;color:var(--text-muted);font-style:italic;">
            Encrypted Private Note
          </div>
        `;
      } else if (item.category === 'address') {
        centerContent = `
          <div style="font-size:0.8rem;color:var(--text-muted);">
            ${item.phone ? UI.escapeHTML(item.phone) : (item.recipient ? UI.escapeHTML(item.recipient) : '')}
          </div>
        `;
      } else if (item.password) {
        const displayPassword = isRevealed ? UI.escapeHTML(item.password) : '••••••••••••';
        let totpChipHTML = '';
        if (item.totp) {
          totpChipHTML = `
            <div class="totp-card-chip" data-action="copy-totp" data-id="${item.id}" data-totp="${UI.escapeHTML(item.totp)}" title="Click to copy 2FA code">
              <span class="totp-card-code" id="totp-code-${item.id}">------</span>
              <div class="totp-card-mini-circle">
                <svg viewBox="0 0 36 36">
                  <circle class="totp-circle-bg" cx="18" cy="18" r="15.915" />
                  <circle class="totp-circle-bar" id="totp-ring-${item.id}" cx="18" cy="18" r="15.915" />
                </svg>
              </div>
            </div>
          `;
        }

        centerContent = `
          <div style="display:flex;align-items:center;gap:10px;">
            <div class="vault-password-preview font-mono" id="pwd-preview-${item.id}">
              ${displayPassword}
            </div>
            <label class="toggle-switch mini" title="Toggle Show/Hide Password">
              <input type="checkbox" class="password-reveal-toggle" data-id="${item.id}" ${isRevealed ? 'checked' : ''} />
              <span class="toggle-slider"></span>
            </label>
            ${totpChipHTML}
          </div>
        `;
      }

      // Actions
      if (isTrash) {
        actionButtons = `
          <button class="btn-icon" data-action="card-restore" data-id="${item.id}" title="Restore to Vault" style="color:var(--primary);">
            <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
            </svg>
          </button>
          <button class="btn-icon" data-action="card-delete-perm" data-id="${item.id}" title="Delete Permanently" style="color:var(--status-danger);">
            <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
            </svg>
          </button>
        `;
      } else {
        if (item.category === 'card') {
          actionButtons += `
            <button class="btn-icon" data-action="copy-card" data-id="${item.id}" title="Copy Card Number">
              <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                <rect x="2" y="5" width="20" height="14" rx="2"></rect>
                <line x1="2" y1="10" x2="22" y2="10"></line>
              </svg>
            </button>
          `;
          if (item.cardCvv) {
            actionButtons += `
              <button class="btn-icon" data-action="copy-cvv" data-id="${item.id}" title="Copy CVV">
                <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                  <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
              </button>
            `;
          }
        } else if (item.category === 'address') {
          actionButtons += `
            <button class="btn-icon" data-action="copy-address" data-id="${item.id}" title="Copy Full Address">
              <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z"/>
                <path stroke-linecap="round" stroke-linejoin="round" d="M15 11a3 3 0 11-6 0 3 3 0 016 0z"/>
              </svg>
            </button>
          `;
        } else if (item.category === 'apikey') {
          actionButtons += `
            <button class="btn-icon" data-action="copy-key" data-id="${item.id}" title="Copy API Key">
              <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/>
              </svg>
            </button>
          `;
        } else if (item.category === 'note') {
          actionButtons += `
            <button class="btn-icon" data-action="copy-note" data-id="${item.id}" title="Copy Note Content">
              <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
              </svg>
            </button>
          `;
        } else {
          // Standard login actions
          if (item.username) {
            actionButtons += `
              <button class="btn-icon" data-action="copy-user" data-id="${item.id}" title="Copy Username">
                <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
                </svg>
              </button>
            `;
          }
          if (item.password) {
            actionButtons += `
              <button class="btn-icon" data-action="copy-pwd" data-id="${item.id}" title="Copy Password">
                <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                  <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
              </button>
            `;
          }
          if (item.totp) {
            actionButtons += `
              <button class="btn-icon" data-action="copy-totp" data-id="${item.id}" title="Copy 2FA Code" style="color:var(--primary);">
                <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                </svg>
              </button>
            `;
          }
          if (item.url) {
            actionButtons += `
              <a href="${item.url.startsWith('http') ? item.url : 'https://' + item.url}" 
                 target="_blank" rel="noopener noreferrer" class="btn-icon" title="Open Website" onclick="event.stopPropagation()">
                <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
                </svg>
              </a>
            `;
          }
        }

        actionButtons += `
          <button class="btn-icon" data-action="open-detail" title="View Details">
            <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M9 5l7 7-7 7"/>
            </svg>
          </button>
        `;
      }

      return `
        <div class="vault-card" data-id="${item.id}">
          <div class="vault-card-left" data-action="open-detail">
            ${UI.renderAvatar(item.name, item.url)}
            <div class="vault-card-meta">
              <div class="vault-card-title">
                ${UI.escapeHTML(item.name || 'Untitled')}
                ${item.favorite ? '<span style="color:#f59e0b;" title="Favorite">★</span>' : ''}
                ${badgeHTML}
              </div>
              <div class="vault-card-subtitle">
                ${subtitle}
              </div>
            </div>
          </div>

          <div class="vault-card-center">
            ${centerContent}
          </div>

          <div class="vault-card-actions">
            ${actionButtons}
          </div>
        </div>
      `;
    }).join('');

    // Bind card events
    this.bindCardInteractiveEvents();
  }

  bindCardInteractiveEvents() {
    // Reveal toggle switches
    document.querySelectorAll('.password-reveal-toggle').forEach(checkbox => {
      checkbox.addEventListener('change', (e) => {
        e.stopPropagation();
        const id = e.target.dataset.id;
        const item = this.vaultItems.find(i => i.id === id);
        if (!item) return;

        const previewElem = document.getElementById(`pwd-preview-${id}`);
        if (e.target.checked) {
          this.revealedPasswords.add(id);
          if (previewElem) {
            if (item.category === 'card') {
              previewElem.textContent = item.cardNumber || '';
            } else if (item.category === 'apikey') {
              previewElem.textContent = item.apiKey || item.password || '';
            } else {
              previewElem.textContent = item.password || '';
            }
          }
        } else {
          this.revealedPasswords.delete(id);
          if (previewElem) {
            if (item.category === 'card') {
              const last4 = item.cardNumber ? item.cardNumber.replace(/\s+/g, '').slice(-4) : '';
              previewElem.textContent = last4 ? `•••• •••• •••• ${last4}` : '•••• •••• •••• ••••';
            } else if (item.category === 'apikey') {
              const k = item.apiKey || item.password || '';
              previewElem.textContent = k ? k.slice(0, 7) + '••••••••' : '••••••••••••';
            } else {
              previewElem.textContent = '••••••••••••';
            }
          }
        }
      });
    });

    // Copy buttons & card click
    document.querySelectorAll('.vault-card').forEach(card => {
      const id = card.dataset.id;
      const item = this.vaultItems.find(i => i.id === id);
      if (!item) return;

      card.addEventListener('click', (e) => {
        const totpChip = e.target.closest('.totp-card-chip');
        if (totpChip && item.totp) {
          TOTPEngine.generateTOTP(item.totp).then(code => {
            UI.copySecure(code, '2FA Authentication Code');
          });
          return;
        }

        const actionBtn = e.target.closest('button');
        if (actionBtn) {
          const action = actionBtn.dataset.action;
          if (action === 'copy-totp') {
            if (item.totp) {
              TOTPEngine.generateTOTP(item.totp).then(code => {
                UI.copySecure(code, '2FA Authentication Code');
              });
            }
            return;
          }
          if (action === 'copy-user') {
            UI.copySecure(item.username, 'Username');
            return;
          }
          if (action === 'copy-pwd') {
            UI.copySecure(item.password, 'Password');
            return;
          }
          if (action === 'copy-card') {
            UI.copySecure(item.cardNumber ? item.cardNumber.replace(/\s+/g, '') : '', 'Card Number');
            return;
          }
          if (action === 'copy-cvv') {
            UI.copySecure(item.cardCvv, 'Card CVV');
            return;
          }
          if (action === 'copy-key') {
            UI.copySecure(item.apiKey || item.password, 'API Key');
            return;
          }
          if (action === 'copy-note') {
            UI.copySecure(item.noteBody || item.notes, 'Note Content');
            return;
          }
          if (action === 'copy-address') {
            const lines = [
              item.recipient,
              item.street1,
              item.street2,
              [item.city, item.state, item.zip].filter(Boolean).join(', '),
              item.country,
              item.phone
            ].filter(Boolean).join('\n');
            UI.copySecure(lines, 'Address');
            return;
          }
          if (action === 'card-restore') {
            item.trash = false;
            delete item.deletedAt;
            StorageEngine.saveVaultItems(this.vaultItems, this.vaultKey).then(() => {
              this.renderMainView();
              UI.showToast(`Restored "${item.name}" to vault!`, 'success');
            });
            return;
          }
          if (action === 'card-delete-perm') {
            if (confirm(`Permanently delete "${item.name}"? This cannot be undone.`)) {
              const idx = this.vaultItems.findIndex(i => i.id === item.id);
              if (idx !== -1) {
                this.vaultItems.splice(idx, 1);
                StorageEngine.saveVaultItems(this.vaultItems, this.vaultKey).then(() => {
                  this.renderMainView();
                  UI.showToast('Item permanently deleted', 'info');
                });
              }
            }
            return;
          }
          if (action === 'open-detail') {
            this.openDetailDrawer(item);
            return;
          }
        }

        // Clicking anywhere on card opens detail drawer unless clicking toggle
        if (!e.target.closest('.toggle-switch') && !e.target.closest('a')) {
          this.openDetailDrawer(item);
        }
      });
    });
  }

  /* =========================================================
     5. Category Utilities & Sliding Detail Drawer
     ========================================================= */
  detectCardBrand(number) {
    const cleaned = (number || '').replace(/\D/g, '');
    if (/^4/.test(cleaned)) return 'Visa';
    if (/^(5[1-5]|2[2-7])/.test(cleaned)) return 'Mastercard';
    if (/^3[47]/.test(cleaned)) return 'Amex';
    if (/^6(011|5)/.test(cleaned)) return 'Discover';
    return 'Card';
  }

  formatCardNumber(val) {
    const digits = val.replace(/\D/g, '').substring(0, 19);
    const parts = [];
    for (let i = 0; i < digits.length; i += 4) {
      parts.push(digits.substring(i, i + 4));
    }
    return parts.join(' ');
  }

  formatCardExp(val) {
    const digits = val.replace(/\D/g, '').substring(0, 4);
    if (digits.length >= 3) {
      return digits.substring(0, 2) + '/' + digits.substring(2);
    }
    return digits;
  }

  updateCardBrandBadge(number) {
    const badge = document.getElementById('edit-card-brand-badge');
    if (!badge) return;
    const brand = this.detectCardBrand(number);
    if (brand && brand !== 'Card') {
      badge.textContent = brand;
      badge.className = `card-brand-badge ${brand.toLowerCase()}`;
      badge.style.display = 'inline-flex';
    } else {
      badge.style.display = 'none';
    }
  }

  updateDrawerCategoryFields(category) {
    const groups = {
      login: document.getElementById('category-fields-login'),
      passkey: document.getElementById('category-fields-passkey'),
      card: document.getElementById('category-fields-card'),
      address: document.getElementById('category-fields-address'),
      apikey: document.getElementById('category-fields-apikey'),
      note: document.getElementById('category-fields-note')
    };

    Object.keys(groups).forEach(cat => {
      if (groups[cat]) {
        groups[cat].style.display = (cat === category) ? 'flex' : 'none';
      }
    });

    const nameLabel = document.getElementById('label-item-name');
    const nameInput = document.getElementById('edit-item-name');
    if (nameLabel && nameInput) {
      switch (category) {
        case 'card':
          nameLabel.textContent = 'Card Nickname';
          nameInput.placeholder = 'e.g. Chase Sapphire, Personal Visa, Apple Card';
          break;
        case 'address':
          nameLabel.textContent = 'Address Label';
          nameInput.placeholder = 'e.g. Home, Office, Vacation Home';
          break;
        case 'apikey':
          nameLabel.textContent = 'API Service / Token Name';
          nameInput.placeholder = 'e.g. OpenAI GPT-4, Stripe Secret, AWS CLI';
          break;
        case 'note':
          nameLabel.textContent = 'Note Title';
          nameInput.placeholder = 'e.g. Server Passphrases, Recovery Codes';
          break;
        case 'passkey':
          nameLabel.textContent = 'Service Name';
          nameInput.placeholder = 'e.g. Google Passkey, GitHub FIDO2';
          break;
        default:
          nameLabel.textContent = 'Website or App Name';
          nameInput.placeholder = 'e.g. Google, GitHub, Netflix...';
          break;
      }
    }
  }

  openDetailDrawer(item = null) {
    this.activeItem = item ? JSON.parse(JSON.stringify(item)) : {
      id: 'toggle_' + Math.random().toString(36).substring(2, 9) + Date.now().toString(36),
      name: '',
      url: '',
      username: '',
      password: '',
      notes: '',
      category: this.currentCategory === 'all' || this.currentCategory === 'trash' || this.currentCategory === 'favorites' ? 'login' : this.currentCategory,
      tags: [],
      favorite: false,
      history: [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    const isNew = !item;
    document.getElementById('drawer-title').textContent = isNew ? 'New Credential' : (this.activeItem.trash ? 'Trashed Item' : 'Edit Credential');

    const restoreBtn = document.getElementById('drawer-restore-btn');
    const deleteBtn = document.getElementById('drawer-delete-btn');
    const saveBtn = document.getElementById('drawer-save-btn');

    if (this.activeItem.trash) {
      if (restoreBtn) restoreBtn.style.display = 'inline-flex';
      if (deleteBtn) deleteBtn.textContent = 'Delete Permanently';
      if (saveBtn) saveBtn.style.display = 'none';
    } else {
      if (restoreBtn) restoreBtn.style.display = 'none';
      if (deleteBtn) deleteBtn.textContent = 'Delete';
      if (saveBtn) saveBtn.style.display = 'inline-flex';
    }

    document.getElementById('edit-item-id').value = this.activeItem.id;
    document.getElementById('edit-item-name').value = this.activeItem.name || '';
    document.getElementById('edit-item-category').value = this.activeItem.category || 'login';
    document.getElementById('edit-item-notes').value = this.activeItem.notes || '';
    document.getElementById('edit-item-fav-toggle').checked = !!this.activeItem.favorite;

    // Login fields
    document.getElementById('edit-item-url').value = this.activeItem.url || '';
    document.getElementById('edit-item-user').value = this.activeItem.username || '';
    document.getElementById('edit-item-password').value = this.activeItem.password || '';
    const totpInput = document.getElementById('edit-item-totp');
    if (totpInput) totpInput.value = this.activeItem.totp || '';

    // Passkey fields
    document.getElementById('edit-passkey-rp').value = this.activeItem.passkeyRp || this.activeItem.url || '';
    document.getElementById('edit-passkey-user').value = this.activeItem.passkeyUser || this.activeItem.username || '';
    document.getElementById('edit-passkey-id').value = this.activeItem.passkeyId || '';
    document.getElementById('edit-passkey-authenticator').value = this.activeItem.passkeyAuthenticator || '';

    // Card fields
    document.getElementById('edit-card-holder').value = this.activeItem.cardHolder || this.activeItem.username || '';
    document.getElementById('edit-card-number').value = this.activeItem.cardNumber || '';
    document.getElementById('edit-card-exp').value = this.activeItem.cardExp || '';
    document.getElementById('edit-card-cvv').value = this.activeItem.cardCvv || '';
    document.getElementById('edit-card-pin').value = this.activeItem.cardPin || '';
    this.updateCardBrandBadge(this.activeItem.cardNumber);

    // Address fields
    document.getElementById('edit-address-recipient').value = this.activeItem.recipient || this.activeItem.name || '';
    document.getElementById('edit-address-street1').value = this.activeItem.street1 || '';
    document.getElementById('edit-address-street2').value = this.activeItem.street2 || '';
    document.getElementById('edit-address-city').value = this.activeItem.city || '';
    document.getElementById('edit-address-state').value = this.activeItem.state || '';
    document.getElementById('edit-address-zip').value = this.activeItem.zip || '';
    document.getElementById('edit-address-country').value = this.activeItem.country || 'United States';
    document.getElementById('edit-address-phone').value = this.activeItem.phone || '';

    // API Key fields
    document.getElementById('edit-apikey-token').value = this.activeItem.apiKey || this.activeItem.password || '';
    document.getElementById('edit-apikey-url').value = this.activeItem.apiUrl || this.activeItem.url || '';
    document.getElementById('edit-apikey-env').value = this.activeItem.apiEnv || 'production';
    document.getElementById('edit-apikey-expiry').value = this.activeItem.apiExpiry || '';

    // Note fields
    document.getElementById('edit-note-body').value = this.activeItem.noteBody || this.activeItem.notes || '';

    // Apply category fields visibility
    this.updateDrawerCategoryFields(this.activeItem.category || 'login');

    // Password strength bar update
    this.updateDrawerPasswordStrength(this.activeItem.password || '');

    // TOTP real-time preview update
    this.updateDrawerTOTP();

    // QR Code generation
    const qrContainer = document.getElementById('drawer-qr-container');
    const qrData = this.activeItem.password || this.activeItem.apiKey || this.activeItem.cardNumber;
    if (qrData) {
      qrContainer.innerHTML = UI.renderSimpleQR(qrData);
      qrContainer.style.display = 'block';
    } else {
      qrContainer.style.display = 'none';
    }

    // Password History Section
    const historyContainer = document.getElementById('drawer-history-section');
    if (this.activeItem.history && this.activeItem.history.length > 0) {
      historyContainer.innerHTML = `
        <div class="form-label" style="margin-top:10px;">Previous Passwords (${this.activeItem.history.length})</div>
        <div style="display:flex;flex-direction:column;gap:6px;">
          ${this.activeItem.history.map(h => `
            <div style="display:flex;justify-content:space-between;align-items:center;background:var(--bg-input);padding:6px 10px;border-radius:6px;font-size:0.8rem;">
              <span class="font-mono">${UI.escapeHTML(h.password)}</span>
              <span style="color:var(--text-dim);font-size:0.75rem;">${new Date(h.date).toLocaleDateString()}</span>
            </div>
          `).join('')}
        </div>
      `;
      historyContainer.style.display = 'block';
    } else {
      historyContainer.style.display = 'none';
    }

    document.getElementById('detail-drawer').classList.add('active');
  }

  closeDrawer() {
    document.getElementById('detail-drawer').classList.remove('active');
    this.activeItem = null;
  }

  updateDrawerPasswordStrength(password) {
    const strength = GeneratorEngine.evaluateStrength(password);
    const container = document.getElementById('drawer-strength-meter');
    if (!container) return;

    container.className = `strength-meter strength-level-${strength.score}`;
    document.getElementById('drawer-strength-label').textContent = strength.label;
    document.getElementById('drawer-crack-time').textContent = `Crack estimate: ${strength.crackTimeText}`;
  }

  async saveActiveItem() {
    if (!this.activeItem) return;

    const category = document.getElementById('edit-item-category').value;
    let name = document.getElementById('edit-item-name').value.trim();
    const notes = document.getElementById('edit-item-notes').value.trim();
    const favorite = document.getElementById('edit-item-fav-toggle').checked;
    const now = new Date().toISOString();

    let updatedItem = {
      ...this.activeItem,
      category,
      notes,
      favorite,
      updatedAt: now
    };

    if (category === 'card') {
      const cardHolder = document.getElementById('edit-card-holder').value.trim();
      const cardNumber = document.getElementById('edit-card-number').value.trim();
      const cardExp = document.getElementById('edit-card-exp').value.trim();
      const cardCvv = document.getElementById('edit-card-cvv').value.trim();
      const cardPin = document.getElementById('edit-card-pin').value.trim();
      const cardBrand = this.detectCardBrand(cardNumber);

      if (!name) name = cardHolder ? `${cardHolder}'s Card` : `${cardBrand} Card`;
      updatedItem = {
        ...updatedItem,
        name,
        username: cardHolder,
        password: cardCvv,
        cardHolder,
        cardNumber,
        cardExp,
        cardCvv,
        cardPin,
        cardBrand
      };
    } else if (category === 'address') {
      const recipient = document.getElementById('edit-address-recipient').value.trim();
      const street1 = document.getElementById('edit-address-street1').value.trim();
      const street2 = document.getElementById('edit-address-street2').value.trim();
      const city = document.getElementById('edit-address-city').value.trim();
      const state = document.getElementById('edit-address-state').value.trim();
      const zip = document.getElementById('edit-address-zip').value.trim();
      const country = document.getElementById('edit-address-country').value.trim();
      const phone = document.getElementById('edit-address-phone').value.trim();

      if (!name) name = recipient ? `${recipient} Address` : (street1 || 'Address');
      updatedItem = {
        ...updatedItem,
        name,
        username: recipient,
        url: phone,
        recipient,
        street1,
        street2,
        city,
        state,
        zip,
        country,
        phone
      };
    } else if (category === 'apikey') {
      const apiKey = document.getElementById('edit-apikey-token').value.trim();
      const apiUrl = document.getElementById('edit-apikey-url').value.trim();
      const apiEnv = document.getElementById('edit-apikey-env').value;
      const apiExpiry = document.getElementById('edit-apikey-expiry').value;

      if (!name) name = apiUrl ? `API (${apiUrl})` : 'API Key';
      updatedItem = {
        ...updatedItem,
        name,
        url: apiUrl,
        username: apiEnv.toUpperCase(),
        password: apiKey,
        apiKey,
        apiUrl,
        apiEnv,
        apiExpiry
      };
    } else if (category === 'note') {
      const noteBody = document.getElementById('edit-note-body').value;
      if (!name) name = 'Secure Note';
      updatedItem = {
        ...updatedItem,
        name,
        noteBody
      };
    } else if (category === 'passkey') {
      const passkeyRp = document.getElementById('edit-passkey-rp').value.trim();
      const passkeyUser = document.getElementById('edit-passkey-user').value.trim();
      const passkeyId = document.getElementById('edit-passkey-id').value.trim();
      const passkeyAuthenticator = document.getElementById('edit-passkey-authenticator').value.trim();

      if (!name) name = passkeyRp || 'Passkey Account';
      updatedItem = {
        ...updatedItem,
        name,
        url: passkeyRp,
        username: passkeyUser,
        passkeyRp,
        passkeyUser,
        passkeyId,
        passkeyAuthenticator
      };
    } else {
      // Default: login
      const url = document.getElementById('edit-item-url').value.trim();
      const username = document.getElementById('edit-item-user').value.trim();
      const newPassword = document.getElementById('edit-item-password').value;
      const totp = document.getElementById('edit-item-totp')?.value.trim();

      if (!name && !url) {
        UI.showToast('Please provide an account name or website URL', 'danger');
        return;
      }

      // Check if password changed, record in history
      const existingIndex = this.vaultItems.findIndex(i => i.id === this.activeItem.id);
      if (existingIndex !== -1 && this.vaultItems[existingIndex].password && this.vaultItems[existingIndex].password !== newPassword) {
        if (!this.activeItem.history) this.activeItem.history = [];
        this.activeItem.history.unshift({
          password: this.vaultItems[existingIndex].password,
          date: now
        });
      }

      updatedItem = {
        ...updatedItem,
        name: name || url,
        url,
        username,
        password: newPassword,
        totp: totp || undefined,
        history: this.activeItem.history || []
      };
    }

    const existingIndex = this.vaultItems.findIndex(i => i.id === this.activeItem.id);
    if (existingIndex !== -1) {
      this.vaultItems[existingIndex] = updatedItem;
    } else {
      this.vaultItems.unshift(updatedItem);
    }

    await StorageEngine.saveVaultItems(this.vaultItems, this.vaultKey);
    this.closeDrawer();
    this.renderMainView();
    UI.showToast('Credential securely saved!', 'success');
  }

  async deleteActiveItem() {
    if (!this.activeItem) return;

    const idx = this.vaultItems.findIndex(i => i.id === this.activeItem.id);
    if (idx === -1) return;

    if (this.activeItem.trash) {
      // Permanently remove
      if (confirm(`Are you sure you want to permanently delete "${this.activeItem.name || 'this item'}"? This cannot be undone.`)) {
        this.vaultItems.splice(idx, 1);
        UI.showToast('Item permanently deleted', 'info');
      } else {
        return;
      }
    } else {
      // Move to trash
      this.vaultItems[idx].trash = true;
      this.vaultItems[idx].deletedAt = new Date().toISOString();
      UI.showToast('Moved to Trash', 'info');
    }

    await StorageEngine.saveVaultItems(this.vaultItems, this.vaultKey);
    this.closeDrawer();
    this.renderMainView();
  }

  async restoreActiveItem() {
    if (!this.activeItem) return;
    const idx = this.vaultItems.findIndex(i => i.id === this.activeItem.id);
    if (idx === -1) return;

    this.vaultItems[idx].trash = false;
    delete this.vaultItems[idx].deletedAt;
    await StorageEngine.saveVaultItems(this.vaultItems, this.vaultKey);
    this.closeDrawer();
    this.renderMainView();
    UI.showToast('Credential restored to vault!', 'success');
  }

  async emptyTrash() {
    const trashCount = this.vaultItems.filter(i => i.trash).length;
    if (trashCount === 0) {
      UI.showToast('Trash is already empty.', 'info');
      return;
    }

    if (!confirm(`Are you sure you want to permanently delete all ${trashCount} items in Trash? This cannot be undone.`)) {
      return;
    }

    this.vaultItems = this.vaultItems.filter(i => !i.trash);
    await StorageEngine.saveVaultItems(this.vaultItems, this.vaultKey);
    this.renderMainView();
    UI.showToast(`Permanently deleted ${trashCount} trashed items.`, 'success');
  }

  /* =========================================================
     6. Security Checkup View
     ========================================================= */
  renderSecurityCheckup() {
    const activeLogins = this.vaultItems.filter(i => (i.category === 'login' || !i.category) && !i.trash);
    const audit = SecurityEngine.runAudit(activeLogins);

    // Update Dial
    const progressCircle = document.getElementById('checkup-dial-progress');
    const scoreText = document.getElementById('checkup-score-number');
    const gradeBadge = document.getElementById('checkup-grade-badge');
    const statusDesc = document.getElementById('checkup-status-desc');

    scoreText.textContent = `${audit.score}%`;
    gradeBadge.textContent = `Grade ${audit.grade}`;
    statusDesc.textContent = audit.statusLabel;

    // Circumference for r=32 is 2 * PI * 32 = 201.06
    const circumference = 201;
    const offset = circumference - (audit.score / 100) * circumference;
    progressCircle.style.strokeDasharray = `${circumference}`;
    progressCircle.style.strokeDashoffset = `${offset}`;

    // Render Compromised / Pattern items
    const compContainer = document.getElementById('checkup-compromised-list');
    if (audit.compromisedItems.length === 0) {
      compContainer.innerHTML = '<div style="color:var(--status-safe);font-size:0.875rem;padding:6px 0;">✓ No known compromised password patterns detected!</div>';
    } else {
      compContainer.innerHTML = audit.compromisedItems.map(({ item, reason }) => `
        <div class="checkup-item-row">
          <div>
            <div style="font-weight:600;font-size:0.9rem;">${UI.escapeHTML(item.name)}</div>
            <div style="font-size:0.775rem;color:var(--status-danger);">${UI.escapeHTML(reason)}</div>
          </div>
          <button class="btn btn-secondary" style="font-size:0.75rem;padding:4px 10px;" data-checkup-fix="${item.id}">Fix Now</button>
        </div>
      `).join('');
    }

    // Render Reused Groups
    const reusedContainer = document.getElementById('checkup-reused-list');
    if (audit.reusedGroups.length === 0) {
      reusedContainer.innerHTML = '<div style="color:var(--status-safe);font-size:0.875rem;padding:6px 0;">✓ All passwords are fully unique!</div>';
    } else {
      reusedContainer.innerHTML = audit.reusedGroups.map(group => `
        <div style="display:flex;flex-direction:column;gap:8px;background:var(--bg-input);padding:12px;border-radius:var(--radius-md);border:1px solid var(--border-subtle);">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <span style="font-size:0.85rem;color:var(--status-warning);font-weight:600;">Reused on ${group.count} accounts (${group.passwordPreview})</span>
          </div>
          <div style="display:flex;flex-direction:column;gap:6px;">
            ${group.items.map(item => `
              <div style="display:flex;justify-content:space-between;align-items:center;padding:4px 0;">
                <span style="font-size:0.875rem;">${UI.escapeHTML(item.name)} <span style="color:var(--text-muted);font-size:0.8rem;">(${UI.escapeHTML(item.username || '')})</span></span>
                <button class="btn btn-secondary" style="font-size:0.75rem;padding:3px 8px;" data-checkup-fix="${item.id}">Change</button>
              </div>
            `).join('')}
          </div>
        </div>
      `).join('');
    }

    // Render Weak items
    const weakContainer = document.getElementById('checkup-weak-list');
    if (audit.weakItems.length === 0) {
      weakContainer.innerHTML = '<div style="color:var(--status-safe);font-size:0.875rem;padding:6px 0;">✓ No weak passwords found!</div>';
    } else {
      weakContainer.innerHTML = audit.weakItems.map(({ item, reason }) => `
        <div class="checkup-item-row">
          <div>
            <div style="font-weight:600;font-size:0.9rem;">${UI.escapeHTML(item.name)}</div>
            <div style="font-size:0.775rem;color:var(--status-danger);">${UI.escapeHTML(reason)}</div>
          </div>
          <button class="btn btn-secondary" style="font-size:0.75rem;padding:4px 10px;" data-checkup-fix="${item.id}">Upgrade</button>
        </div>
      `).join('');
    }

    // Bind Fix buttons to open drawer directly
    document.querySelectorAll('[data-checkup-fix]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const id = e.target.dataset.checkupFix;
        const item = this.vaultItems.find(i => i.id === id);
        if (item) this.openDetailDrawer(item);
      });
    });
  }

  /* =========================================================
     7. Settings & Sync Handlers
     ========================================================= */
  async renderSettings() {
    document.getElementById('setting-autolock-select').value = this.prefs.autoLockMinutes;
    document.getElementById('setting-clipboard-timer').value = this.prefs.autoClearClipboardSec || 30;
    document.getElementById('setting-theme-toggle').checked = this.prefs.theme === 'light';

    // Biometric settings availability & toggle check
    const bioToggle = document.getElementById('setting-biometric-toggle');
    const bioNote = document.getElementById('biometric-availability-note');
    if (bioToggle && bioNote) {
      try {
        const bioData = await StorageEngine.getBiometricData();
        const hasWebAuthn = !!(window.PublicKeyCredential &&
          await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable());

        if (hasWebAuthn) {
          bioToggle.disabled = false;
          bioToggle.checked = !!(bioData && bioData.enabled);
          bioNote.textContent = bioToggle.checked
            ? '✓ Windows Hello / Biometric quick unlock is active'
            : 'Platform authenticator available (Windows Hello / Touch ID)';
          bioNote.style.color = bioToggle.checked ? 'var(--status-safe)' : 'var(--text-muted)';
        } else {
          bioToggle.disabled = true;
          bioToggle.checked = false;
          bioNote.textContent = 'Platform authenticator not supported on this browser/device';
          bioNote.style.color = 'var(--text-muted)';
        }
      } catch {
        bioToggle.disabled = true;
      }
    }
  }

  bindSettingsEvents() {
    // Theme Switch
    document.getElementById('setting-theme-toggle')?.addEventListener('change', async (e) => {
      const theme = e.target.checked ? 'light' : 'dark';
      this.prefs.theme = theme;
      this.applyTheme(theme);
      await StorageEngine.savePreferences(this.prefs);
    });

    // Auto-Lock change
    document.getElementById('setting-autolock-select')?.addEventListener('change', async (e) => {
      this.prefs.autoLockMinutes = parseInt(e.target.value, 10);
      await StorageEngine.savePreferences(this.prefs);
      this.resetInactivityTimer();
      UI.showToast(`Auto-lock set to ${this.prefs.autoLockMinutes} minutes`, 'success');
    });

    // Biometric Quick Unlock Toggle
    document.getElementById('setting-biometric-toggle')?.addEventListener('change', async (e) => {
      const toggle = e.target;
      if (toggle.checked) {
        const success = await this.registerBiometrics();
        if (!success) {
          toggle.checked = false;
        } else {
          this.renderSettings();
        }
      } else {
        await StorageEngine.removeBiometricData();
        UI.showToast('Biometric quick unlock disabled.', 'info');
        this.renderSettings();
      }
    });

    // Emergency Kit Download & Print Buttons (Settings section)
    document.getElementById('btn-download-emergency-kit')?.addEventListener('click', () => {
      this.downloadEmergencyKit();
    });

    document.getElementById('btn-print-emergency-kit')?.addEventListener('click', () => {
      this.openEmergencyKit(true);
    });

    // Emergency Kit Modal Actions
    document.getElementById('btn-kit-download')?.addEventListener('click', () => {
      this.downloadEmergencyKit();
    });

    document.getElementById('btn-kit-print')?.addEventListener('click', () => {
      this.printEmergencyKit();
    });

    // Google CSV Export
    document.getElementById('btn-export-google-csv')?.addEventListener('click', () => {
      const csv = ImportExportEngine.exportGoogleCSV(this.vaultItems);
      ImportExportEngine.triggerDownload(csv, `Toggle_Passwords_${new Date().toISOString().slice(0, 10)}.csv`);
      UI.showToast('Exported Google-compatible CSV', 'success');
    });

    // Encrypted JSON Export
    document.getElementById('btn-export-json')?.addEventListener('click', () => {
      const exportPayload = {
        app: 'Toggle Password Manager',
        version: 1,
        exportedAt: new Date().toISOString(),
        items: this.vaultItems
      };
      ImportExportEngine.triggerDownload(
        JSON.stringify(exportPayload, null, 2),
        `Toggle_Vault_Backup_${new Date().toISOString().slice(0, 10)}.json`,
        'application/json'
      );
      UI.showToast('Vault backup downloaded', 'success');
    });

    // Google CSV File Input
    const csvFileInput = document.getElementById('input-import-google-csv');
    csvFileInput?.addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = async (event) => {
        try {
          const csvText = event.target.result;
          const imported = ImportExportEngine.importGoogleCSV(csvText);

          if (imported.length === 0) {
            UI.showToast('No valid passwords found in CSV file.', 'danger');
            return;
          }

          // Merge imported items into vault
          this.vaultItems.unshift(...imported);
          await StorageEngine.saveVaultItems(this.vaultItems, this.vaultKey);
          this.renderMainView();
          UI.showToast(`Successfully imported ${imported.length} accounts from Google Chrome!`, 'success');
          csvFileInput.value = '';
        } catch (err) {
          UI.showToast('Import Error: ' + err.message, 'danger');
        }
      };
      reader.readAsText(file);
    });

    // Factory Reset Vault (Erase Data)
    document.getElementById('btn-wipe-vault')?.addEventListener('click', async () => {
      const confirmed = confirm('DANGER: This will permanently erase your local encrypted vault and all passwords. Are you absolutely certain?');
      if (confirmed) {
        await StorageEngine.wipeAllData();
        window.location.reload();
      }
    });
  }

  applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('toggle_theme', theme);

    // Top Bar Theme Elements
    const sunIcon = document.getElementById('theme-icon-sun');
    const moonIcon = document.getElementById('theme-icon-moon');
    const themeLabel = document.getElementById('theme-toggle-label');

    // Auth Screen Theme Elements
    const authSunIcon = document.getElementById('auth-theme-icon-sun');
    const authMoonIcon = document.getElementById('auth-theme-icon-moon');
    const authThemeLabel = document.getElementById('auth-theme-label');

    const settingsToggle = document.getElementById('setting-theme-toggle');

    if (theme === 'light') {
      if (sunIcon) sunIcon.style.display = 'none';
      if (moonIcon) moonIcon.style.display = 'block';
      if (themeLabel) themeLabel.textContent = 'Dark Theme';

      if (authSunIcon) authSunIcon.style.display = 'none';
      if (authMoonIcon) authMoonIcon.style.display = 'block';
      if (authThemeLabel) authThemeLabel.textContent = 'Dark Theme';

      if (settingsToggle) settingsToggle.checked = true;
      document.querySelector('meta[name="theme-color"]')?.setAttribute('content', '#f9fafb');
    } else {
      if (sunIcon) sunIcon.style.display = 'block';
      if (moonIcon) moonIcon.style.display = 'none';
      if (themeLabel) themeLabel.textContent = 'White Theme';

      if (authSunIcon) authSunIcon.style.display = 'block';
      if (authMoonIcon) authMoonIcon.style.display = 'none';
      if (authThemeLabel) authThemeLabel.textContent = 'White Theme';

      if (settingsToggle) settingsToggle.checked = false;
      document.querySelector('meta[name="theme-color"]')?.setAttribute('content', '#11141a');
    }
  }

  async toggleTheme() {
    const newTheme = this.prefs.theme === 'light' ? 'dark' : 'light';
    this.prefs.theme = newTheme;
    this.applyTheme(newTheme);
    await StorageEngine.savePreferences(this.prefs);
    UI.showToast(`Switched to ${newTheme === 'light' ? 'White' : 'Dark'} theme`, 'info', 1800);
  }

  async loadDemoData() {
    if (!this.vaultKey) {
      UI.showToast('Please unlock or set up your vault first.', 'info');
      return;
    }

    const now = new Date().toISOString();
    const sampleItems = [
      {
        id: 'sample_google',
        name: 'Google Account',
        url: 'https://accounts.google.com',
        username: 'alex.developer@gmail.com',
        password: 'P@ssw0rd12345!',
        category: 'login',
        notes: 'Primary personal Google and YouTube account.',
        favorite: true,
        createdAt: now,
        updatedAt: now
      },
      {
        id: 'sample_github',
        name: 'GitHub',
        url: 'https://github.com/login',
        username: 'alex-dev-2026',
        password: 'G1tHub#Secur3$Key99!',
        category: 'login',
        notes: 'SSH key passphrases and developer personal access tokens.',
        favorite: true,
        createdAt: now,
        updatedAt: now
      },
      {
        id: 'sample_netflix',
        name: 'Netflix',
        url: 'https://netflix.com',
        username: 'alex.developer@gmail.com',
        password: 'P@ssw0rd12345!',
        category: 'login',
        notes: 'Family streaming plan (Standard 4K). Reused password.',
        favorite: false,
        createdAt: now,
        updatedAt: now
      },
      {
        id: 'sample_spotify',
        name: 'Spotify',
        url: 'https://spotify.com',
        username: 'alex-spotify',
        password: 'password123',
        category: 'login',
        notes: 'Spotify Premium membership. Compromised dictionary keyword.',
        favorite: false,
        createdAt: now,
        updatedAt: now
      },
      {
        id: 'sample_card',
        name: 'Chase Sapphire Reserve',
        url: 'https://chase.com',
        username: 'Alex Mahmood',
        password: '891',
        cardHolder: 'Alex Mahmood',
        cardNumber: '4532 8921 4092 5678',
        cardExp: '12/28',
        cardCvv: '891',
        cardPin: '4092',
        cardBrand: 'Visa',
        category: 'card',
        notes: 'Travel card with $300 annual credit.',
        favorite: true,
        createdAt: now,
        updatedAt: now
      },
      {
        id: 'sample_address',
        name: 'Home Address',
        url: '+1 (512) 555-0199',
        username: 'Alex Mahmood',
        recipient: 'Alex Mahmood',
        street1: '123 Main Street',
        street2: 'Suite 4B',
        city: 'Austin',
        state: 'TX',
        zip: '78701',
        country: 'United States',
        phone: '+1 (512) 555-0199',
        category: 'address',
        notes: 'Primary home address for shipping. Gate code #4912.',
        favorite: false,
        createdAt: now,
        updatedAt: now
      },
      {
        id: 'sample_apikey',
        name: 'OpenAI API Key',
        url: 'https://api.openai.com/v1',
        username: 'DEV',
        password: 'sk-proj-Abc123XyzSecretDevKey456789',
        apiKey: 'sk-proj-Abc123XyzSecretDevKey456789',
        apiUrl: 'https://api.openai.com/v1',
        apiEnv: 'development',
        apiExpiry: '2027-12-31',
        category: 'apikey',
        notes: 'Development key for GPT-4o integration. Monthly limit: $50.',
        favorite: true,
        createdAt: now,
        updatedAt: now
      },
      {
        id: 'sample_note',
        name: 'Server Recovery Passphrase',
        category: 'note',
        noteBody: 'Master SSH Key fingerprint:\nSHA256:4e3a8901bca9823f99017bc42\n\nEmergency cold storage seed:\n9812-4412-9018-3312-7712\nRack #12 DataCenter B',
        notes: 'Encrypted server recovery credentials.',
        favorite: true,
        createdAt: now,
        updatedAt: now
      }
    ];

    this.vaultItems = sampleItems;
    await StorageEngine.saveVaultItems(this.vaultItems, this.vaultKey);
    this.renderMainView();
    UI.showToast('Loaded sample credentials with cards, addresses, and API keys!', 'success');
  }

  /* =========================================================
     8. Generator Dialog & Sliders
     ========================================================= */
  bindGeneratorEvents() {
    const lengthSlider = document.getElementById('gen-length-slider');
    const lengthPill = document.getElementById('gen-length-value');
    const passwordDisplay = document.getElementById('gen-result-display');
    const refreshBtn = document.getElementById('gen-refresh-btn');
    const copyBtn = document.getElementById('gen-copy-btn');

    const generateCurrent = () => {
      const mode = document.querySelector('input[name="gen-mode"]:checked')?.value || 'password';
      if (mode === 'password') {
        const length = parseInt(lengthSlider.value, 10);
        const uppercase = document.getElementById('gen-opt-upper').checked;
        const lowercase = document.getElementById('gen-opt-lower').checked;
        const numbers = document.getElementById('gen-opt-numbers').checked;
        const symbols = document.getElementById('gen-opt-symbols').checked;
        const avoidAmbiguous = document.getElementById('gen-opt-ambiguous').checked;

        const pwd = GeneratorEngine.generatePassword({
          length, uppercase, lowercase, numbers, symbols, avoidAmbiguous
        });
        passwordDisplay.value = pwd;
        this.updateModalStrength(pwd);
      } else {
        const wordCount = parseInt(document.getElementById('gen-words-slider').value, 10);
        const phrase = GeneratorEngine.generatePassphrase(wordCount, '-', true, true);
        passwordDisplay.value = phrase;
        this.updateModalStrength(phrase);
      }
    };

    lengthSlider?.addEventListener('input', (e) => {
      lengthPill.textContent = e.target.value;
      generateCurrent();
    });

    document.querySelectorAll('#generator-modal input[type="checkbox"]').forEach(c => {
      c.addEventListener('change', generateCurrent);
    });

    document.querySelectorAll('input[name="gen-mode"]').forEach(r => {
      r.addEventListener('change', (e) => {
        const isPassphrase = e.target.value === 'passphrase';
        document.getElementById('gen-password-controls').style.display = isPassphrase ? 'none' : 'block';
        document.getElementById('gen-passphrase-controls').style.display = isPassphrase ? 'block' : 'none';
        generateCurrent();
      });
    });

    document.getElementById('gen-words-slider')?.addEventListener('input', (e) => {
      document.getElementById('gen-words-value').textContent = e.target.value;
      generateCurrent();
    });

    refreshBtn?.addEventListener('click', generateCurrent);
    copyBtn?.addEventListener('click', () => {
      if (passwordDisplay.value) {
        UI.copySecure(passwordDisplay.value, 'Generated Password');
      }
    });

    // Quick fill to active drawer
    document.getElementById('gen-fill-drawer-btn')?.addEventListener('click', () => {
      const pwd = passwordDisplay.value;
      if (pwd) {
        const drawerPwd = document.getElementById('edit-item-password');
        if (drawerPwd) {
          drawerPwd.value = pwd;
          this.updateDrawerPasswordStrength(pwd);
        }
        UI.closeModal('generator-modal');
        UI.showToast('Applied to current password form', 'success');
      }
    });
  }

  updateModalStrength(password) {
    const strength = GeneratorEngine.evaluateStrength(password);
    const container = document.getElementById('modal-strength-meter');
    if (container) {
      container.className = `strength-meter strength-level-${strength.score}`;
      document.getElementById('modal-strength-label').textContent = strength.label;
      document.getElementById('modal-crack-time').textContent = `Crack time: ${strength.crackTimeText}`;
    }
  }

  /* =========================================================
     9. Global & Drawer Event Bindings
     ========================================================= */
  bindGlobalEvents() {
    // Activity listener for auto-lock
    ['mousemove', 'keydown', 'click', 'scroll'].forEach(evt => {
      window.addEventListener(evt, () => {
        if (this.vaultKey) this.resetInactivityTimer();
      }, { passive: true });
    });

    // Top Bar Search
    const searchInput = document.getElementById('top-search-input');
    searchInput?.addEventListener('input', (e) => {
      this.searchQuery = e.target.value.trim();
      this.renderVaultCards();
    });

    // Sort Dropdown
    document.getElementById('vault-sort-select')?.addEventListener('change', (e) => {
      this.sortBy = e.target.value;
      this.renderVaultCards();
    });

    // New Item Buttons
    document.querySelectorAll('[data-action="new-item"]').forEach(btn => {
      btn.addEventListener('click', () => this.openDetailDrawer(null));
    });

    // Quick Lock Button
    document.getElementById('btn-quick-lock')?.addEventListener('click', () => this.lockVault());

    // Top Bar Theme Switcher (White / Dark)
    document.getElementById('btn-top-theme')?.addEventListener('click', () => this.toggleTheme());

    // Load Demo Data buttons
    document.getElementById('btn-load-demo-empty')?.addEventListener('click', () => this.loadDemoData());
    document.getElementById('btn-load-demo-settings')?.addEventListener('click', () => this.loadDemoData());

    // Generator Modal Trigger
    document.getElementById('btn-open-generator')?.addEventListener('click', () => {
      UI.openModal('generator-modal');
      document.getElementById('gen-refresh-btn')?.click();
    });

    // Live Breach Scan Trigger (Checkup view)
    document.getElementById('btn-live-breach-scan')?.addEventListener('click', () => {
      this.handleLiveBreachScan();
    });

    // Sidebar Category clicks
    document.querySelectorAll('.sidebar-nav .nav-item').forEach(item => {
      item.addEventListener('click', () => {
        this.currentCategory = item.dataset.category;
        this.renderMainView();
      });
    });

    // Modal Close buttons
    document.querySelectorAll('[data-modal-close]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const modal = e.target.closest('.modal-overlay');
        if (modal) modal.classList.remove('active');
      });
    });

    // ---- Hamburger: Toggle Sidebar ----
    document.getElementById('btn-toggle-sidebar')?.addEventListener('click', () => {
      const sidebar = document.getElementById('app-sidebar');
      sidebar?.classList.toggle('collapsed');
    });

    // ---- Helper: close all top-bar dropdowns ----
    const closeAllDropdowns = () => {
      document.getElementById('notifications-dropdown')?.classList.remove('active');
      document.getElementById('waffle-dropdown')?.classList.remove('active');
      document.getElementById('profile-dropdown')?.classList.remove('active');
    };

    // ---- Notifications Bell Dropdown ----
    document.getElementById('btn-notifications')?.addEventListener('click', (e) => {
      e.stopPropagation();
      const dd = document.getElementById('notifications-dropdown');
      const isOpen = dd?.classList.contains('active');
      closeAllDropdowns();
      if (!isOpen) dd?.classList.add('active');
    });

    // ---- Help modal ----
    document.getElementById('btn-help')?.addEventListener('click', () => {
      closeAllDropdowns();
      UI.openModal('help-modal');
    });

    // ---- 9-Dot Waffle Dropdown ----
    document.getElementById('btn-waffle')?.addEventListener('click', (e) => {
      e.stopPropagation();
      const dd = document.getElementById('waffle-dropdown');
      const isOpen = dd?.classList.contains('active');
      closeAllDropdowns();
      if (!isOpen) dd?.classList.add('active');
    });

    // ---- Profile Dropdown ----
    document.getElementById('btn-profile')?.addEventListener('click', (e) => {
      e.stopPropagation();
      const dd = document.getElementById('profile-dropdown');
      const isOpen = dd?.classList.contains('active');
      closeAllDropdowns();
      if (!isOpen) dd?.classList.add('active');
    });

    // Profile → Toggle Theme
    document.getElementById('profile-toggle-theme')?.addEventListener('click', () => {
      closeAllDropdowns();
      this.toggleTheme();
    });

    // Profile → Load Samples
    document.getElementById('profile-load-samples')?.addEventListener('click', () => {
      closeAllDropdowns();
      this.loadDemoData();
    });

    // Waffle → Load Sample Data
    document.getElementById('waffle-demo-btn')?.addEventListener('click', () => {
      closeAllDropdowns();
      this.loadDemoData();
    });

    // Close all dropdowns when clicking outside
    document.addEventListener('click', () => closeAllDropdowns());

    // Keyboard Shortcuts
    window.addEventListener('keydown', (e) => {
      // Ctrl+K or '/' for search
      if ((e.ctrlKey && e.key === 'k') || (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA')) {
        e.preventDefault();
        document.getElementById('top-search-input')?.focus();
      }

      // Ctrl+L for Quick Lock
      if (e.ctrlKey && e.key === 'l') {
        e.preventDefault();
        this.lockVault();
      }

      // Esc to close drawers / modals / dropdowns
      if (e.key === 'Escape') {
        closeAllDropdowns();
        this.closeDrawer();
        document.querySelectorAll('.modal-overlay').forEach(m => m.classList.remove('active'));
      }
    });
  }

  bindAuthEvents() {
    // Auth screen theme toggle
    document.getElementById('btn-auth-theme')?.addEventListener('click', () => this.toggleTheme());

    document.getElementById('setup-form')?.addEventListener('submit', (e) => this.handleSetupSubmit(e));
    document.getElementById('unlock-form')?.addEventListener('submit', (e) => this.handleUnlockSubmit(e));

    // Unlock peek password toggle
    document.getElementById('unlock-reveal-btn')?.addEventListener('click', () => {
      const input = document.getElementById('unlock-password');
      if (input) {
        input.type = input.type === 'password' ? 'text' : 'password';
      }
    });

    document.getElementById('btn-goto-recovery')?.addEventListener('click', () => this.showRecoveryScreen());
    document.getElementById('btn-back-to-unlock')?.addEventListener('click', () => this.showUnlockScreen());

    document.getElementById('recovery-form')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const phrase = document.getElementById('recovery-phrase-input').value;
      const newPwd = document.getElementById('recovery-new-password').value;

      if (!phrase || !newPwd || newPwd.length < 8) {
        UI.showToast('Please provide valid recovery phrase and minimum 8 char password.', 'danger');
        return;
      }

      try {
        const key = await StorageEngine.unlockWithRecovery(phrase, newPwd);
        this.vaultKey = key;
        this.vaultItems = await StorageEngine.loadVaultItems(key);
        this.finishUnlock();
        UI.showToast('Master password reset and vault unlocked!', 'success');
      } catch (err) {
        UI.showToast(err.message, 'danger');
      }
    });

    // Biometric Quick Unlock button
    document.getElementById('btn-biometric-unlock')?.addEventListener('click', () => {
      this.unlockWithBiometrics();
    });
  }

  bindDrawerEvents() {
    document.getElementById('drawer-close-btn')?.addEventListener('click', () => this.closeDrawer());
    document.getElementById('drawer-save-btn')?.addEventListener('click', () => this.saveActiveItem());
    document.getElementById('drawer-delete-btn')?.addEventListener('click', () => this.deleteActiveItem());
    document.getElementById('drawer-restore-btn')?.addEventListener('click', () => this.restoreActiveItem());
    document.getElementById('btn-empty-trash')?.addEventListener('click', () => this.emptyTrash());

    // Category switch in drawer
    document.getElementById('edit-item-category')?.addEventListener('change', (e) => {
      this.updateDrawerCategoryFields(e.target.value);
    });

    // Real-time strength meter in drawer
    const drawerPwd = document.getElementById('edit-item-password');
    drawerPwd?.addEventListener('input', (e) => {
      this.updateDrawerPasswordStrength(e.target.value);
    });

    // Drawer password reveal toggle
    document.getElementById('drawer-pwd-toggle-btn')?.addEventListener('click', () => {
      const type = drawerPwd.type === 'password' ? 'text' : 'password';
      drawerPwd.type = type;
    });

    // API Key reveal toggle
    const apikeyInput = document.getElementById('edit-apikey-token');
    document.getElementById('drawer-apikey-toggle-btn')?.addEventListener('click', () => {
      if (apikeyInput) {
        apikeyInput.type = apikeyInput.type === 'password' ? 'text' : 'password';
      }
    });

    // Card Number input formatter & brand detection
    const cardNumInput = document.getElementById('edit-card-number');
    cardNumInput?.addEventListener('input', (e) => {
      const cursor = e.target.selectionStart;
      const formatted = this.formatCardNumber(e.target.value);
      e.target.value = formatted;
      this.updateCardBrandBadge(formatted);
    });

    // Card Expiry formatter (MM/YY)
    const cardExpInput = document.getElementById('edit-card-exp');
    cardExpInput?.addEventListener('input', (e) => {
      e.target.value = this.formatCardExp(e.target.value);
    });

    // Drawer generate button
    document.getElementById('drawer-pwd-generate-btn')?.addEventListener('click', () => {
      UI.openModal('generator-modal');
      document.getElementById('gen-refresh-btn')?.click();
    });

    // Drawer TOTP secret input listener
    const drawerTotpInput = document.getElementById('edit-item-totp');
    drawerTotpInput?.addEventListener('input', () => {
      this.updateDrawerTOTP();
    });

    // Drawer TOTP paste button
    document.getElementById('drawer-totp-paste-btn')?.addEventListener('click', async () => {
      try {
        const text = await navigator.clipboard.readText();
        if (drawerTotpInput && text) {
          drawerTotpInput.value = text.trim();
          this.updateDrawerTOTP();
          UI.showToast('Pasted 2FA secret from clipboard', 'info');
        }
      } catch (err) {
        UI.showToast('Unable to read clipboard', 'warning');
      }
    });

    // Drawer copy TOTP code button
    document.getElementById('drawer-totp-copy-btn')?.addEventListener('click', () => {
      if (this.currentDrawerTotpCode) {
        UI.copySecure(this.currentDrawerTotpCode, '2FA Authentication Code');
      }
    });
  }

  /* =========================================================
     Phase 3: Biometric Authentication (WebAuthn / Windows Hello)
     ========================================================= */
  async checkAndShowBiometricButton() {
    const unlockBtn = document.getElementById('btn-biometric-unlock');
    const divider = document.getElementById('biometric-divider');
    if (!unlockBtn) return;

    try {
      const bioData = await StorageEngine.getBiometricData();
      const hasWebAuthn = !!(window.PublicKeyCredential &&
        await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable());

      if (bioData && bioData.enabled && hasWebAuthn) {
        unlockBtn.style.display = 'flex';
        if (divider) divider.style.display = 'flex';
      } else {
        unlockBtn.style.display = 'none';
        if (divider) divider.style.display = 'none';
      }
    } catch {
      unlockBtn.style.display = 'none';
      if (divider) divider.style.display = 'none';
    }
  }

  async registerBiometrics() {
    if (!this.vaultKey) {
      UI.showToast('Please unlock your vault before configuring biometrics.', 'info');
      return false;
    }

    if (!window.PublicKeyCredential) {
      UI.showToast('WebAuthn is not supported in this browser.', 'danger');
      return false;
    }

    try {
      const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      if (!available) {
        UI.showToast('No platform authenticator (Windows Hello / Touch ID) found on this device.', 'danger');
        return false;
      }

      const challenge = CryptoEngine.getRandomBytes(32);
      const userId = CryptoEngine.getRandomBytes(16);

      const credential = await navigator.credentials.create({
        publicKey: {
          challenge: challenge,
          rp: {
            name: 'Toggle Password Manager'
          },
          user: {
            id: userId,
            name: 'toggle-vault-user',
            displayName: 'Toggle Vault User'
          },
          pubKeyCredParams: [
            { type: 'public-key', alg: -7 },   // ES256
            { type: 'public-key', alg: -257 }  // RS256
          ],
          authenticatorSelection: {
            authenticatorAttachment: 'platform',
            userVerification: 'required'
          },
          timeout: 60000
        }
      });

      if (!credential) {
        throw new Error('Biometric setup cancelled or timed out.');
      }

      // Convert rawId to Base64
      const credIdBase64 = CryptoEngine.bufferToBase64(credential.rawId);

      // Export raw vault key and wrap it
      const rawVaultKeyBase64 = await CryptoEngine.exportKeyRaw(this.vaultKey);
      const bioSalt = CryptoEngine.getRandomBytes(16);
      const bioSaltHex = CryptoEngine.bufferToHex(bioSalt);

      // Derive device wrapping key from credentialId + bioSalt
      const wrappingKey = await CryptoEngine.deriveKey(credIdBase64, bioSalt, 10000, false);
      const wrapped = await CryptoEngine.encrypt(rawVaultKeyBase64, wrappingKey);

      await StorageEngine.saveBiometricData(credIdBase64, {
        ciphertext: wrapped.ciphertext,
        iv: wrapped.iv,
        saltHex: bioSaltHex
      });

      UI.showToast('Windows Hello / Biometric unlock successfully enabled!', 'success');
      return true;
    } catch (err) {
      console.warn('Biometric registration error:', err);
      UI.showToast(err.name === 'NotAllowedError' ? 'Biometric registration cancelled.' : ('Biometrics setup: ' + err.message), 'danger');
      return false;
    }
  }

  async unlockWithBiometrics() {
    try {
      const bioData = await StorageEngine.getBiometricData();
      if (!bioData || !bioData.credentialId) {
        UI.showToast('No biometric credential configured.', 'info');
        return;
      }

      const challenge = CryptoEngine.getRandomBytes(32);
      const credBuffer = CryptoEngine.base64ToBuffer(bioData.credentialId);

      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge: challenge,
          allowCredentials: [{
            id: credBuffer,
            type: 'public-key'
          }],
          userVerification: 'required',
          timeout: 60000
        }
      });

      if (!assertion) {
        throw new Error('Biometric verification cancelled.');
      }

      // Derive device wrapping key and decrypt vault key
      const bioSalt = CryptoEngine.hexToBuffer(bioData.saltHex);
      const wrappingKey = await CryptoEngine.deriveKey(bioData.credentialId, bioSalt, 10000, false);
      const rawVaultKeyBase64 = await CryptoEngine.decrypt(bioData.ciphertext, bioData.iv, wrappingKey);

      // Import unwrapped key
      this.vaultKey = await CryptoEngine.importKeyRaw(rawVaultKeyBase64, true);
      this.vaultItems = await StorageEngine.loadVaultItems(this.vaultKey);
      this.finishUnlock();
      UI.showToast('Unlocked with Windows Hello / Biometrics', 'success');
    } catch (err) {
      console.warn('Biometric unlock error:', err);
      if (err.name !== 'NotAllowedError') {
        UI.showToast('Biometric unlock: ' + err.message, 'danger');
      }
    }
  }

  /* =========================================================
     Phase 3: Live Breach Scanning (HaveIBeenPwned k-Anonymity)
     ========================================================= */
  async handleLiveBreachScan() {
    const scanBtn = document.getElementById('btn-live-breach-scan');
    const progressWrap = document.getElementById('breach-scan-progress-wrap');
    const progressBar = document.getElementById('breach-scan-progress-bar');
    const statusText = document.getElementById('breach-scan-status-text');
    const counterText = document.getElementById('breach-scan-counter');
    const resultsContainer = document.getElementById('breach-scan-results');

    const activeLogins = this.vaultItems.filter(i => (i.category === 'login' || !i.category) && !i.trash && i.password);

    if (activeLogins.length === 0) {
      UI.showToast('No login credentials with passwords in vault to scan.', 'info');
      return;
    }

    if (scanBtn) {
      scanBtn.disabled = true;
      scanBtn.innerHTML = `
        <svg class="spin-icon" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
          <circle cx="12" cy="12" r="10" stroke-opacity="0.25"></circle>
          <path d="M4 12a8 8 0 018-8"></path>
        </svg>
        Scanning...
      `;
    }

    if (progressWrap) progressWrap.style.display = 'block';
    if (progressBar) progressBar.style.width = '0%';
    if (resultsContainer) resultsContainer.innerHTML = '';

    try {
      const summary = await SecurityEngine.runLiveBreachScan(activeLogins, ({ current, total, item }) => {
        const pct = Math.round((current / total) * 100);
        if (progressBar) progressBar.style.width = `${pct}%`;
        if (counterText) counterText.textContent = `${current} / ${total}`;
        if (statusText) statusText.textContent = `Scanning ${item.name || 'item'}...`;
      });

      if (progressWrap) progressWrap.style.display = 'none';

      if (resultsContainer) {
        if (summary.breachedCount === 0) {
          resultsContainer.innerHTML = `
            <div class="breach-scan-all-clear">
              <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/>
              </svg>
              <span>All ${summary.scannedCount} passwords scanned against HaveIBeenPwned. Zero breaches detected!</span>
            </div>
          `;
          UI.showToast(`Zero breaches detected across ${summary.scannedCount} credentials!`, 'success');
        } else {
          const breachedItems = summary.results.filter(r => r.breached);
          resultsContainer.innerHTML = `
            <div style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:8px;padding:10px 14px;color:var(--status-danger);font-size:0.85rem;font-weight:600;">
              ⚠ Found ${summary.breachedCount} password${summary.breachedCount > 1 ? 's' : ''} exposed in public data breaches!
            </div>
            ${breachedItems.map(({ item, count }) => `
              <div class="breach-item-row">
                <div style="min-width:0;flex:1;">
                  <div style="font-weight:600;font-size:0.9rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${UI.escapeHTML(item.name)}</div>
                  <div style="font-size:0.775rem;color:var(--text-muted);">${UI.escapeHTML(item.username || 'No username')}</div>
                </div>
                <span class="breach-count-badge">
                  ${count > 0 ? `Leaked in ${count.toLocaleString()} breaches` : 'Leaked'}
                </span>
                <button class="btn btn-secondary" style="font-size:0.75rem;padding:4px 10px;flex-shrink:0;" data-checkup-fix="${item.id}">
                  Change
                </button>
              </div>
            `).join('')}
          `;

          // Bind change buttons
          resultsContainer.querySelectorAll('[data-checkup-fix]').forEach(btn => {
            btn.addEventListener('click', (e) => {
              const id = e.currentTarget.dataset.checkupFix;
              const itm = this.vaultItems.find(i => i.id === id);
              if (itm) this.openDetailDrawer(itm);
            });
          });

          UI.showToast(`Breach scan found ${summary.breachedCount} exposed password(s)!`, 'danger');
        }
      }
    } catch (err) {
      console.error('Breach scan error:', err);
      UI.showToast('Breach scan encountered an error: ' + err.message, 'danger');
    } finally {
      if (scanBtn) {
        scanBtn.disabled = false;
        scanBtn.innerHTML = `
          <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
          </svg>
          Run Scan
        `;
      }
    }
  }

  /* =========================================================
     Phase 3: Emergency Recovery Kit (Print & Standalone HTML)
     ========================================================= */
  async getRecoveryPhraseForKit() {
    try {
      const meta = await StorageEngine.getVaultMeta();
      if (meta?.encryptedRecoveryPhrase && this.vaultKey) {
        return await CryptoEngine.decrypt(
          meta.encryptedRecoveryPhrase.ciphertext,
          meta.encryptedRecoveryPhrase.iv,
          this.vaultKey
        );
      }
    } catch (e) {
      console.warn('Could not decrypt stored recovery phrase:', e);
    }
    const sessionPhrase = sessionStorage.getItem('toggle_setup_phrase');
    if (sessionPhrase) return sessionPhrase;
    return null;
  }

  async openEmergencyKit(autoPrint = false) {
    const phrase = await this.getRecoveryPhraseForKit();
    const meta = await StorageEngine.getVaultMeta();
    const wordGrid = document.getElementById('emergency-kit-word-grid');
    const dateSpan = document.getElementById('emergency-kit-date');

    const createdDate = meta?.createdAt ? new Date(meta.createdAt).toLocaleDateString(undefined, {
      year: 'numeric', month: 'long', day: 'numeric'
    }) : new Date().toLocaleDateString();

    if (dateSpan) dateSpan.textContent = createdDate;

    if (wordGrid) {
      if (phrase) {
        const words = phrase.trim().split(/\s+/);
        wordGrid.innerHTML = words.map((w, idx) => `
          <div class="emergency-word-cell">
            <span class="emergency-word-index">${idx + 1}</span>
            <span class="emergency-word-text">${UI.escapeHTML(w)}</span>
          </div>
        `).join('');
      } else {
        wordGrid.innerHTML = `
          <div style="grid-column:1/-1;background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.25);border-radius:8px;padding:12px;font-size:0.825rem;color:var(--text-secondary);line-height:1.5;">
            Your recovery phrase was saved when this vault was created. If you do not have your 12-word paper backup, please make sure your master password is noted securely in a safe place.
          </div>
        `;
      }
    }

    UI.openModal('emergency-kit-modal');

    if (autoPrint) {
      setTimeout(() => this.printEmergencyKit(), 200);
    }
  }

  async printEmergencyKit() {
    const phrase = await this.getRecoveryPhraseForKit();
    const meta = await StorageEngine.getVaultMeta();
    const createdDate = meta?.createdAt ? new Date(meta.createdAt).toLocaleDateString(undefined, {
      year: 'numeric', month: 'long', day: 'numeric'
    }) : new Date().toLocaleDateString();

    let root = document.getElementById('emergency-print-root');
    if (!root) {
      root = document.createElement('div');
      root.id = 'emergency-print-root';
      document.body.appendChild(root);
    }

    const words = phrase ? phrase.trim().split(/\s+/) : [];

    root.innerHTML = `
      <div class="print-header">
        <h1>TOGGLE PASSWORD MANAGER</h1>
        <p>Emergency Vault Recovery Kit · Store in a Safe, Offline Location</p>
      </div>

      <div style="margin-bottom:16px;font-size:9.5pt;line-height:1.6;color:#333;">
        This document contains your 12-word Emergency Recovery Phrase. If you ever lose or forget your Master Password, this sheet is the <strong>only</strong> way to regain access to your encrypted local vault. Toggle employees or systems cannot recover your password for you.
      </div>

      <div class="print-word-grid">
        ${words.length === 12 ? words.map((w, i) => `
          <div class="print-word-cell">
            <span class="print-word-num">${i + 1}.</span>
            <span class="print-word-val">${UI.escapeHTML(w)}</span>
          </div>
        `).join('') : `
          <div style="grid-column:1/-1;padding:16px;border:1px dashed #666;font-size:10pt;">
            [Recovery Phrase on file: Please write your 12 words here]: ____________________________________
          </div>
        `}
      </div>

      <div class="print-instructions">
        <strong>Important Safety Rules:</strong>
        <ul style="margin:6px 0 0 18px;padding:0;">
          <li>Never photograph this sheet or save it to an unencrypted cloud service.</li>
          <li>Never email or message these words to anyone.</li>
          <li>Store this physical paper in a fireproof safe, safety deposit box, or trusted lockbox.</li>
          <li>To restore access, open Toggle Password Manager, click "Forgot password?", and enter these 12 words.</li>
        </ul>
      </div>

      <div class="print-meta">
        Vault Created: ${createdDate} · Encryption: AES-256-GCM (PBKDF2-SHA256, 600k iterations) · Zero-Knowledge Local Storage
      </div>
    `;

    window.print();
  }

  async downloadEmergencyKit() {
    const phrase = await this.getRecoveryPhraseForKit();
    const meta = await StorageEngine.getVaultMeta();
    const createdDate = meta?.createdAt ? new Date(meta.createdAt).toLocaleDateString(undefined, {
      year: 'numeric', month: 'long', day: 'numeric'
    }) : new Date().toLocaleDateString();

    const words = phrase ? phrase.trim().split(/\s+/) : [];

    const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Toggle Password Manager - Emergency Recovery Kit</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      background: #0f172a;
      color: #f8fafc;
      margin: 0;
      padding: 40px 20px;
      display: flex;
      justify-content: center;
    }
    .sheet {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 16px;
      max-width: 680px;
      width: 100%;
      padding: 36px;
      box-shadow: 0 20px 40px rgba(0,0,0,0.5);
    }
    .header {
      text-align: center;
      border-bottom: 1px solid #334155;
      padding-bottom: 24px;
      margin-bottom: 24px;
    }
    .badge {
      display: inline-block;
      background: rgba(16,185,129,0.15);
      color: #10b981;
      padding: 4px 12px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.05em;
      margin-bottom: 12px;
    }
    h1 {
      margin: 0 0 8px;
      font-size: 24px;
      letter-spacing: -0.02em;
    }
    p {
      margin: 0;
      color: #94a3b8;
      font-size: 14px;
      line-height: 1.6;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 12px;
      margin: 28px 0;
    }
    .cell {
      background: #0f172a;
      border: 1px solid #334155;
      border-radius: 8px;
      padding: 10px 14px;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .num {
      color: #64748b;
      font-size: 12px;
      font-weight: bold;
      min-width: 20px;
    }
    .val {
      font-family: 'Courier New', Courier, monospace;
      font-size: 16px;
      font-weight: bold;
      color: #38bdf8;
    }
    .notice {
      background: rgba(245,158,11,0.1);
      border: 1px solid rgba(245,158,11,0.25);
      border-radius: 10px;
      padding: 16px;
      margin-top: 24px;
      font-size: 13px;
      color: #cbd5e1;
      line-height: 1.6;
    }
    .meta {
      margin-top: 24px;
      border-top: 1px solid #334155;
      padding-top: 16px;
      text-align: center;
      font-size: 12px;
      color: #64748b;
    }
    @media print {
      body { background: #fff; color: #000; padding: 0; }
      .sheet { background: #fff; border: none; box-shadow: none; padding: 20px; max-width: 100%; }
      .cell { background: #f8fafc; border: 1px solid #ccc; }
      .val { color: #000; }
      .notice { border: 1px solid #999; background: #fff; color: #333; }
      .header { border-bottom: 2px solid #000; }
      .meta { border-top: 1px solid #ccc; color: #666; }
    }
  </style>
</head>
<body>
  <div class="sheet">
    <div class="header">
      <div class="badge">OFFLINE EMERGENCY RECOVERY KIT</div>
      <h1>TOGGLE PASSWORD MANAGER</h1>
      <p>Keep this document strictly private and offline in a secure location.</p>
    </div>

    <p>
      If you lose your Master Password, these 12 words are the <strong>only cryptographic method</strong> to unlock your vault. Toggle operates on a Zero-Knowledge architecture: we never possess or store your password, keys, or recovery phrase.
    </p>

    <div class="grid">
      ${words.map((w, i) => `
        <div class="cell">
          <span class="num">${i + 1}.</span>
          <span class="val">${UI.escapeHTML(w)}</span>
        </div>
      `).join('')}
    </div>

    <div class="notice">
      <strong style="color:#f59e0b;">Emergency Kit Best Practices:</strong>
      <ul style="margin:8px 0 0 20px;padding:0;">
        <li>Print this sheet and store the paper in a physical safe or deposit box.</li>
        <li>Do not take a digital photo or store in cloud drives.</li>
        <li>To recover: Open Toggle &rarr; Click "Forgot password?" &rarr; Enter your 12 recovery words.</li>
      </ul>
    </div>

    <div class="meta">
      Vault Created: ${createdDate} &bull; Encryption: AES-256-GCM (PBKDF2-SHA256, 600,000 rounds) &bull; Local-First Zero-Knowledge
    </div>
  </div>
</body>
</html>`;

    ImportExportEngine.triggerDownload(
      htmlContent,
      `Toggle_Emergency_Recovery_Kit_${new Date().toISOString().slice(0, 10)}.html`,

      'text/html'
    );
    UI.showToast('Downloaded Emergency Recovery Kit HTML', 'success');
  }
}

// Instantiate and start app on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  const app = new ToggleApp();
  app.init();
});
