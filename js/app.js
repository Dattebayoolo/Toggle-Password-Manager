/**
 * Toggle Password Manager - Main Application Controller
 */

import { CryptoEngine } from './crypto.js';
import { StorageEngine } from './storage.js';
import { GeneratorEngine } from './generator.js';
import { SecurityEngine } from './security.js';
import { ImportExportEngine } from './importer.js';
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
  }

  async init() {
    this.bindGlobalEvents();
    this.bindAuthEvents();
    this.bindGeneratorEvents();
    this.bindDrawerEvents();
    this.bindSettingsEvents();

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

      // Hide address/apikey from 'all' unless explicitly selected
      if (this.currentCategory === 'all' && (item.category === 'address' || item.category === 'apikey')) {
        // still show them in 'all'
      }

      // Search Query filter
      if (this.searchQuery) {
        const q = this.searchQuery.toLowerCase();
        const matchName = (item.name || '').toLowerCase().includes(q);
        const matchUser = (item.username || '').toLowerCase().includes(q);
        const matchUrl = (item.url || '').toLowerCase().includes(q);
        const matchNotes = (item.notes || '').toLowerCase().includes(q);
        return matchName || matchUser || matchUrl || matchNotes;
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
      const displayPassword = isRevealed ? UI.escapeHTML(item.password || '') : '••••••••••••';
      const strength = GeneratorEngine.evaluateStrength(item.password || '');

      let badgeHTML = '';
      if (item.category === 'note') {
        badgeHTML = `<span class="badge badge-info">Note</span>`;
      } else if (item.category === 'card') {
        badgeHTML = `<span class="badge badge-info">Card</span>`;
      } else if (item.category === 'address') {
        badgeHTML = `<span class="badge badge-info">Address</span>`;
      } else if (item.category === 'apikey') {
        badgeHTML = `<span class="badge badge-info">API Key</span>`;
      } else if (item.category === 'passkey') {
        badgeHTML = `<span class="badge badge-safe">Passkey</span>`;
      } else if (strength.score <= 1 && item.password) {
        badgeHTML = `<span class="badge badge-danger">Weak</span>`;
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
                ${UI.escapeHTML(item.username || item.url || 'No username')}
              </div>
            </div>
          </div>

          <div class="vault-card-center">
            ${item.password ? `
              <div class="vault-password-preview font-mono" id="pwd-preview-${item.id}">
                ${displayPassword}
              </div>
              <!-- Signature Tactile Toggle Reveal -->
              <label class="toggle-switch mini" title="Toggle Show/Hide Password">
                <input type="checkbox" class="password-reveal-toggle" data-id="${item.id}" ${isRevealed ? 'checked' : ''} />
                <span class="toggle-slider"></span>
              </label>
            ` : ''}
          </div>

          <div class="vault-card-actions">
            ${item.username ? `
              <button class="btn-icon" data-action="copy-user" data-id="${item.id}" title="Copy Username">
                <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
                </svg>
              </button>
            ` : ''}

            ${item.password ? `
              <button class="btn-icon" data-action="copy-pwd" data-id="${item.id}" title="Copy Password">
                <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                  <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
              </button>
            ` : ''}

            ${item.url ? `
              <a href="${item.url.startsWith('http') ? item.url : 'https://' + item.url}" 
                 target="_blank" rel="noopener noreferrer" class="btn-icon" title="Open Website" onclick="event.stopPropagation()">
                <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
                </svg>
              </a>
            ` : ''}

            <button class="btn-icon" data-action="open-detail" title="View Details">
              <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M9 5l7 7-7 7"/>
              </svg>
            </button>
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
          if (previewElem) previewElem.textContent = item.password || '';
        } else {
          this.revealedPasswords.delete(id);
          if (previewElem) previewElem.textContent = '••••••••••••';
        }
      });
    });

    // Copy buttons & card click
    document.querySelectorAll('.vault-card').forEach(card => {
      const id = card.dataset.id;
      const item = this.vaultItems.find(i => i.id === id);
      if (!item) return;

      card.addEventListener('click', (e) => {
        const actionBtn = e.target.closest('button');
        if (actionBtn) {
          const action = actionBtn.dataset.action;
          if (action === 'copy-user') {
            UI.copySecure(item.username, 'Username');
            return;
          }
          if (action === 'copy-pwd') {
            UI.copySecure(item.password, 'Password');
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
     5. Sliding Detail & Edit Drawer
     ========================================================= */
  openDetailDrawer(item = null) {
    this.activeItem = item ? JSON.parse(JSON.stringify(item)) : {
      id: 'toggle_' + Math.random().toString(36).substring(2, 9) + Date.now().toString(36),
      name: '',
      url: '',
      username: '',
      password: '',
      notes: '',
      category: this.currentCategory === 'all' || this.currentCategory === 'trash' ? 'login' : this.currentCategory,
      tags: [],
      favorite: false,
      history: [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    const isNew = !item;
    document.getElementById('drawer-title').textContent = isNew ? 'New Credential' : 'Edit Credential';

    document.getElementById('edit-item-id').value = this.activeItem.id;
    document.getElementById('edit-item-name').value = this.activeItem.name || '';
    document.getElementById('edit-item-url').value = this.activeItem.url || '';
    document.getElementById('edit-item-user').value = this.activeItem.username || '';
    document.getElementById('edit-item-password').value = this.activeItem.password || '';
    document.getElementById('edit-item-category').value = this.activeItem.category || 'login';
    document.getElementById('edit-item-notes').value = this.activeItem.notes || '';
    document.getElementById('edit-item-fav-toggle').checked = !!this.activeItem.favorite;

    // Password strength bar update
    this.updateDrawerPasswordStrength(this.activeItem.password || '');

    // QR Code generation
    const qrContainer = document.getElementById('drawer-qr-container');
    if (this.activeItem.password) {
      qrContainer.innerHTML = UI.renderSimpleQR(this.activeItem.password);
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

    const name = document.getElementById('edit-item-name').value.trim();
    const url = document.getElementById('edit-item-url').value.trim();
    const username = document.getElementById('edit-item-user').value.trim();
    const newPassword = document.getElementById('edit-item-password').value;
    const category = document.getElementById('edit-item-category').value;
    const notes = document.getElementById('edit-item-notes').value;
    const favorite = document.getElementById('edit-item-fav-toggle').checked;

    if (!name && !url) {
      UI.showToast('Please provide an account name or website URL', 'danger');
      return;
    }

    const existingIndex = this.vaultItems.findIndex(i => i.id === this.activeItem.id);
    const now = new Date().toISOString();

    // Check if password changed, record in history
    if (existingIndex !== -1 && this.vaultItems[existingIndex].password && this.vaultItems[existingIndex].password !== newPassword) {
      if (!this.activeItem.history) this.activeItem.history = [];
      this.activeItem.history.unshift({
        password: this.vaultItems[existingIndex].password,
        date: now
      });
    }

    const updatedItem = {
      ...this.activeItem,
      name: name || url,
      url,
      username,
      password: newPassword,
      category,
      notes,
      favorite,
      updatedAt: now
    };

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
      this.vaultItems.splice(idx, 1);
      UI.showToast('Item permanently deleted', 'info');
    } else {
      // Move to trash
      this.vaultItems[idx].trash = true;
      UI.showToast('Moved to Trash', 'info');
    }

    await StorageEngine.saveVaultItems(this.vaultItems, this.vaultKey);
    this.closeDrawer();
    this.renderMainView();
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
  renderSettings() {
    document.getElementById('setting-autolock-select').value = this.prefs.autoLockMinutes;
    document.getElementById('setting-clipboard-timer').value = this.prefs.autoClearClipboardSec || 30;
    document.getElementById('setting-theme-toggle').checked = this.prefs.theme === 'light';
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
        password: '•••• •••• •••• 4092 (CVV: 891)',
        category: 'card',
        notes: 'Travel card with $300 annual credit.',
        favorite: true,
        createdAt: now,
        updatedAt: now
      },
      {
        id: 'sample_address',
        name: 'Home Address',
        url: '',
        username: '123 Main Street, Austin TX 78701',
        password: '',
        category: 'address',
        notes: 'Primary home address for shipping. State: Texas.',
        favorite: false,
        createdAt: now,
        updatedAt: now
      },
      {
        id: 'sample_apikey',
        name: 'OpenAI API Key',
        url: 'https://platform.openai.com',
        username: 'sk-proj-...dev-key',
        password: 'sk-proj-Abc123XyzSecretDevKey456789',
        category: 'apikey',
        notes: 'Development key for GPT-4o integration. Monthly limit: $50.',
        favorite: true,
        createdAt: now,
        updatedAt: now
      }
    ];

    this.vaultItems = sampleItems;
    await StorageEngine.saveVaultItems(this.vaultItems, this.vaultKey);
    this.renderMainView();
    UI.showToast('Loaded 7 sample credentials into vault!', 'success');
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
  }

  bindDrawerEvents() {
    document.getElementById('drawer-close-btn')?.addEventListener('click', () => this.closeDrawer());
    document.getElementById('drawer-save-btn')?.addEventListener('click', () => this.saveActiveItem());
    document.getElementById('drawer-delete-btn')?.addEventListener('click', () => this.deleteActiveItem());

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

    // Drawer generate button
    document.getElementById('drawer-pwd-generate-btn')?.addEventListener('click', () => {
      UI.openModal('generator-modal');
      document.getElementById('gen-refresh-btn')?.click();
    });
  }
}

// Instantiate and start app on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  const app = new ToggleApp();
  app.init();
});
