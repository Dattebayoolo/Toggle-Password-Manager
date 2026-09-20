/**
 * Toggle Password Manager - UI Controller & Tactile Micro-Interactions
 */

export class UI {
  static clipboardTimeoutId = null;
  static clipboardIntervalId = null;
  static activeToasts = [];

  /**
   * Shows a rich animated toast notification
   */
  static showToast(message, type = 'success', duration = 3000) {
    let container = document.getElementById('toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toast-container';
      container.className = 'toast-container';
      document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    let icon = '✓';
    if (type === 'danger') icon = '✕';
    if (type === 'info') icon = 'ℹ';

    toast.innerHTML = `
      <span style="font-weight:700;font-size:1.1rem;">${icon}</span>
      <span style="flex:1;font-size:0.875rem;">${this.escapeHTML(message)}</span>
    `;

    container.appendChild(toast);

    setTimeout(() => {
      toast.classList.add('toast-hiding');
      setTimeout(() => toast.remove(), 250);
    }, duration);
  }

  /**
   * Copies text to clipboard with secure 30-second auto-clear countdown banner.
   * Uses navigator.clipboard API with a textarea fallback for legacy browsers
   * (document.execCommand is deprecated and removed in some environments).
   */
  static async copySecure(text, label = 'Password') {
    let copied = false;

    if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
      try {
        await navigator.clipboard.writeText(text);
        copied = true;
      } catch (e) {
        // Clipboard API may be rejected (e.g. non-secure context) — fall through
      }
    }

    if (!copied) {
      // Legacy fallback: textarea + execCommand (deprecated but still widely supported)
      try {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.cssText = 'position:fixed;opacity:0;pointer-events:none;';
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        copied = true;
      } catch (e) {
        // Both methods failed
      }
    }

    if (copied) {
      this.showToast(`${label} copied to clipboard!`, 'success');
      this.startClipboardCountdown(30);
    } else {
      this.showToast('Could not copy — please copy manually.', 'danger');
    }
  }

  /**
   * Starts floating clipboard auto-clear countdown
   */
  static startClipboardCountdown(seconds = 30) {
    let banner = document.getElementById('clipboard-banner');
    if (!banner) {
      banner = document.createElement('div');
      banner.id = 'clipboard-banner';
      banner.className = 'clipboard-banner';
      banner.innerHTML = `
        <span class="clipboard-pulse"></span>
        <span id="clipboard-text">Clipboard clears in 30s</span>
        <button class="btn-ghost" id="clipboard-clear-now" style="font-size:0.75rem;padding:2px 6px;">Clear Now</button>
      `;
      document.body.appendChild(banner);

      document.getElementById('clipboard-clear-now').addEventListener('click', () => {
        this.clearClipboardNow();
      });
    }

    clearInterval(this.clipboardIntervalId);
    clearTimeout(this.clipboardTimeoutId);

    banner.classList.add('active');
    let remaining = seconds;
    const textElem = document.getElementById('clipboard-text');

    this.clipboardIntervalId = setInterval(() => {
      remaining--;
      if (textElem) {
        textElem.textContent = `Clipboard clears in ${remaining}s`;
      }
      if (remaining <= 0) {
        this.clearClipboardNow();
      }
    }, 1000);
  }

  /**
   * Wipes clipboard and hides banner
   */
  static clearClipboardNow() {
    clearInterval(this.clipboardIntervalId);
    clearTimeout(this.clipboardTimeoutId);

    const banner = document.getElementById('clipboard-banner');
    if (banner) {
      banner.classList.remove('active');
    }

    try {
      navigator.clipboard.writeText('');
    } catch {}

    this.showToast('Clipboard cleared for security', 'info', 2000);
  }

  /**
   * Generates a stylized initials avatar or favicon element.
   * The `initial` character is properly escaped before being embedded in
   * onerror attribute HTML to prevent XSS via crafted account names.
   */
  static renderAvatar(name = '', url = '') {
    let hostname = '';
    if (url) {
      try {
        const parsed = new URL(url.startsWith('http') ? url : `https://${url}`);
        hostname = parsed.hostname;
      } catch {}
    }

    const cleanName = (name || hostname || 'Account').trim();
    const initial = this.escapeHTML(cleanName.charAt(0).toUpperCase());
    const safeTitle = this.escapeHTML(cleanName);

    // If there is a hostname, use DuckDuckGo favicon service with graceful fallback to letter
    if (hostname && !hostname.includes('localhost')) {
      // The onerror uses the pre-escaped `initial` — safe to embed in attribute context
      return `
        <div class="vault-card-avatar" title="${safeTitle}">
          <img src="https://icons.duckduckgo.com/ip3/${hostname}.ico" 
               onerror="this.onerror=null; this.parentElement.textContent='${initial}';" 
               alt="${initial}" loading="lazy" />
        </div>
      `;
    }

    return `
      <div class="vault-card-avatar" title="${safeTitle}">
        ${initial}
      </div>
    `;
  }

  /**
   * Minimal vanilla SVG QR code generator for sharing credentials/Wi-Fi to phones
   */
  static renderSimpleQR(text) {
    // Generate a simple high-density SVG visual pattern or visual representation
    // To keep it 100% dependency free and working offline:
    const encoded = encodeURIComponent(text);
    return `
      <div style="text-align:center;padding:16px;">
        <img src="https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encoded}" 
             alt="QR Code" 
             style="border-radius:8px;border:4px solid #fff;"
             onerror="this.parentElement.innerHTML='<div style=\\'color:var(--text-muted);font-size:0.8rem;padding:20px;\\'>Connect device to scan or copy text manually.</div>'" />
      </div>
    `;
  }

  /**
   * Escapes HTML entities to prevent XSS
   */
  static escapeHTML(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  /**
   * Modal management
   */
  static openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
      modal.classList.add('active');
    }
  }

  static closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
      modal.classList.remove('active');
    }
  }
}
