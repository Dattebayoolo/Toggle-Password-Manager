/**
 * Toggle Password Manager - CSV & JSON Import/Export Engine
 * 100% Compatible with Google Chrome / Google Password Manager CSV exports.
 */

export class ImportExportEngine {
  /**
   * Robust RFC 4180 CSV parser supporting escaped quotes, commas, and line breaks
   */
  static parseCSV(csvText) {
    const rows = [];
    let currentRow = [];
    let currentField = '';
    let insideQuotes = false;

    for (let i = 0; i < csvText.length; i++) {
      const char = csvText[i];
      const nextChar = csvText[i + 1];

      if (char === '"') {
        if (insideQuotes && nextChar === '"') {
          currentField += '"';
          i++; // skip next quote
        } else {
          insideQuotes = !insideQuotes;
        }
      } else if (char === ',' && !insideQuotes) {
        currentRow.push(currentField.trim());
        currentField = '';
      } else if ((char === '\r' || char === '\n') && !insideQuotes) {
        if (char === '\r' && nextChar === '\n') {
          i++;
        }
        currentRow.push(currentField.trim());
        if (currentRow.length > 0 && currentRow.some(f => f.length > 0)) {
          rows.push(currentRow);
        }
        currentRow = [];
        currentField = '';
      } else {
        currentField += char;
      }
    }

    if (currentField.length > 0 || currentRow.length > 0) {
      currentRow.push(currentField.trim());
      if (currentRow.some(f => f.length > 0)) {
        rows.push(currentRow);
      }
    }

    return rows;
  }

  /**
   * Imports passwords from Google Chrome / Google Password Manager CSV
   */
  static importGoogleCSV(csvText) {
    const rows = this.parseCSV(csvText);
    if (rows.length < 2) {
      throw new Error('CSV file is empty or does not contain data.');
    }

    const headers = rows[0].map(h => h.toLowerCase().replace(/[^a-z]/g, ''));
    
    // Find column indexes
    let nameIdx = headers.findIndex(h => h.includes('name') || h.includes('title'));
    let urlIdx = headers.findIndex(h => h.includes('url') || h.includes('website'));
    let userIdx = headers.findIndex(h => h.includes('user') || h.includes('email') || h.includes('login'));
    let pwdIdx = headers.findIndex(h => h.includes('pass'));
    let noteIdx = headers.findIndex(h => h.includes('note'));

    if (pwdIdx === -1) {
      throw new Error('Could not find a "password" column in the CSV file.');
    }

    const importedItems = [];
    const now = new Date().toISOString();

    for (let i = 1; i < rows.length; i++) {
      const row = rows[i];
      if (!row || row.length <= pwdIdx) continue;

      const password = row[pwdIdx] || '';
      if (!password) continue; // skip blank password entries

      let url = urlIdx !== -1 && row[urlIdx] ? row[urlIdx] : '';
      let name = nameIdx !== -1 && row[nameIdx] ? row[nameIdx] : '';
      let username = userIdx !== -1 && row[userIdx] ? row[userIdx] : '';
      let note = noteIdx !== -1 && row[noteIdx] ? row[noteIdx] : '';

      // If name is empty, derive from URL
      if (!name && url) {
        try {
          const parsed = new URL(url.startsWith('http') ? url : `https://${url}`);
          name = parsed.hostname.replace('www.', '');
        } catch {
          name = url;
        }
      }

      if (!name) name = 'Imported Account';

      importedItems.push({
        id: 'toggle_' + Math.random().toString(36).substring(2, 9) + Date.now().toString(36),
        name,
        url,
        username,
        password,
        notes: note,
        category: 'login',
        tags: ['Google Import'],
        favorite: false,
        history: [],
        createdAt: now,
        updatedAt: now
      });
    }

    return importedItems;
  }

  /**
   * Generates Google Password Manager compatible CSV string
   */
  static exportGoogleCSV(items = []) {
    const logins = items.filter(item => item.category === 'login' || !item.category);
    const headers = ['name', 'url', 'username', 'password', 'note'];

    const csvRows = [headers.join(',')];

    for (const item of logins) {
      const escapeField = (val) => {
        if (!val) return '""';
        const str = String(val).replace(/"/g, '""');
        return `"${str}"`;
      };

      const row = [
        escapeField(item.name || ''),
        escapeField(item.url || ''),
        escapeField(item.username || ''),
        escapeField(item.password || ''),
        escapeField(item.notes || '')
      ];

      csvRows.push(row.join(','));
    }

    return csvRows.join('\r\n');
  }

  /**
   * Triggers a browser download of a text or JSON file
   */
  static triggerDownload(content, filename, mimeType = 'text/csv;charset=utf-8;') {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }
}
