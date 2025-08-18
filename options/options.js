// Options page script for PhishGuard Pro
class OptionsController {
  constructor() {
    this.settings = {
      enableProtection: true,
      showNotifications: true,
      strictMode: false
    };
    
    this.customWhitelist = [];
    this.customBlacklist = [];
    
    this.init();
  }

  async init() {
    await this.loadSettings();
    this.bindEvents();
    this.updateUI();
    this.loadStats();
  }

  async loadSettings() {
    try {
      const result = await chrome.storage.local.get([
        'settings',
        'customWhitelist',
        'customBlacklist'
      ]);
      
      this.settings = { ...this.settings, ...(result.settings || {}) };
      this.customWhitelist = result.customWhitelist || [];
      this.customBlacklist = result.customBlacklist || [];
    } catch (error) {
      console.error('Failed to load settings:', error);
    }
  }

  async saveSettings() {
    try {
      await chrome.storage.local.set({
        settings: this.settings,
        customWhitelist: this.customWhitelist,
        customBlacklist: this.customBlacklist
      });
    } catch (error) {
      console.error('Failed to save settings:', error);
    }
  }

  bindEvents() {
    // Toggle switches
    document.getElementById('enableProtection').addEventListener('change', (e) => {
      this.settings.enableProtection = e.target.checked;
      this.saveSettings();
    });

    document.getElementById('showNotifications').addEventListener('change', (e) => {
      this.settings.showNotifications = e.target.checked;
      this.saveSettings();
    });

    document.getElementById('strictMode').addEventListener('change', (e) => {
      this.settings.strictMode = e.target.checked;
      this.saveSettings();
    });

    // Whitelist management
    document.getElementById('addWhitelist').addEventListener('click', () => {
      const input = document.getElementById('whitelistInput');
      const domain = input.value.trim().toLowerCase();
      
      if (domain && this.isValidDomain(domain) && !this.customWhitelist.includes(domain)) {
        this.customWhitelist.push(domain);
        input.value = '';
        this.updateWhitelistUI();
        this.saveSettings();
      }
    });

    document.getElementById('whitelistInput').addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        document.getElementById('addWhitelist').click();
      }
    });

    // Blacklist management
    document.getElementById('addBlacklist').addEventListener('click', () => {
      const input = document.getElementById('blacklistInput');
      const domain = input.value.trim().toLowerCase();
      
      if (domain && this.isValidDomain(domain) && !this.customBlacklist.includes(domain)) {
        this.customBlacklist.push(domain);
        input.value = '';
        this.updateBlacklistUI();
        this.saveSettings();
      }
    });

    document.getElementById('blacklistInput').addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        document.getElementById('addBlacklist').click();
      }
    });

    // Action buttons
    document.getElementById('exportSettings').addEventListener('click', () => {
      this.exportSettings();
    });

    document.getElementById('importSettings').addEventListener('click', () => {
      document.getElementById('importFile').click();
    });

    document.getElementById('importFile').addEventListener('change', (e) => {
      this.importSettings(e.target.files[0]);
    });

    document.getElementById('resetSettings').addEventListener('click', () => {
      if (confirm('Are you sure you want to reset all settings to defaults? This action cannot be undone.')) {
        this.resetSettings();
      }
    });
  }

  updateUI() {
    // Update toggle switches
    document.getElementById('enableProtection').checked = this.settings.enableProtection;
    document.getElementById('showNotifications').checked = this.settings.showNotifications;
    document.getElementById('strictMode').checked = this.settings.strictMode;

    // Update lists
    this.updateWhitelistUI();
    this.updateBlacklistUI();
  }

  updateWhitelistUI() {
    const container = document.getElementById('whitelistItems');
    container.innerHTML = this.customWhitelist.length === 0 
      ? '<div class="list-item" style="justify-content: center; color: #9ca3af;">No trusted sites added</div>'
      : this.customWhitelist.map(domain => `
          <div class="list-item">
            <span>${domain}</span>
            <button class="remove-btn" onclick="optionsController.removeFromWhitelist('${domain}')">
              Remove
            </button>
          </div>
        `).join('');
  }

  updateBlacklistUI() {
    const container = document.getElementById('blacklistItems');
    container.innerHTML = this.customBlacklist.length === 0 
      ? '<div class="list-item" style="justify-content: center; color: #9ca3af;">No blocked sites added</div>'
      : this.customBlacklist.map(domain => `
          <div class="list-item">
            <span>${domain}</span>
            <button class="remove-btn" onclick="optionsController.removeFromBlacklist('${domain}')">
              Remove
            </button>
          </div>
        `).join('');
  }

  removeFromWhitelist(domain) {
    this.customWhitelist = this.customWhitelist.filter(d => d !== domain);
    this.updateWhitelistUI();
    this.saveSettings();
  }

  removeFromBlacklist(domain) {
    this.customBlacklist = this.customBlacklist.filter(d => d !== domain);
    this.updateBlacklistUI();
    this.saveSettings();
  }

  isValidDomain(domain) {
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])*$/;
    return domainRegex.test(domain) && domain.length <= 253;
  }

  async loadStats() {
    try {
      const result = await chrome.storage.local.get(['stats']);
      const stats = result.stats || {
        sitesAnalyzed: 0,
        threatsBlocked: 0,
        protectionRate: 0
      };

      document.getElementById('sitesAnalyzed').textContent = stats.sitesAnalyzed.toLocaleString();
      document.getElementById('threatsBlocked').textContent = stats.threatsBlocked.toLocaleString();
      document.getElementById('protectionRate').textContent = `${stats.protectionRate.toFixed(1)}%`;
    } catch (error) {
      console.error('Failed to load stats:', error);
    }
  }

  exportSettings() {
    const exportData = {
      settings: this.settings,
      customWhitelist: this.customWhitelist,
      customBlacklist: this.customBlacklist,
      exportDate: new Date().toISOString(),
      version: '1.0.0'
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishguard-settings-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  async importSettings(file) {
    if (!file) return;

    try {
      const text = await file.text();
      const data = JSON.parse(text);

      if (data.settings) {
        this.settings = { ...this.settings, ...data.settings };
      }
      
      if (data.customWhitelist) {
        this.customWhitelist = [...new Set([...this.customWhitelist, ...data.customWhitelist])];
      }
      
      if (data.customBlacklist) {
        this.customBlacklist = [...new Set([...this.customBlacklist, ...data.customBlacklist])];
      }

      await this.saveSettings();
      this.updateUI();
      
      alert('Settings imported successfully!');
    } catch (error) {
      console.error('Import failed:', error);
      alert('Failed to import settings. Please check the file format.');
    }
  }

  async resetSettings() {
    this.settings = {
      enableProtection: true,
      showNotifications: true,
      strictMode: false
    };
    
    this.customWhitelist = [];
    this.customBlacklist = [];
    
    await this.saveSettings();
    this.updateUI();
    
    // Clear stats
    await chrome.storage.local.remove(['stats']);
    this.loadStats();
  }
}

// Initialize options controller when DOM is loaded
let optionsController;
document.addEventListener('DOMContentLoaded', () => {
  optionsController = new OptionsController();
});