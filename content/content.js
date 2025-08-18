// Enhanced Content script for PhishGuard Pro with Advanced UI
class AdvancedNotificationUI {
  constructor() {
    this.notification = null;
    this.isVisible = false;
    this.autoHideTimer = null;
    this.animationFrame = null;
    this.settings = {
      showNotifications: true,
      animationDuration: 400,
      autoHideDelay: 12000
    };
    this.loadSettings();
  }

  async loadSettings() {
    try {
      const result = await chrome.storage.local.get(['settings']);
      this.settings = { ...this.settings, ...(result.settings || {}) };
    } catch (error) {
      console.error('Failed to load notification settings:', error);
    }
  }

  createNotification(analysis) {
    if (!this.settings.showNotifications) return;
    
    // Remove existing notification
    this.removeNotification();

    const notification = document.createElement('div');
    notification.id = 'phishguard-notification';
    notification.className = `phishguard-notification ${analysis.status}`;
    notification.setAttribute('data-threat-level', analysis.threat);

    const icon = this.getStatusIcon(analysis.status);
    const statusText = this.getStatusText(analysis.status);
    const riskLevel = this.getRiskLevel(analysis.riskScore);

    notification.innerHTML = `
      <div class="phishguard-content">
        <div class="phishguard-header">
          <div class="phishguard-icon-container">
            <div class="phishguard-icon">${icon}</div>
            <div class="phishguard-pulse ${analysis.status}"></div>
          </div>
          <div class="phishguard-title">
            <div class="status-text">${statusText}</div>
            <div class="domain-name" title="${analysis.domain}">${analysis.domain}</div>
            <div class="confidence-badge">
              Confidence: ${analysis.confidence}%
            </div>
          </div>
          <button class="phishguard-close" id="phishguard-close" title="Close notification">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </div>
        
        <div class="phishguard-message">${analysis.message}</div>
        
        <div class="phishguard-metrics">
          <div class="metric-item">
            <div class="metric-label">Risk Score</div>
            <div class="metric-bar-container">
              <div class="metric-bar">
                <div class="metric-fill ${riskLevel}" style="width: ${analysis.riskScore}%"></div>
              </div>
              <span class="metric-value">${analysis.riskScore}%</span>
            </div>
          </div>
          
          <div class="security-indicators">
            <div class="indicator ${analysis.hasSSL ? 'secure' : 'insecure'}">
              <span class="indicator-icon">${analysis.hasSSL ? '🔒' : '⚠️'}</span>
              <span class="indicator-text">${analysis.hasSSL ? 'SSL Secured' : 'No SSL'}</span>
            </div>
            
            <div class="indicator ${this.getDomainAgeClass(analysis.domainCategory)}">
              <span class="indicator-icon">📅</span>
              <span class="indicator-text">
                ${this.formatDomainAge(analysis.domainAge, analysis.domainCategory)}
              </span>
            </div>
            
            <div class="indicator">
              <span class="indicator-icon">⚡</span>
              <span class="indicator-text">
                Analyzed in ${analysis.analysisTime}ms
              </span>
            </div>
          </div>
        </div>

        ${analysis.reasons && analysis.reasons.length > 0 ? `
          <div class="phishguard-details">
            <div class="details-header">
              <span class="details-title">Detection Factors</span>
              <button class="details-toggle" id="details-toggle">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <polyline points="6,9 12,15 18,9"></polyline>
                </svg>
              </button>
            </div>
            <div class="details-content" id="details-content">
              <ul class="reasons-list">
                ${analysis.reasons.map((reason, index) => `
                  <li class="reason-item" style="animation-delay: ${index * 50}ms">
                    <span class="reason-bullet">•</span>
                    <span class="reason-text">${reason}</span>
                  </li>
                `).join('')}
              </ul>
              
              ${analysis.detailedAnalysis ? `
                <div class="analysis-summary">
                  <div class="summary-item">
                    <span class="summary-label">Pattern Matches:</span>
                    <span class="summary-value">${analysis.detailedAnalysis.patterns}</span>
                  </div>
                  <div class="summary-item">
                    <span class="summary-label">Keyword Matches:</span>
                    <span class="summary-value">${analysis.detailedAnalysis.keywords}</span>
                  </div>
                  <div class="summary-item">
                    <span class="summary-label">Homograph Attack:</span>
                    <span class="summary-value">${analysis.detailedAnalysis.homograph ? 'Yes' : 'No'}</span>
                  </div>
                </div>
              ` : ''}
            </div>
          </div>
        ` : ''}

        <div class="phishguard-actions">
          ${analysis.status === 'phishing' ? `
            <button class="action-btn danger" id="block-site">
              <span class="btn-icon">🚫</span>
              Block Site
            </button>
            <button class="action-btn secondary" id="report-phishing">
              <span class="btn-icon">📋</span>
              Report
            </button>
          ` : analysis.status === 'suspicious' ? `
            <button class="action-btn warning" id="proceed-caution">
              <span class="btn-icon">⚠️</span>
              Proceed with Caution
            </button>
            <button class="action-btn secondary" id="add-whitelist">
              <span class="btn-icon">✅</span>
              Trust Site
            </button>
          ` : `
            <button class="action-btn success" id="site-safe">
              <span class="btn-icon">✅</span>
              Site Verified Safe
            </button>
          `}
        </div>
      </div>
    `;

    document.body.appendChild(notification);
    this.notification = notification;

    // Add event listeners
    this.attachEventListeners(analysis);

    // Show notification with enhanced animation
    this.animationFrame = requestAnimationFrame(() => {
      notification.classList.add('show');
      this.isVisible = true;
      
      // Trigger staggered animations for child elements
      this.animateChildElements();
    });

    // Auto-hide logic based on threat level
    if (analysis.status === 'legitimate') {
      this.autoHideTimer = setTimeout(() => {
        this.hideNotification();
      }, this.settings.autoHideDelay);
    } else if (analysis.status === 'suspicious') {
      this.autoHideTimer = setTimeout(() => {
        this.hideNotification();
      }, this.settings.autoHideDelay * 2);
    }
    // Phishing notifications stay visible until manually closed
  }

  attachEventListeners(analysis) {
    // Close button
    const closeBtn = document.getElementById('phishguard-close');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => this.hideNotification());
    }

    // Details toggle
    const detailsToggle = document.getElementById('details-toggle');
    const detailsContent = document.getElementById('details-content');
    if (detailsToggle && detailsContent) {
      detailsToggle.addEventListener('click', () => {
        const isExpanded = detailsContent.classList.contains('expanded');
        detailsContent.classList.toggle('expanded');
        detailsToggle.classList.toggle('rotated');
      });
    }

    // Action buttons
    const blockBtn = document.getElementById('block-site');
    if (blockBtn) {
      blockBtn.addEventListener('click', () => this.blockSite(analysis.domain));
    }

    const reportBtn = document.getElementById('report-phishing');
    if (reportBtn) {
      reportBtn.addEventListener('click', () => this.reportPhishing(analysis));
    }

    const whitelistBtn = document.getElementById('add-whitelist');
    if (whitelistBtn) {
      whitelistBtn.addEventListener('click', () => this.addToWhitelist(analysis.domain));
    }

    const proceedBtn = document.getElementById('proceed-caution');
    if (proceedBtn) {
      proceedBtn.addEventListener('click', () => this.proceedWithCaution());
    }

    // Keyboard shortcuts
    document.addEventListener('keydown', this.handleKeyboardShortcuts.bind(this));
  }

  animateChildElements() {
    const elements = this.notification.querySelectorAll('.metric-item, .indicator, .reason-item');
    elements.forEach((element, index) => {
      setTimeout(() => {
        element.classList.add('animate-in');
      }, index * 100);
    });
  }

  handleKeyboardShortcuts(event) {
    if (!this.isVisible) return;

    if (event.key === 'Escape') {
      this.hideNotification();
    } else if (event.key === 'Enter' && event.ctrlKey) {
      const primaryAction = this.notification.querySelector('.action-btn:first-child');
      if (primaryAction) primaryAction.click();
    }
  }

  getStatusIcon(status) {
    const icons = {
      'legitimate': '✅',
      'questionable': '❓',
      'suspicious': '⚠️',
      'phishing': '🚫'
    };
    return icons[status] || '❓';
  }

  getStatusText(status) {
    const texts = {
      'legitimate': 'Site Verified Safe',
      'questionable': 'Site Questionable',
      'suspicious': 'Suspicious Activity Detected',
      'phishing': 'Phishing Site Detected!'
    };
    return texts[status] || 'Analysis Complete';
  }

  getRiskLevel(score) {
    if (score >= 70) return 'critical';
    if (score >= 45) return 'high';
    if (score >= 25) return 'medium';
    return 'low';
  }

  getDomainAgeClass(category) {
    const classes = {
      'very_new': 'danger',
      'new': 'warning',
      'recent': 'info',
      'established': 'success'
    };
    return classes[category] || 'info';
  }

  formatDomainAge(days, category) {
    if (days < 30) return `${days} days (Very New)`;
    if (days < 90) return `${Math.floor(days / 30)} months (New)`;
    if (days < 365) return `${Math.floor(days / 30)} months (Recent)`;
    return `${Math.floor(days / 365)} years (Established)`;
  }

  async blockSite(domain) {
    try {
      // Add to blacklist
      const result = await chrome.storage.local.get(['customBlacklist']);
      const blacklist = result.customBlacklist || [];
      
      if (!blacklist.includes(domain)) {
        blacklist.push(domain);
        await chrome.storage.local.set({ customBlacklist: blacklist });
      }

      // Show confirmation and redirect
      this.showActionFeedback('Site blocked successfully', 'success');
      
      setTimeout(() => {
        window.location.href = 'about:blank';
      }, 2000);
    } catch (error) {
      this.showActionFeedback('Failed to block site', 'error');
    }
  }

  async reportPhishing(analysis) {
    try {
      // In production, this would send to your backend
      console.log('Reporting phishing site:', analysis);
      
      this.showActionFeedback('Phishing report submitted', 'success');
    } catch (error) {
      this.showActionFeedback('Failed to submit report', 'error');
    }
  }

  async addToWhitelist(domain) {
    try {
      const result = await chrome.storage.local.get(['customWhitelist']);
      const whitelist = result.customWhitelist || [];
      
      if (!whitelist.includes(domain)) {
        whitelist.push(domain);
        await chrome.storage.local.set({ customWhitelist: whitelist });
      }

      this.showActionFeedback('Site added to trusted list', 'success');
      
      setTimeout(() => {
        this.hideNotification();
      }, 2000);
    } catch (error) {
      this.showActionFeedback('Failed to add to whitelist', 'error');
    }
  }

  proceedWithCaution() {
    this.showActionFeedback('Proceeding with caution - stay alert!', 'warning');
    setTimeout(() => {
      this.hideNotification();
    }, 3000);
  }

  showActionFeedback(message, type) {
    const feedback = document.createElement('div');
    feedback.className = `action-feedback ${type}`;
    feedback.textContent = message;
    
    this.notification.querySelector('.phishguard-actions').appendChild(feedback);
    
    setTimeout(() => {
      feedback.remove();
    }, 3000);
  }

  hideNotification() {
    if (this.notification && this.isVisible) {
      this.notification.classList.remove('show');
      this.notification.classList.add('hide');
      
      setTimeout(() => {
        this.removeNotification();
      }, this.settings.animationDuration);
    }

    if (this.autoHideTimer) {
      clearTimeout(this.autoHideTimer);
      this.autoHideTimer = null;
    }
  }

  removeNotification() {
    if (this.notification) {
      this.notification.remove();
      this.notification = null;
      this.isVisible = false;
    }

    if (this.animationFrame) {
      cancelAnimationFrame(this.animationFrame);
      this.animationFrame = null;
    }

    // Remove keyboard event listener
    document.removeEventListener('keydown', this.handleKeyboardShortcuts);
  }
}

// Initialize enhanced notification UI
const notificationUI = new AdvancedNotificationUI();

// Enhanced message listener with error handling
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'ANALYSIS_RESULT') {
    // Delay to ensure page is fully loaded
    setTimeout(() => {
      try {
        notificationUI.createNotification(request.data);
      } catch (error) {
        console.error('Failed to create notification:', error);
      }
    }, 1500);
  }
});

// Enhanced page navigation handling
window.addEventListener('beforeunload', () => {
  notificationUI.removeNotification();
});

// Handle page visibility changes
document.addEventListener('visibilitychange', () => {
  if (document.hidden && notificationUI.isVisible) {
    // Pause auto-hide timer when page is hidden
    if (notificationUI.autoHideTimer) {
      clearTimeout(notificationUI.autoHideTimer);
    }
  }
});

// Performance monitoring
const performanceObserver = new PerformanceObserver((list) => {
  const entries = list.getEntries();
  entries.forEach(entry => {
    if (entry.name.includes('phishguard')) {
      console.log(`PhishGuard Performance: ${entry.name} took ${entry.duration}ms`);
    }
  });
});

try {
  performanceObserver.observe({ entryTypes: ['measure', 'navigation'] });
} catch (error) {
  // Performance API not supported
}