// Enhanced Popup script for PhishGuard Pro with Advanced Analytics
class AdvancedPopupController {
  constructor() {
    this.elements = {
      loading: document.getElementById('loading'),
      result: document.getElementById('result'),
      error: document.getElementById('error'),
      siteStatus: document.getElementById('siteStatus'),
      statusIcon: document.getElementById('statusIcon'),
      statusTitle: document.getElementById('statusTitle'),
      domainName: document.getElementById('domainName'),
      riskBar: document.getElementById('riskBar'),
      riskScore: document.getElementById('riskScore'),
      sslFeature: document.getElementById('sslFeature'),
      sslStatus: document.getElementById('sslStatus'),
      domainAge: document.getElementById('domainAge'),
      reasonsList: document.getElementById('reasonsList'),
      analysisDetails: document.getElementById('analysisDetails'),
      reportBtn: document.getElementById('reportBtn'),
      whitelistBtn: document.getElementById('whitelistBtn'),
      settingsBtn: document.getElementById('settingsBtn'),
      retryBtn: document.getElementById('retryBtn'),
      errorMessage: document.getElementById('errorMessage')
    };

    this.currentAnalysis = null;
    this.animationTimeouts = [];
    this.init();
  }

  init() {
    this.attachEventListeners();
    this.loadUserPreferences();
    this.analyzeCurrentTab();
    this.startPeriodicUpdates();
  }

  async loadUserPreferences() {
    try {
      const result = await chrome.storage.local.get(['popupPreferences']);
      const prefs = result.popupPreferences || {
        showDetailedAnalysis: true,
        autoRefresh: false,
        compactMode: false
      };
      
      this.applyPreferences(prefs);
    } catch (error) {
      console.error('Failed to load preferences:', error);
    }
  }

  applyPreferences(prefs) {
    if (prefs.compactMode) {
      document.body.classList.add('compact-mode');
    }
    
    if (!prefs.showDetailedAnalysis) {
      this.elements.analysisDetails?.classList.add('hidden');
    }
  }

  startPeriodicUpdates() {
    // Auto-refresh every 30 seconds if enabled
    setInterval(async () => {
      const prefs = await chrome.storage.local.get(['popupPreferences']);
      if (prefs.popupPreferences?.autoRefresh && this.currentAnalysis) {
        this.analyzeCurrentTab();
      }
    }, 30000);
  }

  attachEventListeners() {
    this.elements.retryBtn?.addEventListener('click', () => {
      this.analyzeCurrentTab();
    });

    this.elements.reportBtn?.addEventListener('click', () => {
      this.reportIssue();
    });

    this.elements.whitelistBtn?.addEventListener('click', () => {
      this.addToWhitelist();
    });

    this.elements.settingsBtn?.addEventListener('click', () => {
      chrome.runtime.openOptionsPage();
    });

    // Add keyboard shortcuts
    document.addEventListener('keydown', (e) => {
      if (e.key === 'r' && e.ctrlKey) {
        e.preventDefault();
        this.analyzeCurrentTab();
      } else if (e.key === 's' && e.ctrlKey) {
        e.preventDefault();
        chrome.runtime.openOptionsPage();
      }
    });

    // Add refresh button functionality
    const refreshBtn = document.createElement('button');
    refreshBtn.className = 'refresh-btn';
    refreshBtn.innerHTML = '🔄';
    refreshBtn.title = 'Refresh Analysis (Ctrl+R)';
    refreshBtn.addEventListener('click', () => this.analyzeCurrentTab());
    
    const header = document.querySelector('.popup-header');
    if (header) {
      header.appendChild(refreshBtn);
    }
  }

  showLoading() {
    this.clearAnimationTimeouts();
    this.elements.loading?.classList.remove('hidden');
    this.elements.result?.classList.add('hidden');
    this.elements.error?.classList.add('hidden');
    
    // Add loading animation
    const spinner = this.elements.loading?.querySelector('.spinner');
    if (spinner) {
      spinner.style.animation = 'spin 1s linear infinite';
    }
  }

  showResult(analysis) {
    this.currentAnalysis = analysis;
    this.clearAnimationTimeouts();
    
    this.elements.loading?.classList.add('hidden');
    this.elements.result?.classList.remove('hidden');
    this.elements.error?.classList.add('hidden');

    // Enhanced status display
    this.updateStatusDisplay(analysis);
    this.updateRiskMetrics(analysis);
    this.updateSecurityFeatures(analysis);
    this.updateAnalysisDetails(analysis);
    this.updateActionButtons(analysis);
    
    // Animate elements in sequence
    this.animateResultElements();
  }

  updateStatusDisplay(analysis) {
    if (!this.elements.siteStatus) return;

    this.elements.siteStatus.className = `site-status ${analysis.status}`;
    this.elements.siteStatus.setAttribute('data-threat-level', analysis.threat);
    
    if (this.elements.statusIcon) {
      this.elements.statusIcon.textContent = this.getStatusIcon(analysis.status);
    }
    
    if (this.elements.statusTitle) {
      this.elements.statusTitle.textContent = this.getStatusTitle(analysis.status);
    }
    
    if (this.elements.domainName) {
      this.elements.domainName.textContent = analysis.domain || 'Unknown domain';
      this.elements.domainName.title = `Full domain: ${analysis.domain}`;
    }

    // Add confidence indicator
    const confidenceIndicator = document.createElement('div');
    confidenceIndicator.className = 'confidence-indicator';
    confidenceIndicator.innerHTML = `
      <span class="confidence-label">Confidence:</span>
      <span class="confidence-value">${analysis.confidence}%</span>
      <div class="confidence-bar">
        <div class="confidence-fill" style="width: ${analysis.confidence}%"></div>
      </div>
    `;
    
    const existingIndicator = this.elements.siteStatus.querySelector('.confidence-indicator');
    if (existingIndicator) {
      existingIndicator.remove();
    }
    this.elements.siteStatus.appendChild(confidenceIndicator);
  }

  updateRiskMetrics(analysis) {
    if (this.elements.riskScore) {
      this.elements.riskScore.textContent = `${analysis.riskScore}%`;
    }
    
    if (this.elements.riskBar) {
      const riskLevel = this.getRiskLevel(analysis.riskScore);
      this.elements.riskBar.className = `metric-fill ${riskLevel}`;
      
      // Animate the risk bar
      this.elements.riskBar.style.width = '0%';
      this.animationTimeouts.push(setTimeout(() => {
        this.elements.riskBar.style.width = `${Math.min(analysis.riskScore, 100)}%`;
      }, 300));
    }

    // Add risk breakdown
    this.addRiskBreakdown(analysis);
  }

  addRiskBreakdown(analysis) {
    const riskBreakdown = document.createElement('div');
    riskBreakdown.className = 'risk-breakdown';
    
    const factors = [
      { label: 'Domain Reputation', value: analysis.detailedAnalysis?.reputation?.confidence || 0 },
      { label: 'SSL Security', value: analysis.hasSSL ? 100 : 0 },
      { label: 'Domain Age', value: this.getDomainAgeScore(analysis.domainCategory) },
      { label: 'Pattern Analysis', value: Math.max(0, 100 - (analysis.detailedAnalysis?.patterns || 0) * 10) }
    ];

    riskBreakdown.innerHTML = `
      <h4>Risk Factors</h4>
      ${factors.map(factor => `
        <div class="factor-item">
          <span class="factor-label">${factor.label}</span>
          <div class="factor-bar">
            <div class="factor-fill" style="width: ${factor.value}%"></div>
          </div>
          <span class="factor-value">${factor.value}%</span>
        </div>
      `).join('')}
    `;

    const existingBreakdown = document.querySelector('.risk-breakdown');
    if (existingBreakdown) {
      existingBreakdown.remove();
    }
    
    this.elements.result?.appendChild(riskBreakdown);
  }

  updateSecurityFeatures(analysis) {
    // Enhanced SSL status
    if (this.elements.sslStatus) {
      this.elements.sslStatus.textContent = analysis.hasSSL ? 'Secure' : 'Insecure';
      this.elements.sslStatus.className = `feature-status ${analysis.hasSSL ? 'secure' : 'insecure'}`;
    }

    // Enhanced domain age display
    if (this.elements.domainAge) {
      const ageText = this.formatDomainAge(analysis.domainAge, analysis.domainCategory);
      this.elements.domainAge.textContent = ageText;
      this.elements.domainAge.className = `feature-status ${this.getDomainAgeClass(analysis.domainCategory)}`;
    }

    // Add additional security metrics
    this.addSecurityMetrics(analysis);
  }

  addSecurityMetrics(analysis) {
    const metricsContainer = document.createElement('div');
    metricsContainer.className = 'additional-metrics';
    
    const metrics = [
      {
        icon: '🔍',
        label: 'Analysis Time',
        value: `${analysis.analysisTime}ms`,
        status: analysis.analysisTime < 200 ? 'good' : 'slow'
      },
      {
        icon: '🛡️',
        label: 'Threat Level',
        value: analysis.threat.toUpperCase(),
        status: analysis.threat === 'minimal' ? 'good' : analysis.threat === 'high' ? 'bad' : 'warning'
      },
      {
        icon: '📊',
        label: 'Patterns Found',
        value: analysis.detailedAnalysis?.patterns || 0,
        status: (analysis.detailedAnalysis?.patterns || 0) === 0 ? 'good' : 'warning'
      }
    ];

    metricsContainer.innerHTML = `
      <h4>Security Metrics</h4>
      <div class="metrics-grid">
        ${metrics.map(metric => `
          <div class="metric-card ${metric.status}">
            <div class="metric-icon">${metric.icon}</div>
            <div class="metric-info">
              <div class="metric-label">${metric.label}</div>
              <div class="metric-value">${metric.value}</div>
            </div>
          </div>
        `).join('')}
      </div>
    `;

    const existingMetrics = document.querySelector('.additional-metrics');
    if (existingMetrics) {
      existingMetrics.remove();
    }
    
    this.elements.result?.appendChild(metricsContainer);
  }

  updateAnalysisDetails(analysis) {
    if (!analysis.reasons || analysis.reasons.length === 0) {
      this.elements.analysisDetails?.classList.add('hidden');
      return;
    }

    this.elements.analysisDetails?.classList.remove('hidden');
    
    if (this.elements.reasonsList) {
      this.elements.reasonsList.innerHTML = analysis.reasons
        .map((reason, index) => `
          <li class="reason-item" style="animation-delay: ${index * 100}ms">
            <span class="reason-icon">${this.getReasonIcon(reason)}</span>
            <span class="reason-text">${reason}</span>
            <span class="reason-severity">${this.getReasonSeverity(reason)}</span>
          </li>
        `).join('');
    }

    // Add detailed analysis summary
    this.addAnalysisSummary(analysis);
  }

  addAnalysisSummary(analysis) {
    const summary = document.createElement('div');
    summary.className = 'analysis-summary';
    
    const summaryData = [
      { label: 'Reputation Check', value: analysis.detailedAnalysis?.reputation?.status || 'Unknown' },
      { label: 'Homograph Detection', value: analysis.detailedAnalysis?.homograph ? 'Detected' : 'Clean' },
      { label: 'Structure Analysis', value: `${analysis.detailedAnalysis?.structure || 0} issues` },
      { label: 'Redirect Check', value: analysis.detailedAnalysis?.redirects ? 'Suspicious' : 'Clean' }
    ];

    summary.innerHTML = `
      <h4>Analysis Summary</h4>
      <div class="summary-grid">
        ${summaryData.map(item => `
          <div class="summary-item">
            <span class="summary-label">${item.label}:</span>
            <span class="summary-value">${item.value}</span>
          </div>
        `).join('')}
      </div>
    `;

    const existingSummary = this.elements.analysisDetails?.querySelector('.analysis-summary');
    if (existingSummary) {
      existingSummary.remove();
    }
    
    this.elements.analysisDetails?.appendChild(summary);
  }

  updateActionButtons(analysis) {
    // Enhanced button states based on analysis
    if (this.elements.whitelistBtn) {
      if (analysis.status === 'phishing') {
        this.elements.whitelistBtn.style.display = 'none';
      } else {
        this.elements.whitelistBtn.style.display = 'flex';
        this.elements.whitelistBtn.innerHTML = `
          <span>✅</span>
          ${analysis.status === 'legitimate' ? 'Confirm Safe' : 'Trust Site'}
        `;
      }
    }

    if (this.elements.reportBtn) {
      if (analysis.status === 'phishing') {
        this.elements.reportBtn.innerHTML = '<span>🚨</span>Report Phishing';
        this.elements.reportBtn.className = 'btn btn-danger';
      } else {
        this.elements.reportBtn.innerHTML = '<span>📋</span>Report Issue';
        this.elements.reportBtn.className = 'btn btn-secondary';
      }
    }

    // Add additional action buttons
    this.addAdvancedActions(analysis);
  }

  addAdvancedActions(analysis) {
    const actionsContainer = document.querySelector('.actions');
    if (!actionsContainer) return;

    // Remove existing advanced actions
    const existingAdvanced = actionsContainer.querySelectorAll('.advanced-action');
    existingAdvanced.forEach(btn => btn.remove());

    // Add scan again button
    const scanAgainBtn = document.createElement('button');
    scanAgainBtn.className = 'btn btn-secondary advanced-action';
    scanAgainBtn.innerHTML = '<span>🔄</span>Scan Again';
    scanAgainBtn.addEventListener('click', () => this.analyzeCurrentTab());
    actionsContainer.appendChild(scanAgainBtn);

    // Add export results button
    const exportBtn = document.createElement('button');
    exportBtn.className = 'btn btn-secondary advanced-action';
    exportBtn.innerHTML = '<span>📤</span>Export';
    exportBtn.addEventListener('click', () => this.exportAnalysis(analysis));
    actionsContainer.appendChild(exportBtn);
  }

  animateResultElements() {
    const elements = [
      this.elements.siteStatus,
      ...document.querySelectorAll('.metric-item'),
      ...document.querySelectorAll('.feature'),
      ...document.querySelectorAll('.reason-item')
    ];

    elements.forEach((element, index) => {
      if (element) {
        element.style.opacity = '0';
        element.style.transform = 'translateY(20px)';
        
        this.animationTimeouts.push(setTimeout(() => {
          element.style.transition = 'all 0.3s ease';
          element.style.opacity = '1';
          element.style.transform = 'translateY(0)';
        }, index * 100));
      }
    });
  }

  clearAnimationTimeouts() {
    this.animationTimeouts.forEach(timeout => clearTimeout(timeout));
    this.animationTimeouts = [];
  }

  showError(message) {
    this.clearAnimationTimeouts();
    this.elements.loading?.classList.add('hidden');
    this.elements.result?.classList.add('hidden');
    this.elements.error?.classList.remove('hidden');
    
    if (this.elements.errorMessage) {
      this.elements.errorMessage.textContent = message;
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

  getStatusTitle(status) {
    const titles = {
      'legitimate': 'Site Verified Safe',
      'questionable': 'Site Questionable',
      'suspicious': 'Suspicious Activity',
      'phishing': 'Phishing Detected!'
    };
    return titles[status] || 'Analysis Complete';
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

  getDomainAgeScore(category) {
    const scores = {
      'very_new': 20,
      'new': 40,
      'recent': 70,
      'established': 95
    };
    return scores[category] || 50;
  }

  formatDomainAge(days, category) {
    if (days < 30) return `${days} days (Very New)`;
    if (days < 90) return `${Math.floor(days / 30)} months (New)`;
    if (days < 365) return `${Math.floor(days / 30)} months (Recent)`;
    return `${Math.floor(days / 365)} years (Established)`;
  }

  getReasonIcon(reason) {
    if (reason.includes('phishing')) return '🎣';
    if (reason.includes('SSL')) return '🔒';
    if (reason.includes('domain')) return '🌐';
    if (reason.includes('pattern')) return '🔍';
    if (reason.includes('homograph')) return '🔤';
    return '⚠️';
  }

  getReasonSeverity(reason) {
    if (reason.includes('phishing') || reason.includes('homograph')) return 'HIGH';
    if (reason.includes('suspicious') || reason.includes('new domain')) return 'MEDIUM';
    return 'LOW';
  }

  async analyzeCurrentTab() {
    this.showLoading();

    try {
      const response = await new Promise((resolve, reject) => {
        chrome.runtime.sendMessage({ type: 'ANALYZE_CURRENT_TAB' }, (response) => {
          if (chrome.runtime.lastError) {
            reject(chrome.runtime.lastError);
          } else {
            resolve(response);
          }
        });
      });

      if (response.status === 'error') {
        this.showError(response.message);
      } else {
        this.showResult(response);
      }
    } catch (error) {
      console.error('Analysis error:', error);
      this.showError('Failed to analyze the current page. Please try again.');
    }
  }

  async reportIssue() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      
      // Enhanced reporting with analysis data
      const reportData = {
        url: tab.url,
        analysis: this.currentAnalysis,
        timestamp: Date.now(),
        userAgent: navigator.userAgent
      };
      
      console.log('Enhanced report data:', reportData);
      
      // Show enhanced feedback
      const originalText = this.elements.reportBtn.innerHTML;
      this.elements.reportBtn.innerHTML = '<span>✅</span>Reported Successfully';
      this.elements.reportBtn.disabled = true;
      
      setTimeout(() => {
        this.elements.reportBtn.innerHTML = originalText;
        this.elements.reportBtn.disabled = false;
      }, 3000);
    } catch (error) {
      console.error('Report error:', error);
      this.showError('Failed to submit report');
    }
  }

  async addToWhitelist() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const url = new URL(tab.url);
      const domain = url.hostname;

      const result = await chrome.storage.local.get(['customWhitelist']);
      const whitelist = result.customWhitelist || [];
      
      if (!whitelist.includes(domain)) {
        whitelist.push(domain);
        await chrome.storage.local.set({ customWhitelist: whitelist });
        
        // Enhanced feedback
        const originalText = this.elements.whitelistBtn.innerHTML;
        this.elements.whitelistBtn.innerHTML = '<span>✅</span>Added to Trusted Sites';
        this.elements.whitelistBtn.disabled = true;
        
        setTimeout(() => {
          this.elements.whitelistBtn.innerHTML = originalText;
          this.elements.whitelistBtn.disabled = false;
        }, 3000);
      }
    } catch (error) {
      console.error('Whitelist error:', error);
      this.showError('Failed to add to whitelist');
    }
  }

  exportAnalysis(analysis) {
    const exportData = {
      ...analysis,
      exportDate: new Date().toISOString(),
      version: '1.0.0'
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishguard-analysis-${analysis.domain}-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }
}

// Initialize enhanced popup when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new AdvancedPopupController();
});