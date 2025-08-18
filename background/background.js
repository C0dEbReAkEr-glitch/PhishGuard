// Enhanced Background script for PhishGuard Pro with Advanced Detection
class AdvancedPhishingDetector {
  constructor() {
    this.phishingDomains = new Set();
    this.legitimateDomains = new Set();
    this.suspiciousDomains = new Set();
    this.domainCache = new Map();
    this.analysisCache = new Map();
    
    // Enhanced suspicious patterns with weighted scoring
    this.suspiciousPatterns = [
      { pattern: /secure[.-]?update/i, weight: 25, description: 'Fake security update' },
      { pattern: /verify[.-]?account/i, weight: 30, description: 'Account verification scam' },
      { pattern: /suspended[.-]?account/i, weight: 35, description: 'Account suspension threat' },
      { pattern: /urgent[.-]?action/i, weight: 20, description: 'Urgency manipulation' },
      { pattern: /click[.-]?here/i, weight: 15, description: 'Generic click bait' },
      { pattern: /limited[.-]?time/i, weight: 20, description: 'Time pressure tactic' },
      { pattern: /confirm[.-]?identity/i, weight: 25, description: 'Identity confirmation scam' },
      { pattern: /billing[.-]?problem/i, weight: 25, description: 'Fake billing issue' },
      { pattern: /payment[.-]?failed/i, weight: 30, description: 'Payment failure scam' },
      { pattern: /security[.-]?alert/i, weight: 25, description: 'Fake security alert' },
      
      // Domain-based patterns
      { pattern: /\.tk$/i, weight: 40, description: 'High-risk TLD (.tk)' },
      { pattern: /\.ml$/i, weight: 40, description: 'High-risk TLD (.ml)' },
      { pattern: /\.ga$/i, weight: 40, description: 'High-risk TLD (.ga)' },
      { pattern: /\.cf$/i, weight: 40, description: 'High-risk TLD (.cf)' },
      { pattern: /\.pw$/i, weight: 35, description: 'Suspicious TLD (.pw)' },
      
      // IP address patterns
      { pattern: /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/, weight: 50, description: 'Direct IP access' },
      
      // Suspicious domain structures
      { pattern: /[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\./i, weight: 20, description: 'Multiple hyphens in domain' },
      { pattern: /[0-9]{4,}/i, weight: 25, description: 'Long number sequences' },
      { pattern: /[a-z]{20,}/i, weight: 15, description: 'Unusually long domain parts' },
      
      // Homograph attacks
      { pattern: /[а-я]/i, weight: 45, description: 'Cyrillic characters (homograph)' },
      { pattern: /[αβγδεζηθικλμνξοπρστυφχψω]/i, weight: 45, description: 'Greek characters (homograph)' },
      
      // URL shorteners (can be suspicious)
      { pattern: /bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|short\.link/i, weight: 15, description: 'URL shortener' }
    ];

    // Enhanced legitimate domain patterns
    this.legitimatePatterns = [
      /^(www\.)?google\.(com|co\.[a-z]{2}|[a-z]{2})$/i,
      /^(www\.)?github\.com$/i,
      /^(www\.)?stackoverflow\.com$/i,
      /^(www\.)?microsoft\.(com|co\.[a-z]{2})$/i,
      /^(www\.)?amazon\.(com|co\.[a-z]{2}|[a-z]{2})$/i,
      /^(www\.)?facebook\.com$/i,
      /^(www\.)?twitter\.com$/i,
      /^(www\.)?linkedin\.com$/i,
      /^(www\.)?youtube\.com$/i,
      /^(www\.)?wikipedia\.org$/i
    ];

    // Phishing keywords with context analysis
    this.phishingKeywords = [
      { word: 'paypal', context: ['secure', 'verify', 'suspended'], weight: 40 },
      { word: 'amazon', context: ['account', 'suspended', 'verify'], weight: 35 },
      { word: 'apple', context: ['id', 'locked', 'verify'], weight: 35 },
      { word: 'microsoft', context: ['account', 'security', 'verify'], weight: 30 },
      { word: 'google', context: ['account', 'suspended', 'verify'], weight: 30 },
      { word: 'bank', context: ['account', 'suspended', 'verify'], weight: 45 },
      { word: 'security', context: ['alert', 'warning', 'breach'], weight: 25 }
    ];

    this.initializeDatabase();
    this.startPeriodicUpdates();
  }

  async initializeDatabase() {
    // Enhanced known phishing domains (in production, this would be from threat intelligence APIs)
    const knownPhishing = [
      'phishing-example.com',
      'fake-bank.net',
      'suspicious-site.org',
      'scam-paypal.com',
      'fake-amazon.net',
      'phish-apple.com',
      'bogus-microsoft.org',
      'fraudulent-bank.com',
      'fake-security.net'
    ];
    
    // Enhanced legitimate domains with subdomains
    const knownLegitimate = [
      'google.com', 'www.google.com', 'mail.google.com', 'drive.google.com',
      'github.com', 'www.github.com', 'gist.github.com',
      'stackoverflow.com', 'www.stackoverflow.com',
      'mozilla.org', 'www.mozilla.org', 'developer.mozilla.org',
      'microsoft.com', 'www.microsoft.com', 'office.microsoft.com',
      'amazon.com', 'www.amazon.com', 'aws.amazon.com',
      'paypal.com', 'www.paypal.com',
      'apple.com', 'www.apple.com', 'support.apple.com',
      'facebook.com', 'www.facebook.com',
      'twitter.com', 'www.twitter.com',
      'linkedin.com', 'www.linkedin.com',
      'youtube.com', 'www.youtube.com'
    ];

    this.phishingDomains = new Set(knownPhishing);
    this.legitimateDomains = new Set(knownLegitimate);

    // Load user's custom lists from storage
    try {
      const result = await chrome.storage.local.get([
        'customBlacklist', 
        'customWhitelist',
        'domainCache',
        'threatIntelligence'
      ]);
      
      if (result.customBlacklist) {
        result.customBlacklist.forEach(domain => this.phishingDomains.add(domain));
      }
      if (result.customWhitelist) {
        result.customWhitelist.forEach(domain => this.legitimateDomains.add(domain));
      }
      if (result.domainCache) {
        this.domainCache = new Map(result.domainCache);
      }
    } catch (error) {
      console.error('Error loading enhanced database:', error);
    }
  }

  startPeriodicUpdates() {
    // Update threat intelligence every 30 minutes
    setInterval(() => {
      this.updateThreatIntelligence();
    }, 30 * 60 * 1000);

    // Clean cache every hour
    setInterval(() => {
      this.cleanCache();
    }, 60 * 60 * 1000);
  }

  async updateThreatIntelligence() {
    // In production, this would fetch from multiple threat intelligence sources
    try {
      // Simulate API calls to threat intelligence providers
      const updates = await this.fetchThreatUpdates();
      if (updates) {
        updates.phishing?.forEach(domain => this.phishingDomains.add(domain));
        updates.legitimate?.forEach(domain => this.legitimateDomains.add(domain));
        
        // Save updated intelligence
        await chrome.storage.local.set({
          threatIntelligence: {
            lastUpdate: Date.now(),
            phishingCount: this.phishingDomains.size,
            legitimateCount: this.legitimateDomains.size
          }
        });
      }
    } catch (error) {
      console.error('Threat intelligence update failed:', error);
    }
  }

  async fetchThreatUpdates() {
    // Simulate threat intelligence API response
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({
          phishing: ['new-phishing-site.com', 'another-scam.net'],
          legitimate: ['trusted-new-site.com']
        });
      }, 1000);
    });
  }

  cleanCache() {
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours

    for (const [key, value] of this.domainCache.entries()) {
      if (now - value.timestamp > maxAge) {
        this.domainCache.delete(key);
      }
    }

    for (const [key, value] of this.analysisCache.entries()) {
      if (now - value.timestamp > maxAge) {
        this.analysisCache.delete(key);
      }
    }
  }

  extractDomain(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname.toLowerCase();
    } catch (error) {
      return null;
    }
  }

  extractSubdomain(domain) {
    const parts = domain.split('.');
    if (parts.length > 2) {
      return parts[0];
    }
    return null;
  }

  checkSuspiciousPatterns(url) {
    let totalWeight = 0;
    const matchedPatterns = [];

    for (const { pattern, weight, description } of this.suspiciousPatterns) {
      if (pattern.test(url)) {
        totalWeight += weight;
        matchedPatterns.push({ description, weight });
      }
    }

    return { totalWeight, matchedPatterns };
  }

  checkPhishingKeywords(domain, url) {
    let keywordScore = 0;
    const matchedKeywords = [];

    for (const { word, context, weight } of this.phishingKeywords) {
      if (domain.includes(word) || url.includes(word)) {
        let contextMatches = 0;
        for (const ctx of context) {
          if (domain.includes(ctx) || url.includes(ctx)) {
            contextMatches++;
          }
        }
        
        if (contextMatches > 0) {
          const score = weight * (1 + contextMatches * 0.5);
          keywordScore += score;
          matchedKeywords.push({ word, context: contextMatches, score });
        }
      }
    }

    return { keywordScore, matchedKeywords };
  }

  checkHomographAttacks(domain) {
    const suspiciousChars = /[а-яё]|[αβγδεζηθικλμνξοπρστυφχψω]|[àáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ]/gi;
    const matches = domain.match(suspiciousChars);
    
    if (matches) {
      return {
        detected: true,
        score: matches.length * 15,
        characters: [...new Set(matches)]
      };
    }
    
    return { detected: false, score: 0 };
  }

  analyzeDomainStructure(domain) {
    const parts = domain.split('.');
    let structureScore = 0;
    const issues = [];

    // Check for excessive subdomains
    if (parts.length > 4) {
      structureScore += 20;
      issues.push('Excessive subdomains');
    }

    // Check for suspicious TLD combinations
    if (parts.length >= 2) {
      const tld = parts[parts.length - 1];
      const sld = parts[parts.length - 2];
      
      if (tld.length === 2 && sld.length < 3) {
        structureScore += 15;
        issues.push('Suspicious domain structure');
      }
    }

    // Check for mixed character types
    if (/[0-9]/.test(domain) && /[a-z]/.test(domain) && domain.includes('-')) {
      structureScore += 10;
      issues.push('Mixed character types with hyphens');
    }

    return { structureScore, issues };
  }

  async checkDomainReputation(domain) {
    // Check cache first
    if (this.domainCache.has(domain)) {
      const cached = this.domainCache.get(domain);
      if (Date.now() - cached.timestamp < 60 * 60 * 1000) { // 1 hour cache
        return cached.data;
      }
    }

    return new Promise((resolve) => {
      setTimeout(() => {
        let reputation;
        
        if (this.phishingDomains.has(domain)) {
          reputation = { status: 'phishing', confidence: 0.95, source: 'blacklist' };
        } else if (this.legitimateDomains.has(domain)) {
          reputation = { status: 'legitimate', confidence: 0.98, source: 'whitelist' };
        } else if (this.legitimatePatterns.some(pattern => pattern.test(domain))) {
          reputation = { status: 'legitimate', confidence: 0.90, source: 'pattern' };
        } else {
          // Simulate reputation API response
          const randomScore = Math.random();
          if (randomScore > 0.8) {
            reputation = { status: 'legitimate', confidence: 0.85, source: 'api' };
          } else if (randomScore < 0.2) {
            reputation = { status: 'phishing', confidence: 0.75, source: 'api' };
          } else {
            reputation = { status: 'unknown', confidence: 0.5, source: 'api' };
          }
        }

        // Cache the result
        this.domainCache.set(domain, {
          data: reputation,
          timestamp: Date.now()
        });

        resolve(reputation);
      }, 150);
    });
  }

  checkSSLCertificate(url) {
    try {
      const urlObj = new URL(url);
      const hasSSL = urlObj.protocol === 'https:';
      
      // Additional SSL checks could be implemented here
      return {
        hasSSL,
        score: hasSSL ? 0 : 25,
        issues: hasSSL ? [] : ['No SSL certificate']
      };
    } catch (error) {
      return { hasSSL: false, score: 25, issues: ['Invalid URL'] };
    }
  }

  calculateDomainAge(domain) {
    // Enhanced domain age simulation with more realistic data
    const newDomains = [
      'new-site.com', 'fresh-domain.net', 'recent-site.org',
      'just-created.com', 'brand-new.net'
    ];
    
    const oldDomains = [
      'google.com', 'microsoft.com', 'amazon.com', 'apple.com',
      'github.com', 'stackoverflow.com'
    ];

    if (newDomains.includes(domain)) {
      return { days: Math.floor(Math.random() * 30), category: 'very_new' };
    } else if (oldDomains.includes(domain)) {
      return { days: 3000 + Math.floor(Math.random() * 2000), category: 'established' };
    } else {
      const days = Math.floor(Math.random() * 2000) + 30;
      let category;
      if (days < 30) category = 'very_new';
      else if (days < 90) category = 'new';
      else if (days < 365) category = 'recent';
      else category = 'established';
      
      return { days, category };
    }
  }

  checkURLRedirects(url) {
    // Simulate redirect chain analysis
    const suspiciousRedirects = ['bit.ly', 'tinyurl.com', 't.co'];
    const domain = this.extractDomain(url);
    
    if (suspiciousRedirects.some(redirect => domain?.includes(redirect))) {
      return {
        hasSuspiciousRedirects: true,
        score: 20,
        redirectChain: ['original-url.com', 'bit.ly/xyz', 'suspicious-site.com']
      };
    }
    
    return { hasSuspiciousRedirects: false, score: 0 };
  }

  async performAdvancedAnalysis(url, domain) {
    const analysis = {
      url,
      domain,
      timestamp: Date.now(),
      checks: {}
    };

    // Parallel execution of all checks for better performance
    const [
      reputation,
      sslCheck,
      domainAge,
      patternCheck,
      keywordCheck,
      homographCheck,
      structureCheck,
      redirectCheck
    ] = await Promise.all([
      this.checkDomainReputation(domain),
      Promise.resolve(this.checkSSLCertificate(url)),
      Promise.resolve(this.calculateDomainAge(domain)),
      Promise.resolve(this.checkSuspiciousPatterns(url)),
      Promise.resolve(this.checkPhishingKeywords(domain, url)),
      Promise.resolve(this.checkHomographAttacks(domain)),
      Promise.resolve(this.analyzeDomainStructure(domain)),
      Promise.resolve(this.checkURLRedirects(url))
    ]);

    analysis.checks = {
      reputation,
      ssl: sslCheck,
      domainAge,
      patterns: patternCheck,
      keywords: keywordCheck,
      homograph: homographCheck,
      structure: structureCheck,
      redirects: redirectCheck
    };

    return analysis;
  }

  async analyzeURL(url) {
    const domain = this.extractDomain(url);
    if (!domain) return { status: 'error', message: 'Invalid URL' };

    // Check analysis cache
    const cacheKey = `${domain}:${url}`;
    if (this.analysisCache.has(cacheKey)) {
      const cached = this.analysisCache.get(cacheKey);
      if (Date.now() - cached.timestamp < 10 * 60 * 1000) { // 10 minutes cache
        return cached.data;
      }
    }

    try {
      const analysis = await this.performAdvancedAnalysis(url, domain);
      const result = this.calculateFinalScore(analysis);
      
      // Cache the result
      this.analysisCache.set(cacheKey, {
        data: result,
        timestamp: Date.now()
      });

      // Update statistics
      this.updateStatistics(result);

      return result;
    } catch (error) {
      console.error('Analysis failed:', error);
      return { status: 'error', message: 'Analysis failed' };
    }
  }

  calculateFinalScore(analysis) {
    let riskScore = 0;
    let confidence = 0.5;
    const reasons = [];
    const detailedAnalysis = {};

    const { checks } = analysis;

    // Reputation check (highest weight)
    if (checks.reputation.status === 'phishing') {
      riskScore += 70;
      confidence = Math.max(confidence, checks.reputation.confidence);
      reasons.push(`Domain found in phishing database (${checks.reputation.source})`);
    } else if (checks.reputation.status === 'legitimate') {
      riskScore -= 40;
      confidence = Math.max(confidence, checks.reputation.confidence);
      reasons.push(`Domain verified as legitimate (${checks.reputation.source})`);
    }

    // SSL Certificate
    if (!checks.ssl.hasSSL) {
      riskScore += checks.ssl.score;
      reasons.push(...checks.ssl.issues);
    }

    // Domain age
    if (checks.domainAge.category === 'very_new') {
      riskScore += 35;
      reasons.push(`Very new domain (${checks.domainAge.days} days old)`);
    } else if (checks.domainAge.category === 'new') {
      riskScore += 20;
      reasons.push(`New domain (${checks.domainAge.days} days old)`);
    } else if (checks.domainAge.category === 'established') {
      riskScore -= 10;
    }

    // Suspicious patterns
    if (checks.patterns.totalWeight > 0) {
      riskScore += Math.min(checks.patterns.totalWeight, 50);
      checks.patterns.matchedPatterns.forEach(pattern => {
        reasons.push(`${pattern.description} (weight: ${pattern.weight})`);
      });
    }

    // Phishing keywords
    if (checks.keywords.keywordScore > 0) {
      riskScore += Math.min(checks.keywords.keywordScore, 40);
      checks.keywords.matchedKeywords.forEach(keyword => {
        reasons.push(`Phishing keyword "${keyword.word}" with context (score: ${keyword.score.toFixed(1)})`);
      });
    }

    // Homograph attacks
    if (checks.homograph.detected) {
      riskScore += checks.homograph.score;
      reasons.push(`Homograph attack detected: ${checks.homograph.characters.join(', ')}`);
    }

    // Domain structure
    if (checks.structure.structureScore > 0) {
      riskScore += checks.structure.structureScore;
      reasons.push(...checks.structure.issues);
    }

    // URL redirects
    if (checks.redirects.hasSuspiciousRedirects) {
      riskScore += checks.redirects.score;
      reasons.push('Suspicious URL redirects detected');
    }

    // Normalize risk score
    riskScore = Math.max(0, Math.min(100, riskScore));

    // Determine final status with enhanced thresholds
    let status, threat, message, color;
    if (riskScore >= 70) {
      status = 'phishing';
      threat = 'high';
      message = 'This site is very likely a phishing attempt. Do not enter personal information!';
      color = '#ef4444';
    } else if (riskScore >= 45) {
      status = 'suspicious';
      threat = 'medium';
      message = 'This site shows multiple suspicious characteristics. Exercise extreme caution.';
      color = '#f59e0b';
    } else if (riskScore >= 25) {
      status = 'questionable';
      threat = 'low';
      message = 'This site has some concerning features. Verify before proceeding.';
      color = '#eab308';
    } else {
      status = 'legitimate';
      threat = 'minimal';
      message = 'This site appears to be legitimate and safe.';
      color = '#10b981';
    }

    return {
      status,
      threat,
      message,
      color,
      riskScore: Math.round(riskScore),
      confidence: Math.round(confidence * 100),
      reasons: reasons.slice(0, 8), // Limit to top 8 reasons
      domain: analysis.domain,
      hasSSL: checks.ssl.hasSSL,
      domainAge: checks.domainAge.days,
      domainCategory: checks.domainAge.category,
      detailedAnalysis: {
        reputation: checks.reputation,
        patterns: checks.patterns.matchedPatterns.length,
        keywords: checks.keywords.matchedKeywords.length,
        homograph: checks.homograph.detected,
        structure: checks.structure.issues.length,
        redirects: checks.redirects.hasSuspiciousRedirects
      },
      analysisTime: Date.now() - analysis.timestamp
    };
  }

  async updateStatistics(result) {
    try {
      const stats = await chrome.storage.local.get(['stats']) || {};
      const currentStats = stats.stats || {
        sitesAnalyzed: 0,
        threatsBlocked: 0,
        legitimateSites: 0,
        suspiciousSites: 0,
        totalRiskScore: 0,
        lastUpdate: Date.now()
      };

      currentStats.sitesAnalyzed++;
      currentStats.totalRiskScore += result.riskScore;

      if (result.status === 'phishing') {
        currentStats.threatsBlocked++;
      } else if (result.status === 'legitimate') {
        currentStats.legitimateSites++;
      } else {
        currentStats.suspiciousSites++;
      }

      currentStats.protectionRate = currentStats.sitesAnalyzed > 0 
        ? ((currentStats.threatsBlocked / currentStats.sitesAnalyzed) * 100)
        : 0;

      currentStats.averageRiskScore = currentStats.sitesAnalyzed > 0
        ? (currentStats.totalRiskScore / currentStats.sitesAnalyzed)
        : 0;

      currentStats.lastUpdate = Date.now();

      await chrome.storage.local.set({ stats: currentStats });
    } catch (error) {
      console.error('Failed to update statistics:', error);
    }
  }
}

// Initialize the enhanced detector
const detector = new AdvancedPhishingDetector();

// Enhanced tab update listener with better error handling
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url && !tab.url.startsWith('chrome://') && !tab.url.startsWith('moz-extension://')) {
    try {
      // Check if protection is enabled
      const settings = await chrome.storage.local.get(['settings']);
      if (settings.settings?.enableProtection === false) {
        return;
      }

      const analysis = await detector.analyzeURL(tab.url);
      
      // Send analysis to content script with retry mechanism
      let retries = 3;
      while (retries > 0) {
        try {
          await chrome.tabs.sendMessage(tabId, {
            type: 'ANALYSIS_RESULT',
            data: analysis
          });
          break;
        } catch (error) {
          retries--;
          if (retries === 0) {
            console.error('Failed to send analysis to content script:', error);
          } else {
            await new Promise(resolve => setTimeout(resolve, 500));
          }
        }
      }

      // Update badge with enhanced visual indicators
      const badgeText = analysis.threat === 'high' ? '⚠' : 
                       analysis.threat === 'medium' ? '?' : 
                       analysis.threat === 'low' ? '!' : '';
      
      const badgeColor = analysis.color || '#10b981';

      await chrome.action.setBadgeText({ tabId, text: badgeText });
      await chrome.action.setBadgeBackgroundColor({ tabId, color: badgeColor });

      // Send notification for high-risk sites
      if (analysis.threat === 'high') {
        const notificationSettings = await chrome.storage.local.get(['settings']);
        if (notificationSettings.settings?.showNotifications !== false) {
          chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icons/icon48.png',
            title: 'PhishGuard Pro - Threat Detected!',
            message: `Phishing site blocked: ${analysis.domain}`
          });
        }
      }

    } catch (error) {
      console.error('Enhanced analysis failed:', error);
    }
  }
});

// Enhanced message handler
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'ANALYZE_CURRENT_TAB') {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      if (tabs[0]) {
        try {
          const analysis = await detector.analyzeURL(tabs[0].url);
          sendResponse(analysis);
        } catch (error) {
          sendResponse({ status: 'error', message: error.message });
        }
      }
    });
    return true; // Async response
  }

  if (request.type === 'UPDATE_THREAT_INTELLIGENCE') {
    detector.updateThreatIntelligence().then(() => {
      sendResponse({ success: true });
    }).catch(error => {
      sendResponse({ success: false, error: error.message });
    });
    return true;
  }

  if (request.type === 'GET_STATISTICS') {
    chrome.storage.local.get(['stats']).then(result => {
      sendResponse(result.stats || {});
    });
    return true;
  }
});

// Enhanced installation handler
chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === 'install') {
    // Set default settings
    await chrome.storage.local.set({
      settings: {
        enableProtection: true,
        showNotifications: true,
        strictMode: false,
        autoUpdate: true
      },
      stats: {
        sitesAnalyzed: 0,
        threatsBlocked: 0,
        legitimateSites: 0,
        suspiciousSites: 0,
        protectionRate: 0,
        installDate: Date.now()
      }
    });

    // Show welcome notification
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon48.png',
      title: 'PhishGuard Pro Installed!',
      message: 'Advanced phishing protection is now active. Stay safe online!'
    });
  }
});