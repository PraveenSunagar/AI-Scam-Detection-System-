/**
 * AI Scam Detection System - Interactive Web Dashboard Client
 * Handles real-time ML inference, SVG gauge animations, simulator tabs,
 * batch analysis, API sandbox, and local history management.
 */

// Application State
const state = {
  currentResult: null,
  activeTab: 'scanner',
  activeChannel: 'SMS',
  samples: [],
  history: JSON.parse(localStorage.getItem('scam_scan_history') || '[]'),
  modelStats: null
};

// DOM Elements
const elements = {
  // Navigation
  tabButtons: document.querySelectorAll('.tab-btn'),
  tabPanes: document.querySelectorAll('.tab-pane'),
  channelPills: document.querySelectorAll('.channel-pill'),
  
  // Single Scanner Inputs
  messageInput: document.getElementById('messageInput'),
  senderInput: document.getElementById('senderInput'),
  charCount: document.getElementById('charCount'),
  btnScan: document.getElementById('btnScan'),
  btnClear: document.getElementById('btnClear'),
  sampleButtonsContainer: document.getElementById('sampleButtonsContainer'),
  
  // Single Scanner Verdict Elements
  gaugeScore: document.getElementById('gaugeScore'),
  gaugeMeter: document.getElementById('gaugeMeter'),
  riskBadge: document.getElementById('riskBadge'),
  verdictCategory: document.getElementById('verdictCategory'),
  explanationText: document.getElementById('explanationText'),
  triggersPreview: document.getElementById('triggersPreview'),
  entitiesContainer: document.getElementById('entitiesContainer'),
  adviceList: document.getElementById('adviceList'),
  
  // Indicator Bars
  barUrgency: document.getElementById('barUrgency'),
  valUrgency: document.getElementById('valUrgency'),
  barFinancial: document.getElementById('barFinancial'),
  valFinancial: document.getElementById('valFinancial'),
  barThreat: document.getElementById('barThreat'),
  valThreat: document.getElementById('valThreat'),
  barLink: document.getElementById('barLink'),
  valLink: document.getElementById('valLink'),
  
  // SMS Simulator
  smsPhoneSender: document.getElementById('smsPhoneSender'),
  smsPhoneText: document.getElementById('smsPhoneText'),
  smsShieldBadge: document.getElementById('smsShieldBadge'),
  smsInputText: document.getElementById('smsInputText'),
  btnSimulateSms: document.getElementById('btnSimulateSms'),
  
  // Email Inspector
  emailSender: document.getElementById('emailSender'),
  emailSubject: document.getElementById('emailSubject'),
  emailBody: document.getElementById('emailBody'),
  btnScanEmail: document.getElementById('btnScanEmail'),
  emailVerdictBadge: document.getElementById('emailVerdictBadge'),
  emailExplanation: document.getElementById('emailExplanation'),
  
  // Batch Scanner
  batchCsvInput: document.getElementById('batchCsvInput'),
  batchTextInput: document.getElementById('batchTextInput'),
  btnScanBatch: document.getElementById('btnScanBatch'),
  batchTotalCount: document.getElementById('batchTotalCount'),
  batchScamCount: document.getElementById('batchScamCount'),
  batchHamCount: document.getElementById('batchHamCount'),
  batchScamRate: document.getElementById('batchScamRate'),
  batchTableBody: document.getElementById('batchTableBody'),
  btnExportBatchCsv: document.getElementById('btnExportBatchCsv'),
  
  // API Sandbox
  apiCodePre: document.getElementById('apiCodePre'),
  apiPayloadText: document.getElementById('apiPayloadText'),
  btnSendApiReq: document.getElementById('btnSendApiReq'),
  apiResponsePre: document.getElementById('apiResponsePre'),
  apiLatency: document.getElementById('apiLatency'),
  apiSnippetTabs: document.querySelectorAll('.code-tab-btn'),
  
  // Stats
  statAccuracy: document.getElementById('statAccuracy'),
  statSamples: document.getElementById('statSamples'),
  statVocab: document.getElementById('statVocab'),
  topKeywordsBox: document.getElementById('topKeywordsBox')
};

let currentApiSnippetLang = 'curl';
let lastBatchResults = [];

// ==========================================
// Initialization
// ==========================================
document.addEventListener('DOMContentLoaded', () => {
  initEventListeners();
  fetchModelStats();
  fetchSampleScams();
  renderHistory();
  
  // Pre-load a default demo test vector
  if (elements.messageInput && !elements.messageInput.value) {
    loadSampleIntoScanner({
      message: "Dear customer, your SBI bank account has been blocked due to incomplete KYC. Update KYC immediately at http://sbi-kyc-verify.xyz/login to avoid permanent deactivation.",
      sender: "+1 (800) 555-0199",
      channel: "SMS"
    });
  }
});

// ==========================================
// Event Listeners
// ==========================================
function initEventListeners() {
  // Tab Switching
  elements.tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.tab;
      switchTab(target);
    });
  });

  // Channel Pills
  elements.channelPills.forEach(pill => {
    pill.addEventListener('click', () => {
      elements.channelPills.forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      state.activeChannel = pill.dataset.channel;
    });
  });

  // Character Counter & Live Debounce
  let typingTimer;
  if (elements.messageInput) {
    elements.messageInput.addEventListener('input', () => {
      const len = elements.messageInput.value.length;
      if (elements.charCount) elements.charCount.textContent = `${len} chars`;
      
      clearTimeout(typingTimer);
      if (len > 15) {
        typingTimer = setTimeout(() => {
          performSingleScan(false);
        }, 600);
      }
    });
  }

  // Scan & Clear Buttons
  if (elements.btnScan) {
    elements.btnScan.addEventListener('click', () => performSingleScan(true));
  }

  if (elements.btnClear) {
    elements.btnClear.addEventListener('click', () => {
      if (elements.messageInput) elements.messageInput.value = '';
      if (elements.charCount) elements.charCount.textContent = '0 chars';
      resetVerdictPanel();
    });
  }

  // SMS Simulator Scan
  if (elements.btnSimulateSms) {
    elements.btnSimulateSms.addEventListener('click', performSmsSimulation);
  }

  // Email Inspector Scan
  if (elements.btnScanEmail) {
    elements.btnScanEmail.addEventListener('click', performEmailScan);
  }

  // Batch Scanner
  if (elements.btnScanBatch) {
    elements.btnScanBatch.addEventListener('click', performBatchTextScan);
  }

  if (elements.batchCsvInput) {
    elements.batchCsvInput.addEventListener('change', handleCsvUpload);
  }

  if (elements.btnExportBatchCsv) {
    elements.btnExportBatchCsv.addEventListener('click', exportBatchToCsv);
  }

  // API Playground
  elements.apiSnippetTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      elements.apiSnippetTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      currentApiSnippetLang = tab.dataset.lang;
      updateApiCodeSnippet();
    });
  });

  if (elements.btnSendApiReq) {
    elements.btnSendApiReq.addEventListener('click', sendSandboxApiRequest);
  }

  if (elements.apiPayloadText) {
    elements.apiPayloadText.addEventListener('input', updateApiCodeSnippet);
  }
}

// ==========================================
// Tab Switching
// ==========================================
function switchTab(tabId) {
  state.activeTab = tabId;
  elements.tabButtons.forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tabId);
  });
  elements.tabPanes.forEach(pane => {
    pane.classList.toggle('active', pane.id === `tab-${tabId}`);
  });

  if (tabId === 'api') {
    updateApiCodeSnippet();
  }
}

// ==========================================
// API Calls & Data Fetching
// ==========================================
async function fetchModelStats() {
  try {
    const res = await fetch('/api/stats');
    if (!res.ok) return;
    const data = await res.json();
    state.modelStats = data;
    
    if (elements.statAccuracy && data.metrics?.accuracy) {
      elements.statAccuracy.textContent = `${(data.metrics.accuracy * 100).toFixed(1)}%`;
    }
    if (elements.statSamples && data.total_samples) {
      elements.statSamples.textContent = data.total_samples.toLocaleString();
    }
    if (elements.statVocab && data.vocabulary_size) {
      elements.statVocab.textContent = `${data.vocabulary_size} Tokens`;
    }

    if (elements.topKeywordsBox && data.top_scam_keywords) {
      renderTopKeywords(data.top_scam_keywords);
    }
  } catch (err) {
    console.error('Error fetching model stats:', err);
  }
}

async function fetchSampleScams() {
  try {
    const res = await fetch('/api/sample-scams');
    if (!res.ok) return;
    const data = await res.json();
    state.samples = data.samples || [];
    renderSampleButtons(state.samples);
  } catch (err) {
    console.error('Error fetching samples:', err);
  }
}

function renderSampleButtons(samples) {
  if (!elements.sampleButtonsContainer) return;
  elements.sampleButtonsContainer.innerHTML = '';

  samples.forEach(sample => {
    const btn = document.createElement('button');
    const isScam = sample.expected === 'Scam';
    btn.className = `sample-chip ${isScam ? 'chip-scam' : 'chip-ham'}`;
    btn.innerHTML = `<span>${isScam ? '⚠️' : '✅'}</span> ${sample.title}`;
    btn.addEventListener('click', () => loadSampleIntoScanner(sample));
    elements.sampleButtonsContainer.appendChild(btn);
  });
}

function loadSampleIntoScanner(sample) {
  if (elements.messageInput) {
    elements.messageInput.value = sample.message;
    elements.charCount.textContent = `${sample.message.length} chars`;
  }
  if (elements.senderInput && sample.sender) {
    elements.senderInput.value = sample.sender;
  }
  if (sample.channel) {
    state.activeChannel = sample.channel;
    elements.channelPills.forEach(p => {
      p.classList.toggle('active', p.dataset.channel === sample.channel);
    });
  }
  performSingleScan(true);
}

// ==========================================
// Single Message Scanning Logic
// ==========================================
async function performSingleScan(showToastOnComplete = false) {
  const text = elements.messageInput ? elements.messageInput.value.trim() : '';
  if (!text) {
    showToast('Please enter text to analyze', 'warning');
    return;
  }

  const payload = {
    text: text,
    sender: elements.senderInput ? elements.senderInput.value.trim() : null,
    channel: state.activeChannel
  };

  try {
    if (elements.btnScan) {
      elements.btnScan.innerHTML = '<span>⚡</span> Analyzing...';
      elements.btnScan.disabled = true;
    }

    const res = await fetch('/api/detect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Analysis request failed');
    }

    const result = await res.json();
    state.currentResult = result;
    renderVerdict(result);
    saveToHistory(result);

    if (showToastOnComplete) {
      showToast(
        result.is_scam ? `⚠️ Flagged: ${result.category}` : '✅ Clean: Legitimate Message',
        result.is_scam ? 'danger' : 'safe'
      );
    }
  } catch (err) {
    console.error('Scan error:', err);
    showToast(`Error: ${err.message}`, 'danger');
  } finally {
    if (elements.btnScan) {
      elements.btnScan.innerHTML = '<span>⚡</span> Run AI Security Scan';
      elements.btnScan.disabled = false;
    }
  }
}

// ==========================================
// Render Verdict & Animate Radial Gauge
// ==========================================
function renderVerdict(result) {
  const score = result.risk_score;
  const isScam = result.is_scam;

  // 1. Animate Radial Gauge
  animateRadialGauge(score);

  // 2. Risk Level Badge
  if (elements.riskBadge) {
    elements.riskBadge.className = 'risk-level-badge';
    if (result.risk_level === 'Safe') {
      elements.riskBadge.classList.add('badge-risk-safe');
      elements.riskBadge.innerHTML = `<span>🛡️</span> Legitimate / Safe`;
    } else if (result.risk_level === 'Suspicious') {
      elements.riskBadge.classList.add('badge-risk-suspicious');
      elements.riskBadge.innerHTML = `<span>⚠️</span> Suspicious Message`;
    } else {
      elements.riskBadge.classList.add('badge-risk-scam');
      elements.riskBadge.innerHTML = `<span>🚨</span> High Risk Scam`;
    }
  }

  // 3. Category & Explanation
  if (elements.verdictCategory) {
    elements.verdictCategory.textContent = result.category || 'General Classification';
  }
  if (elements.explanationText) {
    elements.explanationText.textContent = result.explanation;
  }

  // 4. Highlight In-Text Triggers
  renderTriggerHighlights(result.text, result.triggers);

  // 5. Indicators Breakdown
  renderIndicators(result.indicators);

  // 6. Extracted Entities
  renderEntities(result.extracted_entities);

  // 7. Defensive Advice
  renderAdvice(result.action_advice);
}

function animateRadialGauge(targetScore) {
  if (!elements.gaugeScore || !elements.gaugeMeter) return;

  const circumference = 440; // 2 * PI * r (r=70)
  const offset = circumference - (targetScore / 100) * circumference;
  elements.gaugeMeter.style.strokeDashoffset = offset;

  // Color interpolation
  let color = '#10b981'; // Green
  if (targetScore > 30 && targetScore <= 65) {
    color = '#f59e0b'; // Amber
  } else if (targetScore > 65) {
    color = '#ef4444'; // Red
  }
  elements.gaugeMeter.style.stroke = color;

  // Animate counter number
  let current = 0;
  const step = targetScore / 25;
  const timer = setInterval(() => {
    current += step;
    if (current >= targetScore) {
      current = targetScore;
      clearInterval(timer);
    }
    elements.gaugeScore.textContent = current.toFixed(1);
    elements.gaugeScore.style.color = color;
  }, 20);
}

function renderTriggerHighlights(originalText, triggers) {
  if (!elements.triggersPreview) return;

  if (!triggers || triggers.length === 0) {
    elements.triggersPreview.innerHTML = `<span style="color: var(--text-muted);">${escapeHtml(originalText)}</span>`;
    return;
  }

  // Highlight matched substrings
  let html = '';
  let lastIdx = 0;

  // Sort triggers by start index
  const sorted = [...triggers].sort((a, b) => a.start - b.start);

  sorted.forEach(t => {
    if (t.start >= lastIdx) {
      html += escapeHtml(originalText.substring(lastIdx, t.start));
      const chipClass = t.category === 'urgency' ? 'trigger-urgency' : (t.category === 'suspicious_link' ? 'trigger-link' : '');
      html += `<mark class="trigger-highlight ${chipClass}" title="Category: ${t.category}">${escapeHtml(originalText.substring(t.start, t.end))}</mark>`;
      lastIdx = t.end;
    }
  });

  if (lastIdx < originalText.length) {
    html += escapeHtml(originalText.substring(lastIdx));
  }

  elements.triggersPreview.innerHTML = html;
}

function renderIndicators(indicators) {
  if (!indicators) return;

  const setBar = (bar, valEl, score) => {
    if (!bar || !valEl) return;
    const pct = Math.round(score * 100);
    bar.style.width = `${pct}%`;
    valEl.textContent = `${pct}%`;

    if (pct > 60) {
      bar.style.background = 'var(--grad-danger)';
    } else if (pct > 30) {
      bar.style.background = 'var(--accent-warning)';
    } else {
      bar.style.background = 'var(--grad-safe)';
    }
  };

  setBar(elements.barUrgency, elements.valUrgency, indicators.urgency_score || 0);
  setBar(elements.barFinancial, elements.valFinancial, indicators.financial_score || 0);
  setBar(elements.barThreat, elements.valThreat, indicators.threat_score || 0);
  setBar(elements.barLink, elements.valLink, indicators.link_score || 0);
}

function renderEntities(entities) {
  if (!elements.entitiesContainer) return;
  elements.entitiesContainer.innerHTML = '';

  if (!entities) return;

  const addEntityPill = (type, list, icon) => {
    if (list && list.length > 0) {
      list.forEach(val => {
        const pill = document.createElement('span');
        pill.className = 'entity-pill';
        pill.innerHTML = `<span>${icon}</span> <strong>${type}:</strong> ${escapeHtml(val)}`;
        elements.entitiesContainer.appendChild(pill);
      });
    }
  };

  addEntityPill('URL', entities.urls, '🔗');
  addEntityPill('Phone', entities.phones, '📞');
  addEntityPill('Email', entities.emails, '✉️');
  addEntityPill('Amount', entities.currencies, '💰');

  if (elements.entitiesContainer.children.length === 0) {
    elements.entitiesContainer.innerHTML = '<span style="font-size:0.8rem; color:var(--text-dim);">No special entities (URLs, phones, currencies) detected.</span>';
  }
}

function renderAdvice(adviceList) {
  if (!elements.adviceList) return;
  elements.adviceList.innerHTML = '';

  if (!adviceList || adviceList.length === 0) return;

  adviceList.forEach(item => {
    const li = document.createElement('li');
    li.className = 'advice-item';
    li.innerHTML = `<span class="advice-icon">🛡️</span> <span>${escapeHtml(item)}</span>`;
    elements.adviceList.appendChild(li);
  });
}

function resetVerdictPanel() {
  if (elements.gaugeScore) elements.gaugeScore.textContent = '0.0';
  if (elements.gaugeMeter) elements.gaugeMeter.style.strokeDashoffset = '440';
  if (elements.riskBadge) {
    elements.riskBadge.className = 'risk-level-badge badge-risk-safe';
    elements.riskBadge.innerHTML = '<span>🛡️</span> Ready to Scan';
  }
  if (elements.verdictCategory) elements.verdictCategory.textContent = 'Awaiting input...';
  if (elements.explanationText) elements.explanationText.textContent = 'Enter or select a message above to run real-time AI security detection.';
  if (elements.triggersPreview) elements.triggersPreview.innerHTML = '<span style="color:var(--text-dim)">Trigger breakdown will appear here.</span>';
  if (elements.entitiesContainer) elements.entitiesContainer.innerHTML = '<span style="color:var(--text-dim)">No entities to display.</span>';
  renderIndicators({ urgency_score: 0, financial_score: 0, threat_score: 0, link_score: 0 });
}

// ==========================================
// SMS / Chat Simulator
// ==========================================
async function performSmsSimulation() {
  const text = elements.smsInputText ? elements.smsInputText.value.trim() : '';
  if (!text) {
    showToast('Please type an SMS message to simulate', 'warning');
    return;
  }

  try {
    const res = await fetch('/api/detect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: text, channel: 'SMS' })
    });
    const result = await res.json();

    if (elements.smsPhoneText) elements.smsPhoneText.textContent = text;
    if (elements.smsShieldBadge) {
      if (result.is_scam) {
        elements.smsShieldBadge.className = 'chat-security-shield-badge badge-risk-scam';
        elements.smsShieldBadge.innerHTML = `⚠️ THREAT: ${result.category} (${result.risk_score}%)`;
      } else {
        elements.smsShieldBadge.className = 'chat-security-shield-badge badge-risk-safe';
        elements.smsShieldBadge.innerHTML = `✅ SAFE MESSAGE (${result.risk_score}%)`;
      }
    }
  } catch (err) {
    console.error('SMS Simulation error:', err);
  }
}

// ==========================================
// Email Security Inspector
// ==========================================
async function performEmailScan() {
  const sender = elements.emailSender ? elements.emailSender.value.trim() : '';
  const subject = elements.emailSubject ? elements.emailSubject.value.trim() : '';
  const body = elements.emailBody ? elements.emailBody.value.trim() : '';

  const fullText = `From: ${sender}\nSubject: ${subject}\n\n${body}`;

  try {
    const res = await fetch('/api/detect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: fullText, sender: sender, channel: 'Email' })
    });
    const result = await res.json();

    if (elements.emailVerdictBadge) {
      elements.emailVerdictBadge.className = `risk-level-badge ${result.is_scam ? 'badge-risk-scam' : 'badge-risk-safe'}`;
      elements.emailVerdictBadge.innerHTML = `${result.is_scam ? '🚨 PHISHING SCAM DETECTED' : '🛡️ LEGITIMATE EMAIL'} (${result.risk_score}%)`;
    }
    if (elements.emailExplanation) {
      elements.emailExplanation.textContent = result.explanation;
    }
  } catch (err) {
    console.error('Email scan error:', err);
  }
}

// ==========================================
// Batch Scanner & CSV Upload
// ==========================================
async function performBatchTextScan() {
  const raw = elements.batchTextInput ? elements.batchTextInput.value.trim() : '';
  if (!raw) {
    showToast('Please enter multiple messages (one per line)', 'warning');
    return;
  }

  const messages = raw.split('\n').map(m => m.trim()).filter(m => m.length > 0);
  if (messages.length === 0) return;

  try {
    if (elements.btnScanBatch) elements.btnScanBatch.textContent = 'Processing Batch...';

    const res = await fetch('/api/batch-detect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ messages: messages })
    });

    const data = await res.json();
    renderBatchResults(data);
  } catch (err) {
    console.error('Batch scan error:', err);
    showToast(`Batch Error: ${err.message}`, 'danger');
  } finally {
    if (elements.btnScanBatch) elements.btnScanBatch.textContent = 'Scan Batch Messages';
  }
}

async function handleCsvUpload(e) {
  const file = e.target.files[0];
  if (!file) return;

  const formData = new FormData();
  formData.append('file', file);

  try {
    showToast(`Uploading and scanning ${file.name}...`, 'info');
    const res = await fetch('/api/upload-csv', {
      method: 'POST',
      body: formData
    });

    if (!res.ok) throw new Error('Failed to parse CSV file');
    const data = await res.json();
    renderBatchResults(data);
    showToast(`Successfully analyzed ${data.total_rows} rows!`, 'safe');
  } catch (err) {
    console.error('CSV upload error:', err);
    showToast(`CSV Upload Error: ${err.message}`, 'danger');
  }
}

function renderBatchResults(data) {
  lastBatchResults = data.results || [];

  if (elements.batchTotalCount) elements.batchTotalCount.textContent = data.total_analyzed || data.total_rows || 0;
  if (elements.batchScamCount) elements.batchScamCount.textContent = data.scam_count || 0;
  if (elements.batchHamCount) elements.batchHamCount.textContent = data.legitimate_count || 0;
  if (elements.batchScamRate) elements.batchScamRate.textContent = `${data.scam_percentage || 0}%`;

  if (!elements.batchTableBody) return;
  elements.batchTableBody.innerHTML = '';

  lastBatchResults.forEach((row, i) => {
    const tr = document.createElement('tr');
    const isScam = row.is_scam;
    tr.innerHTML = `
      <td><strong>#${i + 1}</strong></td>
      <td style="max-width: 320px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(row.text)}</td>
      <td><span class="risk-level-badge ${isScam ? 'badge-risk-scam' : 'badge-risk-safe'}" style="padding: 0.15rem 0.6rem; font-size: 0.72rem;">${row.label}</span></td>
      <td><strong>${row.risk_score}%</strong></td>
      <td>${escapeHtml(row.category)}</td>
      <td>
        <button class="btn-secondary" style="padding: 0.2rem 0.6rem; font-size: 0.72rem;" onclick="inspectBatchRow(${i})">Inspect</button>
      </td>
    `;
    elements.batchTableBody.appendChild(tr);
  });
}

window.inspectBatchRow = function(index) {
  if (lastBatchResults[index]) {
    const row = lastBatchResults[index];
    loadSampleIntoScanner({
      message: row.text,
      sender: row.sender || 'Batch Import',
      channel: row.channel || 'SMS'
    });
    switchTab('scanner');
  }
};

function exportBatchToCsv() {
  if (!lastBatchResults || lastBatchResults.length === 0) {
    showToast('No batch results available to export', 'warning');
    return;
  }

  let csvContent = 'data:text/csv;charset=utf-8,';
  csvContent += 'Index,Message,Classification,Risk_Score,Category\n';

  lastBatchResults.forEach((row, i) => {
    const cleanText = `"${row.text.replace(/"/g, '""')}"`;
    csvContent += `${i + 1},${cleanText},${row.label},${row.risk_score},"${row.category}"\n`;
  });

  const encodedUri = encodeURI(csvContent);
  const link = document.createElement('a');
  link.setAttribute('href', encodedUri);
  link.setAttribute('download', `scam_scan_report_${Date.now()}.csv`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

// ==========================================
// API Playground Sandbox
// ==========================================
function updateApiCodeSnippet() {
  if (!elements.apiCodePre) return;

  const payloadStr = elements.apiPayloadText ? elements.apiPayloadText.value : '{\n  "text": "Your bank account is locked. Update KYC at http://sbi-kyc-verify.xyz/login"\n}';
  const endpoint = `${window.location.origin}/api/detect`;

  let code = '';
  if (currentApiSnippetLang === 'curl') {
    code = `curl -X POST "${endpoint}" \\\n  -H "Content-Type: application/json" \\\n  -d '${payloadStr.replace(/\n/g, '')}'`;
  } else if (currentApiSnippetLang === 'python') {
    code = `import requests\n\nurl = "${endpoint}"\npayload = ${payloadStr}\n\nresponse = requests.post(url, json=payload)\nprint(response.json())`;
  } else if (currentApiSnippetLang === 'javascript') {
    code = `fetch("${endpoint}", {\n  method: "POST",\n  headers: { "Content-Type": "application/json" },\n  body: JSON.stringify(${payloadStr})\n})\n.then(res => res.json())\n.then(data => console.log(data));`;
  }

  elements.apiCodePre.textContent = code;
}

async function sendSandboxApiRequest() {
  if (!elements.apiResponsePre) return;

  const payloadText = elements.apiPayloadText ? elements.apiPayloadText.value.trim() : '';
  let payloadObj;
  try {
    payloadObj = JSON.parse(payloadText);
  } catch (e) {
    showToast('Invalid JSON in payload editor', 'danger');
    return;
  }

  const startTime = performance.now();
  try {
    elements.apiResponsePre.textContent = 'Sending request to /api/detect...';

    const res = await fetch('/api/detect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payloadObj)
    });

    const elapsed = Math.round(performance.now() - startTime);
    if (elements.apiLatency) elements.apiLatency.textContent = `${elapsed} ms`;

    const data = await res.json();
    elements.apiResponsePre.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    elements.apiResponsePre.textContent = `Error: ${err.message}`;
  }
}

// ==========================================
// Model Insights & Top Keywords
// ==========================================
function renderTopKeywords(keywords) {
  if (!elements.topKeywordsBox) return;
  elements.topKeywordsBox.innerHTML = '';

  keywords.forEach(kw => {
    const badge = document.createElement('span');
    badge.className = 'sample-chip chip-scam';
    badge.style.fontSize = '0.72rem';
    badge.innerHTML = `<strong>#</strong> ${escapeHtml(kw)}`;
    elements.topKeywordsBox.appendChild(badge);
  });
}

// ==========================================
// History Management & LocalStorage
// ==========================================
function saveToHistory(result) {
  const item = {
    id: Date.now(),
    text: result.text.substring(0, 80) + '...',
    fullText: result.text,
    label: result.label,
    is_scam: result.is_scam,
    risk_score: result.risk_score,
    category: result.category,
    timestamp: new Date().toLocaleTimeString()
  };

  state.history.unshift(item);
  if (state.history.length > 20) state.history.pop();
  localStorage.setItem('scam_scan_history', JSON.stringify(state.history));
  renderHistory();
}

function renderHistory() {
  const container = document.getElementById('recentHistoryList');
  if (!container) return;

  container.innerHTML = '';
  if (state.history.length === 0) {
    container.innerHTML = '<div style="font-size:0.8rem; color:var(--text-dim); padding: 0.5rem 0;">No previous scans recorded.</div>';
    return;
  }

  state.history.slice(0, 5).forEach(h => {
    const div = document.createElement('div');
    div.className = 'metric-card';
    div.style.padding = '0.6rem 0.85rem';
    div.style.cursor = 'pointer';
    div.innerHTML = `
      <div style="font-size: 1.1rem;">${h.is_scam ? '🚨' : '🛡️'}</div>
      <div style="flex: 1; min-width: 0;">
        <div style="font-size: 0.8rem; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(h.text)}</div>
        <div style="font-size: 0.68rem; color: var(--text-dim);">${h.category} • ${h.timestamp}</div>
      </div>
      <div style="font-family: var(--font-mono); font-size: 0.82rem; font-weight: 700; color: ${h.is_scam ? 'var(--accent-danger)' : 'var(--accent-safe)'};">${h.risk_score}%</div>
    `;
    div.addEventListener('click', () => {
      loadSampleIntoScanner({
        message: h.fullText,
        sender: 'History',
        channel: 'SMS'
      });
      switchTab('scanner');
    });
    container.appendChild(div);
  });
}

// ==========================================
// Toast Notifications & Utilities
// ==========================================
function showToast(message, type = 'info') {
  let container = document.querySelector('.toast-container');
  if (!container) {
    container = document.createElement('div');
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = 'toast';
  
  let icon = 'ℹ️';
  if (type === 'safe') icon = '✅';
  if (type === 'danger') icon = '🚨';
  if (type === 'warning') icon = '⚠️';

  toast.innerHTML = `<span>${icon}</span> <span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

function escapeHtml(text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
