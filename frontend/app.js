/**
 * app.js — Main application logic for opago Travel Rule Demo.
 * Self-contained demo: simulates the full LNURL → eID → Travel Rule flow client-side.
 *
 * Correct flow:
 * 1. Receiver (opago) publishes LNURL-pay endpoint
 * 2. Sender resolves LNURL, enters amount
 * 3. Amount exceeds €1,000 → Travel Rule triggered
 * 4. Sender identifies with German ePerso (eID)
 * 5. Travel rule data sent to receiving VASP
 * 6. Receiving VASP runs compliance checks
 * 7. Invoice issued, payment settled
 */

/* global eidManager */

(function () {
  'use strict';

  const TRAVEL_RULE_THRESHOLD_EUR = 0;
  let initialized = false;

  // ── State ──────────────────────────────────────────────
  const state = {
    sessionId: null,
    currentStep: 1,
    amountSats: 2100,
    amountEur: 0,
    btcEurPrice: 82450,
    receivingVasp: 'opago',
    lnurl: 'LNURL1DP68GURN8GHJ7AMPD3KX2AR0VEEKZAR0WD5XJTNRDAKJ7TNHV4KXCTTTDEHHWM30D3H82UNV9AMKJARGV3EXZAE0',
    identityData: null,
    travelRulePayload: null,
    complianceChecks: {
      originator_identified: 'pending',
      travel_rule_complete: 'pending',
      sanctions_screening: 'pending',
      vasp_registered: 'pending',
    },
    thresholdExceeded: false,
    invoice: null,
    senderApiBase: 'http://localhost:3001',
    receiverApiBase: 'http://localhost:3002',
  };

  // ── SVG Icons ─────────────────────────────────────────
  const icons = {
    check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
    alert: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
    spinner: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M12 2a10 10 0 1 0 10 10" /></svg>',
  };

  // ── DOM helpers ────────────────────────────────────────
  const $ = (sel, ctx = document) => ctx.querySelector(sel);
  const $$ = (sel, ctx = document) => Array.from(ctx.querySelectorAll(sel));

  function setHTML(sel, html) {
    const el = $(sel);
    if (el) el.innerHTML = html;
  }

  function setText(sel, text) {
    const el = $(sel);
    if (el) el.textContent = text;
  }

  function show(sel) {
    const el = $(sel);
    if (el) el.classList.remove('hidden');
  }

  function hide(sel) {
    const el = $(sel);
    if (el) el.classList.add('hidden');
  }

  function showEl(el) {
    if (el) el.classList.remove('hidden');
  }

  function hideEl(el) {
    if (el) el.classList.add('hidden');
  }

  // ── Utilities ──────────────────────────────────────────
  function generateSessionId() {
    return 'TR-' + Math.random().toString(36).substr(2, 9).toUpperCase();
  }

  function formatBTC(sats) {
    return (sats / 1e8).toFixed(5) + ' BTC';
  }

  function formatEUR(eur) {
    return new Intl.NumberFormat('de-DE', { style: 'currency', currency: 'EUR' }).format(eur);
  }

  // ── Step navigation (LEFT panel) ──────────────────────
  function setStep(stepNumber) {
    state.currentStep = stepNumber;
    const steps = $$('#left-content .step');
    steps.forEach((item) => {
      const s = parseInt(item.dataset.step);
      item.classList.remove('active', 'completed', 'hidden');
      if (s === stepNumber) {
        item.classList.add('active');
      } else if (s < stepNumber) {
        item.classList.add('completed');
      } else {
        item.classList.add('hidden');
      }
    });
    steps.forEach((item) => {
      if (!item.classList.contains('active')) {
        collapseStepContent(item);
      }
    });
    const activeStepEl = $(`#left-content .step[data-step="${stepNumber}"]`);
    if (activeStepEl) {
      activeStepEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }

  // ── Step navigation (RIGHT panel) ─────────────────────
  function setRightStep(stepNumber) {
    const steps = $$('#right-content .receiver-step');
    steps.forEach((item) => {
      const s = parseInt(item.dataset.step);
      item.classList.remove('active', 'completed', 'hidden');
      if (s === stepNumber) {
        item.classList.add('active');
      } else if (s < stepNumber) {
        item.classList.add('completed');
      } else {
        item.classList.add('hidden');
      }
    });
    steps.forEach((item) => {
      if (!item.classList.contains('active')) {
        collapseStepContent(item);
      }
    });
    const activeRightStepEl = $(`#right-content .receiver-step[data-step="${stepNumber}"]`);
    if (activeRightStepEl) {
      activeRightStepEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }

  // ── Collapse helper ────────────────────────────────────
  function collapseStepContent(contentEl) {
    // Left-panel elements
    const toHide = [
      '.lnurl-details',
      '.amount-input-group',
      '.eid-simulation',
      '.travel-rule-payload',
      '.payment-result',
      // Right-panel elements
      '.check-list',
      '.compliance-summary',
      '.right-travel-rule-data',
      '.invoice-details',
      '.settlement-details',
    ];
    toHide.forEach((sel) => {
      const el = $(sel, contentEl);
      if (el) el.classList.add('hidden');
    });
  }

  // ── Initialization ─────────────────────────────────────
  async function init() {
    if (initialized) return;
    initialized = true;

    state.sessionId = generateSessionId();
    state.amountEur = (state.amountSats / 1e8) * state.btcEurPrice;
    state.thresholdExceeded = state.amountEur >= TRAVEL_RULE_THRESHOLD_EUR;

    await loadConfig();

    // Render initial UI
    renderLNURLStep();
    renderAmountStep();
    renderPriceInfo();
    setStep(1);
    setRightStep(1);
    renderReceiverStep(1);

    // Bind events
    bindEvents();

    // Listen for eID complete from eid.js (Simulate or AusweisApp2)
    window.addEventListener('eid-complete', (e) => {
      if (e.detail) state.identityData = e.detail;
      renderTravelRuleStep();
      setStep(4);
      setRightStep(2);
      renderReceiverStep(2);
    });

    refreshStatus();
  }

  // ── Render functions ───────────────────────────────────
  function renderPriceInfo() {
    setText('#btc-eur-rate', `1 BTC = ${formatEUR(state.btcEurPrice)}`);
    const amountSatsEl = $('#amount-sats');
    if (amountSatsEl && amountSatsEl.tagName !== 'INPUT') {
      setText('#amount-sats', `${state.amountSats.toLocaleString('de-DE')} sats`);
    }
    setText('#amount-btc', formatBTC(state.amountSats));
    setText('#amount-eur', formatEUR(state.amountEur));
    const amountEurHint = $('#amount-eur-hint');
    if (amountEurHint) {
      amountEurHint.textContent = '≈ ' + formatEUR(state.amountEur);
    }
  }

  function renderLNURLStep() {
    setText('#lnurl-display', state.lnurl);
    setText('#receiving-vasp', state.receivingVasp);
    setText('#session-id', state.sessionId);
  }

  async function loadConfig() {
    try {
      const response = await fetch('config.json', { cache: 'no-store' });
      if (!response.ok) return;
      const cfg = await response.json();
      state.senderApiBase = `http://localhost:${cfg.senderPort || 3001}`;
      state.receiverApiBase = `http://localhost:${cfg.receiverPort || 3002}`;
    } catch (error) {
      // Fall back to default localhost ports.
    }
  }

  function renderAmountStep() {
    const input = $('#amount-sats-input') || $('#amount-sats');
    if (input) input.value = state.amountSats;
    updateThresholdDisplay();
  }

  function updateThresholdDisplay() {
    const eur = (state.amountSats / 1e8) * state.btcEurPrice;
    const exceeded = eur >= TRAVEL_RULE_THRESHOLD_EUR;
    const badge = $('#threshold-badge');
    const warning = $('#threshold-warning');
    if (badge) {
      badge.textContent = exceeded ? '⚠ Travel Rule Required' : '✓ Below Threshold';
      badge.className = 'threshold-badge ' + (exceeded ? 'exceeded' : 'ok');
    }
    if (warning) {
      if (exceeded) {
        warning.classList.remove('hidden');
        setText('#warning-amount', formatEUR(eur));
      } else {
        warning.classList.add('hidden');
      }
    }
  }

  function renderThresholdResult() {
    const container = $('#threshold-result');
    if (!container) return;

    container.innerHTML = `
      <div class="threshold-warning animate-in">
        <div class="threshold-warning__icon">${icons.alert}</div>
        <div class="threshold-warning__text">
          <div class="threshold-warning__title">Travel rule required</div>
          <div class="threshold-warning__description">
            Threshold is set to ${TRAVEL_RULE_THRESHOLD_EUR} EUR for this test. Current amount is ${state.amountSats.toLocaleString('de-DE')} sats (${formatEUR(state.amountEur)}).
          </div>
        </div>
      </div>
    `;
  }

  // ── Event binding ──────────────────────────────────────
  function bindEvents() {
    // Amount input (support both #amount-sats-input and #amount-sats for index.html)
    const amountInput = $('#amount-sats-input') || $('#amount-sats');
    if (amountInput) {
      amountInput.addEventListener('input', () => {
        const val = parseInt(amountInput.value) || 0;
        state.amountSats = val;
        state.amountEur = (val / 1e8) * state.btcEurPrice;
        state.thresholdExceeded = state.amountEur >= TRAVEL_RULE_THRESHOLD_EUR;
        updateThresholdDisplay();
        renderPriceInfo();
      });
    }

    // Initiate Payment (index.html: combines resolve + confirm)
    const btnInitiate = $('#btn-initiate');
    if (btnInitiate) {
      btnInitiate.addEventListener('click', handleInitiatePayment);
    }

    // Step 1 → 2: Resolve LNURL (legacy)
    const resolveLnurlBtn = $('#resolve-lnurl-btn');
    if (resolveLnurlBtn) {
      resolveLnurlBtn.addEventListener('click', handleResolveLNURL);
    }

    // Step 2 → 3: Confirm amount (legacy)
    const confirmAmountBtn = $('#confirm-amount-btn');
    if (confirmAmountBtn) {
      confirmAmountBtn.addEventListener('click', handleConfirmAmount);
    }

    // Step 3 → 4: Complete eID
    const completeEidBtn = $('#complete-eid-btn');
    if (completeEidBtn) {
      completeEidBtn.addEventListener('click', handleCompleteEID);
    }

    // Step 4 → 5: Send travel rule data
    const sendTravelRuleBtn = $('#send-travel-rule-btn');
    if (sendTravelRuleBtn) {
      sendTravelRuleBtn.addEventListener('click', handleSendTravelRule);
    }

    // Step 5 → done
    const requestInvoiceBtn = $('#request-invoice-btn');
    if (requestInvoiceBtn) {
      requestInvoiceBtn.addEventListener('click', handleRequestInvoice);
    }

    // Reset button
    const resetBtn = $('#reset-btn');
    if (resetBtn) {
      resetBtn.addEventListener('click', handleReset);
    }

    // Right panel reset
    const rightResetBtn = $('#right-reset-btn');
    if (rightResetBtn) {
      rightResetBtn.addEventListener('click', handleReset);
    }
  }

  // ── Step handlers ──────────────────────────────────────
  async function handleInitiatePayment() {
    const btn = $('#btn-initiate');
    if (btn) {
      btn.disabled = true;
      btn.classList.add('loading');
    }
    const amountInput = $('#amount-sats') || $('#amount-sats-input');
    if (amountInput) {
      state.amountSats = parseInt(amountInput.value) || 2100;
    }
    state.amountEur = (state.amountSats / 1e8) * state.btcEurPrice;
    state.thresholdExceeded = state.amountEur >= TRAVEL_RULE_THRESHOLD_EUR;
    setText('#amount-eur-hint', '≈ ' + formatEUR(state.amountEur));
    await delay(600);
    renderThresholdResult();
    setStep(2);
    setRightStep(1);
    renderReceiverStep(1);
    await delay(700);
    if (state.thresholdExceeded) {
      setStep(3);
      const eidSection = $('#eid-section');
      if (eidSection) eidSection.style.display = '';
      setRightStep(2);
      renderReceiverStep(2);
    } else {
      setStep(5);
    }
    if (btn) {
      btn.disabled = false;
      btn.classList.remove('loading');
    }
  }

  async function handleResolveLNURL() {
    const btn = $('#resolve-lnurl-btn');
    setButtonLoading(btn, true);

    await delay(800);

    // Show LNURL details
    const details = $('.lnurl-details');
    if (details) {
      details.classList.remove('hidden');
      setText('#lnurl-vasp-name', 'opago GmbH');
      setText('#lnurl-min-sendable', '1,000 sats');
      setText('#lnurl-max-sendable', '100,000,000 sats');
      setText('#lnurl-description', 'opago Lightning Payment');
    }

    setButtonLoading(btn, false);
    setStep(2);
    setRightStep(1);
    renderReceiverStep();
  }

  async function handleConfirmAmount() {
    const btn = $('#confirm-amount-btn');
    const eur = (state.amountSats / 1e8) * state.btcEurPrice;
    state.amountEur = eur;
    state.thresholdExceeded = eur >= TRAVEL_RULE_THRESHOLD_EUR;

    setButtonLoading(btn, true);
    await delay(600);
    setButtonLoading(btn, false);

    // Show amount input details
    const amountGroup = $('.amount-input-group');
    if (amountGroup) amountGroup.classList.remove('hidden');

    if (state.thresholdExceeded) {
      setStep(3); // eID step
      setRightStep(2);
      renderReceiverStep();
    } else {
      // No travel rule needed — jump to invoice
      setStep(5);
    }
  }

  async function handleCompleteEID() {
    const btn = $('#complete-eid-btn');
    setButtonLoading(btn, true);

    // Simulate eID verification
    await delay(1200);

    state.identityData = {
      firstName: 'Max',
      lastName: 'Mustermann',
      dateOfBirth: '1985-07-23',
      nationality: 'DE',
      documentNumber: 'L01X00T476',
      address: 'Musterstraße 42, 10115 Berlin, Deutschland',
    };

    // Show eID simulation result
    const eidSim = $('.eid-simulation');
    if (eidSim) {
      eidSim.classList.remove('hidden');
      setText('#eid-name', `${state.identityData.firstName} ${state.identityData.lastName}`);
      setText('#eid-dob', formatDate(state.identityData.dateOfBirth));
      setText('#eid-nationality', state.identityData.nationality);
      setText('#eid-doc', state.identityData.documentNumber);
      setText('#eid-address', state.identityData.address);
    }

    setButtonLoading(btn, false);
    setStep(4);
  }

  async function handleSendTravelRule() {
    const btn = $('#send-travel-rule-btn');
    setButtonLoading(btn, true);

    state.travelRulePayload = buildTravelRulePayload();
    setRightStep(3);
    renderReceiverStep();
    state.complianceChecks = {
      originator_identified: 'running',
      travel_rule_complete: 'running',
      sanctions_screening: 'pending',
      vasp_registered: 'running',
    };
    renderReceiverStep();

    await delay(1400);
    state.complianceChecks = {
      originator_identified: 'pass',
      travel_rule_complete: 'pass',
      sanctions_screening: 'pass',
      vasp_registered: 'pass',
    };
    renderReceiverStep();
    state.invoice = generateFakeInvoice();
    renderInvoiceStep(state.invoice);
    setRightStep(4);
    renderReceiverStep();
    setButtonLoading(btn, false);
    setStep(5);
  }

  async function handleRequestInvoice() {
    const btn = $('#request-invoice-btn');
    setButtonLoading(btn, true);

    await delay(1000);

    state.invoice = state.invoice || generateFakeInvoice();
    setButtonLoading(btn, false);
    await delay(1500);
    renderCompletionStep();
    setRightStep(5);
    renderReceiverStep();
    setStep(6);
  }

  function handleReset() {
    // Reset state
    state.sessionId = generateSessionId();
    state.currentStep = 1;
    state.identityData = null;
    state.travelRulePayload = null;
    state.complianceChecks = {
      originator_identified: 'pending',
      travel_rule_complete: 'pending',
      sanctions_screening: 'pending',
      vasp_registered: 'pending',
    };

    // Re-render
    renderLNURLStep();
    renderAmountStep();
    renderPriceInfo();
    setStep(1);
    setRightStep(1);
    state.invoice = null;
    renderThresholdResult();
    renderReceiverStep();

    const travelRuleSection = $('#travel-rule-send-section');
    const invoiceSection = $('#invoice-received-section');
    const paymentSection = $('#payment-complete-section');
    if (travelRuleSection) travelRuleSection.style.display = 'none';
    if (invoiceSection) invoiceSection.style.display = 'none';
    if (paymentSection) paymentSection.style.display = 'none';

    if (window.eidManager && typeof window.eidManager.reset === 'function') {
      window.eidManager.reset();
    } else {
      const methodsEl = $('.eid-methods');
      if (methodsEl) methodsEl.style.display = '';
      const eidResult = $('#eid-result');
      const eidProgress = $('#eid-progress');
      if (eidResult) {
        eidResult.innerHTML = '';
        hideEl(eidResult);
      }
      if (eidProgress) {
        hideEl(eidProgress);
        setText('#eid-progress-text', '');
      }
    }
  }

  // ── Travel Rule payload ────────────────────────────────
  function buildTravelRulePayload() {
    return {
      version: '1.0',
      sessionId: state.sessionId,
      timestamp: new Date().toISOString(),
      originator: {
        name: `${state.identityData.firstName} ${state.identityData.lastName}`,
        dateOfBirth: state.identityData.dateOfBirth,
        nationality: state.identityData.nationality,
        documentNumber: state.identityData.documentNumber,
        address: state.identityData.address,
        accountReference: 'self-hosted-wallet',
      },
      beneficiary: {
        name: 'opago GmbH',
        vasp: 'opago',
        lnurl: state.lnurl,
      },
      transaction: {
        amountSats: state.amountSats,
        amountEur: parseFloat(state.amountEur.toFixed(2)),
        currency: 'BTC',
        btcEurRate: state.btcEurPrice,
      },
      compliance: {
        travelRuleApplicable: true,
        thresholdEur: TRAVEL_RULE_THRESHOLD_EUR,
        regulatoryFramework: 'EU AMLD6 / MiCA',
        eIDVerified: true,
        eIDProvider: 'Bundesdruckerei / AusweisApp2',
      },
    };
  }

  function renderTravelRuleStep() {
    const container = $('#travel-rule-send-section');
    if (!container) return;
    const payload = buildTravelRulePayload();
    container.style.display = '';
    container.innerHTML = `
      <div class="card card--highlighted">
        <div class="step__description">Originator identity is ready. Submit the payment request to the self-custodial sender flow.</div>
        <div class="summary-grid">
          <div class="summary-card">
            <span class="summary-label">Originator</span>
            <span class="summary-value">${escapeHtml(payload.originator.name)}</span>
          </div>
          <div class="summary-card">
            <span class="summary-label">Document</span>
            <span class="summary-value">${escapeHtml(payload.originator.documentNumber)}</span>
          </div>
          <div class="summary-card">
            <span class="summary-label">Amount</span>
            <span class="summary-value">${payload.transaction.amountSats} sats</span>
          </div>
          <div class="summary-card">
            <span class="summary-label">Threshold</span>
            <span class="summary-value">${payload.compliance.thresholdEur} EUR</span>
          </div>
        </div>
        <button class="btn btn--primary" id="send-travel-rule-btn">Send Travel Rule Data</button>
      </div>
    `;
    const btn = $('#send-travel-rule-btn');
    if (btn) btn.addEventListener('click', handleSendTravelRule);
  }

  function renderInvoiceStep(invoice) {
    const container = $('#invoice-received-section');
    if (!container) return;
    container.style.display = '';
    container.innerHTML = `
      <div class="card">
        <div class="step__description">Receiving VASP approved the transfer and issued the invoice.</div>
        <div class="summary-grid">
          <div class="summary-card">
            <span class="summary-label">Invoice</span>
            <span class="summary-value">${escapeHtml(invoice.slice(0, 28))}...</span>
          </div>
          <div class="summary-card">
            <span class="summary-label">Amount</span>
            <span class="summary-value">${state.amountSats} sats</span>
          </div>
          <div class="summary-card">
            <span class="summary-label">Travel rule</span>
            <span class="summary-value">Accepted</span>
          </div>
          <div class="summary-card">
            <span class="summary-label">eIDAS</span>
            <span class="summary-value">Verified</span>
          </div>
        </div>
        <button class="btn btn--primary" id="request-invoice-btn">Settle Payment</button>
      </div>
    `;
    const btn = $('#request-invoice-btn');
    if (btn) btn.addEventListener('click', handleRequestInvoice);
  }

  function renderCompletionStep() {
    const container = $('#payment-complete-section');
    if (!container) return;
    container.style.display = '';
    container.innerHTML = `
      <div class="success-banner">
        <div class="success-banner__icon">${icons.check}</div>
        <div class="success-banner__title">Spark payment complete</div>
        <div class="success-banner__badges">
          <span class="top-bar__badge">${state.amountSats} sats</span>
          <span class="top-bar__badge">travel rule from 0 EUR</span>
        </div>
        <div class="summary-grid">
          <div class="summary-card">
            <span class="summary-label">Originator</span>
            <span class="summary-value">${escapeHtml(state.travelRulePayload.originator.name)}</span>
          </div>
          <div class="summary-card">
            <span class="summary-label">Travel rule</span>
            <span class="summary-value">Completed</span>
          </div>
          <div class="summary-card">
            <span class="summary-label">eIDAS</span>
            <span class="summary-value">Verified</span>
          </div>
          <div class="summary-card">
            <span class="summary-label">Session</span>
            <span class="summary-value">${escapeHtml(state.sessionId)}</span>
          </div>
        </div>
      </div>
    `;
  }

  function renderReceiverStep() {
    const step1 = $('#receiver-step-1-content');
    const step2 = $('#receiver-step-2-content');
    const step3 = $('#receiver-step-3-content');
    const step4 = $('#receiver-step-4-content');
    const step5 = $('#receiver-step-5-content');

    if (step1) {
      step1.innerHTML = `
        <div class="data-row">
          <span class="data-row__label">Recipient</span>
          <span class="data-row__value">opago</span>
        </div>
        <div class="data-row">
          <span class="data-row__label">Status</span>
          <span class="data-row__value">Ready for incoming transfer</span>
        </div>
      `;
    }

    if (step2) {
      step2.innerHTML = `
        <div class="data-row">
          <span class="data-row__label">Amount</span>
          <span class="data-row__value">${state.amountSats.toLocaleString('de-DE')} sats</span>
        </div>
        <div class="data-row">
          <span class="data-row__label">Originator</span>
          <span class="data-row__value">${state.identityData ? `${state.identityData.firstName} ${state.identityData.lastName}` : 'Waiting for ePerso identification'}</span>
        </div>
      `;
    }

    if (step3) {
      step3.innerHTML = `
        <div class="check-list">
          ${renderCheckItem('Originator identified', 'ePerso / AusweisApp2 package received.', state.complianceChecks.originator_identified)}
          ${renderCheckItem('Travel rule package complete', 'Originator and beneficiary data are present.', state.complianceChecks.travel_rule_complete)}
          ${renderCheckItem('Compliance screening', 'Receiver sanctions and policy checks are clear.', state.complianceChecks.sanctions_screening)}
          ${renderCheckItem('Counterparty accepted', 'Receiver recognizes the sending wallet context.', state.complianceChecks.vasp_registered)}
        </div>
      `;
    }

    if (step4) {
      step4.innerHTML = `
        <div class="summary-grid">
          <div class="summary-card">
            <span class="summary-label">Invoice</span>
            <span class="summary-value">${state.invoice ? `${escapeHtml(state.invoice.slice(0, 24))}...` : 'Preparing invoice'}</span>
          </div>
          <div class="summary-card">
            <span class="summary-label">Travel rule</span>
            <span class="summary-value">Accepted</span>
          </div>
        </div>
      `;
    }

    if (step5) {
      step5.innerHTML = `
        <div class="success-banner">
          <div class="success-banner__icon">${icons.check}</div>
          <div class="success-banner__title">Receiving side confirmed</div>
          <div class="success-banner__badges">
            <span class="top-bar__badge">Travel rule complete</span>
            <span class="top-bar__badge">eIDAS verified</span>
          </div>
        </div>
      `;
    }
  }

  function renderCheckItem(title, detail, status) {
    const statusClass = status === 'pass' ? 'passed' : status === 'running' ? 'checking' : 'pending';
    const icon = status === 'pass' ? icons.check : status === 'running' ? icons.spinner : '';
    return `
      <div class="check-item ${statusClass}">
        <div class="check-item__icon">${icon}</div>
        <div class="check-item__text">
          <div class="check-item__title">${title}</div>
          <div class="check-item__detail">${detail}</div>
        </div>
      </div>
    `;
  }

  async function refreshStatus() {
    const wsText = $('#ws-status-text');
    const wsDot = $('#ws-dot');
    try {
      const [senderHealth, receiverHealth, balance] = await Promise.all([
        fetchJson(`${state.senderApiBase}/api/health`),
        fetchJson(`${state.receiverApiBase}/api/health`),
        fetchJson(`${state.senderApiBase}/api/balance`),
      ]);
      if (wsText) wsText.textContent = 'Services Ready';
      if (wsDot) wsDot.classList.remove('disconnected');
      setText('#receiving-vasp-name', 'opago — License-pending CASP');
      setText('#sender-wallet-balance', `${balance.balance_sats} sats`);
      renderReceiverStep();
    } catch (error) {
      if (wsText) wsText.textContent = 'Backend Offline';
      if (wsDot) wsDot.classList.add('disconnected');
      setText('#sender-wallet-balance', 'Unavailable');
    }
  }

  async function fetchJson(url) {
    const response = await fetch(url, { cache: 'no-store' });
    if (!response.ok) throw new Error(`Request failed: ${url}`);
    return response.json();
  }

  function escapeHtml(value) {
    return String(value)
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;');
  }

  // ── Invoice generation ─────────────────────────────────
  function generateFakeInvoice() {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let invoice = 'lnbc' + state.amountSats + 'n1p';
    for (let i = 0; i < 90; i++) {
      invoice += chars[Math.floor(Math.random() * chars.length)];
    }
    return invoice;
  }

  // ── Button state helpers ───────────────────────────────
  function setButtonLoading(btn, loading) {
    if (!btn) return;
    if (loading) {
      btn.disabled = true;
      btn.dataset.originalText = btn.textContent;
      btn.innerHTML = icons.spinner + ' Processing...';
      btn.classList.add('loading');
    } else {
      btn.disabled = false;
      btn.textContent = btn.dataset.originalText || btn.textContent;
      btn.classList.remove('loading');
    }
  }

  // ── Date formatter ─────────────────────────────────────
  function formatDate(dateStr) {
    try {
      return new Intl.DateTimeFormat('de-DE', {
        day: '2-digit', month: '2-digit', year: 'numeric',
      }).format(new Date(dateStr));
    } catch (e) {
      return dateStr;
    }
  }

  function delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
    window.addEventListener('load', init, { once: true });
  } else {
    init();
  }

})();
