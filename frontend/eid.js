/**
 * eid.js — AusweisApp2 (German eID) integration via identglue
 *
 * Enables Desktop eID detection and launch for Mac (and other platforms).
 * Uses the official AusweisApp test tcToken endpoint by default.
 *
 * Requires: identglue loaded before this script (exposes AusweisApp2 global)
 */
(function () {
  'use strict';

  const DEFAULT_TCTOKEN_URL =
    'https://test.governikus-eid.de/AusweisAuskunft/WebServiceRequesterServlet';
  const CLIENT_STATUS_URLS = [
    'http://127.0.0.1:24727/eID-Client?Status=json',
    'http://localhost:24727/eID-Client?Status=json',
  ];

  function $(sel, ctx) {
    return (ctx || document).querySelector(sel);
  }

  function resolveEl(selOrEl) {
    return typeof selOrEl === 'string' ? $(selOrEl) : selOrEl;
  }

  function setText(selOrEl, text) {
    const el = resolveEl(selOrEl);
    if (el) el.textContent = text;
  }

  function show(selOrEl) {
    const el = resolveEl(selOrEl);
    if (el) el.style.display = '';
  }

  function hide(selOrEl) {
    const el = resolveEl(selOrEl);
    if (el) el.style.display = 'none';
  }

  function addClass(selOrEl, cls) {
    const el = resolveEl(selOrEl);
    if (el) el.classList.add(cls);
  }

  function removeClass(selOrEl, cls) {
    const el = resolveEl(selOrEl);
    if (el) el.classList.remove(cls);
  }

  function dispatchEidComplete(identityData) {
    window.dispatchEvent(new CustomEvent('eid-complete', { detail: identityData }));
  }

  function getTcTokenUrl() {
    return window.OPAGO_EID_TCTOKEN_URL || DEFAULT_TCTOKEN_URL;
  }

  function resetEidWidget() {
    const methodsEl = $('.eid-methods');
    const progressEl = $('#eid-progress');
    const resultEl = $('#eid-result');
    show(methodsEl);
    hide(progressEl);
    hide(resultEl);
    setText('#eid-progress-text', '');
    if (resultEl) resultEl.innerHTML = '';
  }

  function init() {
    const eidSection = $('#eid-section');
    const statusEl = $('#eid-status');
    const statusText = $('#eid-status-text');
    const btnDesktop = $('#btn-eid-desktop');
    const btnSimulate = $('#btn-eid-simulate');
    const progressEl = $('#eid-progress');
    const resultEl = $('#eid-result');

    if (!eidSection) return;

    show(eidSection);
    resetEidWidget();

    function setDesktopStatus(available, message) {
      if (available) {
        removeClass(statusEl, 'not-detected');
        addClass(statusEl, 'detected');
      } else {
        addClass(statusEl, 'not-detected');
        removeClass(statusEl, 'detected');
      }
      setText(statusText, message);
      if (btnDesktop) btnDesktop.disabled = !available;
    }

    async function isClientReachable() {
      for (const url of CLIENT_STATUS_URLS) {
        try {
          const response = await fetch(url, { cache: 'no-store' });
          if (response.ok) return true;
        } catch (error) {
          // Ignore and try the next localhost alias.
        }
      }
      return false;
    }

    function bindSimulateButton() {
      if (!btnSimulate || btnSimulate.dataset.bound === 'true') return;
      btnSimulate.dataset.bound = 'true';
      btnSimulate.addEventListener('click', () => {
        const identityData = {
          firstName: 'Max',
          lastName: 'Mustermann',
          dateOfBirth: '1985-07-23',
          nationality: 'DE',
          documentNumber: 'L01X00T476',
          address: 'Musterstraße 42, 10115 Berlin, Deutschland',
        };
        resetEidWidget();
        if (resultEl) {
          resultEl.innerHTML =
            '<div class="eid-result-success"><strong>Simulated</strong><br>' +
            identityData.firstName + ' ' + identityData.lastName + '<br>' +
            identityData.documentNumber + '</div>';
          show(resultEl);
        }
        dispatchEidComplete(identityData);
      });
    }

    bindSimulateButton();

    const AusweisApp2 = window.AusweisApp2 || window.identglue;
    if (!AusweisApp2) {
      setText(statusText, 'AusweisApp2 library not loaded. Use Simulate for demo.');
      removeClass(statusEl, 'not-detected');
      addClass(statusEl, 'detected');
      if (btnDesktop) btnDesktop.disabled = true;
      return;
    }

    const StationaryStatusObserver = AusweisApp2.StationaryStatusObserver;
    const getClientURL = AusweisApp2.getClientURL;
    const isMobile = AusweisApp2.isMobile ? AusweisApp2.isMobile() : false;

    if (!StationaryStatusObserver || !getClientURL) {
      setText(statusText, 'identglue API not available. Use Simulate for demo.');
      if (btnDesktop) btnDesktop.disabled = true;
      return;
    }

    if (isMobile) {
      setText(statusText, 'Desktop eID requires a computer with AusweisApp2 running.');
      if (btnDesktop) btnDesktop.disabled = true;
    } else {
      setDesktopStatus(true, 'Click Desktop eID to try local AusweisApp2, or Simulate for demo.');
      const observer = new StationaryStatusObserver((status) => {
        if (status.status === 'available') {
          setDesktopStatus(true, 'AusweisApp2 detected. Click Desktop eID to identify.');
        } else if (status.status === 'safari') {
          setDesktopStatus(
            true,
            'Use Chrome or Firefox for Desktop eID. Safari blocks localhost detection.'
          );
        } else if (status.status === 'unavailable') {
          setDesktopStatus(true, 'Start AusweisApp2 on this Mac, then click Desktop eID to retry.');
        } else {
          setDesktopStatus(true, 'AusweisApp2 status unknown. Try Desktop eID or Simulate.');
        }
      });
      observer.observe();

      // Desktop detection over identglue can be flaky on some setups.
      // Poll the local status endpoint as a fallback and enable the button
      // whenever the client becomes reachable.
      const refreshDesktopStatus = async () => {
        const reachable = await isClientReachable();
        if (reachable) {
          setDesktopStatus(true, 'AusweisApp2 detected on localhost. Click Desktop eID.');
        }
      };
      refreshDesktopStatus();
      window.setInterval(refreshDesktopStatus, 3000);
    }

    if (btnDesktop && btnDesktop.dataset.bound !== 'true') {
      btnDesktop.dataset.bound = 'true';
      btnDesktop.addEventListener('click', () => {
        const tcTokenURL = getTcTokenUrl();
        const url = getClientURL({
          action: 'connect',
          tcTokenURL,
        });
        window.open(url, '_blank', 'noopener,noreferrer');
        setText(
          statusText,
          'AusweisApp2 opened. Complete identification there, or use Simulate to continue the demo.'
        );
        if (progressEl) {
          show(progressEl);
          setText(
            '#eid-progress-text',
            'Waiting for AusweisApp2. If no callback returns, use Simulate to continue the demo.'
          );
        }
      });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  window.eidManager = {
    init,
    dispatchEidComplete,
    reset: resetEidWidget,
  };
})();
