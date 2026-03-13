const EMAIL_HOSTS = [
  'mail.google.com',
  'outlook.live.com',
  'outlook.office.com',
  'mail.yahoo.com',
];

document.addEventListener('DOMContentLoaded', function () {
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    const currentUrl = tabs[0].url;
    const tabId      = tabs[0].id;
    let hostname     = '';
    try { hostname = new URL(currentUrl).hostname; } catch (_) {}

    const urlDisplay = document.getElementById('url');
    urlDisplay.innerText =
      currentUrl.length > 60 ? currentUrl.substring(0, 60) + '...' : currentUrl;

    // ── System pages ────────────────────────────────────────────────────────
    if (currentUrl.startsWith('chrome://') || currentUrl.startsWith('edge://')) {
      document.getElementById('mode-label').innerText = 'System Page';
      document.getElementById('verdict').innerText    = 'System Page Ignored';
      return;
    }

    // ── Email mode ──────────────────────────────────────────────────────────
    if (EMAIL_HOSTS.includes(hostname)) {
      document.getElementById('mode-label').innerText = 'Email Analysis';
      urlDisplay.innerText = hostname;

      // Show the manual scan button
      const scanBtn = document.getElementById('scan-btn');
      scanBtn.style.display = 'block';

      scanBtn.addEventListener('click', function () {
        scanBtn.disabled    = true;
        scanBtn.innerText   = 'Scanning...';
        document.getElementById('verdict').innerText         = 'Scanning...';
        document.getElementById('verdict-container').className = 'loading';

        // Tell the content script to re-run analysis
        chrome.tabs.sendMessage(tabId, { action: 'SCAN_EMAIL' });

        // Poll storage for the result
        let attempts = 0;
        const poll = setInterval(() => {
          attempts++;
          chrome.storage.local.get(['emailAnalysis'], function (result) {
            const data = result.emailAnalysis;
            const fresh = data && (Date.now() - data.timestamp < 8000);

            if (fresh && !data.error && data.verdict) {
              clearInterval(poll);
              showEmailResult(data, urlDisplay);
              scanBtn.disabled  = false;
              scanBtn.innerText = 'Scan Current Email';
            } else if (fresh && data.error) {
              clearInterval(poll);
              document.getElementById('verdict').innerText         = data.error;
              document.getElementById('verdict-container').className = 'loading';
              scanBtn.disabled  = false;
              scanBtn.innerText = 'Scan Current Email';
            } else if (attempts >= 10) {
              clearInterval(poll);
              document.getElementById('verdict').innerText         = 'Timeout — try again';
              document.getElementById('verdict-container').className = 'loading';
              scanBtn.disabled  = false;
              scanBtn.innerText = 'Scan Current Email';
            }
          });
        }, 800);
      });

      // Also try to show any previously stored result on popup open
      chrome.storage.local.get(['emailAnalysis'], function (result) {
        const data = result.emailAnalysis;
        if (!data) {
          document.getElementById('verdict').innerText         = 'Click "Scan Current Email"';
          document.getElementById('verdict-container').className = 'loading';
          return;
        }
        if (data.error) {
          document.getElementById('verdict').innerText         = data.error;
          document.getElementById('verdict-container').className = 'loading';
          return;
        }
        showEmailResult(data, urlDisplay);
      });

    // ── URL mode ────────────────────────────────────────────────────────────
    } else {
      document.getElementById('mode-label').innerText = 'URL Analysis';

      fetch('http://127.0.0.1:5000/predict', {
        method : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body   : JSON.stringify({ url: currentUrl }),
      })
        .then(res => res.json())
        .then(data => renderResult(data))
        .catch(() => {
          document.getElementById('verdict').innerText         = 'API Offline';
          document.getElementById('verdict-container').className = 'loading';
        });
    }
  });

  function showEmailResult(data, urlDisplay) {
    if (data.subject) {
      urlDisplay.innerText =
        data.subject.length > 55
          ? data.subject.substring(0, 55) + '...'
          : data.subject;
    }
    renderResult(data);
  }

  function renderResult(data) {
    const verdictDiv  = document.getElementById('verdict-container');
    const verdictSpan = document.getElementById('verdict');

    verdictDiv.className  = data.is_phishing ? 'phish' : 'safe';
    verdictSpan.innerText = data.verdict;

    document.getElementById('risk-score').innerText  = data.risk_score + ' / 100';
    document.getElementById('confidence').innerText  = (data.confidence * 100).toFixed(2) + ' %';
    document.getElementById('is-phishing').innerText = data.is_phishing.toString().toUpperCase();
  }
});
