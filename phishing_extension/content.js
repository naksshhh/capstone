// PhishGuard — email content extractor

// ── Extractors ──────────────────────────────────────────────────────────────

function extractGmail() {
  const subject =
    document.querySelector('h2.hP') ||
    document.querySelector('h2[data-thread-perm-id]');

  // 1. Try direct DOM selectors (plain-text / simple HTML emails)
  const body =
    document.querySelector('.a3s.aiL')             ||
    document.querySelector('div.ii.gt')             ||
    document.querySelector('.ii.gt .a3s')           ||
    document.querySelector('[data-message-id] .ii') ||
    document.querySelector('.nH .ii');

  if (body && body.innerText.trim().length > 10) {
    return {
      text   : (subject ? subject.innerText + ' ' : '') + body.innerText.trim(),
      subject: subject ? subject.innerText.trim() : '',
    };
  }

  // 2. Fallback: Gmail renders rich HTML emails inside same-origin iframes
  const iframes = document.querySelectorAll('iframe');
  for (const frame of iframes) {
    try {
      const fb = frame.contentDocument && frame.contentDocument.body;
      if (fb && fb.innerText.trim().length > 10) {
        return {
          text   : (subject ? subject.innerText + ' ' : '') + fb.innerText.trim(),
          subject: subject ? subject.innerText.trim() : '',
        };
      }
    } catch (_) { /* cross-origin or sandboxed — skip */ }
  }

  return null;
}

function extractOutlook() {
  const body =
    document.querySelector('[aria-label="Message body"]')           ||
    document.querySelector('.ReadingPaneContent .allowTextSelection') ||
    document.querySelector('[data-testid="message-body"]');

  const subject =
    document.querySelector('[data-testid="subject"]') ||
    document.querySelector('.subject');

  if (!body) return null;
  const text = body.innerText.trim();
  if (text.length < 10) return null;
  return {
    text   : (subject ? subject.innerText + ' ' : '') + text,
    subject: subject ? subject.innerText.trim() : '',
  };
}

function extractYahoo() {
  const body    = document.querySelector('[data-test-id="message-view-body"]');
  const subject = document.querySelector('[data-test-id="message-subject"]');
  if (!body) return null;
  const text = body.innerText.trim();
  if (text.length < 10) return null;
  return {
    text   : (subject ? subject.innerText + ' ' : '') + text,
    subject: subject ? subject.innerText.trim() : '',
  };
}

const EXTRACTORS = {
  'mail.google.com'   : extractGmail,
  'outlook.live.com'  : extractOutlook,
  'outlook.office.com': extractOutlook,
  'mail.yahoo.com'    : extractYahoo,
};

// ── Core analysis (with retry) ───────────────────────────────────────────────

function analyzeCurrentEmail(retries = 5, delay = 1000) {
  const extractor = EXTRACTORS[window.location.hostname];
  if (!extractor) return;

  const emailData = extractor();

  if (!emailData) {
    if (retries > 0) {
      setTimeout(() => analyzeCurrentEmail(retries - 1, delay), delay);
    } else {
      // All retries exhausted and body not found
      chrome.storage.local.set({
        emailAnalysis: { error: 'Email body not found', timestamp: Date.now() },
      });
    }
    return;
  }

  fetch('http://127.0.0.1:5000/predict_email', {
    method : 'POST',
    headers: { 'Content-Type': 'application/json' },
    body   : JSON.stringify({ text: emailData.text }),
  })
    .then(res => res.json())
    .then(data => {
      chrome.storage.local.set({
        emailAnalysis: {
          ...data,
          subject  : emailData.subject,
          timestamp: Date.now(),
        },
      });
    })
    .catch(() => {
      chrome.storage.local.set({
        emailAnalysis: { error: 'API Offline', timestamp: Date.now() },
      });
    });
}

// ── Listen for on-demand scan triggered from the popup ───────────────────────

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.action === 'SCAN_EMAIL') {
    analyzeCurrentEmail(5, 600);
  }
});

// ── Auto-run on injection + watch for SPA navigation ────────────────────────

setTimeout(() => analyzeCurrentEmail(), 1500);

let lastUrl      = location.href;
let debounceTimer = null;

const observer = new MutationObserver(() => {
  const currentUrl = location.href;
  if (currentUrl !== lastUrl) {
    lastUrl = currentUrl;
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => analyzeCurrentEmail(), 1500);
  }
});

observer.observe(document.body, { childList: true, subtree: true });
