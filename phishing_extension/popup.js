document.addEventListener('DOMContentLoaded', function() {
  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    let currentUrl = tabs[0].url;
    
    // Display truncated URL so it doesn't break the UI
    const urlDisplay = document.getElementById('url');
    urlDisplay.innerText = currentUrl.length > 60 ? currentUrl.substring(0, 60) + "..." : currentUrl;

    if (currentUrl.startsWith('chrome://') || currentUrl.startsWith('edge://')) {
        document.getElementById('verdict').innerText = "System Page Ignored";
        return;
    }

    fetch('http://127.0.0.1:5000/predict', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url: currentUrl })
    })
    .then(response => response.json())
    .then(data => {
      // 1. Handle the Verdict Box
      const verdictDiv = document.getElementById('verdict-container');
      const verdictSpan = document.getElementById('verdict');

      if (data.is_phishing) {
        verdictDiv.className = "phish";
        verdictSpan.innerText = data.verdict;
      } else {
        verdictDiv.className = "safe";
        verdictSpan.innerText = data.verdict;
      }
      
      // 2. Populate the Parameters
      document.getElementById('risk-score').innerText = data.risk_score + " / 100";
      document.getElementById('confidence').innerText = (data.confidence * 100).toFixed(2) + " %";
      // Convert boolean to uppercase string (TRUE/FALSE)
      document.getElementById('is-phishing').innerText = data.is_phishing.toString().toUpperCase();
      
    })
    .catch(error => {
      document.getElementById('verdict').innerText = "API Offline";
      document.getElementById('verdict-container').className = "loading";
      console.error('Error connecting to Flask:', error);
    });
  });
});