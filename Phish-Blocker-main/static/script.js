// DOM Elements
const urlInput = document.getElementById('urlInput');
const scanBtn = document.getElementById('scanBtn');
const clearBtn = document.getElementById('clearBtn');
const loadingContainer = document.getElementById('loadingContainer');
const resultsContainer = document.getElementById('resultsContainer');

// Event Listeners
urlInput.addEventListener('input', () => {
    clearBtn.classList.toggle('hidden', !urlInput.value);
});

clearBtn.addEventListener('click', () => {
    urlInput.value = '';
    clearBtn.classList.add('hidden');
    resultsContainer.classList.add('hidden');
    urlInput.focus();
});

urlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') scanUrl();
});

// Initialize on Load
document.addEventListener('DOMContentLoaded', () => {
    initMap();
});

function testUrl(url) {
    urlInput.value = url;
    clearBtn.classList.remove('hidden');
    scanUrl();
}

async function scanUrl() {
    const url = urlInput.value.trim();
    if (!url) {
        alert("Please enter a URL");
        return;
    }

    // Reset UI
    resultsContainer.innerHTML = '';
    resultsContainer.classList.add('hidden');
    loadingContainer.classList.remove('hidden');
    scanBtn.disabled = true;
    scanBtn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Scanning...';

    // Timer Start
    const startTime = performance.now();

    // Simulate Scanning Steps
    await simulateSteps();

    try {
        const formData = new FormData();
        formData.append('url', url);

        const response = await fetch('/predict', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();
        const endTime = performance.now();
        const scanTime = ((endTime - startTime) / 1000).toFixed(2); // in seconds

        displayResult(data, scanTime);
        addToHistory(url, data.result || 'SAFE', (data.phishing_probability || 0) * 100); // Add to history

    } catch (error) {
        resultsContainer.innerHTML = `<div class="result-card danger"><h3>Error</h3><p>${error.message}</p></div>`;
        resultsContainer.classList.remove('hidden');
    } finally {
        loadingContainer.classList.add('hidden');
        scanBtn.disabled = false;
        scanBtn.innerHTML = '<span>Scan Now</span><i class="fas fa-arrow-right"></i>';

        // Reset Steps
        document.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
    }
}

async function simulateSteps() {
    const steps = ['step1', 'step2', 'step3'];
    for (const stepId of steps) {
        document.getElementById(stepId).classList.add('active');
        await new Promise(r => setTimeout(r, 600)); // Delay between steps
    }
}

function displayResult(data, scanTime) {
    const result = data.result; // "PHISHING", "LEGITIMATE", "SUSPICIOUS"
    const probability = (data.phishing_probability * 100).toFixed(1);
    const riskFactors = data.advanced_risk_factors || [];

    let theme = 'success';
    let icon = 'fa-shield-check';
    let title = 'Safe to Access';
    let desc = 'This URL checks out. No Phishing threats detected.';
    let borderColor = 'var(--safe-color)';

    if (result === 'PHISHING') {
        theme = 'danger';
        icon = 'fa-radiation'; // or biohazard/exclamation-triangle
        title = 'Phishing Detected';
        desc = 'High-risk threat detected. Do not visit this site.';
        borderColor = 'var(--danger-color)';
    } else if (result === 'SUSPICIOUS') {
        theme = 'danger'; // Use danger styling but maybe change text logic if needed, or create a 'warning' theme
        icon = 'fa-exclamation-triangle';
        title = 'Suspicious URL';
        desc = 'This URL shows suspicious patterns. Proceed with caution.';
        borderColor = 'var(--suspicious-color)';
    }

    let riskHtml = '';
    if (riskFactors.length > 0) {
        riskHtml = `
            <div class="risk-factors-container">
                <h4><i class="fas fa-bug"></i> Risk Factors Detected:</h4>
                <ul class="risk-list">
                    ${riskFactors.map(factor => `<li class="risk-item"><i class="fas fa-times-circle"></i> ${factor}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    const html = `
        <div class="result-card ${theme}">
            <i class="fas ${icon} result-icon-lg"></i>
            <h2 class="result-title" style="color: ${borderColor}">${title}</h2>
            <p class="result-desc">${desc}</p>
            
            <div class="stats-row">
                <div class="stat-item">
                    <span class="stat-value">${probability}%</span>
                    <span class="stat-label">Risk Score</span>
                </div>
                <div class="stat-item">
                    <span class="stat-value">${scanTime}s</span>
                    <span class="stat-label">Scan Time</span>
                </div>
            </div>

            ${riskHtml}

            <div class="action-row">
                <button class="secondary-btn" onclick="location.reload()"><i class="fas fa-redo"></i> Scan Another</button>
            </div>
        </div>
    `;

    resultsContainer.innerHTML = html;
    resultsContainer.classList.remove('hidden');
    resultsContainer.scrollIntoView({ behavior: 'smooth' });
}

// Recent Scans History Implementation
const SCAN_HISTORY_KEY = 'phishBlocker_history';

document.addEventListener('DOMContentLoaded', () => {
    // initMap(); // Removed Live Map
    loadScanHistory();

    // Clear history handler
    document.getElementById('clearHistoryBtn')?.addEventListener('click', () => {
        if (confirm('Clear all scan history?')) {
            localStorage.removeItem(SCAN_HISTORY_KEY);
            loadScanHistory();
        }
    });
});

function loadScanHistory() {
    const historyList = document.getElementById('scanHistoryList');
    if (!historyList) return;

    const history = JSON.parse(localStorage.getItem(SCAN_HISTORY_KEY) || '[]');

    if (history.length === 0) {
        historyList.innerHTML = `
            <div class="empty-history">
              <i class="fas fa-list-ul"></i>
              <p>No recent scans yet.</p>
            </div>
        `;
        return;
    }

    historyList.innerHTML = history.map(item => `
        <div class="history-item ${item.result === 'PHISHING' ? 'danger' : (item.result === 'SUSPICIOUS' ? 'suspicious' : 'safe')}">
            <div class="url-col" title="${item.url}">${item.url}</div>
            <div class="result-col">${item.result}</div>
            <div class="time-col">${item.time}</div>
        </div>
    `).join('');
}

function addToHistory(url, result, probability) {
    const history = JSON.parse(localStorage.getItem(SCAN_HISTORY_KEY) || '[]');

    const newItem = {
        url: url,
        result: result,
        probability: probability,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    // Add to beginning and limit to 10 items
    history.unshift(newItem);
    if (history.length > 10) history.pop();

    localStorage.setItem(SCAN_HISTORY_KEY, JSON.stringify(history));
    loadScanHistory();
}
