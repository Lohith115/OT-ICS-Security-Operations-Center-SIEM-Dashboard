const API_URL = 'http://localhost:5000/api';
let severityChart;
let attackerChart;
let threatMap = null; 
let markersLayer = null;
window.allLogs = []; // Global log store

// --- Initialization ---
document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    
    // Try to init map, but don't crash if it fails
    try {
        initMap(); 
    } catch (e) {
        console.error("Map failed to load, but dashboard will continue.", e);
    }

    fetchAllData();
    setInterval(fetchAllData, 5000);
    updateClock();
    setInterval(updateClock, 1000);

    // Navigation Tab Switching
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const targetTab = this.getAttribute('data-tab');

            // Update Link State
            document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
            this.classList.add('active');

            // Update Tab Content
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            document.getElementById(targetTab).classList.add('active');
            
            // Fix map display bug when switching tabs
            if(targetTab === 'dashboard' && threatMap) {
                setTimeout(() => {
                    threatMap.invalidateSize();
                }, 100);
            }
        });
    });

    // Search Filter
    const searchInput = document.getElementById('logSearch');
    if (searchInput) {
        searchInput.addEventListener('keyup', filterLogs);
    }
});

// --- Map Logic ---
function initMap() {
    if (typeof L === 'undefined' || !document.getElementById('map')) return;

    threatMap = L.map('map').setView([20, 0], 2);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; CARTO',
        subdomains: 'abcd',
        maxZoom: 19
    }).addTo(threatMap);

    markersLayer = L.layerGroup().addTo(threatMap);
}

function updateMap(alerts) {
    if (!markersLayer || !threatMap) return;
    markersLayer.clearLayers();
    alerts.forEach(alert => {
        if (alert.latitude && alert.longitude) {
            const marker = L.marker([alert.latitude, alert.longitude]);
            marker.bindPopup(`<b>${alert.alert_type}</b><br>IP: ${alert.source_ip}<br>${alert.description}`);
            markersLayer.addLayer(marker);
        }
    });
}

// --- Data Fetching ---
async function fetchAllData() {
    await Promise.all([fetchStats(), fetchLogs(), fetchAlerts()]);
}

async function fetchStats() {
    try {
        const response = await fetch(`${API_URL}/stats`);
        const data = await response.json();
        updateStatsUI(data);
        updateAttackerChart(data.top_attackers);
    } catch (error) { console.error('Error fetching stats:', error); }
}

async function fetchLogs() {
    try {
        const response = await fetch(`${API_URL}/logs?limit=100`);
        const logs = await response.json();
        window.allLogs = logs; // Sync global store
        renderLogs(logs);
        updateSeverityChart(logs);
    } catch (error) { console.error('Error fetching logs:', error); }
}

async function fetchAlerts() {
    try {
        const response = await fetch(`${API_URL}/alerts?limit=20`);
        const alerts = await response.json();
        renderAlerts(alerts);
        updateMap(alerts); 
    } catch (error) { console.error('Error fetching alerts:', error); }
}

// --- UI Rendering ---
function updateStatsUI(data) {
    document.getElementById('stat-total-logs').innerText = data.total_logs || 0;
    document.getElementById('stat-total-alerts').innerText = data.total_alerts || 0;
    const topAttacker = (data.top_attackers && data.top_attackers.length > 0) ? data.top_attackers[0].ip : 'N/A';
    document.getElementById('stat-top-attacker').innerText = topAttacker;
    
    // Update Risk Level based on alerts count
    const riskEl = document.getElementById('risk-level');
    if (data.total_alerts > 50) { riskEl.innerText = "CRITICAL"; riskEl.style.color = "#ef4444"; }
    else if (data.total_alerts > 20) { riskEl.innerText = "HIGH"; riskEl.style.color = "#f59e0b"; }
    else { riskEl.innerText = "LOW"; riskEl.style.color = "#10b981"; }
}

function renderLogs(logs) {
    const mainContainer = document.getElementById('log-stream');
    const miniContainer = document.getElementById('log-stream-mini');
    
    const html = logs.map(log => {
        const type = log.log_type || 'SYS';
        const time = formatTime(log.timestamp);
        const msg = escapeHtml(log.message);
        return `<div class="log-entry"><span class="log-time">${time}</span><span class="log-type ${type}">${type}</span><span class="log-msg">${msg}</span></div>`;
    }).join('');

    if (mainContainer) mainContainer.innerHTML = html;
    if (miniContainer) miniContainer.innerHTML = html;
}

function renderAlerts(alerts) {
    const mainContainer = document.getElementById('alert-list-mini');
    if (!mainContainer) return;
    if (alerts.length === 0) {
        mainContainer.innerHTML = '<div class="alert-item"><div class="alert-desc">No threats detected.</div></div>';
        return;
    }
    const html = alerts.map(alert => {
        const sevClass = alert.severity.toLowerCase();
        const time = formatTime(alert.timestamp);
        const desc = escapeHtml(alert.description);
        const tactic = alert.mitre_tactic || "Unknown";
        const risk = alert.risk_score || 0;

        return `<div class="alert-item ${sevClass}">
            <div class="alert-title">${alert.alert_type}</div>
            <div class="alert-desc">${time} - ${desc}</div>
            <div class="alert-mitre">
                <span class="mitre-badge">${tactic}</span>
                <span class="risk-score">Risk: ${risk}</span>
            </div>
        </div>`;
    }).join('');
    mainContainer.innerHTML = html;
}

// --- Charts ---
function initCharts() {
    const ctxPie = document.getElementById('severityChart').getContext('2d');
    severityChart = new Chart(ctxPie, {
        type: 'doughnut',
        data: {
            labels: ['Info', 'Warning', 'Error', 'Critical', 'Failed'],
            datasets: [{ 
                data: [0, 0, 0, 0, 0], 
                backgroundColor: ['#3b82f6', '#f59e0b', '#ef4444', '#7c3aed', '#64748b'], 
                borderWidth: 0
            }]
        },
        options: { 
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { position: 'bottom', labels: { padding: 20, font: { weight: 'bold' } } } } 
        }
    });

    const ctxBar = document.getElementById('alertTrendChart').getContext('2d');
    attackerChart = new Chart(ctxBar, {
        type: 'bar',
        data: { labels: [], datasets: [{ label: 'Alert Count', data: [], backgroundColor: '#3b82f6', borderRadius: 6 }] },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false }, title: { display: true, text: 'Top Attacking Sources', font: { size: 14, weight: 'bold' } } }
        }
    });
}

function updateSeverityChart(logs) {
    const counts = { 'Info': 0, 'Warning': 0, 'Error': 0, 'Critical': 0, 'Failed': 0 };
    logs.forEach(log => { if (counts.hasOwnProperty(log.severity)) counts[log.severity]++; });
    severityChart.data.datasets[0].data = Object.values(counts);
    severityChart.update();
}

function updateAttackerChart(attackers) {
    if (!attackers) return;
    attackerChart.data.labels = attackers.map(a => a.ip);
    attackerChart.data.datasets[0].data = attackers.map(a => a.count);
    attackerChart.update();
}

// --- Actions ---
function filterLogs() {
    const term = document.getElementById('logSearch').value.toLowerCase();
    const filtered = window.allLogs.filter(log => {
        return (log.source_ip || "").toLowerCase().includes(term) || 
               (log.message || "").toLowerCase().includes(term) || 
               (log.log_type || "").toLowerCase().includes(term) || 
               (log.severity || "").toLowerCase().includes(term);
    });
    renderLogs(filtered);
}

function clearLogs() {
    // We clear the DOM and the global store so the next interval doesn't immediately overwrite the "clear"
    window.allLogs = [];
    document.getElementById('log-stream').innerHTML = '<div class="log-entry">Display cleared. New logs will appear shortly...</div>';
}

async function submitManualLogs() {
    const textarea = document.getElementById('manualLogs');
    const logs = textarea.value.split('\n').filter(line => line.trim() !== '');
    if(logs.length === 0) return alert("Please enter some logs.");
    try {
        const response = await fetch(`${API_URL}/ingest`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ logs: logs }) });
        const data = await response.json();
        alert(`Ingested ${data.processed} logs. Triggered ${data.alerts_triggered} alerts.`);
        textarea.value = '';
        fetchAllData();
    } catch (error) { alert("Error sending logs."); }
}

// --- Helpers ---
function formatTime(isoString) { try { return new Date(isoString).toLocaleTimeString(); } catch (e) { return isoString; } }
function updateClock() { document.getElementById('current-time').innerText = new Date().toLocaleString(); }
function escapeHtml(text) { if (!text) return text; return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;"); }
