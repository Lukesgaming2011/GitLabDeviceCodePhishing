"""
Base interfaces for all modules in the GitLab Phishing Framework.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Tuple, Callable, Optional
from dataclasses import dataclass


@dataclass
class OperationResult:
    """Standard result object for all operations."""
    success: bool
    data: Optional[Dict] = None
    error: Optional[str] = None
    message: Optional[str] = None


class BaseModule(ABC):
    """Base interface for all framework modules."""
    
    @abstractmethod
    def __init__(self, config):
        """Initialize the module with configuration."""
        pass


class DeviceCodeManagerInterface(BaseModule):
    """Interface for Device Code Manager module."""
    
    @abstractmethod
    def generate_code(self, scopes: List[str], base_url: str, client_id: str) -> OperationResult:
        """
        Generate a device code from GitLab OAuth endpoint.
        
        Args:
            scopes: List of OAuth scopes to request
            base_url: GitLab instance base URL
            client_id: OAuth application client ID
            
        Returns:
            OperationResult with DeviceCodeResponse data
        """
        pass
    
    @abstractmethod
    def validate_scopes(self, scopes: List[str]) -> bool:
        """
        Validate that requested scopes are valid GitLab OAuth scopes.
        
        Args:
            scopes: List of scopes to validate
            
        Returns:
            True if all scopes are valid
        """
        pass
    
    @abstractmethod
    def get_scope_templates(self) -> Dict[str, List[str]]:
        """
        Get predefined scope templates for common attack scenarios.
        
        Returns:
            Dictionary mapping template names to scope lists
        """
        pass


class TokenPollerInterface(BaseModule):
    """Interface for Token Poller module."""
    
    @abstractmethod
    def start_polling(self, operation_id: int, victim_id: int, 
                     device_code: str, base_url: str, 
                     client_id: str, interval: int) -> OperationResult:
        """
        Start polling for token authorization.
        
        Args:
            operation_id: ID of the operation
            victim_id: ID of the victim
            device_code: Device code to poll for
            base_url: GitLab instance base URL
            client_id: OAuth application client ID
            interval: Polling interval in seconds
            
        Returns:
            OperationResult indicating polling started
        """
        pass
    
    @abstractmethod
    def stop_polling(self, operation_id: int, victim_id: int) -> OperationResult:
        """
        Stop polling for a specific victim.
        
        Args:
            operation_id: ID of the operation
            victim_id: ID of the victim
            
        Returns:
            OperationResult indicating polling stopped
        """
        pass
    
    @abstractmethod
    def set_token_callback(self, callback: Callable) -> None:
        """
        Set callback function to be called when token is captured.
        
        Args:
            callback: Function to call with (operation_id, victim_id, access_token, scope)
        """
        pass


class PhishingServerInterface(BaseModule):
    """Interface for Phishing Server module."""
    
    @abstractmethod
    def start(self) -> bool:
        """
        Start the phishing server.
        
        Returns:
            True if server started successfully
        """
        pass
    
    @abstractmethod
    def stop(self) -> bool:
        """
        Stop the phishing server.
        
        Returns:
            True if server stopped successfully
        """
        pass
    
    @abstractmethod
    def register_operation(self, operation_id: int, config) -> bool:
        """
        Register a new operation with the phishing server.
        
        Args:
            operation_id: ID of the operation
            config: OperationConfig object
            
        Returns:
            True if operation registered successfully
        """
        pass
    
    @abstractmethod
    def unregister_operation(self, operation_id: int) -> bool:
        """
        Unregister an operation from the phishing server.
        
        Args:
            operation_id: ID of the operation
            
        Returns:
            True if operation unregistered successfully
        """
        pass


class WebServerInterface(BaseModule):
    """Interface for Admin Panel Web Server module."""
    
    @abstractmethod
    def start_server(self, port: int = 3000) -> OperationResult:
        """
        Start the admin panel web server.
        
        Args:
            port: Port to listen on
            
        Returns:
            OperationResult indicating server started
        """
        pass
    
    @abstractmethod
    def stop_server(self) -> OperationResult:
        """
        Stop the admin panel web server.
        
        Returns:
            OperationResult indicating server stopped
        """
        pass
    
    @abstractmethod
    def set_engine_callback(self, callback: Callable) -> None:
        """
        Set callback to access core engine functionality.
        
        Args:
            callback: Function to access engine methods
        """
        pass


class ResourceEnumeratorInterface(BaseModule):
    """Interface for Resource Enumerator module."""
    
    @abstractmethod
    def enumerate_all(self, operation_id: int, victim_id: int, 
                     access_token: str, base_url: str) -> OperationResult:
        """
        Enumerate all accessible resources for a victim.
        
        Args:
            operation_id: ID of the operation
            victim_id: ID of the victim
            access_token: OAuth access token
            base_url: GitLab instance base URL
            
        Returns:
            OperationResult with enumeration results
        """
        pass
    
    @abstractmethod
    def enumerate_user(self, access_token: str, base_url: str) -> Dict:
        """
        Enumerate user information.
        
        Args:
            access_token: OAuth access token
            base_url: GitLab instance base URL
            
        Returns:
            Dictionary with user information
        """
        pass
    
    @abstractmethod
    def enumerate_projects(self, access_token: str, base_url: str) -> List[Dict]:
        """
        Enumerate accessible projects.
        
        Args:
            access_token: OAuth access token
            base_url: GitLab instance base URL
            
        Returns:
            List of project dictionaries
        """
        pass
    
    @abstractmethod
    def enumerate_ci_variables(self, access_token: str, base_url: str, 
                               project_id: int) -> List[Dict]:
        """
        Enumerate CI/CD variables for a project.
        
        Args:
            access_token: OAuth access token
            base_url: GitLab instance base URL
            project_id: ID of the project
            
        Returns:
            List of CI/CD variable dictionaries
        """
        pass

class CoreEngineInterface(ABC):
    """Interface for Core Engine orchestration."""
    
    @abstractmethod
    def __init__(self, config):
        """Initialize the core engine with configuration."""
        pass
    
    @abstractmethod
    def start_admin_only(self) -> OperationResult:
        """
        Start only the admin panel without any operations.
        
        Returns:
            OperationResult indicating admin panel started
        """
        pass
    
    @abstractmethod
    def start_operation(self, operation_id: int, scopes: List[str], 
                       instance_type: str, base_url: str, 
                       client_id: str) -> OperationResult:
        """
        Start a phishing operation.
        
        Args:
            operation_id: ID of the operation
            scopes: List of OAuth scopes
            instance_type: 'saas' or 'self-managed'
            base_url: GitLab instance base URL
            client_id: OAuth application client ID
            
        Returns:
            OperationResult indicating operation started
        """
        pass
    
    @abstractmethod
    def stop_operation(self, operation_id: int) -> OperationResult:
        """
        Stop a running operation.
        
        Args:
            operation_id: ID of the operation
            
        Returns:
            OperationResult indicating operation stopped
        """
        pass
    
    @abstractmethod
    def get_operation_status(self, operation_id: int):
        """
        Get current status of an operation.
        
        Args:
            operation_id: ID of the operation
            
        Returns:
            OperationStatus object
        """
        pass
    
    @abstractmethod
    def handle_token_received(self, operation_id: int, victim_id: int, 
                             access_token: str, scope: str) -> None:
        """
        Handle token capture event.
        
        Args:
            operation_id: ID of the operation
            victim_id: ID of the victim
            access_token: Captured access token
            scope: Token scope
        """
        pass
