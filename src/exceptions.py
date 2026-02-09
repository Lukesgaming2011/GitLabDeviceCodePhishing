"""
Custom exception classes for the GitLab Phishing Framework.

This module defines custom exceptions for better error handling and
categorization of different error types throughout the framework.
"""

from typing import Optional, Dict, Any


class GitLabPhishingError(Exception):
    """Base exception class for all GitLab Phishing Framework errors."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialize base exception.
        
        Args:
            message: Error message
            details: Optional dictionary with additional error details
        """
        self.message = message
        self.details = details or {}
        super().__init__(self.message)
    
    def __str__(self):
        """String representation of the exception."""
        if self.details:
            details_str = ', '.join(f"{k}={v}" for k, v in self.details.items())
            return f"{self.message} ({details_str})"
        return self.message


class GitLabAPIError(GitLabPhishingError):
    """
    Exception raised for GitLab API errors.
    
    This exception is raised when GitLab API requests fail, including
    network errors, authentication failures, and API-specific errors.
    """
    
    def __init__(self, message: str, status_code: Optional[int] = None, 
                 response_data: Optional[Dict] = None, 
                 endpoint: Optional[str] = None):
        """
        Initialize GitLab API error.
        
        Args:
            message: Error message
            status_code: HTTP status code from the response
            response_data: Response data from GitLab API (if available)
            endpoint: API endpoint that was called
        """
        self.status_code = status_code
        self.response_data = response_data or {}
        self.endpoint = endpoint
        
        details = {}
        if status_code:
            details['status_code'] = status_code
        if endpoint:
            details['endpoint'] = endpoint
        
        super().__init__(message, details)
    
    def is_rate_limited(self) -> bool:
        """Check if error is due to rate limiting."""
        return self.status_code == 429
    
    def is_unauthorized(self) -> bool:
        """Check if error is due to authentication failure."""
        return self.status_code == 401
    
    def is_forbidden(self) -> bool:
        """Check if error is due to insufficient permissions."""
        return self.status_code == 403
    
    def is_not_found(self) -> bool:
        """Check if error is due to resource not found."""
        return self.status_code == 404
    
    def is_server_error(self) -> bool:
        """Check if error is a server-side error (5xx)."""
        return self.status_code is not None and 500 <= self.status_code < 600
    
    def get_error_message(self) -> str:
        """
        Extract error message from response data.
        
        Returns:
            Error message from GitLab API or the exception message
        """
        if self.response_data:
            # Try different common error message fields
            for field in ['message', 'error', 'error_description']:
                if field in self.response_data:
                    return str(self.response_data[field])
        return self.message


class GitLabAuthError(GitLabAPIError):
    """
    Exception raised for GitLab authentication and authorization errors.
    
    This is a specialized version of GitLabAPIError for authentication-specific
    issues like invalid tokens, expired tokens, or insufficient permissions.
    """
    
    def __init__(self, message: str, status_code: Optional[int] = None,
                 response_data: Optional[Dict] = None,
                 endpoint: Optional[str] = None,
                 token_expired: bool = False):
        """
        Initialize GitLab authentication error.
        
        Args:
            message: Error message
            status_code: HTTP status code from the response
            response_data: Response data from GitLab API (if available)
            endpoint: API endpoint that was called
            token_expired: Whether the error is due to an expired token
        """
        self.token_expired = token_expired
        super().__init__(message, status_code, response_data, endpoint)
        
        if token_expired:
            self.details['token_expired'] = True


class ConfigurationError(GitLabPhishingError):
    """
    Exception raised for configuration errors.
    
    This exception is raised when there are issues with the framework
    configuration, such as missing required settings, invalid values,
    or configuration file errors.
    """
    
    def __init__(self, message: str, config_key: Optional[str] = None,
                 config_value: Optional[Any] = None):
        """
        Initialize configuration error.
        
        Args:
            message: Error message
            config_key: Configuration key that caused the error
            config_value: Invalid configuration value
        """
        self.config_key = config_key
        self.config_value = config_value
        
        details = {}
        if config_key:
            details['config_key'] = config_key
        if config_value is not None:
            details['config_value'] = str(config_value)
        
        super().__init__(message, details)


class NetworkError(GitLabPhishingError):
    """
    Exception raised for network-related errors.
    
    This exception is raised for connection errors, timeouts, and other
    network-related issues when communicating with GitLab.
    """
    
    def __init__(self, message: str, url: Optional[str] = None,
                 timeout: bool = False, connection_error: bool = False):
        """
        Initialize network error.
        
        Args:
            message: Error message
            url: URL that was being accessed
            timeout: Whether the error was due to a timeout
            connection_error: Whether the error was a connection error
        """
        self.url = url
        self.timeout = timeout
        self.connection_error = connection_error
        
        details = {}
        if url:
            details['url'] = url
        if timeout:
            details['timeout'] = True
        if connection_error:
            details['connection_error'] = True
        
        super().__init__(message, details)


class OperationError(GitLabPhishingError):
    """
    Exception raised for operation-related errors.
    
    This exception is raised when there are issues with operation
    lifecycle management, such as starting/stopping operations,
    or operation state errors.
    """
    
    def __init__(self, message: str, operation_id: Optional[int] = None,
                 operation_status: Optional[str] = None):
        """
        Initialize operation error.
        
        Args:
            message: Error message
            operation_id: ID of the operation that caused the error
            operation_status: Current status of the operation
        """
        self.operation_id = operation_id
        self.operation_status = operation_status
        
        details = {}
        if operation_id is not None:
            details['operation_id'] = operation_id
        if operation_status:
            details['operation_status'] = operation_status
        
        super().__init__(message, details)


class DatabaseError(GitLabPhishingError):
    """
    Exception raised for database-related errors.
    
    This exception is raised when there are issues with database
    operations, such as connection failures, query errors, or
    data integrity issues.
    """
    
    def __init__(self, message: str, query: Optional[str] = None,
                 table: Optional[str] = None):
        """
        Initialize database error.
        
        Args:
            message: Error message
            query: SQL query that caused the error (if applicable)
            table: Database table involved in the error
        """
        self.query = query
        self.table = table
        
        details = {}
        if table:
            details['table'] = table
        
        super().__init__(message, details)


# SSHKeyError removed - SSH persistence feature disabled


class EnumerationError(GitLabPhishingError):
    """
    Exception raised for resource enumeration errors.
    
    This exception is raised when there are issues during resource
    enumeration, such as API failures or permission issues.
    """
    
    def __init__(self, message: str, resource_type: Optional[str] = None,
                 partial_success: bool = False):
        """
        Initialize enumeration error.
        
        Args:
            message: Error message
            resource_type: Type of resource being enumerated (user, projects, etc.)
            partial_success: Whether some enumeration succeeded
        """
        self.resource_type = resource_type
        self.partial_success = partial_success
        
        details = {}
        if resource_type:
            details['resource_type'] = resource_type
        if partial_success:
            details['partial_success'] = True
        
        super().__init__(message, details)
