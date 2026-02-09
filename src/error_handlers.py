"""
Error handling decorators and utilities for the GitLab Phishing Framework.

This module provides decorators for handling common error scenarios,
including API call failures, network errors, and retry logic.
"""

import logging
import time
import functools
from typing import Callable, Any, Optional
import requests

from .exceptions import (
    GitLabAPIError,
    GitLabAuthError,
    NetworkError,
    ConfigurationError
)
from .interfaces import OperationResult


logger = logging.getLogger(__name__)


def handle_gitlab_api_call(func: Callable) -> Callable:
    """
    Decorator for handling GitLab API calls with comprehensive error handling.
    
    This decorator catches common exceptions that occur during GitLab API calls
    and converts them into appropriate custom exceptions or OperationResult objects.
    
    Handles:
    - Network timeouts
    - Connection errors
    - HTTP error responses (401, 403, 404, 429, 5xx)
    - JSON parsing errors
    - Unexpected exceptions
    
    Args:
        func: Function to decorate (should make GitLab API calls)
        
    Returns:
        Decorated function that returns OperationResult
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> OperationResult:
        func_name = func.__name__
        
        try:
            # Call the original function
            result = func(*args, **kwargs)
            
            # If function already returns OperationResult, return it
            if isinstance(result, OperationResult):
                return result
            
            # Otherwise wrap the result
            return OperationResult(
                success=True,
                data=result,
                message=f"{func_name} completed successfully"
            )
        
        except requests.exceptions.Timeout as e:
            error_msg = f"Request timeout in {func_name}"
            logger.error(f"{error_msg}: {str(e)}")
            return OperationResult(
                success=False,
                error=error_msg,
                message="API request timed out"
            )
        
        except requests.exceptions.ConnectionError as e:
            error_msg = f"Connection error in {func_name}"
            logger.error(f"{error_msg}: {str(e)}")
            return OperationResult(
                success=False,
                error=error_msg,
                message="Cannot connect to GitLab"
            )
        
        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code if e.response else None
            error_msg = f"HTTP error {status_code} in {func_name}"
            
            # Handle specific status codes
            if status_code == 401:
                logger.error(f"{error_msg}: Unauthorized - invalid or expired token")
                return OperationResult(
                    success=False,
                    error="Unauthorized: Invalid or expired access token",
                    message="Authentication failed"
                )
            
            elif status_code == 403:
                logger.error(f"{error_msg}: Forbidden - insufficient permissions")
                return OperationResult(
                    success=False,
                    error="Forbidden: Insufficient permissions",
                    message="Permission denied"
                )
            
            elif status_code == 404:
                logger.error(f"{error_msg}: Not found")
                return OperationResult(
                    success=False,
                    error="Resource not found",
                    message="Requested resource does not exist"
                )
            
            elif status_code == 429:
                logger.warning(f"{error_msg}: Rate limited")
                return OperationResult(
                    success=False,
                    error="Rate limited by GitLab API",
                    message="Too many requests - rate limit exceeded"
                )
            
            elif status_code and 500 <= status_code < 600:
                logger.error(f"{error_msg}: Server error")
                return OperationResult(
                    success=False,
                    error=f"GitLab server error: {status_code}",
                    message="GitLab server encountered an error"
                )
            
            else:
                logger.error(f"{error_msg}: {str(e)}")
                return OperationResult(
                    success=False,
                    error=f"HTTP error: {status_code}",
                    message="API request failed"
                )
        
        except GitLabAPIError as e:
            logger.error(f"GitLab API error in {func_name}: {e.message}")
            return OperationResult(
                success=False,
                error=e.message,
                message="GitLab API error",
                data={'status_code': e.status_code, 'response_data': e.response_data}
            )
        
        except GitLabAuthError as e:
            logger.error(f"GitLab auth error in {func_name}: {e.message}")
            return OperationResult(
                success=False,
                error=e.message,
                message="Authentication error",
                data={'token_expired': e.token_expired}
            )
        
        except NetworkError as e:
            logger.error(f"Network error in {func_name}: {e.message}")
            return OperationResult(
                success=False,
                error=e.message,
                message="Network error"
            )
        
        except ConfigurationError as e:
            logger.error(f"Configuration error in {func_name}: {e.message}")
            return OperationResult(
                success=False,
                error=e.message,
                message="Configuration error"
            )
        
        except ValueError as e:
            error_msg = f"Invalid value in {func_name}"
            logger.error(f"{error_msg}: {str(e)}")
            return OperationResult(
                success=False,
                error=str(e),
                message="Invalid input value"
            )
        
        except Exception as e:
            error_msg = f"Unexpected error in {func_name}"
            logger.exception(f"{error_msg}: {str(e)}")
            return OperationResult(
                success=False,
                error=str(e),
                message="Unexpected error occurred"
            )
    
    return wrapper


def retry_on_failure(max_retries: int = 3, delay: int = 5, 
                    backoff: float = 2.0, 
                    retry_on_rate_limit: bool = True) -> Callable:
    """
    Decorator for retrying failed operations with exponential backoff.
    
    This decorator automatically retries operations that fail due to
    transient errors like network issues or rate limiting.
    
    Args:
        max_retries: Maximum number of retry attempts (default: 3)
        delay: Initial delay between retries in seconds (default: 5)
        backoff: Backoff multiplier for exponential backoff (default: 2.0)
        retry_on_rate_limit: Whether to retry on rate limit errors (default: True)
        
    Returns:
        Decorator function
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            func_name = func.__name__
            current_delay = delay
            
            for attempt in range(max_retries + 1):
                try:
                    # Call the original function
                    result = func(*args, **kwargs)
                    
                    # If result is OperationResult, check success
                    if isinstance(result, OperationResult):
                        if result.success:
                            if attempt > 0:
                                logger.info(f"{func_name} succeeded on attempt {attempt + 1}")
                            return result
                        
                        # Check if we should retry based on error type
                        should_retry = False
                        
                        # Retry on rate limit if enabled
                        if retry_on_rate_limit and result.error and 'rate limit' in result.error.lower():
                            should_retry = True
                            logger.warning(f"{func_name} rate limited, retrying in {current_delay}s...")
                        
                        # Retry on timeout or connection errors
                        elif result.error and any(keyword in result.error.lower() 
                                                 for keyword in ['timeout', 'connection', 'network']):
                            should_retry = True
                            logger.warning(f"{func_name} network error, retrying in {current_delay}s...")
                        
                        # Retry on server errors (5xx)
                        elif result.error and 'server error' in result.error.lower():
                            should_retry = True
                            logger.warning(f"{func_name} server error, retrying in {current_delay}s...")
                        
                        # Don't retry on auth errors or client errors
                        elif result.error and any(keyword in result.error.lower() 
                                                 for keyword in ['unauthorized', 'forbidden', 'not found', 'invalid']):
                            should_retry = False
                            logger.debug(f"{func_name} failed with non-retryable error: {result.error}")
                        
                        if not should_retry or attempt >= max_retries:
                            if attempt >= max_retries:
                                logger.error(f"{func_name} failed after {max_retries + 1} attempts")
                            return result
                    
                    else:
                        # Non-OperationResult return value, assume success
                        return result
                
                except requests.exceptions.Timeout:
                    if attempt < max_retries:
                        logger.warning(f"{func_name} timed out (attempt {attempt + 1}/{max_retries + 1}), "
                                     f"retrying in {current_delay}s...")
                    else:
                        logger.error(f"{func_name} timed out after {max_retries + 1} attempts")
                        raise
                
                except requests.exceptions.ConnectionError:
                    if attempt < max_retries:
                        logger.warning(f"{func_name} connection error (attempt {attempt + 1}/{max_retries + 1}), "
                                     f"retrying in {current_delay}s...")
                    else:
                        logger.error(f"{func_name} connection failed after {max_retries + 1} attempts")
                        raise
                
                except GitLabAPIError as e:
                    # Retry on rate limiting or server errors
                    if e.is_rate_limited() or e.is_server_error():
                        if attempt < max_retries:
                            logger.warning(f"{func_name} API error (attempt {attempt + 1}/{max_retries + 1}), "
                                         f"retrying in {current_delay}s...")
                        else:
                            logger.error(f"{func_name} API error after {max_retries + 1} attempts")
                            raise
                    else:
                        # Don't retry on auth or client errors
                        logger.debug(f"{func_name} failed with non-retryable API error")
                        raise
                
                except Exception as e:
                    # Don't retry on unexpected exceptions
                    logger.error(f"{func_name} failed with unexpected error: {str(e)}")
                    raise
                
                # Wait before retrying (except on last attempt)
                if attempt < max_retries:
                    time.sleep(current_delay)
                    current_delay *= backoff  # Exponential backoff
            
            # Should not reach here, but return failure if we do
            logger.error(f"{func_name} exhausted all retry attempts")
            return OperationResult(
                success=False,
                error="Maximum retry attempts exceeded",
                message=f"Operation failed after {max_retries + 1} attempts"
            )
        
        return wrapper
    return decorator


def handle_rate_limit(wait_time: int = 60, max_wait: int = 300) -> Callable:
    """
    Decorator for handling GitLab API rate limiting.
    
    This decorator automatically waits and retries when rate limit is hit.
    It respects the Retry-After header if present.
    
    Args:
        wait_time: Default wait time in seconds if no Retry-After header (default: 60)
        max_wait: Maximum wait time in seconds (default: 300)
        
    Returns:
        Decorator function
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            func_name = func.__name__
            
            while True:
                try:
                    result = func(*args, **kwargs)
                    return result
                
                except requests.exceptions.HTTPError as e:
                    if e.response and e.response.status_code == 429:
                        # Rate limited - check for Retry-After header
                        retry_after = e.response.headers.get('Retry-After')
                        
                        if retry_after:
                            try:
                                wait = min(int(retry_after), max_wait)
                            except ValueError:
                                wait = min(wait_time, max_wait)
                        else:
                            wait = min(wait_time, max_wait)
                        
                        logger.warning(f"{func_name} rate limited, waiting {wait}s before retry...")
                        time.sleep(wait)
                        continue
                    else:
                        # Not a rate limit error, re-raise
                        raise
                
                except GitLabAPIError as e:
                    if e.is_rate_limited():
                        wait = min(wait_time, max_wait)
                        logger.warning(f"{func_name} rate limited, waiting {wait}s before retry...")
                        time.sleep(wait)
                        continue
                    else:
                        # Not a rate limit error, re-raise
                        raise
        
        return wrapper
    return decorator


def graceful_degradation(continue_on_error: bool = True, 
                        log_errors: bool = True) -> Callable:
    """
    Decorator for graceful degradation when operations fail.
    
    This decorator allows operations to continue even if they fail,
    logging errors but not raising exceptions. Useful for enumeration
    and other non-critical operations.
    
    Args:
        continue_on_error: Whether to continue on error (default: True)
        log_errors: Whether to log errors (default: True)
        
    Returns:
        Decorator function
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> OperationResult:
            func_name = func.__name__
            
            try:
                result = func(*args, **kwargs)
                
                # If result is OperationResult, return it
                if isinstance(result, OperationResult):
                    return result
                
                # Otherwise wrap the result
                return OperationResult(
                    success=True,
                    data=result,
                    message=f"{func_name} completed"
                )
            
            except Exception as e:
                if log_errors:
                    logger.warning(f"{func_name} failed but continuing: {str(e)}")
                
                if continue_on_error:
                    # Return a failed OperationResult but don't raise
                    return OperationResult(
                        success=False,
                        error=str(e),
                        message=f"{func_name} failed but operation continues"
                    )
                else:
                    # Re-raise the exception
                    raise
        
        return wrapper
    return decorator


def log_execution(log_level: int = logging.INFO) -> Callable:
    """
    Decorator for logging function execution.
    
    Logs when a function starts and completes, including execution time.
    
    Args:
        log_level: Logging level to use (default: logging.INFO)
        
    Returns:
        Decorator function
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            func_name = func.__name__
            start_time = time.time()
            
            logger.log(log_level, f"Starting {func_name}")
            
            try:
                result = func(*args, **kwargs)
                elapsed = time.time() - start_time
                logger.log(log_level, f"Completed {func_name} in {elapsed:.2f}s")
                return result
            
            except Exception as e:
                elapsed = time.time() - start_time
                logger.error(f"Failed {func_name} after {elapsed:.2f}s: {str(e)}")
                raise
        
        return wrapper
    return decorator
