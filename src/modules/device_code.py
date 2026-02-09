"""
Device Code Manager module for GitLab OAuth device authorization flow.

This module handles the generation of device codes from GitLab OAuth endpoints,
supporting both GitLab SaaS (gitlab.com) and self-managed instances.
"""

import logging
import requests
from datetime import datetime
from typing import List, Dict
from urllib.parse import urljoin

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.interfaces import DeviceCodeManagerInterface, OperationResult
from src.models import Config, DeviceCodeResponse
from src.exceptions import GitLabAPIError, NetworkError
from src.error_handlers import handle_gitlab_api_call, retry_on_failure


logger = logging.getLogger(__name__)


class DeviceCodeManager(DeviceCodeManagerInterface):
    """
    Manages device code generation and validation for GitLab OAuth.
    
    This class implements the device authorization grant flow for GitLab,
    supporting both SaaS and self-managed instances.
    """
    
    # Valid GitLab OAuth scopes
    # Source: https://docs.gitlab.com/ee/integration/oauth_provider.html#authorized-applications
    VALID_SCOPES = {
        # Full access scopes
        'api': 'Grants complete read/write access to the API, including all groups and projects, the container registry, the dependency proxy, and the package registry',
        'read_api': 'Grants read access to the API, including all groups and projects, the container registry, and the package registry',
        'read_user': 'Grants read-only access to your profile through the /user API endpoint, which includes username, public email, and full name. Also grants access to read-only API endpoints under /users',
        
        # Runner scopes
        'create_runner': 'Grants create access to the runners',
        'manage_runner': 'Grants access to manage the runners',
        
        # Kubernetes
        'k8s_proxy': 'Grants permission to perform Kubernetes API calls using the agent for Kubernetes',
        
        # Granular scopes
        'read_repository': 'Grants read-only access to repositories on private projects using Git-over-HTTP or the Repository Files API',
        'write_repository': 'Grants read-write access to repositories on private projects using Git-over-HTTP (not using the API)',
        'read_registry': 'Grants read-only access to container registry images on private projects',
        'write_registry': 'Grants write access to container registry images on private projects. You need both read and write access to push images',
        'read_virtual_registry': 'Grants read-only access to container images through the dependency proxy in private projects',
        'write_virtual_registry': 'Grants read, write, and delete access to container images through the dependency proxy in private projects',
        'read_observability': 'Grants read-only access to GitLab Observability',
        'write_observability': 'Grants write access to GitLab Observability',
        'ai_features': 'Grants access to GitLab Duo related API endpoints',
        
        # Admin scopes (self-managed only)
        'sudo': 'Grants permission to perform API actions as any user in the system, when authenticated as an administrator user',
        'admin_mode': 'Grants permission to perform API actions as an administrator, when Admin Mode is enabled',
        'read_service_ping': 'Grants access to download Service Ping payloads through the API when authenticated as an administrator user',
        
        # OpenID Connect scopes
        'openid': 'Grants permission to authenticate with GitLab using OpenID Connect. Also gives read-only access to the user\'s profile and group memberships',
        'profile': 'Grants read-only access to the user\'s profile data using OpenID Connect',
        'email': 'Grants read-only access to the user\'s primary email address using OpenID Connect'
    }
    
    # Admin-only scopes (require administrator privileges)
    ADMIN_SCOPES = {'sudo', 'admin_mode', 'read_service_ping'}
    
    # Predefined scope templates for common attack scenarios
    SCOPE_TEMPLATES = {
        'basic_recon': {
            'scopes': ['read_api', 'read_user'],
            'description': 'Basic reconnaissance - read user profile and API access',
            'saas_compatible': True,
            'requires_admin': False
        },
        'advanced_recon': {
            'scopes': ['read_api', 'read_repository', 'read_registry'],
            'description': 'Advanced reconnaissance - full read access to projects, repos, and registry',
            'saas_compatible': True,
            'requires_admin': False
        },

        'admin_takeover_saas': {
            'scopes': ['api'],
            'description': 'Admin takeover (SaaS) - full API access (requires admin user)',
            'saas_compatible': True,
            'requires_admin': True
        },
        'admin_takeover_self_managed': {
            'scopes': ['api', 'sudo', 'admin_mode'],
            'description': 'Admin takeover (Self-Managed) - full admin access with sudo capabilities',
            'saas_compatible': False,
            'requires_admin': True
        },
        'ci_cd_compromise': {
            'scopes': ['api', 'read_repository', 'write_repository'],
            'description': 'CI/CD compromise - read/write access to repositories and CI/CD',
            'saas_compatible': True,
            'requires_admin': False
        },
        'full_access_saas': {
            'scopes': ['api'],
            'description': 'Full access (SaaS) - complete API access (requires admin user)',
            'saas_compatible': True,
            'requires_admin': True
        },
        'full_access_self_managed': {
            'scopes': ['api', 'sudo', 'admin_mode', 'read_service_ping'],
            'description': 'Full access (Self-Managed) - complete control over GitLab instance',
            'saas_compatible': False,
            'requires_admin': True
        }
    }
    
    @classmethod
    def get_templates_for_instance(cls, instance_type: str) -> dict:
        """
        Get scope templates filtered by instance type.
        
        Args:
            instance_type: 'saas' or 'self-managed'
            
        Returns:
            Dictionary of templates compatible with the instance type
        """
        if instance_type == 'saas':
            return {k: v for k, v in cls.SCOPE_TEMPLATES.items() if v['saas_compatible']}
        else:
            return cls.SCOPE_TEMPLATES.copy()
    
    @classmethod
    def validate_scopes_for_instance(cls, scopes: list, instance_type: str) -> tuple:
        """
        Validate scopes for a specific instance type.
        
        Args:
            scopes: List of scopes to validate
            instance_type: 'saas' or 'self-managed'
            
        Returns:
            Tuple of (is_valid, warnings)
        """
        warnings = []
        
        # Check for admin scopes
        admin_scopes_used = [s for s in scopes if s in cls.ADMIN_SCOPES]
        if admin_scopes_used:
            if instance_type == 'saas':
                warnings.append(f"Admin scopes {admin_scopes_used} are technically valid but will only work if the user is an administrator")
            else:
                warnings.append(f"Admin scopes {admin_scopes_used} require administrator privileges")
        
        return True, warnings
    
    def __init__(self, config: Config):
        """
        Initialize the Device Code Manager.
        
        Args:
            config: Framework configuration object
        """
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'GitLab-Device-Flow/1.0',
            'Accept': 'application/json'
        })
        # Disable SSL warnings if verification is disabled
        if not config.verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.warning("SSL verification is DISABLED - this is insecure and should only be used for testing")
        logger.info("DeviceCodeManager initialized")
    
    def generate_code(self, scopes: List[str], base_url: str, client_id: str) -> OperationResult:
        """
        Generate a device code from GitLab OAuth endpoint.
        
        This method makes a POST request to the GitLab device authorization endpoint
        to obtain a device code and user code for the OAuth flow.
        
        Args:
            scopes: List of OAuth scopes to request
            base_url: GitLab instance base URL (e.g., 'https://gitlab.com' or 'https://gitlab.company.com')
            client_id: OAuth application client ID
            
        Returns:
            OperationResult with DeviceCodeResponse data on success, or error message on failure
        """
        # Validate scopes
        if not self.validate_scopes(scopes):
            invalid_scopes = [s for s in scopes if s not in self.VALID_SCOPES]
            error_msg = f"Invalid scopes: {', '.join(invalid_scopes)}"
            logger.error(error_msg)
            return OperationResult(
                success=False,
                error=error_msg,
                message="Scope validation failed"
            )
        
        # Normalize base URL (remove trailing slash)
        base_url = base_url.rstrip('/')
        
        # Construct the device authorization endpoint
        endpoint = urljoin(base_url + '/', 'oauth/authorize_device')
        
        # Prepare request data
        scope_string = ' '.join(scopes)
        data = {
            'client_id': client_id,
            'scope': scope_string
        }
        
        logger.info(f"Generating device code for client_id={client_id}, scopes={scope_string}, endpoint={endpoint}")
        
        try:
            # Make POST request to GitLab
            response = self.session.post(
                endpoint,
                data=data,
                timeout=self.config.api_timeout,
                verify=self.config.verify_ssl
            )
            
            # Check for HTTP errors
            if response.status_code != 200:
                error_msg = f"GitLab API returned status {response.status_code}"
                try:
                    error_data = response.json()
                    if 'error' in error_data:
                        error_desc = error_data.get('error_description', error_data['error'])
                        error_msg += f": {error_desc}"
                        
                        # Add helpful message for scope errors
                        if 'scope' in error_desc.lower() or 'invalid' in error_desc.lower():
                            error_msg += f"\n\nRequested scopes: {scope_string}"
                            error_msg += "\n\nPossible causes:"
                            error_msg += "\n1. The OAuth application doesn't have these scopes enabled"
                            error_msg += "\n2. The GitLab instance doesn't support these scopes"
                            error_msg += "\n3. Some scopes (like 'sudo', 'admin_mode') are only available on self-managed instances"
                            error_msg += "\n\nTry using basic scopes like: api, read_api, read_user"
                except:
                    error_msg += f": {response.text}"
                
                logger.error(error_msg)
                raise GitLabAPIError(error_msg, response.status_code, response.json() if response.text else None)
            
            # Parse response
            response_data = response.json()
            
            # Validate response contains required fields
            required_fields = ['device_code', 'user_code', 'verification_uri', 'expires_in', 'interval']
            missing_fields = [field for field in required_fields if field not in response_data]
            
            if missing_fields:
                error_msg = f"GitLab response missing required fields: {', '.join(missing_fields)}"
                logger.error(error_msg)
                return OperationResult(
                    success=False,
                    error=error_msg,
                    message="Invalid response from GitLab"
                )
            
            # Create DeviceCodeResponse object
            device_code_response = DeviceCodeResponse(
                device_code=response_data['device_code'],
                user_code=response_data['user_code'],
                verification_uri=response_data['verification_uri'],
                verification_uri_complete=response_data.get('verification_uri_complete', 
                                                            f"{response_data['verification_uri']}?user_code={response_data['user_code']}"),
                expires_in=response_data['expires_in'],
                interval=response_data['interval'],
                created_at=datetime.now()
            )
            
            logger.info(f"Device code generated successfully: user_code={device_code_response.user_code}, expires_in={device_code_response.expires_in}s")
            
            return OperationResult(
                success=True,
                data={
                    'device_code': device_code_response.device_code,
                    'user_code': device_code_response.user_code,
                    'verification_uri': device_code_response.verification_uri,
                    'verification_uri_complete': device_code_response.verification_uri_complete,
                    'expires_in': device_code_response.expires_in,
                    'interval': device_code_response.interval,
                    'created_at': device_code_response.created_at.isoformat(),
                    'device_code_response': device_code_response
                },
                message="Device code generated successfully"
            )
            
        except requests.exceptions.Timeout:
            error_msg = f"Timeout connecting to GitLab at {endpoint}"
            logger.error(error_msg)
            raise NetworkError(error_msg, url=endpoint, timeout=True)
        
        except requests.exceptions.ConnectionError as e:
            error_msg = f"Cannot connect to GitLab at {endpoint}: {str(e)}"
            logger.error(error_msg)
            raise NetworkError(error_msg, url=endpoint, connection_error=True)
        
        except GitLabAPIError:
            # Re-raise GitLabAPIError to be handled by decorator
            raise
        
        except Exception as e:
            error_msg = f"Unexpected error generating device code: {str(e)}"
            logger.exception(error_msg)
            return OperationResult(
                success=False,
                error=error_msg,
                message="Unexpected error"
            )
    
    def validate_scopes(self, scopes: List[str]) -> bool:
        """
        Validate that requested scopes are valid GitLab OAuth scopes.
        
        Args:
            scopes: List of scopes to validate
            
        Returns:
            True if all scopes are valid, False otherwise
        """
        if not scopes:
            logger.warning("Empty scopes list provided")
            return False
        
        invalid_scopes = [scope for scope in scopes if scope not in self.VALID_SCOPES]
        
        if invalid_scopes:
            logger.warning(f"Invalid scopes detected: {', '.join(invalid_scopes)}")
            return False
        
        logger.debug(f"All scopes valid: {', '.join(scopes)}")
        return True
    
    def get_scope_templates(self) -> Dict[str, List[str]]:
        """
        Get predefined scope templates for common attack scenarios.
        
        Returns:
            Dictionary mapping template names to scope lists with descriptions
        """
        return self.SCOPE_TEMPLATES
    
    def get_scope_description(self, scope: str) -> str:
        """
        Get description for a specific scope.
        
        Args:
            scope: Scope name
            
        Returns:
            Description of the scope, or empty string if not found
        """
        return self.VALID_SCOPES.get(scope, '')
    
    def get_all_scopes(self) -> Dict[str, str]:
        """
        Get all valid GitLab OAuth scopes with descriptions.
        
        Returns:
            Dictionary mapping scope names to descriptions
        """
        return self.VALID_SCOPES.copy()
