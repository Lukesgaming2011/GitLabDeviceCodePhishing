"""
Configuration management for the GitLab Phishing Framework.
"""

import json
import os
from pathlib import Path
from typing import Optional
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.models import Config


class ConfigurationError(Exception):
    """Exception raised for configuration errors."""
    pass


def get_config_path() -> Path:
    """Get the path to the configuration file."""
    config_dir = Path(__file__).parent
    return config_dir / "default.json"


def load_config_from_file(config_path: Path) -> dict:
    """
    Load configuration from JSON file.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Dictionary with configuration values
        
    Raises:
        ConfigurationError: If file cannot be read or parsed
    """
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        raise ConfigurationError(f"Configuration file not found: {config_path}")
    except json.JSONDecodeError as e:
        raise ConfigurationError(f"Invalid JSON in configuration file: {e}")
    except Exception as e:
        raise ConfigurationError(f"Error reading configuration file: {e}")


def apply_env_overrides(config_dict: dict) -> dict:
    """
    Apply environment variable overrides to configuration.
    
    Environment variables should be prefixed with GITLAB_PHISHING_
    and use uppercase with underscores.
    
    Examples:
        GITLAB_PHISHING_ADMIN_PORT=3001
        GITLAB_PHISHING_LOG_LEVEL=DEBUG
    
    Args:
        config_dict: Base configuration dictionary
        
    Returns:
        Configuration dictionary with environment overrides applied
    """
    env_prefix = "GITLAB_PHISHING_"
    
    # Map environment variable names to config keys
    env_mappings = {
        f"{env_prefix}ADMIN_PORT": ("admin_port", int),
        f"{env_prefix}PHISHING_PORT": ("phishing_port", int),
        f"{env_prefix}HOST": ("host", str),
        f"{env_prefix}DB_PATH": ("db_path", str),
        f"{env_prefix}LOG_LEVEL": ("log_level", str),
        f"{env_prefix}LOG_DIR": ("log_dir", str),
        f"{env_prefix}RESULTS_DIR": ("results_dir", str),
        f"{env_prefix}SSH_KEYS_DIR": ("ssh_keys_dir", str),
        f"{env_prefix}POLLING_TIMEOUT": ("polling_timeout", int),
        f"{env_prefix}API_TIMEOUT": ("api_timeout", int),
        f"{env_prefix}MAX_RETRIES": ("max_retries", int),
        f"{env_prefix}RETRY_DELAY": ("retry_delay", int),
        f"{env_prefix}DEFAULT_GITLAB_URL": ("default_gitlab_url", str),
        f"{env_prefix}VERIFY_SSL": ("verify_ssl", lambda x: x.lower() in ('true', '1', 'yes')),
    }
    
    for env_var, (config_key, value_type) in env_mappings.items():
        env_value = os.environ.get(env_var)
        if env_value is not None:
            try:
                config_dict[config_key] = value_type(env_value)
            except ValueError:
                raise ConfigurationError(
                    f"Invalid value for {env_var}: {env_value} (expected {value_type.__name__})"
                )
    
    return config_dict


def validate_config(config: Config) -> None:
    """
    Validate configuration values.
    
    Args:
        config: Config object to validate
        
    Raises:
        ConfigurationError: If configuration is invalid
    """
    # Validate ports
    if not (1024 <= config.admin_port <= 65535):
        raise ConfigurationError(f"Invalid admin_port: {config.admin_port} (must be 1024-65535)")
    
    if not (1024 <= config.phishing_port <= 65535):
        raise ConfigurationError(f"Invalid phishing_port: {config.phishing_port} (must be 1024-65535)")
    
    if config.admin_port == config.phishing_port:
        raise ConfigurationError("admin_port and phishing_port cannot be the same")
    
    # Validate log level
    valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    if config.log_level.upper() not in valid_log_levels:
        raise ConfigurationError(
            f"Invalid log_level: {config.log_level} (must be one of {valid_log_levels})"
        )
    
    # Validate timeouts
    if config.polling_timeout <= 0:
        raise ConfigurationError(f"Invalid polling_timeout: {config.polling_timeout} (must be > 0)")
    
    if config.api_timeout <= 0:
        raise ConfigurationError(f"Invalid api_timeout: {config.api_timeout} (must be > 0)")
    
    # Validate retry settings
    if config.max_retries < 0:
        raise ConfigurationError(f"Invalid max_retries: {config.max_retries} (must be >= 0)")
    
    if config.retry_delay < 0:
        raise ConfigurationError(f"Invalid retry_delay: {config.retry_delay} (must be >= 0)")
    
    # Validate GitLab URL
    if not config.default_gitlab_url.startswith(("http://", "https://")):
        raise ConfigurationError(
            f"Invalid default_gitlab_url: {config.default_gitlab_url} (must start with http:// or https://)"
        )


def create_default_config_file(config_path: Path) -> None:
    """
    Create a default configuration file.
    
    Args:
        config_path: Path where to create the configuration file
    """
    default_config = {
        "admin_port": 3000,
        "phishing_port": 8080,
        "host": "0.0.0.0",
        "db_path": "data/gitlab_phishing.db",
        "log_level": "INFO",
        "log_dir": "logs/",
        "results_dir": "results/",
        "ssh_keys_dir": "results/ssh_keys/",
        "polling_timeout": 900,
        "api_timeout": 30,
        "max_retries": 3,
        "retry_delay": 5,
        "default_gitlab_url": "https://gitlab.com",
        "verify_ssl": true
    }
    
    config_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(config_path, 'w') as f:
        json.dump(default_config, f, indent=4)


def get_config(config_path: Optional[Path] = None) -> Config:
    """
    Load and return the framework configuration.
    
    This function:
    1. Loads configuration from file (or creates default if missing)
    2. Applies environment variable overrides
    3. Validates the configuration
    4. Returns a Config object
    
    Args:
        config_path: Optional path to configuration file (defaults to config/default.json)
        
    Returns:
        Config object with validated configuration
        
    Raises:
        ConfigurationError: If configuration is invalid
    """
    if config_path is None:
        config_path = get_config_path()
    
    # Create default config if it doesn't exist
    if not config_path.exists():
        create_default_config_file(config_path)
    
    # Load configuration from file
    config_dict = load_config_from_file(config_path)
    
    # Apply environment variable overrides
    config_dict = apply_env_overrides(config_dict)
    
    # Create Config object
    config = Config(**config_dict)
    
    # Validate configuration
    validate_config(config)
    
    return config


def save_config(config: Config, config_path: Optional[Path] = None) -> None:
    """
    Save configuration to file.
    
    Args:
        config: Config object to save
        config_path: Optional path to configuration file
        
    Raises:
        ConfigurationError: If configuration cannot be saved
    """
    if config_path is None:
        config_path = get_config_path()
    
    # Validate before saving
    validate_config(config)
    
    config_dict = {
        "admin_port": config.admin_port,
        "phishing_port": config.phishing_port,
        "host": config.host,
        "db_path": config.db_path,
        "log_level": config.log_level,
        "log_dir": config.log_dir,
        "results_dir": config.results_dir,
        "ssh_keys_dir": config.ssh_keys_dir,
        "polling_timeout": config.polling_timeout,
        "api_timeout": config.api_timeout,
        "max_retries": config.max_retries,
        "retry_delay": config.retry_delay,
        "default_gitlab_url": config.default_gitlab_url,
        "verify_ssl": config.verify_ssl
    }
    
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, 'w') as f:
            json.dump(config_dict, f, indent=4)
    except Exception as e:
        raise ConfigurationError(f"Error saving configuration: {e}")
