"""
Configuration module for GitLab Phishing Framework
"""

from .settings import get_config, save_config, ConfigurationError

__all__ = ['get_config', 'save_config', 'ConfigurationError']
