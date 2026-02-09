#!/usr/bin/env python3
"""
Setup script for GitLab Device Code Phishing Framework.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file for long description
readme_file = Path(__file__).parent / "README.md"
long_description = ""
if readme_file.exists():
    with open(readme_file, "r", encoding="utf-8") as f:
        long_description = f.read()

# Read requirements from requirements.txt
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_file.exists():
    with open(requirements_file, "r", encoding="utf-8") as f:
        requirements = [
            line.strip() 
            for line in f 
            if line.strip() and not line.startswith("#")
        ]

setup(
    name="gitlab-phishing-framework",
    version="1.0.0",
    description="GitLab Device Code Phishing Framework for authorized security testing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Security Research Team",
    author_email="security@example.com",
    url="https://github.com/yourusername/gitlab-phishing-framework",
    license="MIT",
    
    # Package configuration
    packages=find_packages(exclude=["tests", "tests.*", "docs"]),
    include_package_data=True,
    package_data={
        "src.web": [
            "templates/*.html",
            "static/css/*.css",
            "static/js/*.js"
        ],
        "config": ["*.json"]
    },
    
    # Python version requirement
    python_requires=">=3.8",
    
    # Dependencies
    install_requires=requirements,
    
    # Entry points for CLI
    entry_points={
        "console_scripts": [
            "gitlab-phishing=main:main",
        ],
    },
    
    # Classifiers for PyPI
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
    ],
    
    # Keywords for discovery
    keywords=[
        "gitlab",
        "oauth",
        "device-code",
        "phishing",
        "security",
        "penetration-testing",
        "red-team",
        "security-testing"
    ],
    
    # Project URLs
    project_urls={
        "Bug Reports": "https://github.com/yourusername/gitlab-phishing-framework/issues",
        "Source": "https://github.com/yourusername/gitlab-phishing-framework",
        "Documentation": "https://github.com/yourusername/gitlab-phishing-framework/blob/main/README.md",
    },
)
