# GitLab Device Code Phishing Tool

*A tool that provides a web interface to easily perform GitLab Device Code phishing against GitLab SaaS or self-hosted instances*

## Quick Links

[Maldev Academy Home](https://maldevacademy.com?ref=gh)

[Offensive Phishing Operations Course Syllabus](https://maldevacademy.com/phishing-course/syllabus?ref=gh)

[Malware Development Course Syllabus](https://maldevacademy.com/maldev-course/syllabus?ref=gh)

## Requirements

- Python 3.8 or higher
- Pip

## Local Installation

```bash
# Clone the repository
git clone https://github.com/Maldev-Academy/GitLabDeviceCodePhishing.git
cd GitLabDeviceCodePhishing

# Install dependencies
pip install -r requirements.txt

# Start the application
python main.py
```

## Docker Installation

```bash
# Build and run with Docker
docker build -t gitlab-phishing .
docker run -p 3000:3000 -p 8080:8080 gitlab-phishing

# Or use Docker Compose
docker-compose up -d
```

## Web Interfaces

The application hosts two interfaces:

* Admin interface - This is available on `http://localhost:3000/admin` and allows you to create new operations, view captured tokens, user information and more.

* Phishing Interface - This is available on `http://localhost:8080` and is a GitLab-styled device code authorization page with dynamic code generation for each visitor.

## Configuration

The application uses environment variables and a JSON configuration file located at `config/default.json`.

### Environment Variables

```bash
# Server Configuration
ADMIN_PORT=3000
PHISHING_PORT=8080
HOST=0.0.0.0

# Database
DB_PATH=data/gitlab_phishing.db

# Logging
LOG_LEVEL=INFO
LOG_DIR=logs/

# Results
RESULTS_DIR=results/
SSH_KEYS_DIR=results/ssh_keys/

# SSL Verification (for self-managed instances)
VERIFY_SSL=true
```

## Basic Usage

1. Start the application by running `python main.py`

2. Access admin panel on `http://localhost:3000/admin`

3. Create a new operation with desired scopes and client ID

4. Share the generated phishing URL (e.g., `http://localhost:8080/op/1`)

5. Monitor captured tokens and enumerated resources in the admin panel

## Demo

## Credits

Huge thanks to [@0xh3l1x](https://x.com/cgomezz_23) for developing this tool as part of the Offensive Phishing Operations training update.

## Notice

> [!WARNING]
> This tool is intended for use in authorized security engagements only. Use responsibly and in accordance with all applicable laws.