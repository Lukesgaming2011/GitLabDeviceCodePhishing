# GitLab Device Code Phishing Framework - Dockerfile
# 
# This Dockerfile creates a containerized environment for running the
# GitLab Phishing Framework with all necessary dependencies.

FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories with proper permissions
RUN mkdir -p data logs results results/ssh_keys && \
    chmod 755 data logs results results/ssh_keys

# Expose ports
# 3000: Admin Panel
# 8080: Phishing Server
EXPOSE 3000 8080

# Set environment variables for configuration
ENV PYTHONUNBUFFERED=1

# Health check to ensure the admin panel is running
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:3000/api/stats', timeout=5)" || exit 1

# Run the application
CMD ["python", "main.py"]
