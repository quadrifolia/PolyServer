#!/bin/bash
# deploy-unified.sh - Base server configuration deployment script
# Usage: ./deploy-unified.sh [environment file] [ssh user] [ssh host] [ssh port]

set -e

# Default paths and settings
SCRIPT_DIR="$(dirname "$0")"
TEMPLATE_DIR="$(dirname "$0")/../templates"
DEFAULT_ENV="${TEMPLATE_DIR}/defaults.env"
CONFIG_DIR="$(dirname "$0")/../config"

# Parse arguments
ENV_FILE="${1:-$DEFAULT_ENV}"
SSH_USER="${2:-$(grep DEPLOY_USER "$ENV_FILE" | cut -d= -f2)}"
SSH_HOST="${3:-$SSH_HOST}"
SSH_PORT="${4:-$(grep SSH_PORT "$ENV_FILE" | cut -d= -f2)}"

if [ -z "$SSH_HOST" ]; then
  echo "ERROR: SSH host not provided. Please specify SSH_HOST as an environment variable or as the third argument."
  exit 1
fi

# Load environment variables
source "$ENV_FILE"

echo "===== PolyServer Base Configuration Deployment ====="
echo "Target: ${SSH_USER}@${SSH_HOST}:${SSH_PORT}"
echo "Deploy directory: ${DEPLOY_DIR:-/opt/polyserver}"

# Generate configurations
echo "===== Generating base configuration files ====="
"$SCRIPT_DIR/generate-configs.sh" "$ENV_FILE" "$CONFIG_DIR"

# Deploy base configuration
echo "===== Deploying base server configuration ====="

# Create deployment directory on remote server
ssh -p "$SSH_PORT" "$SSH_USER@$SSH_HOST" "
    sudo mkdir -p ${DEPLOY_DIR:-/opt/polyserver}/{config,logs,backups}
    sudo chown -R $SSH_USER:$SSH_USER ${DEPLOY_DIR:-/opt/polyserver}
"

# Copy configuration files
echo "Copying configuration files..."
scp -P "$SSH_PORT" -r "$CONFIG_DIR"/* "$SSH_USER@$SSH_HOST:${DEPLOY_DIR:-/opt/polyserver}/config/"

# Apply security configurations
echo "===== Applying security configurations ====="
ssh -p "$SSH_PORT" "$SSH_USER@$SSH_HOST" "
    # Update audit configuration if changed
    if [ -f ${DEPLOY_DIR:-/opt/polyserver}/config/audit/auditd.conf ]; then
        sudo cp ${DEPLOY_DIR:-/opt/polyserver}/config/audit/auditd.conf /etc/audit/
        sudo cp ${DEPLOY_DIR:-/opt/polyserver}/config/audit/audit.rules /etc/audit/rules.d/
        sudo systemctl restart auditd
    fi
    
    # Update Unbound DNS configuration if changed
    if [ -f ${DEPLOY_DIR:-/opt/polyserver}/config/unbound/local.conf ]; then
        sudo cp ${DEPLOY_DIR:-/opt/polyserver}/config/unbound/local.conf /etc/unbound/conf.d/
        sudo systemctl restart unbound
    fi
    
    # Update Nginx configurations if changed
    if [ -f ${DEPLOY_DIR:-/opt/polyserver}/config/nginx/nginx.conf ]; then
        sudo cp ${DEPLOY_DIR:-/opt/polyserver}/config/nginx/nginx.conf /etc/nginx/
    fi
    
    if [ -f ${DEPLOY_DIR:-/opt/polyserver}/config/nginx/conf.d/default.conf ]; then
        sudo cp ${DEPLOY_DIR:-/opt/polyserver}/config/nginx/conf.d/default.conf /etc/nginx/conf.d/
    fi
    
    if [ -f ${DEPLOY_DIR:-/opt/polyserver}/config/nginx/conf.d/security.conf ]; then
        sudo cp ${DEPLOY_DIR:-/opt/polyserver}/config/nginx/conf.d/security.conf /etc/nginx/conf.d/
    fi
    
    if [ -f ${DEPLOY_DIR:-/opt/polyserver}/config/nginx/conf.d/proxy_params ]; then
        sudo cp ${DEPLOY_DIR:-/opt/polyserver}/config/nginx/conf.d/proxy_params /etc/nginx/conf.d/
    fi
    
    # Copy default HTML files
    if [ -f ${DEPLOY_DIR:-/opt/polyserver}/config/www/html/index.html ]; then
        sudo mkdir -p /var/www/html
        sudo cp ${DEPLOY_DIR:-/opt/polyserver}/config/www/html/index.html /var/www/html/
        sudo chown -R www-data:www-data /var/www/html
    fi
    
    # Test and reload nginx configuration
    sudo nginx -t && sudo systemctl reload nginx
    
    echo 'Base server configuration deployment completed successfully!'
"

echo "===== Base Configuration Deployment Complete ====="
echo "Base server is ready for application-specific deployments."