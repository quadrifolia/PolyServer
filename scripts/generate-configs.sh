#!/bin/bash
# generate-configs.sh - Generates configuration files from templates
# Usage: ./generate-configs.sh [environment file] [output directory]

set -e

# Default paths
TEMPLATE_DIR="$(dirname "$0")/../templates"
DEFAULT_ENV="${TEMPLATE_DIR}/defaults.env"
OUTPUT_DIR="$(dirname "$0")/../config"

# Parse arguments
ENV_FILE="${1:-$DEFAULT_ENV}"
OUTPUT_DIR="${2:-$OUTPUT_DIR}"

echo "===== Generating configuration files ====="
echo "Using environment file: $ENV_FILE"
echo "Output directory: $OUTPUT_DIR"

# Ensure template directory exists
if [ ! -d "$TEMPLATE_DIR" ]; then
  echo "ERROR: Template directory not found: $TEMPLATE_DIR"
  exit 1
fi

# Ensure environment file exists
if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: Environment file not found: $ENV_FILE"
  exit 1
fi

# Create output directories
mkdir -p "${OUTPUT_DIR}/nginx/conf.d"
mkdir -p "${OUTPUT_DIR}/scripts"
mkdir -p "${OUTPUT_DIR}/unbound"

# Load environment variables
source "$ENV_FILE"

# Check deployment mode (ensure it's set, default to baremetal if not)
if [ -z "$DEPLOYMENT_MODE" ]; then
    DEPLOYMENT_MODE="baremetal"
fi
echo "Deployment mode: $DEPLOYMENT_MODE"

# Function to replace variables in a template
render_template() {
  local template="$1"
  local output="$2"
  
  echo "Generating: $output from $template"
  
  # Create a temporary file with variables exported
  local tmpfile=$(mktemp)
  
  # Read the template and replace all {{VARIABLE}} occurrences
  content=$(cat "$template")
  
  # Get all variables from the env file
  while IFS='=' read -r key value; do
    # Skip comments and empty lines
    [[ $key =~ ^# ]] || [[ -z $key ]] && continue
    
    # Remove quotes if present
    value=$(echo "$value" | sed -e 's/^"//' -e 's/"$//')
    
    # Replace placeholders
    content=$(echo "$content" | sed "s|{{$key}}|$value|g")
  done < "$ENV_FILE"
  
  # Write to output file
  echo "$content" > "$output"
  rm "$tmpfile"
}

# Generate application-specific configurations as needed
# Note: This script generates base configurations only
# Application-specific configurations should be handled separately

# Generate systemd service file if template exists
if [ -f "${TEMPLATE_DIR}/systemd/application.service.template" ]; then
  mkdir -p "${OUTPUT_DIR}/systemd"
  render_template "${TEMPLATE_DIR}/systemd/application.service.template" "${OUTPUT_DIR}/systemd/application.service"
fi

# Generate base nginx configurations
mkdir -p "${OUTPUT_DIR}/nginx/conf.d"

# Generate main nginx configuration based on deployment mode
if [ "$DEPLOYMENT_MODE" = "docker" ]; then
  if [ -f "${TEMPLATE_DIR}/nginx/nginx-docker.conf.template" ]; then
    render_template "${TEMPLATE_DIR}/nginx/nginx-docker.conf.template" "${OUTPUT_DIR}/nginx/nginx.conf"
  fi
  
  # Generate default site configuration for Docker mode (reverse proxy)
  if [ -f "${TEMPLATE_DIR}/nginx/default-docker.conf.template" ]; then
    render_template "${TEMPLATE_DIR}/nginx/default-docker.conf.template" "${OUTPUT_DIR}/nginx/conf.d/default.conf"
  fi
else
  # Bare metal mode
  if [ -f "${TEMPLATE_DIR}/nginx/nginx-baremetal.conf.template" ]; then
    render_template "${TEMPLATE_DIR}/nginx/nginx-baremetal.conf.template" "${OUTPUT_DIR}/nginx/nginx.conf"
  fi
  
  # Generate default site configuration for bare metal mode (direct serving)
  if [ -f "${TEMPLATE_DIR}/nginx/default-baremetal.conf.template" ]; then
    render_template "${TEMPLATE_DIR}/nginx/default-baremetal.conf.template" "${OUTPUT_DIR}/nginx/conf.d/default.conf"
  fi
fi

# Generate nginx security configuration
if [ -f "${TEMPLATE_DIR}/nginx/security.conf.template" ]; then
  render_template "${TEMPLATE_DIR}/nginx/security.conf.template" "${OUTPUT_DIR}/nginx/conf.d/security.conf"
fi

# Generate nginx proxy parameters
if [ -f "${TEMPLATE_DIR}/nginx/proxy_params.template" ]; then
  render_template "${TEMPLATE_DIR}/nginx/proxy_params.template" "${OUTPUT_DIR}/nginx/conf.d/proxy_params"
fi

# Generate default index.html
if [ -f "${TEMPLATE_DIR}/nginx/index.html.template" ]; then
  mkdir -p "${OUTPUT_DIR}/www/html"
  render_template "${TEMPLATE_DIR}/nginx/index.html.template" "${OUTPUT_DIR}/www/html/index.html"
fi

# Generate backup scripts
mkdir -p "${OUTPUT_DIR}/scripts"
render_template "${TEMPLATE_DIR}/scripts/backup.sh.template" "${OUTPUT_DIR}/scripts/backup.sh"
chmod +x "${OUTPUT_DIR}/scripts/backup.sh"

# Generate S3 backup script if template exists
if [ -f "${TEMPLATE_DIR}/scripts/s3backup.sh.template" ]; then
  render_template "${TEMPLATE_DIR}/scripts/s3backup.sh.template" "${OUTPUT_DIR}/scripts/s3backup.sh"
  chmod +x "${OUTPUT_DIR}/scripts/s3backup.sh"
fi

# Generate server setup script from template
if [ -f "${TEMPLATE_DIR}/server-setup.sh.template" ]; then
  render_template "${TEMPLATE_DIR}/server-setup.sh.template" "${OUTPUT_DIR}/server-setup.sh"
  chmod +x "${OUTPUT_DIR}/server-setup.sh"
fi

# Generate monitoring configuration if templates exist
if [ -f "${TEMPLATE_DIR}/netdata/health_alarm_notify.conf.template" ]; then
  mkdir -p "${OUTPUT_DIR}/monitoring/netdata"
  render_template "${TEMPLATE_DIR}/netdata/health_alarm_notify.conf.template" "${OUTPUT_DIR}/monitoring/netdata/health_alarm_notify.conf"
fi

if [ -f "${TEMPLATE_DIR}/netdata/docker.conf.template" ]; then
  mkdir -p "${OUTPUT_DIR}/monitoring/netdata/go.d"
  render_template "${TEMPLATE_DIR}/netdata/docker.conf.template" "${OUTPUT_DIR}/monitoring/netdata/go.d/docker.conf"
fi

if [ -f "${TEMPLATE_DIR}/netdata/health.d/cgroups.conf.template" ]; then
  mkdir -p "${OUTPUT_DIR}/monitoring/netdata/health.d"
  render_template "${TEMPLATE_DIR}/netdata/health.d/cgroups.conf.template" "${OUTPUT_DIR}/monitoring/netdata/health.d/cgroups.conf"
fi

# Generate Unbound configuration if enabled
if [ "${UNBOUND_ENABLED:-false}" = "true" ]; then
  echo "Generating Unbound DNS cache configurations..."
  
  # Generate unbound configuration file
  if [ -f "${TEMPLATE_DIR}/unbound/local.conf.template" ]; then
    render_template "${TEMPLATE_DIR}/unbound/local.conf.template" "${OUTPUT_DIR}/unbound/local.conf"
  fi
  
  # Generate dhclient configuration file
  if [ -f "${TEMPLATE_DIR}/unbound/dhclient.conf.template" ]; then
    render_template "${TEMPLATE_DIR}/unbound/dhclient.conf.template" "${OUTPUT_DIR}/unbound/dhclient.conf"
  fi
fi

# Generate Audit configuration if enabled
if [ "${AUDIT_ENABLED:-false}" = "true" ]; then
  echo "Generating Audit framework configurations..."
  
  # Create audit directory
  mkdir -p "${OUTPUT_DIR}/audit"
  mkdir -p "${OUTPUT_DIR}/audit/rules.d"
  
  # Generate audit configuration file
  if [ -f "${TEMPLATE_DIR}/audit/auditd.conf.template" ]; then
    render_template "${TEMPLATE_DIR}/audit/auditd.conf.template" "${OUTPUT_DIR}/audit/auditd.conf"
  fi
  
  # Generate audit rules file
  if [ -f "${TEMPLATE_DIR}/audit/audit.rules.template" ]; then
    render_template "${TEMPLATE_DIR}/audit/audit.rules.template" "${OUTPUT_DIR}/audit/rules.d/audit.rules"
  fi
fi

echo "===== Configuration files generated successfully ====="
echo "You can now deploy these files to your server"