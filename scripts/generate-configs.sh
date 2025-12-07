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

# Helper to test truthy values (true/yes/1/on)
_is_truthy() {
  local v="${1:-}"
  v=$(echo "$v" | tr '[:upper:]' '[:lower:]')
  case "$v" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

# Function to replace variables and handle simple Mustache-like sections in a template
render_template() {
  local template="$1"
  local output="$2"

  echo "Generating: $output from $template"

  # Read the template content
  local content
  content=$(cat "$template")

  # Handle conditional sections {{#VAR}} ... {{/VAR}} based on env values
  # Collect unique section variables
  local section_vars
  section_vars=$(echo "$content" | grep -oE '{{#[A-Za-z0-9_]+}}' | sed 's/{{#//;s/}}//g' | sort -u || true)
  for var in $section_vars; do
    # Read value from environment (ENV_FILE has been sourced above)
    # Use indirect expansion via eval but with proper quoting
    local val=""
    if eval "[ -n \"\${${var}+x}\" ]"; then
      # Variable is set, get its value
      val="$(eval "echo \"\$${var}\"")"
    fi

    if _is_truthy "$val"; then
      # Keep contents, strip the section markers
      content=$(echo "$content" | sed -e "s|{{#$var}}||g" -e "s|{{/$var}}||g")
    else
      # Remove the entire section (non-greedy across newlines)
      content=$(perl -0777 -pe "s/{{#$var}}.*?{{\/$var}}//gs" <<< "$content")
    fi
  done

  # Replace all {{VARIABLE}} occurrences with values from ENV_FILE
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
}

# Generate application-specific configurations as needed
# Note: This script generates base configurations only
# Application-specific configurations should be handled separately

# NOTE: systemd/application.service is application-specific, not part of base server setup
# Applications should generate their own systemd services
# Skipping systemd service generation for base server deployment

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

# NOTE: Netdata monitoring configurations are managed by server-setup.sh during installation
# These templates are not deployed via deploy-unified.sh as Netdata installs its own configs
# Skipping Netdata config generation for base server deployment

# Generate Unbound configuration if enabled
if [ "${UNBOUND_ENABLED:-false}" = "true" ]; then
  echo "Generating Unbound DNS cache configurations..."

  # Generate unbound configuration file
  if [ -f "${TEMPLATE_DIR}/unbound/local.conf.template" ]; then
    mkdir -p "${OUTPUT_DIR}/unbound"
    render_template "${TEMPLATE_DIR}/unbound/local.conf.template" "${OUTPUT_DIR}/unbound/local.conf"
  fi

  # NOTE: dhclient.conf is not used in modern Debian with systemd-resolved
  # Unbound is configured directly in server-setup.sh
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

# NOTE: PHP configurations are managed by server-setup.sh during PHP installation
# These templates are installed directly by server-setup.sh when INSTALL_PHP=true
# Skipping PHP config generation for base server deployment

echo "===== Configuration files generated successfully ====="
echo "You can now deploy these files to your server"
