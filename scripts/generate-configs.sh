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
    if eval "declare -p ${var} >/dev/null 2>&1"; then
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

# Generate nginx configurations (only if INSTALL_NGINX is enabled)
if _is_truthy "${INSTALL_NGINX:-true}"; then
  mkdir -p "${OUTPUT_DIR}/nginx/conf.d"
  mkdir -p "${OUTPUT_DIR}/nginx/sites-available"
  mkdir -p "${OUTPUT_DIR}/nginx/snippets"

  # Generate main nginx configuration based on deployment mode
  if [ "$DEPLOYMENT_MODE" = "docker" ]; then
    if [ -f "${TEMPLATE_DIR}/nginx/nginx-docker.conf.template" ]; then
      render_template "${TEMPLATE_DIR}/nginx/nginx-docker.conf.template" "${OUTPUT_DIR}/nginx/nginx.conf"
    fi
  else
    # Bare metal mode
    if [ -f "${TEMPLATE_DIR}/nginx/nginx-baremetal.conf.template" ]; then
      render_template "${TEMPLATE_DIR}/nginx/nginx-baremetal.conf.template" "${OUTPUT_DIR}/nginx/nginx.conf"
    fi
  fi

  # Generate sites-available configurations
  if [ -f "${TEMPLATE_DIR}/nginx/sites-available/default.conf.template" ]; then
    render_template "${TEMPLATE_DIR}/nginx/sites-available/default.conf.template" "${OUTPUT_DIR}/nginx/sites-available/default"
  fi

  if [ -f "${TEMPLATE_DIR}/nginx/sites-available/example-proxy.conf.template" ]; then
    render_template "${TEMPLATE_DIR}/nginx/sites-available/example-proxy.conf.template" "${OUTPUT_DIR}/nginx/sites-available/example-proxy.conf"
  fi

  # Generate nginx security locations snippet
  if [ -f "${TEMPLATE_DIR}/nginx/security-locations.conf.template" ]; then
    render_template "${TEMPLATE_DIR}/nginx/security-locations.conf.template" "${OUTPUT_DIR}/nginx/snippets/security-locations.conf"
  fi

  # Generate nginx proxy parameters
  if [ -f "${TEMPLATE_DIR}/nginx/proxy_params.template" ]; then
    render_template "${TEMPLATE_DIR}/nginx/proxy_params.template" "${OUTPUT_DIR}/nginx/conf.d/proxy_params"
  fi

  # Generate www HTML files
  mkdir -p "${OUTPUT_DIR}/www/html"

  if [ -f "${TEMPLATE_DIR}/www/html/index.html.template" ]; then
    render_template "${TEMPLATE_DIR}/www/html/index.html.template" "${OUTPUT_DIR}/www/html/index.html"
  fi

  if [ -f "${TEMPLATE_DIR}/www/html/404.html.template" ]; then
    render_template "${TEMPLATE_DIR}/www/html/404.html.template" "${OUTPUT_DIR}/www/html/404.html"
  fi

  if [ -f "${TEMPLATE_DIR}/www/html/50x.html.template" ]; then
    render_template "${TEMPLATE_DIR}/www/html/50x.html.template" "${OUTPUT_DIR}/www/html/50x.html"
  fi
else
  echo "Skipping nginx configuration generation (INSTALL_NGINX=${INSTALL_NGINX:-false})"
fi

# Generate MariaDB configurations (only if INSTALL_MARIADB is enabled)
if _is_truthy "${INSTALL_MARIADB:-false}"; then
  mkdir -p "${OUTPUT_DIR}/mariadb/conf.d"

  if [ -f "${TEMPLATE_DIR}/mariadb/50-server.cnf.template" ]; then
    render_template "${TEMPLATE_DIR}/mariadb/50-server.cnf.template" "${OUTPUT_DIR}/mariadb/conf.d/50-server.cnf"
    echo "Generated MariaDB configuration"
  fi
else
  echo "Skipping MariaDB configuration generation (INSTALL_MARIADB=${INSTALL_MARIADB:-false})"
fi

# Generate PostgreSQL configurations (only if INSTALL_POSTGRESQL is enabled)
if _is_truthy "${INSTALL_POSTGRESQL:-false}"; then
  mkdir -p "${OUTPUT_DIR}/postgresql/conf.d"

  if [ -f "${TEMPLATE_DIR}/postgresql/postgresql.conf.template" ]; then
    render_template "${TEMPLATE_DIR}/postgresql/postgresql.conf.template" "${OUTPUT_DIR}/postgresql/conf.d/postgresql.conf"
  fi

  if [ -f "${TEMPLATE_DIR}/postgresql/pg_hba.conf.template" ]; then
    render_template "${TEMPLATE_DIR}/postgresql/pg_hba.conf.template" "${OUTPUT_DIR}/postgresql/pg_hba.conf"
  fi

  if [ -d "${OUTPUT_DIR}/postgresql" ]; then
    echo "Generated PostgreSQL configuration"
  fi
else
  echo "Skipping PostgreSQL configuration generation (INSTALL_POSTGRESQL=${INSTALL_POSTGRESQL:-false})"
fi

# Generate PHP configurations (only if INSTALL_PHP is enabled)
if _is_truthy "${INSTALL_PHP:-false}"; then
  mkdir -p "${OUTPUT_DIR}/php/cli/conf.d"
  mkdir -p "${OUTPUT_DIR}/php/fpm/conf.d"
  mkdir -p "${OUTPUT_DIR}/php/fpm/pool.d"
  mkdir -p "${OUTPUT_DIR}/php/mods-available"

  # Generate main PHP configuration
  if [ -f "${TEMPLATE_DIR}/php/php.ini.template" ]; then
    # PHP CLI configuration
    render_template "${TEMPLATE_DIR}/php/php.ini.template" "${OUTPUT_DIR}/php/cli/conf.d/99-polyserver.ini"
    # PHP FPM configuration
    render_template "${TEMPLATE_DIR}/php/php.ini.template" "${OUTPUT_DIR}/php/fpm/conf.d/99-polyserver.ini"
  fi

  # Generate security configuration
  if [ -f "${TEMPLATE_DIR}/php/99-security.ini.template" ]; then
    render_template "${TEMPLATE_DIR}/php/99-security.ini.template" "${OUTPUT_DIR}/php/mods-available/99-security.ini"
  fi

  # Generate FPM pool configurations
  if [ -f "${TEMPLATE_DIR}/php/www.conf.template" ]; then
    render_template "${TEMPLATE_DIR}/php/www.conf.template" "${OUTPUT_DIR}/php/fpm/pool.d/www.conf"
  fi

  if [ -f "${TEMPLATE_DIR}/php/security-pool.conf.template" ]; then
    render_template "${TEMPLATE_DIR}/php/security-pool.conf.template" "${OUTPUT_DIR}/php/fpm/pool.d/security.conf"
  fi

  # Generate Xdebug configuration (only if dev tools enabled)
  if _is_truthy "${INSTALL_PHP_DEV_TOOLS:-false}"; then
    if [ -f "${TEMPLATE_DIR}/php/xdebug.ini.template" ]; then
      render_template "${TEMPLATE_DIR}/php/xdebug.ini.template" "${OUTPUT_DIR}/php/mods-available/xdebug.ini"
      echo "Generated PHP configuration with Xdebug (development)"
    fi
  else
    echo "Generated PHP configuration (production)"
  fi
else
  echo "Skipping PHP configuration generation (INSTALL_PHP=${INSTALL_PHP:-false})"
fi

# Generate Redis configurations (only if INSTALL_REDIS is enabled)
if _is_truthy "${INSTALL_REDIS:-false}"; then
  mkdir -p "${OUTPUT_DIR}/redis"

  if [ -f "${TEMPLATE_DIR}/redis/redis.conf.template" ]; then
    render_template "${TEMPLATE_DIR}/redis/redis.conf.template" "${OUTPUT_DIR}/redis/redis.conf"
    echo "Generated Redis configuration"
  fi
else
  echo "Skipping Redis configuration generation (INSTALL_REDIS=${INSTALL_REDIS:-false})"
fi

# Generate Docker/Netdata monitoring configuration (only if INSTALL_DOCKER is enabled)
if _is_truthy "${INSTALL_DOCKER:-false}"; then
  mkdir -p "${OUTPUT_DIR}/netdata"

  if [ -f "${TEMPLATE_DIR}/netdata/docker.conf.template" ]; then
    render_template "${TEMPLATE_DIR}/netdata/docker.conf.template" "${OUTPUT_DIR}/netdata/docker.conf"
    echo "Generated Docker monitoring configuration for Netdata"
  fi

  # Generate health.d configurations for container monitoring
  if [ -d "${TEMPLATE_DIR}/netdata/health.d" ]; then
    mkdir -p "${OUTPUT_DIR}/netdata/health.d"
    for template_file in "${TEMPLATE_DIR}/netdata/health.d"/*.template; do
      if [ -f "$template_file" ]; then
        filename=$(basename "$template_file" .template)
        render_template "$template_file" "${OUTPUT_DIR}/netdata/health.d/$filename"
        echo "Generated Netdata health configuration: $filename"
      fi
    done
  fi
else
  echo "Skipping Docker monitoring configuration (INSTALL_DOCKER=${INSTALL_DOCKER:-false})"
fi

# Generate Netdata health alarm notification configuration (only if NETDATA_ENABLED is enabled)
if _is_truthy "${NETDATA_ENABLED:-true}"; then
  mkdir -p "${OUTPUT_DIR}/netdata"

  if [ -f "${TEMPLATE_DIR}/netdata/health_alarm_notify.conf.template" ]; then
    render_template "${TEMPLATE_DIR}/netdata/health_alarm_notify.conf.template" "${OUTPUT_DIR}/netdata/health_alarm_notify.conf"
    echo "Generated Netdata health alarm notification configuration"
  fi
else
  echo "Skipping Netdata health alarm notification configuration (NETDATA_ENABLED=${NETDATA_ENABLED:-true})"
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

# Generate server helper script
if [ -f "${TEMPLATE_DIR}/scripts/server-helper.sh.template" ]; then
  render_template "${TEMPLATE_DIR}/scripts/server-helper.sh.template" "${OUTPUT_DIR}/scripts/server-helper.sh"
  chmod +x "${OUTPUT_DIR}/scripts/server-helper.sh"
fi

# Generate server setup script from template
if [ -f "${TEMPLATE_DIR}/server-setup.sh.template" ]; then
  render_template "${TEMPLATE_DIR}/server-setup.sh.template" "${OUTPUT_DIR}/server-setup.sh"
  chmod +x "${OUTPUT_DIR}/server-setup.sh"
fi

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

# NOTE: DSGVO/GDPR files are NOT generated by this script
# They are deployed directly via deploy-unified.sh and installed by setup-dsgvo.sh
# This keeps the DSGVO setup separate and allows for proper template processing

echo "===== Configuration files generated successfully ====="
echo "You can now deploy these files to your server"
