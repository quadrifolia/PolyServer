#!/bin/bash
# deploy-unified.sh - Deploy generated configuration to server
#
# IMPORTANT: Run ./scripts/generate-configs.sh FIRST to generate config files!
#
# Usage: ./deploy-unified.sh [options]
#
# Options:
#   -e, --env-file FILE       Environment file (default: templates/defaults.env)
#   -u, --user USER          SSH user (default: from env file DEPLOY_USER)
#   -h, --host HOST          SSH host (required)
#   -p, --port PORT          SSH port (default: from env file SSH_PORT or 22)
#   -i, --identity FILE      SSH private key file (optional)
#   --help                   Show this help message
#
# Examples:
#   ./deploy-unified.sh -h server.example.com
#   ./deploy-unified.sh -h server.example.com -u deploy -p 2222 -i ~/.ssh/id_ed25519

set -e

# Default paths
SCRIPT_DIR="$(dirname "$0")"
TEMPLATE_DIR="$(dirname "$0")/../templates"
DEFAULT_ENV="${TEMPLATE_DIR}/defaults.env"
CONFIG_DIR="$(dirname "$0")/../config"

# Defaults
ENV_FILE="$DEFAULT_ENV"
SSH_USER=""
SSH_HOST=""
SSH_PORT=""
SSH_IDENTITY=""

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--env-file)
            ENV_FILE="$2"
            shift 2
            ;;
        -u|--user)
            SSH_USER="$2"
            shift 2
            ;;
        -h|--host)
            SSH_HOST="$2"
            shift 2
            ;;
        -p|--port)
            SSH_PORT="$2"
            shift 2
            ;;
        -i|--identity)
            SSH_IDENTITY="$2"
            shift 2
            ;;
        --help)
            grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //'
            exit 0
            ;;
        *)
            echo -e "${RED}ERROR: Unknown option: $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Validate environment file
if [ ! -f "$ENV_FILE" ]; then
    echo -e "${RED}ERROR: Environment file not found: $ENV_FILE${NC}"
    exit 1
fi

# Save command-line values before sourcing env file
CLI_SSH_USER="$SSH_USER"
CLI_SSH_PORT="$SSH_PORT"

# Load environment variables
source "$ENV_FILE"

# Set defaults: command-line > env file > defaults
SSH_USER="${CLI_SSH_USER:-${DEPLOY_USER:-deploy}}"
SSH_PORT="${CLI_SSH_PORT:-${SSH_PORT:-22}}"

# Validate required parameters
if [ -z "$SSH_HOST" ]; then
    echo -e "${RED}ERROR: SSH host is required${NC}"
    echo "Usage: $0 --host <hostname> [options]"
    echo "Use --help for more information"
    exit 1
fi

# Check if config directory exists and has files
if [ ! -d "$CONFIG_DIR" ] || [ -z "$(ls -A "$CONFIG_DIR" 2>/dev/null)" ]; then
    echo -e "${RED}ERROR: Config directory is empty or doesn't exist: $CONFIG_DIR${NC}"
    echo ""
    echo -e "${YELLOW}Please run generate-configs.sh first:${NC}"
    echo "  ./scripts/generate-configs.sh"
    echo ""
    exit 1
fi

# Build SSH command with optional identity
SSH_CMD="ssh"
SCP_CMD="scp"
if [ -n "$SSH_IDENTITY" ]; then
    if [ ! -f "$SSH_IDENTITY" ]; then
        echo -e "${RED}ERROR: SSH identity file not found: $SSH_IDENTITY${NC}"
        exit 1
    fi
    SSH_CMD="ssh -i $SSH_IDENTITY"
    SCP_CMD="scp -i $SSH_IDENTITY"
fi
SSH_CMD="$SSH_CMD -p $SSH_PORT"
SCP_CMD="$SCP_CMD -P $SSH_PORT"

echo "===== PolyServer Configuration Deployment ====="
echo "Target: ${SSH_USER}@${SSH_HOST}:${SSH_PORT}"
echo "Deploy directory: ${DEPLOY_DIR:-/opt/polyserver}"
if [ -n "$SSH_IDENTITY" ]; then
    echo "SSH key: $SSH_IDENTITY"
fi
echo ""

# Test SSH connection
echo "Testing SSH connection..."
if ! $SSH_CMD "$SSH_USER@$SSH_HOST" "echo 'SSH connection successful'" 2>/dev/null; then
    echo -e "${RED}ERROR: Cannot connect to $SSH_USER@$SSH_HOST:$SSH_PORT${NC}"
    echo ""
    echo "Troubleshooting:"
    echo "1. Check if the server is reachable"
    echo "2. Verify SSH_USER, SSH_HOST, and SSH_PORT are correct"
    echo "3. If using SSH keys, make sure the correct key is specified with -i"
    echo "4. Add your SSH key to the agent: ssh-add ~/.ssh/your_key"
    echo ""
    exit 1
fi
echo -e "${GREEN}✓ SSH connection successful${NC}"
echo ""

# Deploy configuration
echo "===== Deploying configuration files ====="

# Create deployment directory structure on remote server
echo "Creating directory structure..."
$SSH_CMD "$SSH_USER@$SSH_HOST" "
    sudo mkdir -p ${DEPLOY_DIR:-/opt/polyserver}/{config,logs,backups,data}
    sudo chown -R $SSH_USER:$SSH_USER ${DEPLOY_DIR:-/opt/polyserver}
"
echo -e "${GREEN}✓ Directory structure created${NC}"

# Copy environment file first (server-setup.sh needs this)
echo "Copying environment configuration..."
$SCP_CMD "$ENV_FILE" "$SSH_USER@$SSH_HOST:${DEPLOY_DIR:-/opt/polyserver}/config/defaults.env"
echo -e "${GREEN}✓ Environment configuration deployed${NC}"

# Copy server-setup.sh script
if [ -f "$CONFIG_DIR/server-setup.sh" ]; then
    echo "Copying server setup script..."
    $SCP_CMD "$CONFIG_DIR/server-setup.sh" "$SSH_USER@$SSH_HOST:${DEPLOY_DIR:-/opt/polyserver}/config/"
    $SSH_CMD "$SSH_USER@$SSH_HOST" "chmod +x ${DEPLOY_DIR:-/opt/polyserver}/config/server-setup.sh"
    echo -e "${GREEN}✓ Server setup script deployed${NC}"
fi

# Copy backup scripts
if [ -d "$CONFIG_DIR/scripts" ]; then
    echo "Copying backup scripts..."
    $SCP_CMD -r "$CONFIG_DIR/scripts" "$SSH_USER@$SSH_HOST:${DEPLOY_DIR:-/opt/polyserver}/"
    $SSH_CMD "$SSH_USER@$SSH_HOST" "chmod +x ${DEPLOY_DIR:-/opt/polyserver}/scripts/*.sh"
    echo -e "${GREEN}✓ Backup scripts deployed${NC}"
fi

# Copy nginx configurations (if they exist and will be used)
if [ -d "$CONFIG_DIR/nginx" ]; then
    echo "Copying nginx configurations..."
    $SSH_CMD "$SSH_USER@$SSH_HOST" "mkdir -p ${DEPLOY_DIR:-/opt/polyserver}/config/nginx/conf.d"
    $SCP_CMD -r "$CONFIG_DIR/nginx"/* "$SSH_USER@$SSH_HOST:${DEPLOY_DIR:-/opt/polyserver}/config/nginx/"
    echo -e "${GREEN}✓ Nginx configurations deployed${NC}"
fi

# Copy www files (if they exist)
if [ -d "$CONFIG_DIR/www" ]; then
    echo "Copying www files..."
    $SCP_CMD -r "$CONFIG_DIR/www" "$SSH_USER@$SSH_HOST:${DEPLOY_DIR:-/opt/polyserver}/config/"
    echo -e "${GREEN}✓ WWW files deployed${NC}"
fi

# Copy audit configurations (if enabled)
if [ -d "$CONFIG_DIR/audit" ] && [ "${AUDIT_ENABLED:-false}" = "true" ]; then
    echo "Copying audit configurations..."
    $SCP_CMD -r "$CONFIG_DIR/audit" "$SSH_USER@$SSH_HOST:${DEPLOY_DIR:-/opt/polyserver}/config/"
    echo -e "${GREEN}✓ Audit configurations deployed${NC}"
fi

# Copy unbound configurations (if enabled)
if [ -d "$CONFIG_DIR/unbound" ] && [ "${UNBOUND_ENABLED:-false}" = "true" ]; then
    echo "Copying unbound configurations..."
    $SCP_CMD -r "$CONFIG_DIR/unbound" "$SSH_USER@$SSH_HOST:${DEPLOY_DIR:-/opt/polyserver}/config/"
    echo -e "${GREEN}✓ Unbound configurations deployed${NC}"
fi

echo ""
echo "===== Deployment Complete ====="
echo ""
echo -e "${GREEN}Configuration deployed successfully!${NC}"
echo ""
echo "Next steps:"
echo ""
echo "1. SSH into the server:"
echo "   ssh -p $SSH_PORT $SSH_USER@$SSH_HOST"
echo ""
echo "2. Run the server setup script:"
echo "   cd ${DEPLOY_DIR:-/opt/polyserver}/config"
echo "   sudo bash server-setup.sh"
echo ""
echo "The setup script will read configuration from:"
echo "   ${DEPLOY_DIR:-/opt/polyserver}/config/defaults.env"
echo ""
