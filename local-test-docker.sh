#!/bin/bash
# Local Docker Testing Script for PolyServer
# This script sets up a Docker-based testing environment to validate the PolyServer foundation

set -e

# Configuration
CONTAINER_NAME="polyserver-test"
NETWORK_NAME="polyserver-network"
TEST_PORT="8080"

echo "🚀 Starting PolyServer local Docker testing environment..."

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker and try again."
    exit 1
fi

# Cleanup any existing PolyServer test environment (safe cleanup)
echo "🧹 Cleaning up any existing PolyServer test environment..."
echo "🔒 Only removing PolyServer-specific test resources..."

# Safe cleanup - only remove our specific containers/networks/volumes
docker stop $CONTAINER_NAME 2>/dev/null || echo "No existing $CONTAINER_NAME container"
docker rm $CONTAINER_NAME 2>/dev/null || echo "No existing $CONTAINER_NAME container to remove"
docker network rm $NETWORK_NAME 2>/dev/null || echo "No existing $NETWORK_NAME network to remove"
docker volume rm polyserver-data polyserver-logs polyserver-config 2>/dev/null || echo "No existing PolyServer volumes to remove"
rm -rf ./test-config 2>/dev/null || true

# Create Docker network
echo "🌐 Creating Docker network..."
docker network create $NETWORK_NAME

# Create volumes for persistent data
echo "💾 Creating Docker volumes..."
docker volume create polyserver-data
docker volume create polyserver-logs
docker volume create polyserver-config

# Generate test configuration
echo "⚙️ Generating test configuration..."
mkdir -p test-config

# Create a test environment file
cat > test-config/.env << EOF
# PolyServer Test Configuration
DEPLOY_USER=testuser
DEPLOY_DIR=/opt/polyserver
BASE_DOMAIN=localhost
HOSTNAME=polyserver-test
SSH_PORT=2222
SSL_EMAIL=test@example.com
LOGWATCH_EMAIL=admin@example.com

# Deployment mode for testing (change to "docker" to test Docker mode)
DEPLOYMENT_MODE=baremetal

# Docker-specific settings
DOCKER_NETWORK=polyserver-network
BACKEND_HOST=127.0.0.1
BACKEND_PORT=3000

# Security settings
BACKUP_RETENTION_DAYS=7
ENABLE_FAIL2BAN=true
ENABLE_MODSECURITY=true
ENABLE_SURICATA=true
RATE_LIMIT=10

# Testing mode
TESTING_MODE=true
EOF

# Generate configurations from templates
echo "📝 Generating configuration files from templates..."
if [ -f "./scripts/generate-configs.sh" ]; then
    ./scripts/generate-configs.sh test-config/.env test-config/
else
    echo "❌ generate-configs.sh not found!"
    exit 1
fi

# Copy other scripts (but not server-setup.sh since we use the generated one)
echo "📋 Copying PolyServer scripts and templates..."
mkdir -p test-config/scripts/
mkdir -p test-config/templates/
# Copy all scripts except server-setup.sh (we use the generated one)
for script in scripts/*.sh; do
    if [[ "$(basename "$script")" != "server-setup.sh" ]]; then
        cp "$script" test-config/scripts/
    fi
done
cp -r templates/* test-config/templates/

# Create a test Dockerfile that runs the real PolyServer setup
cat > test-config/Dockerfile << 'EOF'
FROM debian:12-slim

# Install minimal packages needed to run server-setup.sh
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    sudo \
    systemctl \
    openssh-server \
    && rm -rf /var/lib/apt/lists/*

# Copy all PolyServer files (including templates)
COPY . /opt/polyserver/

# Make all scripts executable (including the generated server-setup.sh)
RUN chmod +x /opt/polyserver/scripts/*.sh && \
    chmod +x /opt/polyserver/server-setup.sh

# Create SSH directory for server-setup.sh
RUN mkdir -p /root/.ssh && \
    touch /root/.ssh/authorized_keys && \
    chmod 700 /root/.ssh && \
    chmod 600 /root/.ssh/authorized_keys

# Set environment for Docker testing
ENV TESTING_MODE=true
ENV LOGWATCH_EMAIL=test@example.com

# Run the generated PolyServer server-setup.sh script (customized from template)
RUN /opt/polyserver/server-setup.sh

# Copy the generated index.html to nginx web root if it exists
RUN cp /opt/polyserver/www/html/index.html /var/www/html/index.html 2>/dev/null || \
    cp /opt/polyserver/templates/nginx/index.html.template /var/www/html/index.html 2>/dev/null || \
    echo "Using default nginx index.html"

# Fix permissions for web files
RUN chmod 644 /var/www/html/index.html

# Create nginx config that includes security rules properly 
RUN rm -f /etc/nginx/conf.d/security.conf && \
    echo 'server {\n\
    listen 80 default_server;\n\
    listen [::]:80 default_server;\n\
    root /var/www/html;\n\
    index index.html;\n\
    server_name _;\n\
    \n\
    # Hide nginx version information\n\
    server_tokens off;\n\
    \n\
    # Basic security headers\n\
    add_header X-Frame-Options "SAMEORIGIN" always;\n\
    add_header X-Content-Type-Options "nosniff" always;\n\
    add_header X-XSS-Protection "1; mode=block" always;\n\
    \n\
    # Block access to hidden files\n\
    location ~ /\\. {\n\
        access_log off;\n\
        log_not_found off;\n\
        deny all;\n\
    }\n\
    \n\
    # Allow Let'\''s Encrypt ACME challenge\n\
    location ~ ^/(\\.well-known/acme-challenge/)(.*)$ {\n\
        allow all;\n\
    }\n\
    \n\
    # Block sensitive file types\n\
    location ~* \\.(env|git|gitignore|htaccess|htpasswd|ini|log|sh|sql|conf|config|bak|backup|swp|tmp)$ {\n\
        access_log off;\n\
        log_not_found off;\n\
        deny all;\n\
    }\n\
    \n\
    # Block script files (server serves only static content)\n\
    location ~* \\.(asp|aspx|jsp|cgi|pl|py|rb|php|php3|php4|php5|phtml|shtml)$ {\n\
        access_log off;\n\
        log_not_found off;\n\
        return 444;\n\
    }\n\
    \n\
    # Main location for static content\n\
    location / {\n\
        try_files $uri $uri/ =404;\n\
    }\n\
    \n\
    # Test endpoint for health checks\n\
    location /health {\n\
        access_log off;\n\
        return 200 "healthy\\n";\n\
        add_header Content-Type text/plain;\n\
    }\n\
}' > /etc/nginx/sites-available/default

# Link nginx logs to stdout/stderr for Docker logging
RUN ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log

EXPOSE 80

# Start nginx in foreground mode so logs go to Docker
CMD ["nginx", "-g", "daemon off;"]
EOF

# Build test container
echo "🔨 Building test container..."
docker build --label "polyserver-test=true" -t polyserver:test test-config/

# Run the test container
echo "🚀 Starting test container..."
docker run -d \
    --name $CONTAINER_NAME \
    --network $NETWORK_NAME \
    -p $TEST_PORT:80 \
    -v polyserver-data:/opt/polyserver/data \
    -v polyserver-logs:/opt/polyserver/logs \
    -v polyserver-config:/opt/polyserver/config \
    polyserver:test

# Wait for container to be ready
echo "⏳ Waiting for container to be ready..."
sleep 5

# Test the deployment
echo "🧪 Testing the deployment..."

# Check if container is running
if docker ps | grep -q $CONTAINER_NAME; then
    echo "✅ Container is running"
else
    echo "❌ Container failed to start"
    docker logs $CONTAINER_NAME
    exit 1
fi

# Test HTTP response
if curl -s http://localhost:$TEST_PORT/health | grep -q "healthy"; then
    echo "✅ HTTP health check passed"
else
    echo "❌ HTTP health check failed"
    echo "Container logs:"
    docker logs $CONTAINER_NAME
    exit 1
fi

# Test basic web response
if curl -s http://localhost:$TEST_PORT | grep -q "PolyServer"; then
    echo "✅ Web server is serving content"
else
    echo "❌ Web server test failed"
    exit 1
fi

# Generate some log entries for testing
echo "📝 Generating test log entries..."
curl -s http://localhost:$TEST_PORT/health >/dev/null
curl -s http://localhost:$TEST_PORT/ >/dev/null
curl -s http://localhost:$TEST_PORT/nonexistent >/dev/null 2>&1 # This will generate a 404 error log

echo ""
echo "🎉 PolyServer local testing environment is ready!"
echo ""
echo "📊 Test Environment Details:"
echo "  - Container: $CONTAINER_NAME"
echo "  - Network: $NETWORK_NAME"
echo "  - Web interface: http://localhost:$TEST_PORT"
echo "  - Health check: http://localhost:$TEST_PORT/health"
echo ""
echo "🔍 Useful commands:"
echo "  - View container logs: docker logs $CONTAINER_NAME"
echo "  - Follow logs in real-time: docker logs -f $CONTAINER_NAME"
echo "  - Access zsh shell (as root): docker exec -it $CONTAINER_NAME /bin/zsh"
echo "  - Access zsh shell (as deploy): docker exec -it -u deploy $CONTAINER_NAME /bin/zsh" 
echo "  - Access zsh shell (as testuser): docker exec -it -u testuser $CONTAINER_NAME /bin/zsh"
echo "  - View running containers: docker ps"
echo "  - Stop test environment: docker stop $CONTAINER_NAME"
echo ""
echo "🧪 Testing PolyServer functionality:"
echo "  - Test DSGVO scripts: docker exec -it $CONTAINER_NAME /bin/zsh -c 'cd /opt/polyserver/scripts && ll'"
echo "  - Run compliance check: docker exec -it $CONTAINER_NAME /opt/polyserver/scripts/dsgvo-compliance-check.sh"
echo "  - Test breach response: docker exec -it $CONTAINER_NAME /opt/polyserver/scripts/breach-response-checklist.sh"
echo "  - Interactive shell for testing: docker exec -it $CONTAINER_NAME /bin/zsh"
echo "  - Test vim config: docker exec -it $CONTAINER_NAME /bin/zsh -c 'vim --version | head -5'"
echo ""
echo "✨ PolyServer features included:"
echo "  - Complete server-setup.sh execution (real PolyServer foundation)"
echo "  - Oh My Zsh with enhanced plugins for all users (root, deploy, testuser)"
echo "  - Advanced vim configuration optimized for server administration" 
echo "  - Global aliases (ll, la, l) working in interactive and non-interactive shells"
echo "  - All PolyServer DSGVO/GDPR compliance scripts"
echo "  - Monitoring tools (htop, iotop, sysstat)"
echo "  - Network tools for diagnostics"
echo "  - Security packages (where compatible with Docker)"
echo ""
echo "📋 Test Environment Notes:"
echo "  - This Docker environment runs the actual server-setup.sh script"
echo "  - Provides realistic testing of the complete PolyServer foundation"
echo "  - Some services (firewall, systemd) are skipped in Docker mode"
echo "  - Perfect for testing scripts, configurations, and shell environment"
echo ""
echo "🧹 To clean up everything:"
echo "  ./local-test-cleanup-docker.sh"
echo ""
echo "📝 Test configuration files are in: ./test-config/"