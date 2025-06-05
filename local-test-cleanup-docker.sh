#!/bin/bash
# Local Docker Testing Cleanup Script for PolyServer
# This script SAFELY cleans up ONLY PolyServer-specific Docker resources

set -e

echo "🧹 Cleaning up PolyServer Docker testing environment..."
echo "🔒 SAFE MODE: Only removing PolyServer-specific test resources"
echo "   - Container: polyserver-test"
echo "   - Network: polyserver-network" 
echo "   - Volumes: polyserver-data, polyserver-logs, polyserver-config"
echo ""

# Stop and remove containers
echo "Stopping containers..."
docker stop polyserver-test 2>/dev/null || echo "No running polyserver-test container"
docker stop polyserver-nginx 2>/dev/null || echo "No running polyserver-nginx container"
docker stop polyserver-app 2>/dev/null || echo "No running polyserver-app container"

echo "Removing containers..."
docker rm polyserver-test 2>/dev/null || echo "No polyserver-test container to remove"
docker rm polyserver-nginx 2>/dev/null || echo "No polyserver-nginx container to remove"
docker rm polyserver-app 2>/dev/null || echo "No polyserver-app container to remove"

# Remove networks
echo "Removing networks..."
docker network rm polyserver-network 2>/dev/null || echo "No polyserver-network to remove"

# Remove volumes
echo "Removing volumes..."
docker volume rm polyserver-data 2>/dev/null || echo "No polyserver-data volume to remove"
docker volume rm polyserver-logs 2>/dev/null || echo "No polyserver-logs volume to remove"
docker volume rm polyserver-config 2>/dev/null || echo "No polyserver-config volume to remove"

# Remove images (optional - uncomment if you want to remove built images)
# echo "Removing images..."
# docker rmi polyserver:test 2>/dev/null || echo "No polyserver:test image to remove"

# Clean up only PolyServer test-related dangling resources
echo "Cleaning up PolyServer test-related dangling resources..."
# Only remove dangling resources that were created by our test (safer approach)
docker images -f "dangling=true" -f "label=polyserver-test" -q | xargs -r docker rmi
echo "Note: Only PolyServer test-related resources cleaned up"

# Remove test configuration directory
echo "Removing test configuration directory..."
rm -rf ./test-config

echo "✅ PolyServer Docker test cleanup completed!"
echo ""
echo "ℹ️  Only PolyServer test resources were cleaned up."
echo "   Your other Docker containers and networks are safe."
echo ""
echo "⚠️  If you want to clean up ALL unused Docker resources (DANGEROUS), run:"
echo "   docker system prune -a --volumes"
echo "   (This will affect ALL your Docker resources, not just PolyServer!)"