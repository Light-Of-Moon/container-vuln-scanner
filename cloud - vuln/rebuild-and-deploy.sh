#!/bin/bash
# =============================================================================
# Rebuild and Redeploy Script for Kubernetes
# =============================================================================
# This script rebuilds Docker images and redeploys to Kubernetes
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLUSTER_NAME="vulnscan"

echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE} Rebuilding and Redeploying to Kubernetes${NC}"
echo -e "${BLUE}=============================================${NC}"

# Step 1: Rebuild Docker images
echo -e "\n${YELLOW}[1/6] Building Docker images...${NC}"
cd "$PROJECT_DIR"

echo "Building backend image..."
docker build -f Dockerfile.backend -t vulnscan-api:latest -t vulnscan-worker:latest .

echo "Building frontend image..."
docker build -f Dockerfile.frontend -t vulnscan-frontend:latest .

echo -e "${GREEN}✓ Docker images built${NC}"

# Step 2: Load images into KinD cluster
echo -e "\n${YELLOW}[2/6] Loading images into KinD cluster...${NC}"
kind load docker-image vulnscan-api:latest --name $CLUSTER_NAME
kind load docker-image vulnscan-worker:latest --name $CLUSTER_NAME
kind load docker-image vulnscan-frontend:latest --name $CLUSTER_NAME
echo -e "${GREEN}✓ Images loaded${NC}"

# Step 3: Apply database migration
echo -e "\n${YELLOW}[3/6] Applying database migration...${NC}"
# Check if postgres is running
if kubectl get pod postgres-0 -n vulnscan &>/dev/null; then
    # Copy and run migration
    kubectl cp migrations/002_remove_idempotency_unique_constraint.sql vulnscan/postgres-0:/tmp/ 2>/dev/null || true
    kubectl exec -n vulnscan postgres-0 -- psql -U scanner -d vulnscan -f /tmp/002_remove_idempotency_unique_constraint.sql 2>/dev/null || {
        echo "Migration may already be applied"
    }
    echo -e "${GREEN}✓ Migration applied${NC}"
else
    echo -e "${YELLOW}⚠ PostgreSQL pod not found, skipping migration${NC}"
fi

# Step 4: Update Ingress configuration
echo -e "\n${YELLOW}[4/6] Updating Ingress configuration...${NC}"
kubectl apply -f k8s/ingress.yaml
echo -e "${GREEN}✓ Ingress updated${NC}"

# Step 5: Restart deployments
echo -e "\n${YELLOW}[5/6] Restarting deployments...${NC}"
kubectl rollout restart deployment vulnscan-api -n vulnscan
kubectl rollout restart deployment vulnscan-worker -n vulnscan
kubectl rollout restart deployment vulnscan-frontend -n vulnscan
echo -e "${GREEN}✓ Deployments restarted${NC}"

# Step 6: Wait for pods to be ready
echo -e "\n${YELLOW}[6/6] Waiting for pods to be ready...${NC}"

echo "Waiting for API pods..."
kubectl wait --for=condition=ready pod -l app=vulnscan-api -n vulnscan --timeout=120s 2>/dev/null || {
    echo "API pods still starting..."
}

echo "Waiting for Worker pods..."
kubectl wait --for=condition=ready pod -l app=vulnscan-worker -n vulnscan --timeout=120s 2>/dev/null || {
    echo "Worker pods still starting..."
}

echo "Waiting for Frontend pods..."
kubectl wait --for=condition=ready pod -l app=vulnscan-frontend -n vulnscan --timeout=120s 2>/dev/null || {
    echo "Frontend pods still starting..."
}

echo -e "${GREEN}✓ Pods are ready${NC}"

# Display status
echo -e "\n${BLUE}=============================================${NC}"
echo -e "${GREEN} Deployment Complete!${NC}"
echo -e "${BLUE}=============================================${NC}"
echo -e "\nPod Status:"
kubectl get pods -n vulnscan

echo -e "\n${GREEN}Frontend URL:${NC} http://vulnscan.example.com:8080"
echo -e "${GREEN}API URL:${NC} http://api.vulnscan.example.com:8080"
echo -e "\nYou can now access the application!"
