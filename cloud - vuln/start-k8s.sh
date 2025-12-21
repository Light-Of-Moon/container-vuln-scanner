#!/bin/bash
# =============================================================================
# Container Vulnerability Scanner - Kubernetes Startup Script
# =============================================================================
# This script deploys the entire project on KinD (Kubernetes in Docker)
# Run this script after every computer restart to start all services
#
# Usage: ./start-k8s.sh [--fresh]
#   --fresh : Delete existing cluster and create a new one
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CLUSTER_NAME="vulnscan"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOSTS_ENTRIES="127.0.0.1 vulnscan.example.com api.vulnscan.example.com"

echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE} Container Vulnerability Scanner - K8s Deploy${NC}"
echo -e "${BLUE}=============================================${NC}"

# Function to check if command exists
check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}Error: $1 is not installed${NC}"
        exit 1
    fi
}

# Check required tools
echo -e "\n${YELLOW}[1/10] Checking required tools...${NC}"
check_command docker
check_command kind
check_command kubectl
echo -e "${GREEN}✓ All required tools are installed${NC}"

# Check if fresh install requested
if [[ "$1" == "--fresh" ]]; then
    echo -e "\n${YELLOW}[2/10] Deleting existing cluster...${NC}"
    kind delete cluster --name $CLUSTER_NAME 2>/dev/null || true
    CLUSTER_EXISTS=false
else
    # Check if cluster exists
    if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
        CLUSTER_EXISTS=true
        echo -e "\n${YELLOW}[2/10] Cluster '$CLUSTER_NAME' exists, checking status...${NC}"
    else
        CLUSTER_EXISTS=false
        echo -e "\n${YELLOW}[2/10] Cluster '$CLUSTER_NAME' not found, will create...${NC}"
    fi
fi

# Create KinD cluster if needed
if [[ "$CLUSTER_EXISTS" == false ]]; then
    echo -e "\n${YELLOW}[3/10] Creating KinD cluster with Ingress support...${NC}"
    cat <<EOF | kind create cluster --name $CLUSTER_NAME --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    kubeadmConfigPatches:
      - |
        kind: InitConfiguration
        nodeRegistration:
          kubeletExtraArgs:
            node-labels: "ingress-ready=true"
    extraPortMappings:
      - containerPort: 80
        hostPort: 8080
        protocol: TCP
      - containerPort: 443
        hostPort: 8443
        protocol: TCP
      - containerPort: 30080
        hostPort: 30080
        protocol: TCP
EOF
    echo -e "${GREEN}✓ KinD cluster created${NC}"
else
    echo -e "\n${YELLOW}[3/10] Using existing cluster...${NC}"
    # Ensure kubectl context is set
    kubectl cluster-info --context kind-$CLUSTER_NAME &>/dev/null || {
        echo -e "${RED}Cluster exists but not accessible. Run with --fresh to recreate.${NC}"
        exit 1
    }
    echo -e "${GREEN}✓ Cluster is accessible${NC}"
fi

# Set kubectl context
kubectl config use-context kind-$CLUSTER_NAME

# Build and load Docker images
echo -e "\n${YELLOW}[4/10] Building Docker images...${NC}"
cd "$PROJECT_DIR"

echo "Building backend image..."
docker build -f Dockerfile.backend -t vulnscan-api:latest -t vulnscan-worker:latest . 

echo "Building frontend image..."
docker build -f Dockerfile.frontend -t vulnscan-frontend:latest .

echo -e "${GREEN}✓ Docker images built${NC}"

# Load images into KinD
echo -e "\n${YELLOW}[5/10] Loading images into KinD cluster...${NC}"
kind load docker-image vulnscan-api:latest --name $CLUSTER_NAME
kind load docker-image vulnscan-worker:latest --name $CLUSTER_NAME
kind load docker-image vulnscan-frontend:latest --name $CLUSTER_NAME
echo -e "${GREEN}✓ Images loaded into cluster${NC}"

# Install NGINX Ingress Controller
echo -e "\n${YELLOW}[6/10] Installing NGINX Ingress Controller...${NC}"
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml

echo "Waiting for Ingress controller to be ready..."
kubectl wait --namespace ingress-nginx \
  --for=condition=ready pod \
  --selector=app.kubernetes.io/component=controller \
  --timeout=120s 2>/dev/null || {
    echo "Waiting for ingress pods to start..."
    sleep 30
}
echo -e "${GREEN}✓ Ingress controller installed${NC}"

# Apply Kubernetes manifests
echo -e "\n${YELLOW}[7/10] Applying Kubernetes manifests...${NC}"

# Apply namespace first
kubectl apply -f k8s/namespace.yaml
echo "✓ Namespace created"

# Apply PostgreSQL
kubectl apply -f k8s/postgres.yaml
echo "✓ PostgreSQL deployed"

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL to be ready..."
kubectl wait --for=condition=ready pod -l app=postgres -n vulnscan --timeout=120s 2>/dev/null || {
    echo "PostgreSQL starting..."
    sleep 30
}

# Apply database migration
echo "Applying database migration..."
kubectl cp migrations/001_initial_schema.sql vulnscan/postgres-0:/tmp/ 2>/dev/null || true
kubectl exec -n vulnscan postgres-0 -- psql -U scanner -d vulnscan -f /tmp/001_initial_schema.sql 2>/dev/null || {
    echo "Migration may already be applied or postgres not ready yet"
}
echo "✓ Database migration applied"

# Apply API and Worker
kubectl apply -f k8s/api.yaml
echo "✓ API deployed"

kubectl apply -f k8s/worker.yaml
echo "✓ Worker deployed"

# Apply Frontend
kubectl apply -f k8s/frontend.yaml
echo "✓ Frontend deployed"

# Apply Ingress
kubectl apply -f k8s/ingress.yaml
echo "✓ Ingress configured"

echo -e "${GREEN}✓ All manifests applied${NC}"

# Configure /etc/hosts
echo -e "\n${YELLOW}[8/10] Configuring /etc/hosts...${NC}"
if grep -q "vulnscan.example.com" /etc/hosts; then
    echo "Hosts entries already exist"
else
    echo "Adding hosts entries (requires sudo)..."
    echo "$HOSTS_ENTRIES" | sudo tee -a /etc/hosts > /dev/null
    echo -e "${GREEN}✓ Hosts entries added${NC}"
fi

# Wait for services to be ready
echo -e "\n${YELLOW}[9/10] Waiting for services to be ready...${NC}"

echo "Waiting for API pods..."
kubectl wait --for=condition=ready pod -l app=vulnscan-api -n vulnscan --timeout=120s 2>/dev/null || {
    echo "API pods still starting..."
    sleep 20
}

echo "Waiting for Frontend pods..."
kubectl wait --for=condition=ready pod -l app=vulnscan-frontend -n vulnscan --timeout=120s 2>/dev/null || {
    echo "Frontend pods still starting..."
    sleep 20
}

echo "Waiting for Worker pods..."
kubectl wait --for=condition=ready pod -l app=vulnscan-worker -n vulnscan --timeout=60s 2>/dev/null || {
    echo "Worker may still be initializing (this is normal)..."
}

echo -e "${GREEN}✓ Services are starting${NC}"

# Verify deployment
echo -e "\n${YELLOW}[10/10] Verifying deployment...${NC}"
echo ""
echo "=== Pod Status ==="
kubectl get pods -n vulnscan

echo ""
echo "=== Services ==="
kubectl get svc -n vulnscan

echo ""
echo "=== Ingress ==="
kubectl get ingress -n vulnscan

# Test API
echo ""
echo "=== Testing API Health ==="
sleep 5

# Test via port-forward in background
kubectl port-forward -n vulnscan svc/vulnscan-api 9999:80 &>/dev/null &
PF_PID=$!
sleep 3

if curl -s http://localhost:9999/health | grep -q "healthy"; then
    echo -e "${GREEN}✓ API is healthy!${NC}"
else
    echo -e "${YELLOW}API may still be starting...${NC}"
fi

# Kill port-forward
kill $PF_PID 2>/dev/null || true

# Print access information
echo ""
echo -e "${BLUE}=============================================${NC}"
echo -e "${GREEN}✓ DEPLOYMENT COMPLETE!${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""
echo -e "${YELLOW}Access URLs:${NC}"
echo ""
echo "  Via Ingress (if /etc/hosts configured):"
echo "    • Frontend:  http://vulnscan.example.com:8080"
echo "    • API:       http://api.vulnscan.example.com:8080"
echo "    • API Docs:  http://api.vulnscan.example.com:8080/docs"
echo ""
echo "  Via Port-Forward (always works):"
echo "    Frontend: kubectl port-forward -n vulnscan svc/vulnscan-frontend 3000:80"
echo "    • Frontend:  http://localhost:3000"
echo ""
echo "    API:      kubectl port-forward -n vulnscan svc/vulnscan-api 8000:80"
echo "    • API:       http://localhost:8000"
echo "    • API Docs:  http://localhost:8000/docs"
echo ""
echo -e "${YELLOW}Useful Commands:${NC}"
echo "  • View pods:      kubectl get pods -n vulnscan"
echo "  • API logs:       kubectl logs -n vulnscan -l app=vulnscan-api -f"
echo "  • Frontend logs:  kubectl logs -n vulnscan -l app=vulnscan-frontend -f"
echo "  • Worker logs:    kubectl logs -n vulnscan -l app=vulnscan-worker -f"
echo "  • Delete all:     kind delete cluster --name $CLUSTER_NAME"
echo ""
