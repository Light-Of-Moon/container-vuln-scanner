#!/bin/bash
# =============================================================================
# ArgoCD Installation and Configuration Script
# =============================================================================
# This script installs ArgoCD on the KinD cluster and configures the
# vulnerability scanner application for GitOps deployment.
#
# Prerequisites:
#   - KinD cluster must be running
#   - kubectl configured with the cluster
#
# Usage: ./deploy-argocd.sh
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

CLUSTER_NAME="vulnscan"
ARGOCD_VERSION="v2.9.3"

echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE} ArgoCD Deployment for VulnScan ${NC}"
echo -e "${BLUE}=============================================${NC}"

# Check if cluster exists
echo -e "\n${YELLOW}[1/7] Checking KinD cluster...${NC}"
if ! kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    echo -e "${RED}Error: Cluster '$CLUSTER_NAME' not found${NC}"
    echo -e "${YELLOW}Run ./start-k8s.sh first to create the cluster${NC}"
    exit 1
fi
kubectl cluster-info --context kind-$CLUSTER_NAME &>/dev/null
echo -e "${GREEN}✓ Cluster is accessible${NC}"

# Install ArgoCD
echo -e "\n${YELLOW}[2/7] Installing ArgoCD...${NC}"
kubectl create namespace argocd 2>/dev/null || echo "Namespace argocd already exists"

kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/${ARGOCD_VERSION}/manifests/install.yaml

echo -e "${GREEN}✓ ArgoCD manifests applied${NC}"

# Wait for ArgoCD to be ready
echo -e "\n${YELLOW}[3/7] Waiting for ArgoCD to be ready...${NC}"
echo "This may take a few minutes..."

kubectl wait --for=condition=available deployment/argocd-server -n argocd --timeout=300s
kubectl wait --for=condition=available deployment/argocd-repo-server -n argocd --timeout=300s
kubectl wait --for=condition=available deployment/argocd-dex-server -n argocd --timeout=300s

echo -e "${GREEN}✓ ArgoCD is ready${NC}"

# Patch ArgoCD server service to use NodePort for easy access
echo -e "\n${YELLOW}[4/7] Configuring ArgoCD access...${NC}"
kubectl patch svc argocd-server -n argocd -p '{"spec": {"type": "NodePort", "ports": [{"port": 80, "nodePort": 30080, "name": "http"}, {"port": 443, "nodePort": 30443, "name": "https"}]}}'

echo -e "${GREEN}✓ ArgoCD server exposed on NodePort 30080${NC}"

# Get initial admin password
echo -e "\n${YELLOW}[5/7] Retrieving ArgoCD admin password...${NC}"
ARGOCD_PASSWORD=$(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d)

echo -e "${GREEN}✓ Admin password retrieved${NC}"

# Configure ArgoCD to disable TLS (for local development)
echo -e "\n${YELLOW}[6/7] Configuring ArgoCD for insecure mode (local dev)...${NC}"
kubectl patch deployment argocd-server -n argocd --type='json' \
  -p='[{"op": "add", "path": "/spec/template/spec/containers/0/command/-", "value": "--insecure"}]' 2>/dev/null || true

# Wait for ArgoCD server to restart
sleep 10
kubectl wait --for=condition=available deployment/argocd-server -n argocd --timeout=120s 2>/dev/null || true

echo -e "${GREEN}✓ ArgoCD configured${NC}"

# Create ArgoCD Application (if Git repo is available)
echo -e "\n${YELLOW}[7/7] ArgoCD Application Configuration...${NC}"
echo ""
echo -e "${YELLOW}Note: The ArgoCD Application manifest (k8s/argocd-app.yaml) is configured${NC}"
echo -e "${YELLOW}      but requires a Git repository URL to be set.${NC}"
echo ""
echo -e "To deploy the application via ArgoCD:"
echo -e "  1. Push this project to a Git repository"
echo -e "  2. Update k8s/argocd-app.yaml with your Git repo URL"
echo -e "  3. Run: kubectl apply -f k8s/argocd-app.yaml"
echo ""
echo -e "${YELLOW}For now, the application is deployed directly via kubectl (see start-k8s.sh)${NC}"

# Display access information
echo ""
echo -e "${BLUE}=============================================${NC}"
echo -e "${GREEN}✓ ArgoCD DEPLOYMENT COMPLETE!${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""
echo -e "${YELLOW}ArgoCD Access Information:${NC}"
echo ""
echo "  • URL:      http://localhost:30080"
echo "  • Username: admin"
echo "  • Password: ${ARGOCD_PASSWORD}"
echo ""
echo -e "${YELLOW}To access ArgoCD UI:${NC}"
echo "  1. Open http://localhost:30080 in your browser"
echo "  2. Login with the credentials above"
echo "  3. Change the password on first login (recommended)"
echo ""
echo -e "${YELLOW}ArgoCD CLI Login:${NC}"
echo "  argocd login localhost:30080 --insecure --username admin --password '${ARGOCD_PASSWORD}'"
echo ""
echo -e "${YELLOW}Useful ArgoCD Commands:${NC}"
echo "  • List apps:        argocd app list"
echo "  • Sync app:         argocd app sync vulnscan"
echo "  • Get app status:   argocd app get vulnscan"
echo "  • View logs:        kubectl logs -n argocd -l app.kubernetes.io/name=argocd-server -f"
echo ""
echo -e "${YELLOW}Save this password securely!${NC}"
echo ""

# Save password to file
echo "$ARGOCD_PASSWORD" > argocd-password.txt
chmod 600 argocd-password.txt
echo -e "${GREEN}Password saved to: argocd-password.txt${NC}"
echo ""
