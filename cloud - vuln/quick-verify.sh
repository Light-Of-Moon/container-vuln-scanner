#!/bin/bash
# =============================================================================
# Quick Verification Script - Container Vulnerability Scanner
# =============================================================================
# This script performs a quick health check of all components
# =============================================================================

echo "🔍 Container Vulnerability Scanner - Quick Verification"
echo "========================================================"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

# Check cluster
echo "1️⃣  Checking Kubernetes cluster..."
if kubectl cluster-info --context kind-vulnscan > /dev/null 2>&1; then
  echo -e "${GREEN}✅ Cluster is running${NC}"
  ((PASS++))
else
  echo -e "${RED}❌ Cluster not found${NC}"
  ((FAIL++))
fi

# Check namespaces
echo ""
echo "2️⃣  Checking namespaces..."
if kubectl get namespace vulnscan > /dev/null 2>&1 && kubectl get namespace argocd > /dev/null 2>&1; then
  echo -e "${GREEN}✅ Required namespaces exist (vulnscan, argocd)${NC}"
  ((PASS++))
else
  echo -e "${RED}❌ Some namespaces are missing${NC}"
  ((FAIL++))
fi

# Check pods
echo ""
echo "3️⃣  Checking pods status..."
ALL_RUNNING=$(kubectl get pods -n vulnscan --no-headers 2>/dev/null | awk '{print $3}' | grep -v "Running" | wc -l)
TOTAL_PODS=$(kubectl get pods -n vulnscan --no-headers 2>/dev/null | wc -l)
if [ "$ALL_RUNNING" -eq 0 ] && [ "$TOTAL_PODS" -gt 0 ]; then
  echo -e "${GREEN}✅ All $TOTAL_PODS pods are running${NC}"
  ((PASS++))
else
  echo -e "${RED}❌ Some pods are not running${NC}"
  kubectl get pods -n vulnscan
  ((FAIL++))
fi

# Check API
echo ""
echo "4️⃣  Checking API health..."
kubectl port-forward -n vulnscan svc/vulnscan-api 9998:80 &>/dev/null &
PF_PID=$!
sleep 3
HEALTH=$(curl -s http://localhost:9998/health 2>/dev/null | grep "healthy")
kill $PF_PID 2>/dev/null
wait $PF_PID 2>/dev/null
if [ -n "$HEALTH" ]; then
  echo -e "${GREEN}✅ API is healthy${NC}"
  ((PASS++))
else
  echo -e "${RED}❌ API health check failed${NC}"
  ((FAIL++))
fi

# Check database
echo ""
echo "5️⃣  Checking database..."
DB_CHECK=$(kubectl exec -n vulnscan postgres-0 -- psql -U scanner -d vulnscan -c "\dt" 2>/dev/null | grep vulnerability_scans)
if [ -n "$DB_CHECK" ]; then
  SCAN_COUNT=$(kubectl exec -n vulnscan postgres-0 -- psql -U scanner -d vulnscan -t -c "SELECT COUNT(*) FROM vulnerability_scans;" 2>/dev/null | tr -d ' ')
  echo -e "${GREEN}✅ Database is healthy (${SCAN_COUNT} scans stored)${NC}"
  ((PASS++))
else
  echo -e "${RED}❌ Database tables not found${NC}"
  ((FAIL++))
fi

# Check worker
echo ""
echo "6️⃣  Checking worker..."
WORKER_RUNNING=$(kubectl get pods -n vulnscan -l app=vulnscan-worker --no-headers 2>/dev/null | grep Running)
if [ -n "$WORKER_RUNNING" ]; then
  echo -e "${GREEN}✅ Worker is running${NC}"
  ((PASS++))
else
  echo -e "${RED}❌ Worker is not running${NC}"
  ((FAIL++))
fi

# Check frontend
echo ""
echo "7️⃣  Checking frontend..."
FRONTEND_RUNNING=$(kubectl get pods -n vulnscan -l app=vulnscan-frontend --no-headers 2>/dev/null | grep Running | wc -l)
if [ "$FRONTEND_RUNNING" -gt 0 ]; then
  echo -e "${GREEN}✅ Frontend is running ($FRONTEND_RUNNING replicas)${NC}"
  ((PASS++))
else
  echo -e "${RED}❌ Frontend is not running${NC}"
  ((FAIL++))
fi

# Check ArgoCD
echo ""
echo "8️⃣  Checking ArgoCD installation..."
ARGOCD_RUNNING=$(kubectl get pods -n argocd --no-headers 2>/dev/null | grep argocd-server | grep Running)
if [ -n "$ARGOCD_RUNNING" ]; then
  echo -e "${GREEN}✅ ArgoCD is running${NC}"
  ((PASS++))
else
  echo -e "${YELLOW}⚠️  ArgoCD is not running (run ./deploy-argocd.sh)${NC}"
fi

# Check ArgoCD application
echo ""
echo "9️⃣  Checking ArgoCD application..."
if kubectl get application vulnscan -n argocd &>/dev/null; then
  APP_SYNC=$(kubectl get application vulnscan -n argocd -o jsonpath='{.status.sync.status}' 2>/dev/null)
  APP_HEALTH=$(kubectl get application vulnscan -n argocd -o jsonpath='{.status.health.status}' 2>/dev/null)
  if [ "$APP_SYNC" == "Synced" ] && [ "$APP_HEALTH" == "Healthy" ]; then
    echo -e "${GREEN}✅ ArgoCD application is synced and healthy${NC}"
    ((PASS++))
  else
    echo -e "${YELLOW}⚠️  ArgoCD application status: Sync=$APP_SYNC, Health=$APP_HEALTH${NC}"
  fi
else
  echo -e "${YELLOW}⚠️  ArgoCD application not found (run: kubectl apply -f k8s/argocd-app.yaml)${NC}"
fi

# Check Ingress
echo ""
echo "🔟 Checking Ingress..."
INGRESS_EXISTS=$(kubectl get ingress -n vulnscan 2>/dev/null | grep vulnscan-ingress)
if [ -n "$INGRESS_EXISTS" ]; then
  echo -e "${GREEN}✅ Ingress is configured${NC}"
  ((PASS++))
else
  echo -e "${YELLOW}⚠️  Ingress not found${NC}"
fi

# Summary
echo ""
echo "========================================================"
echo "📊 Verification Summary"
echo "========================================================"
echo -e "${GREEN}✅ Passed: $PASS${NC}"
if [ "$FAIL" -gt 0 ]; then
  echo -e "${RED}❌ Failed: $FAIL${NC}"
fi
echo ""

if [ "$FAIL" -eq 0 ]; then
  echo -e "${GREEN}🎉 All core components are working!${NC}"
  echo ""
  echo "Next steps:"
  echo "  1. Access frontend: kubectl port-forward -n vulnscan svc/vulnscan-frontend 3000:80"
  echo "     Then open: http://localhost:3000"
  echo ""
  echo "  2. Access ArgoCD: http://localhost:30080"
  echo "     Credentials in: argocd-password.txt"
  echo ""
  echo "  3. Test a scan: Enter 'nginx:alpine' in the dashboard"
  echo ""
else
  echo -e "${RED}⚠️  Some components need attention${NC}"
  echo ""
  echo "Troubleshooting:"
  echo "  • View pod details: kubectl describe pod -n vulnscan <pod-name>"
  echo "  • Check logs: kubectl logs -n vulnscan <pod-name>"
  echo "  • Restart deployment: kubectl rollout restart deployment -n vulnscan <deployment-name>"
  echo ""
fi

echo "For detailed verification, see: VERIFICATION_CHECKLIST.md"
echo ""
