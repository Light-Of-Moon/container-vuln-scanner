# ✅ Container Vulnerability Scanner - Verification Checklist

**GitHub Repository**: https://github.com/Light-Of-Moon/container-vuln-scanner

Use this checklist to verify that **all project requirements** are implemented and working.

---

## 📋 Project Requirements Verification

### Requirement 1: ✅ **API for submitting Docker image names**

**Expected**: REST API that accepts Docker image names for scanning

**Tests**:
```bash
# Test API is running
kubectl port-forward -n vulnscan svc/vulnscan-api 8000:80 &
curl http://localhost:8000/health

# Test scan submission
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"image_name":"nginx","image_tag":"alpine"}'

# Test scan listing
curl http://localhost:8000/api/v1/scans
```

**Verification Checklist**:
- [ ] API service is deployed and running
- [ ] Health endpoint returns `{"status":"healthy"}`
- [ ] POST /api/v1/scan accepts image names
- [ ] API returns scan ID (UUID format)
- [ ] GET /api/v1/scans returns list of scans
- [ ] GET /api/v1/scans/{id} returns specific scan details
- [ ] API documentation is accessible at /docs
- [ ] CORS is properly configured for frontend

**Status**: ⬜ Not Tested | ✅ Pass | ❌ Fail

---

### Requirement 2: ✅ **Worker responsible for scanning images**

**Expected**: Background worker that pulls images and scans them using Trivy

**Tests**:
```bash
# Check worker is running
kubectl get pods -n vulnscan -l app=vulnscan-worker

# Submit a scan
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"image_name":"alpine","image_tag":"3.18"}'

# Watch worker logs
kubectl logs -n vulnscan -l app=vulnscan-worker -f

# Wait 60 seconds, then check scan status
sleep 60
curl http://localhost:8000/api/v1/scans | grep alpine
```

**Verification Checklist**:
- [ ] Worker pod is deployed and running
- [ ] Worker polls for pending scans every 5 seconds
- [ ] Worker successfully pulls Docker images
- [ ] Trivy is installed and functional in worker container
- [ ] Worker scans images and detects vulnerabilities
- [ ] Scan progresses through states: PENDING → PULLING → SCANNING → COMPLETED
- [ ] Worker handles errors gracefully (failed scans marked as FAILED)
- [ ] Worker updates scan status in database
- [ ] Worker stores vulnerability details
- [ ] Worker calculates risk scores correctly

**Status**: ⬜ Not Tested | ✅ Pass | ❌ Fail

---

### Requirement 3: ✅ **Database storing scan results**

**Expected**: PostgreSQL database with schema for storing scan results and vulnerability data

**Tests**:
```bash
# Check PostgreSQL is running
kubectl get statefulset -n vulnscan postgres

# Connect to database
kubectl exec -n vulnscan postgres-0 -- psql -U scanner -d vulnscan -c "\dt"

# Check tables exist
kubectl exec -n vulnscan postgres-0 -- psql -U scanner -d vulnscan -c "
  SELECT table_name FROM information_schema.tables 
  WHERE table_schema='public' 
  ORDER BY table_name;
"

# Check scan data
kubectl exec -n vulnscan postgres-0 -- psql -U scanner -d vulnscan -c "
  SELECT id, image_name, image_tag, status, total_vulnerabilities 
  FROM vulnerability_scans 
  LIMIT 5;
"

# Check vulnerability details
kubectl exec -n vulnscan postgres-0 -- psql -U scanner -d vulnscan -c "
  SELECT COUNT(*) FROM vulnerability_details;
"
```

**Verification Checklist**:
- [ ] PostgreSQL StatefulSet is deployed
- [ ] PostgreSQL pod is running and healthy
- [ ] Database `vulnscan` exists
- [ ] Table `vulnerability_scans` exists
- [ ] Table `vulnerability_details` exists
- [ ] Table `scan_audit_log` exists
- [ ] Database migrations have been applied
- [ ] Scan records are stored correctly
- [ ] Vulnerability details are normalized and stored
- [ ] Indexes are created for performance
- [ ] Foreign key relationships are intact
- [ ] PersistentVolume is attached (data persists across restarts)

**Status**: ⬜ Not Tested | ✅ Pass | ❌ Fail

---

### Requirement 4: ✅ **Dashboard showing vulnerabilities**

**Expected**: Web-based UI displaying scan results, statistics, and vulnerability details

**Tests**:
```bash
# Port-forward to frontend
kubectl port-forward -n vulnscan svc/vulnscan-frontend 3000:80 &

# Check frontend is serving
curl -s http://localhost:3000 | grep "Container Vulnerability Scanner"
```

**Manual Browser Tests** (http://localhost:3000):

**Verification Checklist**:
- [ ] Frontend service is deployed and running
- [ ] Dashboard loads in browser without errors
- [ ] **Statistics Dashboard** displays:
  - [ ] Total scans count
  - [ ] Active/Completed/Failed scans
  - [ ] Critical/High/Medium/Low vulnerability counts
  - [ ] Compliance statistics
  - [ ] Risk score metrics
- [ ] **Scan Table** shows:
  - [ ] List of all scans
  - [ ] Image name and tag
  - [ ] Status (with color coding)
  - [ ] Vulnerability breakdown
  - [ ] Risk score
  - [ ] Compliance status
  - [ ] Created/Completed timestamps
- [ ] **Scan Image Form** works:
  - [ ] Can enter image name
  - [ ] Can enter image tag
  - [ ] "Scan Image" button submits request
  - [ ] Toast notification shows success
  - [ ] New scan appears in table immediately
- [ ] **View Details Modal** works:
  - [ ] Clicking "View Details" opens modal
  - [ ] Shows comprehensive vulnerability information
  - [ ] Lists CVE IDs with links to NVD
  - [ ] Shows severity levels (color-coded)
  - [ ] Displays affected packages
  - [ ] Shows fixed versions (if available)
  - [ ] Displays CVSS scores
  - [ ] Can filter by severity
- [ ] **Real-time Updates**:
  - [ ] Status updates automatically (polling every 5s)
  - [ ] Statistics refresh in real-time
  - [ ] Active scans show progress
- [ ] **Delete Function**:
  - [ ] Delete button works
  - [ ] Scan is removed from table
  - [ ] Statistics update after deletion
- [ ] **Upload Feature** (if implemented):
  - [ ] Upload button is visible
  - [ ] Can select .tar files
  - [ ] Upload progress is shown
  - [ ] Uploaded images are scanned
- [ ] **UI/UX**:
  - [ ] Responsive design (works on different screen sizes)
  - [ ] Animations are smooth
  - [ ] Loading indicators show during operations
  - [ ] Error messages are user-friendly
  - [ ] Connection status indicator works

**Status**: ⬜ Not Tested | ✅ Pass | ❌ Fail

---

### Requirement 5: ✅ **ArgoCD to keep scanner definitions and application updates deployed using GitOps**

**Expected**: ArgoCD managing deployments from Git repository with automatic sync

**Tests**:
```bash
# Check ArgoCD is installed
kubectl get pods -n argocd

# Check ArgoCD application
kubectl get applications -n argocd

# Get application status via CLI
argocd login localhost:30080 --insecure --username admin --password $(cat argocd-password.txt)
argocd app get vulnscan
```

**Manual ArgoCD UI Tests** (http://localhost:30080):

**Verification Checklist**:
- [ ] **ArgoCD Installation**:
  - [ ] ArgoCD is deployed in `argocd` namespace
  - [ ] All ArgoCD pods are running (server, repo-server, controller, dex, redis)
  - [ ] ArgoCD UI is accessible at http://localhost:30080
  - [ ] Can login with admin credentials
- [ ] **ArgoCD Application**:
  - [ ] Application `vulnscan` exists in ArgoCD
  - [ ] Application is connected to GitHub repository
  - [ ] Repository URL: https://github.com/Light-Of-Moon/container-vuln-scanner.git
  - [ ] Path is set to: `cloud - vuln/k8s`
  - [ ] Target namespace is: `vulnscan`
- [ ] **Sync Status**:
  - [ ] Application status is "Synced"
  - [ ] Application health is "Healthy"
  - [ ] All resources are green in UI
- [ ] **Auto-Sync**:
  - [ ] Auto-sync policy is enabled
  - [ ] Prune resources option is enabled
  - [ ] Self-heal option is enabled
- [ ] **Resource Management**:
  - [ ] ArgoCD shows all Kubernetes resources:
    - [ ] Namespace
    - [ ] 3 Deployments (API, Worker, Frontend)
    - [ ] 1 StatefulSet (PostgreSQL)
    - [ ] 4 Services
    - [ ] ConfigMaps
    - [ ] Secrets
    - [ ] Ingress
    - [ ] NetworkPolicy
- [ ] **GitOps Workflow**:
  - [ ] Can manually sync from UI
  - [ ] Can view sync history
  - [ ] Can rollback to previous versions
  - [ ] Sync logs are available
- [ ] **Auto-Deployment Test**:
  - [ ] Make a change in Git (e.g., update ConfigMap)
  - [ ] Push to GitHub
  - [ ] ArgoCD detects change within 3 minutes
  - [ ] ArgoCD auto-syncs the change
  - [ ] Resources are updated in cluster
  - [ ] No manual intervention required

**Status**: ⬜ Not Tested | ✅ Pass | ❌ Fail

---

## 🐳 Additional Requirement Verifications

### Docker Containerization

**Verification Checklist**:
- [ ] Dockerfile.backend exists and builds successfully
- [ ] Dockerfile.frontend exists and builds successfully
- [ ] Backend image includes Trivy
- [ ] Frontend image uses Nginx for serving
- [ ] docker-compose.yml works for local development
- [ ] All images are loaded into KinD cluster

**Status**: ⬜ Not Tested | ✅ Pass | ❌ Fail

---

### Kubernetes Deployment

**Verification Checklist**:
- [ ] KinD cluster is created successfully
- [ ] All Kubernetes manifests are valid YAML
- [ ] Namespace `vulnscan` is created
- [ ] NetworkPolicy is applied
- [ ] ResourceQuota is applied
- [ ] LimitRange is applied
- [ ] All deployments are healthy
- [ ] All services are accessible
- [ ] Ingress routing works
- [ ] PersistentVolumes are bound

**Status**: ⬜ Not Tested | ✅ Pass | ❌ Fail

---

### Trivy CLI Integration

**Verification Checklist**:
- [ ] Trivy is installed in worker container
- [ ] Trivy version is displayed correctly
- [ ] Trivy can download vulnerability database
- [ ] Trivy can scan Docker images
- [ ] Trivy produces JSON output
- [ ] JSON output is parsed correctly by worker
- [ ] Vulnerabilities are extracted accurately
- [ ] CVE IDs are captured
- [ ] Severity levels are identified correctly

**Status**: ⬜ Not Tested | ✅ Pass | ❌ Fail

---

## 🧪 End-to-End Integration Tests

### Test Scenario 1: Complete Scan Workflow

**Steps**:
1. Access frontend: http://localhost:3000
2. Enter image: `nginx:alpine`
3. Click "Scan Image"
4. Wait for completion

**Verification**:
- [ ] Scan is created (status: PENDING)
- [ ] Worker picks up scan
- [ ] Status changes to PULLING
- [ ] Docker image is pulled
- [ ] Status changes to SCANNING
- [ ] Trivy scans the image
- [ ] Status changes to COMPLETED
- [ ] Vulnerabilities are displayed
- [ ] Risk score is calculated
- [ ] Compliance status is determined
- [ ] Total time < 2 minutes

**Status**: ⬜ Not Tested | ✅ Pass | ❌ Fail

---

### Test Scenario 2: Multiple Image Scans

**Steps**:
1. Scan these images:
   - `alpine:latest`
   - `ubuntu:22.04`
   - `python:3.11-slim`
   - `node:18-alpine`

**Verification**:
- [ ] All 4 scans are created
- [ ] Each scan has unique ID
- [ ] All scans complete successfully
- [ ] Different vulnerability counts for each
- [ ] Dashboard statistics update correctly
- [ ] Risk scores vary appropriately

**Status**: ⬜ Not Tested | ✅ Pass | ❌ Fail

---

### Test Scenario 3: View Vulnerability Details

**Steps**:
1. Wait for a scan to complete
2. Click "View Details" button
3. Inspect the modal content

**Verification**:
- [ ] Modal opens correctly
- [ ] CVE IDs are listed (e.g., CVE-2023-XXXXX)
- [ ] Severity badges are color-coded
- [ ] Package names are shown
- [ ] Package versions are shown
- [ ] Fixed versions are shown (if available)
- [ ] CVSS scores are displayed
- [ ] Description is present
- [ ] Can filter by severity
- [ ] CVE links to NVD database

**Status**: ⬜ Not Tested | ✅ Pass | ❌ Fail

---

### Test Scenario 4: Delete Scan

**Steps**:
1. Click delete button on a scan
2. Confirm deletion

**Verification**:
- [ ] Confirmation prompt appears
- [ ] Scan is removed from UI
- [ ] Scan is deleted from database
- [ ] Statistics are updated
- [ ] No errors in console

**Status**: ⬜ Not Tested | ✅ Pass | ❌ Fail

---

### Test Scenario 5: GitOps Deployment Update

**Steps**:
1. Open `k8s/api.yaml` in GitHub
2. Edit the file (e.g., change replicas from 2 to 3)
3. Commit and push to GitHub
4. Wait 3 minutes

**Verification**:
- [ ] ArgoCD detects the change
- [ ] Application status shows "OutOfSync"
- [ ] Auto-sync is triggered
- [ ] Resources are updated in cluster
- [ ] New API pod is created
- [ ] Application returns to "Synced" status
- [ ] All 3 API pods are running

**Status**: ⬜ Not Tested | ✅ Pass | ❌ Fail

---

### Test Scenario 6: Restart/Recovery Test

**Steps**:
1. Delete all pods: `kubectl delete pods -n vulnscan --all`
2. Wait for pods to restart
3. Test functionality

**Verification**:
- [ ] All pods restart automatically
- [ ] Data persists (PostgreSQL data intact)
- [ ] API is accessible again
- [ ] Worker resumes processing
- [ ] Frontend loads correctly
- [ ] Previous scans are still visible
- [ ] Can submit new scans

**Status**: ⬜ Not Tested | ✅ Pass | ❌ Fail

---

## 📊 Final Verification Summary

### Core Requirements Status

| Requirement | Status | Notes |
|-------------|--------|-------|
| API Service | ⬜ | Submit Docker image names |
| Worker Service | ⬜ | Scan images with Trivy |
| Database | ⬜ | Store scan results |
| Dashboard | ⬜ | Visualize vulnerabilities |
| ArgoCD | ⬜ | GitOps deployment |
| Docker | ⬜ | Containerize all services |
| KinD | ⬜ | Local K8s cluster |
| Kubernetes | ⬜ | Deploy services |

**Legend**: ⬜ Not Tested | ✅ Pass | ❌ Fail

---

### Quick Verification Script

Run this to quickly check all major components:

```bash
#!/bin/bash

echo "🔍 Container Vulnerability Scanner - Quick Verification"
echo "========================================================"
echo ""

# Check cluster
echo "1️⃣ Checking Kubernetes cluster..."
kubectl cluster-info --context kind-vulnscan > /dev/null 2>&1 && echo "✅ Cluster is running" || echo "❌ Cluster not found"

# Check pods
echo ""
echo "2️⃣ Checking pods..."
ALL_RUNNING=$(kubectl get pods -n vulnscan --no-headers | awk '{print $3}' | grep -v "Running" | wc -l)
if [ "$ALL_RUNNING" -eq 0 ]; then
  echo "✅ All pods are running"
else
  echo "❌ Some pods are not running"
  kubectl get pods -n vulnscan
fi

# Check API
echo ""
echo "3️⃣ Checking API health..."
kubectl port-forward -n vulnscan svc/vulnscan-api 8000:80 &>/dev/null &
PF_PID=$!
sleep 2
HEALTH=$(curl -s http://localhost:8000/health | grep "healthy")
kill $PF_PID 2>/dev/null
if [ -n "$HEALTH" ]; then
  echo "✅ API is healthy"
else
  echo "❌ API health check failed"
fi

# Check database
echo ""
echo "4️⃣ Checking database..."
DB_CHECK=$(kubectl exec -n vulnscan postgres-0 -- psql -U scanner -d vulnscan -c "\dt" 2>/dev/null | grep vulnerability_scans)
if [ -n "$DB_CHECK" ]; then
  echo "✅ Database tables exist"
else
  echo "❌ Database tables not found"
fi

# Check ArgoCD
echo ""
echo "5️⃣ Checking ArgoCD..."
ARGOCD_RUNNING=$(kubectl get pods -n argocd --no-headers | grep argocd-server | grep Running)
if [ -n "$ARGOCD_RUNNING" ]; then
  echo "✅ ArgoCD is running"
else
  echo "❌ ArgoCD is not running"
fi

# Check ArgoCD application
echo ""
echo "6️⃣ Checking ArgoCD application..."
APP_STATUS=$(kubectl get application vulnscan -n argocd -o jsonpath='{.status.sync.status}' 2>/dev/null)
if [ "$APP_STATUS" == "Synced" ]; then
  echo "✅ ArgoCD application is synced"
else
  echo "⚠️ ArgoCD application status: $APP_STATUS"
fi

# Check worker
echo ""
echo "7️⃣ Checking worker..."
WORKER_RUNNING=$(kubectl get pods -n vulnscan -l app=vulnscan-worker --no-headers | grep Running)
if [ -n "$WORKER_RUNNING" ]; then
  echo "✅ Worker is running"
else
  echo "❌ Worker is not running"
fi

echo ""
echo "========================================================"
echo "✅ Quick verification complete!"
echo ""
echo "For detailed verification, see ARGOCD_DEPLOYMENT_GUIDE.md"
```

Save this as `quick-verify.sh` and run:
```bash
chmod +x quick-verify.sh
./quick-verify.sh
```

---

## 🎯 Success Criteria

**Project is considered FULLY FUNCTIONAL if**:

✅ **All 5 Core Requirements Pass**
- API service working
- Worker scanning images
- Database storing results
- Dashboard displaying vulnerabilities
- ArgoCD managing deployments

✅ **All End-to-End Tests Pass**
- Complete scan workflow works
- Multiple scans succeed
- View details modal works
- Delete function works
- GitOps auto-sync works

✅ **No Critical Issues**
- No pods in CrashLoopBackOff
- No persistent errors in logs
- All health checks passing
- Data persistence working

---

## 📅 Testing Timeline

1. **Infrastructure Setup** (15 min)
   - Install tools
   - Create cluster
   - Deploy services

2. **Component Testing** (30 min)
   - Test API, Worker, Database, Frontend individually

3. **Integration Testing** (30 min)
   - End-to-end scan workflows

4. **GitOps Testing** (15 min)
   - ArgoCD deployment and auto-sync

**Total Estimated Time**: ~90 minutes

---

## 📞 Need Help?

- **Full Guide**: [ARGOCD_DEPLOYMENT_GUIDE.md](ARGOCD_DEPLOYMENT_GUIDE.md)
- **Project Analysis**: [PROJECT_ANALYSIS_REPORT.md](PROJECT_ANALYSIS_REPORT.md)
- **Quick Start**: [QUICK_START.md](QUICK_START.md)
- **GitHub**: https://github.com/Light-Of-Moon/container-vuln-scanner

---

**Last Updated**: December 21, 2025  
**Version**: 1.0
