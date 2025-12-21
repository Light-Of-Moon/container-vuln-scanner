# 🚀 ArgoCD Deployment & Verification Guide

**GitHub Repository**: https://github.com/Light-Of-Moon/container-vuln-scanner

---

## 📋 Prerequisites

Ensure all tools are installed:
```bash
docker --version
kubectl version --client
kind version
argocd version --client
```

If not installed, run:
```bash
sudo ./install-tools.sh
# Log out and back in after installation
```

---

## 🎯 Step-by-Step Deployment

### Step 1: Deploy Kubernetes Cluster
```bash
cd "/home/ahmed/container-vuln-scanner/cloud - vuln"
./start-k8s.sh
```

**Expected Output**:
- ✅ KinD cluster created
- ✅ Docker images built and loaded
- ✅ PostgreSQL deployed
- ✅ API, Worker, Frontend deployed
- ✅ Services are healthy

**Verification**:
```bash
kubectl get pods -n vulnscan
# All pods should be Running
```

---

### Step 2: Deploy ArgoCD
```bash
./deploy-argocd.sh
```

**Expected Output**:
- ✅ ArgoCD installed (v2.9.3)
- ✅ ArgoCD server accessible on port 30080
- ✅ Admin password displayed and saved to `argocd-password.txt`

**Verification**:
```bash
# Check ArgoCD pods
kubectl get pods -n argocd

# Should see:
# - argocd-server (Running)
# - argocd-repo-server (Running)
# - argocd-application-controller (Running)
# - argocd-dex-server (Running)
# - argocd-redis (Running)
```

---

### Step 3: Access ArgoCD UI

**URL**: http://localhost:30080

**Credentials**:
- **Username**: `admin`
- **Password**: Check `argocd-password.txt` or run:
  ```bash
  cat argocd-password.txt
  ```

**Browser Steps**:
1. Open http://localhost:30080
2. Click "Login"
3. Enter username: `admin`
4. Enter password from file
5. ✅ You should see the ArgoCD dashboard

---

### Step 4: Connect ArgoCD to GitHub Repository

#### Option A: Via ArgoCD UI (Easiest)

1. **Login to ArgoCD**: http://localhost:30080

2. **Click "NEW APP" button** (top left)

3. **Fill in Application Details**:
   - **Application Name**: `vulnscan`
   - **Project**: `default`
   - **Sync Policy**: `Automatic`
   - ✅ Check "PRUNE RESOURCES"
   - ✅ Check "SELF HEAL"

4. **Fill in Source**:
   - **Repository URL**: `https://github.com/Light-Of-Moon/container-vuln-scanner.git`
   - **Revision**: `HEAD` (or `main`/`master`)
   - **Path**: `cloud - vuln/k8s`

5. **Fill in Destination**:
   - **Cluster URL**: `https://kubernetes.default.svc`
   - **Namespace**: `vulnscan`

6. **Click "CREATE"** at the top

7. **Wait for Sync**: ArgoCD will automatically sync and deploy

#### Option B: Via kubectl (Alternative)

```bash
# Apply the ArgoCD Application manifest
kubectl apply -f k8s/argocd-app.yaml
```

**Verification**:
```bash
# Check ArgoCD application status
kubectl get applications -n argocd

# Should show "vulnscan" with "Synced" and "Healthy"
```

---

### Step 5: Verify ArgoCD Deployment

**Via ArgoCD UI**:
1. Go to http://localhost:30080
2. Click on "vulnscan" application
3. You should see:
   - ✅ **Status**: Healthy
   - ✅ **Sync Status**: Synced
   - ✅ All resources (Deployments, Services, etc.) displayed as green

**Via ArgoCD CLI**:
```bash
# Login to ArgoCD CLI
argocd login localhost:30080 --insecure --username admin --password $(cat argocd-password.txt)

# Get application status
argocd app get vulnscan

# Should show:
# - Health Status: Healthy
# - Sync Status: Synced
```

**Via kubectl**:
```bash
# Check all resources in vulnscan namespace
kubectl get all -n vulnscan

# Should show:
# - 3 deployments (api, worker, frontend)
# - 1 statefulset (postgres)
# - 4 services
# - Multiple pods (all Running)
```

---

## ✅ Comprehensive Verification Checklist

### 🔧 **1. Infrastructure Verification**

#### 1.1 Kubernetes Cluster
```bash
# Check cluster info
kubectl cluster-info --context kind-vulnscan
```
- [ ] Cluster is running
- [ ] kubectl can connect

#### 1.2 Namespaces
```bash
kubectl get namespaces
```
- [ ] `vulnscan` namespace exists
- [ ] `argocd` namespace exists
- [ ] `ingress-nginx` namespace exists

#### 1.3 Pods Status
```bash
kubectl get pods -n vulnscan
kubectl get pods -n argocd
kubectl get pods -n ingress-nginx
```
- [ ] All pods in `vulnscan` are Running
- [ ] All pods in `argocd` are Running
- [ ] Ingress controller pod is Running

---

### 🗄️ **2. Database Verification**

#### 2.1 PostgreSQL Status
```bash
kubectl get statefulset -n vulnscan
kubectl get pods -n vulnscan -l app=postgres
```
- [ ] PostgreSQL StatefulSet exists
- [ ] PostgreSQL pod is Running
- [ ] PersistentVolumeClaim is Bound

#### 2.2 Database Connectivity
```bash
kubectl exec -n vulnscan postgres-0 -- psql -U scanner -d vulnscan -c "SELECT version();"
```
- [ ] PostgreSQL version displayed (15.x)

#### 2.3 Schema Verification
```bash
kubectl exec -n vulnscan postgres-0 -- psql -U scanner -d vulnscan -c "\dt"
```
- [ ] `vulnerability_scans` table exists
- [ ] `vulnerability_details` table exists
- [ ] `scan_audit_log` table exists

#### 2.4 Database Data
```bash
kubectl exec -n vulnscan postgres-0 -- psql -U scanner -d vulnscan -c "SELECT COUNT(*) FROM vulnerability_scans;"
```
- [ ] Query executes successfully (count may be 0 initially)

---

### 🌐 **3. API Service Verification**

#### 3.1 API Deployment
```bash
kubectl get deployment -n vulnscan vulnscan-api
kubectl get pods -n vulnscan -l app=vulnscan-api
```
- [ ] Deployment exists with 2 replicas
- [ ] Both API pods are Running
- [ ] Pods are Ready (2/2)

#### 3.2 API Service
```bash
kubectl get service -n vulnscan vulnscan-api
```
- [ ] Service exists (ClusterIP)
- [ ] Port 80 mapped to 8000

#### 3.3 API Health Check
```bash
kubectl port-forward -n vulnscan svc/vulnscan-api 8000:80 &
sleep 2
curl http://localhost:8000/health
```
- [ ] Returns: `{"status":"healthy","timestamp":"..."}`
- [ ] HTTP 200 status code

#### 3.4 API Documentation
```bash
curl -s http://localhost:8000/docs | grep "Swagger"
```
- [ ] Swagger UI is accessible
- [ ] API documentation loads

#### 3.5 API Endpoints
Test each endpoint:
```bash
# List scans
curl http://localhost:8000/api/v1/scans

# Get stats
curl http://localhost:8000/api/v1/stats

# Create scan
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"image_name":"alpine","image_tag":"latest"}'
```
- [ ] GET /api/v1/scans returns JSON list
- [ ] GET /api/v1/stats returns statistics
- [ ] POST /api/v1/scan creates a scan (HTTP 202)

---

### ⚙️ **4. Worker Service Verification**

#### 4.1 Worker Deployment
```bash
kubectl get deployment -n vulnscan vulnscan-worker
kubectl get pods -n vulnscan -l app=vulnscan-worker
```
- [ ] Deployment exists with 1 replica
- [ ] Worker pod is Running

#### 4.2 Worker Logs
```bash
kubectl logs -n vulnscan -l app=vulnscan-worker --tail=50
```
- [ ] Worker is polling for pending scans
- [ ] No critical errors in logs
- [ ] Trivy is available

#### 4.3 Trivy Integration
```bash
kubectl exec -n vulnscan -l app=vulnscan-worker -- trivy --version
```
- [ ] Trivy version displayed
- [ ] Trivy is executable

#### 4.4 Scan Processing
```bash
# Create a test scan
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"image_name":"alpine","image_tag":"3.18"}'

# Wait 30 seconds, then check worker logs
sleep 30
kubectl logs -n vulnscan -l app=vulnscan-worker --tail=100 | grep "alpine"
```
- [ ] Worker picks up the scan
- [ ] Scan progresses through states: PENDING → PULLING → SCANNING → COMPLETED
- [ ] Results are saved to database

---

### 🎨 **5. Frontend Verification**

#### 5.1 Frontend Deployment
```bash
kubectl get deployment -n vulnscan vulnscan-frontend
kubectl get pods -n vulnscan -l app=vulnscan-frontend
```
- [ ] Deployment exists with 2 replicas
- [ ] Both frontend pods are Running

#### 5.2 Frontend Service
```bash
kubectl get service -n vulnscan vulnscan-frontend
```
- [ ] Service exists (ClusterIP)
- [ ] Port 80 is exposed

#### 5.3 Frontend Accessibility
```bash
kubectl port-forward -n vulnscan svc/vulnscan-frontend 3000:80 &
sleep 2
curl -s http://localhost:3000 | grep "Container Vulnerability Scanner"
```
- [ ] Frontend HTML loads
- [ ] Title contains "Container Vulnerability Scanner"

#### 5.4 Frontend UI Test (Manual)
Open http://localhost:3000 in browser:
- [ ] Dashboard loads successfully
- [ ] Statistics cards are visible
- [ ] Scan table is displayed
- [ ] "Scan Image" button is present
- [ ] No JavaScript errors in browser console

#### 5.5 Frontend-API Integration
In browser at http://localhost:3000:
1. Enter image name: `nginx`
2. Click "Scan Image"
- [ ] Scan is submitted successfully
- [ ] Toast notification appears
- [ ] Scan appears in the table
- [ ] Status updates in real-time

---

### 🔀 **6. Ingress Verification**

#### 6.1 Ingress Resource
```bash
kubectl get ingress -n vulnscan
```
- [ ] Ingress resource exists
- [ ] Hosts are configured: `vulnscan.example.com`, `api.vulnscan.example.com`
- [ ] Address is assigned

#### 6.2 Ingress Controller
```bash
kubectl get pods -n ingress-nginx
```
- [ ] Ingress controller pod is Running

#### 6.3 Ingress Routing (if /etc/hosts configured)
```bash
# Only if /etc/hosts has entries
curl -s http://vulnscan.example.com:8080 | grep "Container"
curl http://api.vulnscan.example.com:8080/health
```
- [ ] Frontend is accessible via Ingress (if hosts configured)
- [ ] API is accessible via Ingress (if hosts configured)

---

### 🔄 **7. ArgoCD GitOps Verification**

#### 7.1 ArgoCD Installation
```bash
kubectl get pods -n argocd
```
- [ ] All ArgoCD pods are Running:
  - argocd-server
  - argocd-repo-server
  - argocd-application-controller
  - argocd-dex-server
  - argocd-redis

#### 7.2 ArgoCD UI Access
Open http://localhost:30080:
- [ ] ArgoCD login page loads
- [ ] Can login with admin credentials
- [ ] Dashboard is accessible

#### 7.3 ArgoCD Application
```bash
kubectl get applications -n argocd
# OR via ArgoCD CLI
argocd app list
```
- [ ] `vulnscan` application exists
- [ ] Sync Status: Synced
- [ ] Health Status: Healthy

#### 7.4 ArgoCD Application Details
In ArgoCD UI, click on `vulnscan` application:
- [ ] All resources are displayed (green)
- [ ] Resource tree shows:
  - Namespace
  - Deployments (3)
  - StatefulSet (1)
  - Services (4)
  - ConfigMaps
  - Secrets
  - Ingress
- [ ] No sync errors

#### 7.5 ArgoCD Sync Test
```bash
# Make a change to a configmap (e.g., in k8s/api.yaml)
# ArgoCD should auto-sync within 3 minutes
```
- [ ] ArgoCD detects Git changes
- [ ] Auto-sync is triggered
- [ ] Resources are updated

---

### 🧪 **8. End-to-End Functional Testing**

#### 8.1 Complete Scan Workflow
```bash
# Access frontend
kubectl port-forward -n vulnscan svc/vulnscan-frontend 3000:80 &
```

**Manual Test**:
1. Open http://localhost:3000
2. Enter image: `nginx:alpine`
3. Click "Scan Image"
4. Wait for completion (~1-2 minutes)

**Verify**:
- [ ] Scan is created (appears in table)
- [ ] Status changes: Pending → Pulling → Scanning → Completed
- [ ] Vulnerability counts are displayed
- [ ] Risk score is calculated
- [ ] Compliance status is shown (Compliant/Non-Compliant)

#### 8.2 View Scan Details
1. Click "View Details" on a completed scan

**Verify**:
- [ ] Modal opens with vulnerability details
- [ ] CVE IDs are listed
- [ ] Severity levels are shown (color-coded)
- [ ] Package names and versions are displayed
- [ ] Fixed versions are shown (if available)
- [ ] CVSS scores are displayed

#### 8.3 Multiple Scans
1. Scan the same image 3 times

**Verify**:
- [ ] Each scan creates a new entry (no deduplication)
- [ ] All scans are visible in the table
- [ ] Each has a unique ID
- [ ] Statistics are updated correctly

#### 8.4 Different Images
Scan these images:
- `alpine:latest`
- `nginx:latest`
- `ubuntu:22.04`
- `python:3.11-slim`

**Verify**:
- [ ] All scans complete successfully
- [ ] Different vulnerability counts for each
- [ ] Risk scores vary based on vulnerabilities
- [ ] Dashboard statistics update

#### 8.5 Delete Scan
1. Click delete button on a scan
2. Confirm deletion

**Verify**:
- [ ] Scan is removed from table
- [ ] Statistics are updated
- [ ] Database entry is deleted

#### 8.6 Upload Feature (if available)
1. Save a Docker image: `docker save alpine:latest -o alpine.tar`
2. Click upload icon in UI
3. Upload the tarball

**Verify**:
- [ ] File uploads successfully
- [ ] Scan is created
- [ ] Image is scanned
- [ ] Results are displayed

---

### 📊 **9. Performance & Scalability Verification**

#### 9.1 Resource Usage
```bash
kubectl top pods -n vulnscan
```
- [ ] API pods using < 512Mi memory
- [ ] Worker pod using < 1Gi memory
- [ ] Frontend pods using < 256Mi memory
- [ ] PostgreSQL using reasonable memory

#### 9.2 API Scaling
```bash
kubectl scale deployment vulnscan-api -n vulnscan --replicas=3
kubectl get pods -n vulnscan -l app=vulnscan-api
```
- [ ] New pod is created
- [ ] All 3 pods become Ready
- [ ] Load is distributed (check logs)

#### 9.3 Concurrent Scans
Submit 5 scans simultaneously:
```bash
for i in {1..5}; do
  curl -X POST http://localhost:8000/api/v1/scan \
    -H "Content-Type: application/json" \
    -d "{\"image_name\":\"alpine\",\"image_tag\":\"3.1$i\"}" &
done
wait
```
- [ ] All scans are queued
- [ ] Worker processes them sequentially
- [ ] All complete successfully

---

### 🔒 **10. Security Verification**

#### 10.1 Network Policies
```bash
kubectl get networkpolicy -n vulnscan
```
- [ ] NetworkPolicy exists
- [ ] Ingress rules defined
- [ ] Egress rules defined

#### 10.2 Pod Security
```bash
kubectl get pods -n vulnscan -o jsonpath='{.items[*].spec.securityContext}'
```
- [ ] API pods run as non-root (uid 1000)
- [ ] Frontend pods have security context
- [ ] Appropriate capabilities dropped

#### 10.3 Secrets Management
```bash
kubectl get secrets -n vulnscan
```
- [ ] Database secrets exist
- [ ] API secrets exist
- [ ] Worker secrets exist
- [ ] Secrets are not exposed in logs

---

### 📈 **11. Monitoring & Observability**

#### 11.1 Logs Accessibility
```bash
# API logs
kubectl logs -n vulnscan -l app=vulnscan-api --tail=20

# Worker logs
kubectl logs -n vulnscan -l app=vulnscan-worker --tail=20

# Frontend logs
kubectl logs -n vulnscan -l app=vulnscan-frontend --tail=20
```
- [ ] Logs are accessible for all services
- [ ] Logs show structured format
- [ ] No critical errors

#### 11.2 Health Endpoints
```bash
# API health
kubectl exec -n vulnscan -l app=vulnscan-api -- wget -q -O- localhost:8000/health

# Check liveness probes
kubectl describe pod -n vulnscan -l app=vulnscan-api | grep Liveness
```
- [ ] Health endpoints respond
- [ ] Liveness probes configured and passing
- [ ] Readiness probes configured and passing

---

### 🔄 **12. GitOps Workflow Verification**

#### 12.1 Manual Sync
In ArgoCD UI:
1. Click "Sync" button
2. Select "Synchronize"

**Verify**:
- [ ] Sync completes successfully
- [ ] All resources are updated
- [ ] No errors in sync result

#### 12.2 Auto-Sync Test
1. Make a change in Git (e.g., update API replicas in `k8s/api.yaml`)
2. Push to GitHub
3. Wait 3 minutes

**Verify**:
- [ ] ArgoCD detects the change
- [ ] Auto-sync is triggered
- [ ] Resources are updated in cluster
- [ ] Change is reflected in cluster

#### 12.3 Rollback Test
In ArgoCD UI:
1. Go to application history
2. Click "Rollback" on a previous version

**Verify**:
- [ ] Rollback completes successfully
- [ ] Resources are restored to previous state

---

## 🎯 **Final Verification Summary**

### **All Systems Check** ✅

Run this comprehensive check:
```bash
#!/bin/bash
echo "=== Cluster Health ==="
kubectl get nodes
echo ""

echo "=== Namespace Status ==="
kubectl get pods -n vulnscan
echo ""

echo "=== Services ==="
kubectl get svc -n vulnscan
echo ""

echo "=== ArgoCD Status ==="
kubectl get applications -n argocd
echo ""

echo "=== API Health ==="
kubectl port-forward -n vulnscan svc/vulnscan-api 8000:80 &>/dev/null &
sleep 2
curl -s http://localhost:8000/health
echo ""

echo "=== Database Connection ==="
kubectl exec -n vulnscan postgres-0 -- psql -U scanner -d vulnscan -c "SELECT COUNT(*) FROM vulnerability_scans;"
echo ""

echo "=== Worker Status ==="
kubectl logs -n vulnscan -l app=vulnscan-worker --tail=5
echo ""

echo "✅ All checks complete!"
```

### **Success Criteria**

Your deployment is **fully successful** if:

- ✅ All pods are Running
- ✅ All services are accessible
- ✅ API health check returns "healthy"
- ✅ Database is accessible and tables exist
- ✅ Worker is processing scans
- ✅ Frontend loads in browser
- ✅ ArgoCD shows application as "Healthy" and "Synced"
- ✅ End-to-end scan workflow works
- ✅ GitOps auto-sync is functional

---

## 🆘 Troubleshooting

### Issue: ArgoCD can't connect to GitHub
**Solution**:
```bash
# Check if repo is public
# If private, add SSH key or credentials in ArgoCD UI
# Settings → Repositories → Connect Repo
```

### Issue: Pods in CrashLoopBackOff
**Solution**:
```bash
kubectl describe pod -n vulnscan <pod-name>
kubectl logs -n vulnscan <pod-name> --previous
```

### Issue: Database migration not applied
**Solution**:
```bash
kubectl cp migrations/001_initial_schema.sql vulnscan/postgres-0:/tmp/
kubectl exec -n vulnscan postgres-0 -- psql -U scanner -d vulnscan -f /tmp/001_initial_schema.sql
```

### Issue: Worker not scanning
**Solution**:
```bash
# Check worker logs
kubectl logs -n vulnscan -l app=vulnscan-worker -f

# Verify Trivy is available
kubectl exec -n vulnscan -l app=vulnscan-worker -- trivy --version

# Check pending scans
kubectl exec -n vulnscan postgres-0 -- psql -U scanner -d vulnscan -c "SELECT id, status FROM vulnerability_scans WHERE status='pending';"
```

---

## 📞 Support

- **Documentation**: [PROJECT_ANALYSIS_REPORT.md](PROJECT_ANALYSIS_REPORT.md)
- **Quick Start**: [QUICK_START.md](QUICK_START.md)
- **GitHub**: https://github.com/Light-Of-Moon/container-vuln-scanner

---

**🎉 Congratulations! Your Container Vulnerability Scanner is fully deployed with GitOps! 🚀**
