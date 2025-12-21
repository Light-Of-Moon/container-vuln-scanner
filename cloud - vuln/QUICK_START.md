# 🚀 Quick Start Guide - Container Vulnerability Scanner

## Prerequisites Check

Run this to check if tools are installed:
```bash
docker --version && kubectl version --client && kind version && echo "✅ All tools installed!"
```

If any command fails, install tools:
```bash
sudo ./install-tools.sh
# Then log out and log back in
```

---

## 🎯 Quick Deployment (3 Steps)

### Step 1: Deploy Application
```bash
./start-k8s.sh
```
**Time**: ~5-10 minutes  
**What it does**: Creates Kubernetes cluster, builds images, deploys all services

### Step 2: Access Dashboard
```bash
# Option A: Via Ingress (if /etc/hosts configured by script)
http://vulnscan.example.com:8080

# Option B: Via Port-Forward (always works)
kubectl port-forward -n vulnscan svc/vulnscan-frontend 3000:80
# Then open: http://localhost:3000
```

### Step 3: Scan Your First Image
1. Open the dashboard
2. Enter image name: `nginx:latest`
3. Click "Scan Image"
4. Watch results appear!

---

## 🔄 Common Tasks

### View Logs
```bash
# API logs
kubectl logs -n vulnscan -l app=vulnscan-api -f

# Worker logs (see scanning in progress)
kubectl logs -n vulnscan -l app=vulnscan-worker -f

# Frontend logs
kubectl logs -n vulnscan -l app=vulnscan-frontend -f
```

### Check Status
```bash
# All pods
kubectl get pods -n vulnscan

# Services
kubectl get svc -n vulnscan

# Ingress
kubectl get ingress -n vulnscan
```

### Restart After Code Changes
```bash
./rebuild-and-deploy.sh
```

### Delete Everything
```bash
kind delete cluster --name vulnscan
```

### Start Fresh
```bash
./start-k8s.sh --fresh
```

---

## 🎨 Testing Scenarios

### Test 1: Quick Scan
```bash
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"image_name": "alpine", "image_tag": "latest"}'
```

### Test 2: Upload Docker Image
1. Save image: `docker save nginx:latest -o nginx.tar`
2. Upload via dashboard UI (click upload icon)

### Test 3: Multiple Scans
Scan the same image multiple times - each creates a new entry!

---

## 🔧 Troubleshooting

### Pods Not Starting?
```bash
# Check events
kubectl get events -n vulnscan --sort-by='.lastTimestamp'

# Describe pod
kubectl describe pod -n vulnscan POD_NAME
```

### API Not Responding?
```bash
# Check if healthy
kubectl port-forward -n vulnscan svc/vulnscan-api 8000:80 &
curl http://localhost:8000/health
```

### Database Issues?
```bash
# Check PostgreSQL
kubectl exec -n vulnscan postgres-0 -- psql -U scanner -d vulnscan -c "SELECT COUNT(*) FROM vulnerability_scans;"
```

### Worker Not Scanning?
```bash
# Check worker logs
kubectl logs -n vulnscan -l app=vulnscan-worker -f

# Check pending scans in database
kubectl exec -n vulnscan postgres-0 -- psql -U scanner -d vulnscan -c "SELECT id, image_name, status FROM vulnerability_scans WHERE status='pending';"
```

---

## 📱 Access Points

| Service | URL | Purpose |
|---------|-----|---------|
| Frontend | http://localhost:3000 (port-forward) | Dashboard UI |
| API | http://localhost:8000 (port-forward) | REST API |
| API Docs | http://localhost:8000/docs | Swagger UI |
| ArgoCD | http://localhost:30080 | GitOps Dashboard |

---

## 🎓 Next Steps

1. ✅ Deploy the application
2. ✅ Scan some Docker images
3. ⭐ Deploy ArgoCD: `./deploy-argocd.sh`
4. ⭐ Push to Git and configure ArgoCD App
5. ⭐ Configure production secrets
6. ⭐ Set up monitoring (Prometheus/Grafana)

---

## 📞 Need Help?

- **Full Documentation**: See `PROJECT_ANALYSIS_REPORT.md`
- **Deployment Guide**: See `DEPLOYMENT_GUIDE.md`
- **Kubernetes Details**: See `k8s/README.md`

---

**Happy Scanning! 🛡️**
