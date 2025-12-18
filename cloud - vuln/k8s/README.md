# Kubernetes Manifests

This directory contains the Kubernetes manifests for deploying the Container Vulnerability Scanner.

## Files

| File | Description |
|------|-------------|
| `namespace.yaml` | Namespace, NetworkPolicy, ResourceQuota, LimitRange |
| `postgres.yaml` | PostgreSQL StatefulSet with PVC |
| `api.yaml` | FastAPI Deployment, Service, HPA, PDB |
| `worker.yaml` | Trivy Worker Deployment with cache volume |
| `ingress.yaml` | Ingress with TLS and rate limiting |
| `argocd-app.yaml` | ArgoCD Application and AppProject |

## Deployment Order

```bash
# 1. Create namespace and policies
kubectl apply -f namespace.yaml

# 2. Deploy PostgreSQL
kubectl apply -f postgres.yaml

# 3. Wait for PostgreSQL to be ready
kubectl wait --for=condition=ready pod -l app=postgres -n vulnscan --timeout=120s

# 4. Deploy API
kubectl apply -f api.yaml

# 5. Deploy Worker
kubectl apply -f worker.yaml

# 6. Deploy Ingress (optional)
kubectl apply -f ingress.yaml
```

## GitOps with ArgoCD

```bash
# Install ArgoCD Application
kubectl apply -f argocd-app.yaml
```

## Configuration

### Secrets (update before deploying!)

1. **postgres-secrets** in `postgres.yaml`:
   - `POSTGRES_PASSWORD`: Change from default

2. **api-secrets** in `api.yaml`:
   - `DATABASE_URL`: Update password to match postgres

3. **worker-secrets** in `worker.yaml`:
   - `DATABASE_URL`: Update password to match postgres

### Ingress

Update `ingress.yaml`:
- Replace `vulnscan.example.com` with your domain
- Configure cert-manager issuer if using TLS

## Resource Requirements

| Component | CPU Request | CPU Limit | Memory Request | Memory Limit |
|-----------|-------------|-----------|----------------|--------------|
| PostgreSQL | 250m | 1000m | 512Mi | 1Gi |
| API | 100m | 500m | 256Mi | 512Mi |
| Worker | 250m | 1000m | 512Mi | 1Gi |

## Scaling

- **API**: Automatically scales 2-10 replicas based on CPU/memory
- **Worker**: Scales 1-5 replicas based on CPU/memory
- **PostgreSQL**: Single replica (use managed DB for HA)

## Monitoring

All pods expose Prometheus metrics:
- API: `:8000/metrics`
- PostgreSQL: `:9187/metrics` (with postgres_exporter sidecar)
