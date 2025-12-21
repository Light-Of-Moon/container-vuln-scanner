# 🛡️ Container Vulnerability Scanner

A production-grade **DevSecOps** platform for scanning Docker containers and images for vulnerabilities (CVEs). Built with a microservices architecture, this system provides real-time scanning, risk scoring, and a modern dashboard for security assessment.

---

## 📖 Overview

The **Container Vulnerability Scanner** automates the security auditing of container images. It leverages **Trivy** as the underlying scanning engine but wraps it in a scalable, distributed architecture suitable for enterprise deployment.

**Problem Solved:** Manual security scanning is slow and lacks visibility. This tool creates a centralized dashboard to track, audit, and remediate container vulnerabilities before deployment.

---

## 🏗️ Architecture

The system follows a strictly decoupled microservices pattern:

```
graph LR
    User[User/Browser] --> Ingress[NGINX Ingress]
    Ingress --> Front[Frontend (React)]
    Ingress --> API[Backend API (FastAPI)]
    API --> DB[(PostgreSQL)]
    API --> Queue[Job Queue]
    Queue --> Worker[Scanner Worker]
    Worker --> Trivy[Trivy Engine]
    Worker --> DB

```

### Core Components

* **API Service (FastAPI):** Handles requests, manages scan lifecycle, and serves data.
* **Worker Service:** Asynchronous worker that pulls images and executes Trivy scans.
* **Frontend (React + Tailwind):** Interactive dashboard for visualization and reporting.
* **Database (PostgreSQL):** Stores scan results, vulnerability details, and audit logs.
* **Orchestration:** Fully containerized and deployed via **Kubernetes**.

---

## ✨ Key Features

* **🔍 Deep Vulnerability Scanning:** Detects OS packages and application dependency vulnerabilities using Trivy.
* **⚡ Real-Time Updates:** Asynchronous scanning with live status updates (Pending → Pulling → Scanning → Completed).
* **📊 Interactive Dashboard:** Visual breakdown of Critical, High, Medium, and Low risks.
* **🐳 Multi-Source Support:** Scan images from Docker Hub, private registries, or upload `.tar` files directly.
* **🛡️ Risk Scoring:** Automated calculation of image security posture scores.
* **☁️ Cloud Native:** Designed for Kubernetes (EKS/Kind) with GitOps (ArgoCD) support.

---

## 🚀 Getting Started

### Prerequisites

* **Docker** & **Kubernetes** (Kind or Minikube)
* **kubectl**
* **ArgoCD** (Optional, for GitOps)

### 📥 Rapid Installation (Local)

We provide an automated script to set up the entire stack in minutes.

1. **Clone the repository:**
```bash
git clone https://github.com/yourusername/cloud-vuln.git
cd "cloud - vuln"

```


2. **Install Dependencies:**
```bash
chmod +x install-tools.sh
sudo ./install-tools.sh

```


3. **Deploy Cluster:**
```bash
chmod +x start-k8s.sh
./start-k8s.sh

```


4. **Access the Dashboard:**
* **Frontend:** `http://localhost:3000` (via port-forward)
* **API:** `http://localhost:8000`



---

## ☁️ AWS Deployment (EKS)

To deploy this project on AWS Elastic Kubernetes Service (EKS):

1. **Push Images to ECR:**
```bash
aws ecr create-repository --repository-name vulnscan-backend
# Build and push commands (see deployment guide)

```


2. **Create EKS Cluster:**
```bash
eksctl create cluster --name vulnscan-prod --node-type t3.medium --nodes 2

```


3. **Apply Manifests:**
Update `k8s/*.yaml` images to your ECR URI and apply:
```bash
kubectl apply -f k8s/

```



---

## 🖥️ Usage Guide

### 1. Scanning a Public Image

1. Open the Dashboard.
2. Enter the image name (e.g., `nginx:1.14` or `postgres:latest`).
3. Click **Scan**.
4. Watch the progress bar as the worker pulls and scans the image.

### 2. Uploading a Local Image

1. Save your local image: `docker save my-app:v1 -o my-app.tar`.
2. Click the **Upload** icon on the dashboard.
3. Drag & drop the `.tar` file.

### 3. API Documentation

Full Swagger/OpenAPI documentation is available at:

* `http://localhost:8000/docs`

---

## 🛠️ Technology Stack

| Component | Technology | Description |
| --- | --- | --- |
| **Backend** | Python 3.11, FastAPI | High-performance async API |
| **Frontend** | React 18, Vite, Tailwind | Modern, responsive UI |
| **Database** | PostgreSQL 15 | Relational data & JSONB storage |
| **Scanning** | Trivy (Aqua Security) | Vulnerability detection engine |
| **DevOps** | Docker, Kubernetes, ArgoCD | Container orchestration & CI/CD |
| **Testing** | Pytest, HTTPX | Comprehensive test suite |

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](https://www.google.com/search?q=LICENSE) file for details.

---

### ⚠️ Disclaimer

This tool is intended for **educational and defensive security purposes only**. Ensure you have permission to scan the container images you target.
