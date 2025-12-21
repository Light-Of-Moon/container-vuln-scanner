#!/bin/bash
# =============================================================================
# Tool Installation Script for Container Vulnerability Scanner
# =============================================================================
# This script installs all required tools: Docker, kubectl, KinD, and ArgoCD CLI
# Run with: sudo ./install-tools.sh
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE} Installing Required Tools ${NC}"
echo -e "${BLUE}=============================================${NC}"

# Check if running as root or with sudo
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root or with sudo${NC}"
   exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
else
    echo -e "${RED}Cannot detect OS version${NC}"
    exit 1
fi

echo -e "\n${YELLOW}Detected OS: $OS $VERSION${NC}\n"

# =============================================================================
# 1. Install Docker
# =============================================================================
if command -v docker &> /dev/null; then
    echo -e "${GREEN}✓ Docker is already installed ($(docker --version))${NC}"
else
    echo -e "${YELLOW}[1/4] Installing Docker...${NC}"
    
    if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
        # Remove old versions
        apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
        
        # Install dependencies
        apt-get update
        apt-get install -y \
            ca-certificates \
            curl \
            gnupg \
            lsb-release
        
        # Add Docker's official GPG key
        mkdir -p /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/$OS/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        
        # Set up repository
        echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$OS \
          $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
        
        # Install Docker Engine
        apt-get update
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
        
    elif [[ "$OS" == "fedora" ]] || [[ "$OS" == "rhel" ]] || [[ "$OS" == "centos" ]]; then
        dnf -y install dnf-plugins-core
        dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
        dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
        
    else
        echo -e "${RED}Unsupported OS: $OS${NC}"
        exit 1
    fi
    
    # Start and enable Docker
    systemctl start docker
    systemctl enable docker
    
    # Add current user to docker group (if not root)
    if [ -n "$SUDO_USER" ]; then
        usermod -aG docker $SUDO_USER
        echo -e "${YELLOW}Note: User $SUDO_USER added to docker group. Log out and back in for changes to take effect.${NC}"
    fi
    
    echo -e "${GREEN}✓ Docker installed successfully ($(docker --version))${NC}"
fi

# =============================================================================
# 2. Install kubectl
# =============================================================================
if command -v kubectl &> /dev/null; then
    echo -e "${GREEN}✓ kubectl is already installed ($(kubectl version --client --short 2>/dev/null || kubectl version --client))${NC}"
else
    echo -e "\n${YELLOW}[2/4] Installing kubectl...${NC}"
    
    # Download latest stable version
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
    
    # Verify checksum
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl.sha256"
    echo "$(cat kubectl.sha256)  kubectl" | sha256sum --check
    
    # Install
    install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
    
    # Cleanup
    rm kubectl kubectl.sha256
    
    echo -e "${GREEN}✓ kubectl installed successfully ($(kubectl version --client --short 2>/dev/null || kubectl version --client))${NC}"
fi

# =============================================================================
# 3. Install KinD (Kubernetes in Docker)
# =============================================================================
if command -v kind &> /dev/null; then
    echo -e "${GREEN}✓ KinD is already installed ($(kind version))${NC}"
else
    echo -e "\n${YELLOW}[3/4] Installing KinD...${NC}"
    
    # Download and install
    curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
    chmod +x ./kind
    mv ./kind /usr/local/bin/kind
    
    echo -e "${GREEN}✓ KinD installed successfully ($(kind version))${NC}"
fi

# =============================================================================
# 4. Install ArgoCD CLI
# =============================================================================
if command -v argocd &> /dev/null; then
    echo -e "${GREEN}✓ ArgoCD CLI is already installed ($(argocd version --client --short 2>/dev/null || echo 'installed'))${NC}"
else
    echo -e "\n${YELLOW}[4/4] Installing ArgoCD CLI...${NC}"
    
    # Download latest version
    curl -sSL -o /usr/local/bin/argocd https://github.com/argoproj/argo-cd/releases/latest/download/argocd-linux-amd64
    chmod +x /usr/local/bin/argocd
    
    echo -e "${GREEN}✓ ArgoCD CLI installed successfully${NC}"
fi

# =============================================================================
# Verification
# =============================================================================
echo -e "\n${BLUE}=============================================${NC}"
echo -e "${GREEN}✓ ALL TOOLS INSTALLED SUCCESSFULLY!${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""
echo "Installed versions:"
echo "  • Docker:   $(docker --version)"
echo "  • kubectl:  $(kubectl version --client --short 2>/dev/null || kubectl version --client | head -n1)"
echo "  • KinD:     $(kind version)"
echo "  • ArgoCD:   $(argocd version --client --short 2>/dev/null || echo 'installed')"
echo ""
echo -e "${YELLOW}Important Notes:${NC}"
echo "  1. If you added a user to the docker group, they need to log out and back in"
echo "  2. Test Docker without sudo: docker run hello-world"
echo "  3. You can now run: ./start-k8s.sh to deploy the application"
echo ""
echo -e "${GREEN}Ready to deploy! Run: ./start-k8s.sh${NC}"
echo ""
