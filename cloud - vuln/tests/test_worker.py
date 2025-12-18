"""
Worker Unit Tests
=================
Tests for the vulnerability scanner worker module.
"""

import json
import pytest
from unittest.mock import Mock, patch, AsyncMock
from pathlib import Path

from app.worker import (
    calculate_risk_metrics,
    extract_cvss_score,
    WorkerConfig,
    RiskMetrics,
)
from app.models import ComplianceStatus


# =============================================================================
# FIXTURES - Sample Trivy Output
# =============================================================================

@pytest.fixture
def sample_trivy_output_critical():
    """Sample Trivy output with critical vulnerabilities."""
    return {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "nginx:latest (debian 11.6)",
                "Class": "os-pkgs",
                "Type": "debian",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-0001",
                        "PkgName": "openssl",
                        "InstalledVersion": "1.1.1",
                        "FixedVersion": "1.1.2",
                        "Severity": "CRITICAL",
                        "CVSS": {
                            "nvd": {"V3Score": 9.8}
                        },
                    },
                    {
                        "VulnerabilityID": "CVE-2024-0002",
                        "PkgName": "curl",
                        "InstalledVersion": "7.64.0",
                        "FixedVersion": "7.64.1",
                        "Severity": "HIGH",
                        "CVSS": {
                            "nvd": {"V3Score": 7.5}
                        },
                    },
                    {
                        "VulnerabilityID": "CVE-2024-0003",
                        "PkgName": "libxml2",
                        "InstalledVersion": "2.9.4",
                        "FixedVersion": "",  # No fix available
                        "Severity": "MEDIUM",
                        "CVSS": {
                            "nvd": {"V3Score": 5.3}
                        },
                    },
                    {
                        "VulnerabilityID": "CVE-2024-0004",
                        "PkgName": "zlib",
                        "InstalledVersion": "1.2.11",
                        "Severity": "LOW",  # No CVSS
                    },
                ],
            },
        ],
    }


@pytest.fixture
def sample_trivy_output_clean():
    """Sample Trivy output with no vulnerabilities."""
    return {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "alpine:latest",
                "Class": "os-pkgs",
                "Type": "alpine",
                "Vulnerabilities": None,  # No vulnerabilities
            },
        ],
    }


@pytest.fixture
def sample_trivy_output_medium_only():
    """Sample Trivy output with only medium vulnerabilities."""
    return {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "python:3.11",
                "Class": "os-pkgs",
                "Type": "debian",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-1001",
                        "PkgName": "pip",
                        "InstalledVersion": "23.0.0",
                        "FixedVersion": "23.0.1",
                        "Severity": "MEDIUM",
                        "CVSS": {"nvd": {"V3Score": 5.0}},
                    },
                    {
                        "VulnerabilityID": "CVE-2024-1002",
                        "PkgName": "setuptools",
                        "InstalledVersion": "65.0.0",
                        "FixedVersion": "65.0.1",
                        "Severity": "MEDIUM",
                        "CVSS": {"nvd": {"V3Score": 4.5}},
                    },
                ],
            },
        ],
    }


@pytest.fixture
def worker_config():
    """Default worker configuration for tests."""
    return WorkerConfig(
        trivy_binary="/usr/local/bin/trivy",
        trivy_cache_dir="/tmp/trivy-cache-test",
        trivy_timeout=60,
        weight_critical=100,
        weight_high=50,
        weight_medium=10,
        weight_low=1,
    )


# =============================================================================
# RISK METRICS CALCULATION TESTS
# =============================================================================

class TestCalculateRiskMetrics:
    """Tests for calculate_risk_metrics function."""
    
    def test_critical_vulnerabilities(
        self, sample_trivy_output_critical, worker_config
    ):
        """Test metrics calculation with critical vulnerabilities."""
        metrics = calculate_risk_metrics(sample_trivy_output_critical, worker_config)
        
        # Check counts
        assert metrics.critical_count == 1
        assert metrics.high_count == 1
        assert metrics.medium_count == 1
        assert metrics.low_count == 1
        assert metrics.total_vulnerabilities == 4
        
        # Check fixable count (3 have FixedVersion, 1 does not)
        assert metrics.fixable_count == 2  # openssl and curl have fixes
        assert metrics.unfixable_count == 2  # libxml2 (empty) and zlib (no field)
        
        # Check risk score: 1*100 + 1*50 + 1*10 + 1*1 = 161
        assert metrics.risk_score == 161
        
        # Check compliance
        assert metrics.is_compliant is False
        assert metrics.compliance_status == ComplianceStatus.NON_COMPLIANT
        
        # Check CVSS
        assert metrics.max_cvss_score == 9.8
        assert metrics.avg_cvss_score is not None
    
    def test_clean_image(self, sample_trivy_output_clean, worker_config):
        """Test metrics calculation with no vulnerabilities."""
        metrics = calculate_risk_metrics(sample_trivy_output_clean, worker_config)
        
        assert metrics.critical_count == 0
        assert metrics.high_count == 0
        assert metrics.medium_count == 0
        assert metrics.low_count == 0
        assert metrics.total_vulnerabilities == 0
        assert metrics.risk_score == 0
        assert metrics.is_compliant is True
        assert metrics.compliance_status == ComplianceStatus.COMPLIANT
    
    def test_medium_only_pending_review(
        self, sample_trivy_output_medium_only, worker_config
    ):
        """Test that medium-only vulns result in PENDING_REVIEW status."""
        metrics = calculate_risk_metrics(sample_trivy_output_medium_only, worker_config)
        
        assert metrics.critical_count == 0
        assert metrics.high_count == 0
        assert metrics.medium_count == 2
        assert metrics.risk_score == 20  # 2 * 10
        assert metrics.compliance_status == ComplianceStatus.PENDING_REVIEW
    
    def test_empty_results(self, worker_config):
        """Test handling of empty results array."""
        empty_output = {"Results": []}
        metrics = calculate_risk_metrics(empty_output, worker_config)
        
        assert metrics.total_vulnerabilities == 0
        assert metrics.is_compliant is True
    
    def test_missing_results_key(self, worker_config):
        """Test handling of missing Results key."""
        invalid_output = {"SchemaVersion": 2}
        metrics = calculate_risk_metrics(invalid_output, worker_config)
        
        assert metrics.total_vulnerabilities == 0
        assert metrics.is_compliant is True


class TestExtractCvssScore:
    """Tests for CVSS score extraction."""
    
    def test_nvd_v3_score(self):
        """Test extraction of NVD V3 score."""
        vuln = {
            "CVSS": {
                "nvd": {"V3Score": 9.8, "V2Score": 7.5}
            }
        }
        assert extract_cvss_score(vuln) == 9.8
    
    def test_vendor_v3_score(self):
        """Test extraction of vendor V3 score when NVD missing."""
        vuln = {
            "CVSS": {
                "redhat": {"V3Score": 8.5}
            }
        }
        assert extract_cvss_score(vuln) == 8.5
    
    def test_fallback_to_v2(self):
        """Test fallback to V2 score when V3 unavailable."""
        vuln = {
            "CVSS": {
                "nvd": {"V2Score": 6.5}
            }
        }
        assert extract_cvss_score(vuln) == 6.5
    
    def test_no_cvss_data(self):
        """Test handling of missing CVSS data."""
        vuln = {"VulnerabilityID": "CVE-2024-0001"}
        assert extract_cvss_score(vuln) is None
    
    def test_empty_cvss(self):
        """Test handling of empty CVSS object."""
        vuln = {"CVSS": {}}
        assert extract_cvss_score(vuln) is None


# =============================================================================
# RISK SCORE CALCULATION TESTS
# =============================================================================

class TestRiskScoreCalculation:
    """Tests for risk score calculation accuracy."""
    
    def test_score_weights(self, worker_config):
        """Test that scoring weights are applied correctly."""
        # Create output with known vulnerability counts
        output = {
            "Results": [{
                "Target": "test",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-1", "PkgName": "a", "InstalledVersion": "1", "Severity": "CRITICAL"},
                    {"VulnerabilityID": "CVE-2", "PkgName": "b", "InstalledVersion": "1", "Severity": "CRITICAL"},
                    {"VulnerabilityID": "CVE-3", "PkgName": "c", "InstalledVersion": "1", "Severity": "HIGH"},
                    {"VulnerabilityID": "CVE-4", "PkgName": "d", "InstalledVersion": "1", "Severity": "MEDIUM"},
                    {"VulnerabilityID": "CVE-5", "PkgName": "e", "InstalledVersion": "1", "Severity": "LOW"},
                    {"VulnerabilityID": "CVE-6", "PkgName": "f", "InstalledVersion": "1", "Severity": "LOW"},
                ],
            }],
        }
        
        metrics = calculate_risk_metrics(output, worker_config)
        
        # Expected: 2*100 + 1*50 + 1*10 + 2*1 = 262
        assert metrics.risk_score == 262
    
    def test_custom_weights(self):
        """Test with custom scoring weights."""
        custom_config = WorkerConfig(
            weight_critical=200,
            weight_high=100,
            weight_medium=20,
            weight_low=5,
        )
        
        output = {
            "Results": [{
                "Target": "test",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-1", "PkgName": "a", "InstalledVersion": "1", "Severity": "CRITICAL"},
                    {"VulnerabilityID": "CVE-2", "PkgName": "b", "InstalledVersion": "1", "Severity": "LOW"},
                ],
            }],
        }
        
        metrics = calculate_risk_metrics(output, custom_config)
        
        # Expected: 1*200 + 1*5 = 205
        assert metrics.risk_score == 205


# =============================================================================
# VULNERABILITY DETAILS EXTRACTION TESTS
# =============================================================================

class TestVulnerabilityDetailsExtraction:
    """Tests for vulnerability details extraction."""
    
    def test_vulnerability_details_extracted(
        self, sample_trivy_output_critical, worker_config
    ):
        """Test that vulnerability details are properly extracted."""
        metrics = calculate_risk_metrics(sample_trivy_output_critical, worker_config)
        
        assert len(metrics.vulnerabilities) == 4
        
        # Check first vulnerability
        first_vuln = next(
            v for v in metrics.vulnerabilities
            if v["vulnerability_id"] == "CVE-2024-0001"
        )
        assert first_vuln["package_name"] == "openssl"
        assert first_vuln["package_version"] == "1.1.1"
        assert first_vuln["fixed_version"] == "1.1.2"
        assert first_vuln["severity"] == "CRITICAL"
        assert first_vuln["cvss_score"] == 9.8
        assert first_vuln["is_fixable"] is True
    
    def test_unfixable_vulnerability(
        self, sample_trivy_output_critical, worker_config
    ):
        """Test that unfixable vulnerabilities are marked correctly."""
        metrics = calculate_risk_metrics(sample_trivy_output_critical, worker_config)
        
        # CVE-2024-0003 has empty FixedVersion
        libxml_vuln = next(
            v for v in metrics.vulnerabilities
            if v["vulnerability_id"] == "CVE-2024-0003"
        )
        assert libxml_vuln["is_fixable"] is False
        assert libxml_vuln["fixed_version"] is None


# =============================================================================
# WORKER CONFIG TESTS
# =============================================================================

class TestWorkerConfig:
    """Tests for WorkerConfig dataclass."""
    
    def test_default_values(self):
        """Test that default values are set correctly."""
        config = WorkerConfig()
        
        assert config.weight_critical == 100
        assert config.weight_high == 50
        assert config.weight_medium == 10
        assert config.weight_low == 1
        assert "worker-" in config.worker_id
    
    def test_custom_values(self):
        """Test custom configuration values."""
        config = WorkerConfig(
            trivy_timeout=120,
            poll_interval=10,
            max_retries=5,
        )
        
        assert config.trivy_timeout == 120
        assert config.poll_interval == 10
        assert config.max_retries == 5
