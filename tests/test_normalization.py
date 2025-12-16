"""Tests for normalization engine"""

import pytest
from src.layer2_normalization.transformer import transformer
from src.layer2_normalization.ocsf_schema import map_severity_to_ocsf, OCSFSeverityID


def test_severity_mapping():
    """Test severity mapping"""
    assert map_severity_to_ocsf("critical") == OCSFSeverityID.CRITICAL.value
    assert map_severity_to_ocsf("high") == OCSFSeverityID.HIGH.value
    assert map_severity_to_ocsf("medium") == OCSFSeverityID.MEDIUM.value
    assert map_severity_to_ocsf("low") == OCSFSeverityID.LOW.value


@pytest.mark.asyncio
async def test_tenable_transformation():
    """Test Tenable to OCSF transformation"""
    tenable_data = {
        "id": "test-1",
        "source": "tenable",
        "vuln_id": "CVE-2024-123",
        "cve": "CVE-2024-123",
        "severity": "high",
        "name": "Test Vulnerability",
        "description": "Test description",
        "timestamp": "2024-01-01T00:00:00Z"
    }
    
    ocsf_data = await transformer.transform("tenable", tenable_data)
    
    assert ocsf_data["class_uid"] == 2002  # Vulnerability Finding
    assert ocsf_data["severity_id"] == OCSFSeverityID.HIGH.value
    assert "vulnerability" in ocsf_data
    assert ocsf_data["vulnerability"]["cve"] == "CVE-2024-123"

