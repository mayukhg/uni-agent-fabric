"""OCSF (Open Cybersecurity Schema Framework) schema definitions and validation"""

from typing import Dict, Any, Optional, List
from enum import IntEnum
from pydantic import BaseModel, Field, validator
import structlog

logger = structlog.get_logger(__name__)


class OCSFSeverityID(IntEnum):
    """OCSF Severity ID enumeration"""
    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    FATAL = 6


class OCSFClassUID(IntEnum):
    """OCSF Class UID enumeration"""
    BASE_EVENT = 1001
    FINDING = 2001
    VULNERABILITY_FINDING = 2002
    SECURITY_FINDING = 2003
    INCIDENT_FINDING = 2004
    COMPLIANCE_FINDING = 2005
    ASSET_INVENTORY = 1001
    NETWORK_ACTIVITY = 4001


class OCSFBaseEvent(BaseModel):
    """Base OCSF event structure"""
    class_uid: int = Field(..., description="OCSF class UID")
    class_name: str = Field(..., description="OCSF class name")
    severity_id: int = Field(..., description="OCSF severity ID")
    severity: str = Field(..., description="Severity name")
    time: int = Field(..., description="Event timestamp (Unix epoch)")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    
    @validator("severity_id")
    def validate_severity(cls, v):
        if v not in [s.value for s in OCSFSeverityID]:
            raise ValueError(f"Invalid severity_id: {v}")
        return v


class OCSFVulnerabilityFinding(OCSFBaseEvent):
    """OCSF Vulnerability Finding (class_uid: 2002)"""
    class_uid: int = Field(default=OCSFClassUID.VULNERABILITY_FINDING, const=True)
    class_name: str = Field(default="Vulnerability Finding", const=True)
    vulnerability: Dict[str, Any] = Field(..., description="Vulnerability details")
    asset: Optional[Dict[str, Any]] = Field(None, description="Affected asset")
    src_endpoint: Optional[Dict[str, Any]] = Field(None, description="Source endpoint")
    dst_endpoint: Optional[Dict[str, Any]] = Field(None, description="Destination endpoint")
    
    def __init__(self, **data):
        if "class_uid" not in data:
            data["class_uid"] = OCSFClassUID.VULNERABILITY_FINDING
        if "class_name" not in data:
            data["class_name"] = "Vulnerability Finding"
        super().__init__(**data)


class OCSFFinding(OCSFBaseEvent):
    """OCSF Finding (class_uid: 2001)"""
    class_uid: int = Field(default=OCSFClassUID.FINDING, const=True)
    class_name: str = Field(default="Finding", const=True)
    finding: Dict[str, Any] = Field(..., description="Finding details")
    resources: Optional[List[Dict[str, Any]]] = Field(None, description="Related resources")
    
    def __init__(self, **data):
        if "class_uid" not in data:
            data["class_uid"] = OCSFClassUID.FINDING
        if "class_name" not in data:
            data["class_name"] = "Finding"
        super().__init__(**data)


class OCSFAssetInventory(OCSFBaseEvent):
    """OCSF Asset Inventory (class_uid: 1001)"""
    class_uid: int = Field(default=OCSFClassUID.ASSET_INVENTORY, const=True)
    class_name: str = Field(default="Asset Inventory", const=True)
    asset: Dict[str, Any] = Field(..., description="Asset details")
    location: Optional[Dict[str, Any]] = Field(None, description="Asset location")
    
    def __init__(self, **data):
        if "class_uid" not in data:
            data["class_uid"] = OCSFClassUID.ASSET_INVENTORY
        if "class_name" not in data:
            data["class_name"] = "Asset Inventory"
        super().__init__(**data)


def map_severity_to_ocsf(severity: str) -> int:
    """
    Map standard severity string to OCSF severity ID
    
    Args:
        severity: Severity string (critical, high, medium, low, info, unknown)
        
    Returns:
        OCSF severity ID
    """
        severity_lower = severity.lower()
        mapping = {
            "critical": OCSFSeverityID.CRITICAL,
            "high": OCSFSeverityID.HIGH,
            "medium": OCSFSeverityID.MEDIUM,
            "low": OCSFSeverityID.LOW,
            "info": OCSFSeverityID.INFORMATIONAL,
            "informational": OCSFSeverityID.INFORMATIONAL,
            "unknown": OCSFSeverityID.UNKNOWN
        }
        return mapping.get(severity_lower, OCSFSeverityID.UNKNOWN).value


def get_severity_name(severity_id: int) -> str:
    """Get severity name from OCSF severity ID"""
    try:
        return OCSFSeverityID(severity_id).name.lower()
    except ValueError:
        return "unknown"

