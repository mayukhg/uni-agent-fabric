"""Transformation strategies for different security vendors"""

from abc import ABC, abstractmethod
from typing import Dict, Any
from datetime import datetime
from .ocsf_schema import (
    OCSFVulnerabilityFinding,
    OCSFFinding,
    map_severity_to_ocsf,
    get_severity_name
)

class TransformationStrategy(ABC):
    """Abstract base class for transformation strategies"""
    
    @abstractmethod
    async def transform(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform vendor data to OCSF"""
        pass

class TenableStrategy(TransformationStrategy):
    async def transform(self, data: Dict[str, Any]) -> Dict[str, Any]:
        timestamp = data.get("timestamp") or datetime.now().timestamp()
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
            except Exception:
                timestamp = datetime.now().timestamp()
        
        severity_id = map_severity_to_ocsf(data.get("severity", "unknown"))
        
        ocsf = OCSFVulnerabilityFinding(
            severity_id=severity_id,
            severity=get_severity_name(severity_id),
            time=int(timestamp),
            vulnerability={
                "cve": data.get("cve"),
                "name": data.get("name"),
                "description": data.get("description"),
                "vuln_id": data.get("vuln_id"),
            },
            metadata={
                "source": "tenable",
                "original_data": data.get("raw_data", {}),
                "connector_id": data.get("connector_id"),
            }
        )
        return ocsf.dict()

class SplunkStrategy(TransformationStrategy):
    async def transform(self, data: Dict[str, Any]) -> Dict[str, Any]:
        timestamp = data.get("timestamp") or datetime.now().isoformat()
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
            except Exception:
                timestamp = datetime.now().timestamp()
        else:
            timestamp = datetime.now().timestamp()
        
        severity_id = map_severity_to_ocsf(data.get("severity", "unknown"))
        
        ocsf = OCSFFinding(
            severity_id=severity_id,
            severity=get_severity_name(severity_id),
            time=int(timestamp),
            finding={
                "title": data.get("title"),
                "description": data.get("description"),
                "uid": data.get("id"),
            },
            metadata={
                "source": "splunk",
                "original_data": data.get("raw_data", {}),
                "connector_id": data.get("connector_id"),
            }
        )
        return ocsf.dict()

class AwsSecurityHubStrategy(TransformationStrategy):
    async def transform(self, data: Dict[str, Any]) -> Dict[str, Any]:
        timestamp_str = data.get("timestamp") or data.get("UpdatedAt") or datetime.now().isoformat()
        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00")).timestamp()
        except Exception:
            timestamp = datetime.now().timestamp()
            
        severity_id = map_severity_to_ocsf(data.get("severity", "unknown"))
        
        ocsf = OCSFFinding(
            severity_id=severity_id,
            severity=get_severity_name(severity_id),
            time=int(timestamp),
            finding={
                "title": data.get("title"),
                "description": data.get("description"),
                "uid": data.get("id"),
            },
            metadata={
                "source": "aws_security_hub",
                "original_data": data.get("raw_data", {}),
                "connector_id": data.get("connector_id"),
                "product_arn": data.get("raw_data", {}).get("ProductArn"),
            }
        )
        return ocsf.dict()

class CrowdStrikeStrategy(TransformationStrategy):
    async def transform(self, data: Dict[str, Any]) -> Dict[str, Any]:
        timestamp = data.get("timestamp") or datetime.now().isoformat()
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
            except Exception:
                timestamp = datetime.now().timestamp()
        
        severity_id = map_severity_to_ocsf(data.get("severity", "unknown"))
        
        ocsf = OCSFFinding(
            severity_id=severity_id,
            severity=get_severity_name(severity_id),
            time=int(timestamp),
            finding={
                "title": data.get("title"),
                "description": data.get("description"),
                "uid": data.get("id"),
            },
            metadata={
                "source": "crowdstrike",
                "original_data": data.get("raw_data", {}),
                "connector_id": data.get("connector_id"),
            }
        )
        return ocsf.dict()

class QualysStrategy(TransformationStrategy):
    async def transform(self, data: Dict[str, Any]) -> Dict[str, Any]:
        timestamp = datetime.now().timestamp()
        severity_id = map_severity_to_ocsf(data.get("severity", "unknown"))
        
        ocsf = OCSFVulnerabilityFinding(
            severity_id=severity_id,
            severity=get_severity_name(severity_id),
            time=int(timestamp),
            vulnerability={
                "cve": data.get("cve"),
                "name": data.get("title"),
                "description": data.get("description"),
                "vuln_id": data.get("qid"),
            },
            metadata={
                "source": "qualys",
                "original_data": data,
            }
        )
        return ocsf.dict()

class AzureSentinelStrategy(TransformationStrategy):
    async def transform(self, data: Dict[str, Any]) -> Dict[str, Any]:
        # Implement proper field mapping for Azure Sentinel
        timestamp_str = data.get("TimeGenerated") or data.get("last_updated_time")
        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00")).timestamp() if timestamp_str else datetime.now().timestamp()
        except:
             timestamp = datetime.now().timestamp()

        severity_id = map_severity_to_ocsf(data.get("Severity", "unknown"))
        
        ocsf = OCSFFinding(
            severity_id=severity_id,
            severity=get_severity_name(severity_id),
            time=int(timestamp),
            finding={
                "title": data.get("Title") or data.get("AlertDisplayName"),
                "description": data.get("Description"),
                "uid": data.get("SystemAlertId") or data.get("id"),
            },
            metadata={
                "source": "azure_sentinel",
                "original_data": data,
                "provider_name": "Azure Sentinel"
            }
        )
        return ocsf.dict()
