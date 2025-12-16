"""Data transformation engine for converting vendor-specific data to OCSF"""

from typing import Dict, Any, Optional
from datetime import datetime
import structlog
from .ocsf_schema import (
    OCSFVulnerabilityFinding,
    OCSFFinding,
    OCSFAssetInventory,
    map_severity_to_ocsf,
    get_severity_name
)
from ..common.exceptions import NormalizationError, OCSFValidationError

logger = structlog.get_logger(__name__)


class TransformationEngine:
    """Engine for transforming vendor data to OCSF format"""
    
    def __init__(self):
        self.logger = logger
        self.transformers = {
            "tenable": self._transform_tenable,
            "splunk": self._transform_splunk,
            "aws_security_hub": self._transform_aws_security_hub,
            "crowdstrike": self._transform_crowdstrike,
            "azure_sentinel": self._transform_azure_sentinel,
            "qualys": self._transform_qualys,
        }
    
    async def transform(self, source: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform vendor-specific data to OCSF format
        
        Args:
            source: Source connector name
            data: Raw vendor data
            
        Returns:
            OCSF-formatted data dictionary
            
        Raises:
            NormalizationError: If transformation fails
        """
        transformer = self.transformers.get(source.lower())
        if not transformer:
            raise NormalizationError(f"No transformer found for source: {source}")
        
        try:
            ocsf_data = await transformer(data)
            self.logger.info("Data transformed", source=source, class_uid=ocsf_data.get("class_uid"))
            return ocsf_data
        except Exception as e:
            self.logger.error("Transformation failed", source=source, error=str(e))
            raise NormalizationError(f"Failed to transform data from {source}: {e}")
    
    async def _transform_tenable(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Tenable data to OCSF Vulnerability Finding"""
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
    
    async def _transform_splunk(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Splunk data to OCSF Finding"""
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
    
    async def _transform_aws_security_hub(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform AWS Security Hub data to OCSF"""
        # Parse timestamp
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
    
    async def _transform_crowdstrike(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform CrowdStrike data to OCSF"""
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
    
    async def _transform_azure_sentinel(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Azure Sentinel data to OCSF"""
        # Placeholder - implement based on Azure Sentinel schema
        timestamp = datetime.now().timestamp()
        severity_id = map_severity_to_ocsf(data.get("Severity", "unknown"))
        
        ocsf = OCSFFinding(
            severity_id=severity_id,
            severity=get_severity_name(severity_id),
            time=int(timestamp),
            finding={
                "title": data.get("Title"),
                "description": data.get("Description"),
                "uid": data.get("Id"),
            },
            metadata={
                "source": "azure_sentinel",
                "original_data": data,
            }
        )
        return ocsf.dict()
    
    async def _transform_qualys(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Qualys data to OCSF Vulnerability Finding"""
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


# Global transformer instance
transformer = TransformationEngine()

