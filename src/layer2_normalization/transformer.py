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
from .ocsf_schema import (
    OCSFVulnerabilityFinding,
    OCSFFinding,
    OCSFAssetInventory,
    map_severity_to_ocsf,
    get_severity_name
)
from ..common.exceptions import NormalizationError, OCSFValidationError
from .strategies import (
    TenableStrategy,
    SplunkStrategy,
    AwsSecurityHubStrategy,
    CrowdStrikeStrategy,
    QualysStrategy,
    AzureSentinelStrategy
)

logger = structlog.get_logger(__name__)


class TransformationEngine:
    """Engine for transforming vendor data to OCSF format"""
    
    def __init__(self):
        self.logger = logger
        self.transformers = {
            "tenable": TenableStrategy(),
            "splunk": SplunkStrategy(),
            "aws_security_hub": AwsSecurityHubStrategy(),
            "crowdstrike": CrowdStrikeStrategy(),
            "azure_sentinel": AzureSentinelStrategy(),
            "qualys": QualysStrategy(),
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
            ocsf_data = await transformer.transform(data)
            self.logger.info("Data transformed", source=source, class_uid=ocsf_data.get("class_uid"))
            return ocsf_data
        except Exception as e:
            self.logger.error("Transformation failed", source=source, error=str(e))
            raise NormalizationError(f"Failed to transform data from {source}: {e}")


# Global transformer instance
transformer = TransformationEngine()

