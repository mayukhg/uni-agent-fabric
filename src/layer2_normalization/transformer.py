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
    AzureSentinelStrategy,
    ConfigurableStrategy
)
import os

logger = structlog.get_logger(__name__)


class TransformationEngine:
    """
    Engine for transforming vendor-specific security data into OCSF format.
    
    This engine manages a collection of `TransformationStrategy` implementations.
    It supports both hardcoded strategies (for standard vendors) and dynamic YAML-based 
    strategies loaded from `config/mappings/`.
    
    Attributes:
        transformers (Dict[str, TransformationStrategy]): Registry of loaded strategies.
    """
    
    def __init__(self):
        self.logger = logger
        self.transformers = {}
        self._load_strategies()
        
    def _load_strategies(self):
        """
        Load transformation strategies with precedence: YAML > Default.
        
        1. Defines default hardcoded strategies.
        2. Scans `config/mappings/` for YAML files to create `ConfigurableStrategy` instances.
        3. Registers defaults only if a YAML strategy for that source doesn't exist.
        """
        # 1. Load Hardcoded Strategies (Definitions)
        # We define them here but might overwrite if YAML exists
        defaults = {
            "tenable": TenableStrategy(),
            "splunk": SplunkStrategy(),
            "aws_security_hub": AwsSecurityHubStrategy(),
            "crowdstrike": CrowdStrikeStrategy(),
            "azure_sentinel": AzureSentinelStrategy(),
            "qualys": QualysStrategy(),
        }
        
        # 2. Check for YAML configurations
        mapping_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "config", "mappings")
        
        if os.path.exists(mapping_dir):
            for filename in os.listdir(mapping_dir):
                if filename.endswith(".yaml") or filename.endswith(".yml"):
                    source_name = os.path.splitext(filename)[0]
                    config_path = os.path.join(mapping_dir, filename)
                    try:
                        self.transformers[source_name] = ConfigurableStrategy(config_path)
                        self.logger.info("Loaded YAML strategy", source=source_name)
                    except Exception as e:
                        self.logger.error("Failed to load YAML strategy", source=source_name, error=str(e))
        
        # 3. Fill missing with defaults
        for source, strategy in defaults.items():
            if source not in self.transformers:
                self.transformers[source] = strategy
                self.logger.info("Loaded default strategy", source=source)
    
    async def transform(self, source: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform raw vendor data into the OCSF schema.
        
        Delegates the actual transformation to the registered strategy for the given source.
        
        Args:
            source: Source identifier (e.g., 'tenable', 'splunk'). Case-insensitive.
            data: Raw dictionary containing the vendor finding/alert.
            
        Returns:
            Dict[str, Any]: OCSF-compliant dictionary (e.g., Finding, VulnerabilityFinding).
            
        Raises:
            NormalizationError: If no strategy is found or the transformation fails.
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

