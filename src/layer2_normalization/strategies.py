"""Transformation strategies for different security vendors"""

from abc import ABC, abstractmethod
from typing import Dict, Any
from datetime import datetime
from .ocsf_schema import (
    OCSFVulnerabilityFinding,
    OCSFFinding,
    map_severity_to_ocsf,
    get_severity_name,
    OCSFClassUID
)
import yaml
import os
import structlog

logger = structlog.get_logger(__name__)

class TransformationStrategy(ABC):
    """
    Abstract base class for all transformation strategies.
    
    Implementations must convert raw vendor dictionaries into OCSF-compliant dictionaries.
    """
    
    @abstractmethod
    async def transform(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform raw data into OCSF format.
        
        Args:
            data: Raw vendor data map.
            
        Returns:
            Dict complying with OCSF schema (typically Finding or Vulnerability classes).
        """
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

class ConfigurableStrategy(TransformationStrategy):
    """
    Strategy that performs transformations based on a YAML configuration file.
    
    This allows adding new vendor mappings without changing code.
    The YAML file should define 'defaults' (like class_uid) and a list of 'rules'
    mapping input fields to output OCSF fields, optionally with transformation functions.
    """
    
    def __init__(self, config_path: str):
        self.config_path = config_path
        self._load_config()
        
    def _load_config(self):
        """Load and parse the YAML configuration file."""
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
        with open(self.config_path, 'r') as f:
            self.config = yaml.safe_load(f)
            
    async def transform(self, data: Dict[str, Any]) -> Dict[str, Any]:
        rules = self.config.get("rules", [])
        defaults = self.config.get("defaults", {})
        
        # Initialize OCSF structure based on class_uid
        class_uid = defaults.get("class_uid", 2002) # Default to Vulnerability Finding
        
        # Base/Metadata construction
        result = {
            "class_uid": class_uid,
            "class_name": defaults.get("class_name", "Vulnerability Finding"),
            "metadata": {
                "source": defaults.get("source", "unknown"),
                "product": {"name": defaults.get("source", "unknown")},
                "version": "1.1.0",
                "profiles": ["security_control"]
            }
        }
        
        # Add timestamp defaults
        result["time"] = int(datetime.now().timestamp())
        
        # Apply rules
        for rule in rules:
            input_field = rule.get("input")
            output_path = rule.get("output")
            transform_func = rule.get("transform")
            
            # Get value
            value = data.get(input_field)
            if value is None:
                continue
                
            # Apply transformation
            if transform_func:
                value = self._apply_transform(transform_func, value)
                
            # Set value in result
            self._set_nested(result, output_path, value)
            
        # Ensure mandatory fields
        if "severity_id" not in result:
             result["severity_id"] = 0
             result["severity"] = "unknown"
             
        # Add connector_id if present in data but not ruled
        if "connector_id" in data and not any(r["output"] == "metadata.connector_id" for r in rules):
             if "metadata" not in result: result["metadata"] = {}
             result["metadata"]["connector_id"] = data["connector_id"]

        self._finalize_structure(result)
        return result

    def _apply_transform(self, func_name: str, value: Any) -> Any:
        """
        Apply a named transformation function to a value.
        
        Supported functions:
        - 'map_severity': Maps vendor severity strings/ints to OCSF severity IDs.
        - 'lowercase_string': Converts string to lowercase.
        - 'to_timestamp': Converts various date formats/timestamps to Unix epoch integer.
        """
        if func_name == "map_severity":
            return map_severity_to_ocsf(str(value))
        elif func_name == "lowercase_string":
            return str(value).lower()
        elif func_name == "to_timestamp":
            if isinstance(value, (int, float)):
                return int(value)
            try:
                # Basic ISO parsing
                dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                return int(dt.timestamp())
            except:
                return int(datetime.now().timestamp())
        return value

    def _set_nested(self, d: Dict, path: str, value: Any):
        """
        Set a value in a nested dictionary using dot notation path.
        
        Example: path="metadata.product.name" sets d["metadata"]["product"]["name"] = value
        """
        parts = path.split('.')
        for part in parts[:-1]:
            d = d.setdefault(part, {})
        d[parts[-1]] = value
        
    def _finalize_structure(self, result: Dict):
        """Hook for any final structure adjustments."""
        pass
