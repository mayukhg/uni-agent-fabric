"""AWS Security Hub connector implementation"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import boto3
from src.layer1_integration.base_connector import BaseConnector
from src.common.exceptions import AuthenticationError, ConnectorError


class AwsSecurityHubConnector(BaseConnector):
    """Connector for AWS Security Hub"""
    
    def __init__(self, connector_id: str, connector_name: str, config: Dict[str, Any]):
        super().__init__(connector_id, connector_name, config)
        self.region_name = config.get("region_name", "us-east-1")
        self.access_key = config.get("aws_access_key_id")
        self.secret_key = config.get("aws_secret_access_key")
        self.client = None
    
    async def authenticate(self) -> bool:
        """Authenticate with AWS"""
        try:
            self.client = boto3.client(
                "securityhub",
                region_name=self.region_name,
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key
            )
            # Verify connectivity by listing detectors/enabled standards or similar lightweight call
            self.client.get_enabled_standards(MaxResults=1)
            self._authenticated = True
            self.logger.info("AWS authentication successful")
            return True
        except Exception as e:
            self.logger.error("AWS authentication error", error=str(e))
            raise AuthenticationError(f"Failed to authenticate: {e}")
    
    async def fetch(self, since: Optional[datetime] = None, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Fetch findings from Security Hub"""
        if not self._authenticated:
            await self.authenticate()
        
        try:
            filters = {"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]}
            if since:
                filters["UpdatedAt"] = [{"Start": since.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "End": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")}]

            response = self.client.get_findings(
                Filters=filters,
                MaxResults=limit if limit and limit <= 100 else 100
            )
            
            findings = response.get("Findings", [])
            alerts = []
            
            for finding in findings:
                alerts.append({
                    "id": f"aws_{finding.get('Id')}",
                    "source": "aws_security_hub",
                    "severity": finding.get("Severity", {}).get("Label", "UNKNOWN").lower(),
                    "title": finding.get("Title"),
                    "description": finding.get("Description"),
                    "timestamp": finding.get("UpdatedAt"),
                    "raw_data": finding
                })
            
            self.logger.info("Fetched findings from AWS Security Hub", count=len(alerts))
            return alerts

        except Exception as e:
            self.logger.error("Failed to fetch from AWS Security Hub", error=str(e))
            raise ConnectorError(f"Failed to fetch data: {e}")

    async def health_check(self) -> bool:
        """Check AWS API health"""
        try:
            if not self.client:
                await self.authenticate()
            self.client.get_enabled_standards(MaxResults=1)
            return True
        except Exception:
            return False
