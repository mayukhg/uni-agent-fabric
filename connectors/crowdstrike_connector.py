"""CrowdStrike Falcon connector implementation"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import httpx
from src.layer1_integration.base_connector import BaseConnector
from src.common.exceptions import AuthenticationError, ConnectorError


class CrowdStrikeConnector(BaseConnector):
    """Connector for CrowdStrike Falcon"""
    
    def __init__(self, connector_id: str, connector_name: str, config: Dict[str, Any]):
        super().__init__(connector_id, connector_name, config)
        self.client_id = config.get("client_id")
        self.client_secret = config.get("client_secret")
        self.base_url = config.get("base_url", "https://api.crowdstrike.com")
        self.access_token = None
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=30.0
        )

    async def authenticate(self) -> bool:
        """Authenticate with CrowdStrike and get access token"""
        try:
            response = await self.client.post(
                "/oauth2/token",
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret
                }
            )
            response.raise_for_status()
            self.access_token = response.json().get("access_token")
            if self.access_token:
                self.client.headers["Authorization"] = f"Bearer {self.access_token}"
                self._authenticated = True
                self.logger.info("CrowdStrike authentication successful")
                return True
            else:
                raise AuthenticationError("Failed to obtain access token")
        except Exception as e:
            self.logger.error("CrowdStrike authentication error", error=str(e))
            raise AuthenticationError(f"Failed to authenticate: {e}")

    async def fetch(self, since: Optional[datetime] = None, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Fetch alerts from CrowdStrike"""
        if not self._authenticated:
            await self.authenticate()
        
        try:
            # Step 1: Query for detection IDs
            params = {"limit": limit or 100}
            if since:
                 # CrowdStrike FQL filter format (simplified)
                 params["filter"] = f"created_timestamp:>{int(since.timestamp())}"

            ids_response = await self.client.get("/alerts/queries/alerts/v1", params=params)
            ids_response.raise_for_status()
            alert_ids = ids_response.json().get("resources", [])
            
            if not alert_ids:
                return []

            # Step 2: Get alert details
            alerts = []
            # Fetch details in batches if needed, here simplified to one batch call
            details_response = await self.client.post(
                "/alerts/entities/alerts/v2",
                json={"ids": alert_ids}
            )
            details_response.raise_for_status()
            resources = details_response.json().get("resources", [])

            for alert in resources:
                alerts.append({
                    "id": f"cs_{alert.get('composite_id')}",
                    "source": "crowdstrike",
                    "severity": self._map_severity(alert.get("severity")), # CrowdStrike severity is int 10-100 or string
                    "title": alert.get("description", "CrowdStrike Alert"), # CrowdStrike fields vary
                    "description": alert.get("description", ""),
                    "timestamp": alert.get("timestamp"),
                    "raw_data": alert
                })
            
            self.logger.info("Fetched alerts from CrowdStrike", count=len(alerts))
            return alerts

        except Exception as e:
            self.logger.error("Failed to fetch from CrowdStrike", error=str(e))
            raise ConnectorError(f"Failed to fetch data: {e}")

    async def health_check(self) -> bool:
        """Check CrowdStrike API health"""
        try:
            # Determine health by trying to get a token or simple query
            if not self._authenticated:
                await self.authenticate()
            return self._authenticated
        except Exception:
            return False

    def _map_severity(self, severity: Any) -> str:
        """Map CrowdStrike severity score to standard severity"""
        # CrowdStrike uses 1-100
        try:
            score = int(severity)
            if score >= 80: return "critical"
            if score >= 60: return "high"
            if score >= 40: return "medium"
            if score >= 20: return "low"
            return "info"
        except (ValueError, TypeError):
             return "unknown"
