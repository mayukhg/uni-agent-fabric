"""Tenable connector implementation"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import httpx
from src.layer1_integration.base_connector import BaseConnector
from src.common.exceptions import AuthenticationError, ConnectorError


class TenableConnector(BaseConnector):
    """Connector for Tenable.io/Tenable.sc"""
    
    def __init__(self, connector_id: str, connector_name: str, config: Dict[str, Any]):
        super().__init__(connector_id, connector_name, config)
        self.api_key = config.get("api_key")
        self.secret_key = config.get("secret_key")
        self.base_url = config.get("base_url", "https://cloud.tenable.com")
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=30.0,
            headers={"X-ApiKeys": f"accessKey={self.api_key};secretKey={self.secret_key}"}
        )
    
    async def authenticate(self) -> bool:
        """Authenticate with Tenable API"""
        try:
            response = await self.client.get("/scans")
            if response.status_code == 200:
                self._authenticated = True
                self.logger.info("Tenable authentication successful")
                return True
            else:
                raise AuthenticationError(f"Authentication failed: {response.status_code}")
        except Exception as e:
            self.logger.error("Tenable authentication error", error=str(e))
            raise AuthenticationError(f"Failed to authenticate: {e}")
    
    async def fetch(self, since: Optional[datetime] = None, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Fetch vulnerability data from Tenable"""
        if not self._authenticated:
            await self.authenticate()
        
        try:
            params = {}
            if since:
                params["last_modification_date"] = int(since.timestamp())
            if limit:
                params["limit"] = limit
            
            response = await self.client.get("/scans", params=params)
            response.raise_for_status()
            
            scans = response.json().get("scans", [])
            alerts = []
            
            for scan in scans:
                # Fetch vulnerabilities for each scan
                scan_id = scan.get("id")
                if scan_id:
                    vuln_response = await self.client.get(f"/scans/{scan_id}")
                    if vuln_response.status_code == 200:
                        vulns = vuln_response.json().get("vulnerabilities", [])
                        for vuln in vulns:
                            alerts.append({
                                "id": f"tenable_{scan_id}_{vuln.get('plugin_id')}",
                                "source": "tenable",
                                "vuln_id": vuln.get("plugin_id"),
                                "cve": vuln.get("cve"),
                                "severity": self._map_severity(vuln.get("severity")),
                                "name": vuln.get("plugin_name"),
                                "description": vuln.get("description"),
                                "timestamp": scan.get("last_modification_date"),
                                "raw_data": vuln
                            })
            
            self.logger.info("Fetched alerts from Tenable", count=len(alerts))
            return alerts[:limit] if limit else alerts
            
        except Exception as e:
            self.logger.error("Failed to fetch from Tenable", error=str(e))
            raise ConnectorError(f"Failed to fetch data: {e}")
    
    async def health_check(self) -> bool:
        """Check Tenable API health"""
        try:
            response = await self.client.get("/scans", params={"limit": 1})
            return response.status_code == 200
        except Exception:
            return False
    
    def _map_severity(self, severity_id: Optional[int]) -> str:
        """Map Tenable severity ID to standard severity"""
        severity_map = {
            0: "info",
            1: "low",
            2: "low",
            3: "medium",
            4: "high",
            5: "critical"
        }
        return severity_map.get(severity_id or 0, "low")

