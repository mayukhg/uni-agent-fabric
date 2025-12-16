"""Splunk connector implementation"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import httpx
import base64
from src.layer1_integration.base_connector import BaseConnector
from src.common.exceptions import AuthenticationError, ConnectorError


class SplunkConnector(BaseConnector):
    """Connector for Splunk Enterprise Security"""
    
    def __init__(self, connector_id: str, connector_name: str, config: Dict[str, Any]):
        super().__init__(connector_id, connector_name, config)
        self.username = config.get("username")
        self.password = config.get("password")
        self.base_url = config.get("base_url", "https://localhost:8089")
        self.app = config.get("app", "search")
        
        # Create basic auth header
        credentials = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=30.0,
            headers={
                "Authorization": f"Basic {credentials}",
                "Content-Type": "application/x-www-form-urlencoded"
            },
            verify=False  # In production, use proper SSL verification
        )
        self.session_key = None
    
    async def authenticate(self) -> bool:
        """Authenticate with Splunk and get session key"""
        try:
            response = await self.client.post(
                "/services/auth/login",
                data={"username": self.username, "password": self.password}
            )
            response.raise_for_status()
            
            # Parse session key from response
            import xml.etree.ElementTree as ET
            root = ET.fromstring(response.text)
            self.session_key = root.find(".//sessionKey").text if root.find(".//sessionKey") is not None else None
            
            if self.session_key:
                self.client.headers["Authorization"] = f"Splunk {self.session_key}"
                self._authenticated = True
                self.logger.info("Splunk authentication successful")
                return True
            else:
                raise AuthenticationError("Failed to obtain session key")
        except Exception as e:
            self.logger.error("Splunk authentication error", error=str(e))
            raise AuthenticationError(f"Failed to authenticate: {e}")
    
    async def fetch(self, since: Optional[datetime] = None, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Fetch security alerts from Splunk"""
        if not self._authenticated:
            await self.authenticate()
        
        try:
            # Build search query
            search_query = "index=security | head 100"
            if since:
                search_query = f"index=security earliest={int(since.timestamp())} | head 100"
            
            # Create search job
            job_response = await self.client.post(
                "/services/search/jobs",
                data={"search": search_query, "output_mode": "json"}
            )
            job_response.raise_for_status()
            job_data = job_response.json()
            job_id = job_data.get("sid")
            
            if not job_id:
                raise ConnectorError("Failed to create search job")
            
            # Wait for job to complete
            import asyncio
            for _ in range(30):  # Wait up to 30 seconds
                await asyncio.sleep(1)
                status_response = await self.client.get(f"/services/search/jobs/{job_id}")
                status_data = status_response.json()
                if status_data.get("entry", [{}])[0].get("content", {}).get("isDone"):
                    break
            
            # Get results
            results_response = await self.client.get(
                f"/services/search/jobs/{job_id}/results",
                params={"output_mode": "json", "count": limit or 100}
            )
            results_response.raise_for_status()
            results_data = results_response.json()
            
            alerts = []
            for result in results_data.get("results", []):
                alerts.append({
                    "id": f"splunk_{result.get('_cd', 'unknown')}",
                    "source": "splunk",
                    "severity": self._map_severity(result.get("severity", "low")),
                    "title": result.get("title", result.get("_raw", "")[:100]),
                    "description": result.get("_raw", ""),
                    "timestamp": result.get("_time", datetime.now().isoformat()),
                    "raw_data": result
                })
            
            self.logger.info("Fetched alerts from Splunk", count=len(alerts))
            return alerts
            
        except Exception as e:
            self.logger.error("Failed to fetch from Splunk", error=str(e))
            raise ConnectorError(f"Failed to fetch data: {e}")
    
    async def health_check(self) -> bool:
        """Check Splunk API health"""
        try:
            response = await self.client.get("/services/server/info")
            return response.status_code == 200
        except Exception:
            return False
    
    def _map_severity(self, severity: str) -> str:
        """Map Splunk severity to standard severity"""
        severity_lower = severity.lower()
        if "critical" in severity_lower or severity_lower == "5":
            return "critical"
        elif "high" in severity_lower or severity_lower == "4":
            return "high"
        elif "medium" in severity_lower or severity_lower == "3":
            return "medium"
        elif "low" in severity_lower or severity_lower == "2":
            return "low"
        else:
            return "info"

