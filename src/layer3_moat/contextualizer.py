"""Contextualization service for enriching OCSF data with asset context"""

from typing import Dict, Any, Optional, List
import structlog
from .graph_client import GraphClient, get_graph_client
from ..common.exceptions import GraphDatabaseError

logger = structlog.get_logger(__name__)


class Contextualizer:
    """Service for contextualizing and storing data in the graph"""
    
    def __init__(self, graph_client: Optional[GraphClient] = None):
        self.graph = graph_client or get_graph_client()
        self.logger = logger
    
    async def ingest_ocsf_data(self, ocsf_data: Dict[str, Any]) -> str:
        """
        Ingest OCSF data into the graph database with context
        
        Args:
            ocsf_data: OCSF-formatted data dictionary
            
        Returns:
            Node ID in the graph
        """
        class_uid = ocsf_data.get("class_uid")
        source = ocsf_data.get("metadata", {}).get("source", "unknown")
        
        try:
            if class_uid == 2002:  # Vulnerability Finding
                return await self._ingest_vulnerability(ocsf_data)
            elif class_uid == 2001:  # Finding
                return await self._ingest_finding(ocsf_data)
            elif class_uid == 1001:  # Asset Inventory
                return await self._ingest_asset(ocsf_data)
            else:
                # Generic finding
                return await self._ingest_finding(ocsf_data)
        except Exception as e:
            self.logger.error("Failed to ingest OCSF data", error=str(e), class_uid=class_uid)
            raise GraphDatabaseError(f"Failed to ingest data: {e}")
    
    async def _ingest_vulnerability(self, ocsf_data: Dict[str, Any]) -> str:
        """Ingest vulnerability finding"""
        vuln_data = ocsf_data.get("vulnerability", {})
        asset_data = ocsf_data.get("asset")
        
        # Create vulnerability node
        vuln_props = {
            "cve": vuln_data.get("cve"),
            "name": vuln_data.get("name"),
            "description": vuln_data.get("description"),
            "severity_id": ocsf_data.get("severity_id"),
            "severity": ocsf_data.get("severity"),
            "risk_score": self._calculate_risk_score(ocsf_data),
            "source": ocsf_data.get("metadata", {}).get("source"),
            "timestamp": ocsf_data.get("time"),
        }
        vuln_id = await self.graph.create_node("Vulnerability", vuln_props)
        
        # Link to asset if provided
        if asset_data:
            asset_id = await self._ensure_asset(asset_data)
            await self.graph.create_relationship(
                asset_id, 
                vuln_id, 
                "HAS_VULNERABILITY",
                {"discovered_at": ocsf_data.get("time")}
            )
        
        return vuln_id
    
    async def _ingest_finding(self, ocsf_data: Dict[str, Any]) -> str:
        """Ingest security finding"""
        finding_data = ocsf_data.get("finding", {})
        
        finding_props = {
            "title": finding_data.get("title"),
            "description": finding_data.get("description"),
            "uid": finding_data.get("uid"),
            "severity_id": ocsf_data.get("severity_id"),
            "severity": ocsf_data.get("severity"),
            "risk_score": self._calculate_risk_score(ocsf_data),
            "source": ocsf_data.get("metadata", {}).get("source"),
            "timestamp": ocsf_data.get("time"),
        }
        finding_id = await self.graph.create_node("Finding", finding_props)
        
        # Link to resources if provided
        resources = ocsf_data.get("resources", [])
        for resource in resources:
            resource_id = await self._ensure_asset(resource)
            await self.graph.create_relationship(
                resource_id,
                finding_id,
                "AFFECTED_BY",
                {}
            )
        
        return finding_id
    
    async def _ingest_asset(self, ocsf_data: Dict[str, Any]) -> str:
        """Ingest asset inventory data"""
        asset_data = ocsf_data.get("asset", {})
        return await self._ensure_asset(asset_data)
    
    async def _ensure_asset(self, asset_data: Dict[str, Any]) -> str:
        """Ensure asset exists, create if not"""
        # Check if asset already exists
        query = (
            "MATCH (a:Asset {name: $name, hostname: $hostname}) "
            "RETURN id(a) as node_id LIMIT 1"
        )
        results = await self.graph.query(query, {
            "name": asset_data.get("name"),
            "hostname": asset_data.get("hostname")
        })
        
        if results:
            return str(results[0]["node_id"])
        
        # Create new asset
        asset_props = {
            "name": asset_data.get("name"),
            "hostname": asset_data.get("hostname"),
            "ip_address": asset_data.get("ip"),
            "asset_type": asset_data.get("type"),
            "criticality": asset_data.get("criticality", "medium"),
        }
        return await self.graph.create_node("Asset", asset_props)
    
    def _calculate_risk_score(self, ocsf_data: Dict[str, Any]) -> int:
        """
        Calculate risk score from OCSF data
        
        Args:
            ocsf_data: OCSF data dictionary
            
        Returns:
            Risk score (0-10)
        """
        severity_id = ocsf_data.get("severity_id", 0)
        base_score = severity_id  # OCSF severity_id maps well to risk
        
        # Add source-specific adjustments
        source = ocsf_data.get("metadata", {}).get("source", "")
        if "critical" in source.lower():
            base_score = min(10, base_score + 1)
        
        return min(10, max(0, base_score))
    
    async def enrich_with_context(self, node_id: str) -> Dict[str, Any]:
        """Enrich a node with contextual information from the graph"""
        query = (
            "MATCH (n) WHERE id(n) = $node_id "
            "OPTIONAL MATCH (n)-[r]-(related) "
            "RETURN n, collect({rel: type(r), node: related}) as context"
        )
        results = await self.graph.query(query, {"node_id": int(node_id)})
        
        if results:
            return {
                "node": dict(results[0]["n"]),
                "context": results[0]["context"]
            }
        return {}


# Global contextualizer instance
contextualizer = Contextualizer()

