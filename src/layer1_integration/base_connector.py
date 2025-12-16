"""Base connector interface for all integration connectors"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from datetime import datetime
import structlog
from ..common.exceptions import ConnectorError, AuthenticationError
from .secrets_manager import get_secrets_manager

logger = structlog.get_logger(__name__)


class BaseConnector(ABC):
    """Base class for all security tool connectors"""
    
    def __init__(self, connector_id: str, connector_name: str, config: Dict[str, Any]):
        """
        Initialize connector
        
        Args:
            connector_id: Unique identifier for this connector instance
            connector_name: Human-readable name of the connector
            config: Configuration dictionary
        """
        self.connector_id = connector_id
        self.connector_name = connector_name
        self.config = config
        self.logger = logger.bind(connector_id=connector_id, connector_name=connector_name)
        self._authenticated = False
        try:
            self.secrets_manager = get_secrets_manager()
        except Exception as e:
            self.logger.warning("Secrets manager not available, falling back to config", error=str(e))
            self.secrets_manager = None
    
    @abstractmethod
    async def authenticate(self) -> bool:
        """
        Authenticate with the security tool API.
        
        This method should handle token retrieval, key validation, and setting the internal `_authenticated` flag.
        Connectors should handle transient authentication errors and log details.
        
        Returns:
            True if authentication successful, False otherwise.
            
        Raises:
            AuthenticationError: If credentials are permanently invalid or access is denied.
        """
        pass
    
    @abstractmethod
    async def fetch(self, since: Optional[datetime] = None, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Fetch alerts/data from the security tool.
        
        Implementers should handle pagination internally or respect the `limit` argument if provided.
        
        Args:
            since: Timestamp to filter data for incremental sync. If None, fetch recent or all data depending on policy.
            limit: Maximum number of records to return in this batch.
            
        Returns:
            List of raw data dictionaries (not yet normalized).
            
        Raises:
            ConnectorError: If network issues or API errors occur during fetch.
        """
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """
        Check if the connector can connect to the API.
        
        A lightweight check (e.g., ping, version check) to verify API connectivity and credential validity.
        
        Returns:
            True if healthy (API reachable and authorized), False otherwise.
        """
        pass
    
    @property
    def is_authenticated(self) -> bool:
        """Check if connector is authenticated"""
        return self._authenticated
    
    def get_metadata(self) -> Dict[str, Any]:
        """Get connector metadata"""
        return {
            "connector_id": self.connector_id,
            "connector_name": self.connector_name,
            "authenticated": self._authenticated,
            "config_keys": list(self.config.keys()),
        }
    
    async def test_connection(self) -> bool:
        """
        Test the connection by performing authentication and health check.
        
        This is a convenience method often used during onboarding or configuration validation.
        
        Returns:
            True if both authentication and health check pass.
        """
        try:
            auth_result = await self.authenticate()
            if not auth_result:
                self.logger.warning("Authentication failed during connection test")
                return False
            return await self.health_check()
        except Exception as e:
            self.logger.error("Connection test experienced an error", error=str(e))
            return False

