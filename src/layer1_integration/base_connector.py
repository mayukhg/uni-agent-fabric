"""Base connector interface for all integration connectors"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from datetime import datetime
import structlog
from ..common.exceptions import ConnectorError, AuthenticationError

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
    
    @abstractmethod
    async def authenticate(self) -> bool:
        """
        Authenticate with the security tool API
        
        Returns:
            True if authentication successful, False otherwise
            
        Raises:
            AuthenticationError: If authentication fails
        """
        pass
    
    @abstractmethod
    async def fetch(self, since: Optional[datetime] = None, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Fetch alerts/data from the security tool
        
        Args:
            since: Fetch data since this timestamp (for incremental fetching)
            limit: Maximum number of records to fetch
            
        Returns:
            List of raw alert/data dictionaries
            
        Raises:
            ConnectorError: If fetch operation fails
        """
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """
        Check if the connector can connect to the API
        
        Returns:
            True if healthy, False otherwise
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
        Test the connection by performing authentication and health check
        
        Returns:
            True if connection is successful
        """
        try:
            auth_result = await self.authenticate()
            if not auth_result:
                return False
            return await self.health_check()
        except Exception as e:
            self.logger.error("Connection test failed", error=str(e))
            return False

