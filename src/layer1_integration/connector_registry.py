"""Connector registry for dynamic connector discovery and loading"""

from typing import Dict, Type, Optional, List
import importlib
import inspect
from pathlib import Path
import structlog
from .base_connector import BaseConnector
from ..common.exceptions import ConnectorError

logger = structlog.get_logger(__name__)


class ConnectorRegistry:
    """Registry for managing connector classes and instances"""
    
    def __init__(self):
        self._connectors: Dict[str, Type[BaseConnector]] = {}
        self._instances: Dict[str, BaseConnector] = {}
        self.logger = logger
    
    def register(self, connector_name: str, connector_class: Type[BaseConnector]) -> None:
        """
        Register a connector class
        
        Args:
            connector_name: Unique name for the connector
            connector_class: Connector class that extends BaseConnector
        """
        if not issubclass(connector_class, BaseConnector):
            raise ConnectorError(f"Connector class must extend BaseConnector: {connector_class}")
        
        self._connectors[connector_name.lower()] = connector_class
        self.logger.info("Connector registered", connector_name=connector_name)
    
    def get_connector_class(self, connector_name: str) -> Optional[Type[BaseConnector]]:
        """
        Get a connector class by name
        
        Args:
            connector_name: Name of the connector
            
        Returns:
            Connector class or None if not found
        """
        return self._connectors.get(connector_name.lower())
    
    def create_instance(
        self, 
        connector_id: str, 
        connector_name: str, 
        config: Dict
    ) -> BaseConnector:
        """
        Create a connector instance
        
        Args:
            connector_id: Unique identifier for the instance
            connector_name: Name of the connector type
            config: Configuration dictionary
            
        Returns:
            Connector instance
            
        Raises:
            ConnectorError: If connector not found or creation fails
        """
        connector_class = self.get_connector_class(connector_name)
        if not connector_class:
            raise ConnectorError(f"Connector not found: {connector_name}")
        
        try:
            instance = connector_class(connector_id, connector_name, config)
            self._instances[connector_id] = instance
            self.logger.info("Connector instance created", connector_id=connector_id, connector_name=connector_name)
            return instance
        except Exception as e:
            raise ConnectorError(f"Failed to create connector instance: {e}")
    
    def get_instance(self, connector_id: str) -> Optional[BaseConnector]:
        """Get a connector instance by ID"""
        return self._instances.get(connector_id)
    
    def list_connectors(self) -> List[str]:
        """List all registered connector names"""
        return list(self._connectors.keys())
    
    def list_instances(self) -> List[str]:
        """List all active connector instance IDs"""
        return list(self._instances.keys())
    
    def load_connectors_from_module(self, module_path: str) -> None:
        """
        Dynamically load connectors from a module
        
        Args:
            module_path: Python module path (e.g., 'connectors.splunk')
        """
        try:
            module = importlib.import_module(module_path)
            for name, obj in inspect.getmembers(module):
                if (inspect.isclass(obj) and 
                    issubclass(obj, BaseConnector) and 
                    obj != BaseConnector):
                    # Use class name as connector name
                    connector_name = obj.__name__.replace("Connector", "").lower()
                    self.register(connector_name, obj)
                    self.logger.info("Connector loaded from module", module=module_path, connector=connector_name)
        except Exception as e:
            self.logger.error("Failed to load connectors from module", module=module_path, error=str(e))
            raise ConnectorError(f"Failed to load connectors from {module_path}: {e}")


# Global registry instance
registry = ConnectorRegistry()

