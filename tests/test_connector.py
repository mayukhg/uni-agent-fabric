"""Tests for connector framework"""

import pytest
from src.layer1_integration.base_connector import BaseConnector
from src.layer1_integration.connector_registry import ConnectorRegistry


class MockConnector(BaseConnector):
    """Mock connector for testing"""
    
    async def authenticate(self) -> bool:
        return True
    
    async def fetch(self, since=None, limit=None):
        return [{"id": "test-1", "data": "test"}]
    
    async def health_check(self) -> bool:
        return True


def test_connector_registry():
    """Test connector registry"""
    registry = ConnectorRegistry()
    registry.register("mock", MockConnector)
    
    assert "mock" in registry.list_connectors()
    
    connector = registry.create_instance("test-1", "mock", {})
    assert connector is not None
    assert connector.connector_id == "test-1"

