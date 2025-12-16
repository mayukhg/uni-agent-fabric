"""Custom exceptions for the Universal Agentic Fabric"""


class UniversalAgenticFabricError(Exception):
    """Base exception for all fabric errors"""
    pass


class ConnectorError(UniversalAgenticFabricError):
    """Error in connector operations"""
    pass


class AuthenticationError(ConnectorError):
    """Authentication failure"""
    pass


class NormalizationError(UniversalAgenticFabricError):
    """Error in data normalization"""
    pass


class OCSFValidationError(NormalizationError):
    """OCSF schema validation error"""
    pass


class GraphDatabaseError(UniversalAgenticFabricError):
    """Error in graph database operations"""
    pass


class SecretsManagementError(UniversalAgenticFabricError):
    """Error in secrets management"""
    pass


class CircuitBreakerOpenError(UniversalAgenticFabricError):
    """Circuit breaker is open"""
    pass

