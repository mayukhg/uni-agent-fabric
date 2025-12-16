"""Custom exceptions for the Universal Agentic Fabric"""


class UniversalAgenticFabricError(Exception):
    """
    Base exception for all fabric errors. 
    
    This serves as the root exception class for the application to catch all internal errors.
    """
    pass


class ConnectorError(UniversalAgenticFabricError):
    """
    Error in connector operations.
    
    Raised when a connector fails to fetch data, connect, or process an external request.
    """
    pass


class AuthenticationError(ConnectorError):
    """
    Authentication failure.
    
    Raised when a connector's credentials (API key, token) are invalid or expired.
    """
    pass


class NormalizationError(UniversalAgenticFabricError):
    """
    Error in data normalization.
    
    Raised during the transformation of vendor-specific data into OCSF schema.
    """
    pass


class OCSFValidationError(NormalizationError):
    """
    OCSF schema validation error.
    
    Raised when transformed data fails to validate against the required OCSF schema constraints.
    """
    pass


class GraphDatabaseError(UniversalAgenticFabricError):
    """
    Error in graph database operations.
    
    Raised when queries to Neo4j or Neptune fail, or when connection issues occur with the graph backend.
    """
    pass


class SecretsManagementError(UniversalAgenticFabricError):
    """
    Error in secrets management.
    
    Raised when secrets cannot be retrieved from the backend (Vault, AWS SM) or are missing.
    """
    pass


class CircuitBreakerOpenError(UniversalAgenticFabricError):
    """
    Circuit breaker is open.
    
    Raised when an operation is attempted on a service that has recently failed too many times, skipping execution.
    """
    pass

