"""Graph database client for Neo4j and Amazon Neptune"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
import structlog
try:
    from gremlin_python.driver.driver_remote_connection import DriverRemoteConnection
    from gremlin_python.structure.graph import Graph
    from gremlin_python.process.graph_traversal import __
    from gremlin_python.process.traversal import T, P, Order
except ImportError:
    pass # Handle in __init__ if needed
from ..common.exceptions import GraphDatabaseError
from ..common.config import settings

logger = structlog.get_logger(__name__)


class GraphClient(ABC):
    """
    Abstract base class defining the interface for graph database interactions.
    
    This layer of abstraction allows the application to switch between Neo4j and Amazon Neptune
    (or other graph DBs) without changing business logic in upper layers.
    """
    
    @abstractmethod
    async def create_node(self, label: str, properties: Dict[str, Any]) -> str:
        """
        Create a new node with a specific label and properties.
        
        Args:
            label: The primary label/tag for the node (e.g., 'Asset', 'Finding').
            properties: Dictionary of key-value pairs to store on the node.
            
        Returns:
            str: The unique identifier (ID) of the created node.
        """
        pass
    
    @abstractmethod
    async def create_relationship(
        self, 
        from_id: str, 
        to_id: str, 
        rel_type: str, 
        properties: Optional[Dict] = None
    ) -> str:
        """Create a relationship between nodes"""
        pass
    
    @abstractmethod
    async def query(self, query: str, parameters: Optional[Dict] = None) -> List[Dict[str, Any]]:
        """Execute a query and return results"""
        pass
    
    @abstractmethod
    async def find_high_risk_nodes(self, threshold: int = 7, time_window: Optional[float] = None) -> List[Dict[str, Any]]:
        """
        Find nodes with high risk scores
        
        Args:
            threshold: Risk score threshold
            time_window: Only return nodes updated after this timestamp
        """
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """Check database health"""
        pass


class Neo4jClient(GraphClient):
    """
    Neo4j implementation using the official `neo4j` async driver.
    
    Executes Cypher queries directly against the database.
    Suitable for local development or on-premise deployments.
    """
    
    def __init__(self):
        try:
            from neo4j import AsyncGraphDatabase
        except ImportError:
            raise GraphDatabaseError("neo4j library not installed. Install with: pip install neo4j")
        
        self.uri = settings.neo4j_uri or "bolt://localhost:7687"
        self.user = settings.neo4j_user or "neo4j"
        self.password = settings.neo4j_password or "password"
        self.driver = AsyncGraphDatabase.driver(self.uri, auth=(self.user, self.password))
        self.logger = logger.bind(backend="neo4j")
    
    async def create_node(self, label: str, properties: Dict[str, Any]) -> str:
        """Create a node in Neo4j"""
        async with self.driver.session() as session:
            query = f"CREATE (n:{label} $props) RETURN id(n) as node_id"
            result = await session.run(query, props=properties)
            record = await result.single()
            node_id = str(record["node_id"]) if record else None
            self.logger.info("Node created", label=label, node_id=node_id)
            return node_id
    
    async def create_relationship(
        self, 
        from_id: str, 
        to_id: str, 
        rel_type: str, 
        properties: Optional[Dict] = None
    ) -> str:
        """Create a relationship in Neo4j"""
        async with self.driver.session() as session:
            query = (
                f"MATCH (a), (b) "
                f"WHERE id(a) = $from_id AND id(b) = $to_id "
                f"CREATE (a)-[r:{rel_type} $props]->(b) "
                f"RETURN id(r) as rel_id"
            )
            props = properties or {}
            result = await session.run(
                query, 
                from_id=int(from_id), 
                to_id=int(to_id), 
                props=props
            )
            record = await result.single()
            rel_id = str(record["rel_id"]) if record else None
            self.logger.info("Relationship created", rel_type=rel_type, rel_id=rel_id)
            return rel_id
    
    async def query(self, query: str, parameters: Optional[Dict] = None) -> List[Dict[str, Any]]:
        """Execute a Cypher query"""
        async with self.driver.session() as session:
            result = await session.run(query, parameters or {})
            records = []
            async for record in result:
                records.append(dict(record))
            return records
    
    async def find_high_risk_nodes(self, threshold: int = 7, time_window: Optional[float] = None) -> List[Dict[str, Any]]:
        """Find nodes with risk_score >= threshold, optionally filtered by update time"""
        query_parts = [
            "MATCH (n)",
            "WHERE n.risk_score >= $threshold"
        ]
        
        params = {"threshold": threshold}
        
        if time_window:
            query_parts.append("AND n.updated_at >= $time_window")
            params["time_window"] = time_window
            
        query_parts.append("RETURN n, labels(n) as labels, id(n) as node_id")
        query_parts.append("ORDER BY n.risk_score DESC")
        
        query = " ".join(query_parts)
        results = await self.query(query, params)
        return results
    
    async def health_check(self) -> bool:
        """Check Neo4j connection"""
        try:
            async with self.driver.session() as session:
                await session.run("RETURN 1")
            return True
        except Exception as e:
            self.logger.error("Neo4j health check failed", error=str(e))
            return False
    
    async def close(self):
        """Close the driver connection"""
        await self.driver.close()


def get_graph_client() -> GraphClient:
    """
    Factory function to get the appropriate graph client
    
    Returns:
        GraphClient instance
    """
    db_type = settings.graph_db_type.lower()
    
class NeptuneClient(GraphClient):
    """
    Amazon Neptune implementation using `gremlinpython`.
    
    Uses the Gremlin Traversal Language (Bytecode) for interactions.
    
    Security Note:
        - Raw string query execution is intentionally DISABLED to prevent validation/injection attacks.
        - All queries must be constructed using the Traversal API (`self.g.V()...`).
    """
    
    def __init__(self):
        try:
            from gremlin_python.driver.driver_remote_connection import DriverRemoteConnection
            from gremlin_python.structure.graph import Graph
        except ImportError:
            raise GraphDatabaseError("gremlinpython library not installed. Install with: pip install gremlinpython")
            
        self.endpoint = settings.neptune_endpoint or "localhost"
        self.port = settings.neptune_port or 8182
        self.url = f"ws://{self.endpoint}:{self.port}/gremlin"
        
        try:
            self.remote_connection = DriverRemoteConnection(self.url, 'g')
            self.graph = Graph()
            self.g = self.graph.traversal().withRemote(self.remote_connection)
            self.logger = logger.bind(backend="neptune")
        except Exception as e:
            raise GraphDatabaseError(f"Failed to connect to Neptune: {e}")

    async def create_node(self, label: str, properties: Dict[str, Any]) -> str:
        """Create a node in Neptune"""
        try:
            # Note: Gremlin is often synchronous in python driver unless using aiohttp transport explicitly configured
            # But here we assume standard driver usage. For true async, we might need to wrap in executor
            # For this implementation, we'll try to use the traversal api
            
            t = self.g.addV(label)
            for k, v in properties.items():
                t = t.property(k, v)
            
            # Add updated_at if not present
            if "updated_at" not in properties:
                import time
                t = t.property("updated_at", time.time())
                
            element = t.next()
            node_id = str(element.id)
            self.logger.info("Node created", label=label, node_id=node_id)
            return node_id
        except Exception as e:
            self.logger.error("Failed to create node", error=str(e))
            raise GraphDatabaseError(f"Neptune node creation failed: {e}")

    async def create_relationship(
        self, 
        from_id: str, 
        to_id: str, 
        rel_type: str, 
        properties: Optional[Dict] = None
    ) -> str:
        """Create a relationship in Neptune"""
        try:
            t = self.g.V(from_id).addE(rel_type).to(__.V(to_id))
            
            if properties:
                for k, v in properties.items():
                    t = t.property(k, v)
                    
            element = t.next()
            rel_id = str(element.id)
            self.logger.info("Relationship created", rel_type=rel_type, rel_id=rel_id)
            return rel_id
        except Exception as e:
            self.logger.error("Failed to create relationship", error=str(e))
            raise GraphDatabaseError(f"Neptune relationship creation failed: {e}")

    async def query(self, query: str, parameters: Optional[Dict] = None) -> List[Dict[str, Any]]:
        """
        Execute a Gremlin query (passed as string)
        
        WARNING: Raw Gremlin string execution is disabled for security reasons (Injection Risk).
        This method will raise an error for Neptune.
        """
        self.logger.error("Attempted to execute raw Gremlin query", query=query)
        raise GraphDatabaseError("Raw Gremlin/string queries are disabled for security. Use the Traversal API (bytecode) instead.")

    async def find_high_risk_nodes(self, threshold: int = 7, time_window: Optional[float] = None) -> List[Dict[str, Any]]:
        """Find nodes with high risk scores using Traversal API"""
        try:
            t = self.g.V().has("risk_score", P.gte(threshold))
            
            if time_window:
                t = t.has("updated_at", P.gte(time_window))
                
            t = t.project("node_id", "data", "labels") \
                 .by(__.id()) \
                 .by(__.valueMap(True)) \
                 .by(__.label()) \
                 .order().by(__.select("data").select("risk_score"), Order.desc)
                 
            # Convert to list
            input_results = t.toList()
            
            # Format results to match interface expectation
            results = []
            for r in input_results:
                results.append({
                    "node_id": str(r["node_id"]),
                    "data": self._clean_properties(r["data"]),
                    "labels": [r["labels"]] # Gremlin nodes usually have one label, but can have multiple
                })
                
            return results
        except Exception as e:
            self.logger.error("Failed to find high risk nodes", error=str(e))
            return []

    def _clean_properties(self, props: Dict) -> Dict:
        """Clean up Gremlin valueMap output (which wraps values in lists)"""
        clean = {}
        for k, v in props.items():
            if isinstance(v, list) and len(v) == 1:
                clean[str(k)] = v[0]
            else:
                clean[str(k)] = v
        return clean
        
    async def health_check(self) -> bool:
        """Check Neptune connection"""
        try:
            self.g.V().limit(1).toList()
            return True
        except Exception:
            return False
            
    async def close(self):
        self.remote_connection.close()


def get_graph_client() -> GraphClient:
    """
    Factory function to get the appropriate graph client
    
    Returns:
        GraphClient instance
    """
    db_type = settings.graph_db_type.lower()
    
    if db_type == "neo4j":
        return Neo4jClient()
    elif db_type == "neptune":
        return NeptuneClient()
    else:
        raise GraphDatabaseError(f"Unknown graph database type: {db_type}")

