"""Graph database client for Neo4j and Amazon Neptune"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
import structlog
from ..common.exceptions import GraphDatabaseError
from ..common.config import settings

logger = structlog.get_logger(__name__)


class GraphClient(ABC):
    """Abstract base class for graph database clients"""
    
    @abstractmethod
    async def create_node(self, label: str, properties: Dict[str, Any]) -> str:
        """Create a node and return its ID"""
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
    async def find_high_risk_nodes(self, threshold: int = 7) -> List[Dict[str, Any]]:
        """Find nodes with high risk scores"""
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """Check database health"""
        pass


class Neo4jClient(GraphClient):
    """Neo4j graph database client"""
    
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
    
    async def find_high_risk_nodes(self, threshold: int = 7) -> List[Dict[str, Any]]:
        """Find nodes with risk_score >= threshold"""
        query = (
            "MATCH (n) "
            "WHERE n.risk_score >= $threshold "
            "RETURN n, labels(n) as labels, id(n) as node_id "
            "ORDER BY n.risk_score DESC"
        )
        results = await self.query(query, {"threshold": threshold})
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
    
    if db_type == "neo4j":
        return Neo4jClient()
    elif db_type == "neptune":
        # Neptune implementation would use Gremlin
        raise GraphDatabaseError("Amazon Neptune not yet implemented")
    else:
        raise GraphDatabaseError(f"Unknown graph database type: {db_type}")

