"""LangGraph state machine for risk detection and decision making"""

from typing import TypedDict, List, Dict, Any, Optional
from datetime import datetime
import structlog
from langgraph.graph import StateGraph, END
from ..layer3_moat.graph_client import get_graph_client
from ..common.exceptions import GraphDatabaseError
from .iac_parser import IaCParser

logger = structlog.get_logger(__name__)


class AgentState(TypedDict):
    """State for the agentic state machine"""
    high_risk_nodes: List[Dict[str, Any]]
    iac_risks: List[Dict[str, Any]]
    risk_scores: Dict[str, int]
    decisions: List[Dict[str, Any]]
    reasoning_log: List[str]
    source_attribution: Dict[str, str]
    threshold: int


class RiskDetectionStateMachine:
    """LangGraph state machine for detecting and responding to high-risk objects"""
    
    def __init__(self, threshold: int = 7, iac_path: str = "./terraform"):
        self.graph_client = get_graph_client()
        self.iac_parser = IaCParser()
        self.iac_path = iac_path
        self.threshold = threshold
        self.logger = logger
        self.workflow = self._build_workflow()
    
    def _build_workflow(self) -> StateGraph:
        """Build the LangGraph workflow"""
        workflow = StateGraph(AgentState)
        
        # Add nodes
        workflow.add_node("query_graph", self._query_graph_node)
        workflow.add_node("scan_iac", self._scan_iac_node)
        workflow.add_node("analyze_risks", self._analyze_risks_node)
        workflow.add_node("make_decisions", self._make_decisions_node)
        workflow.add_node("log_reasoning", self._log_reasoning_node)
        
        # Define edges
        workflow.set_entry_point("query_graph")
        workflow.add_edge("query_graph", "scan_iac")
        workflow.add_edge("scan_iac", "analyze_risks")
        workflow.add_edge("analyze_risks", "make_decisions")
        workflow.add_edge("make_decisions", "log_reasoning")
        workflow.add_edge("log_reasoning", END)
        
        return workflow.compile()
    
    async def _query_graph_node(self, state: AgentState) -> AgentState:
        """Query graph database for high-risk nodes"""
        self.logger.info("Querying graph for high-risk nodes", threshold=self.threshold)
        
        try:
            high_risk_nodes = await self.graph_client.find_high_risk_nodes(self.threshold)
            
            state["high_risk_nodes"] = [
                {
                    "node_id": str(node["node_id"]),
                    "data": dict(node["n"]),
                    "labels": node.get("labels", [])
                }
                for node in high_risk_nodes
            ]
            
            self.logger.info("Found high-risk nodes", count=len(state["high_risk_nodes"]))
        except Exception as e:
            self.logger.error("Failed to query graph", error=str(e))
            state["high_risk_nodes"] = []
        
        return state
    
    async def _scan_iac_node(self, state: AgentState) -> AgentState:
        """Scan Infrastructure as Code files for risks"""
        self.logger.info("Scanning IaC files", path=self.iac_path)
        try:
            # Note: This is synchronous in current implementation
            iac_risks = self.iac_parser.parse_directory(self.iac_path)
            state["iac_risks"] = iac_risks
            self.logger.info("IaC scan complete", risk_count=len(iac_risks))
        except Exception as e:
            self.logger.error("Failed to scan IaC", error=str(e))
            state["iac_risks"] = []
        return state
    
    async def _analyze_risks_node(self, state: AgentState) -> AgentState:
        """Analyze risks and calculate composite scores"""
        self.logger.info("Analyzing risks", node_count=len(state["high_risk_nodes"]))
        
        risk_scores = {}
        source_attribution = {}
        
        # Process Graph Nodes
        for node in state["high_risk_nodes"]:
            node_id = node["node_id"]
            node_data = node["data"]
            
            composite_score = self._calculate_composite_risk(node_data, node)
            risk_scores[node_id] = composite_score
            
            source = node_data.get("source", "unknown")
            source_attribution[node_id] = source
            
        # Process IaC Risks
        for idx, risk in enumerate(state.get("iac_risks", [])):
            risk_id = f"iac_{idx}_{risk['rule_id']}"
            risk_scores[risk_id] = risk["risk_score"]
            source_attribution[risk_id] = f"iac_scanner:{risk['file']}"
        
        state["risk_scores"] = risk_scores
        state["source_attribution"] = source_attribution
        state["threshold"] = self.threshold
        
        return state
    
    async def _make_decisions_node(self, state: AgentState) -> AgentState:
        """Make decisions based on risk scores with Safety Guardrails"""
        self.logger.info("Making decisions", risk_count=len(state["risk_scores"]))
        
        # Import here to avoid circular dependencies if any
        from .approvals import approval_manager
        
        decisions = []
        
        for node_id, risk_score in state["risk_scores"].items():
            if risk_score >= self.threshold:
                source = state["source_attribution"].get(node_id, "unknown")
                
                # SAFETY RAIL: Critical risks require human approval
                if risk_score >= 9:
                    action = "PENDING_APPROVAL"
                    description = f"High risk detected (Score: {risk_score}). Source: {source}"
                    op_id = approval_manager.request_approval(
                        risk_score=risk_score,
                        description=description,
                        action_type="remediate",
                        target=node_id,
                        metadata={"source": source}
                    )
                    self.logger.warning("Safety Guardrail Triggered", node_id=node_id, op_id=op_id)
                else:
                    action = "remediate" if risk_score >= 8 else "investigate"
                
                decision = {
                    "node_id": node_id,
                    "risk_score": risk_score,
                    "action": action,
                    "source": source,
                    "timestamp": datetime.now().isoformat(),
                }
                decisions.append(decision)
                
                self.logger.warning(
                    "Decision made",
                    node_id=node_id,
                    risk_score=risk_score,
                    action=decision["action"],
                    source=source
                )
        
        state["decisions"] = decisions
        return state
    
    async def _log_reasoning_node(self, state: AgentState) -> AgentState:
        """Generate reasoning log with source attribution"""
        reasoning_log = []
        
        reasoning_log.append(f"Analysis completed at {datetime.now().isoformat()}")
        reasoning_log.append(f"Found {len(state['high_risk_nodes'])} high-risk nodes")
        reasoning_log.append(f"Found {len(state.get('iac_risks', []))} IaC risks")
        reasoning_log.append(f"Risk threshold: {self.threshold}")
        
        for decision in state["decisions"]:
            source = decision["source"]
            reasoning_log.append(
                f"Based on data from {source}: "
                f"Node {decision['node_id']} has risk score {decision['risk_score']}. "
                f"Action: {decision['action']}"
            )
        
        state["reasoning_log"] = reasoning_log
        
        # Log reasoning
        for entry in reasoning_log:
            self.logger.info("Reasoning", entry=entry)
        
        return state
    
    def _calculate_composite_risk(self, node_data: Dict[str, Any], node: Dict[str, Any]) -> int:
        """
        Calculate composite risk score considering multiple factors
        
        Args:
            node_data: Node data dictionary
            node: Full node information
            
        Returns:
            Composite risk score (0-10)
        """
        base_score = node_data.get("risk_score", 0)
        
        # Factor in severity
        severity_id = node_data.get("severity_id", 0)
        severity_factor = severity_id / 5.0  # Normalize to 0-1
        
        # Factor in asset criticality if available
        criticality_map = {"critical": 1.2, "high": 1.1, "medium": 1.0, "low": 0.9}
        criticality = node_data.get("criticality", "medium")
        criticality_factor = criticality_map.get(criticality, 1.0)
        
        # Calculate composite
        composite = int(base_score * (1 + severity_factor * 0.2) * criticality_factor)
        return min(10, max(0, composite))
    
    async def run(self) -> AgentState:
        """
        Run the state machine
        
        Returns:
            Final state with decisions and reasoning
        """
        initial_state: AgentState = {
            "high_risk_nodes": [],
            "iac_risks": [],
            "risk_scores": {},
            "decisions": [],
            "reasoning_log": [],
            "source_attribution": {},
            "threshold": self.threshold,
        }
        
        result = await self.workflow.ainvoke(initial_state)
        return result

