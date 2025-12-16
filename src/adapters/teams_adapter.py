"""Microsoft Teams output adapter"""

import httpx
from typing import Dict, Any
from .base_adapter import BaseOutputAdapter
import structlog

logger = structlog.get_logger(__name__)


class TeamsAdapter(BaseOutputAdapter):
    """Microsoft Teams webhook adapter"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.webhook_url = config.get("webhook_url")
        self.client = httpx.AsyncClient(timeout=10.0)
    
    async def format_message(self, decision: Dict[str, Any], reasoning_log: list) -> Dict[str, Any]:
        """Format message for Teams (returns card JSON)"""
        risk_score = decision.get("risk_score", 0)
        action = decision.get("action", "unknown")
        source = decision.get("source", "unknown")
        node_id = decision.get("node_id", "unknown")
        
        # Determine color based on risk
        color = "FF0000" if risk_score >= 9 else "FF8800" if risk_score >= 7 else "FFAA00"
        
        card = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": f"Security Alert - Risk Score: {risk_score}",
            "themeColor": color,
            "title": "Security Alert",
            "sections": [
                {
                    "activityTitle": f"Risk Score: {risk_score}/10",
                    "activitySubtitle": f"Action Required: {action.upper()}",
                    "facts": [
                        {"name": "Source", "value": source},
                        {"name": "Node ID", "value": node_id},
                        {"name": "Timestamp", "value": decision.get("timestamp", "unknown")}
                    ]
                },
                {
                    "title": "Reasoning",
                    "text": "\n".join(reasoning_log[-3:])  # Last 3 entries
                }
            ]
        }
        
        return card
    
    async def send(self, message: Dict[str, Any]) -> bool:
        """Send message to Teams"""
        if not self.webhook_url:
            self.logger.error("Teams webhook URL not configured")
            return False
        
        try:
            card = await self.format_message(
                message.get("decision", {}),
                message.get("reasoning_log", [])
            )
            
            response = await self.client.post(self.webhook_url, json=card)
            response.raise_for_status()
            
            self.logger.info("Message sent to Teams")
            return True
        except Exception as e:
            self.logger.error("Failed to send to Teams", error=str(e))
            return False

