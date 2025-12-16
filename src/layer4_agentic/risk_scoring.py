"""Risk scoring engine that works with OCSF data"""

from typing import Dict, Any
import structlog
from ..layer2_normalization.ocsf_schema import OCSFSeverityID

logger = structlog.get_logger(__name__)


class RiskScoringEngine:
    """Universal risk scoring engine for OCSF data"""
    
    def __init__(self):
        self.logger = logger
    
    def calculate_risk_score(self, ocsf_data: Dict[str, Any]) -> int:
        """
        Calculate risk score from OCSF data (vendor-agnostic)
        
        Args:
            ocsf_data: OCSF-formatted data dictionary
            
        Returns:
            Risk score (0-10)
        """
        # Base score from severity
        severity_id = ocsf_data.get("severity_id", OCSFSeverityID.UNKNOWN)
        base_score = int(severity_id)
        
        # Adjustments based on data type
        class_uid = ocsf_data.get("class_uid")
        
        if class_uid == 2002:  # Vulnerability Finding
            base_score = self._score_vulnerability(ocsf_data, base_score)
        elif class_uid == 2001:  # Finding
            base_score = self._score_finding(ocsf_data, base_score)
        
        # Time-based decay (older findings get lower scores)
        base_score = self._apply_time_decay(ocsf_data, base_score)
        
        return min(10, max(0, base_score))
    
    def _score_vulnerability(self, ocsf_data: Dict[str, Any], base_score: int) -> int:
        """Score vulnerability finding"""
        vuln = ocsf_data.get("vulnerability", {})
        
        # CVE presence increases risk
        if vuln.get("cve"):
            base_score += 1
        
        # Known exploit increases risk
        if vuln.get("exploit_available"):
            base_score += 2
        
        return base_score
    
    def _score_finding(self, ocsf_data: Dict[str, Any], base_score: int) -> int:
        """Score security finding"""
        finding = ocsf_data.get("finding", {})
        
        # Title keywords that indicate higher risk
        high_risk_keywords = ["breach", "compromise", "unauthorized", "malware", "ransomware"]
        title = finding.get("title", "").lower()
        
        for keyword in high_risk_keywords:
            if keyword in title:
                base_score += 1
                break
        
        return base_score
    
    def _apply_time_decay(self, ocsf_data: Dict[str, Any], base_score: int) -> int:
        """Apply time-based decay to risk score"""
        from datetime import datetime
        
        event_time = ocsf_data.get("time")
        if not event_time:
            return base_score
        
        try:
            if isinstance(event_time, int):
                event_dt = datetime.fromtimestamp(event_time)
            else:
                event_dt = datetime.fromisoformat(str(event_time))
            
            now = datetime.now(event_dt.tzinfo) if event_dt.tzinfo else datetime.now()
            age_hours = (now - event_dt).total_seconds() / 3600
            
            # Reduce score for alerts older than 24 hours
            if age_hours > 24:
                decay_factor = max(0.5, 1 - (age_hours - 24) / 168)  # Decay over a week
                base_score = int(base_score * decay_factor)
        except Exception:
            pass
        
        return base_score


# Global risk scoring engine
risk_scoring_engine = RiskScoringEngine()

