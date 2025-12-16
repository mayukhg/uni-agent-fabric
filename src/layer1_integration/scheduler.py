"""Scheduling service for connector polling"""

from typing import Dict, Callable, Optional
from datetime import datetime, timedelta
import asyncio
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger
import structlog
from ..common.config import settings
from ..common.exceptions import ConnectorError
from .circuit_breaker import ConnectorCircuitBreaker

logger = structlog.get_logger(__name__)


class ConnectorScheduler:
    """Scheduler for managing connector polling intervals"""
    
    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self.jobs: Dict[str, str] = {}  # connector_id -> job_id
        self.circuit_breakers: Dict[str, ConnectorCircuitBreaker] = {}
        self.logger = logger
        self._running = False
    
    def start(self) -> None:
        """Start the scheduler"""
        if not self._running:
            self.scheduler.start()
            self._running = True
            self.logger.info("Scheduler started")
    
    def stop(self) -> None:
        """Stop the scheduler"""
        if self._running:
            self.scheduler.shutdown()
            self._running = False
            self.logger.info("Scheduler stopped")
    
    def schedule_connector(
        self,
        connector_id: str,
        fetch_func: Callable,
        interval_seconds: Optional[int] = None,
        cron_expression: Optional[str] = None
    ) -> None:
        """
        Schedule a connector for periodic fetching
        
        Args:
            connector_id: Unique identifier for the connector
            fetch_func: Async function to call for fetching
            interval_seconds: Polling interval in seconds (default from config)
            cron_expression: Optional cron expression for custom scheduling
        """
        if connector_id in self.jobs:
            self.unschedule_connector(connector_id)
        
        interval = interval_seconds or settings.default_polling_interval
        
        if cron_expression:
            trigger = CronTrigger.from_crontab(cron_expression)
        else:
            trigger = IntervalTrigger(seconds=interval)
        
        # Get or create circuit breaker for this connector
        if connector_id not in self.circuit_breakers:
            self.circuit_breakers[connector_id] = ConnectorCircuitBreaker(name=f"cb_{connector_id}")
            
        circuit_breaker = self.circuit_breakers[connector_id]
        
        # Wrap fetch function with circuit breaker
        async def protected_fetch():
            try:
                await circuit_breaker.call(fetch_func)
            except Exception as e:
                self.logger.error("Protected fetch failed", connector_id=connector_id, error=str(e))
        
        job_id = self.scheduler.add_job(
            func=protected_fetch,
            trigger=trigger,
            id=f"connector_{connector_id}",
            replace_existing=True,
            max_instances=1,
            misfire_grace_time=60
        )
        
        self.jobs[connector_id] = job_id.id
        self.logger.info(
            "Connector scheduled",
            connector_id=connector_id,
            interval=interval,
            cron=cron_expression
        )
    
    def unschedule_connector(self, connector_id: str) -> None:
        """Remove a connector from the schedule"""
        if connector_id in self.jobs:
            job_id = self.jobs[connector_id]
            try:
                self.scheduler.remove_job(job_id)
                del self.jobs[connector_id]
                self.logger.info("Connector unscheduled", connector_id=connector_id)
            except Exception as e:
                self.logger.error("Failed to unschedule connector", connector_id=connector_id, error=str(e))
    
    def get_next_run_time(self, connector_id: str) -> Optional[datetime]:
        """Get the next scheduled run time for a connector"""
        if connector_id not in self.jobs:
            return None
        
        job_id = self.jobs[connector_id]
        job = self.scheduler.get_job(job_id)
        return job.next_run_time if job else None
    
    def list_scheduled_connectors(self) -> list:
        """List all scheduled connector IDs"""
        return list(self.jobs.keys())
    
    async def trigger_now(self, connector_id: str, fetch_func: Callable) -> None:
        """Manually trigger a connector fetch immediately"""
        self.logger.info("Manual trigger requested", connector_id=connector_id)
        try:
            await fetch_func()
        except Exception as e:
            self.logger.error("Manual trigger failed", connector_id=connector_id, error=str(e))
            raise ConnectorError(f"Manual trigger failed: {e}")


# Global scheduler instance
scheduler = ConnectorScheduler()

