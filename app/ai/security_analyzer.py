"""
AI-Powered Security Analyzer for authentication events
Safe for FastAPI, JWT, refresh-token rotation, and async usage
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


# =========================
# ENUMS
# =========================

class SecurityRiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# =========================
# DATA MODELS
# =========================

@dataclass
class SecurityEvent:
    """
    Represents a security-related event in the authentication system
    """
    timestamp: datetime
    event_type: str              # login_attempt, failed_login, logout, token_refresh, etc.
    ip_address: str
    user_id: Optional[int]
    user_email: Optional[str]
    success: bool
    details: Dict[str, str]


@dataclass
class SecurityAnalysis:
    """
    Result of AI-powered security analysis
    """
    risk_level: SecurityRiskLevel
    confidence_score: float          # 0.0 - 1.0
    threats_identified: List[str]
    recommendations: List[str]
    anomaly_score: float             # 0.0 - 1.0


# =========================
# ANALYZER
# =========================

class SecurityAnalyzer:
    """
    AI-powered analyzer for authentication & session security
    """

    def __init__(self):
        self.event_history: List[SecurityEvent] = []

        self.risk_thresholds = {
            SecurityRiskLevel.LOW: 0.3,
            SecurityRiskLevel.MEDIUM: 0.6,
            SecurityRiskLevel.HIGH: 0.8,
            SecurityRiskLevel.CRITICAL: 0.95,
        }

    # ---------------------
    # PUBLIC API
    # ---------------------

    def add_event(self, event: SecurityEvent) -> None:
        """
        Safely add an event and keep last 24 hours only
        """

        # Defensive timestamp normalization
        event.timestamp = self._normalize_timestamp(event.timestamp)

        self.event_history.append(event)

        cutoff_time = datetime.utcnow() - timedelta(hours=24)

        self.event_history = [
            e for e in self.event_history
            if e.timestamp > cutoff_time
        ]

    def analyze_login_pattern(self, user_id: int, ip_address: str) -> SecurityAnalysis:
        """
        Analyze user login behavior for anomalies
        """

        user_events = [
            e for e in self.event_history
            if e.user_id == user_id
        ]

        if len(user_events) < 2:
            return self._low_risk_baseline()

        temporal_score = self._analyze_temporal_pattern(user_events)
        geo_score = self._analyze_geographic_pattern(user_events, ip_address)
        frequency_score = self._analyze_frequency_pattern(user_events)

        anomaly_score = min(
            (temporal_score + geo_score + frequency_score) / 3,
            1.0
        )

        risk_level = self._score_to_risk_level(anomaly_score)

        threats, recommendations = self._build_findings(
            temporal_score,
            geo_score,
            frequency_score
        )

        return SecurityAnalysis(
            risk_level=risk_level,
            confidence_score=0.85,
            threats_identified=threats,
            recommendations=recommendations,
            anomaly_score=anomaly_score,
        )

    # ---------------------
    # INTERNAL ANALYSIS
    # ---------------------

    def _analyze_temporal_pattern(self, events: List[SecurityEvent]) -> float:
        events = sorted(events, key=lambda e: e.timestamp)

        latest = events[-1]
        previous = events[-2]

        delta_hours = (latest.timestamp - previous.timestamp).total_seconds() / 3600

        if delta_hours < 0.1:        # < 6 minutes
            return 0.85
        elif delta_hours < 2:
            return 0.5
        elif delta_hours < 24:
            return 0.3
        else:
            return 0.15

    def _analyze_geographic_pattern(
        self,
        events: List[SecurityEvent],
        current_ip: str
    ) -> float:

        known_ips = {e.ip_address for e in events if e.ip_address}

        return 0.1 if current_ip in known_ips else 0.7

    def _analyze_frequency_pattern(self, events: List[SecurityEvent]) -> float:
        window_start = datetime.utcnow() - timedelta(minutes=10)

        recent_events = [
            e for e in events
            if e.timestamp > window_start
        ]

        if len(recent_events) > 5:
            return 0.9
        elif len(recent_events) > 2:
            return 0.6
        else:
            return 0.2

    # ---------------------
    # HELPERS
    # ---------------------

    def _normalize_timestamp(self, ts) -> datetime:
        """
        Guarantees timestamp is datetime
        """
        if isinstance(ts, datetime):
            return ts

        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts)
            except ValueError:
                logger.warning("Invalid timestamp format, using utcnow()")
                return datetime.utcnow()

        logger.warning("Unknown timestamp type, using utcnow()")
        return datetime.utcnow()

    def _score_to_risk_level(self, score: float) -> SecurityRiskLevel:
        if score >= self.risk_thresholds[SecurityRiskLevel.CRITICAL]:
            return SecurityRiskLevel.CRITICAL
        if score >= self.risk_thresholds[SecurityRiskLevel.HIGH]:
            return SecurityRiskLevel.HIGH
        if score >= self.risk_thresholds[SecurityRiskLevel.MEDIUM]:
            return SecurityRiskLevel.MEDIUM
        return SecurityRiskLevel.LOW

    def _build_findings(
        self,
        temporal: float,
        geo: float,
        frequency: float
    ) -> tuple[list[str], list[str]]:

        threats = []
        recommendations = []

        if temporal > 0.7:
            threats.append("Unusual login timing detected")
            recommendations.append("Require multi-factor authentication")

        if geo > 0.7:
            threats.append("Login from unknown location")
            recommendations.append("Verify IP geolocation")

        if frequency > 0.7:
            threats.append("High request frequency")
            recommendations.append("Monitor for brute-force attempts")

        return threats, recommendations

    def _low_risk_baseline(self) -> SecurityAnalysis:
        return SecurityAnalysis(
            risk_level=SecurityRiskLevel.LOW,
            confidence_score=0.75,
            threats_identified=[],
            recommendations=["Continue monitoring to establish baseline"],
            anomaly_score=0.1,
        )


# =========================
# SINGLETON INSTANCE
# =========================

security_analyzer = SecurityAnalyzer()
