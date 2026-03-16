"""
utils/threat_model.py
Dataclasses and helpers for the threat analysis result.
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class ThreatResult:
    risk_score: int                  # 0–100
    detected_language: str           # e.g. "Marathi"
    confidence: int                  # language detection confidence 0–100
    urgency_detected: bool
    otp_request: bool
    bank_details_request: bool
    impersonation_detected: bool
    cultural_tactic: bool
    summary: str
    key_phrases: List[str] = field(default_factory=list)

    @property
    def risk_level(self) -> str:
        if self.risk_score >= 70:
            return "HIGH"
        elif self.risk_score >= 40:
            return "MEDIUM"
        return "LOW"

    @property
    def threat_count(self) -> int:
        return sum([
            self.urgency_detected,
            self.otp_request,
            self.bank_details_request,
            self.impersonation_detected,
            self.cultural_tactic,
        ])


def assess_risk_color(score: int) -> str:
    """Return a hex color string for the risk score."""
    if score >= 70:
        return "#FF4B4B"
    elif score >= 40:
        return "#F5A623"
    return "#00E5B4"
