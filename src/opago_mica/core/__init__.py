"""
Core module barrel exports.

Re-exports UMAMiCAProtocol and ComplianceEngine for convenient top-level imports.
"""

from __future__ import annotations

from opago_mica.core.compliance_engine import (
    ComplianceDecision,
    ComplianceDecisionOutcome,
    ComplianceEngine,
    ComplianceEngineConfig,
    ComplianceEvaluationResult,
    ComplianceReport,
    KycComplianceInfo,
    ScreeningMatch,
    ScreeningOutcome,
    ScreeningResult,
    TravelRuleComplianceInfo,
    ValidationIssue,
    ValidationResult,
)
from opago_mica.core.uma_mica import UMAMiCAProtocol

__all__ = [
    "UMAMiCAProtocol",
    "ComplianceEngine",
    "ComplianceEngineConfig",
    "ComplianceDecision",
    "ComplianceDecisionOutcome",
    "ComplianceEvaluationResult",
    "ComplianceReport",
    "KycComplianceInfo",
    "ScreeningMatch",
    "ScreeningOutcome",
    "ScreeningResult",
    "TravelRuleComplianceInfo",
    "ValidationIssue",
    "ValidationResult",
]
