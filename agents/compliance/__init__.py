"""Agentes de Cumplimiento y Reportes — 10 agentes."""

from agents.compliance.compliance_auditor import ComplianceAuditorAgent
from agents.compliance.report_generator import ReportGeneratorAgent
from agents.compliance.executive_dashboard import ExecutiveDashboardAgent
from agents.compliance.sla_monitor import SLAMonitorAgent
from agents.compliance.kpi_tracker import KPITrackerAgent
from agents.compliance.risk_scorer import RiskScorerAgent
from agents.compliance.audit_trail_manager import AuditTrailManagerAgent
from agents.compliance.policy_enforcer import PolicyEnforcerAgent
from agents.compliance.security_scorecard import SecurityScorecardAgent
from agents.compliance.regulatory_reporter import RegulatoryReporterAgent

__all__ = [
    "ComplianceAuditorAgent", "ReportGeneratorAgent", "ExecutiveDashboardAgent",
    "SLAMonitorAgent", "KPITrackerAgent", "RiskScorerAgent",
    "AuditTrailManagerAgent", "PolicyEnforcerAgent", "SecurityScorecardAgent",
    "RegulatoryReporterAgent",
]
