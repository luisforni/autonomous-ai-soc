"""Agentes de Detección de Amenazas — 20 agentes."""

from agents.threats.malware_detector import MalwareDetectorAgent
from agents.threats.phishing_detector import PhishingDetectorAgent
from agents.threats.ransomware_detector import RansomwareDetectorAgent
from agents.threats.apt_detector import APTDetectorAgent
from agents.threats.lateral_movement_detector import LateralMovementDetectorAgent
from agents.threats.data_exfiltration_detector import DataExfiltrationDetectorAgent
from agents.threats.privilege_escalation_detector import PrivilegeEscalationDetectorAgent
from agents.threats.brute_force_detector import BruteForceDetectorAgent
from agents.threats.sql_injection_detector import SQLInjectionDetectorAgent
from agents.threats.xss_detector import XSSDetectorAgent
from agents.threats.zero_day_detector import ZeroDayDetectorAgent
from agents.threats.insider_threat_detector import InsiderThreatDetectorAgent
from agents.threats.ddos_detector import DDoSDetectorAgent
from agents.threats.c2_detector import C2DetectorAgent
from agents.threats.cryptomining_detector import CryptominingDetectorAgent
from agents.threats.rootkit_detector import RootkitDetectorAgent
from agents.threats.fileless_malware_detector import FilelessMalwareDetectorAgent
from agents.threats.supply_chain_detector import SupplyChainAttackDetectorAgent
from agents.threats.social_engineering_detector import SocialEngineeringDetectorAgent
from agents.threats.anomaly_detector import AnomalyDetectorAgent

__all__ = [
    "MalwareDetectorAgent", "PhishingDetectorAgent", "RansomwareDetectorAgent",
    "APTDetectorAgent", "LateralMovementDetectorAgent", "DataExfiltrationDetectorAgent",
    "PrivilegeEscalationDetectorAgent", "BruteForceDetectorAgent",
    "SQLInjectionDetectorAgent", "XSSDetectorAgent", "ZeroDayDetectorAgent",
    "InsiderThreatDetectorAgent", "DDoSDetectorAgent", "C2DetectorAgent",
    "CryptominingDetectorAgent", "RootkitDetectorAgent", "FilelessMalwareDetectorAgent",
    "SupplyChainAttackDetectorAgent", "SocialEngineeringDetectorAgent", "AnomalyDetectorAgent",
]
