"""Agentes de Análisis de Sistemas Operativos — 10 agentes."""

from agents.os_analysis.linux_analyzer import LinuxAnalyzerAgent
from agents.os_analysis.windows_analyzer import WindowsAnalyzerAgent
from agents.os_analysis.macos_analyzer import MacOSAnalyzerAgent
from agents.os_analysis.linux_forensics import LinuxForensicsAgent
from agents.os_analysis.windows_forensics import WindowsForensicsAgent
from agents.os_analysis.linux_hardening import LinuxHardeningAgent
from agents.os_analysis.windows_hardening import WindowsHardeningAgent
from agents.os_analysis.patch_management import PatchManagementAgent
from agents.os_analysis.registry_analyzer import RegistryAnalyzerAgent
from agents.os_analysis.syslog_analyzer import SyslogAnalyzerAgent

__all__ = [
    "LinuxAnalyzerAgent",
    "WindowsAnalyzerAgent",
    "MacOSAnalyzerAgent",
    "LinuxForensicsAgent",
    "WindowsForensicsAgent",
    "LinuxHardeningAgent",
    "WindowsHardeningAgent",
    "PatchManagementAgent",
    "RegistryAnalyzerAgent",
    "SyslogAnalyzerAgent",
]
