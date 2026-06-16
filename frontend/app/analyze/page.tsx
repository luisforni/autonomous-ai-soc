'use client'

import { useState, useEffect, useRef, useCallback } from 'react'
import { createScan, getScan, deleteScan } from '@/lib/api'
import { Search, Loader2, CheckCircle2, XCircle, AlertTriangle, ChevronDown, ChevronUp, RotateCcw, Clock, Square, FileDown } from 'lucide-react'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { RiskGauge } from '@/components/ui/RiskGauge'
import { useTranslation } from '@/lib/i18n'
import type { ScanResult } from '@/lib/types'

type TargetType = 'domain' | 'ip' | 'url'

interface AgentConfig {
  name: string
  label: string
  description: string
  types: TargetType[]
  buildData: (target: string, type: TargetType) => Record<string, unknown>
}

interface AgentGroup {
  group: string
  externalDefault: boolean
  agents: AgentConfig[]
}

const SCAN_KEY = 'soc_scan_id'

function clean(target: string) {
  return target.replace(/^https?:\/\//, '').split('/')[0]
}

const AGENT_GROUPS: AgentGroup[] = [
  {
    group: 'Inteligencia OSINT',
    externalDefault: true,
    agents: [
      {
        name: 'OSINTInvestigatorAgent',
        label: 'OSINT Investigator',
        description: 'Investigación completa: WHOIS, Shodan, VirusTotal, DNS pasivo',
        types: ['domain', 'ip', 'url'],
        buildData: (target, type) => ({ target, target_type: type, context: 'AI-SOC scan', initial_data: {} }),
      },
      {
        name: 'DomainIntelligenceAgent',
        label: 'Domain Intelligence',
        description: 'Análisis DNS, WHOIS, historial de registros, infraestructura',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ domain: clean(target), dns_data: {}, whois: {}, passive_dns: [], certificates: [] }),
      },
      {
        name: 'IPReputationAgent',
        label: 'IP Reputation',
        description: 'Reputación de IPs: blacklists, abuso, geolocalización',
        types: ['domain', 'ip', 'url'],
        buildData: (target, type) => ({
          ips: type === 'ip' ? [target] : [],
          domain: type !== 'ip' ? clean(target) : undefined,
          context: 'reputation check',
        }),
      },
      {
        name: 'CertificateTransparencyAgent',
        label: 'Certificate Transparency',
        description: 'Certificados SSL/TLS, subdominios expuestos, CT logs',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ domain: clean(target), certificates: [], check_subdomains: true }),
      },
      {
        name: 'GeolocationAnalyzerAgent',
        label: 'Geolocation Analyzer',
        description: 'Geolocalización del servidor, ASN, proveedor de hosting',
        types: ['domain', 'ip', 'url'],
        buildData: (target, type) => ({ target, target_type: type, domain: clean(target) }),
      },
      {
        name: 'ThreatIntelAggregatorAgent',
        label: 'Threat Intel Aggregator',
        description: 'Agrega inteligencia de OTX, MISP y feeds de amenazas',
        types: ['domain', 'ip', 'url'],
        buildData: (target, type) => ({ indicators: [{ value: clean(target), type }], context: 'external scan' }),
      },
      {
        name: 'IOCEnricherAgent',
        label: 'IOC Enricher',
        description: 'Enriquece indicadores de compromiso con contexto adicional',
        types: ['domain', 'ip', 'url'],
        buildData: (target, type) => ({ iocs: [{ value: clean(target), type }] }),
      },
      {
        name: 'BrandProtectionAgent',
        label: 'Brand Protection',
        description: 'Detecta typosquatting, dominios similares, suplantación de marca',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ domain: clean(target), brand: clean(target).split('.')[0], check_lookalikes: true }),
      },
      {
        name: 'DarkWebMonitorAgent',
        label: 'Dark Web Monitor',
        description: 'Menciones del target en dark web y foros clandestinos',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), keywords: [clean(target)], scan_forums: true }),
      },
      {
        name: 'PasteSiteMonitorAgent',
        label: 'Paste Site Monitor',
        description: 'Leaks en Pastebin, GitHub Gists y sitios de paste',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ keywords: [clean(target)], target: clean(target) }),
      },
      {
        name: 'SocialMediaIntelAgent',
        label: 'Social Media Intel',
        description: 'Menciones en redes sociales: Twitter, Reddit, Telegram',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), platforms: ['twitter', 'reddit', 'telegram'] }),
      },
      {
        name: 'VulnerabilityIntelAgent',
        label: 'Vulnerability Intel',
        description: 'CVEs asociadas, exploits públicos, exposición de servicios',
        types: ['domain', 'ip', 'url'],
        buildData: (target, type) => ({ target: clean(target), target_type: type, check_cves: true }),
      },
      {
        name: 'ThreatActorProfilerAgent',
        label: 'Threat Actor Profiler',
        description: 'Actores de amenaza asociados al target',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ indicators: [clean(target)], context: 'external recon' }),
      },
      {
        name: 'MITREATTACKAnalyzerAgent',
        label: 'MITRE ATT&CK',
        description: 'Técnicas y tácticas del framework MITRE ATT&CK',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), context: 'external domain analysis' }),
      },
      {
        name: 'CVEAnalyzerAgent',
        label: 'CVE Analyzer',
        description: 'Análisis detallado de vulnerabilidades CVE asociadas al target',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), cves: [], check_exploits: true }),
      },
    ],
  },
  {
    group: 'Detección de Amenazas Web',
    externalDefault: true,
    agents: [
      {
        name: 'PhishingDetectorAgent',
        label: 'Phishing Detector',
        description: 'Señales de phishing, redirecciones maliciosas, lookalikes',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({
          url: target.startsWith('http') ? target : `https://${target}`,
          domain: clean(target),
        }),
      },
      {
        name: 'MalwareDetectorAgent',
        label: 'Malware Detector',
        description: 'Asociación del dominio/IP con distribución de malware',
        types: ['domain', 'ip', 'url'],
        buildData: (target, type) => ({ target: clean(target), target_type: type, scan_url: true }),
      },
      {
        name: 'C2DetectorAgent',
        label: 'C2 / Command & Control',
        description: 'Detección de servidores C2 de botnets',
        types: ['domain', 'ip', 'url'],
        buildData: (target, type) => ({ indicators: [{ value: clean(target), type }], network_data: [] }),
      },
    ],
  },
  {
    group: 'Detección de Amenazas',
    externalDefault: false,
    agents: [
      {
        name: 'AnomalyDetectorAgent',
        label: 'Anomaly Detector',
        description: 'Detecta anomalías estadísticas en tráfico y comportamiento',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ data_type: 'network_traffic', target: clean(target), events: [] }),
      },
      {
        name: 'APTDetectorAgent',
        label: 'APT Detector',
        description: 'Detección de amenazas persistentes avanzadas (APT)',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ organization: clean(target), network_traffic: [], dns_logs: [], indicators: [clean(target)] }),
      },
      {
        name: 'BruteForceDetectorAgent',
        label: 'Brute Force Detector',
        description: 'Detecta ataques de fuerza bruta contra servicios expuestos',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ service: 'web', target: clean(target), login_attempts: [] }),
      },
      {
        name: 'CryptominingDetectorAgent',
        label: 'Cryptomining Detector',
        description: 'Detección de minería de criptomonedas no autorizada',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ hostname: clean(target), avg_cpu_pct: 0, processes: [] }),
      },
      {
        name: 'DataExfiltrationDetectorAgent',
        label: 'Data Exfiltration',
        description: 'Detecta posible exfiltración de datos hacia el target',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ user: 'unknown', hostname: clean(target), network_events: [] }),
      },
      {
        name: 'DDoSDetectorAgent',
        label: 'DDoS Detector',
        description: 'Análisis de capacidad y riesgo de ataques DDoS',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), traffic_data: [] }),
      },
      {
        name: 'FilelessMalwareDetectorAgent',
        label: 'Fileless Malware',
        description: 'Detección de malware residente solo en memoria',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ hostname: clean(target), os: 'Linux', process_tree: [] }),
      },
      {
        name: 'InsiderThreatDetectorAgent',
        label: 'Insider Threat',
        description: 'Detección de amenazas internas y comportamiento anómalo',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ username: 'unknown', organization: clean(target), activity_logs: [] }),
      },
      {
        name: 'LateralMovementDetectorAgent',
        label: 'Lateral Movement',
        description: 'Detecta movimiento lateral entre sistemas de la red',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ network_segment: clean(target), connection_logs: [] }),
      },
      {
        name: 'PrivilegeEscalationDetectorAgent',
        label: 'Privilege Escalation',
        description: 'Detecta intentos de escalada de privilegios',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ hostname: clean(target), os: 'Linux', auth_logs: [] }),
      },
      {
        name: 'RansomwareDetectorAgent',
        label: 'Ransomware Detector',
        description: 'Detección de actividad de ransomware y cifrado masivo',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ hostname: clean(target), file_events: [] }),
      },
      {
        name: 'RootkitDetectorAgent',
        label: 'Rootkit Detector',
        description: 'Detección de rootkits y persistencia a nivel kernel',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ hostname: clean(target), os: 'Linux', scan_results: {} }),
      },
      {
        name: 'SocialEngineeringDetectorAgent',
        label: 'Social Engineering',
        description: 'Detecta campañas de ingeniería social vinculadas al target',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ report_type: 'domain', target: clean(target), content: clean(target) }),
      },
      {
        name: 'SQLInjectionDetectorAgent',
        label: 'SQL Injection',
        description: 'Detecta vectores de inyección SQL en aplicaciones web',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ application: clean(target), requests: [] }),
      },
      {
        name: 'SupplyChainAttackDetectorAgent',
        label: 'Supply Chain Attack',
        description: 'Detecta ataques a la cadena de suministro de software',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ type: 'software', organization: clean(target), packages: [] }),
      },
      {
        name: 'XSSDetectorAgent',
        label: 'XSS Detector',
        description: 'Detecta vectores de Cross-Site Scripting en el target',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ application: clean(target), requests: [] }),
      },
      {
        name: 'ZeroDayDetectorAgent',
        label: 'Zero-Day Detector',
        description: 'Análisis de vulnerabilidades zero-day potenciales',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ application: clean(target), version: 'unknown', behavior_logs: [] }),
      },
    ],
  },
  {
    group: 'Analítica & Threat Hunting',
    externalDefault: false,
    agents: [
      {
        name: 'ThreatHunterAgent',
        label: 'Threat Hunter',
        description: 'Cacería proactiva de amenazas con hipótesis basadas en el target',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ hypothesis: `Detectar amenazas asociadas a ${clean(target)}`, target: clean(target), data_sources: [] }),
      },
      {
        name: 'NetworkBaselinerAgent',
        label: 'Network Baseliner',
        description: 'Análisis de baseline de red y detección de anomalías',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ time_window: '24h', network_cidr: clean(target), traffic_data: [] }),
      },
      {
        name: 'UEBAAnalyzerAgent',
        label: 'UEBA Analyzer',
        description: 'Análisis de comportamiento de usuario y entidad',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ user_id: 'external', role: 'unknown', department: clean(target), activity_logs: [] }),
      },
      {
        name: 'DeceptionManagerAgent',
        label: 'Deception Manager',
        description: 'Gestión de activos honeypot y deception technology',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ asset_type: 'honeypot', asset_name: clean(target), event_data: {} }),
      },
      {
        name: 'SOAROrchestatorAgent',
        label: 'SOAR Orchestrator',
        description: 'Orquestación automatizada de respuesta a incidentes',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ incident_type: 'external_threat', target: clean(target), indicators: [clean(target)] }),
      },
      {
        name: 'VulnerabilityManagerAgent',
        label: 'Vulnerability Manager',
        description: 'Priorización y gestión del ciclo de vida de vulnerabilidades',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ sector: 'web', environment: 'production', target: clean(target), vulnerabilities: [] }),
      },
    ],
  },
  {
    group: 'Cloud & Infraestructura',
    externalDefault: false,
    agents: [
      {
        name: 'CloudAnalyzerAgent',
        label: 'Cloud Analyzer',
        description: 'Análisis general de postura de seguridad en la nube',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ provider: 'unknown', target: clean(target), events: [] }),
      },
      {
        name: 'AWSAnalyzerAgent',
        label: 'AWS Analyzer',
        description: 'Análisis de seguridad de infraestructura AWS',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), account_id: 'unknown', region: 'us-east-1', events: [] }),
      },
      {
        name: 'AWSCloudTrailAnalyzerAgent',
        label: 'AWS CloudTrail',
        description: 'Análisis de logs CloudTrail para detectar actividad sospechosa',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ account_id: 'unknown', events: [], target: clean(target) }),
      },
      {
        name: 'AWSGuardDutyAgent',
        label: 'AWS GuardDuty',
        description: 'Integración con GuardDuty para hallazgos de amenazas AWS',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ account_id: 'unknown', findings: [], target: clean(target) }),
      },
      {
        name: 'AzureAnalyzerAgent',
        label: 'Azure Analyzer',
        description: 'Análisis de seguridad de infraestructura Azure',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ subscription_id: 'unknown', target: clean(target), events: [] }),
      },
      {
        name: 'AzureADAnalyzerAgent',
        label: 'Azure AD Analyzer',
        description: 'Análisis de identidades y accesos en Azure Active Directory',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ tenant_id: 'unknown', target: clean(target), events: [] }),
      },
      {
        name: 'AzureSentinelAgent',
        label: 'Azure Sentinel',
        description: 'Correlación de incidentes desde Microsoft Sentinel',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ workspace_id: 'unknown', target: clean(target), incidents: [] }),
      },
      {
        name: 'GCPAnalyzerAgent',
        label: 'GCP Analyzer',
        description: 'Análisis de seguridad en Google Cloud Platform',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ project_id: 'unknown', target: clean(target), logs: [] }),
      },
      {
        name: 'GCPCloudArmorAgent',
        label: 'GCP Cloud Armor',
        description: 'Análisis de reglas y políticas de Cloud Armor',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ project_id: 'unknown', target: clean(target), policies: [] }),
      },
      {
        name: 'IAMAnalyzerAgent',
        label: 'IAM Analyzer',
        description: 'Análisis de políticas IAM y permisos excesivos',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), provider: 'unknown', policies: [], users: [] }),
      },
      {
        name: 'MultiCloudPostureAgent',
        label: 'Multi-Cloud Posture',
        description: 'Evaluación de postura de seguridad multi-nube',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), providers: ['aws', 'azure', 'gcp'], findings: [] }),
      },
      {
        name: 'CloudNetworkAnalyzerAgent',
        label: 'Cloud Network',
        description: 'Análisis de VPCs, security groups y flujos de red cloud',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), vpc_id: 'unknown', flow_logs: [] }),
      },
      {
        name: 'CloudStorageAnalyzerAgent',
        label: 'Cloud Storage',
        description: 'Detección de buckets/blobs expuestos públicamente',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), buckets: [], provider: 'unknown' }),
      },
      {
        name: 'S3BucketSecurityAgent',
        label: 'S3 Bucket Security',
        description: 'Auditoría de permisos y configuración de buckets S3',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), buckets: [], account_id: 'unknown' }),
      },
      {
        name: 'ServerlessSecurityAgent',
        label: 'Serverless Security',
        description: 'Análisis de seguridad en funciones Lambda/Cloud Functions',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), functions: [], provider: 'unknown' }),
      },
    ],
  },
  {
    group: 'Contenedores & Kubernetes',
    externalDefault: false,
    agents: [
      {
        name: 'KubernetesAnalyzerAgent',
        label: 'Kubernetes Analyzer',
        description: 'Análisis de seguridad general del cluster Kubernetes',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ cluster_name: clean(target), namespaces: [], pods: [] }),
      },
      {
        name: 'KubernetesRBACAnalyzerAgent',
        label: 'K8s RBAC',
        description: 'Auditoría de roles y permisos en Kubernetes',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ cluster: clean(target), roles: [], bindings: [] }),
      },
      {
        name: 'PodSecurityAnalyzerAgent',
        label: 'Pod Security',
        description: 'Evaluación de políticas de seguridad de pods',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ cluster: clean(target), pods: [], namespace: 'default' }),
      },
      {
        name: 'K8sAdmissionControllerAgent',
        label: 'K8s Admission Control',
        description: 'Análisis de admission controllers y políticas de validación',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ cluster: clean(target), admission_requests: [], policies: [] }),
      },
      {
        name: 'ContainerImageScannerAgent',
        label: 'Container Image Scanner',
        description: 'Escaneo de vulnerabilidades en imágenes de contenedor',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ image: clean(target), registry: clean(target), vulnerabilities: [] }),
      },
      {
        name: 'ContainerRegistryAgent',
        label: 'Container Registry',
        description: 'Auditoría de seguridad del registro de contenedores',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ registry: clean(target), images: [], vulnerabilities: [] }),
      },
      {
        name: 'ContainerNetworkAnalyzerAgent',
        label: 'Container Network',
        description: 'Análisis de políticas de red entre contenedores',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ cluster: clean(target), network_policies: [], connections: [] }),
      },
      {
        name: 'DockerAnalyzerAgent',
        label: 'Docker Analyzer',
        description: 'Análisis de seguridad de host Docker y configuraciones',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ host: clean(target), containers: [], images: [] }),
      },
      {
        name: 'HelmChartAnalyzerAgent',
        label: 'Helm Chart Analyzer',
        description: 'Análisis de seguridad en charts de Helm',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ chart_name: clean(target), values: {}, target: clean(target) }),
      },
      {
        name: 'ServiceMeshAnalyzerAgent',
        label: 'Service Mesh',
        description: 'Análisis de seguridad en Istio/Linkerd service mesh',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ mesh_type: 'istio', cluster: clean(target), services: [] }),
      },
    ],
  },
  {
    group: 'Monitoreo Continuo',
    externalDefault: false,
    agents: [
      {
        name: 'HTTPSMonitorAgent',
        label: 'HTTPS Monitor',
        description: 'Monitoreo de SSL/TLS, certificados y configuración HTTPS',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ domain: clean(target), url: `https://${clean(target)}`, ssl_data: {} }),
      },
      {
        name: 'DNSMonitorAgent',
        label: 'DNS Monitor',
        description: 'Monitoreo de resoluciones DNS y detección de anomalías',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ domain: clean(target), dns_queries: [], anomalies: [] }),
      },
      {
        name: 'APISecurityMonitorAgent',
        label: 'API Security Monitor',
        description: 'Monitoreo de endpoints API y detección de abuso',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), api_logs: [], endpoints: [] }),
      },
      {
        name: 'EmailSecurityMonitorAgent',
        label: 'Email Security',
        description: 'Monitoreo de seguridad del dominio de correo (SPF, DKIM, DMARC)',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ domain: clean(target), email_logs: [], quarantine: [] }),
      },
      {
        name: 'NetworkTrafficMonitorAgent',
        label: 'Network Traffic',
        description: 'Monitoreo de patrones de tráfico de red',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), traffic_data: [], interface: 'eth0' }),
      },
      {
        name: 'LogAnalyzerAgent',
        label: 'Log Analyzer',
        description: 'Análisis de logs para detección de anomalías y amenazas',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ source: clean(target), logs: [], log_type: 'syslog' }),
      },
      {
        name: 'SIEMMonitorAgent',
        label: 'SIEM Monitor',
        description: 'Correlación de eventos y alertas desde SIEM',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), events: [], rules: [] }),
      },
      {
        name: 'EndpointMonitorAgent',
        label: 'Endpoint Monitor',
        description: 'Monitoreo de endpoints y detección de comportamiento anómalo',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ hostname: clean(target), endpoint_events: [], alerts: [] }),
      },
      {
        name: 'FileIntegrityMonitorAgent',
        label: 'File Integrity',
        description: 'Monitoreo de integridad de archivos y detección de cambios',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ hostname: clean(target), file_events: [], baseline: {} }),
      },
      {
        name: 'DatabaseActivityMonitorAgent',
        label: 'Database Activity',
        description: 'Monitoreo de actividad de base de datos y consultas anómalas',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ hostname: clean(target), db_type: 'unknown', query_logs: [] }),
      },
      {
        name: 'IdentityAccessMonitorAgent',
        label: 'Identity & Access',
        description: 'Monitoreo de autenticación y control de acceso',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), auth_logs: [], users: [] }),
      },
      {
        name: 'PrivilegedAccessMonitorAgent',
        label: 'Privileged Access',
        description: 'Monitoreo de accesos privilegiados y sesiones administrativas',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ hostname: clean(target), privileged_sessions: [], users: [] }),
      },
      {
        name: 'CloudActivityMonitorAgent',
        label: 'Cloud Activity',
        description: 'Monitoreo de actividad en plataformas cloud',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), provider: 'unknown', activity_logs: [] }),
      },
      {
        name: 'ComplianceMonitorAgent',
        label: 'Compliance Monitor',
        description: 'Monitoreo continuo de cumplimiento normativo',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), framework: 'ISO27001', findings: [] }),
      },
      {
        name: 'PacketAnalyzerAgent',
        label: 'Packet Analyzer',
        description: 'Análisis profundo de paquetes de red (DPI)',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), packets: [], capture_file: '' }),
      },
    ],
  },
  {
    group: 'Sistemas Operativos',
    externalDefault: false,
    agents: [
      {
        name: 'WindowsAnalyzerAgent',
        label: 'Windows Analyzer',
        description: 'Análisis de seguridad de sistemas Windows',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ hostname: clean(target), os_version: 'Windows', event_logs: [] }),
      },
      {
        name: 'WindowsForensicsAgent',
        label: 'Windows Forensics',
        description: 'Análisis forense de sistemas Windows',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ hostname: clean(target), artifacts: {}, event_logs: [] }),
      },
      {
        name: 'WindowsHardeningAgent',
        label: 'Windows Hardening',
        description: 'Evaluación y recomendaciones de hardening para Windows',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ hostname: clean(target), current_config: {}, os_version: 'Windows' }),
      },
      {
        name: 'LinuxAnalyzerAgent',
        label: 'Linux Analyzer',
        description: 'Análisis de seguridad de sistemas Linux/Unix',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ hostname: clean(target), os_version: 'Linux', system_logs: [] }),
      },
      {
        name: 'LinuxForensicsAgent',
        label: 'Linux Forensics',
        description: 'Análisis forense de sistemas Linux',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ hostname: clean(target), artifacts: {}, system_logs: [] }),
      },
      {
        name: 'LinuxHardeningAgent',
        label: 'Linux Hardening',
        description: 'Evaluación y recomendaciones de hardening para Linux',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ hostname: clean(target), current_config: {}, os_version: 'Linux' }),
      },
      {
        name: 'MacOSAnalyzerAgent',
        label: 'macOS Analyzer',
        description: 'Análisis de seguridad de sistemas macOS',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ hostname: clean(target), os_version: 'macOS', system_logs: [] }),
      },
      {
        name: 'PatchManagementAgent',
        label: 'Patch Management',
        description: 'Gestión de parches y análisis de vulnerabilidades por parchear',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ hostname: clean(target), installed_packages: [], os: 'Linux' }),
      },
      {
        name: 'RegistryAnalyzerAgent',
        label: 'Registry Analyzer',
        description: 'Análisis del registro de Windows en busca de persistencia',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ hostname: clean(target), registry_data: {}, os: 'Windows' }),
      },
      {
        name: 'SyslogAnalyzerAgent',
        label: 'Syslog Analyzer',
        description: 'Análisis de logs del sistema operativo',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ hostname: clean(target), syslog_entries: [], log_source: clean(target) }),
      },
    ],
  },
  {
    group: 'Cumplimiento & Reportes',
    externalDefault: false,
    agents: [
      {
        name: 'ComplianceAuditorAgent',
        label: 'Compliance Auditor',
        description: 'Auditoría de cumplimiento: ISO27001, SOC2, PCI-DSS',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ organization: clean(target), framework: 'ISO27001', systems: [] }),
      },
      {
        name: 'RiskScorerAgent',
        label: 'Risk Scorer',
        description: 'Puntuación cuantitativa de riesgo organizacional',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ organization: clean(target), assets: [], vulnerabilities: [] }),
      },
      {
        name: 'SecurityScorecardAgent',
        label: 'Security Scorecard',
        description: 'Scorecard integral de madurez de seguridad',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ organization: clean(target), target: clean(target), categories: [] }),
      },
      {
        name: 'RegulatoryReporterAgent',
        label: 'Regulatory Reporter',
        description: 'Generación de reportes para reguladores (GDPR, HIPAA, NIS2)',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ organization: clean(target), framework: 'GDPR', findings: [] }),
      },
      {
        name: 'PolicyEnforcerAgent',
        label: 'Policy Enforcer',
        description: 'Evaluación de cumplimiento de políticas de seguridad',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ organization: clean(target), policies: [], violations: [] }),
      },
      {
        name: 'AuditTrailManagerAgent',
        label: 'Audit Trail',
        description: 'Gestión y análisis de pistas de auditoría',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ organization: clean(target), audit_logs: [], period: '30d' }),
      },
      {
        name: 'ReportGeneratorAgent',
        label: 'Report Generator',
        description: 'Generación automática de reportes ejecutivos de seguridad',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ organization: clean(target), report_type: 'security', data: {} }),
      },
      {
        name: 'ExecutiveDashboardAgent',
        label: 'Executive Dashboard',
        description: 'Métricas y KPIs para dashboard ejecutivo de seguridad',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ organization: clean(target), metrics: {}, period: '30d' }),
      },
      {
        name: 'KPITrackerAgent',
        label: 'KPI Tracker',
        description: 'Seguimiento de indicadores clave de rendimiento de seguridad',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ organization: clean(target), kpis: {}, period: '30d' }),
      },
      {
        name: 'SLAMonitorAgent',
        label: 'SLA Monitor',
        description: 'Monitoreo de SLAs de respuesta a incidentes',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ organization: clean(target), sla_data: {}, incidents: [] }),
      },
    ],
  },
  {
    group: 'Respuesta a Incidentes',
    externalDefault: false,
    agents: [
      {
        name: 'IncidentResponderAgent',
        label: 'Incident Responder',
        description: 'Coordinación y respuesta a incidentes de seguridad',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ incident_type: 'external_threat', target: clean(target), indicators: [clean(target)] }),
      },
      {
        name: 'ForensicsCollectorAgent',
        label: 'Forensics Collector',
        description: 'Recolección de evidencias forenses digitales',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ hostname: clean(target), artifacts: [], collection_type: 'live' }),
      },
      {
        name: 'EvidenceCollectorAgent',
        label: 'Evidence Collector',
        description: 'Gestión de evidencias para análisis forense',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ case_id: clean(target), target: clean(target), evidence_types: ['logs', 'network'] }),
      },
      {
        name: 'AutoRemediationAgent',
        label: 'Auto Remediation',
        description: 'Remediación automática de vulnerabilidades detectadas',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), findings: [], incident_type: 'external_threat' }),
      },
      {
        name: 'IsolationAgent',
        label: 'Isolation Agent',
        description: 'Evaluación de estrategias de aislamiento de sistemas comprometidos',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ hostname: clean(target), reason: 'security assessment', severity: 'high' }),
      },
      {
        name: 'FirewallRuleManagerAgent',
        label: 'Firewall Rules',
        description: 'Gestión y análisis de reglas de firewall',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), rules: [], action: 'analyze' }),
      },
      {
        name: 'NetworkForensicsAgent',
        label: 'Network Forensics',
        description: 'Análisis forense de tráfico de red',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), pcap_data: '', network_artifacts: [] }),
      },
      {
        name: 'MemoryForensicsAgent',
        label: 'Memory Forensics',
        description: 'Análisis forense de volcados de memoria',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ hostname: clean(target), memory_dump: '', artifacts: [] }),
      },
      {
        name: 'DiskForensicsAgent',
        label: 'Disk Forensics',
        description: 'Análisis forense de imágenes de disco',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ hostname: clean(target), disk_image: '', artifacts: [] }),
      },
      {
        name: 'ChainOfCustodyAgent',
        label: 'Chain of Custody',
        description: 'Gestión de cadena de custodia de evidencias',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ case_id: clean(target), evidence: [], handler: 'ai-soc' }),
      },
      {
        name: 'PostIncidentAnalyzerAgent',
        label: 'Post-Incident Analysis',
        description: 'Análisis post-incidente y lecciones aprendidas',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ incident_id: clean(target), timeline: [], root_cause: '' }),
      },
      {
        name: 'LessonsLearnedAgent',
        label: 'Lessons Learned',
        description: 'Documentación de lecciones aprendidas de incidentes',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ incident_id: clean(target), timeline: [], findings: [] }),
      },
      {
        name: 'BackupRecoveryAgent',
        label: 'Backup & Recovery',
        description: 'Evaluación de estrategias de backup y recuperación',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ organization: clean(target), backup_data: {}, systems: [] }),
      },
      {
        name: 'AccountLockoutAgent',
        label: 'Account Lockout',
        description: 'Análisis de patrones de bloqueo de cuentas',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), locked_accounts: [], reason: 'security assessment' }),
      },
      {
        name: 'PasswordResetAgent',
        label: 'Password Reset',
        description: 'Gestión de resets de contraseña en respuesta a incidentes',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), accounts: [], reason: 'security assessment' }),
      },
    ],
  },
  {
    group: 'Seguridad Especializada',
    externalDefault: false,
    agents: [
      {
        name: 'APIGatewaySecurityAgent',
        label: 'API Gateway Security',
        description: 'Seguridad de API gateways y protección de APIs',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), api_logs: [], endpoints: [] }),
      },
      {
        name: 'CodeSecurityAgent',
        label: 'Code Security',
        description: 'Análisis de seguridad de código fuente (SAST)',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ repository: clean(target), language: 'unknown', code_snippets: [] }),
      },
      {
        name: 'AIMLSecurityAgent',
        label: 'AI/ML Security',
        description: 'Seguridad de sistemas de IA/ML: adversarial attacks, model poisoning',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), model_type: 'unknown', endpoints: [] }),
      },
      {
        name: 'IoTSecurityAgent',
        label: 'IoT Security',
        description: 'Análisis de seguridad de dispositivos IoT',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), devices: [], protocols: [] }),
      },
      {
        name: 'ICSAnalyzerAgent',
        label: 'ICS/SCADA Analyzer',
        description: 'Análisis de seguridad de sistemas industriales ICS/SCADA',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), protocols: [], devices: [] }),
      },
      {
        name: 'MobileSecurityAgent',
        label: 'Mobile Security',
        description: 'Análisis de seguridad de aplicaciones móviles',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ app_name: clean(target), platform: 'unknown', permissions: [] }),
      },
      {
        name: 'BankingSecurityAgent',
        label: 'Banking Security',
        description: 'Seguridad especializada para sector bancario y financiero',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), institution: clean(target), transactions: [] }),
      },
      {
        name: 'HealthcareSecurityAgent',
        label: 'Healthcare Security',
        description: 'Seguridad para sector salud: HIPAA, HL7, DICOM',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ organization: clean(target), phi_systems: [], hipaa_status: 'unknown' }),
      },
      {
        name: 'BlockchainSecurityAgent',
        label: 'Blockchain Security',
        description: 'Análisis de seguridad de contratos inteligentes y blockchain',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ target: clean(target), network: 'ethereum', transactions: [] }),
      },
      {
        name: 'GovernmentSecurityAgent',
        label: 'Government Security',
        description: 'Seguridad especializada para organismos gubernamentales',
        types: ['domain', 'ip', 'url'],
        buildData: (target) => ({ organization: clean(target), classification: 'unclassified', systems: [] }),
      },
    ],
  },
]

const ALL_AGENTS = AGENT_GROUPS.flatMap(g => g.agents)
const DEFAULT_AGENT_NAMES = new Set(
  AGENT_GROUPS.filter(g => g.externalDefault).flatMap(g => g.agents).map(a => a.name)
)

function detectType(input: string): TargetType {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(input.trim())) return 'ip'
  if (/^https?:\/\//.test(input.trim())) return 'url'
  return 'domain'
}

function riskColor(score: number) {
  if (score >= 8) return 'text-red-400'
  if (score >= 5) return 'text-orange-400'
  if (score >= 3) return 'text-yellow-400'
  return 'text-green-400'
}

function riskLabel(score: number) {
  if (score >= 8) return 'CRITICAL'
  if (score >= 5) return 'HIGH'
  if (score >= 3) return 'MEDIUM'
  return 'LOW'
}

function safeNum(v: unknown): number {
  const n = Number(v)
  return isFinite(n) && n >= 0 ? Math.min(n, 10) : 0
}

function parseRaw(raw: string): { risk_score?: number; summary?: string; recommendations?: string[] } {
  try {
    const match = raw.match(/\{[\s\S]*\}/)
    if (!match) return {}
    const p = JSON.parse(match[0])
    const recs = p.recommendations
    const recsArr = Array.isArray(recs)
      ? recs.filter((v: unknown): v is string => typeof v === 'string')
      : typeof recs === 'object' && recs !== null
      ? Object.values(recs).filter((v): v is string => typeof v === 'string')
      : typeof recs === 'string' ? [recs] : []
    const rawScore = p.risk_score
    return {
      risk_score: rawScore != null ? safeNum(rawScore) : undefined,
      summary: p.exposure_level || p.summary,
      recommendations: recsArr,
    }
  } catch { return {} }
}

function estimateMinutes(count: number) {
  const mins = Math.ceil(count * 1.5)
  return mins >= 60 ? `~${Math.floor(mins / 60)}h ${mins % 60}m` : `~${mins}m`
}

export default function AnalyzePage() {
  const { t } = useTranslation()
  const [target, setTarget] = useState('')
  const [targetType, setTargetType] = useState<TargetType>('domain')
  const [results, setResults] = useState<ScanResult[]>([])
  const [scanning, setScanning] = useState(false)
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})
  const [showAgentSelector, setShowAgentSelector] = useState(false)
  const [selectedAgents, setSelectedAgents] = useState<Set<string>>(() => new Set(DEFAULT_AGENT_NAMES))
  const [showStopConfirm, setShowStopConfirm] = useState(false)
  const [generatingPDF, setGeneratingPDF] = useState(false)

  const scanIdRef = useRef<string | null>(null)

  useEffect(() => {
    const saved = typeof window !== 'undefined' ? localStorage.getItem(SCAN_KEY) : null
    if (!saved) return
    getScan(saved)
      .then(scan => {
        scanIdRef.current = saved
        setTarget(scan.target)
        setTargetType(scan.target_type as TargetType)
        setResults(scan.agents.map(a => ({
          agent: a.name,
          label: a.label,
          status: a.status,
          result: a.result ?? undefined,
          error: a.error ?? undefined,
        })))
        if (scan.status === 'running') setScanning(true)
      })
      .catch(() => { localStorage.removeItem(SCAN_KEY) })
  }, [])

  useEffect(() => {
    if (!scanning) return
    const timer = setInterval(async () => {
      if (!scanIdRef.current) return
      try {
        const scan = await getScan(scanIdRef.current)
        setResults(scan.agents.map(a => ({
          agent: a.name,
          label: a.label,
          status: a.status,
          result: a.result ?? undefined,
          error: a.error ?? undefined,
        })))
        if (scan.status === 'complete') setScanning(false)
      } catch { setScanning(false) }
    }, 3000)
    return () => clearInterval(timer)
  }, [scanning])

  function handleTargetChange(val: string) {
    setTarget(val)
    setTargetType(detectType(val))
  }

  function toggleAgent(name: string) {
    setSelectedAgents(prev => {
      const next = new Set(prev)
      next.has(name) ? next.delete(name) : next.add(name)
      return next
    })
  }

  function toggleGroup(groupAgents: AgentConfig[]) {
    setSelectedAgents(prev => {
      const next = new Set(prev)
      const names = groupAgents.map(a => a.name)
      const allOn = names.every(n => prev.has(n))
      names.forEach(n => allOn ? next.delete(n) : next.add(n))
      return next
    })
  }

  function selectAll() {
    setSelectedAgents(new Set(ALL_AGENTS.map(a => a.name)))
  }

  function selectDefault() {
    setSelectedAgents(new Set(DEFAULT_AGENT_NAMES))
  }

  async function handleScan(e: React.FormEvent) {
    e.preventDefault()
    if (!target.trim() || selectedAgents.size === 0) return

    const cleanTarget = target.trim()
    const type = detectType(cleanTarget)
    const toRun = ALL_AGENTS.filter(a => selectedAgents.has(a.name))

    try {
      const { scan_id } = await createScan(
        cleanTarget,
        type,
        toRun.map(a => ({ name: a.name, label: a.label, data: a.buildData(cleanTarget, type) }))
      )
      scanIdRef.current = scan_id
      localStorage.setItem(SCAN_KEY, scan_id)
      setResults(toRun.map(a => ({ agent: a.name, label: a.label, status: 'pending' as const })))
      setScanning(true)
      setExpanded({})
    } catch (err) {
      console.error('Failed to start scan:', err)
    }
  }

  const handleReset = useCallback(async () => {
    if (scanIdRef.current) {
      try { await deleteScan(scanIdRef.current) } catch {}
      scanIdRef.current = null
    }
    localStorage.removeItem(SCAN_KEY)
    setTarget('')
    setTargetType('domain')
    setResults([])
    setScanning(false)
    setExpanded({})
    setSelectedAgents(new Set(DEFAULT_AGENT_NAMES))
  }, [])

  const handleStop = useCallback(async () => {
    setShowStopConfirm(false)
    if (scanIdRef.current) {
      try { await deleteScan(scanIdRef.current) } catch {}
    }
    setScanning(false)
    setResults(prev => prev.map(r =>
      r.status === 'pending' || r.status === 'running'
        ? { ...r, status: 'error' as const, error: 'Detenido manualmente' }
        : r
    ))
  }, [])

  const handleDownloadPDF = useCallback(async () => {
    setGeneratingPDF(true)
    try {
      const { generateReport } = await import('@/lib/generate-report')
      const done = results.filter(r => r.status === 'done' && r.result)
      const maxR = done.length
        ? Math.max(...done.map(r => {
            try {
              const m = (r.result?.raw_ai_response || '').match(/\{[\s\S]*\}/)
              if (m) { const p = JSON.parse(m[0]); if (p.risk_score != null) return Math.min(Math.max(0, Number(p.risk_score)), 10) }
            } catch {}
            return Math.min(Math.max(0, Number(r.result?.risk_score ?? 0)), 10)
          }))
        : 0
      const labels = {
        reportTitle:     t('pdf.reportTitle'),
        analyzedTarget:  t('pdf.analyzedTarget'),
        maxRiskDetected: t('pdf.maxRiskDetected'),
        totalAgents:     t('pdf.totalAgents'),
        completed:       t('pdf.completed'),
        withError:       t('pdf.withError'),
        riskMax:         t('pdf.riskMax'),
        footer:          t('pdf.footer'),
        execSummary:     t('pdf.execSummary'),
        agentCol:        t('pdf.agentCol'),
        scoreCol:        t('pdf.scoreCol'),
        levelCol:        t('pdf.levelCol'),
        alertsCol:       t('pdf.alertsCol'),
        recsCol:         t('pdf.recsCol'),
        agentsWithError: t('pdf.agentsWithError'),
        unknownError:    t('pdf.unknownError'),
        agentResults:    t('pdf.agentResults'),
        alertsLabel:     t('pdf.alertsLabel'),
        recsLabel:       t('pdf.recsLabel'),
        exposureLevel:   t('pdf.exposureLevel'),
        pageLabel:       t('pdf.pageLabel'),
        pageFooter:      t('pdf.pageFooter'),
      }
      generateReport({ target, targetType, results, maxRisk: isFinite(maxR) ? maxR : 0, labels })
    } catch (err) {
      console.error('PDF generation failed:', err)
    } finally {
      setGeneratingPDF(false)
    }
  }, [target, targetType, results])

  const doneResults = results.filter(r => r.status === 'done' && r.result)
  const maxRisk = doneResults.length
    ? Math.max(...doneResults.map(r => {
        const fromRaw = parseRaw(r.result?.raw_ai_response || '').risk_score
        return fromRaw ?? safeNum(r.result?.risk_score)
      }))
    : 0

  const completedCount = results.filter(r => r.status === 'done' || r.status === 'error').length
  const selectedCount = selectedAgents.size

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Target Scanner</h1>
          <p className="text-slate-400 text-sm mt-1">
            {selectedCount} agente{selectedCount !== 1 ? 's' : ''} seleccionados · {estimateMinutes(selectedCount)} estimado
          </p>
        </div>
        {results.length > 0 && (
          <div className="flex items-center gap-2">
            {doneResults.length > 0 && (
              <button
                onClick={handleDownloadPDF}
                disabled={generatingPDF || scanning}
                className="flex items-center gap-2 text-sm text-accent hover:text-accent/80 border border-accent/40 hover:border-accent/60 bg-accent/5 hover:bg-accent/10 rounded-lg px-3 py-2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {generatingPDF
                  ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  : <FileDown className="w-3.5 h-3.5" />}
                {generatingPDF ? 'Generando...' : 'Descargar PDF'}
              </button>
            )}
            {scanning && (
              <button
                onClick={() => setShowStopConfirm(true)}
                className="flex items-center gap-2 text-sm text-red-400 hover:text-red-300 border border-red-500/40 hover:border-red-400/60 bg-red-500/5 hover:bg-red-500/10 rounded-lg px-3 py-2 transition-colors"
              >
                <Square className="w-3.5 h-3.5 fill-current" />
                Detener
              </button>
            )}
            <button
              onClick={handleReset}
              disabled={scanning}
              className="flex items-center gap-2 text-sm text-slate-400 hover:text-white border border-border hover:border-slate-500 rounded-lg px-3 py-2 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Nuevo análisis
            </button>
          </div>
        )}
      </div>

      {results.length === 0 && (
        <form onSubmit={handleScan} className="bg-surface border border-border rounded-xl p-5 space-y-4">
          <div className="flex gap-3">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
              <input
                type="text"
                value={target}
                onChange={e => handleTargetChange(e.target.value)}
                placeholder="ejemplo.com · https://sitio.com · 8.8.8.8"
                className="w-full bg-background border border-border rounded-lg pl-9 pr-4 py-3 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-accent transition-colors"
                autoFocus
              />
              {target && (
                <span className="absolute right-3 top-1/2 -translate-y-1/2 text-xs font-mono px-1.5 py-0.5 rounded bg-accent/10 text-accent border border-accent/20">
                  {targetType}
                </span>
              )}
            </div>
            <button
              type="submit"
              disabled={!target.trim() || selectedAgents.size === 0}
              className="flex items-center gap-2 bg-accent text-background font-semibold px-6 py-3 rounded-lg hover:bg-accent/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed shrink-0"
            >
              <Search className="w-4 h-4" />
              Escanear
            </button>
          </div>

          <div>
            <div className="flex items-center gap-3 mb-1">
              <button
                type="button"
                onClick={() => setShowAgentSelector(v => !v)}
                className="flex items-center gap-2 text-xs text-slate-400 hover:text-white transition-colors"
              >
                {showAgentSelector ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                {selectedCount} de {ALL_AGENTS.length} agentes seleccionados
              </button>
              <button type="button" onClick={selectAll} className="text-xs text-accent hover:underline">todos</button>
              <button type="button" onClick={selectDefault} className="text-xs text-slate-500 hover:text-slate-300 hover:underline">solo externos</button>
              {selectedCount > 18 && (
                <span className="flex items-center gap-1 text-xs text-yellow-400">
                  <Clock className="w-3 h-3" />
                  {estimateMinutes(selectedCount)}
                </span>
              )}
            </div>

            {showAgentSelector && (
              <div className="mt-3 space-y-5">
                {AGENT_GROUPS.map(group => {
                  const allOn = group.agents.every(a => selectedAgents.has(a.name))
                  const someOn = group.agents.some(a => selectedAgents.has(a.name))
                  return (
                    <div key={group.group}>
                      <div className="flex items-center gap-3 mb-2">
                        <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">{group.group}</p>
                        <button type="button" onClick={() => toggleGroup(group.agents)} className="text-xs text-accent hover:underline">
                          {allOn ? 'quitar todos' : 'seleccionar todos'}
                        </button>
                        {!allOn && someOn && <span className="text-xs text-slate-600">parcial</span>}
                      </div>
                      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                        {group.agents.map(agent => (
                          <label
                            key={agent.name}
                            className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors ${
                              selectedAgents.has(agent.name)
                                ? 'border-accent/50 bg-accent/5'
                                : 'border-border bg-background hover:border-slate-600'
                            }`}
                          >
                            <input
                              type="checkbox"
                              checked={selectedAgents.has(agent.name)}
                              onChange={() => toggleAgent(agent.name)}
                              className="mt-0.5 accent-accent shrink-0"
                            />
                            <div>
                              <p className={`text-xs font-medium ${selectedAgents.has(agent.name) ? 'text-accent' : 'text-white'}`}>
                                {agent.label}
                              </p>
                              <p className="text-xs text-slate-500 mt-0.5">{agent.description}</p>
                            </div>
                          </label>
                        ))}
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </form>
      )}

      {scanning && (
        <div className="bg-surface border border-accent/30 rounded-xl p-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Loader2 className="w-4 h-4 animate-spin text-accent" />
            <div>
              <p className="text-sm font-medium text-white">Analizando <span className="font-mono text-accent">{target}</span></p>
              <p className="text-xs text-slate-400 mt-0.5">
                Agente {completedCount + 1} de {results.length} · {estimateMinutes(results.length - completedCount)} restante
              </p>
            </div>
          </div>
          <div className="text-xs text-slate-400">
            {completedCount}/{results.length} completados
          </div>
        </div>
      )}

      {doneResults.length > 0 && (
        <div className="bg-surface border border-border rounded-xl p-5 flex items-center gap-6">
          <RiskGauge score={maxRisk} />
          <div>
            <p className="text-slate-400 text-xs">Riesgo máximo detectado</p>
            <p className={`text-3xl font-bold mt-0.5 ${riskColor(maxRisk)}`}>{riskLabel(maxRisk)}</p>
            <p className="text-xs text-slate-400 mt-1">
              {doneResults.length}/{results.length} agentes completados · <span className="font-mono text-slate-300">{target}</span>
              {scanning && <span className="text-accent"> · en curso...</span>}
            </p>
          </div>
        </div>
      )}

      {results.length > 0 && (
        <div className="space-y-2">
          {results.map(r => {
            const isExp = expanded[r.agent]
            const parsed = r.result ? parseRaw(r.result.raw_ai_response || '') : {}
            const score = safeNum(parsed.risk_score ?? r.result?.risk_score)
            const recs = parsed.recommendations?.length ? parsed.recommendations : r.result?.recommendations ?? []
            const alerts = r.result?.alerts ?? []
            const agentCfg = ALL_AGENTS.find(a => a.name === r.agent)

            return (
              <div key={r.agent} className={`bg-surface border rounded-xl overflow-hidden transition-colors ${
                r.status === 'running' ? 'border-accent/40' :
                r.status === 'error' ? 'border-red-500/30' :
                r.status === 'pending' ? 'border-border opacity-50' :
                'border-border'
              }`}>
                <button
                  className="w-full flex items-center justify-between px-5 py-3.5 hover:bg-white/5 transition-colors"
                  onClick={() => r.status === 'done' && setExpanded(prev => ({ ...prev, [r.agent]: !prev[r.agent] }))}
                  disabled={r.status !== 'done'}
                >
                  <div className="flex items-center gap-3">
                    {r.status === 'running' && <Loader2 className="w-4 h-4 animate-spin text-accent shrink-0" />}
                    {r.status === 'done' && <CheckCircle2 className="w-4 h-4 text-green-400 shrink-0" />}
                    {r.status === 'error' && <XCircle className="w-4 h-4 text-red-400 shrink-0" />}
                    {r.status === 'pending' && <div className="w-4 h-4 rounded-full border border-slate-600 shrink-0" />}
                    <div className="text-left">
                      <p className="text-sm font-medium text-white">{r.label}</p>
                      {agentCfg && <p className="text-xs text-slate-500">{agentCfg.description}</p>}
                    </div>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    {r.status === 'done' && (
                      <>
                        <span className={`text-sm font-bold ${riskColor(score)}`}>{score.toFixed(1)}</span>
                        <span className={`text-xs px-2 py-0.5 rounded font-medium border ${
                          score >= 8 ? 'bg-red-500/10 text-red-400 border-red-500/30' :
                          score >= 5 ? 'bg-orange-500/10 text-orange-400 border-orange-500/30' :
                          score >= 3 ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30' :
                          'bg-green-500/10 text-green-400 border-green-500/30'
                        }`}>{riskLabel(score)}</span>
                        {isExp ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
                      </>
                    )}
                    {r.status === 'running' && <span className="text-xs text-accent italic">analizando...</span>}
                    {r.status === 'pending' && <span className="text-xs text-slate-600">en espera</span>}
                    {r.status === 'error' && <span className="text-xs text-red-400 max-w-xs truncate">{r.error}</span>}
                  </div>
                </button>

                {isExp && r.result && (
                  <div className="border-t border-border px-5 py-4 space-y-4">
                    {alerts.length > 0 && (
                      <div>
                        <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Alertas</p>
                        <div className="space-y-2">
                          {alerts.map((a, i) => (
                            <div key={i} className="flex items-start gap-3 bg-background rounded-lg p-3">
                              <AlertTriangle className="w-4 h-4 text-high shrink-0 mt-0.5" />
                              <div><SeverityBadge severity={a.severity} /><p className="text-sm text-slate-200 mt-1">{a.title || a.description}</p></div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    {recs.length > 0 && (
                      <div>
                        <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Recomendaciones</p>
                        <ul className="space-y-1.5">
                          {recs.map((rec, i) => (
                            <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                              <span className="text-accent mt-0.5 shrink-0">→</span>{rec}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {parsed.summary && (
                      <p className="text-xs text-slate-400">Exposición: <span className="text-slate-200 capitalize">{parsed.summary}</span></p>
                    )}
                    <details>
                      <summary className="text-xs text-slate-600 hover:text-slate-400 cursor-pointer select-none">Ver respuesta completa de la IA</summary>
                      <pre className="mt-2 text-xs text-slate-400 bg-background rounded-lg p-3 overflow-auto max-h-64 whitespace-pre-wrap">{r.result.raw_ai_response}</pre>
                    </details>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}

      {results.length === 0 && !scanning && (
        <div className="flex flex-col items-center justify-center py-16 text-slate-600 gap-3">
          <Search className="w-10 h-10" />
          <p className="text-sm">Ingresá un objetivo para comenzar</p>
          <p className="text-xs font-mono text-slate-600">ejemplo.com · https://sitio.com · 8.8.8.8</p>
        </div>
      )}

      {showStopConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setShowStopConfirm(false)} />
          <div className="relative bg-surface border border-red-500/30 rounded-xl p-6 w-full max-w-sm mx-4 shadow-2xl">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-9 h-9 rounded-full bg-red-500/10 border border-red-500/30 flex items-center justify-center shrink-0">
                <Square className="w-4 h-4 text-red-400 fill-current" />
              </div>
              <h2 className="text-base font-semibold text-white">¿Detener el análisis?</h2>
            </div>
            <p className="text-sm text-slate-400 mb-5">
              Se cancelarán todos los agentes pendientes. Los resultados obtenidos hasta ahora se conservan.
            </p>
            <div className="flex gap-3">
              <button
                onClick={() => setShowStopConfirm(false)}
                className="flex-1 py-2 rounded-lg border border-border text-sm text-slate-400 hover:text-white hover:border-slate-500 transition-colors"
              >
                Cancelar
              </button>
              <button
                onClick={handleStop}
                className="flex-1 py-2 rounded-lg bg-red-500/10 border border-red-500/40 text-sm text-red-400 hover:bg-red-500/20 hover:text-red-300 transition-colors font-medium"
              >
                Sí, detener
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
