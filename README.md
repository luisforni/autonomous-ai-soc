# AI-SOC — Centro de Operaciones de Ciberseguridad Autónomo

[![Python](https://img.shields.io/badge/Python-3.11+-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Next.js-14-black)](https://nextjs.org)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

Plataforma de Centro de Operaciones de Seguridad completamente autónoma impulsada por IA. Detecta, analiza y responde a amenazas cibernéticas en tiempo real. Diseñada para proteger bancos, hospitales, gobiernos y empresas medianas, con soporte para **14 proveedores de IA** — APIs cloud y modelos locales. **126 agentes especializados.** Incluye interfaz web completa en Next.js 14 con reportes PDF, i18n en 10 idiomas y dashboard en tiempo real.

## Arquitectura

```
┌─────────────────────────────────────────────────────┐
│                    FastAPI REST API                  │
├─────────────────────────────────────────────────────┤
│                    Orchestrator                      │
│         (concurrencia, despacho, incidentes)         │
├──────────┬──────────┬──────────┬────────────────────┤
│Monitoring│  Threats │   Cloud  │    Specialized     │
│ (15 ag.) │ (20 ag.) │ (15 ag.) │    (10 ag.)        │
├──────────┬──────────┬──────────┬────────────────────┤
│OS Analys.│Containers│Compliance│    Analytics       │
│ (10 ag.) │ (10 ag.) │ (10 ag.) │    (6 ag.)         │
├──────────┴──────────┴──────────┴────────────────────┤
│           AI Provider Layer (14 providers)           │
│  Anthropic · OpenAI · Gemini · Bedrock · Mistral    │
│  Groq · Cohere · Together · Perplexity · Ollama     │
│  LM Studio · vLLM · llama.cpp · Azure OpenAI        │
├─────────────────────────────────────────────────────┤
│  PostgreSQL/TimescaleDB  │  Redis  │  Elasticsearch  │
└─────────────────────────────────────────────────────┘
```

## Proveedores de IA soportados

| Proveedor | Tipo | Modelos recomendados |
|-----------|------|----------------------|
| **Anthropic** | Cloud API | claude-opus-4-8, claude-sonnet-4-6 |
| **OpenAI** | Cloud API | gpt-4o, gpt-4o-mini |
| **Azure OpenAI** | Cloud API | gpt-4o (deployment propio) |
| **Google Gemini** | Cloud API | gemini-1.5-pro, gemini-1.5-flash |
| **AWS Bedrock** | Cloud API | anthropic.claude-opus-4-8-v1:0 |
| **Mistral** | Cloud API | mistral-large-latest |
| **Groq** | Cloud API (LPU) | llama-3.3-70b-versatile |
| **Cohere** | Cloud API | command-r-plus |
| **Together AI** | Cloud API | Llama-3.3-70B-Instruct-Turbo |
| **Perplexity** | Cloud API | llama-3.1-sonar-large-128k-online |
| **Ollama** | Local | llama3.3, mistral, phi4, qwen2.5 |
| **LM Studio** | Local | cualquier GGUF |
| **vLLM** | Local | Llama-3.3-70B-Instruct |
| **llama.cpp** | Local | cualquier GGUF |

## Agentes (126)

### Monitoreo (15)

| Agente | Función |
|--------|---------|
| `SIEMMonitorAgent` | Monitoreo SIEM centralizado |
| `LogAnalyzerAgent` | Análisis inteligente de logs |
| `NetworkTrafficMonitorAgent` | Monitoreo de tráfico de red |
| `PacketAnalyzerAgent` | Análisis profundo de paquetes (DPI) |
| `DNSMonitorAgent` | Detección de DNS tunneling y DGA |
| `HTTPSMonitorAgent` | Inspección de tráfico HTTPS |
| `EmailSecurityMonitorAgent` | Seguridad de correo electrónico |
| `FileIntegrityMonitorAgent` | Monitor de integridad de archivos |
| `DatabaseActivityMonitorAgent` | Monitoreo de actividad en BD |
| `APISecurityMonitorAgent` | Seguridad de APIs en tiempo real |
| `EndpointMonitorAgent` | Monitoreo de endpoints |
| `CloudActivityMonitorAgent` | Actividad en entornos cloud |
| `IdentityAccessMonitorAgent` | Monitoreo de identidades y accesos |
| `PrivilegedAccessMonitorAgent` | PAM — accesos privilegiados |
| `ComplianceMonitorAgent` | Monitoreo de cumplimiento continuo |

### Análisis de SO (10)

| Agente | Función |
|--------|---------|
| `LinuxAnalyzerAgent` | Análisis de seguridad Linux |
| `WindowsAnalyzerAgent` | Análisis de seguridad Windows |
| `MacOSAnalyzerAgent` | Análisis de seguridad macOS |
| `LinuxForensicsAgent` | Forense en sistemas Linux |
| `WindowsForensicsAgent` | Forense en sistemas Windows |
| `LinuxHardeningAgent` | Hardening de sistemas Linux |
| `WindowsHardeningAgent` | Hardening de sistemas Windows |
| `PatchManagementAgent` | Gestión de parches y vulnerabilidades |
| `RegistryAnalyzerAgent` | Análisis del registro de Windows |
| `SyslogAnalyzerAgent` | Análisis de syslog |

### Cloud (15)

| Agente | Función |
|--------|---------|
| `CloudAnalyzerAgent` | Análisis multi-cloud |
| `AWSAnalyzerAgent` | Seguridad AWS |
| `AzureAnalyzerAgent` | Seguridad Azure |
| `GCPAnalyzerAgent` | Seguridad Google Cloud |
| `AWSCloudTrailAgent` | Auditoría CloudTrail |
| `AWSGuardDutyAgent` | Integración GuardDuty |
| `AzureSentinelAgent` | Integración Microsoft Sentinel |
| `AzureADAnalyzerAgent` | Seguridad Azure Active Directory |
| `GCPCloudArmorAgent` | Google Cloud Armor |
| `S3SecurityAgent` | Seguridad de buckets S3 |
| `IAMAnalyzerAgent` | Análisis de políticas IAM |
| `ServerlessSecurityAgent` | Seguridad de funciones serverless |
| `CloudStorageAnalyzerAgent` | Seguridad de almacenamiento cloud |
| `CloudNetworkAnalyzerAgent` | Seguridad de redes cloud |
| `MultiCloudPostureAgent` | Postura de seguridad multi-cloud |

### Contenedores (10)

| Agente | Función |
|--------|---------|
| `KubernetesAnalyzerAgent` | Seguridad de clústeres Kubernetes |
| `DockerAnalyzerAgent` | Seguridad de contenedores Docker |
| `ContainerImageScannerAgent` | Escaneo de imágenes de contenedor |
| `KubernetesRBACAgent` | RBAC de Kubernetes |
| `PodSecurityAgent` | Seguridad de Pods |
| `ContainerNetworkAgent` | Seguridad de red en contenedores |
| `HelmChartAnalyzerAgent` | Análisis de Helm Charts |
| `ServiceMeshAnalyzerAgent` | Seguridad de service mesh (Istio) |
| `ContainerRegistryAgent` | Seguridad de registros de contenedores |
| `K8sAdmissionControllerAgent` | Admission controller de K8s |

### Detección de Amenazas (20)

| Agente | Función |
|--------|---------|
| `MalwareDetectorAgent` | Detección de malware |
| `PhishingDetectorAgent` | Detección de phishing |
| `RansomwareDetectorAgent` | Detección de ransomware |
| `APTDetectorAgent` | Detección de APTs |
| `LateralMovementDetectorAgent` | Detección de movimiento lateral |
| `DataExfiltrationDetectorAgent` | Detección de exfiltración de datos |
| `PrivilegeEscalationDetectorAgent` | Detección de escalada de privilegios |
| `BruteForceDetectorAgent` | Detección de fuerza bruta |
| `SQLInjectionDetectorAgent` | Detección de SQL Injection |
| `XSSDetectorAgent` | Detección de XSS |
| `ZeroDayDetectorAgent` | Detección de 0-days |
| `InsiderThreatDetectorAgent` | Detección de amenazas internas |
| `DDoSDetectorAgent` | Detección de DDoS |
| `C2DetectorAgent` | Detección de C2/C&C |
| `CryptominingDetectorAgent` | Detección de cryptomining |
| `RootkitDetectorAgent` | Detección de rootkits |
| `FilelessMalwareDetectorAgent` | Detección de malware sin archivo |
| `SupplyChainDetectorAgent` | Detección de ataques supply chain |
| `SocialEngineeringDetectorAgent` | Detección de ingeniería social |
| `AnomalyDetectorAgent` | Detección de anomalías por IA |

### Inteligencia de Amenazas (15)

| Agente | Función |
|--------|---------|
| `OSINTInvestigatorAgent` | Investigación OSINT |
| `ThreatIntelAggregatorAgent` | Agregación de inteligencia |
| `IOCEnricherAgent` | Enriquecimiento de IOCs |
| `CVEAnalyzerAgent` | Análisis de CVEs |
| `DarkWebMonitorAgent` | Monitoreo de dark web |
| `ThreatActorProfilerAgent` | Perfilado de actores de amenaza |
| `MITREATTACKAnalyzerAgent` | Framework MITRE ATT&CK |
| `VulnerabilityIntelAgent` | Inteligencia de vulnerabilidades |
| `BrandProtectionAgent` | Protección de marca |
| `DomainIntelligenceAgent` | Inteligencia de dominios |
| `IPReputationAgent` | Reputación de IPs |
| `CertificateTransparencyAgent` | Transparencia de certificados |
| `PasteSiteMonitorAgent` | Monitoreo de pastebin/sites |
| `SocialMediaIntelAgent` | Inteligencia en redes sociales |
| `GeolocationAnalyzerAgent` | Análisis de geolocalización |

### Respuesta a Incidentes (15)

| Agente | Función |
|--------|---------|
| `IncidentResponderAgent` | Coordinación de respuesta |
| `AutoRemediationAgent` | Remediación automática |
| `ForensicsCollectorAgent` | Recolección forense |
| `MemoryForensicsAgent` | Forense de memoria RAM |
| `DiskForensicsAgent` | Forense de disco |
| `NetworkForensicsAgent` | Forense de red |
| `EvidenceCollectorAgent` | Recolección de evidencias |
| `ChainOfCustodyAgent` | Cadena de custodia digital |
| `IsolationAgent` | Aislamiento de sistemas comprometidos |
| `PasswordResetAgent` | Reset masivo de credenciales |
| `AccountLockoutAgent` | Bloqueo de cuentas comprometidas |
| `FirewallRuleManagerAgent` | Gestión de reglas de firewall |
| `BackupRecoveryAgent` | Recuperación desde backup |
| `PostIncidentAnalyzerAgent` | Análisis post-incidente |
| `LessonsLearnedAgent` | Lecciones aprendidas |

### Compliance (10)

| Agente | Función |
|--------|---------|
| `ComplianceAuditorAgent` | Auditoría de cumplimiento |
| `ReportGeneratorAgent` | Generación de reportes |
| `ExecutiveDashboardAgent` | Dashboard ejecutivo |
| `SLAMonitorAgent` | Monitoreo de SLAs |
| `KPITrackerAgent` | Tracking de KPIs de seguridad |
| `RiskScorerAgent` | Scoring de riesgo |
| `AuditTrailManagerAgent` | Gestión de audit trail |
| `PolicyEnforcerAgent` | Aplicación de políticas |
| `SecurityScorecardAgent` | Scorecard de seguridad |
| `RegulatoryReporterAgent` | Reportes regulatorios (GDPR, HIPAA, PCI) |

### Analytics Avanzado (6)

| Agente | Función |
|--------|---------|
| `UEBAAnalyzerAgent` | User & Entity Behavior Analytics — detección de amenazas internas |
| `ThreatHunterAgent` | Caza proactiva de amenazas avanzadas (APT, LOLBins, C2) |
| `DeceptionManagerAgent` | Honeypots, canary tokens y trampas activas |
| `NetworkBaselinerAgent` | Baseline de red y detección de drift/anomalías |
| `VulnerabilityManagerAgent` | Gestión y priorización de vulnerabilidades (CVSS + EPSS + KEV) |
| `SOAROrchestatorAgent` | Orquestación de respuesta automatizada con playbooks |

### Especializados por Sector (10)

| Agente | Sector |
|--------|---------|
| `BankingSecurityAgent` | Banca y Fintech |
| `HealthcareSecurityAgent` | Hospitales y Salud |
| `GovernmentSecurityAgent` | Gobierno e Infraestructura Crítica |
| `ICSAnalyzerAgent` | ICS/SCADA e Industrial |
| `MobileSecurityAgent` | Seguridad Móvil |
| `IoTSecurityAgent` | Internet of Things |
| `BlockchainSecurityAgent` | Blockchain y DeFi |
| `AIMLSecurityAgent` | Seguridad de Sistemas AI/ML |
| `CodeSecurityAgent` | DevSecOps y Código |
| `APIGatewaySecurityAgent` | API Gateways |

## Stack Tecnológico

| Capa | Tecnología |
|------|------------|
| Frontend | Next.js 14 App Router + Tailwind CSS |
| API | FastAPI + Uvicorn |
| IA | 14 proveedores (cloud + local) |
| Base de Datos | PostgreSQL + TimescaleDB |
| Cache | Redis |
| Search/SIEM | Elasticsearch |
| Mensajería | Kafka / Redis Pub/Sub |
| Monitoreo | Prometheus + Grafana |
| Contenedores | Docker + Kubernetes |
| CI/CD | GitHub Actions |

## Quick Start

### 1. Clonar y configurar

```bash
git clone https://github.com/luisforni/autonomous-ai-soc.git
cd autonomous-ai-soc
cp .env.example .env
```

### 2. Elegir proveedor de IA en `.env`

```bash
# Cloud (requiere API key)
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...

# Local sin internet (requiere Ollama instalado)
AI_PROVIDER=ollama
OLLAMA_MODEL=llama3.3
# ollama pull llama3.3
```

### 3. Levantar infraestructura

```bash
make docker-up
```

### 4. Instalar dependencias y correr

```bash
make install
make dev
```

### 5. Verificar

```bash
curl http://localhost:8888/health
curl http://localhost:8888/api/v1/agents
```

### 6. Acceder a la interfaz web

Abrir [http://localhost:3030](http://localhost:3030) — Dashboard, escaneo de objetivos, 126 agentes, alertas, documentación y exportación de reportes PDF.

## Puertos

| Servicio | Puerto |
|----------|--------|
| Backend API | http://localhost:8888 |
| Frontend | http://localhost:3030 |
| Kibana | http://localhost:5602 |
| Prometheus | http://localhost:9292 |
| Grafana | http://localhost:3004 (admin / aisoc2024) |

## Sectores de clientes

- **Bancos y Fintech** — PCI-DSS, SWIFT, detección de fraude en tiempo real
- **Hospitales y Salud** — HIPAA compliance, protección de datos de pacientes
- **Gobiernos** — Seguridad nacional, protección de infraestructura crítica
- **Empresas Medianas** — SOC-as-a-Service, protección 24/7

## Interfaz Web

- **Dashboard** — métricas en tiempo real, score de riesgo, alertas recientes
- **Escaneo** — analizar dominios, IPs y URLs con los 126 agentes en paralelo
- **Agentes** — catálogo completo con categoría, prioridad y estado
- **Alertas** — feed con severidad, agente y timestamp
- **Documentación** — guía de todos los agentes con técnicas MITRE, riesgos y herramientas
- **Reportes PDF** — exportación ejecutiva con resumen, tabla de agentes y resultados detallados
- **i18n** — Español, English, Português, Français, Deutsch, Italiano, 中文, 日本語, العربية, Русский

## Autor

**Luis Forni** — Arquitecto de Seguridad & Desarrollador Principal

---

*AI-SOC — Ciberseguridad autónoma impulsada por inteligencia artificial*
