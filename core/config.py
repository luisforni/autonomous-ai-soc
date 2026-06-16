"""Configuración central del AI-SOC."""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from core.ai_provider import AIProviderType


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "AI-SOC"
    app_env: str = "development"
    app_debug: bool = False
    app_secret_key: str = "change_this_in_production"
    api_version: str = "v1"

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 4

    # -----------------------------------------------------------------------
    # AI Provider Selection
    # -----------------------------------------------------------------------
    ai_provider: AIProviderType = AIProviderType.OLLAMA
    ai_max_tokens: int = 4096
    ai_temperature: float = 0.1

    # -----------------------------------------------------------------------
    # Anthropic
    # -----------------------------------------------------------------------
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-opus-4-8"

    # -----------------------------------------------------------------------
    # OpenAI
    # -----------------------------------------------------------------------
    openai_api_key: str = ""
    openai_model: str = "gpt-4o"

    # -----------------------------------------------------------------------
    # Azure OpenAI
    # -----------------------------------------------------------------------
    azure_openai_api_key: str = ""
    azure_openai_endpoint: str = ""
    azure_openai_api_version: str = "2024-02-01"
    azure_openai_deployment: str = "gpt-4o"

    # -----------------------------------------------------------------------
    # Google Gemini
    # -----------------------------------------------------------------------
    gemini_api_key: str = ""
    gemini_model: str = "gemini-1.5-pro"

    # -----------------------------------------------------------------------
    # AWS Bedrock
    # -----------------------------------------------------------------------
    bedrock_model_id: str = "anthropic.claude-opus-4-8-v1:0"
    # reuse aws_access_key_id / aws_secret_access_key / aws_default_region

    # -----------------------------------------------------------------------
    # Mistral
    # -----------------------------------------------------------------------
    mistral_api_key: str = ""
    mistral_model: str = "mistral-large-latest"

    # -----------------------------------------------------------------------
    # Groq
    # -----------------------------------------------------------------------
    groq_api_key: str = ""
    groq_model: str = "llama-3.3-70b-versatile"

    # -----------------------------------------------------------------------
    # Cohere
    # -----------------------------------------------------------------------
    cohere_api_key: str = ""
    cohere_model: str = "command-r-plus"

    # -----------------------------------------------------------------------
    # Together AI
    # -----------------------------------------------------------------------
    together_api_key: str = ""
    together_model: str = "meta-llama/Llama-3.3-70B-Instruct-Turbo"

    # -----------------------------------------------------------------------
    # Perplexity
    # -----------------------------------------------------------------------
    perplexity_api_key: str = ""
    perplexity_model: str = "llama-3.1-sonar-large-128k-online"

    # -----------------------------------------------------------------------
    # Ollama (local)
    # -----------------------------------------------------------------------
    ollama_base_url: str = "http://localhost:11434/v1"
    ollama_model: str = "llama3.3"

    # -----------------------------------------------------------------------
    # LM Studio (local)
    # -----------------------------------------------------------------------
    lm_studio_base_url: str = "http://localhost:1234/v1"
    lm_studio_model: str = "lmstudio-community/Meta-Llama-3.1-8B-Instruct-GGUF"

    # -----------------------------------------------------------------------
    # vLLM (local)
    # -----------------------------------------------------------------------
    vllm_base_url: str = "http://localhost:8000/v1"
    vllm_model: str = "meta-llama/Llama-3.3-70B-Instruct"

    # -----------------------------------------------------------------------
    # llama.cpp (local)
    # -----------------------------------------------------------------------
    llamacpp_base_url: str = "http://localhost:8080/v1"
    llamacpp_model: str = "llama-3.3-70b"

    # -----------------------------------------------------------------------
    # Databases
    # -----------------------------------------------------------------------
    database_url: str = "postgresql+asyncpg://aisoc:password@localhost:5432/aisoc"
    database_pool_size: int = 20
    redis_url: str = "redis://localhost:6379/0"
    redis_pool_size: int = 10
    elasticsearch_url: str = "http://localhost:9200"
    elasticsearch_index_prefix: str = "aisoc"

    # Kafka
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_topic_alerts: str = "aisoc.alerts"
    kafka_topic_events: str = "aisoc.events"
    kafka_topic_incidents: str = "aisoc.incidents"

    # SIEM
    splunk_host: str = ""
    splunk_port: int = 8089
    splunk_token: str = ""
    splunk_index: str = "main"
    elastic_siem_url: str = ""
    elastic_siem_api_key: str = ""
    qradar_host: str = ""
    qradar_token: str = ""
    azure_sentinel_workspace_id: str = ""
    azure_sentinel_primary_key: str = ""

    # AWS
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_default_region: str = "us-east-1"
    aws_guardduty_detector_id: str = ""

    # Azure
    azure_subscription_id: str = ""
    azure_tenant_id: str = ""
    azure_client_id: str = ""
    azure_client_secret: str = ""

    # GCP
    gcp_project_id: str = ""
    gcp_credentials_file: str = ""

    # Threat Intel
    virustotal_api_key: str = ""
    shodan_api_key: str = ""
    misp_url: str = ""
    misp_key: str = ""
    abuseipdb_api_key: str = ""
    alienvault_otx_key: str = ""

    # Ticketing
    jira_url: str = ""
    jira_email: str = ""
    jira_token: str = ""
    jira_project_key: str = "SOC"
    servicenow_url: str = ""
    servicenow_user: str = ""
    servicenow_password: str = ""
    pagerduty_integration_key: str = ""

    # Notifications
    slack_bot_token: str = ""
    slack_channel_alerts: str = "#soc-alerts"
    slack_channel_critical: str = "#soc-critical"
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    email_from: str = ""

    # Auth
    jwt_secret_key: str = "change_this_jwt_secret"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7

    # Rate Limiting
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])

    # Agent Configuration
    agent_max_concurrent: int = 20
    agent_timeout_seconds: int = 300
    agent_retry_attempts: int = 3
    agent_retry_delay: int = 5

    # Monitoring
    prometheus_port: int = 9090
    grafana_url: str = "http://localhost:3000"
    grafana_api_key: str = ""

    def is_production(self) -> bool:
        return self.app_env == "production"

    def is_development(self) -> bool:
        return self.app_env == "development"

    def get_ai_config(self) -> dict[str, Any]:
        return {
            "provider": self.ai_provider.value,
            "max_tokens": self.ai_max_tokens,
            "temperature": self.ai_temperature,
        }


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
