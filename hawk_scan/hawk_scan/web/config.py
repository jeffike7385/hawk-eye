from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://hawkscan:hawkscan@localhost:5432/hawkscan"
    redis_url: str = "redis://localhost:6379/0"
    secret_key: str = "change-me-in-production"
    azure_tenant_id: str = ""
    azure_client_id: str = ""
    azure_client_secret: str = ""
    retention_days: int = 90
    max_concurrent_scans: int = 3
    session_ttl_hours: int = 8
    reports_dir: str = "/app/reports"
    base_url: str = "http://localhost:8000"

    model_config = {"env_prefix": "HAWKSCAN_", "env_file": ".env"}


def get_settings() -> Settings:
    return Settings()
