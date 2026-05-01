from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional, List


class Settings(BaseSettings):
    # Telegram
    telegram_token: str = Field(..., env="TELEGRAM_TOKEN")
    allowed_users: Optional[str] = Field(None, env="ALLOWED_USERS")  # CSV of user IDs

    # Neo4j
    neo4j_uri: str = Field("bolt://localhost:7687", env="NEO4J_URI")
    neo4j_user: str = Field("neo4j", env="NEO4J_USER")
    neo4j_password: str = Field("changeme123", env="NEO4J_PASSWORD")
    max_neo4j_results: int = Field(10, env="MAX_NEO4J_RESULTS")

    # Ollama
    ollama_base_url: str = Field("http://localhost:11434", env="OLLAMA_BASE_URL")
    ollama_model: str = Field("qwen3.5:9b", env="OLLAMA_MODEL")
    ollama_timeout: int = Field(120, env="OLLAMA_TIMEOUT")

    # Internet / Search
    searxng_url: str = Field("https://searx.be", env="SEARXNG_URL")
    max_search_results: int = Field(5, env="MAX_SEARCH_RESULTS")

    # Verifier thresholds
    verifier_entropy_window: int = Field(50, env="VERIFIER_ENTROPY_WINDOW")
    entropy_z_threshold: float = Field(2.0, env="ENTROPY_Z_THRESHOLD")
    semantic_similarity_threshold: float = Field(0.35, env="SEMANTIC_SIMILARITY_THRESHOLD")
    perplexity_threshold: float = Field(500.0, env="PERPLEXITY_THRESHOLD")

    # Logging
    log_level: str = Field("INFO", env="LOG_LEVEL")

    @property
    def allowed_user_ids(self) -> List[int]:
        if not self.allowed_users:
            return []
        return [int(uid.strip()) for uid in self.allowed_users.split(",") if uid.strip()]

    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
