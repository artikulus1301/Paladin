.PHONY: up down logs build pull-models shell-neo4j

# Start all services
up:
	docker compose up -d --build
	@echo "✅ Bot is running. Check logs: make logs"

# Stop all services
down:
	docker compose down

# Rebuild bot image only
build:
	docker compose build bot

# View bot logs (follow)
logs:
	docker compose logs -f bot

# Pull Qwen model into Ollama (runs automatically on first start)
pull-models:
	docker compose exec ollama ollama pull qwen3.5:9b
	docker compose exec ollama ollama pull nomic-embed-text

# Open Cypher shell in Neo4j
shell-neo4j:
	docker compose exec neo4j cypher-shell -u neo4j -p $(shell grep NEO4J_PASSWORD .env | cut -d= -f2)

# Neo4j browser URL
neo4j-browser:
	@echo "Open: http://localhost:7474"

# Check health of all services
health:
	@docker compose ps
	@echo ""
	@curl -sf http://localhost:11434/api/tags | python3 -c "import sys,json; d=json.load(sys.stdin); print('Ollama models:', [m['name'] for m in d['models']])" 2>/dev/null || echo "Ollama not ready"

# Restart bot only (e.g. after code change)
restart-bot:
	docker compose up -d --build bot
