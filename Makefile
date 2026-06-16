.PHONY: install dev test lint format docker-up docker-down docker-build docker-dev logs clean

# -----------------------------------------------------------------------
# Development
# -----------------------------------------------------------------------
install:
	pip install -e ".[dev]"

dev:
	uvicorn api.main:app --reload --host 0.0.0.0 --port 8000

dev-frontend:
	cd frontend && npm install --legacy-peer-deps && npm run dev

test:
	pytest tests/ -v --cov=. --cov-report=term-missing

lint:
	ruff check .

format:
	ruff format .

# -----------------------------------------------------------------------
# Docker — produccion
# -----------------------------------------------------------------------
docker-build:
	docker compose build

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down

docker-restart:
	docker compose restart

logs:
	docker compose logs -f

logs-backend:
	docker compose logs -f backend

logs-frontend:
	docker compose logs -f frontend

# -----------------------------------------------------------------------
# Docker — desarrollo (hot-reload)
# -----------------------------------------------------------------------
docker-dev:
	docker compose -f docker-compose.yml -f docker-compose.dev.yml up

docker-dev-build:
	docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build

# -----------------------------------------------------------------------
# Utilidades
# -----------------------------------------------------------------------
clean:
	docker compose down -v --remove-orphans
	docker system prune -f

ps:
	docker compose ps

shell-backend:
	docker compose exec backend bash

shell-frontend:
	docker compose exec frontend sh

db-shell:
	docker compose exec postgres psql -U soc -d aisoc
