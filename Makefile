.PHONY: help install test run docker-build docker-up docker-down helm-install helm-uninstall

help:
	@echo "Universal Agentic Fabric - Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  install       - Install Python dependencies"
	@echo "  test          - Run tests"
	@echo "  run           - Run the application"
	@echo "  docker-build  - Build Docker images"
	@echo "  docker-up     - Start services with Docker Compose"
	@echo "  docker-down   - Stop services"
	@echo "  helm-install  - Install with Helm"
	@echo "  helm-uninstall - Uninstall Helm release"

install:
	pip install -r requirements.txt

test:
	pytest tests/ -v --cov=src --cov-report=html

run:
	python -m src.main

docker-build:
	docker-compose build

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

helm-install:
	helm install agentic-defense ./helm-chart

helm-uninstall:
	helm uninstall agentic-defense

lint:
	ruff check src/ connectors/
	black --check src/ connectors/

format:
	black src/ connectors/
	ruff check --fix src/ connectors/

