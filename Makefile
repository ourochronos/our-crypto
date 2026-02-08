.PHONY: help install dev lint format test test-unit test-int test-cov clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install package
	pip install -e .

dev: ## Install package with dev dependencies
	pip install -e ".[dev]"
	pre-commit install

lint: ## Run linters (ruff + mypy)
	ruff check src/ tests/
	ruff format --check src/ tests/
	mypy src/

format: ## Auto-format code
	ruff check --fix src/ tests/
	ruff format src/ tests/

test: test-unit ## Run tests (unit only by default)

test-unit: ## Run unit tests
	pytest tests/ -m "not integration and not slow" -v

test-int: ## Run integration tests
	pytest tests/ -m integration -v --timeout=60

test-all: ## Run all tests
	pytest tests/ -v --timeout=120

test-cov: ## Run tests with coverage report
	pytest tests/ -m "not integration and not slow" --cov --cov-report=term-missing --cov-report=html

clean: ## Remove build artifacts and caches
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
