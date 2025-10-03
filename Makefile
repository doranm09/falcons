# CyberPenTest Test Runner Makefile

# Default Python and Django settings
PYTHON = python
DJANGO_SETTINGS_MODULE = cyber_pen_test.test_settings
MANAGE = $(PYTHON) manage.py

# Virtual environment support
ifdef VIRTUAL_ENV
    PIP = pip
else ifneq (,$(wildcard $(HOME)/.virtualenvs/cyber_pen_test/bin/pip))
    PIP = $(HOME)/.virtualenvs/cyber_pen_test/bin/pip
else
    PIP = pip
endif

.PHONY: help install test test-server test-e2e clean lint

help: ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

install: ## Install development dependencies
	$(PIP) install -r requirements-dev.txt
	$(PYTHON) -m playwright install --with-deps chromium

install-deps: ## Install all dependencies (app + dev)
	$(PIP) install -r requirements.txt
	$(PIP) install -r requirements-dev.txt
	$(PYTHON) -m playwright install --with-deps chromium

migrate: ## Run Django migrations
	$(MANAGE) migrate --settings=$(DJANGO_SETTINGS_MODULE)

test: ## Run all tests (server + E2E)
	$(PYTHON) -m pytest -q --settings=$(DJANGO_SETTINGS_MODULE)

test-server: ## Run server-side tests only
	$(PYTHON) -m pytest tests/server -q --settings=$(DJANGO_SETTINGS_MODULE)

test-e2e: ## Run E2E tests only
	$(PYTHON) -m pytest tests/e2e -q --settings=$(DJANGO_SETTINGS_MODULE)

test-verbose: ## Run all tests with verbose output
	$(PYTHON) -m pytest --settings=$(DJANGO_SETTINGS_MODULE) -v

test-cov: ## Run tests with coverage report
	$(PYTHON) -m pytest --settings=$(DJANGO_SETTINGS_MODULE) --cov=dashboard --cov-report=html --cov-report=term

test-cov-xml: ## Run tests with coverage report (XML format for CI)
	$(PYTHON) -m pytest --settings=$(DJANGO_SETTINGS_MODULE) --cov=dashboard --cov-report=xml --cov-report=term

clean: ## Clean up test artifacts
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name ".coverage" -delete
	rm -rf htmlcov/
	rm -rf .pytest_cache/

lint: ## Run linting (flake8)
	$(PIP) install flake8
	flake8 dashboard/ tests/ --max-line-length=100 --ignore=E501,W503

dev-server: ## Run development server
	$(MANAGE) runserver --settings=cyber_pen_test.settings

shell: ## Open Django shell
	$(MANAGE) shell --settings=$(DJANGO_SETTINGS_MODULE)
