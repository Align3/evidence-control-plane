.PHONY: dev features check test lint go-test all

dev:
	docker compose up -d
	pip install -e ".[dev]"

features:
	python tools/extract_features.py --docs docs --out tests/features

check:
	python tools/extract_features.py --docs docs --out tests/features --check

test:
	pytest -q

go-test:
	cd verifier-go && go test ./... && go build ./...

lint:
	ruff check .
	mypy services sdk_python

all: check lint test go-test
