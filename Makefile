.PHONY: dev features check test lint go-test typescript-vectors all

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

# ES-029 vectors are normative for every implementation, not only the two with
# their own CI job. Without this target a TypeScript operation can fall out of
# conformance -- or never be built at all -- behind a green Python and Go run,
# which is how `verify_bundle` stayed unimplemented here after EV-41 published
# its vectors.
typescript-vectors:
	cd sdk_typescript && npm ci --no-audit --no-fund && npm run typecheck && npm test && npm run test:vectors

lint:
	ruff check .
	mypy services sdk_python

all: check lint test go-test typescript-vectors
