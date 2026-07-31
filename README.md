# Verifiable Evidence Control Plane

Proof of what an agent was authorized to do, what it actually did, whether human
oversight was real, and whether trust claims still hold after deployment.

## Start here

1. `docs/agent-working-agreement.md` — read before touching anything
2. `docs/prd.md` — stories, dependencies, and Touches sets
3. `docs/coverage-methodology.md` — the intellectual core

## Development

    make dev        # containers + editable install
    make features   # regenerate tests/features from docs/
    make all        # drift check, lint, tests, go build

`tests/features/` is generated. Never edit it by hand (AG-001).
