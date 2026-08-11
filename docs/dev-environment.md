# Development Environment

**Repo location:** `docs/dev-environment.md`
**Purpose:** WSL setup, parallel agent isolation, GitHub configuration.

---

## 1. WSL

Ubuntu 24.04 under WSL2. Keep the repository on the **Linux filesystem** (`~/dev/...`), never under `/mnt/c/`. Cross-filesystem I/O is roughly an order of magnitude slower and breaks file-watching, which matters when two agents are running test suites simultaneously.

```bash
sudo apt update && sudo apt install -y \
  build-essential git curl postgresql-client

# Python 3.12
sudo add-apt-repository -y ppa:deadsnakes/ppa && sudo apt update
sudo apt install -y python3.12 python3.12-venv python3.12-dev

# Go 1.23 (for the verifier)
curl -fsSL https://go.dev/dl/go1.23.5.linux-amd64.tar.gz | sudo tar -C /usr/local -xz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc

# Node 22 (for the TypeScript SDK, EV-10)
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - && sudo apt install -y nodejs

# Docker Desktop with WSL2 integration enabled, or docker-ce inside WSL
```

**DE-001** — Give WSL enough memory. Two agents plus Postgres plus Go builds will thrash at the 4 GB default. In `%UserProfile%\.wslconfig`:

```ini
[wsl2]
memory=12GB
processors=6
```

---

## 2. Parallel agents via worktrees

Two agents in one working tree will collide. Not might — will. Git worktrees give each agent its own checkout and its own branch, sharing one object store.

```bash
cd ~/dev
git clone git@github.com:<you>/evidence-control-plane.git
cd evidence-control-plane

mkdir -p ~/dev/wt

# Track 1 — evidence primitives (EV-02 → 03 → 04 → 05)
git worktree add ~/dev/wt/t1-evidence -b agent/ev-02-evidence-schema

# Track 2 — ledger (EV-06)
git worktree add ~/dev/wt/t2-ledger -b agent/ev-06-ledger-schema
```

Each agent runs with its worktree as its working directory and never leaves it.

**DE-002 — Never run `git stash` in a worktree an agent is using.** On DamDam a stash during a review session swept up another session's untracked files before being popped back. Worktrees prevent most interference; stash reaches across it. If an agent needs to set work aside, it commits to its own branch.

**DE-003 — Each worktree gets its own database.** Sharing one Postgres between two agents running migrations concurrently is the same collision by another route.

```bash
# In each worktree, a distinct port and database
# t1: POSTGRES_PORT=5432 DB=evidence_t1
# t2: POSTGRES_PORT=5433 DB=evidence_t2
```

**DE-004 — Assign tracks by Touches set, never by story number.** Before starting a second agent, check `docs/prd.md` and confirm the two stories' Touches sets are disjoint. This is the rule that was learned expensively.

### Track assignment for the opening phase

| Track | Stories | Touches | Agent |
|---|---|---|---|
| T1 | EV-02 → 03 → 04 → 05 | `sdk-python/evidence/`, `tests/vectors/`, `verifier-go/` | Builder |
| T2 | EV-06 | `services/ledger/`, `migrations/`, `docs/data-model.md` | Builder |

Disjoint. Both start immediately after `EV-01` lands on `develop`.

**EV-07 (ingestion) depends on both** — it is the join point, and it should be a single agent after T1 and T2 merge. Do not start it early.

---

## 3. GitHub

**DE-005 — The repository is private.** The evidence specification becomes public later, deliberately and on its own timeline. Everything else — methodology, threat model, coverage internals — is the moat.

Note the consequence: private repositories consume paid Actions minutes (2,000/month free on the Free plan). The CI here is light, but watch it. Do **not** repeat the DamDam manoeuvre of going public for free minutes — a public repo plus a self-hosted runner is a code-execution risk, and here the repository contents are the asset.

### Branch protection

```
develop   — no protection; agents push freely
staging   — requires CI green
main      — requires CI green + signoff artifact + enforce_admins: true
```

Following the DamDam convention: `develop → staging → main`, with `main` representing what is actually deployed.

### Required status checks on `main`

- `Feature files match documents` (the AG-001 drift gate)
- `Python`
- `Go verifier`
- `Cross-implementation conformance` (once EV-05 lands)
- Release signoff validator (port `scripts/validate-release-signoff.sh` from DamDam)

**DE-006** — The drift check is a required status, not advisory. It is the only mechanical defence against an agent editing a scenario to make a build pass.

### Repository settings

- Squash merge only; delete branch on merge
- Require linear history on `main`
- Dependabot on; security advisories on

---

## 4. Daily loop

```bash
# Agent starts
cd ~/dev/wt/t1-evidence
git fetch origin && git rebase origin/develop
make check          # confirm no drift before starting
pytest -q           # confirm the scenarios you're about to satisfy are failing

# ... agent works ...

make all            # drift, lint, tests, go build
git push -u origin agent/ev-02-evidence-schema
gh pr create --base develop --title "EV-02: evidence schema and canonicalisation"
```

**DE-007** — Review happens in a **fresh session in the main clone**, run by a **different model from the builder** (AG-008), and reproduces claims with real commands. Reviewing inside the authoring worktree invites accepting a self-report; reviewing with the same model that wrote the code inherits its blind spots.

---

## 5. Environment variables

```bash
# .env — never committed
DATABASE_URL=postgresql://evidence:devonly@localhost:5432/evidence_t1
REDIS_URL=redis://localhost:6379/0
EVIDENCE_SIGNING_KEY_PATH=~/.evidence/dev-tenant.ed25519
ISSUER_SIGNING_KEY_PATH=~/.evidence/dev-issuer.ed25519
```

**DE-008** — Development keys live outside the repository and the two namespaces are separate files from day one. A single dev key used for both evidence and issuer signing will make `SE-S-001` pass for the wrong reason and hide a real design violation until much later.

---

## 6. What to install where

| Component | Location | Notes |
|---|---|---|
| Postgres, Redis | Docker, per worktree | Distinct ports |
| Python venv | Per worktree | `pip install -e ".[dev]"` |
| Go toolchain | System | Shared; no per-worktree state |
| Node | System | Only needed from EV-10 |

---

## 7. Before the first PR

- [ ] `make all` passes on a clean checkout
- [ ] Both worktrees created with disjoint tracks
- [ ] Separate databases confirmed
- [ ] Separate dev signing keys for evidence and issuer namespaces
- [ ] Branch protection configured on `main`
- [ ] Drift check confirmed as a required status
- [ ] `docs/agent-working-agreement.md` included in both agents' opening context

## Verification classifications

> **Verification (document default) — non-testable (process).** These requirements govern local development, worktree, secret, and review procedure rather than product runtime behaviour.
