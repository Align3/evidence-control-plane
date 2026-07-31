# Setup Guide

**Repo location:** `docs/setup-guide.md`
**From:** a Windows machine with nothing installed
**To:** two agents building in parallel, first PR open
**Version:** 0.4 — corrected
**Time:** about two hours, most of it waiting on downloads

> **Corrections from 0.3:** Part 3.3 required only three status checks while CI
> runs four, so a pull request could merge to `main` with
> `Cross-implementation conformance` red. All four are now required.

> **Corrections from 0.2:** `pytest` no longer fails on a fresh scaffold. It was
> collecting zero tests and exiting 5, which CI reports as a failure;
> `tests/test_scaffold.py` now asserts the scaffold invariants. Part 6 and the
> completion checklist both said the correct starting state was a failing
> `pytest` — it is 5 passed, 1 skipped, with no story scenarios collected.

> **Corrections from 0.1:** removed the deadsnakes PPA and `update-alternatives`
> (24.04 already has Python 3.12; repointing it breaks apt); removed the required
> approving review on `main` (a solo maintainer cannot approve their own PR, which
> with `enforce_admins` locks the branch permanently); `docker-compose.yml` now
> reads `POSTGRES_PORT`/`POSTGRES_DB`/`REDIS_PORT` so the second worktree can start.

Work through in order. Each part ends with a verification step — if it fails, stop and fix before continuing.

---

## Part 0 — Windows side (15 min)

### 0.1 Install WSL2

In PowerShell **as Administrator**:

```powershell
wsl --install -d Ubuntu-24.04
```

Reboot when prompted. On first launch, set a username and password.

### 0.2 Give WSL enough memory

Two agents plus two Postgres instances plus Go builds will thrash at the default. Create `C:\Users\<you>\.wslconfig`:

```ini
[wsl2]
memory=12GB
processors=6
swap=4GB
```

Then in PowerShell:

```powershell
wsl --shutdown
```

### 0.3 Docker Desktop

Install Docker Desktop, then **Settings → Resources → WSL Integration → enable for Ubuntu-24.04**.

**Verify:**

```bash
# in WSL
docker run --rm hello-world
free -g | head -2      # should show ~12GB total
```

---

## Part 1 — WSL toolchain (20 min)

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y build-essential git curl unzip postgresql-client jq

# Python: Ubuntu 24.04 already ships 3.12 as python3. Do NOT add the deadsnakes
# PPA or repoint python3 via update-alternatives -- that breaks apt.
sudo apt install -y python3.12-venv python3-pip

# Go 1.23
curl -fsSL https://go.dev/dl/go1.23.5.linux-amd64.tar.gz | sudo tar -C /usr/local -xz
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/.local/bin' >> ~/.bashrc
source ~/.bashrc

# Node 22 (not needed until EV-10, install now to avoid a later detour)
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs

# GitHub CLI
sudo mkdir -p -m 755 /etc/apt/keyrings
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
  | sudo tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null
sudo chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
  | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt update && sudo apt install -y gh
```

**Verify:**

```bash
python3 --version   # 3.12.x
go version          # go1.23.5
node --version      # v22.x
gh --version
```

### 1.1 Git and GitHub auth

```bash
git config --global user.name "Ibrahim Adamu"
git config --global user.email "<your email>"
git config --global init.defaultBranch develop
git config --global pull.rebase true

gh auth login   # HTTPS, authenticate via browser, yes to git credential helper
```

---

## Part 2 — Repository scaffold (10 min)

> **Keep everything under `~/dev`, never `/mnt/c/`.** Cross-filesystem I/O is roughly ten times slower and breaks file watching — which matters when two agents run test suites at once.

```bash
mkdir -p ~/dev/evidence-control-plane && cd ~/dev/evidence-control-plane

# Put bootstrap.sh and the artifacts somewhere reachable first, e.g. ~/artifacts/
bash ~/artifacts/bootstrap.sh

cp ~/artifacts/*.md docs/
cp ~/artifacts/extract_features.py tools/
rm -f docs/setup-guide.md && cp ~/artifacts/setup-guide.md docs/   # this file
```

You should now have 14 documents in `docs/` — the eleven specs plus `dev-environment.md`, `agent-prompts.md`, and this guide.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
make features
```

**Verify:**

```bash
ls docs/*.md | wc -l          # 14
ls tests/features/*.feature   # 8 files
make check                    # "55 scenarios across 8 feature files", exit 0
cd verifier-go && go build ./... && cd ..
```

If `make check` fails with DRIFT, run `make features` and try again.

### 2.1 First commit

```bash
git add -A
git commit -m "EV-01: repository scaffold, specifications, and CI"
```

---

## Part 3 — GitHub (20 min)

### 3.1 Create the repository — **private**

```bash
gh repo create evidence-control-plane --private --source=. --remote=origin --push
```

The specification becomes public later, deliberately and on its own timeline. Methodology, threat model, and coverage internals are the moat. Do not make this repo public for free Actions minutes — 2,000/month on the Free plan is ample for this CI.

### 3.2 Create the other branches

Branch protection can only reference status checks GitHub has already seen, so CI has to run once first.

```bash
git push -u origin develop
# Wait for the first CI run to complete
gh run watch

git checkout -b staging && git push -u origin staging
git checkout -b main    && git push -u origin main
git checkout develop
```

### 3.3 Branch protection on `main`

```bash
gh api -X PUT repos/:owner/evidence-control-plane/branches/main/protection \
  --input - <<'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "Feature files match documents",
      "Python",
      "Go verifier",
      "Cross-implementation conformance"
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": null,
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false
}
EOF
```

Then `staging`, which needs CI green but not the signoff:

```bash
gh api -X PUT repos/:owner/evidence-control-plane/branches/staging/protection \
  --input - <<'EOF'
{
  "required_status_checks": {"strict": true, "contexts": ["Feature files match documents", "Python", "Go verifier", "Cross-implementation conformance"]},
  "enforce_admins": false,
  "required_pull_request_reviews": null,
  "restrictions": null
}
EOF
```

`required_pull_request_reviews` is null deliberately. GitHub does not let you approve
your own pull request, and with `enforce_admins: true` a review requirement would lock
`main` permanently for a solo maintainer. The real gate is the cross-model agent review
plus the signoff artifact.

All four CI jobs are required, not three. `Cross-implementation conformance` is a
placeholder until EV-05 — it currently echoes and passes — but requiring it now
means the gate is already enforced the moment it asserts ES-S-007 for real, rather
than depending on someone remembering to add it. It carries `needs: [python, go]`,
so it can only be skipped when a required check has already failed; it cannot
deadlock a pull request on its own.

`develop` stays unprotected — agents push to it freely.

### 3.4 Repository settings

```bash
gh repo edit --enable-squash-merge --enable-merge-commit=false \
  --enable-rebase-merge=false --delete-branch-on-merge
```

**Verify:**

```bash
gh api repos/:owner/evidence-control-plane/branches/main/protection | jq '.required_status_checks.contexts'
```

The drift check must appear in that list. It is the only mechanical defence against an agent editing a scenario to make a build pass.

---

## Part 4 — Parallel worktrees (15 min)

### 4.1 Create them

```bash
cd ~/dev/evidence-control-plane
mkdir -p ~/dev/wt

git worktree add ~/dev/wt/t1-evidence -b agent/ev-02-evidence-schema
git worktree add ~/dev/wt/t2-ledger   -b agent/ev-06-ledger-schema
```

### 4.2 Separate databases

Worktrees isolate the filesystem but not Postgres. Two agents running migrations against one database is the same collision by another route.

```bash
# Track 1
cd ~/dev/wt/t1-evidence
COMPOSE_PROJECT_NAME=t1 POSTGRES_PORT=5432 REDIS_PORT=6379 POSTGRES_DB=evidence_t1 \
  docker compose up -d

# Track 2
cd ~/dev/wt/t2-ledger
COMPOSE_PROJECT_NAME=t2 POSTGRES_PORT=5433 REDIS_PORT=6380 POSTGRES_DB=evidence_t2 \
  docker compose up -d
```

### 4.3 Per-worktree environment

```bash
cd ~/dev/wt/t1-evidence
cat > .env <<'EOF'
COMPOSE_PROJECT_NAME=t1
POSTGRES_PORT=5432
POSTGRES_DB=evidence_t1
REDIS_PORT=6379
DATABASE_URL=postgresql://evidence:devonly@localhost:5432/evidence_t1
REDIS_URL=redis://localhost:6379/0
EVIDENCE_SIGNING_KEY_PATH=/home/USER/.evidence/dev-evidence.ed25519
ISSUER_SIGNING_KEY_PATH=/home/USER/.evidence/dev-issuer.ed25519
EOF
sed -i "s|/home/USER|$HOME|g" .env

cd ~/dev/wt/t2-ledger
sed 's/t1/t2/g; s/5432/5433/g; s/6379/6380/g' ~/dev/wt/t1-evidence/.env > .env
```

### 4.4 Development signing keys — two of them

```bash
mkdir -p ~/.evidence && chmod 700 ~/.evidence
openssl genpkey -algorithm ed25519 -out ~/.evidence/dev-evidence.ed25519
openssl genpkey -algorithm ed25519 -out ~/.evidence/dev-issuer.ed25519
chmod 600 ~/.evidence/*.ed25519
```

Two separate keys from day one (DE-008). A single key used for both namespaces makes `SE-S-001` pass for the wrong reason and hides a real design violation until much later.

### 4.5 Virtualenv per worktree

```bash
for w in ~/dev/wt/t1-evidence ~/dev/wt/t2-ledger; do
  cd "$w" && python3 -m venv .venv && ./.venv/bin/pip install -q -e ".[dev]"
done
```

**Verify:**

```bash
docker ps --format '{{.Names}}\t{{.Ports}}' | grep postgres   # two, on 5432 and 5433
psql "postgresql://evidence:devonly@localhost:5432/evidence_t1" -c '\l' >/dev/null && echo t1 ok
psql "postgresql://evidence:devonly@localhost:5433/evidence_t2" -c '\l' >/dev/null && echo t2 ok
```

---

## Part 5 — Agents (10 min)

```bash
npm install -g @anthropic-ai/claude-code
# Codex CLI per its current install instructions
```

Authenticate each, then confirm both can run a trivial command in a worktree.

**Assignment for the opening phase:**

| Track | Directory | Story | Builder | Reviewer |
|---|---|---|---|---|
| T1 | `~/dev/wt/t1-evidence` | EV-02 → 03 → 04 → 05 | Model A | Model B |
| T2 | `~/dev/wt/t2-ledger` | EV-06 | Model B | Model A |

Which model is A and which is B does not matter. That they differ does (AG-008).

**Do not start a third agent.** EV-07 joins T1 and T2 and cannot begin until both land; everything after depends on it. The graph is two wide right now.

---

## Part 6 — First story

For each agent, in its own worktree, paste the builder prompt from `docs/agent-prompts.md` §1 with the story ID substituted.

Before the agent starts, from inside the worktree:

```bash
source .venv/bin/activate
make check      # no drift
pytest -q       # 5 passed, 1 skipped — scaffold invariants only
```

The 55 scenarios in `tests/features/` are not collected: pytest-bdd needs step
definitions and none exist yet. Writing the ones for this story's scenarios, so
that they collect and fail, is the first task inside the story rather than a
precondition of it. An agent that begins with nothing red has nothing to drive
against.

While they work, watch for two things:

- **Anything modified under `tests/features/`.** That directory is generated. Any change there is either an agent editing a scenario or a stale regeneration, and both need stopping.
- **Anything modified outside the story's Touches set.** `git status` in each worktree.

When a story is done:

```bash
make all
git push -u origin agent/ev-02-evidence-schema
gh pr create --base develop --title "EV-02: evidence schema and canonicalisation"
```

---

## Part 7 — First review

**In the main clone, not the worktree. Different model from the builder.**

```bash
cd ~/dev/evidence-control-plane
gh pr checkout <n>
```

Paste the reviewer prompt from `docs/agent-prompts.md` §2. For EV-05 append the adversarial pass from §2.1.

Your own three checks, which take a minute and catch the worst failures:

```bash
# 1. Were the generated feature files touched?
git diff origin/develop --stat -- tests/features/     # must be empty

# 2. Did it stay inside its Touches set?
git diff origin/develop --name-only

# 3. Do the scenarios it claims actually pass?
pytest -q -k "ES_S"
```

Merge only on an explicit Go from the reviewing agent plus those three clean. CI green is necessary, not sufficient.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `make check` fails with DRIFT | A doc changed without regeneration | `make features`, commit both |
| Port already allocated | Compose file is the un-parameterised 0.1 version | Confirm `docker-compose.yml` contains `${POSTGRES_PORT:-5432}`, not a hard-coded `5432:5432` |
| Extremely slow tests | Repo on `/mnt/c/` | Move to `~/dev` |
| Branch protection rejects the check name | CI has not run under that exact name | Push to develop, wait for a run, retry |
| Agent modified a `.feature` file | AG-001 violation | Revert, regenerate, remind it the directory is generated |
| Postgres healthy but connection refused | Docker Desktop WSL integration off | Settings → Resources → WSL Integration |
| Both agents editing `docs/data-model.md` | Migration number contention | Claim numbers in separate commits (DM-001) |

---

## Completion checklist

- [ ] `make all` passes on a clean checkout of `develop`
- [ ] Private repo; `develop`, `staging`, `main` all pushed
- [ ] Branch protection on `main` includes the drift check as required
- [ ] Two worktrees on separate branches
- [ ] Two Postgres instances on distinct ports with distinct databases
- [ ] Two separate dev signing keys, evidence and issuer namespaces
- [ ] Both agents authenticated and able to run in their worktrees
- [ ] `pytest` **passes** in both worktrees — 5 passed, 1 skipped. Those are the
      scaffold invariants in `tests/test_scaffold.py`. No story scenarios are
      collected, because no step definitions exist yet. That is the correct
      starting state
- [ ] Builder and reviewer are different models

---

## In parallel, away from the keyboard

The build is not the critical path for the company. While the agents work through EV-02 and EV-06, the highest-value things you can do are the ones nothing here unblocks:

1. **The destination-system probe.** Run the qualification procedure in `coverage-methodology.md` §7 against two or three candidate systems. It gates EV-13 and it is the riskiest assumption in the venture.
2. **Company formation.** Weeks of lead time, and no attestation can be issued to anyone until an issuing legal entity exists.
3. **Vendor outreach**, with the one qualifying question: *can you list everything your agent did last week, separately from what your human staff did?*
