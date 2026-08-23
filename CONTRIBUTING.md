# Contributing Guide

This project is designed for parallel team work with minimal merge conflicts.

## 1. Branching Rule

Do not commit directly to `main`.

Create one branch per task:

- `feature/<short-name>`
- `fix/<short-name>`
- `docs/<short-name>`

Examples:

- `feature/simulation-event-stream`
- `fix/anomaly-threshold`
- `docs/update-data-interface`

## 2. Keep Changes Small

Each pull request should do one thing only.

Good:

- one module change
- one bug fix
- one documentation update

Avoid mixing code changes + dependency upgrades + docs in the same PR.

## 3. Sync Before You Push

Before pushing your branch:

1. Pull latest `main`
2. Rebase or merge `main` into your branch
3. Run tests locally

## 4. Respect Data Contracts

All modules must follow the shared data interface in [docs/README.md](docs/README.md).

If you need to change a contract:

- Open a dedicated PR titled `Interface Change: <title>`
- Explain impact on `simulation`, `detection`, `containment`, `dashboard`
- Get explicit approval before merge

## 5. PR Requirements

A PR should include:

- clear purpose
- changed files summary
- test evidence
- rollback note (if risky)

Use the pull request template in `.github/pull_request_template.md`.

## 6. Conflict Prevention Rules

- Claim your task before starting.
- Avoid editing the same file as another person at the same time.
- If overlap is unavoidable, coordinate early and merge in smaller PRs.

## 7. Suggested Ownership

Path ownership is defined in `.github/CODEOWNERS`.

Reviewers from the owning module should approve related PRs.
