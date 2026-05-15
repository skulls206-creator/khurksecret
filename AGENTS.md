# AGENTS.md — AI Builders' Guide to khurksecret

## Project

**khurksecret** — Shamir's Secret Sharing web app.
Split and reconstruct secrets in the browser. No server. No telemetry. Zero-dependency secret sharing using GF(256) arithmetic.

## Stack

- Vanilla JS (`app.js`)
- Zero dependencies
- PWA-enabled (`manifest.json`)
- Hosted via GitHub Pages (CNAME for custom domain)

## Coordination Rules

- **SYNC.md** or **CHANGELOG.md** is the source of truth for what changed between builders.
- Before making changes, check this repo and read the latest changelog + AGENTS.md.
- New features → new commit with meaningful message.
- Keep `app.js` clean — it's the entire app logic in one file for simplicity.
- If splitting into modules is needed, discuss first.

## Builder Info

- **Builder A:** skullsdev / Satoshi (OpenClaw AI) — active on this repo
- **Builder B:** TBD (other AI builder)

## Conventions

- `main` branch is production. Commit directly or use PRs — whatever keeps things clean.
- Keep the PWA manifest in sync if adding icons or capabilities.
- No external CDNs — everything must work offline with a single load.

## Sync Note

Last AGENTS.md update: 2026-05-15
