# Lumen: internal release notes tool

Lumen collects release notes from every service repo, groups them by customer
impact and publishes a weekly digest. It is a small Flask app with a Postgres
store and a nightly sync job.

## Components

- `src/app.py`: HTTP API and the digest renderer
- `config/app.env`: runtime configuration (database, payment provider, API token)
- nightly job: pulls merged pull requests and tags them

## Status

Version 0.9. The digest renderer is stable; the nightly job still misses PRs
merged through the API without a merge commit.
