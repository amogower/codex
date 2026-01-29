# Account pool (multiple ChatGPT accounts)

This fork adds an **account pool** so you can keep multiple authenticated ChatGPT (and/or API key) accounts locally and switch between them.

## Files on disk

All data lives under your Codex home directory (usually `~/.codex`):

- `account-pool/pool.json`: pool metadata (order, active profile, disabled-until timestamps)
- `account-pool/profiles/<name>/auth.json`: stored credentials per profile

No changes are made to the upstream `auth.json` schema.

When a ChatGPT token refresh happens, Codex syncs the refreshed credentials back into the active pool profile so refresh-token rotation doesn’t “strand” the profile.

## Commands

### Add profiles

- Add a ChatGPT profile (browser login):
  - `codex accounts add work`
- Add a ChatGPT profile (device code flow):
  - `codex accounts add work --device-auth`
- Add an API key profile (reads the key from stdin):
  - `printenv OPENAI_API_KEY | codex accounts add api --with-api-key`

By default, `add` also sets the profile active. Use `--no-set-active` to avoid switching.

### Switch / rotate

- List profiles:
  - `codex accounts list`
- Switch active profile:
  - `codex accounts use work`
- Rotate to next enabled profile:
  - `codex accounts rotate`

### Auto-rotation on quota

When Codex encounters a ChatGPT **usage limit reached** (429 with `usage_limit_reached`), it:

1. Marks the current profile as disabled until the server-provided reset time (when available).
2. Switches to the next enabled profile in `pool.json` order.
3. Retries the request automatically.
