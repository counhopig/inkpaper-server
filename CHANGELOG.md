# Changelog

All notable changes to **inkwash-server** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),

## [0.6.0] - 2026-09-08

### Changed
- Version aligned with the Inkwash v0.6.0 release across the server,
  desktop, MCP, and firmware repositories.
- The existing pinned `inkwash-logic` revision and sync wire-contract
  fixtures remain in use.
## [0.5.0] - 2026-08-27

### Changed
- **Version aligned to 0.5.0** across the four Inkwash repositories.
- **inkwash-logic bumped to firmware HEAD** (`0ba5958`) - the commits
  since the old pin are pure refactors and additions; the sync wire
  contract is unchanged (locked by the new contract fixture tests).
- **Removed the blanket permissive CORS layer** - every real client is
  same-origin (embedded console / Vite dev proxy) or non-browser
  (firmware, desktop reqwest, webhook POSTs), so CORS only widened
  browser attack surface.

### Added
- **Sync wire-contract tests** (`models::wire_contract_tests`) - freeze
  the `docs/sync-api.md` response shape and round-trip the server's
  serialized output through the firmware's `SyncResponse` types, so
  contract drift fails CI instead of surfacing as a silent device.
- **`scripts/check-logic-pin.sh`** - reports when the pinned
  inkwash-logic rev is behind the firmware repo's `logic/` HEAD.
- **CI workflow** - `cargo test` (plus the embedded admin-ui build) on
  push/PR.

### Fixed
- `build.rs` distinguishes a missing Node.js from missing admin-ui
  dependencies and points at `scripts/start.sh` for the one-time setup.

## [0.4.0] - 2026-08-21

### Changed
- **Rebranded to Inkwash** - package/binary name, urgent-poll header
  (`x-inkpaper-poll` -> `x-inkwash-poll`), admin console title, and the
  default database file (`inkwash.sqlite3`; a fresh database is created
  on next start - recreate channels/webhook tokens).

## [0.3.0] - 2026-08-21

### Added
- **Webhook channels** — per-device channels with one-time delivery
  tokens (`POST /api/devices/:id/channels`, `.../rotate-token`), and
  `POST /api/channels/:channel_id/messages` webhook delivery: size
  limits, optional `Idempotency-Key` dedup, and `priority: "high"`
  flagging that drives the device's urgent reminder.
- **Device inbox** — `inbox` table, `inbox_read_acked` / `inbox_truncated`
  sync fields, admin inbox debug endpoints (`GET`/`DELETE`), and the
  `has_unread_high_inbox` query backing urgent delivery.
- **Lightweight urgent poll** — `X-Inkwash-Poll: 1` on `POST /api/sync`
  answers `{"urgent": bool}` immediately (no merge, no full payload), so
  the firmware can poll for high-priority messages on a short cron
  cadence without pulling everything.
- **Console UI** — channels & inbox management in the Device view:
  create webhook channels, copy/rotate the delivery token, and view /
  delete inbox messages.

## [0.2.0] - 2026-08-20

### Added
- **Console accounts** — register, log in, log out and change password
  (`POST /api/auth/*`), with Argon2id-hashed passwords and per-account
  device ownership. Account sessions are scoped to the account's own
  devices; admin-token-created devices stay owned by the server owner.
- **Admin Users panel** — owner-only management of console accounts
  (`GET/DELETE /api/admin/accounts`, password reset), listing each
  account with its device/session counts.
- **PostgreSQL support** — storage now runs on sqlx `Any`; set
  `DATABASE_URL` to a `postgres://` URL to use PostgreSQL alongside the
  default zero-config SQLite backend. DDL is emitted per dialect.
- **Hierarchical console views** — login/register screen, and a
  dashboard/device/account view split driven by session state.

### Changed
- Admin console is now a layered Vue 3 view-based app (no router): a new
  `DashboardView`/`DeviceView`/`AccountView`/`LoginView` split replaces
  the previous single-view console.
- Every mutation flows through a shared busy/401 handler; stale responses
  are guarded by a sequence guard so they can't overwrite newer data.
- The release workflow now **publishes** Linux/macOS binaries
  automatically on a `v*` tag instead of leaving a draft.

### Fixed
- Frontend `tsconfig` `moduleResolution` corrected from `Node` to
  `Bundler` so the admin-ui builds correctly.

## [0.1.0] - 2026-08-19

### Added
- Initial backend server: Rust + `axum`, SQLite storage.
- Device registration with one-time per-device bearer tokens; `uuid`
  device keys.
- Alarm and todo CRUD with bulk clear, validation hardening, and
  importance / due-date support.
- Recurring (repeat) schedules for alarms and todos.
- Device-facing `GET` (ETag/304) and bidirectional `POST /api/sync`
  endpoints; `POST` merges only known IDs' `enabled`/`done` flags and
  never lets device data create content.
- Embedded admin console (Vue 3 + Vite) and `start.sh` first-run setup.
- Apache-2.0 license and open-source README.
