# AGENTS.md

Current release: v0.6.0 (2026-09-08).

Personal-scale device-cloud backend in Rust + axum: an admin API guarded by the single `ADMIN_TOKEN` **plus** console-account sessions (`POST /api/auth/*`, Argon2id passwords, per-account device ownership), and a device-facing sync endpoint `/api/sync` (per-device tokens, ETag/304 caching). Storage is sqlx's `Any` driver: SQLite by default (zero-config), or PostgreSQL when `DATABASE_URL` is a `postgres://` URL. The Vue 3 console `admin-ui/` is embedded into the binary at compile time via rust-embed. One of four repos: firmware + protocol docs live in `../inkwash-firmware`, the desktop tool in `../inkwash-desktop`, the MCP server in `../inkwash-mcp`.

## Critical gotchas

- `build.rs` runs `npm run build` (in `admin-ui/`) on every `cargo build`/`cargo run` and panics if `admin-ui/node_modules` is missing - run `npm install --prefix admin-ui` once after cloning. UI changes are rebuilt automatically; before touching Rust, make sure node_modules still exists.
- `ADMIN_TOKEN` is required or the server refuses to start; `.env` is loaded automatically by dotenvy from the working directory and is gitignored (never commit keys). A single `DATABASE_URL` selects the backend (default `sqlite://inkwash.sqlite3`; set `postgres://user:pass@host:5432/db` to switch to PostgreSQL - never log it, it may embed credentials). Also `BIND_ADDR` (default `0.0.0.0:8080`).
- CI: `.github/workflows/ci.yml` runs `cargo test --locked` (plus the embedded admin-ui build) on push/PR; it installs `admin-ui` deps first because `build.rs` panics without them. Pre-commit verification: `cargo fmt --check && cargo clippy --all-targets && cargo test` (19 tests: db CRUD/transactions in `db.rs`, auth dispatch in `routes.rs`, plus the sync wire-contract fixtures in `models.rs`). The release workflow is `.github/workflows/release.yml` (below); `scripts/check-logic-pin.sh` reports when the pinned `inkwash-logic` rev (Cargo.toml) falls behind the firmware repo's `logic/` HEAD. Setting `DATABASE_URL` to a `postgres://` URL points the db tests at PostgreSQL instead of in-memory SQLite; tests only assert on rows they created themselves, so a shared database is safe.
  - Server-local DTOs in `models.rs` also carry ts-rs `#[derive(TS)]`: any `cargo test` run regenerates `admin-ui/src/lib/generated/*.ts`, and `admin-ui/src/lib/types.ts` re-exports them - commit refreshed files together with the model change (types mirroring the git-pinned `inkwash-logic` crate stay handwritten there). For breaking DTO edits use `npm run codegen` inside `admin-ui/` - it sets `INKWASH_SKIP_UI_BUILD=1` so build.rs skips the vue-tsc pass that would otherwise fail against the stale committed bindings before the export tests can run.

## Releases
`.github/workflows/release.yml` builds Linux x86_64 + macOS arm64 binaries (GitHub retired the Intel macOS runners, so there is no macOS x86_64 artifact — Intel-Mac users build from source) and **publishes automatically** (`draft: false`) whenever a `v*` tag is pushed to the `github` remote — no manual draft handling.

- **Critical:** GitHub Actions runs the workflow file **at the tagged commit**, not at `main`. If you re-trigger a release by deleting + re-pushing a tag, the tag must point to a commit that already contains the latest workflow changes — otherwise the *old* workflow runs. Also delete the old release + remote tag first, because force-updating an existing tag does not reliably re-trigger the workflow:
  ```bash
  gh release delete v0.1.0 --repo counhopig/inkwash-server --yes
  git push github :refs/tags/v0.1.0
  git tag -f v0.1.0 <commit-with-latest-workflow>
  git push github v0.1.0
  ```
- Release check: `gh release view v0.1.0 --repo counhopig/inkwash-server --json isDraft,assets` (expect `isDraft: false`, one asset per platform).

## Architecture

- Entry chain: `src/main.rs` -> `src/routes.rs` (axum router; handlers return a concrete `Response`, auth is manual via a `HeaderMap` parameter) -> `src/db.rs` -> `src/models.rs` (wire types). `src/auth.rs` has the Argon2id password hashing + username/password validation.
- **Storage (`src/db.rs`)**: a module root that defines `Db` (the sqlx `Any` pool + a `postgres` flag) and re-exports three split modules - `db/schema.rs` (schema + migrations), `db/queries.rs` (CRUD), `db/sync.rs` (`merge_device_state`). Callers keep using `db::` paths via the re-exports. All handlers `await` sqlx calls (the old sync `rusqlite` behind `Arc<Mutex<Connection>>` is gone; sqlx pool `max_connections` is small (2), still far from needing deadpool).
- **Schema/migrations**: the DDL lives in per-dialect sqlx migration files (`migrations/sqlite/0001_init.sql` vs `migrations/postgres/0001_init.sql` - `AUTOINCREMENT` vs `BIGSERIAL` can't share one file), embedded via `sqlx::migrate!` and run at `open()`. `sqlx migrate run --source migrations/sqlite` (or `/postgres`) works against either backend. `db/schema.rs` keeps a `SQLITE_TABLES` copy (cross-referenced) only for the pre-UUID-era `migrate_legacy_integer_ids` rebuild, plus an explicit column-existence-checked backfill for pre-migration SQLite files - no swallowed `let _ =` errors anymore.
- Data SQL for placeholder-bearing statements is explicitly maintained as dual-dialect string pairs (`Db::sql(sqlite_sql, postgres_sql)`, `?` vs `$1, $2, …`), picked once via the backend flag - there is no runtime placeholder rewriting. When adding a query: write both variants, keep tables/columns/bind order identical between them, and verify against Postgres with `DATABASE_URL=postgres://… cargo test`. Statements without placeholders are dialect-neutral and need no pair.
- Three trust domains share one router, resolved by one dispatch: `routes::authenticate(headers, state, channel_id)` returns `enum AuthSubject { Admin, Session{account_id}, Device{device_id, version}, Channel{device_id} }` - admin token (constant-time compare via `subtle`), console session, device sync token, then webhook channel token (Argon2id) against the channel named in the request path (channel tokens can't identify their channel alone - the hash is one-way). Routes match on the variant they accept; don't invent a fourth credential kind outside this enum. Scope rules: a console account can only see/register/manage its own devices (`devices.account_id`); the `ADMIN_TOKEN` can see and manage everything, including unowned devices (the ones the desktop tool registers), so existing desktop workflows keep working unchanged. Device/session tokens are stored plaintext by design (documented in `db/queries.rs::register_device` - 48-char CSPRNG, revocable, hashing would break the `WHERE token = ?` lookup).
- Every alarm/todo mutation bumps `devices.version`; `GET /api/sync` returns ETag `"d{device_id}-v{version}"` and answers 304 on matching `If-None-Match` (device id is embedded so a stale cache from an old/re-registered device can't suppress the first payload).
- `POST /api/sync`: the device may only upload `enabled` flags for alarms and `done` flags for todos; unknown ids are silently ignored (no recreating content deleted server-side).
- Alarm/todo `local_id` is `u8` (0..255); new ids take MAX+1 and error at the limit (`next_local_id`).
- Accounts/sessions live in `accounts` and `sessions` tables; `devices.account_id` is `NULL` for devices registered with the admin token (desktop tool) and set for console-registered devices.

## Wire contract (don't change casually)

- `src/models.rs` re-exports the wire types from the git-pinned `inkwash-logic` crate (`alarm_schedule::{Repeat, StoredAlarm}`, `inbox_item::*`, `todo::*`) - the exact crate the firmware deserializes through, so there is no adapter layer. `Repeat` is serde externally tagged: `"Daily"` or `{"Once":{year,month,day}}` - this is why the UI sends `repeat: "Daily"` (capital D). The wire-contract fixture tests in `models.rs` freeze the `docs/sync-api.md` shape in both directions. Any wire-shape change requires bumping the pinned rev in Cargo.toml (see `scripts/check-logic-pin.sh`) and updating `../inkwash-firmware/docs/sync-api.md` too.
- A device token is returned exactly once, in the `POST /api/devices` registration response; it is never readable again (`list_devices` omits it) - losing it means re-registering.

## admin-ui

- Vue 3, no router/state library - views switch via a `view` ref in `App.vue` (`dashboard` | `device` | `account`). `App.vue` is the coordinator: it owns the session, device list + per-device stats, and global toast/confirm/busy plumbing, and provides them to child views through `lib/ui.ts` (an `InjectionKey`; views `inject(uiKey)` instead of prop-drilling).
- View components: `LoginView.vue` (sign in / create account / admin-token fallback), `DashboardView.vue` (stat strip + device cards + register device), `DeviceView.vue` (alarms/todos editor for one device, loads its own content), `AccountView.vue` (session info, change password, sign out). `src/lib/api.ts` is a thin same-origin fetch wrapper using relative paths - there is no base-URL config. `src/lib/storage.ts` persists the session (`inkwash.admin.session`) and the admin token.
- Every mutation goes through `ui.run(name, fn)` (double-submit guard + shared 401/error handling; a 401 anywhere drops the session back to login); `loadContent`/`loadDevices` use a sequence guard so stale responses can't overwrite newer ones.
- Dev loop: `npm run dev` (:5173, vite proxies `/api` and `/health` to :8080) alongside a separate `cargo run`; `src/lib/clipboard.ts` falls back to `execCommand('copy')` because the console is normally opened over plain LAN http (no secure context).

## Other

- `scripts/start.sh` does the full first-run setup (generates `.env` with a fresh `ADMIN_TOKEN`, runs `npm install`, then `cargo run --release`).
- Commits use Conventional Commits with English subjects (`feat:`/`fix:`/`docs:`/`chore:`/`build:`).
