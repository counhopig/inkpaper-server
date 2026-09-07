//! HTTP handlers. Three trust domains share this router:
//! - `/api/*` (except `/api/sync`) is the admin/management surface used by
//!   `inkwash-desktop` to register devices and edit their alarms/todos.
//!   Guarded by either the single fixed `ADMIN_TOKEN` (see `main.rs`) - a
//!   personal server for one owner - or a console-account session.
//! - `/api/auth/*` is the console account surface (register/login/logout/
//!   change password). Account sessions are bearer tokens stored in the DB.
//! - `/api/sync` is the device-facing endpoint from
//!   `inkwash/docs/sync-api.md`, guarded per-device by the token
//!   `register_device` issued.
//!
//! Scope rules: a console account can only see/register/manage its own
//! devices (`devices.account_id`); the `ADMIN_TOKEN` can see and manage
//! everything, including unowned devices (the ones the desktop tool
//! registers), so existing desktop workflows keep working unchanged.

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use rust_embed::RustEmbed;
use subtle::ConstantTimeEq;
use inkwash_logic::sync_validate::{validate_date, validate_repeat};

use crate::db::{self, Db};
use crate::models::{
    Account, AdminResetPasswordRequest, AuthRequest, AuthResponse, ChangePasswordRequest,
    ChannelCreated, CreateChannelRequest, DeviceSyncRequest, InboxAccepted, InboxCreateRequest,
    RegisterDeviceRequest, SyncResponse, UpdateChannelRequest, UpsertAlarmRequest,
    UpsertTodoRequest,
};

/// The built admin console (`admin-ui/`, a small Vue 3 + Vite app - see
/// that directory's README) embedded into the binary at compile time, so
/// the server stays a single deployable artifact with no extra static
/// files to ship alongside it. Run `npm run build` in `admin-ui/` before
/// `cargo build`/`cargo run` to regenerate `admin-ui/dist/`.
#[derive(RustEmbed)]
#[folder = "admin-ui/dist/"]
struct AdminAssets;

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub admin_token: String,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(admin_index))
        .route("/assets/*path", get(admin_asset))
        .route("/health", get(health))
        .route("/api/auth/register", post(register_account))
        .route("/api/auth/login", post(login_account))
        .route("/api/auth/logout", post(logout_account))
        .route("/api/auth/me", get(me))
        .route("/api/auth/password", post(change_password))
        .route("/api/admin/accounts", get(admin_list_accounts))
        .route(
            "/api/admin/accounts/:account_id",
            delete(admin_delete_account),
        )
        .route(
            "/api/admin/accounts/:account_id/password",
            post(admin_reset_password),
        )
        .route("/api/sync", get(device_sync).post(device_push_sync))
        .route("/api/devices", post(register_device).get(list_devices))
        .route("/api/devices/:device_id", delete(delete_device))
        .route(
            "/api/devices/:device_id/channels",
            get(list_channels).post(create_channel),
        )
        .route(
            "/api/devices/:device_id/channels/:channel_id",
            get(get_channel).put(update_channel).delete(delete_channel),
        )
        .route(
            "/api/devices/:device_id/channels/:channel_id/rotate-token",
            post(rotate_channel_token),
        )
        .route("/api/channels/:channel_id/messages", post(deliver_inbox))
        .route(
            "/api/devices/:device_id/inbox",
            get(list_inbox).delete(clear_inbox),
        )
        .route(
            "/api/devices/:device_id/inbox/:seq",
            delete(delete_inbox_item),
        )
        .route(
            "/api/devices/:device_id/alarms",
            get(list_alarms).post(create_alarm).delete(clear_alarms),
        )
        .route(
            "/api/devices/:device_id/alarms/:alarm_id",
            put(update_alarm).delete(delete_alarm),
        )
        .route(
            "/api/devices/:device_id/todos",
            get(list_todos).post(create_todo).delete(clear_todos),
        )
        .route(
            "/api/devices/:device_id/todos/:todo_id",
            put(update_todo).delete(delete_todo),
        )
        .with_state(state)
}

async fn admin_index() -> Response {
    serve_admin_asset("index.html")
}

async fn admin_asset(Path(path): Path<String>) -> Response {
    // Embedded keys are relative to admin-ui/dist/ (e.g. "assets/index-*.js"),
    // but the wildcard route only captures what follows "/assets/".
    serve_admin_asset(&format!("assets/{path}"))
}

fn serve_admin_asset(path: &str) -> Response {
    match AdminAssets::get(path) {
        Some(file) => {
            let mime = file.metadata.mimetype();
            ([(header::CONTENT_TYPE, mime)], file.data).into_response()
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

// --- Console accounts ------------------------------------------------------

async fn register_account(State(state): State<AppState>, Json(req): Json<AuthRequest>) -> Response {
    let username = req.username.trim();
    if let Err(msg) = crate::auth::validate_username(username) {
        return bad_request(msg);
    }
    if let Err(msg) = crate::auth::validate_password(&req.password) {
        return bad_request(msg);
    }
    if match db::find_account_by_username(&state.db, username).await {
        Ok(v) => v,
        Err(err) => return internal_error(err),
    }
    .is_some()
    {
        return (StatusCode::CONFLICT, "username already taken").into_response();
    }
    let hash = match crate::auth::hash_password(&req.password) {
        Ok(h) => h,
        Err(err) => return internal_error(err),
    };
    let account = match db::register_account(&state.db, username, &hash).await {
        Ok(a) => a,
        Err(err) if db::is_unique_violation(&err) => {
            return (StatusCode::CONFLICT, "username already taken").into_response()
        }
        Err(err) => return internal_error(err),
    };
    issue_session(&state, account).await
}

async fn login_account(State(state): State<AppState>, Json(req): Json<AuthRequest>) -> Response {
    let username = req.username.trim();
    let stored = match db::find_account_by_username(&state.db, username).await {
        Ok(v) => v,
        Err(err) => return internal_error(err),
    };
    let account_id = match stored {
        Some((id, hash)) => {
            if !crate::auth::verify_password(&req.password, &hash) {
                return (StatusCode::UNAUTHORIZED, "invalid username or password").into_response();
            }
            id
        }
        None => {
            // Verify against a throwaway hash so unknown usernames cost a
            // real Argon2 round too - no easy user enumeration by timing.
            let _ = crate::auth::verify_password(
                &req.password,
                "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            );
            return (StatusCode::UNAUTHORIZED, "invalid username or password").into_response();
        }
    };
    let account = match db::account_by_id(&state.db, account_id).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return (StatusCode::UNAUTHORIZED, "invalid username or password").into_response()
        }
        Err(err) => return internal_error(err),
    };
    issue_session(&state, account).await
}

async fn issue_session(state: &AppState, account: Account) -> Response {
    let token = match db::create_session(&state.db, account.id).await {
        Ok(t) => t,
        Err(err) => return internal_error(err),
    };
    tracing::info!(account_id = account.id, username = %account.username, "console session issued");
    (
        StatusCode::OK,
        Json(AuthResponse {
            token,
            username: account.username,
        }),
    )
        .into_response()
}

async fn logout_account(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(token) = bearer_token(&headers) else {
        return (StatusCode::NO_CONTENT).into_response();
    };
    match db::delete_session(&state.db, token).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => internal_error(err),
    }
}

/// Validates a stored session token so the console can confirm it's still
/// logged in on load. Also answers for the admin token.
async fn me(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match authenticate(&headers, &state, None).await {
        Ok(AuthSubject::Admin) => Json(serde_json::json!({ "kind": "admin" })).into_response(),
        Ok(AuthSubject::Session { account_id }) => {
            match db::account_by_id(&state.db, account_id).await {
                Ok(Some(account)) => Json(serde_json::json!({
                    "kind": "account",
                    "account_id": account.id,
                    "username": account.username
                }))
                .into_response(),
                Ok(None) => (StatusCode::UNAUTHORIZED, "invalid session").into_response(),
                Err(err) => internal_error(err),
            }
        }
        Ok(AuthSubject::Device { .. } | AuthSubject::Channel { .. }) => {
            (StatusCode::UNAUTHORIZED, "invalid session").into_response()
        }
        Err(resp) => resp.into_response(),
    }
}

async fn change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Response {
    let subject = match authenticate(&headers, &state, None).await {
        Ok(subject) => subject,
        Err(resp) => return resp.into_response(),
    };
    let AuthSubject::Session { account_id } = subject else {
        match subject {
            // The admin token is configured via env, not a password we can
            // change - reject instead of pretending to succeed.
            AuthSubject::Admin => {
                return (
                    StatusCode::BAD_REQUEST,
                    "admin token is set in server config",
                )
                    .into_response();
            }
            _ => return (StatusCode::UNAUTHORIZED, "invalid session").into_response(),
        }
    };
    let stored = match db::account_by_id(&state.db, account_id).await {
        Ok(Some(a)) => a,
        Ok(None) => return (StatusCode::UNAUTHORIZED, "invalid session").into_response(),
        Err(err) => return internal_error(err),
    };
    let (_, hash) = match db::find_account_by_username(&state.db, &stored.username).await {
        Ok(Some(v)) => v,
        Ok(None) => return (StatusCode::UNAUTHORIZED, "invalid session").into_response(),
        Err(err) => return internal_error(err),
    };
    if !crate::auth::verify_password(&req.old_password, &hash) {
        return (StatusCode::UNAUTHORIZED, "current password is incorrect").into_response();
    }
    if let Err(msg) = crate::auth::validate_password(&req.new_password) {
        return bad_request(msg);
    }
    let new_hash = match crate::auth::hash_password(&req.new_password) {
        Ok(h) => h,
        Err(err) => return internal_error(err),
    };
    match db::update_account_password(&state.db, account_id, &new_hash).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => internal_error(err),
    }
}

fn bad_request(message: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, message.into()).into_response()
}
/// Validates an alarm against the same rules the firmware enforces in
/// `sync_validate.rs` — hour/minute range, Repeat validity, and for
/// `Once` alarms the exact date range the PCF8563 + firmware recurrence
/// math supports (2000–2099, with a real calendar day for that month/year).
/// Mirrors `inkwash-firmware/logic/src/sync_validate.rs:validate_repeat` +
/// `validate_date` so server-authored alarms can never produce a sync
/// response the device will reject wholesale.
fn validate_alarm(req: &UpsertAlarmRequest) -> Result<(), String> {
    if req.hour > 23 || req.minute > 59 {
        return Err(format!(
            "alarm time {:02}:{:02} is out of range (hour 0..23, minute 0..59)",
            req.hour, req.minute
        ));
    }
    if req.label.chars().count() > 40 {
        return Err("alarm label must be at most 40 characters".to_string());
    }
    validate_repeat(&req.repeat)
        .map_err(|err| format!("invalid repeat rule: {err}"))
}

/// Validates a todo against the firmware's date/repeat rules
/// (same crate as [`validate_alarm`]). `Once` is rejected because the
/// device calendar/reminder logic only supports Daily/Weekly/Monthly for
/// recurring todos — one-off due dates belong in `due_date`, not `repeat`.
fn validate_todo(req: &UpsertTodoRequest) -> Result<(), String> {
    let text_len = req.text.chars().count();
    if req.text.trim().is_empty() {
        return Err("todo text must not be empty".to_string());
    }
    if text_len > 120 {
        return Err(format!(
            "todo text must be at most 120 characters (got {text_len})"
        ));
    }
    if let Some(due) = req.due_date {
        validate_date(due.year, due.month, due.day)
            .map_err(|err| format!("invalid due date: {err}"))?;
    }
    if let Some(repeat) = &req.repeat {
        if matches!(repeat, crate::models::Repeat::Once { .. }) {
            return Err("todo repeat Once is not supported; use due_date for a single due date".to_string());
        }
        validate_repeat(repeat)
            .map_err(|err| format!("invalid repeat rule: {err}"))?;
    }
    Ok(())
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

/// Who is calling, resolved by the single `authenticate()` dispatch below.
/// This is the one place all four credential kinds are recognized - before
/// this existed, admin/session (`auth_context`), device (`/api/sync`'s bare
/// token lookup) and channel webhook (inline `verify_password`) each had
/// their own independent authorization path, so a new route category could
/// easily have invented a fifth. Routes match on the variant they accept
/// and reject everything else with 401/403 exactly as the old paths did.
#[derive(Clone, Debug)]
pub enum AuthSubject {
    /// The owner's `ADMIN_TOKEN` (full access to every device).
    Admin,
    /// A console-account session token; scoped to the account's own devices.
    Session { account_id: i64 },
    /// A device sync token issued by `register_device`.
    Device { device_id: String, version: i64 },
    /// A webhook channel token, already verified against the channel named
    /// in the request path (`authenticate` is given `Some(channel_id)`).
    Channel { device_id: String },
}

/// Resolves the bearer credential in `headers` to an `AuthSubject`, trying
/// the four credential kinds in order. `channel_id` is `Some` only on the
/// webhook delivery route: a `ipwh_`-prefixed token can't be matched to a
/// channel from the token alone (the hash is one-way), so the channel named
/// in the request path carries the hash to verify against.
///
/// Error semantics match the old separate paths: anything unrecognized is a
/// 401; callers that require a specific subject turn other subjects into
/// the same 401/403 they produced before the unification.
pub async fn authenticate(
    headers: &HeaderMap,
    state: &AppState,
    channel_id: Option<&str>,
) -> Result<AuthSubject, (StatusCode, &'static str)> {
    let Some(token) = bearer_token(headers) else {
        return Err((StatusCode::UNAUTHORIZED, "missing or invalid credentials"));
    };
    // Admin token: constant-time comparison so a wrong token's reject path
    // doesn't finish measurably earlier than a right one's.
    if bool::from(state.admin_token.as_bytes().ct_eq(token.as_bytes())) {
        return Ok(AuthSubject::Admin);
    }
    match db::find_session(&state.db, token).await {
        Ok(Some(account_id)) => return Ok(AuthSubject::Session { account_id }),
        Ok(None) => {}
        Err(err) => {
            tracing::error!("{err:#}");
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "storage error"));
        }
    }
    if let Some((device_id, version)) =
        db::find_device_by_token(&state.db, token)
            .await
            .map_err(|err| {
                tracing::error!("{err:#}");
                (StatusCode::INTERNAL_SERVER_ERROR, "storage error")
            })?
    {
        return Ok(AuthSubject::Device { device_id, version });
    }
    if let Some(channel_id) = channel_id {
        if let Some((device_id, token_hash)) = db::get_channel_for_delivery(&state.db, channel_id)
            .await
            .map_err(|err| {
                tracing::error!("{err:#}");
                (StatusCode::INTERNAL_SERVER_ERROR, "storage error")
            })?
        {
            if crate::auth::verify_password(token, &token_hash) {
                return Ok(AuthSubject::Channel { device_id });
            }
        }
    }
    Err((StatusCode::UNAUTHORIZED, "missing or invalid credentials"))
}

/// Authenticates and, for account sessions, verifies the account owns
/// `device_id`. The admin token may access any device. Returns the resolved
/// subject so the caller knows whether it is managing another account's
/// device (relevant for `register_device`, which must attach ownership).
async fn require_device_access(
    headers: &HeaderMap,
    state: &AppState,
    device_id: &str,
) -> Result<AuthSubject, Box<Response>> {
    let subject = authenticate(headers, state, None)
        .await
        .map_err(|e| Box::new(e.into_response()))?;
    match subject {
        AuthSubject::Admin => Ok(subject),
        AuthSubject::Session { account_id } => {
            match db::device_owned_by(&state.db, device_id, account_id).await {
                Ok(true) => Ok(subject),
                Ok(false) => Err(Box::new(
                    (StatusCode::NOT_FOUND, "device not found").into_response(),
                )),
                Err(err) => Err(Box::new(internal_error(err))),
            }
        }
        // A device or channel token is not a management credential - same
        // 401 the old `auth_context` produced for them.
        AuthSubject::Device { .. } | AuthSubject::Channel { .. } => Err(Box::new(
            (StatusCode::UNAUTHORIZED, "missing or invalid credentials").into_response(),
        )),
    }
}

fn internal_error(err: anyhow::Error) -> Response {
    // Log the full error internally but return only a generic message to the
    // client to avoid leaking database details (table/column names, constraint
    // values, foreign-key references) over the wire.
    tracing::error!("{err:#}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Internal server error",
    )
        .into_response()
}

// --- Admin: account management ---------------------------------------------

/// The `ADMIN_TOKEN` is the owner credential; account sessions are not
/// allowed past this gate.
async fn require_admin_only(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<(), (StatusCode, &'static str)> {
    match authenticate(headers, state, None).await {
        Ok(AuthSubject::Admin) => Ok(()),
        Ok(AuthSubject::Session { .. }) => Err((StatusCode::FORBIDDEN, "admin token required")),
        Ok(AuthSubject::Device { .. } | AuthSubject::Channel { .. }) => {
            Err((StatusCode::UNAUTHORIZED, "missing or invalid credentials"))
        }
        Err(resp) => Err(resp),
    }
}

async fn admin_list_accounts(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_admin_only(&headers, &state).await {
        return resp.into_response();
    }
    match db::list_accounts(&state.db).await {
        Ok(accounts) => Json(accounts).into_response(),
        Err(err) => internal_error(err),
    }
}

async fn admin_delete_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(account_id): Path<i64>,
) -> Response {
    if let Err(resp) = require_admin_only(&headers, &state).await {
        return resp.into_response();
    }
    match db::delete_account(&state.db, account_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "account not found").into_response(),
        Err(err) => internal_error(err),
    }
}

async fn admin_reset_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(account_id): Path<i64>,
    Json(req): Json<AdminResetPasswordRequest>,
) -> Response {
    if let Err(resp) = require_admin_only(&headers, &state).await {
        return resp.into_response();
    }
    if let Err(msg) = crate::auth::validate_password(&req.new_password) {
        return bad_request(msg);
    }
    let hash = match crate::auth::hash_password(&req.new_password) {
        Ok(h) => h,
        Err(err) => return internal_error(err),
    };
    match db::update_account_password(&state.db, account_id, &hash).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => internal_error(err),
    }
}

// --- Device-facing sync endpoint (docs/sync-api.md) -------------------

/// Builds the sync payload (alarms/todos + capped inbox). Reuses the inbox
/// read-merge so the `inbox_read` upload is folded into the response.
///
/// Preflight-checks the serialized alarm and todo lists against the
/// firmware's fixed NVS capacities (alarms 1024 bytes, todos 2048 bytes)
/// — the same limits enforced by `inkwash-firmware/logic/src/sync_validate.rs`
/// `validate_sync_response`. Without this, a device that can never fit the
/// response will silently reject every sync, losing all new data.
async fn build_sync_response(
    state: &AppState,
    device_id: &str,
    inbox_read: &[u64],
) -> Result<SyncResponse, Response> {
    let alarms = db::list_alarms(&state.db, device_id)
        .await
        .map_err(internal_error)?;
    let todos = db::list_todos(&state.db, device_id)
        .await
        .map_err(internal_error)?;
    let acked = db::mark_inbox_read(&state.db, device_id, inbox_read)
        .await
        .map_err(internal_error)?;
    let (inbox, truncated) = db::list_inbox(&state.db, device_id, INBOX_LIMIT)
        .await
        .map_err(internal_error)?;
    // Preflight firmware NVS capacity — if the serialized list won't fit,
    // reject now with a 409 Conflict instead of sending a response the
    // device will reject and stall on.
    if serde_json::to_vec(&alarms)
        .map_err(|e| internal_error(anyhow::anyhow!("{e}")))?
        .len()
        > ALARM_NVS_CAPACITY
    {
        tracing::warn!(device_id, alarm_count = alarms.len(), "alarm list exceeds device NVS capacity");
        return Err((
            StatusCode::CONFLICT,
            "alarm list exceeds device storage capacity",
        )
            .into_response());
    }
    if serde_json::to_vec(&todos)
        .map_err(|e| internal_error(anyhow::anyhow!("{e}")))?
        .len()
        > TODO_NVS_CAPACITY
    {
        tracing::warn!(device_id, todo_count = todos.len(), "todo list exceeds device NVS capacity");
        return Err((
            StatusCode::CONFLICT,
            "todo list exceeds device storage capacity",
        )
            .into_response());
    }
    let response = SyncResponse {
        alarms,
        todos,
        inbox,
        inbox_read_acked: acked,
        inbox_truncated: truncated,
    };
    // Preflight the firmware's total response buffer (16 KiB PSRAM) — the
    // sum of all serialized fields must fit or the device truncates the JSON
    // and reports a misleading parse error. See
    // `inkwash-firmware/rust-firmware/src/sync.rs:35` (RESPONSE_BUF_LEN).
    let total_len = serde_json::to_vec(&response)
        .map_err(|e| internal_error(anyhow::anyhow!("{e}")))?
        .len();
    if total_len > SYNC_RESPONSE_BUDGET {
        tracing::warn!(
            device_id,
            total_len,
            alarm_count = response.alarms.len(),
            todo_count = response.todos.len(),
            inbox_count = response.inbox.len(),
            "sync response exceeds firmware 16KiB buffer"
        );
        return Err((
            StatusCode::CONFLICT,
            "sync response payload too large for device buffer",
        )
            .into_response());
    }
    Ok(response)
}

/// Firmware's total sync response buffer size (16 KiB PSRAM). See
/// `inkwash-firmware/rust-firmware/src/sync.rs:35` (RESPONSE_BUF_LEN).
/// The server preflight-checks the full serialized response against this
/// so the device never receives a truncated body.
const SYNC_RESPONSE_BUDGET: usize = 16384;
/// Firmware NVS storage budget for the alarm list (bytes of serialized JSON).
/// See `inkwash-firmware/rust-firmware/src/alarms.rs:18` and
/// `inkwash-firmware/logic/src/sync_validate.rs:100`.
const ALARM_NVS_CAPACITY: usize = 1024;
/// Firmware NVS storage budget for the todo list (bytes of serialized JSON).
/// See `inkwash-firmware/rust-firmware/src/todos.rs:20` and
/// `inkwash-firmware/logic/src/sync_validate.rs:110`.
const TODO_NVS_CAPACITY: usize = 2048;

/// Max inbox items sent to the device in one sync response (hard capacity).
const INBOX_LIMIT: usize = 20;

/// Includes device identity so a cached ETag from an old/re-registered
/// device can never suppress the first payload for a different device.
fn sync_etag(device_id: &str, version: i64) -> String {
    format!("\"d{device_id}-v{version}\"")
}

async fn device_sync(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let subject = match authenticate(&headers, &state, None).await {
        Ok(subject) => subject,
        Err(resp) => return resp.into_response(),
    };
    // Only a device sync token is accepted on this endpoint - admin, session
    // and channel credentials get the same 401 they did from the old bare
    // `find_device_by_token` lookup.
    let AuthSubject::Device { device_id, version } = subject else {
        tracing::warn!("sync rejected: non-device credentials");
        return (StatusCode::UNAUTHORIZED, "unknown device token").into_response();
    };

    let etag = sync_etag(&device_id, version);
    let if_none_match = headers
        .get(axum::http::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok());
    if if_none_match == Some(etag.as_str()) {
        tracing::info!(device_id, version, "sync not modified");
        return StatusCode::NOT_MODIFIED.into_response();
    }

    let body = match build_sync_response(&state, &device_id, &[]).await {
        Ok(body) => Json(body),
        Err(resp) => return resp.into_response(),
    };
    tracing::info!(
        device_id,
        version,
        alarm_count = body.0.alarms.len(),
        todo_count = body.0.todos.len(),
        inbox_count = body.0.inbox.len(),
        "sync payload served"
    );
    (StatusCode::OK, [(axum::http::header::ETAG, etag)], body).into_response()
}

async fn device_push_sync(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DeviceSyncRequest>,
) -> Response {
    let subject = match authenticate(&headers, &state, None).await {
        Ok(subject) => subject,
        Err(resp) => return resp.into_response(),
    };
    let AuthSubject::Device { device_id, .. } = subject else {
        tracing::warn!("sync rejected: non-device credentials");
        return (StatusCode::UNAUTHORIZED, "unknown device token").into_response();
    };

    // Lightweight poll: the device asks with `X-Inkwash-Poll: 1` to check
    // for unread urgent (high-priority) messages without pulling the whole
    // sync payload. Returns immediately (no hold, no merge, no full body) so
    // the firmware can poll frequently for urgent messages on a short timer
    // without keeping a long connection open or blocking its main loop.
    let wants_poll = headers
        .get("x-inkwash-poll")
        .and_then(|v| v.to_str().ok())
        .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if wants_poll {
        let urgent = match db::has_unread_high_inbox(&state.db, &device_id).await {
            Ok(v) => v,
            Err(err) => return internal_error(err),
        };
        return Json(serde_json::json!({ "urgent": urgent })).into_response();
    }

    let version = match db::merge_device_state(&state.db, &device_id, &req).await {
        Ok(version) => version,
        Err(err) => return internal_error(err),
    };
    let body = match build_sync_response(&state, &device_id, &req.inbox_read).await {
        Ok(body) => Json(body),
        Err(resp) => return resp.into_response(),
    };
    let etag = sync_etag(&device_id, version);
    tracing::info!(
        device_id,
        version,
        alarm_count = body.0.alarms.len(),
        todo_count = body.0.todos.len(),
        inbox_count = body.0.inbox.len(),
        "device state merged and sync payload served"
    );
    (StatusCode::OK, [(axum::http::header::ETAG, etag)], body).into_response()
}

// --- Admin: devices -----------------------------------------------------

async fn register_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterDeviceRequest>,
) -> Response {
    let subject = match authenticate(&headers, &state, None).await {
        Ok(subject) => subject,
        Err(resp) => return resp.into_response(),
    };
    if req.name.trim().is_empty() || req.name.chars().count() > 80 {
        return bad_request("device name must be 1..80 characters");
    }
    let account_id = match subject {
        AuthSubject::Admin => None,
        AuthSubject::Session { account_id } => Some(account_id),
        AuthSubject::Device { .. } | AuthSubject::Channel { .. } => {
            return (StatusCode::UNAUTHORIZED, "missing or invalid credentials").into_response()
        }
    };
    match db::register_device(&state.db, &req.name, account_id).await {
        Ok(device) => (StatusCode::CREATED, Json(device)).into_response(),
        Err(err) => internal_error(err),
    }
}

async fn list_devices(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let subject = match authenticate(&headers, &state, None).await {
        Ok(subject) => subject,
        Err(resp) => return resp.into_response(),
    };
    let devices = match subject {
        AuthSubject::Admin => db::list_devices(&state.db).await,
        AuthSubject::Session { account_id } => {
            db::list_account_devices(&state.db, account_id).await
        }
        AuthSubject::Device { .. } | AuthSubject::Channel { .. } => {
            return (StatusCode::UNAUTHORIZED, "missing or invalid credentials").into_response()
        }
    };
    match devices {
        Ok(devices) => Json(devices).into_response(),
        Err(err) => internal_error(err),
    }
}

async fn delete_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
) -> Response {
    match require_device_access(&headers, &state, &device_id).await {
        Ok(_) => {}
        Err(resp) => return *resp,
    }
    match db::delete_device(&state.db, &device_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => internal_error(err),
    }
}

// --- Admin: alarms --------------------------------------------------------

async fn list_alarms(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
) -> Response {
    if let Err(resp) = require_device_access(&headers, &state, &device_id).await {
        return *resp;
    }
    match db::list_alarms(&state.db, &device_id).await {
        Ok(alarms) => Json(alarms).into_response(),
        Err(err) => internal_error(err),
    }
}

async fn create_alarm(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
    Json(req): Json<UpsertAlarmRequest>,
) -> Response {
    if let Err(resp) = require_device_access(&headers, &state, &device_id).await {
        return *resp;
    }
    if let Err(msg) = validate_alarm(&req) {
        return bad_request(msg);
    }
    match db::upsert_alarm(&state.db, &device_id, None, &req).await {
        Ok(id) => (StatusCode::CREATED, Json(serde_json::json!({ "id": id }))).into_response(),
        Err(err) => internal_error(err),
    }
}

async fn update_alarm(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((device_id, alarm_id)): Path<(String, u8)>,
    Json(req): Json<UpsertAlarmRequest>,
) -> Response {
    if let Err(resp) = require_device_access(&headers, &state, &device_id).await {
        return *resp;
    }
    if let Err(msg) = validate_alarm(&req) {
        return bad_request(msg);
    }
    match db::upsert_alarm(&state.db, &device_id, Some(alarm_id), &req).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => internal_error(err),
    }
}

async fn clear_alarms(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
) -> Response {
    if let Err(resp) = require_device_access(&headers, &state, &device_id).await {
        return *resp;
    }
    match db::clear_alarms(&state.db, &device_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => internal_error(err),
    }
}

async fn delete_alarm(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((device_id, alarm_id)): Path<(String, u8)>,
) -> Response {
    if let Err(resp) = require_device_access(&headers, &state, &device_id).await {
        return *resp;
    }
    match db::delete_alarm(&state.db, &device_id, alarm_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => internal_error(err),
    }
}

// --- Admin: todos ---------------------------------------------------------

async fn list_todos(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
) -> Response {
    if let Err(resp) = require_device_access(&headers, &state, &device_id).await {
        return *resp;
    }
    match db::list_todos(&state.db, &device_id).await {
        Ok(todos) => Json(todos).into_response(),
        Err(err) => internal_error(err),
    }
}

async fn create_todo(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
    Json(req): Json<UpsertTodoRequest>,
) -> Response {
    if let Err(resp) = require_device_access(&headers, &state, &device_id).await {
        return *resp;
    }
    if let Err(msg) = validate_todo(&req) {
        return bad_request(msg);
    }
    match db::upsert_todo(&state.db, &device_id, None, &req).await {
        Ok(id) => (StatusCode::CREATED, Json(serde_json::json!({ "id": id }))).into_response(),
        Err(err) => internal_error(err),
    }
}

async fn update_todo(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((device_id, todo_id)): Path<(String, u8)>,
    Json(req): Json<UpsertTodoRequest>,
) -> Response {
    if let Err(resp) = require_device_access(&headers, &state, &device_id).await {
        return *resp;
    }
    if let Err(msg) = validate_todo(&req) {
        return bad_request(msg);
    }
    match db::upsert_todo(&state.db, &device_id, Some(todo_id), &req).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => internal_error(err),
    }
}

async fn clear_todos(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
) -> Response {
    if let Err(resp) = require_device_access(&headers, &state, &device_id).await {
        return *resp;
    }
    match db::clear_todos(&state.db, &device_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => internal_error(err),
    }
}

async fn delete_todo(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((device_id, todo_id)): Path<(String, u8)>,
) -> Response {
    if let Err(resp) = require_device_access(&headers, &state, &device_id).await {
        return *resp;
    }
    match db::delete_todo(&state.db, &device_id, todo_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => internal_error(err),
    }
}

// --- External channels & inbox --------------------------------------------

fn validate_channel_request(req: &CreateChannelRequest) -> Result<(), &'static str> {
    if req.name.trim().is_empty() || req.name.chars().count() > 80 {
        return Err("channel name must be 1..80 characters");
    }
    match req.kind.as_str() {
        "webhook" => Ok(()),
        other => Err(match other {
            "caldav_basic" => "caldav_basic is not yet implemented",
            _ => "channel kind must be 'webhook'",
        }),
    }
}

/// Validates a webhook payload; rejects (rather than silently truncates)
/// anything that violates the size limits.
fn validate_inbox_payload(req: &InboxCreateRequest) -> Result<(), &'static str> {
    if !matches!(req.kind.as_str(), "alert" | "event" | "info") {
        return Err("kind must be one of 'alert' | 'event' | 'info'");
    }
    let title = req.title.trim();
    if title.is_empty() {
        return Err("title must not be empty");
    }
    if req.title.chars().count() > 120 || req.title.len() > 512 {
        return Err("title too long (max 120 chars / 512 bytes)");
    }
    if req.body.chars().count() > 1000 || req.body.len() > 4096 {
        return Err("body too long (max 1000 chars / 4 KiB)");
    }
    if let Some(when) = req.when {
        if !(0..=4_102_444_800).contains(&when) {
            return Err("when is outside a valid Unix epoch range");
        }
    }
    if let Some(priority) = req.priority {
        if !matches!(
            priority,
            crate::models::Priority::Normal | crate::models::Priority::High
        ) {
            return Err("priority must be one of 'normal' | 'high'");
        }
    }
    Ok(())
}

async fn list_channels(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
) -> Response {
    if let Err(resp) = require_device_access(&headers, &state, &device_id).await {
        return *resp;
    }
    match db::list_channels(&state.db, &device_id).await {
        Ok(channels) => Json(channels).into_response(),
        Err(err) => internal_error(err),
    }
}

async fn create_channel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
    Json(req): Json<CreateChannelRequest>,
) -> Response {
    if let Err(resp) = require_device_access(&headers, &state, &device_id).await {
        return *resp;
    }
    if let Err(msg) = validate_channel_request(&req) {
        return bad_request(msg);
    }
    // Phase 1 is webhook-only; no CalDAV config is accepted yet.
    let config_encrypted = None;
    match db::create_channel(
        &state.db,
        &device_id,
        &req.kind,
        &req.name,
        config_encrypted,
    )
    .await
    {
        Ok((channel, token)) => {
            let delivery_url = token
                .as_ref()
                .map(|_| format!("/api/channels/{}/messages", channel.id));
            (
                StatusCode::CREATED,
                Json(ChannelCreated {
                    channel,
                    token,
                    delivery_url,
                }),
            )
                .into_response()
        }
        Err(err) => internal_error(err),
    }
}

async fn get_channel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((device_id, channel_id)): Path<(String, String)>,
) -> Response {
    if let Err(resp) = require_device_access(&headers, &state, &device_id).await {
        return *resp;
    }
    match db::get_channel(&state.db, &device_id, &channel_id).await {
        Ok(Some(channel)) => Json(channel).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "channel not found").into_response(),
        Err(err) => internal_error(err),
    }
}

async fn update_channel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((device_id, channel_id)): Path<(String, String)>,
    Json(req): Json<UpdateChannelRequest>,
) -> Response {
    if let Err(resp) = require_device_access(&headers, &state, &device_id).await {
        return *resp;
    }
    let name = req.name.as_deref();
    if let Some(name) = name {
        if name.trim().is_empty() || name.chars().count() > 80 {
            return bad_request("channel name must be 1..80 characters");
        }
    }
    match db::update_channel(&state.db, &device_id, &channel_id, name, req.enabled).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "channel not found").into_response(),
        Err(err) => internal_error(err),
    }
}

async fn delete_channel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((device_id, channel_id)): Path<(String, String)>,
) -> Response {
    if let Err(resp) = require_device_access(&headers, &state, &device_id).await {
        return *resp;
    }
    match db::delete_channel(&state.db, &device_id, &channel_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "channel not found").into_response(),
        Err(err) => internal_error(err),
    }
}

async fn rotate_channel_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((device_id, channel_id)): Path<(String, String)>,
) -> Response {
    if let Err(resp) = require_device_access(&headers, &state, &device_id).await {
        return *resp;
    }
    match db::rotate_channel_token(&state.db, &device_id, &channel_id).await {
        Ok(Some((token, prefix))) => {
            Json(serde_json::json!({ "token": token, "token_prefix": prefix })).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "channel not found or not a webhook").into_response(),
        Err(err) => internal_error(err),
    }
}

/// Webhook delivery endpoint: authenticates via the channel's own bearer
/// token (distinct from admin/device tokens), validates the payload, and
/// inserts an inbox item. `Idempotency-Key` maps to `source_ref`.
async fn deliver_inbox(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(channel_id): Path<String>,
    Json(req): Json<InboxCreateRequest>,
) -> Response {
    // Existence check first, then token verification, so wrong-token and
    // unknown-channel end as 401/404 respectively and channel existence
    // isn't leaked. The token is verified by `authenticate` against the
    // hash of this path's channel (a channel token can't identify its own
    // channel - the hash is one-way).
    let Some((device_id, _)) = (match db::get_channel_for_delivery(&state.db, &channel_id).await {
        Ok(v) => v,
        Err(err) => return internal_error(err),
    }) else {
        return (StatusCode::NOT_FOUND, "unknown channel").into_response();
    };
    match authenticate(&headers, &state, Some(&channel_id)).await {
        Ok(AuthSubject::Channel {
            device_id: verified,
        }) if verified == device_id => {}
        _ => return (StatusCode::UNAUTHORIZED, "invalid channel token").into_response(),
    }
    // Only enabled channels accept deliveries.
    let enabled = match db::get_channel(&state.db, &device_id, &channel_id).await {
        Ok(Some(c)) => c.enabled,
        _ => return (StatusCode::NOT_FOUND, "unknown channel").into_response(),
    };
    if !enabled {
        return (StatusCode::FORBIDDEN, "channel disabled").into_response();
    }
    if let Err(msg) = validate_inbox_payload(&req) {
        return bad_request(msg);
    }
    let source_ref = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let priority = req.priority.unwrap_or(crate::models::Priority::Normal);
    match db::deliver_inbox(
        &state.db,
        &device_id,
        &channel_id,
        req.kind.as_str(),
        match priority {
            crate::models::Priority::High => "high",
            crate::models::Priority::Normal => "normal",
        },
        req.title.trim(),
        req.body.trim(),
        req.when,
        source_ref.as_deref(),
    )
    .await
    {
        Ok((seq, created)) => {
            let status = if created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            };
            (
                status,
                Json(InboxAccepted {
                    accepted: true,
                    id: seq,
                }),
            )
                .into_response()
        }
        Err(err) => internal_error(err),
    }
}

async fn list_inbox(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
) -> Response {
    if let Err(resp) = require_device_access(&headers, &state, &device_id).await {
        return *resp;
    }
    match db::list_inbox(&state.db, &device_id, 200).await {
        Ok((items, _truncated)) => Json(items).into_response(),
        Err(err) => internal_error(err),
    }
}

async fn delete_inbox_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((device_id, seq)): Path<(String, u64)>,
) -> Response {
    if let Err(resp) = require_device_access(&headers, &state, &device_id).await {
        return *resp;
    }
    match db::delete_inbox_item(&state.db, &device_id, seq).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "inbox item not found").into_response(),
        Err(err) => internal_error(err),
    }
}

async fn clear_inbox(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
) -> Response {
    if let Err(resp) = require_device_access(&headers, &state, &device_id).await {
        return *resp;
    }
    match db::clear_read_inbox(&state.db, &device_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => internal_error(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    async fn test_state() -> AppState {
        let db = db::open("sqlite::memory:", 1)
            .await
            .expect("open in-memory db");
        AppState {
            db,
            admin_token: "admin-token-123".to_string(),
        }
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        headers
    }

    #[tokio::test]
    async fn authenticate_rejects_missing_and_wrong_tokens() {
        let state = test_state().await;
        // No Authorization header at all.
        assert!(authenticate(&HeaderMap::new(), &state, None).await.is_err());
        // A wrong admin token must still be rejected (constant-time compare).
        let err = authenticate(&bearer("wrong-token"), &state, None)
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn authenticate_resolves_all_four_subjects() {
        let state = test_state().await;
        // Admin token.
        match authenticate(&bearer("admin-token-123"), &state, None)
            .await
            .unwrap()
        {
            AuthSubject::Admin => {}
            other => panic!("expected Admin, got {other:?}"),
        }
        // Console session token.
        let account = db::register_account(&state.db, "alice", "hash")
            .await
            .unwrap();
        let session = db::create_session(&state.db, account.id).await.unwrap();
        match authenticate(&bearer(&session), &state, None).await.unwrap() {
            AuthSubject::Session { account_id } => assert_eq!(account_id, account.id),
            other => panic!("expected Session, got {other:?}"),
        }
        // Device sync token.
        let device = db::register_device(&state.db, "clock", None).await.unwrap();
        match authenticate(&bearer(device.token.as_deref().unwrap()), &state, None)
            .await
            .unwrap()
        {
            AuthSubject::Device { device_id, .. } => assert_eq!(device_id, device.id),
            other => panic!("expected Device, got {other:?}"),
        }
        // Channel webhook token, verified against the channel in the path.
        let (channel, token) = db::create_channel(&state.db, &device.id, "webhook", "CI", None)
            .await
            .unwrap();
        match authenticate(
            &bearer(token.as_deref().unwrap()),
            &state,
            Some(&channel.id),
        )
        .await
        .unwrap()
        {
            AuthSubject::Channel { device_id } => assert_eq!(device_id, device.id),
            other => panic!("expected Channel, got {other:?}"),
        }
        // A session token resolves as a session even on the channel route;
        // the webhook handler then rejects any non-Channel subject.
        match authenticate(&bearer(&session), &state, Some(&channel.id))
            .await
            .unwrap()
        {
            AuthSubject::Session { .. } => {}
            other => panic!("expected Session, got {other:?}"),
        }
        // A device token is not a management credential on device-scoped routes.
        let headers = bearer(device.token.as_deref().unwrap());
        assert!(require_device_access(&headers, &state, &device.id)
            .await
            .is_err());
        // require_admin_only rejects sessions with 403 and devices with 401.
        assert_eq!(
            require_admin_only(&bearer(&session), &state)
                .await
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            require_admin_only(&bearer(device.token.as_deref().unwrap()), &state)
                .await
                .unwrap_err()
                .0,
            StatusCode::UNAUTHORIZED
        );
    }

    /// Server-side validation must reject the same malformed dates and repeat
    /// rules the firmware rejects in `sync_validate.rs`, so alarms/todos that
    /// pass the server can never cause a device sync failure.
    #[test]
    fn validate_alarm_rejects_firmware_invalid_inputs() {
        // Weekly days must be in 0..=6 — day 7 is the firmware's boundary test.
        let bad_weekly = UpsertAlarmRequest {
            hour: 10,
            minute: 0,
            repeat: crate::models::Repeat::Weekly { days: vec![0, 7] },
            enabled: true,
            label: "Bad weekly".into(),
        };
        assert!(validate_alarm(&bad_weekly).is_err());

        // Empty Weekly days list.
        let empty_weekly = UpsertAlarmRequest {
            hour: 10,
            minute: 0,
            repeat: crate::models::Repeat::Weekly { days: vec![] },
            enabled: true,
            label: "Empty weekly".into(),
        };
        assert!(validate_alarm(&empty_weekly).is_err());

        // Monthly days must be 1..=31 — day 0 and 32 are out of range.
        let bad_monthly = UpsertAlarmRequest {
            hour: 10,
            minute: 0,
            repeat: crate::models::Repeat::Monthly { days: vec![0] },
            enabled: true,
            label: "Bad monthly".into(),
        };
        assert!(validate_alarm(&bad_monthly).is_err());

        // Once with an invalid calendar date (Feb 31).
        let bad_once = UpsertAlarmRequest {
            hour: 10,
            minute: 0,
            repeat: crate::models::Repeat::Once { year: 2026, month: 2, day: 31 },
            enabled: true,
            label: "Bad once".into(),
        };
        assert!(validate_alarm(&bad_once).is_err());

        // Once year outside the firmware's 2000..=2099 window.
        let bad_year = UpsertAlarmRequest {
            hour: 10,
            minute: 0,
            repeat: crate::models::Repeat::Once { year: 1999, month: 12, day: 25 },
            enabled: true,
            label: "Bad year".into(),
        };
        assert!(validate_alarm(&bad_year).is_err());

        // A valid alarm still passes.
        let good = UpsertAlarmRequest {
            hour: 7,
            minute: 30,
            repeat: crate::models::Repeat::Once { year: 2026, month: 12, day: 25 },
            enabled: true,
            label: "Christmas".into(),
        };
        assert!(validate_alarm(&good).is_ok());
    }

    #[test]
    fn validate_todo_rejects_firmware_invalid_inputs() {
        // Todo with Once repeat is rejected — use due_date instead.
        let once_repeat = UpsertTodoRequest {
            text: "One-off todo".into(),
            done: false,
            importance: crate::models::Importance::Medium,
            due_date: None,
            repeat: Some(crate::models::Repeat::Once { year: 2026, month: 6, day: 1 }),
        };
        assert!(validate_todo(&once_repeat).is_err());

        // Todo with invalid due_date (April 31).
        let bad_due = UpsertTodoRequest {
            text: "Bad due".into(),
            done: false,
            importance: crate::models::Importance::Medium,
            due_date: Some(crate::models::TodoDue { year: 2026, month: 4, day: 31 }),
            repeat: None,
        };
        assert!(validate_todo(&bad_due).is_err());

        // Empty text still rejected.
        let empty_text = UpsertTodoRequest {
            text: "  ".into(),
            done: false,
            importance: crate::models::Importance::Medium,
            due_date: None,
            repeat: None,
        };
        assert!(validate_todo(&empty_text).is_err());

        // Valid todo with Weekly repeat and valid due_date passes.
        let good = UpsertTodoRequest {
            text: "Weekly review".into(),
            done: false,
            importance: crate::models::Importance::High,
            due_date: Some(crate::models::TodoDue { year: 2026, month: 8, day: 19 }),
            repeat: Some(crate::models::Repeat::Weekly { days: vec![1, 3, 5] }),
        };
        assert!(validate_todo(&good).is_ok());
    }

    /// build_sync_response rejects payloads that would exceed firmware NVS
    /// capacity before the device ever sees them.
    #[tokio::test]
    async fn build_sync_response_rejects_oversized_alarm_list() {
        let state = test_state().await;
        let device = db::register_device(&state.db, "clock", None).await.unwrap();
        // 3 alarms with 300-byte labels = >1024 serialized bytes.
        let big_label = "Z".repeat(300);
        for _ in 0..3 {
            let req = UpsertAlarmRequest {
                hour: 7,
                minute: 0,
                repeat: crate::models::Repeat::Daily,
                enabled: true,
                label: big_label.clone(),
            };
            db::upsert_alarm(&state.db, &device.id, None, &req).await.unwrap();
        }
        let result = build_sync_response(&state, &device.id, &[]).await;
        assert!(result.is_err(), "expected NVS capacity pre-check to reject oversized alarm list");
    }
}
