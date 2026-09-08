//! Wire types shared with the firmware's sync response (see
//! `inkwash/docs/sync-api.md`).
//!
//! `Repeat`/`Alarm`/`Importance`/`TodoDue`/`Todo`/`InboxKind`/`Priority`/
//! `InboxItem` are re-exports of `inkwash-logic`'s definitions (see the
//! `inkwash-logic` dependency in `Cargo.toml`) rather than a hand-copied
//! shape that could drift from the firmware's own - the firmware
//! deserializes this JSON directly into those same Rust types with no
//! adapter layer, so this crate and `rust-firmware` now literally share
//! one definition instead of two independently-maintained ones that
//! happened to agree. `Alarm` is `StoredAlarm` under its server-side name
//! so every existing `models::Alarm` call site keeps working unchanged.
//!
//! Everything below that line is server-only - HTTP request/response DTOs
//! whose JSON shape happens to match what the firmware expects, but that
//! are never the literal same Rust value crossing a process boundary the
//! way the re-exports above are, so keeping them as this crate's own types
//! costs nothing and preserves the `skip_serializing_if` compactness the
//! shared `SyncResponse` in `inkwash-logic` doesn't need to care about.
//!
//! Admin-ui TypeScript bindings: server-local DTOs carry
//! `#[derive(TS)] #[ts(export, export_to = "../admin-ui/src/lib/generated/")]`
//! so `cargo test` regenerates one `.ts` file per type there (see
//! admin-ui/src/lib/types.ts for which types stay handwritten because they
//! embed `inkwash-logic` shapes). u64/i64 would default to TS `bigint`;
//! every value actually sent (rowids, unix timestamps) fits JS's exact-
//! number range, so such fields are pinned to `number`.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

pub use inkwash_logic::alarm_schedule::{Repeat, StoredAlarm as Alarm};
pub use inkwash_logic::inbox_item::{InboxItem, InboxKind, Priority};
pub use inkwash_logic::todo::{Importance, Todo, TodoDue};

/// Body of a successful (HTTP 200) `GET /api/sync` response - see
/// `inkwash/docs/sync-api.md`.
#[derive(Clone, Debug, Serialize)]
pub struct SyncResponse {
    pub alarms: Vec<Alarm>,
    pub todos: Vec<Todo>,
    /// Inbox notifications delivered to the device (capacity-capped).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbox: Vec<InboxItem>,
    /// The device reported these `seq`s as read; echoed back so the
    /// firmware can drop them from its pending-read set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbox_read_acked: Vec<u64>,
    /// True when the server had more inbox items than it could fit in the
    /// response; the device shows a "more on server" hint.
    #[serde(default)]
    pub inbox_truncated: bool,
}

/// Mutable device-side state uploaded before the server returns its
/// authoritative content. Text, schedules and membership remain managed by
/// Desktop/Server; the device may only report completion/enabled flags for
/// records that still exist on the server.
#[derive(Clone, Debug, Deserialize)]
pub struct DeviceSyncRequest {
    #[serde(default)]
    pub alarms: Vec<DeviceAlarmState>,
    #[serde(default)]
    pub todos: Vec<DeviceTodoState>,
    /// Device-local inbox `seq`s the user has read; unknown ids are ignored.
    #[serde(default)]
    pub inbox_read: Vec<u64>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DeviceAlarmState {
    pub id: u8,
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DeviceTodoState {
    pub id: u8,
    pub done: bool,
    /// `None` when an older firmware uploads without importance - only
    /// present states are applied.
    #[serde(default)]
    pub importance: Option<Importance>,
}

#[derive(Clone, Debug, Serialize, TS)]
#[ts(export, export_to = "../admin-ui/src/lib/generated/")]
pub struct Device {
    /// UUID (v4) - opaque string, not an enumerable integer, so ids can't
    /// be guessed or iterated by an attacker who steals one url.
    pub id: String,
    pub name: String,
    /// Only ever returned once, at registration time - not readable again
    /// afterward (see `db::register_device`'s doc comment).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub token: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RegisterDeviceRequest {
    pub name: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct UpsertAlarmRequest {
    pub hour: u8,
    pub minute: u8,
    pub repeat: Repeat,
    pub enabled: bool,
    #[serde(default)]
    pub label: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct UpsertTodoRequest {
    pub text: String,
    #[serde(default)]
    pub done: bool,
    #[serde(default)]
    pub importance: Importance,
    #[serde(default)]
    pub due_date: Option<TodoDue>,
    #[serde(default)]
    pub repeat: Option<Repeat>,
}

// --- Console accounts -----------------------------------------------------
// These types are admin-console-only; they don't cross the sync wire
// contract (the firmware never sees them).

#[derive(Clone, Debug, Serialize)]
pub struct Account {
    pub id: i64,
    pub username: String,
    pub created_at: i64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
}

/// Session credential returned by register/login. The client sends it back
/// as a bearer token, exactly like the `ADMIN_TOKEN`.
#[derive(Clone, Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub username: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

/// Admin-only view of an account (never exposes the password hash).
#[derive(Clone, Debug, Serialize, TS)]
#[ts(export, export_to = "../admin-ui/src/lib/generated/")]
pub struct AccountSummary {
    /// Rowid/timestamp counters are pinned to TS `number` (not `bigint`) -
    /// see the module doc on admin-ui bindings.
    #[ts(type = "number")]
    pub id: i64,
    pub username: String,
    #[ts(type = "number")]
    pub created_at: i64,
    #[ts(type = "number")]
    pub device_count: i64,
    #[ts(type = "number")]
    pub session_count: i64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AdminResetPasswordRequest {
    pub new_password: String,
}

// --- External channels & inbox ---------------------------------------------

/// A configured external source (webhook / CalDAV) bound to one device.
/// This is the admin-facing view; it never contains the plaintext token or
/// decrypted CalDAV credentials.
#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../admin-ui/src/lib/generated/")]
pub struct Channel {
    pub id: String,
    pub device_id: String,
    /// `"webhook"` or `"caldav_basic"` (Phase 1 implements webhook). Stored
    /// as a plain string and validated on write, so the generated TS type is
    /// `string`; the UI narrows it locally where it needs the union.
    pub kind: String,
    pub name: String,
    pub enabled: bool,
    /// Short prefix of the webhook token for human identification (never a
    /// credential). Empty for non-webhook channels.
    pub token_prefix: String,
    #[ts(type = "number | null")]
    pub last_sync_at: Option<i64>,
    pub last_sync_error: Option<String>,
    #[ts(type = "number")]
    pub created_at: i64,
    #[ts(type = "number")]
    pub updated_at: i64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CreateChannelRequest {
    pub kind: String,
    pub name: String,
    /// CalDAV-only: `{ url, username, password }` (encrypted server-side).
    /// Reserved for Phase 2; webhook channels ignore it.
    #[serde(default)]
    #[allow(dead_code)]
    pub config: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct UpdateChannelRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
}

/// Response to `POST .../channels` for a webhook channel: the plaintext
/// token is returned exactly once here.
#[derive(Clone, Debug, Serialize, TS)]
#[ts(export, export_to = "../admin-ui/src/lib/generated/")]
pub struct ChannelCreated {
    pub channel: Channel,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub delivery_url: Option<String>,
}

/// Webhook delivery payload (`POST /api/channels/:id/messages`).
#[derive(Clone, Debug, Deserialize)]
pub struct InboxCreateRequest {
    pub kind: String,
    #[serde(default)]
    pub priority: Option<Priority>,
    pub title: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub when: Option<i64>,
}

/// Response to a successful webhook delivery.
#[derive(Clone, Debug, Serialize)]
pub struct InboxAccepted {
    pub accepted: bool,
    pub id: u64,
}

#[cfg(test)]
mod wire_contract_tests {
    //! Cross-repo guardrail for the sync wire contract (`docs/sync-api.md`
    //! in the firmware repo). The firmware deserializes this crate's
    //! serialized `SyncResponse` into the *same* `inkwash-logic` types the
    //! server's own DTOs wrap, so drift shows up as a parse/field failure
    //! here - in CI, on both repos - instead of as a device that silently
    //! stops syncing. These tests freeze the documented contract shape, so
    //! they must be updated (and the docs/schema bumped together) whenever
    //! the contract intentionally changes.

    use super::*;
    use inkwash_logic::sync_validate::SyncResponse as LogicSyncResponse;

    /// The canonical 200 OK body from `docs/sync-api.md` (alarms + todos),
    /// plus an inbox item exercising every documented field.
    const SYNC_API_EXAMPLE: &str = r#"{
        "alarms": [
            { "id": 0, "hour": 7, "minute": 30, "repeat": "Daily", "enabled": true, "label": "Morning" },
            { "id": 1, "hour": 22, "minute": 0, "repeat": { "Once": { "year": 2026, "month": 12, "day": 25 } }, "enabled": true, "label": "Christmas alarm" },
            { "id": 2, "hour": 9, "minute": 0, "repeat": { "Weekly": { "days": [0, 2, 4] } }, "enabled": true, "label": "Gym" }
        ],
        "todos": [
            { "id": 0, "text": "Buy groceries", "done": false, "importance": "medium", "due_date": null, "repeat": null },
            { "id": 1, "text": "Call home", "done": true, "importance": "high", "due_date": { "year": 2026, "month": 8, "day": 19 }, "repeat": { "Monthly": { "days": [1, 15] } } }
        ],
        "inbox": [
            { "id": 41, "kind": "alert", "priority": "high", "title": "Build failed", "body": "CI on main is red", "when": 1785272400, "read": false }
        ],
        "inbox_read_acked": [1, 2],
        "inbox_truncated": false
    }"#;

    #[test]
    fn doc_example_parses_into_firmware_sync_response() {
        let parsed: LogicSyncResponse =
            serde_json::from_str(SYNC_API_EXAMPLE).expect("sync-api.md example must parse");

        assert_eq!(parsed.alarms.len(), 3);
        assert_eq!(parsed.alarms[0].id, 0);
        assert_eq!(parsed.alarms[0].hour, 7);
        assert_eq!(parsed.alarms[0].minute, 30);
        assert!(matches!(parsed.alarms[0].repeat, Repeat::Daily));
        assert!(parsed.alarms[0].enabled);
        assert_eq!(parsed.alarms[0].label, "Morning");
        assert!(matches!(
            parsed.alarms[1].repeat,
            Repeat::Once {
                year: 2026,
                month: 12,
                day: 25
            }
        ));
        assert!(matches!(parsed.alarms[2].repeat, Repeat::Weekly { .. }));
        if let Repeat::Weekly { days } = &parsed.alarms[2].repeat {
            assert_eq!(days, &vec![0u8, 2, 4]);
        }

        assert_eq!(parsed.todos.len(), 2);
        assert_eq!(parsed.todos[0].text, "Buy groceries");
        assert!(!parsed.todos[0].done);
        assert_eq!(parsed.todos[0].importance, Importance::Medium);
        assert!(parsed.todos[0].due_date.is_none());
        assert!(parsed.todos[0].repeat.is_none());
        assert!(parsed.todos[1].done);
        assert_eq!(parsed.todos[1].importance, Importance::High);
        assert_eq!(
            parsed.todos[1].due_date,
            Some(TodoDue {
                year: 2026,
                month: 8,
                day: 19
            })
        );
        assert!(matches!(
            parsed.todos[1].repeat,
            Some(Repeat::Monthly { .. })
        ));
        if let Some(Repeat::Monthly { days }) = &parsed.todos[1].repeat {
            assert_eq!(days, &vec![1u8, 15]);
        }

        assert_eq!(parsed.inbox.len(), 1);
        assert_eq!(parsed.inbox[0].id, 41);
        assert!(matches!(parsed.inbox[0].kind, InboxKind::Alert));
        assert!(matches!(parsed.inbox[0].priority, Priority::High));
        assert_eq!(parsed.inbox[0].title, "Build failed");
        assert_eq!(parsed.inbox[0].body, "CI on main is red");
        assert_eq!(parsed.inbox[0].when, Some(1785272400));
        assert!(!parsed.inbox[0].read);

        assert_eq!(parsed.inbox_read_acked, vec![1u64, 2]);
        assert!(!parsed.inbox_truncated);
    }

    #[test]
    fn server_sync_response_roundtrips_into_firmware_sync_response() {
        // Whatever the server serializes must deserialize on the firmware
        // side (the same inkwash-logic types) with every documented field
        // intact - this is the direction a server-side DTO edit can break.
        let server_view = SyncResponse {
            alarms: vec![Alarm {
                id: 3,
                hour: 6,
                minute: 45,
                repeat: Repeat::Daily,
                enabled: true,
                label: "Workout".into(),
            }],
            todos: vec![Todo {
                id: 7,
                text: "Ship the release".into(),
                done: false,
                importance: Importance::High,
                due_date: None,
                repeat: None,
            }],
            inbox: vec![InboxItem {
                id: 9,
                kind: InboxKind::Info,
                priority: Priority::Normal,
                title: "Deploy finished".into(),
                body: String::new(),
                when: None,
                read: true,
            }],
            inbox_read_acked: vec![4, 5],
            inbox_truncated: true,
        };

        let serialized =
            serde_json::to_value(&server_view).expect("server SyncResponse must serialize");
        let parsed: LogicSyncResponse = serde_json::from_value(serialized.clone())
            .expect("server output must parse as firmware SyncResponse");

        assert_eq!(parsed.alarms.len(), 1);
        assert_eq!(parsed.alarms[0].id, 3);
        assert_eq!(parsed.alarms[0].hour, 6);
        assert_eq!(parsed.alarms[0].minute, 45);
        assert!(matches!(parsed.alarms[0].repeat, Repeat::Daily));
        assert!(parsed.alarms[0].enabled);
        assert_eq!(parsed.alarms[0].label, "Workout");
        assert_eq!(parsed.todos[0].id, 7);
        assert_eq!(parsed.todos[0].text, "Ship the release");
        assert_eq!(parsed.todos[0].importance, Importance::High);
        assert_eq!(parsed.inbox[0].id, 9);
        assert!(matches!(parsed.inbox[0].kind, InboxKind::Info));
        assert_eq!(parsed.inbox[0].when, None);
        assert!(parsed.inbox[0].read);
        assert_eq!(parsed.inbox_read_acked, vec![4u64, 5]);
        assert!(parsed.inbox_truncated);

        // Documented top-level keys must be present in the serialized form.
        let obj = serialized.as_object().expect("sync response is an object");
        for key in [
            "alarms",
            "todos",
            "inbox",
            "inbox_read_acked",
            "inbox_truncated",
        ] {
            assert!(obj.contains_key(key), "missing documented key {key}");
        }
        // Every serialized alarm carries the full documented field set.
        let alarm_obj = obj["alarms"][0].as_object().unwrap();
        for key in ["id", "hour", "minute", "repeat", "enabled", "label"] {
            assert!(alarm_obj.contains_key(key), "alarm missing key {key}");
        }
    }
}
