//! Storage behind sqlx's `Any` driver, so one codebase serves both SQLite
//! (default, zero-config `sqlite://` URL) and PostgreSQL (via a
//! `postgres://` `DATABASE_URL`). The backend is selected at `open()` time
//! from the URL; the schema lives in sqlx migration files (see
//! `db::schema`), and the query code is split by responsibility:
//!
//! - [`schema`] - DDL, migrations, `open()`, the pre-UUID-era SQLite rebuild
//! - [`queries`] - CRUD for devices, accounts/sessions, channels/inbox,
//!   alarms/todos (re-exported below so callers keep using `db::` paths)
//! - [`sync`] - `merge_device_state` (device-uploaded flag merging)
//!
//! Data SQL exists in explicitly maintained dual-dialect form: every
//! placeholder-bearing statement carries a SQLite (`?`) and a PostgreSQL
//! (`$1, $2, …`) variant, picked once per call by [`Db::sql`] from the
//! backend flag - no runtime rewriting (sqlx 0.8's Postgres driver does not
//! translate `?` itself). Every integer is bound as `i64` on both backends.
//! A small connection pool (default max 2) replaces the old single
//! `Arc<Mutex<Connection>>`.

use sqlx::AnyPool;

pub mod queries;
pub mod schema;
pub mod sync;

pub use queries::*;
pub use schema::open;
pub use sync::*;

/// Wraps the sqlx `Any` pool plus the backend flag. Placeholder-bearing SQL
/// is maintained as explicit SQLite/PostgreSQL string pairs selected by
/// [`Db::sql`]; dialect-neutral statements (no placeholders) are passed to
/// sqlx as-is.
#[derive(Clone)]
pub struct Db {
    pool: AnyPool,
    postgres: bool,
}

impl Db {
    /// Picks between the explicitly maintained SQLite and PostgreSQL forms of
    /// one statement. The two must say the same thing - same tables, columns
    /// and bind order - and differ only in placeholder style (`?` vs
    /// `$1, $2, …`). Statements without placeholders are dialect-neutral and
    /// don't need this helper.
    pub(crate) fn sql<'a>(&self, sqlite: &'a str, postgres: &'a str) -> &'a str {
        if self.postgres {
            postgres
        } else {
            sqlite
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        DeviceSyncRequest, Importance, Repeat, UpsertAlarmRequest, UpsertTodoRequest,
    };
    use uuid::Uuid;

    /// Opens the database under test. Honors `DATABASE_URL` so the same suite
    /// exercises PostgreSQL too (`DATABASE_URL=postgres://… cargo test`);
    /// defaults to a throwaway in-memory SQLite database. Tests only assert
    /// on rows they created themselves, so they are safe to point at a shared
    /// database that holds unrelated data.
    async fn test_db() -> Db {
        let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite::memory:".to_string());
        open(&url, 1).await.expect("open test db")
    }

    #[tokio::test]
    async fn bulk_clear_preserves_device_and_other_content() {
        let db = test_db().await;
        let device = register_device(&db, "test", None).await.unwrap();
        upsert_alarm(
            &db,
            device.id.as_str(),
            None,
            &UpsertAlarmRequest {
                hour: 7,
                minute: 30,
                repeat: Repeat::Daily,
                enabled: true,
                label: "wake".to_string(),
            },
        )
        .await
        .unwrap();
        upsert_todo(
            &db,
            device.id.as_str(),
            None,
            &UpsertTodoRequest {
                text: "keep".to_string(),
                done: false,
                importance: Importance::High,
                due_date: Some(crate::models::TodoDue {
                    year: 2026,
                    month: 12,
                    day: 25,
                }),
                repeat: None,
            },
        )
        .await
        .unwrap();

        clear_alarms(&db, device.id.as_str()).await.unwrap();
        assert!(list_alarms(&db, device.id.as_str())
            .await
            .unwrap()
            .is_empty());
        let todos = list_todos(&db, device.id.as_str()).await.unwrap();
        assert_eq!(todos.len(), 1);
        assert_eq!(todos[0].importance, Importance::High);
        assert_eq!(
            todos[0].due_date,
            Some(crate::models::TodoDue {
                year: 2026,
                month: 12,
                day: 25
            })
        );
        // Only this test's device is asserted on - the database may be shared.
        assert!(list_devices(&db)
            .await
            .unwrap()
            .iter()
            .any(|d| d.id == device.id));
    }

    #[tokio::test]
    async fn device_merge_updates_flags_without_recreating_unknown_content() {
        let db = test_db().await;
        let device = register_device(&db, "test", None).await.unwrap();
        let todo_id = upsert_todo(
            &db,
            device.id.as_str(),
            None,
            &UpsertTodoRequest {
                text: "server text".to_string(),
                done: false,
                importance: Importance::Low,
                due_date: None,
                repeat: None,
            },
        )
        .await
        .unwrap();
        let before = find_device_by_token(&db, device.token.as_deref().unwrap())
            .await
            .unwrap()
            .unwrap()
            .1;
        merge_device_state(
            &db,
            device.id.as_str(),
            &DeviceSyncRequest {
                alarms: vec![],
                todos: vec![
                    crate::models::DeviceTodoState {
                        id: todo_id,
                        done: true,
                        importance: Some(Importance::High),
                    },
                    crate::models::DeviceTodoState {
                        id: 250,
                        done: true,
                        importance: None,
                    },
                ],
                inbox_read: vec![],
            },
        )
        .await
        .unwrap();
        let todos = list_todos(&db, device.id.as_str()).await.unwrap();
        assert_eq!(todos.len(), 1);
        assert_eq!(todos[0].text, "server text");
        assert!(todos[0].done);
        assert_eq!(todos[0].importance, Importance::High);
        let after = find_device_by_token(&db, device.token.as_deref().unwrap())
            .await
            .unwrap()
            .unwrap()
            .1;
        assert_eq!(after, before + 1);
    }

    #[tokio::test]
    async fn account_flow_and_admin_summary() {
        let db = test_db().await;
        // Unique-per-run username: this suite may run against a shared
        // PostgreSQL database that already holds an "alice".
        let username = format!("alice-{}", Uuid::new_v4().simple());
        let account = register_account(&db, &username, "fake-hash").await.unwrap();
        assert!(account.id > 0);
        let found = find_account_by_username(&db, &username)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.0, account.id);

        let device = register_device(&db, "alice-clock", Some(account.id))
            .await
            .unwrap();
        assert!(device_owned_by(&db, &device.id, account.id).await.unwrap());
        assert!(!device_owned_by(&db, &device.id, 999).await.unwrap());

        let summaries = list_accounts(&db).await.unwrap();
        let summary = summaries
            .iter()
            .find(|s| s.username == username)
            .expect("newly created account listed");
        assert_eq!(summary.device_count, 1);

        assert!(delete_account(&db, account.id).await.unwrap());
        assert!(!delete_account(&db, account.id).await.unwrap());
        // The cascade must have removed the account's device (not every
        // device - the database may be shared).
        assert!(!list_devices(&db)
            .await
            .unwrap()
            .iter()
            .any(|d| d.id == device.id));
    }

    #[tokio::test]
    async fn webhook_channel_delivers_unique_seq_and_idempotent_dedup() {
        let db = test_db().await;
        let device = register_device(&db, "dev", None).await.unwrap();
        let (channel, token) = create_channel(&db, &device.id, "webhook", "CI", None)
            .await
            .unwrap();
        assert!(token.unwrap().starts_with("ipwh_"));

        // Concurrent-ish sequential deliveries must get increasing, unique seq.
        let (seq1, created1) = deliver_inbox(
            &db,
            &device.id,
            &channel.id,
            "alert",
            "normal",
            "Build failed",
            "main",
            None,
            None,
        )
        .await
        .unwrap();
        let (seq2, created2) = deliver_inbox(
            &db,
            &device.id,
            &channel.id,
            "info",
            "normal",
            "Build ok",
            "",
            None,
            None,
        )
        .await
        .unwrap();
        assert!(created1 && created2);
        assert_eq!(seq1, 1);
        assert_eq!(seq2, 2);
        assert_ne!(seq1, seq2);

        // Idempotency: same source_ref returns the same seq without a new row.
        let (seq_orig, created_orig) = deliver_inbox(
            &db,
            &device.id,
            &channel.id,
            "alert",
            "normal",
            "Build failed",
            "main",
            None,
            Some("key-1"),
        )
        .await
        .unwrap();
        let (seq_replay, created_replay) = deliver_inbox(
            &db,
            &device.id,
            &channel.id,
            "alert",
            "normal",
            "Build failed",
            "main",
            None,
            Some("key-1"),
        )
        .await
        .unwrap();
        assert!(created_orig);
        assert!(!created_replay);
        assert_eq!(seq_orig, seq_replay);

        // Read merge only affects this device and acks what was marked.
        let (_items, truncated) = list_inbox(&db, &device.id, 20).await.unwrap();
        assert!(!truncated);
        let acked = mark_inbox_read(&db, &device.id, &[seq1]).await.unwrap();
        assert_eq!(acked, vec![seq1]);
        let (items2, _) = list_inbox(&db, &device.id, 20).await.unwrap();
        assert!(items2.iter().find(|i| i.id == seq1).unwrap().read);
        // Re-marking an already-read item returns nothing (no double ack).
        assert!(mark_inbox_read(&db, &device.id, &[seq1])
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn channel_ownership_and_rotate() {
        let db = test_db().await;
        let device = register_device(&db, "dev", None).await.unwrap();
        let (channel, _) = create_channel(&db, &device.id, "webhook", "CI", None)
            .await
            .unwrap();
        let version_before_rotate = find_device_by_token(&db, device.token.as_deref().unwrap())
            .await
            .unwrap()
            .unwrap()
            .1;

        // Wrong device cannot fetch this channel.
        let other = register_device(&db, "other", None).await.unwrap();
        assert!(get_channel(&db, &other.id, &channel.id)
            .await
            .unwrap()
            .is_none());

        // Rotate changes the token (verifiable via a changed hash check).
        let (new_token, new_prefix) = rotate_channel_token(&db, &device.id, &channel.id)
            .await
            .unwrap()
            .unwrap();
        assert!(new_token.starts_with("ipwh_"));
        assert_eq!(new_prefix, new_token.chars().take(12).collect::<String>());
        let version_after_rotate = find_device_by_token(&db, device.token.as_deref().unwrap())
            .await
            .unwrap()
            .unwrap()
            .1;
        assert_eq!(version_after_rotate, version_before_rotate + 1);
        assert_ne!(
            get_channel(&db, &device.id, &channel.id)
                .await
                .unwrap()
                .unwrap()
                .token_prefix,
            channel.token_prefix
        );

        // Rotate on a non-webhook channel returns None.
        assert!(rotate_channel_token(&db, &device.id, "does-not-exist")
            .await
            .unwrap()
            .is_none());

        // Deleting a channel cascades its inbox.
        deliver_inbox(
            &db,
            &device.id,
            &channel.id,
            "info",
            "normal",
            "x",
            "",
            None,
            None,
        )
        .await
        .unwrap();
        assert!(delete_channel(&db, &device.id, &channel.id).await.unwrap());
        let (items, _) = list_inbox(&db, &device.id, 20).await.unwrap();
        assert!(items.is_empty());
    }

    #[tokio::test]
    async fn inbox_capacity_is_capped() {
        let db = test_db().await;
        let device = register_device(&db, "dev", None).await.unwrap();
        let (channel, _) = create_channel(&db, &device.id, "webhook", "CI", None)
            .await
            .unwrap();
        for i in 0..30 {
            deliver_inbox(
                &db,
                &device.id,
                &channel.id,
                "info",
                "normal",
                &format!("m{i}"),
                "",
                None,
                None,
            )
            .await
            .unwrap();
        }
        let (items, truncated) = list_inbox(&db, &device.id, 20).await.unwrap();
        assert_eq!(items.len(), 20);
        assert!(truncated);
        // Newest seq first (seq DESC).
        assert_eq!(items[0].id, 30);
    }

    #[tokio::test]
    async fn inbox_priority_roundtrips_and_drives_urgent_flag() {
        let db = test_db().await;
        let device = register_device(&db, "dev", None).await.unwrap();
        let (channel, _) = create_channel(&db, &device.id, "webhook", "CI", None)
            .await
            .unwrap();

        deliver_inbox(
            &db,
            &device.id,
            &channel.id,
            "info",
            "normal",
            "normal msg",
            "",
            None,
            None,
        )
        .await
        .unwrap();
        deliver_inbox(
            &db,
            &device.id,
            &channel.id,
            "alert",
            "high",
            "urgent msg",
            "",
            None,
            None,
        )
        .await
        .unwrap();

        let (items, _) = list_inbox(&db, &device.id, 20).await.unwrap();
        assert_eq!(items.len(), 2);
        let urgent = items.iter().find(|i| i.title == "urgent msg").unwrap();
        assert_eq!(urgent.priority, crate::models::Priority::High);
        let normal = items.iter().find(|i| i.title == "normal msg").unwrap();
        assert_eq!(normal.priority, crate::models::Priority::Normal);

        // has_unread_high_inbox is true while the urgent one is unread.
        assert!(has_unread_high_inbox(&db, &device.id).await.unwrap());

        // Marking the urgent one read clears the flag.
        mark_inbox_read(&db, &device.id, &[urgent.id])
            .await
            .unwrap();
        assert!(!has_unread_high_inbox(&db, &device.id).await.unwrap());
    }

    #[tokio::test]
    async fn failed_write_does_not_bump_device_version() {
        let db = test_db().await;
        let device = register_device(&db, "dev", None).await.unwrap();
        let before = find_device_by_token(&db, device.token.as_deref().unwrap())
            .await
            .unwrap()
            .unwrap()
            .1;
        // Insert an alarm for a nonexistent device: the FK violation aborts
        // the transaction, so the version bump inside it must not persist.
        let res = upsert_alarm(
            &db,
            "no-such-device",
            None,
            &UpsertAlarmRequest {
                hour: 7,
                minute: 0,
                repeat: Repeat::Daily,
                enabled: true,
                label: String::new(),
            },
        )
        .await;
        assert!(res.is_err());
        let after = find_device_by_token(&db, device.token.as_deref().unwrap())
            .await
            .unwrap()
            .unwrap()
            .1;
        assert_eq!(after, before, "version must not advance on a failed write");
    }
    #[tokio::test]
    async fn alarm_todo_delete_and_account_updates() {
        let db = test_db().await;
        let username = format!("carol-{}", Uuid::new_v4().simple());
        let account = register_account(&db, &username, "hash-1").await.unwrap();

        // account_by_id / update_account_password roundtrip.
        let fetched = account_by_id(&db, account.id).await.unwrap().unwrap();
        assert_eq!(fetched.username, username);
        let session = create_session(&db, account.id).await.unwrap();
        assert_eq!(find_session(&db, &session).await.unwrap(), Some(account.id));
        assert!(update_account_password(&db, account.id, "hash-2")
            .await
            .unwrap());
        assert_eq!(find_session(&db, &session).await.unwrap(), None);
        let (_, password_hash) = find_account_by_username(&db, &username)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(password_hash, "hash-2");

        // delete_alarm / delete_todo remove exactly their row.
        let device = register_device(&db, "dev", None).await.unwrap();
        let alarm_id = upsert_alarm(
            &db,
            &device.id,
            None,
            &UpsertAlarmRequest {
                hour: 6,
                minute: 45,
                repeat: Repeat::Daily,
                enabled: true,
                label: "a".to_string(),
            },
        )
        .await
        .unwrap();
        delete_alarm(&db, &device.id, alarm_id).await.unwrap();
        assert!(list_alarms(&db, &device.id).await.unwrap().is_empty());

        let todo_id = upsert_todo(
            &db,
            &device.id,
            None,
            &UpsertTodoRequest {
                text: "t".to_string(),
                done: false,
                importance: Importance::Low,
                due_date: None,
                repeat: None,
            },
        )
        .await
        .unwrap();
        delete_todo(&db, &device.id, todo_id).await.unwrap();
        assert!(list_todos(&db, &device.id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn session_lifecycle() {
        let db = test_db().await;
        let username = format!("dave-{}", Uuid::new_v4().simple());
        let account = register_account(&db, &username, "h").await.unwrap();
        let token = create_session(&db, account.id).await.unwrap();
        assert_eq!(find_session(&db, &token).await.unwrap(), Some(account.id));
        delete_session(&db, &token).await.unwrap();
        assert_eq!(find_session(&db, &token).await.unwrap(), None);
    }

    #[tokio::test]
    async fn expired_sessions_are_rejected_and_cleaned_up() {
        let db = test_db().await;
        let username = format!("expiry-{}", Uuid::new_v4().simple());
        let account = register_account(&db, &username, "h").await.unwrap();
        let token = create_session(&db, account.id).await.unwrap();
        sqlx::query(db.sql(
            "UPDATE sessions SET expires_at = 0 WHERE token = ?",
            "UPDATE sessions SET expires_at = 0 WHERE token = $1",
        ))
        .bind(&token)
        .execute(&db.pool)
        .await
        .unwrap();

        assert_eq!(find_session(&db, &token).await.unwrap(), None);
        assert_eq!(delete_expired_sessions(&db).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn channel_update_delivery_and_inbox_management() {
        let db = test_db().await;
        let device = register_device(&db, "dev", None).await.unwrap();
        let (channel, token) = create_channel(&db, &device.id, "webhook", "old", None)
            .await
            .unwrap();

        // list_channels scopes to the device; get_channel_for_delivery is
        // unscoped and hands back the stored hash for token verification.
        let listed = list_channels(&db, &device.id).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "old");
        let (delivery_device, hash) = get_channel_for_delivery(&db, &channel.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(delivery_device, device.id);
        assert!(crate::auth::verify_password(&token.unwrap(), &hash));

        // update_channel merges only the provided fields.
        assert!(
            update_channel(&db, &device.id, &channel.id, Some("new"), Some(false))
                .await
                .unwrap()
        );
        let updated = get_channel(&db, &device.id, &channel.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.name, "new");
        assert!(!updated.enabled);
        update_channel(&db, &device.id, &channel.id, None, Some(true))
            .await
            .unwrap();

        // delete_inbox_item removes one seq; clear_read_inbox drops read ones.
        let (seq1, _) = deliver_inbox(
            &db,
            &device.id,
            &channel.id,
            "info",
            "normal",
            "x",
            "",
            None,
            None,
        )
        .await
        .unwrap();
        let (seq2, _) = deliver_inbox(
            &db,
            &device.id,
            &channel.id,
            "info",
            "normal",
            "y",
            "",
            None,
            None,
        )
        .await
        .unwrap();
        mark_inbox_read(&db, &device.id, &[seq1]).await.unwrap();
        assert!(delete_inbox_item(&db, &device.id, seq2).await.unwrap());
        clear_read_inbox(&db, &device.id).await.unwrap();
        let (items, _) = list_inbox(&db, &device.id, 20).await.unwrap();
        assert!(items.is_empty());

        // delete_device cascades: its channels disappear with it.
        delete_device(&db, &device.id).await.unwrap();
        assert!(get_channel(&db, &device.id, &channel.id)
            .await
            .unwrap()
            .is_none());
    }
}
