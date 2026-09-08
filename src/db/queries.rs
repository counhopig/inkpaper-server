//! CRUD queries behind the `Any` driver, split out of the old monolithic
//! `db.rs`. Everything here is a write or read of one aggregate (devices,
//! accounts/sessions, channels/inbox, alarms/todos); the cross-aggregate
//! sync merge lives in `sync.rs`.
//!
//! Placeholder-bearing statements are explicitly maintained as SQLite/PostgreSQL
//! string pairs picked by `Db::sql`; statements without placeholders are
//! dialect-neutral and passed to sqlx as-is. Every integer is bound as `i64`
//! on both backends. Keep each pair's tables, columns and bind order identical -
//! only the placeholder style (`?` vs `$1, $2, …`) may differ.

use anyhow::{anyhow, Result};
use rand::distributions::Alphanumeric;
use rand::Rng;
use sqlx::{Any, Executor, Row, Transaction};
use uuid::Uuid;

use super::Db;
use crate::models::{
    Account, AccountSummary, Alarm, Channel, Device, Importance, InboxItem, InboxKind, Priority,
    Repeat, Todo, UpsertAlarmRequest, UpsertTodoRequest,
};

const SESSION_TTL_SECONDS: i64 = 30 * 24 * 60 * 60;

fn new_token() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(48)
        .map(char::from)
        .collect()
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Registers a new device and returns it with its token populated. The token
/// is a bearer credential (see `docs/sync-api.md`'s Security section in the
/// firmware repo) - only ever returned here, at creation time;
/// `list_devices` omits it, so losing it means re-registering. `account_id:
/// None` creates an unowned device (only reachable with the `ADMIN_TOKEN`);
/// `Some` ties the device to a console account.
///
/// ## Token storage decision (2026-08-25)
/// Device and session tokens are stored **plaintext**, unlike webhook
/// channel tokens (Argon2id-hashed in `create_channel`). Deliberate:
/// - A device/session token is a 48-char CSPRNG string with ~288 bits of
///   entropy - brute-forcing the stored value is not a realistic attack,
///   unlike the user-chosen passwords those same tables otherwise hold.
/// - Both are looked up with `WHERE token = ?` at every request. Hashing
///   them would make lookup an all-rows scan (Argon2 is one-way; a hash
///   can't index the table), costing far more than the plaintext compare
///   saves - and the DB is already behind the same trust boundary that
///   grants admin access to everything.
/// - Tokens are per-device/per-session and revocable by deletion
///   (`delete_device`/`delete_session`), so a leaked value is contained
///   without a data migration.
/// - Channel tokens are hashed instead because they are meant to be pasted
///   into third-party tools and integrations, where the "personal server"
///   trust boundary does not hold the same way.
pub async fn register_device(db: &Db, name: &str, account_id: Option<i64>) -> Result<Device> {
    let token = new_token();
    let now = now_unix();
    let id = Uuid::new_v4().to_string();
    sqlx::query(db.sql(
            "INSERT INTO devices (id, name, token, version, created_at, account_id) VALUES (?, ?, ?, 0, ?, ?)",
            "INSERT INTO devices (id, name, token, version, created_at, account_id) VALUES ($1, $2, $3, 0, $4, $5)"
        ))
    .bind(&id)
    .bind(name)
    .bind(&token)
    .bind(now)
    .bind(account_id)
    .execute(&db.pool)
    .await?;
    Ok(Device {
        id,
        name: name.to_string(),
        token: Some(token),
    })
}

pub async fn list_devices(db: &Db) -> Result<Vec<Device>> {
    let rows = sqlx::query(db.sql(
        "SELECT id, name FROM devices ORDER BY name",
        "SELECT id, name FROM devices ORDER BY name",
    ))
    .fetch_all(&db.pool)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(Device {
                id: r.try_get(0)?,
                name: r.try_get(1)?,
                token: None,
            })
        })
        .collect()
}

/// Devices owned by one console account (for `GET /api/devices` when the
/// caller is an account session rather than the admin token).
pub async fn list_account_devices(db: &Db, account_id: i64) -> Result<Vec<Device>> {
    let rows = sqlx::query(db.sql(
        "SELECT id, name FROM devices WHERE account_id = ? ORDER BY name",
        "SELECT id, name FROM devices WHERE account_id = $1 ORDER BY name",
    ))
    .bind(account_id)
    .fetch_all(&db.pool)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(Device {
                id: r.try_get(0)?,
                name: r.try_get(1)?,
                token: None,
            })
        })
        .collect()
}

/// Whether `device_id` exists and is owned by `account_id`.
pub async fn device_owned_by(db: &Db, device_id: &str, account_id: i64) -> Result<bool> {
    let count: i64 = sqlx::query_scalar(db.sql(
        "SELECT COUNT(*) FROM devices WHERE id = ? AND account_id = ?",
        "SELECT COUNT(*) FROM devices WHERE id = $1 AND account_id = $2",
    ))
    .bind(device_id)
    .bind(account_id)
    .fetch_one(&db.pool)
    .await?;
    Ok(count > 0)
}

pub async fn delete_device(db: &Db, device_id: &str) -> Result<()> {
    sqlx::query(db.sql(
        "DELETE FROM devices WHERE id = ?",
        "DELETE FROM devices WHERE id = $1",
    ))
    .bind(device_id)
    .execute(&db.pool)
    .await?;
    Ok(())
}

/// Looks up the device owning `token`, returning `(device_id, version)`.
/// Plaintext lookup by design - see `register_device`'s "Token storage
/// decision" comment.
pub async fn find_device_by_token(db: &Db, token: &str) -> Result<Option<(String, i64)>> {
    let row = sqlx::query(db.sql(
        "SELECT id, version FROM devices WHERE token = ?",
        "SELECT id, version FROM devices WHERE token = $1",
    ))
    .bind(token)
    .fetch_optional(&db.pool)
    .await?;
    row.map(|r| -> Result<(String, i64)> { Ok((r.try_get(0)?, r.try_get(1)?)) })
        .transpose()
}

/// Reads the current sync version after a sync response has been assembled.
/// Callers must not reuse the version captured during authentication because
/// response construction may itself acknowledge inbox items and bump it.
pub async fn device_version(db: &Db, device_id: &str) -> Result<i64> {
    sqlx::query_scalar(db.sql(
        "SELECT version FROM devices WHERE id = ?",
        "SELECT version FROM devices WHERE id = $1",
    ))
    .bind(device_id)
    .fetch_one(&db.pool)
    .await
    .map_err(Into::into)
}

/// Bumps a device's sync version. Callers that combine a write with a bump
/// must run both inside one `pool.begin()` transaction (see `upsert_alarm`
/// and friends) so a failed write can't leave a phantom version bump.
pub async fn bump_version<'e, E>(db: &Db, executor: E, device_id: &str) -> Result<()>
where
    E: Executor<'e, Database = Any>,
{
    sqlx::query(db.sql(
        "UPDATE devices SET version = version + 1 WHERE id = ?",
        "UPDATE devices SET version = version + 1 WHERE id = $1",
    ))
    .bind(device_id)
    .execute(executor)
    .await?;
    Ok(())
}

pub async fn list_alarms(db: &Db, device_id: &str) -> Result<Vec<Alarm>> {
    let rows = sqlx::query(db.sql(
        "SELECT local_id, hour, minute, repeat_kind, once_year, once_month, once_day, repeat_days, enabled, label
         FROM alarms WHERE device_id = ? ORDER BY local_id",
        "SELECT local_id, hour, minute, repeat_kind, once_year, once_month, once_day, repeat_days, enabled, label
         FROM alarms WHERE device_id = $1 ORDER BY local_id",
    ))
    .bind(device_id)
    .fetch_all(&db.pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            let repeat_kind: String = row.try_get(3)?;
            let repeat = repeat_from_columns(
                &repeat_kind,
                row.try_get(4)?,
                row.try_get(5)?,
                row.try_get(6)?,
                row.try_get(7)?,
            );
            Ok(Alarm {
                id: u8::try_from(row.try_get::<i64, _>(0)?)
                    .map_err(|_| anyhow!("alarm id out of range"))?,
                hour: u8::try_from(row.try_get::<i64, _>(1)?)
                    .map_err(|_| anyhow!("hour out of range"))?,
                minute: u8::try_from(row.try_get::<i64, _>(2)?)
                    .map_err(|_| anyhow!("minute out of range"))?,
                repeat,
                enabled: row.try_get::<i64, _>(8)? != 0,
                label: row.try_get(9)?,
            })
        })
        .collect()
}

pub async fn list_todos(db: &Db, device_id: &str) -> Result<Vec<Todo>> {
    let rows = sqlx::query(db.sql(
            "SELECT local_id, text, done, importance, due_year, due_month, due_day, repeat_kind, repeat_days
         FROM todos WHERE device_id = ? ORDER BY local_id",
            "SELECT local_id, text, done, importance, due_year, due_month, due_day, repeat_kind, repeat_days
         FROM todos WHERE device_id = $1 ORDER BY local_id"
        ))
    .bind(device_id)
    .fetch_all(&db.pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            let importance_str: String = row.try_get(3)?;
            let due_year: Option<i64> = row.try_get(4)?;
            let due_month: Option<i64> = row.try_get(5)?;
            let due_day: Option<i64> = row.try_get(6)?;
            let repeat_kind: Option<String> = row.try_get(7)?;
            let repeat_days: Option<String> = row.try_get(8)?;
            let due_date = match (due_year, due_month, due_day) {
                (year, Some(month), Some(day)) => Some(crate::models::TodoDue {
                    year: year.unwrap_or(0) as u16,
                    month: month as u8,
                    day: day as u8,
                }),
                _ => None,
            };
            let repeat = match repeat_kind.as_deref() {
                Some(kind) if !kind.is_empty() => {
                    Some(repeat_from_columns(kind, None, None, None, repeat_days))
                }
                _ => None,
            };
            Ok(Todo {
                id: u8::try_from(row.try_get::<i64, _>(0)?)
                    .map_err(|_| anyhow!("todo id out of range"))?,
                text: row.try_get(1)?,
                done: row.try_get::<i64, _>(2)? != 0,
                importance: importance_from_str(&importance_str),
                due_date,
                repeat,
            })
        })
        .collect()
}

/// Allocates the first wire-compatible id that has never been assigned to
/// this device/list. Deleted ids stay in `device_local_ids`: the device may
/// still have a dirty copy of one while it is waiting to receive the next
/// authoritative sync response, so reusing it could apply stale state to a
/// different record.
async fn next_local_id<'e, E>(db: &Db, executor: E, kind: &str, device_id: &str) -> Result<u8>
where
    E: Executor<'e, Database = Any>,
{
    let rows = sqlx::query(db.sql(
        "SELECT local_id FROM device_local_ids WHERE device_id = ? AND kind = ?",
        "SELECT local_id FROM device_local_ids WHERE device_id = $1 AND kind = $2",
    ))
    .bind(device_id)
    .bind(kind)
    .fetch_all(executor)
    .await?;
    let mut used = [false; 256];
    for row in rows {
        if let Ok(id) = usize::try_from(row.try_get::<i64, _>(0)?) {
            if id < used.len() {
                used[id] = true;
            }
        }
    }
    used.iter()
        .position(|assigned| !assigned)
        .and_then(|id| u8::try_from(id).ok())
        .ok_or_else(|| anyhow!("device has reached the 256-alarm/todo id limit"))
}

async fn reserve_local_id(
    db: &Db,
    tx: &mut Transaction<'_, Any>,
    device_id: &str,
    kind: &str,
    id: u8,
) -> Result<()> {
    let released: Option<i64> = sqlx::query_scalar(db.sql(
        "SELECT released FROM device_local_ids WHERE device_id = ? AND kind = ? AND local_id = ?",
        "SELECT released FROM device_local_ids WHERE device_id = $1 AND kind = $2 AND local_id = $3",
    ))
    .bind(device_id)
    .bind(kind)
    .bind(id as i64)
    .fetch_optional(&mut **tx)
    .await?;
    if released == Some(1) {
        return Err(anyhow!("local id is awaiting device sync confirmation"));
    }
    sqlx::query(db.sql(
        "INSERT INTO device_local_ids (device_id, kind, local_id, released) VALUES (?, ?, ?, 0) ON CONFLICT(device_id, kind, local_id) DO NOTHING",
        "INSERT INTO device_local_ids (device_id, kind, local_id, released) VALUES ($1, $2, $3, 0) ON CONFLICT(device_id, kind, local_id) DO NOTHING",
    ))
    .bind(device_id)
    .bind(kind)
    .bind(id as i64)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(crate) async fn release_confirmed_local_ids(
    db: &Db,
    tx: &mut Transaction<'_, Any>,
    device_id: &str,
    kind: &str,
    uploaded_ids: &[u8],
) -> Result<()> {
    let mut sql = format!(
        "DELETE FROM device_local_ids WHERE device_id = {} AND kind = {} AND released = {}",
        if db.postgres { "$1" } else { "?" },
        if db.postgres { "$2" } else { "?" },
        if db.postgres { "$3" } else { "?" },
    );
    if !uploaded_ids.is_empty() {
        let placeholders = (0..uploaded_ids.len())
            .map(|index| {
                if db.postgres {
                    format!("${}", index + 4)
                } else {
                    "?".to_string()
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        sql.push_str(&format!(" AND local_id NOT IN ({placeholders})"));
    }
    let mut query = sqlx::query(&sql).bind(device_id).bind(kind).bind(1_i64);
    for id in uploaded_ids {
        query = query.bind(*id as i64);
    }
    query.execute(&mut **tx).await?;
    Ok(())
}

/// Takes the SQLite writer lock before reading the allocation history. A
/// deferred transaction would let concurrent upserts observe the same free
/// slot and then race while upgrading to a writer; serializing on the device
/// row keeps the allocation and insert in one lock-protected transaction.
pub(crate) async fn lock_device_for_write<'e, E>(
    db: &Db,
    executor: E,
    device_id: &str,
) -> Result<()>
where
    E: Executor<'e, Database = Any>,
{
    let result = sqlx::query(db.sql(
        "UPDATE devices SET version = version WHERE id = ?",
        "UPDATE devices SET version = version WHERE id = $1",
    ))
    .bind(device_id)
    .execute(executor)
    .await?;
    if result.rows_affected() == 0 {
        return Err(anyhow!("device not found"));
    }
    Ok(())
}

/// Creates a new alarm (`id: None`) or replaces an existing one (`id:
/// Some`) for `device_id`, and returns the alarm's id. Bumps the device's
/// sync version in the same transaction so a failed write can't leave a
/// phantom version bump behind.
pub async fn upsert_alarm(
    db: &Db,
    device_id: &str,
    id: Option<u8>,
    req: &UpsertAlarmRequest,
) -> Result<u8> {
    let mut tx = db.pool.begin().await?;
    lock_device_for_write(db, &mut *tx, device_id).await?;
    let id = match id {
        Some(id) => id,
        None => next_local_id(db, &mut *tx, "alarm", device_id).await?,
    };
    reserve_local_id(db, &mut tx, device_id, "alarm", id).await?;
    let (repeat_kind, once_year, once_month, once_day, repeat_days) =
        repeat_to_columns(&req.repeat);
    sqlx::query(db.sql(
            "INSERT INTO alarms (device_id, local_id, hour, minute, repeat_kind, once_year, once_month, once_day, repeat_days, enabled, label)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(device_id, local_id) DO UPDATE SET
            hour=excluded.hour, minute=excluded.minute, repeat_kind=excluded.repeat_kind,
            once_year=excluded.once_year, once_month=excluded.once_month, once_day=excluded.once_day,
            repeat_days=excluded.repeat_days,
            enabled=excluded.enabled, label=excluded.label",
            "INSERT INTO alarms (device_id, local_id, hour, minute, repeat_kind, once_year, once_month, once_day, repeat_days, enabled, label)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         ON CONFLICT(device_id, local_id) DO UPDATE SET
            hour=excluded.hour, minute=excluded.minute, repeat_kind=excluded.repeat_kind,
            once_year=excluded.once_year, once_month=excluded.once_month, once_day=excluded.once_day,
            repeat_days=excluded.repeat_days,
            enabled=excluded.enabled, label=excluded.label"
        ))
    .bind(device_id)
    .bind(id as i64)
    .bind(req.hour as i64)
    .bind(req.minute as i64)
    .bind(repeat_kind)
    .bind(once_year)
    .bind(once_month)
    .bind(once_day)
    .bind(repeat_days)
    .bind(req.enabled as i64)
    .bind(&req.label)
    .execute(&mut *tx)
    .await?;
    bump_version(db, &mut *tx, device_id).await?;
    tx.commit().await?;
    Ok(id)
}

pub async fn delete_alarm(db: &Db, device_id: &str, id: u8) -> Result<()> {
    delete_local_id(db, "alarms", device_id, id).await
}

pub async fn clear_alarms(db: &Db, device_id: &str) -> Result<()> {
    clear_table(db, "alarms", device_id).await
}

pub async fn upsert_todo(
    db: &Db,
    device_id: &str,
    id: Option<u8>,
    req: &UpsertTodoRequest,
) -> Result<u8> {
    let mut tx = db.pool.begin().await?;
    lock_device_for_write(db, &mut *tx, device_id).await?;
    let id = match id {
        Some(id) => id,
        None => next_local_id(db, &mut *tx, "todo", device_id).await?,
    };
    reserve_local_id(db, &mut tx, device_id, "todo", id).await?;
    let (due_year, due_month, due_day) = match req.due_date {
        Some(due) => (
            Some(due.year as i64),
            Some(due.month as i64),
            Some(due.day as i64),
        ),
        None => (None, None, None),
    };
    // A todo's one-off nature is expressed by `due_date`; `Once` repeats
    // are folded to no-repeat so a repeating schedule can't lose its
    // meaning in the todos table (which has no once columns).
    let (repeat_kind, repeat_days) = match req.repeat.as_ref() {
        Some(Repeat::Daily) => (Some("daily"), None),
        Some(Repeat::Weekly { days }) => (Some("weekly"), repeat_days_json_opt(days)),
        Some(Repeat::Monthly { days }) => (Some("monthly"), repeat_days_json_opt(days)),
        Some(Repeat::Once { .. }) | None => (None, None),
    };
    sqlx::query(db.sql(
            "INSERT INTO todos (device_id, local_id, text, done, importance, due_year, due_month, due_day, repeat_kind, repeat_days)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(device_id, local_id) DO UPDATE SET
            text=excluded.text, done=excluded.done, importance=excluded.importance,
            due_year=excluded.due_year, due_month=excluded.due_month, due_day=excluded.due_day,
            repeat_kind=excluded.repeat_kind, repeat_days=excluded.repeat_days",
            "INSERT INTO todos (device_id, local_id, text, done, importance, due_year, due_month, due_day, repeat_kind, repeat_days)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         ON CONFLICT(device_id, local_id) DO UPDATE SET
            text=excluded.text, done=excluded.done, importance=excluded.importance,
            due_year=excluded.due_year, due_month=excluded.due_month, due_day=excluded.due_day,
            repeat_kind=excluded.repeat_kind, repeat_days=excluded.repeat_days"
        ))
    .bind(device_id)
    .bind(id as i64)
    .bind(&req.text)
    .bind(req.done as i64)
    .bind(req.importance.as_str())
    .bind(due_year)
    .bind(due_month)
    .bind(due_day)
    .bind(repeat_kind)
    .bind(repeat_days)
    .execute(&mut *tx)
    .await?;
    bump_version(db, &mut *tx, device_id).await?;
    tx.commit().await?;
    Ok(id)
}

pub async fn delete_todo(db: &Db, device_id: &str, id: u8) -> Result<()> {
    delete_local_id(db, "todos", device_id, id).await
}

pub async fn clear_todos(db: &Db, device_id: &str) -> Result<()> {
    clear_table(db, "todos", device_id).await
}

/// Deletes one `local_id`-keyed row for `device_id` and bumps the device's
/// sync version in the same transaction. Shared by `delete_alarm`/
/// `delete_todo` - `table` is always a hardcoded caller-supplied literal
/// (`"alarms"`/`"todos"`), never request input, so building the query with
/// `format!` here is safe (same pattern already used by `next_local_id`).
async fn delete_local_id(db: &Db, table: &str, device_id: &str, id: u8) -> Result<()> {
    let mut tx = db.pool.begin().await?;
    let kind = match table {
        "alarms" => "alarm",
        "todos" => "todo",
        _ => unreachable!("delete_local_id only accepts alarm/todo tables"),
    };
    let sql = if db.postgres {
        format!("DELETE FROM {table} WHERE device_id = $1 AND local_id = $2")
    } else {
        format!("DELETE FROM {table} WHERE device_id = ? AND local_id = ?")
    };
    sqlx::query(&sql)
        .bind(device_id)
        .bind(id as i64)
        .execute(&mut *tx)
        .await?;
    sqlx::query(db.sql(
        "UPDATE device_local_ids SET released = 1 WHERE device_id = ? AND kind = ? AND local_id = ?",
        "UPDATE device_local_ids SET released = 1 WHERE device_id = $1 AND kind = $2 AND local_id = $3",
    ))
    .bind(device_id)
    .bind(kind)
    .bind(id as i64)
    .execute(&mut *tx)
    .await?;
    bump_version(db, &mut *tx, device_id).await?;
    tx.commit().await?;
    Ok(())
}

/// Deletes every row for `device_id` from `table` and bumps the device's
/// sync version in the same transaction. Shared by `clear_alarms`/
/// `clear_todos` - see `delete_local_id` for why the `format!` here is safe.
async fn clear_table(db: &Db, table: &str, device_id: &str) -> Result<()> {
    let mut tx = db.pool.begin().await?;
    let kind = match table {
        "alarms" => "alarm",
        "todos" => "todo",
        _ => unreachable!("clear_table only accepts alarm/todo tables"),
    };
    let sql = if db.postgres {
        format!("DELETE FROM {table} WHERE device_id = $1")
    } else {
        format!("DELETE FROM {table} WHERE device_id = ?")
    };
    sqlx::query(&sql).bind(device_id).execute(&mut *tx).await?;
    sqlx::query(db.sql(
        "UPDATE device_local_ids SET released = 1 WHERE device_id = ? AND kind = ?",
        "UPDATE device_local_ids SET released = 1 WHERE device_id = $1 AND kind = $2",
    ))
    .bind(device_id)
    .bind(kind)
    .execute(&mut *tx)
    .await?;
    bump_version(db, &mut *tx, device_id).await?;
    tx.commit().await?;
    Ok(())
}

// --- Console accounts & sessions ---------------------------------------

pub async fn register_account(db: &Db, username: &str, password_hash: &str) -> Result<Account> {
    let id: i64 = sqlx::query_scalar(db.sql(
            "INSERT INTO accounts (username, password_hash, created_at) VALUES (?, ?, ?) RETURNING id",
            "INSERT INTO accounts (username, password_hash, created_at) VALUES ($1, $2, $3) RETURNING id"
        ))
    .bind(username)
    .bind(password_hash)
    .bind(now_unix())
    .fetch_one(&db.pool)
    .await?;
    Ok(Account {
        id,
        username: username.to_string(),
        created_at: now_unix(),
    })
}

/// Returns whether an anyhow-wrapped SQLx error is a backend unique-key
/// violation. Routes use this to turn concurrent registration conflicts into
/// the documented 409 response instead of a generic 500.
pub fn is_unique_violation(err: &anyhow::Error) -> bool {
    err.downcast_ref::<sqlx::Error>()
        .and_then(sqlx::Error::as_database_error)
        .is_some_and(|db_err| db_err.is_unique_violation())
}

/// Returns `(account_id, password_hash)` for a username, if it exists.
pub async fn find_account_by_username(db: &Db, username: &str) -> Result<Option<(i64, String)>> {
    let row = sqlx::query(db.sql(
        "SELECT id, password_hash FROM accounts WHERE username = ?",
        "SELECT id, password_hash FROM accounts WHERE username = $1",
    ))
    .bind(username)
    .fetch_optional(&db.pool)
    .await?;
    row.map(|r| -> Result<(i64, String)> {
        Ok((r.try_get::<i64, _>(0)?, r.try_get::<String, _>(1)?))
    })
    .transpose()
}

pub async fn account_by_id(db: &Db, account_id: i64) -> Result<Option<Account>> {
    let row = sqlx::query(db.sql(
        "SELECT id, username, created_at FROM accounts WHERE id = ?",
        "SELECT id, username, created_at FROM accounts WHERE id = $1",
    ))
    .bind(account_id)
    .fetch_optional(&db.pool)
    .await?;
    row.map(|r| -> Result<Account> {
        Ok(Account {
            id: r.try_get(0)?,
            username: r.try_get(1)?,
            created_at: r.try_get(2)?,
        })
    })
    .transpose()
}

/// Updates an account password and revokes every existing session in one
/// transaction. Returns false when the account no longer exists.
pub async fn update_account_password(
    db: &Db,
    account_id: i64,
    password_hash: &str,
) -> Result<bool> {
    let mut tx = db.pool.begin().await?;
    let updated = sqlx::query(db.sql(
        "UPDATE accounts SET password_hash = ? WHERE id = ?",
        "UPDATE accounts SET password_hash = $1 WHERE id = $2",
    ))
    .bind(password_hash)
    .bind(account_id)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(false);
    }
    sqlx::query(db.sql(
        "DELETE FROM sessions WHERE account_id = ?",
        "DELETE FROM sessions WHERE account_id = $1",
    ))
    .bind(account_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// Admin-only listing of every account with its device/session counts.
pub async fn list_accounts(db: &Db) -> Result<Vec<AccountSummary>> {
    let rows = sqlx::query(db.sql(
        "SELECT a.id, a.username, a.created_at,
                (SELECT COUNT(*) FROM devices d WHERE d.account_id = a.id),
                (SELECT COUNT(*) FROM sessions s WHERE s.account_id = a.id)
         FROM accounts a ORDER BY a.username",
        "SELECT a.id, a.username, a.created_at,
                (SELECT COUNT(*) FROM devices d WHERE d.account_id = a.id),
                (SELECT COUNT(*) FROM sessions s WHERE s.account_id = a.id)
         FROM accounts a ORDER BY a.username",
    ))
    .fetch_all(&db.pool)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(AccountSummary {
                id: r.try_get(0)?,
                username: r.try_get(1)?,
                created_at: r.try_get(2)?,
                device_count: r.try_get(3)?,
                session_count: r.try_get(4)?,
            })
        })
        .collect()
}

/// Deletes an account; `false` when no such account exists.
pub async fn delete_account(db: &Db, account_id: i64) -> Result<bool> {
    let res = sqlx::query(db.sql(
        "DELETE FROM accounts WHERE id = ?",
        "DELETE FROM accounts WHERE id = $1",
    ))
    .bind(account_id)
    .execute(&db.pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Creates a session for `account_id` and returns its bearer token.
/// Stored plaintext by design - see `register_device`'s "Token storage
/// decision" comment: sessions are 48-char CSPRNG, revocable via
/// `delete_session`, and hashing would turn the `WHERE token = ?` lookup
/// into an all-rows scan.
pub async fn create_session(db: &Db, account_id: i64) -> Result<String> {
    let token = new_token();
    let created_at = now_unix();
    sqlx::query(db.sql(
        "INSERT INTO sessions (token, account_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
        "INSERT INTO sessions (token, account_id, created_at, expires_at) VALUES ($1, $2, $3, $4)",
    ))
    .bind(&token)
    .bind(account_id)
    .bind(created_at)
    .bind(created_at + SESSION_TTL_SECONDS)
    .execute(&db.pool)
    .await?;
    Ok(token)
}

/// Maps a session token to its `account_id`, if valid.
pub async fn find_session(db: &Db, token: &str) -> Result<Option<i64>> {
    let row = sqlx::query(db.sql(
        "SELECT account_id FROM sessions WHERE token = ? AND expires_at > ?",
        "SELECT account_id FROM sessions WHERE token = $1 AND expires_at > $2",
    ))
    .bind(token)
    .bind(now_unix())
    .fetch_optional(&db.pool)
    .await?;
    Ok(row.map(|r| r.try_get(0)).transpose()?)
}

/// Removes expired sessions and returns the number of rows deleted.
pub async fn delete_expired_sessions(db: &Db) -> Result<u64> {
    let result = sqlx::query(db.sql(
        "DELETE FROM sessions WHERE expires_at IS NULL OR expires_at <= ?",
        "DELETE FROM sessions WHERE expires_at IS NULL OR expires_at <= $1",
    ))
    .bind(now_unix())
    .execute(&db.pool)
    .await?;
    Ok(result.rows_affected())
}

pub async fn delete_session(db: &Db, token: &str) -> Result<()> {
    sqlx::query(db.sql(
        "DELETE FROM sessions WHERE token = ?",
        "DELETE FROM sessions WHERE token = $1",
    ))
    .bind(token)
    .execute(&db.pool)
    .await?;
    Ok(())
}

// --- External channels & inbox ---------------------------------------------

fn new_uuid() -> String {
    Uuid::new_v4().to_string()
}

/// Generates a webhook bearer token: a 32+ byte CSPRNG string with an
/// `ipwh_` prefix used to distinguish it from admin/device/session tokens.
pub fn new_channel_token() -> String {
    format!("ipwh_{}", new_token())
}

/// Short prefix shown to clients so a webhook token can be recognized
/// without ever re-displaying (or storing) the full secret.
fn token_prefix(token: &str) -> String {
    token.chars().take(12).collect()
}

/// Creates a channel for `device_id` and returns `(Channel, plaintext_token)`.
/// `token` is `Some` only for webhook channels and is returned exactly once.
/// `config` (CalDAV etc.) is stored encrypted by the caller if provided.
/// The channel insert and the device version bump share one transaction.
pub async fn create_channel(
    db: &Db,
    device_id: &str,
    kind: &str,
    name: &str,
    config_encrypted: Option<&str>,
) -> Result<(Channel, Option<String>)> {
    let now = now_unix();
    let id = new_uuid();
    let (token_hash, token_prefix, token) = if kind == "webhook" {
        let token = new_channel_token();
        let hash = crate::auth::hash_password(&token)
            .map_err(|e| anyhow!("failed to hash channel token: {e}"))?;
        let prefix = token_prefix(&token);
        (Some(hash), Some(prefix), Some(token))
    } else {
        (None, None, None)
    };
    let mut tx = db.pool.begin().await?;
    sqlx::query(db.sql(
            "INSERT INTO channels (id, device_id, kind, name, enabled, token_hash, token_prefix, config_encrypted, config_version, created_at, updated_at)
         VALUES (?, ?, ?, ?, 1, ?, ?, ?, 1, ?, ?)",
            "INSERT INTO channels (id, device_id, kind, name, enabled, token_hash, token_prefix, config_encrypted, config_version, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 1, $5, $6, $7, 1, $8, $9)"
        ))
    .bind(&id)
    .bind(device_id)
    .bind(kind)
    .bind(name)
    .bind(&token_hash)
    .bind(&token_prefix)
    .bind(config_encrypted)
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    bump_version(db, &mut *tx, device_id).await?;
    tx.commit().await?;
    let channel = Channel {
        id,
        device_id: device_id.to_string(),
        kind: kind.to_string(),
        name: name.to_string(),
        enabled: true,
        token_prefix: token_prefix.unwrap_or_default(),
        last_sync_at: None,
        last_sync_error: None,
        created_at: now,
        updated_at: now,
    };
    Ok((channel, token))
}

fn channel_from_row(row: sqlx::any::AnyRow) -> Result<Channel> {
    Ok(Channel {
        id: row.try_get(0)?,
        device_id: row.try_get(1)?,
        kind: row.try_get(2)?,
        name: row.try_get(3)?,
        enabled: row.try_get::<i64, _>(4)? != 0,
        token_prefix: row.try_get::<Option<String>, _>(5)?.unwrap_or_default(),
        last_sync_at: row.try_get(6)?,
        last_sync_error: row.try_get(7)?,
        created_at: row.try_get(8)?,
        updated_at: row.try_get(9)?,
    })
}

pub async fn list_channels(db: &Db, device_id: &str) -> Result<Vec<Channel>> {
    let rows = sqlx::query(db.sql(
            "SELECT id, device_id, kind, name, enabled, token_prefix, last_sync_at, last_sync_error, created_at, updated_at
         FROM channels WHERE device_id = ? ORDER BY created_at",
            "SELECT id, device_id, kind, name, enabled, token_prefix, last_sync_at, last_sync_error, created_at, updated_at
         FROM channels WHERE device_id = $1 ORDER BY created_at"
        ))
    .bind(device_id)
    .fetch_all(&db.pool)
    .await?;
    rows.into_iter().map(channel_from_row).collect()
}

pub async fn get_channel(db: &Db, device_id: &str, channel_id: &str) -> Result<Option<Channel>> {
    let row = sqlx::query(db.sql(
            "SELECT id, device_id, kind, name, enabled, token_prefix, last_sync_at, last_sync_error, created_at, updated_at
         FROM channels WHERE device_id = ? AND id = ?",
            "SELECT id, device_id, kind, name, enabled, token_prefix, last_sync_at, last_sync_error, created_at, updated_at
         FROM channels WHERE device_id = $1 AND id = $2"
        ))
    .bind(device_id)
    .bind(channel_id)
    .fetch_optional(&db.pool)
    .await?;
    row.map(channel_from_row).transpose()
}

/// Finds a webhook channel by id without device scoping (delivery path) and
/// returns it along with its stored token hash. Enforced `enabled` is checked
/// by the caller after token verification so a wrong token and a disabled
/// channel are indistinguishable.
pub async fn get_channel_for_delivery(
    db: &Db,
    channel_id: &str,
) -> Result<Option<(String, String)>> {
    let row = sqlx::query(db.sql(
        "SELECT device_id, token_hash FROM channels WHERE id = ?",
        "SELECT device_id, token_hash FROM channels WHERE id = $1",
    ))
    .bind(channel_id)
    .fetch_optional(&db.pool)
    .await?;
    row.map(|r| -> Result<(String, String)> {
        let hash: String = r
            .try_get::<Option<String>, _>(1)?
            .ok_or_else(|| anyhow!("channel is not a webhook channel"))?;
        Ok((r.try_get(0)?, hash))
    })
    .transpose()
}

pub async fn update_channel(
    db: &Db,
    device_id: &str,
    channel_id: &str,
    name: Option<&str>,
    enabled: Option<bool>,
) -> Result<bool> {
    let mut tx = db.pool.begin().await?;
    let res = sqlx::query(db.sql(
            "UPDATE channels SET name = COALESCE(?, name), enabled = COALESCE(?, enabled), updated_at = ?
         WHERE device_id = ? AND id = ?",
            "UPDATE channels SET name = COALESCE($1, name), enabled = COALESCE($2, enabled), updated_at = $3
         WHERE device_id = $4 AND id = $5"
        ))
    .bind(name)
    .bind(enabled.map(|b| b as i64))
    .bind(now_unix())
    .bind(device_id)
    .bind(channel_id)
    .execute(&mut *tx)
    .await?;
    let changed = res.rows_affected() > 0;
    if changed {
        bump_version(db, &mut *tx, device_id).await?;
    }
    tx.commit().await?;
    Ok(changed)
}

pub async fn delete_channel(db: &Db, device_id: &str, channel_id: &str) -> Result<bool> {
    let mut tx = db.pool.begin().await?;
    let res = sqlx::query(db.sql(
        "DELETE FROM channels WHERE device_id = ? AND id = ?",
        "DELETE FROM channels WHERE device_id = $1 AND id = $2",
    ))
    .bind(device_id)
    .bind(channel_id)
    .execute(&mut *tx)
    .await?;
    let changed = res.rows_affected() > 0;
    if changed {
        bump_version(db, &mut *tx, device_id).await?;
    }
    tx.commit().await?;
    Ok(changed)
}

/// Rotates a webhook channel's token, returning the new plaintext and its
/// display prefix. Rejects non-webhook channels. The old token stops
/// working immediately because it hashed to a different value than the
/// stored one.
pub async fn rotate_channel_token(
    db: &Db,
    device_id: &str,
    channel_id: &str,
) -> Result<Option<(String, String)>> {
    let mut tx = db.pool.begin().await?;
    let channel_lock = sqlx::query(db.sql(
        "UPDATE channels SET updated_at = updated_at WHERE device_id = ? AND id = ?",
        "UPDATE channels SET updated_at = updated_at WHERE device_id = $1 AND id = $2",
    ))
    .bind(device_id)
    .bind(channel_id)
    .execute(&mut *tx)
    .await?;
    if channel_lock.rows_affected() == 0 {
        tx.commit().await?;
        return Ok(None);
    }
    let row = sqlx::query(db.sql(
        "SELECT kind FROM channels WHERE device_id = ? AND id = ?",
        "SELECT kind FROM channels WHERE device_id = $1 AND id = $2",
    ))
    .bind(device_id)
    .bind(channel_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        tx.commit().await?;
        return Ok(None);
    };
    let kind: String = row.try_get(0)?;
    if kind != "webhook" {
        tx.commit().await?;
        return Ok(None);
    }
    let token = new_channel_token();
    let hash = crate::auth::hash_password(&token)
        .map_err(|e| anyhow!("failed to hash channel token: {e}"))?;
    let prefix = token_prefix(&token);
    sqlx::query(db.sql(
            "UPDATE channels SET token_hash = ?, token_prefix = ?, updated_at = ? WHERE device_id = ? AND id = ?",
            "UPDATE channels SET token_hash = $1, token_prefix = $2, updated_at = $3 WHERE device_id = $4 AND id = $5"
        ))
    .bind(&hash)
    .bind(&prefix)
    .bind(now_unix())
    .bind(device_id)
    .bind(channel_id)
    .execute(&mut *tx)
    .await?;
    bump_version(db, &mut *tx, device_id).await?;
    tx.commit().await?;
    Ok(Some((token, prefix)))
}

/// Atomically allocates the next inbox `seq` for a device and writes the
/// inbox row in the same transaction, so concurrent deliveries can never
/// issue a duplicate `seq` for one device. Returns the allocated `seq`.
#[allow(clippy::too_many_arguments)]
async fn insert_inbox_with_seq(
    db: &Db,
    tx: &mut sqlx::Transaction<'_, Any>,
    id: &str,
    device_id: &str,
    channel_id: &str,
    kind: &str,
    priority: &str,
    title: &str,
    body: &str,
    when: Option<i64>,
    source_ref: Option<&str>,
) -> Result<i64> {
    // Ensure a sequence row exists, then claim the next value. The row is
    // seeded at 0 and incremented before read, so the first allocated seq
    // is 1.
    sqlx::query(db.sql(
        "INSERT INTO device_sequences (device_id, next_inbox_seq) VALUES (?, 0)
         ON CONFLICT(device_id) DO NOTHING",
        "INSERT INTO device_sequences (device_id, next_inbox_seq) VALUES ($1, 0)
         ON CONFLICT(device_id) DO NOTHING",
    ))
    .bind(device_id)
    .execute(&mut **tx)
    .await?;
    // Postgres can hand back the new value in one statement via RETURNING;
    // SQLite (sqlx 0.8) cannot, so the increment and read are two steps.
    let seq: i64 = if db.postgres {
        sqlx::query_scalar(
            "UPDATE device_sequences SET next_inbox_seq = next_inbox_seq + 1
             WHERE device_id = $1 RETURNING next_inbox_seq",
        )
        .bind(device_id)
        .fetch_one(&mut **tx)
        .await?
    } else {
        let row = sqlx::query(
            "UPDATE device_sequences SET next_inbox_seq = next_inbox_seq + 1
             WHERE device_id = ?",
        )
        .bind(device_id)
        .execute(&mut **tx)
        .await?;
        if row.rows_affected() == 0 {
            return Err(anyhow!("failed to allocate inbox sequence"));
        }
        sqlx::query_scalar("SELECT next_inbox_seq FROM device_sequences WHERE device_id = ?")
            .bind(device_id)
            .fetch_one(&mut **tx)
            .await?
    };
    let now = now_unix();
    sqlx::query(db.sql(
            "INSERT INTO inbox (id, device_id, channel_id, seq, kind, priority, title, body, when_epoch, source_ref, read, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
            "INSERT INTO inbox (id, device_id, channel_id, seq, kind, priority, title, body, when_epoch, source_ref, read, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 0, $11, $12)"
        ))
    .bind(id)
    .bind(device_id)
    .bind(channel_id)
    .bind(seq)
    .bind(kind)
    .bind(priority)
    .bind(title)
    .bind(body)
    .bind(when)
    .bind(source_ref)
    .bind(now)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    Ok(seq)
}

/// Inserts a webhook-delivered inbox item, honoring idempotency via
/// `source_ref`. Returns `(seq, created)` where `created` is false when the
/// `source_ref` already exists (idempotent replay).
#[allow(clippy::too_many_arguments)]
pub async fn deliver_inbox(
    db: &Db,
    device_id: &str,
    channel_id: &str,
    kind: &str,
    priority: &str,
    title: &str,
    body: &str,
    when: Option<i64>,
    source_ref: Option<&str>,
) -> Result<(u64, bool)> {
    let mut tx = db.pool.begin().await?;
    let channel_lock = sqlx::query(db.sql(
        "UPDATE channels SET updated_at = updated_at WHERE device_id = ? AND id = ? AND enabled = 1",
        "UPDATE channels SET updated_at = updated_at WHERE device_id = $1 AND id = $2 AND enabled = 1",
    ))
    .bind(device_id)
    .bind(channel_id)
    .execute(&mut *tx)
    .await?;
    if channel_lock.rows_affected() == 0 {
        return Err(anyhow!("channel not found"));
    }
    if let Some(ref_ref) = source_ref {
        let existing: Option<i64> = sqlx::query_scalar(db.sql(
            "SELECT seq FROM inbox WHERE channel_id = ? AND source_ref = ?",
            "SELECT seq FROM inbox WHERE channel_id = $1 AND source_ref = $2",
        ))
        .bind(channel_id)
        .bind(ref_ref)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(seq) = existing {
            tx.commit().await?;
            return Ok((seq as u64, false));
        }
    }
    let id = new_uuid();
    let seq = insert_inbox_with_seq(
        db, &mut tx, &id, device_id, channel_id, kind, priority, title, body, when, source_ref,
    )
    .await?;
    bump_version(db, &mut *tx, device_id).await?;
    tx.commit().await?;
    Ok((seq as u64, true))
}

/// Returns the device's inbox for the sync response: unread first, then by
/// `seq DESC`, capped at `limit`. `truncated` is true when more rows exist.
pub async fn list_inbox(db: &Db, device_id: &str, limit: usize) -> Result<(Vec<InboxItem>, bool)> {
    let total: i64 = sqlx::query_scalar(db.sql(
        "SELECT COUNT(*) FROM inbox WHERE device_id = ?",
        "SELECT COUNT(*) FROM inbox WHERE device_id = $1",
    ))
    .bind(device_id)
    .fetch_one(&db.pool)
    .await?;
    let rows = sqlx::query(db.sql(
        "SELECT seq, kind, priority, title, body, when_epoch, read FROM inbox
         WHERE device_id = ? ORDER BY read ASC, seq DESC LIMIT ?",
        "SELECT seq, kind, priority, title, body, when_epoch, read FROM inbox
         WHERE device_id = $1 ORDER BY read ASC, seq DESC LIMIT $2",
    ))
    .bind(device_id)
    .bind(limit as i64)
    .fetch_all(&db.pool)
    .await?;
    let items = rows
        .into_iter()
        .map(|r| {
            Ok(InboxItem {
                id: r.try_get::<i64, _>(0)? as u64,
                kind: InboxKind::from(r.try_get::<String, _>(1)?.as_str()),
                priority: Priority::from(r.try_get::<String, _>(2)?.as_str()),
                title: r.try_get(3)?,
                body: r.try_get::<Option<String>, _>(4)?.unwrap_or_default(),
                when: r.try_get(5)?,
                read: r.try_get::<i64, _>(6)? != 0,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let truncated = (total as usize) > items.len();
    Ok((items, truncated))
}

/// Marks inbox items read for a device. Only `seq`s belonging to `device_id`
/// are touched; unknown ids are silently ignored (cannot create content).
/// Returns the seqs actually acked (those that transitioned to read), in the
/// order sent. Bumps the device version only if something changed, inside
/// the same transaction.
pub async fn mark_inbox_read(db: &Db, device_id: &str, seqs: &[u64]) -> Result<Vec<u64>> {
    if seqs.is_empty() {
        return Ok(Vec::new());
    }
    let mut tx = db.pool.begin().await?;
    let mut acked = Vec::new();
    for seq in seqs {
        let res = sqlx::query(db.sql(
            "UPDATE inbox SET read = 1, updated_at = ? WHERE device_id = ? AND seq = ? AND read = 0",
            "UPDATE inbox SET read = 1, updated_at = $1 WHERE device_id = $2 AND seq = $3 AND read = 0"
        ))
        .bind(now_unix())
        .bind(device_id)
        .bind(*seq as i64)
        .execute(&mut *tx)
        .await?;
        if res.rows_affected() > 0 {
            acked.push(*seq);
        }
    }
    if !acked.is_empty() {
        bump_version(db, &mut *tx, device_id).await?;
    }
    tx.commit().await?;
    Ok(acked)
}

/// Management/debug helper: delete a single inbox item for a device.
pub async fn delete_inbox_item(db: &Db, device_id: &str, seq: u64) -> Result<bool> {
    let mut tx = db.pool.begin().await?;
    let res = sqlx::query(db.sql(
        "DELETE FROM inbox WHERE device_id = ? AND seq = ?",
        "DELETE FROM inbox WHERE device_id = $1 AND seq = $2",
    ))
    .bind(device_id)
    .bind(seq as i64)
    .execute(&mut *tx)
    .await?;
    let changed = res.rows_affected() > 0;
    if changed {
        bump_version(db, &mut *tx, device_id).await?;
    }
    tx.commit().await?;
    Ok(changed)
}

/// Management/debug helper: clear read inbox history for a device.
pub async fn clear_read_inbox(db: &Db, device_id: &str) -> Result<()> {
    let mut tx = db.pool.begin().await?;
    let res = sqlx::query(db.sql(
        "DELETE FROM inbox WHERE device_id = ? AND read = 1",
        "DELETE FROM inbox WHERE device_id = $1 AND read = 1",
    ))
    .bind(device_id)
    .execute(&mut *tx)
    .await?;
    if res.rows_affected() > 0 {
        bump_version(db, &mut *tx, device_id).await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Whether the device has any unread `high`-priority inbox items. Used by the
/// long-poll wait so the server can return immediately when an urgent message
/// arrives, without the device polling on a timer.
pub async fn has_unread_high_inbox(db: &Db, device_id: &str) -> Result<bool> {
    let count: i64 = sqlx::query_scalar(db.sql(
        "SELECT COUNT(*) FROM inbox WHERE device_id = ? AND read = 0 AND priority = 'high'",
        "SELECT COUNT(*) FROM inbox WHERE device_id = $1 AND read = 0 AND priority = 'high'",
    ))
    .bind(device_id)
    .fetch_one(&db.pool)
    .await?;
    Ok(count > 0)
}

// --- Column helpers (shared by both backends) -----------------------------

/// Parses the `importance` column; unknown/legacy values fall back to
/// `Medium`.
fn importance_from_str(s: &str) -> Importance {
    match s {
        "low" => Importance::Low,
        "high" => Importance::High,
        _ => Importance::Medium,
    }
}

fn repeat_days_json_opt(days: &[u8]) -> Option<String> {
    serde_json::to_string(days).ok().map(|s| s.replace(' ', ""))
}

fn repeat_to_columns(
    repeat: &Repeat,
) -> (
    &'static str,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<String>,
) {
    match repeat {
        Repeat::Daily => ("daily", None, None, None, None),
        Repeat::Weekly { days } | Repeat::Monthly { days } => {
            (repeat.kind(), None, None, None, repeat_days_json_opt(days))
        }
        Repeat::Once { year, month, day } => (
            "once",
            Some(*year as i64),
            Some(*month as i64),
            Some(*day as i64),
            None,
        ),
    }
}

fn repeat_from_columns(
    repeat_kind: &str,
    once_year: Option<i64>,
    once_month: Option<i64>,
    once_day: Option<i64>,
    repeat_days: Option<String>,
) -> Repeat {
    match repeat_kind {
        "once" => match (once_year, once_month, once_day) {
            (Some(year), Some(month), Some(day)) => Repeat::Once {
                year: year as u16,
                month: month as u8,
                day: day as u8,
            },
            _ => Repeat::Daily,
        },
        "weekly" => Repeat::Weekly {
            days: repeat_days_json(repeat_days.as_deref()),
        },
        "monthly" => Repeat::Monthly {
            days: repeat_days_json(repeat_days.as_deref()),
        },
        _ => Repeat::Daily,
    }
}

fn repeat_days_json(raw: Option<&str>) -> Vec<u8> {
    raw.and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default()
}
