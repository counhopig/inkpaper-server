//! DDL and migrations for the `Any`-driver pool. The schema lives in the
//! sqlx migration files under `migrations/sqlite/` and `migrations/postgres/`
//! (one dialect each - `AUTOINCREMENT` vs `BIGSERIAL` can't share one file),
//! embedded at compile time and applied by `open()` on every startup.
//!
//! `SQLITE_TABLES` is still duplicated here because the pre-UUID-era
//! `migrate_legacy_integer_ids` rebuild (SQLite-only) drops and recreates
//! tables inside a transaction, which can't re-run an already-applied
//! migration file. Keep it in sync with the current SQLite migrations.

use anyhow::{Context, Result};
use sqlx::any::AnyPoolOptions;
use sqlx::Row;
use uuid::Uuid;

use super::Db;

/// Per-dialect migration sets: the sqlx `Migrate` impl exists for the `Any`
/// driver, but the migration files themselves can't be dialect-neutral
/// (`AUTOINCREMENT` vs `BIGSERIAL`), so each backend gets its own directory
/// and the right one is embedded/run at `open()` time.
static SQLITE_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("migrations/sqlite");
static POSTGRES_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("migrations/postgres");

/// Opens (creating the schema if needed) the database at `url`, which may be
/// `sqlite://...` (or a bare SQLite file path) or `postgres://...`.
/// `max_connections` sizes the pool; in-memory SQLite databases must use 1
/// so every query hits the same connection (memory DBs are per-connection).
pub async fn open(url: &str, max_connections: u32) -> Result<Db> {
    sqlx::any::install_default_drivers();
    let is_postgres = url.starts_with("postgres://") || url.starts_with("postgresql://");

    // sqlx 0.8 defaults to *not* creating a missing SQLite file, whereas the
    // old rusqlite backend created the database on open. Default to
    // `mode=rwc` (read-write + create) unless the caller pinned a mode.
    let mut url = url.to_string();
    if !is_postgres && !url.contains("mode=") {
        url.push_str(if url.contains('?') {
            "&mode=rwc"
        } else {
            "?mode=rwc"
        });
    }

    let mut options = AnyPoolOptions::new().max_connections(max_connections);
    if !is_postgres {
        // SQLite foreign keys are off per-connection by default; make sure
        // every pooled connection enforces them so cascades behave.
        options = options.after_connect(|conn, _meta| {
            Box::pin(async move {
                sqlx::query("PRAGMA foreign_keys = ON")
                    .execute(&mut *conn)
                    .await?;
                // Wait briefly for another writer instead of surfacing an
                // avoidable SQLITE_BUSY error to the HTTP layer.
                sqlx::query("PRAGMA busy_timeout = 5000")
                    .execute(&mut *conn)
                    .await?;
                Ok(())
            })
        });
    }
    let pool = options
        .connect(&url)
        .await
        .with_context(|| format!("failed to connect to database at {url}"))?;
    let db = Db {
        pool,
        postgres: is_postgres,
    };

    if is_postgres {
        // `CREATE TABLE IF NOT EXISTS` means the 0001 migration is a no-op
        // on databases created before this file existed, and the columns it
        // declares have existed for as long as the Postgres backend has
        // (they were never added via the SQLite-only ALTER path), so no
        // column backfill is needed there.
        POSTGRES_MIGRATOR
            .run(&db.pool)
            .await
            .context("postgres migrations failed")?;
    } else {
        SQLITE_MIGRATOR
            .run(&db.pool)
            .await
            .context("sqlite migrations failed")?;
        migrate_legacy_integer_ids(&db).await?;
        backfill_missing_columns(&db).await?;
    }

    Ok(db)
}

/// Legacy pre-UUID `alarms` row shape used only by the SQLite migration.
type LegacyAlarmRow = (
    i64,
    i64,
    i64,
    i64,
    String,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    i64,
    String,
);

/// Migrates SQLite databases from the pre-UUID era where `devices.id` was an
/// `INTEGER PRIMARY KEY AUTOINCREMENT` and `alarms`/`todos` referenced it with
/// an INTEGER `device_id`. Personal-scale data (a handful of devices) is
/// copied over row by row; the device auth token is preserved, so devices
/// keep syncing without re-registering. Only called on the SQLite path from
/// `open()` (the `pragma_table_info` checks below are SQLite-only), so its
/// statements are plain SQLite SQL with no dialect selection.
async fn migrate_legacy_integer_ids(db: &Db) -> Result<()> {
    let legacy: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('devices') WHERE name = 'id' AND type = 'INTEGER'",
    )
    .fetch_one(&db.pool)
    .await?;
    if legacy == 0 {
        return Ok(());
    }
    tracing::info!("detected pre-UUID device ids; migrating to UUID keys");

    let mut tx = db.pool.begin().await?;
    let devices: Vec<(i64, String, String, i64, i64)> = {
        let rows = sqlx::query("SELECT id, name, token, version, created_at FROM devices")
            .fetch_all(&mut *tx)
            .await?;
        rows.into_iter()
            .map(|r| {
                Ok((
                    r.try_get::<i64, _>(0)?,
                    r.try_get::<String, _>(1)?,
                    r.try_get::<String, _>(2)?,
                    r.try_get::<i64, _>(3)?,
                    r.try_get::<i64, _>(4)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?
    };
    let alarms: Vec<LegacyAlarmRow> = {
        let rows = sqlx::query("SELECT device_id, local_id, hour, minute, repeat_kind, once_year, once_month, once_day, enabled, label FROM alarms")
        .fetch_all(&mut *tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok((
                    r.try_get::<i64, _>(0)?,
                    r.try_get::<i64, _>(1)?,
                    r.try_get::<i64, _>(2)?,
                    r.try_get::<i64, _>(3)?,
                    r.try_get::<String, _>(4)?,
                    r.try_get::<Option<i64>, _>(5)?,
                    r.try_get::<Option<i64>, _>(6)?,
                    r.try_get::<Option<i64>, _>(7)?,
                    r.try_get::<i64, _>(8)?,
                    r.try_get::<String, _>(9)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?
    };
    let todos: Vec<(i64, i64, String, i64)> = {
        let rows = sqlx::query("SELECT device_id, local_id, text, done FROM todos")
            .fetch_all(&mut *tx)
            .await?;
        rows.into_iter()
            .map(|r| Ok((r.try_get(0)?, r.try_get(1)?, r.try_get(2)?, r.try_get(3)?)))
            .collect::<Result<Vec<_>>>()?
    };

    sqlx::raw_sql(
        "DROP TABLE device_local_ids; DROP TABLE alarms; DROP TABLE todos; DROP TABLE devices;",
    )
    .execute(&mut *tx)
    .await?;
    // Recreate with the UUID schema (SQLite dialect - this path is SQLite-only).
    sqlx::raw_sql(SQLITE_TABLES).execute(&mut *tx).await?;

    let mut id_map = std::collections::HashMap::new();
    for (old_id, name, token, version, created_at) in &devices {
        let new_id = Uuid::new_v4().to_string();
        id_map.insert(*old_id, new_id.clone());
        sqlx::query(
            "INSERT INTO devices (id, name, token, version, created_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&new_id)
        .bind(name)
        .bind(token)
        .bind(version)
        .bind(created_at)
        .execute(&mut *tx)
        .await?;
    }
    for (
        device_id,
        local_id,
        hour,
        minute,
        repeat_kind,
        once_year,
        once_month,
        once_day,
        enabled,
        label,
    ) in &alarms
    {
        let Some(new_device_id) = id_map.get(device_id) else {
            continue;
        };
        sqlx::query("INSERT INTO alarms (device_id, local_id, hour, minute, repeat_kind, once_year, once_month, once_day, enabled, label)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(new_device_id)
        .bind(local_id)
        .bind(hour)
        .bind(minute)
        .bind(repeat_kind)
        .bind(once_year)
        .bind(once_month)
        .bind(once_day)
        .bind(enabled)
        .bind(label)
        .execute(&mut *tx)
        .await?;
    }
    for (device_id, local_id, text, done) in &todos {
        let Some(new_device_id) = id_map.get(device_id) else {
            continue;
        };
        sqlx::query("INSERT INTO todos (device_id, local_id, text, done) VALUES (?, ?, ?, ?)")
            .bind(new_device_id)
            .bind(local_id)
            .bind(text)
            .bind(done)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::raw_sql(
        "INSERT OR IGNORE INTO device_local_ids (device_id, kind, local_id)
         SELECT device_id, 'alarm', local_id FROM alarms;
         INSERT OR IGNORE INTO device_local_ids (device_id, kind, local_id)
         SELECT device_id, 'todo', local_id FROM todos;",
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    tracing::info!("migrated {} devices to UUID ids", devices.len());
    Ok(())
}

/// The 9 `ALTER TABLE ... ADD COLUMN` statements that databases created
/// before this column existed are missing. They were previously run with
/// `let _ = ...` swallowing every error (a poor-man's "IF NOT EXISTS");
/// now each column is checked explicitly first, and a real failure to add
/// one propagates loudly instead of being silently ignored. On fresh
/// databases 0001_init.sql already declares every column, so this is a
/// no-op there - it only ever fires on pre-migration-era SQLite files.
/// Like `migrate_legacy_integer_ids`, this only runs on the SQLite path, so
/// its statements are plain SQLite SQL (`pragma_table_info`) with no dialect
/// selection.
async fn backfill_missing_columns(db: &Db) -> Result<()> {
    // (table, column, ADD COLUMN clause); column names are hardcoded, never
    // request input.
    let candidates: &[(&str, &str, &str)] = &[
        ("todos", "importance", "TEXT NOT NULL DEFAULT 'medium'"),
        ("todos", "due_month", "INTEGER"),
        ("todos", "due_day", "INTEGER"),
        ("todos", "due_year", "INTEGER"),
        ("todos", "repeat_kind", "TEXT"),
        ("todos", "repeat_days", "TEXT"),
        ("alarms", "repeat_days", "TEXT"),
        ("devices", "account_id", "INTEGER"),
        ("inbox", "priority", "TEXT NOT NULL DEFAULT 'normal'"),
    ];
    for (table, column, ddl) in candidates {
        let exists: i64 = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = '{column}'"
        ))
        .fetch_one(&db.pool)
        .await?;
        if exists > 0 {
            continue;
        }
        tracing::info!("backfilling missing column {table}.{column}");
        sqlx::raw_sql(&format!("ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
            .execute(&db.pool)
            .await
            .with_context(|| format!("failed to add missing column {table}.{column}"))?;
    }
    Ok(())
}

/// Recreates the SQLite schema for `migrate_legacy_integer_ids`'s
/// drop-and-rebuild path. Keep in sync with the current migration schema -
/// these statements are duplicated only because a rebuild inside a
/// transaction can't re-run an applied migration.
const SQLITE_TABLES: &str = "
    CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        created_at INTEGER NOT NULL,
        expires_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        token TEXT NOT NULL UNIQUE,
        version INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        account_id INTEGER REFERENCES accounts(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS alarms (
        device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
        local_id INTEGER NOT NULL,
        hour INTEGER NOT NULL,
        minute INTEGER NOT NULL,
        repeat_kind TEXT NOT NULL,
        once_year INTEGER,
        once_month INTEGER,
        once_day INTEGER,
        repeat_days TEXT,
        enabled INTEGER NOT NULL,
        label TEXT NOT NULL,
        PRIMARY KEY (device_id, local_id)
    );
    CREATE TABLE IF NOT EXISTS todos (
        device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
        local_id INTEGER NOT NULL,
        text TEXT NOT NULL,
        done INTEGER NOT NULL,
        importance TEXT NOT NULL DEFAULT 'medium',
        due_year INTEGER,
        due_month INTEGER,
        due_day INTEGER,
        repeat_kind TEXT,
        repeat_days TEXT,
        PRIMARY KEY (device_id, local_id)
    );
    CREATE TABLE IF NOT EXISTS device_local_ids (
        device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
        kind TEXT NOT NULL CHECK (kind IN ('alarm', 'todo')),
        local_id INTEGER NOT NULL,
        released INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (device_id, kind, local_id)
    );
    CREATE TABLE IF NOT EXISTS channels (
        id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
        kind TEXT NOT NULL,
        name TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        token_hash TEXT,
        token_prefix TEXT,
        config_encrypted TEXT,
        config_version INTEGER NOT NULL DEFAULT 1,
        last_sync_at INTEGER,
        last_sync_error TEXT,
        sync_state TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_channels_device ON channels(device_id);
    CREATE INDEX IF NOT EXISTS idx_channels_kind_enabled ON channels(kind, enabled);
    CREATE TABLE IF NOT EXISTS inbox (
        id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
        channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
        event_id TEXT,
        seq INTEGER NOT NULL,
        kind TEXT NOT NULL,
        priority TEXT NOT NULL DEFAULT 'normal',
        title TEXT NOT NULL,
        body TEXT,
        when_epoch INTEGER,
        source_ref TEXT,
        read INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        UNIQUE(device_id, seq),
        UNIQUE(channel_id, source_ref)
    );
    CREATE INDEX IF NOT EXISTS idx_inbox_device_seq ON inbox(device_id, seq DESC);
    CREATE INDEX IF NOT EXISTS idx_inbox_device_read ON inbox(device_id, read, seq DESC);
    CREATE TABLE IF NOT EXISTS device_sequences (
        device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
        next_inbox_seq INTEGER NOT NULL
    );";
