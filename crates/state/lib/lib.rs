//! Durable wrapper session leases and cross-process VM reservations backed by SQLite.

#![forbid(unsafe_code)]

use std::{
    env, fs,
    path::{Path, PathBuf},
    time::Duration,
};

use chrono::{DateTime, TimeZone, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// State-store result type.
pub type Result<T> = std::result::Result<T, StateError>;

/// State persistence error.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// No platform data directory can be determined.
    #[error("cannot determine agent-sandbox state directory; set ASBX_HOME")]
    MissingHome,

    /// State directory creation failed.
    #[error("cannot create state directory {path}: {source}")]
    CreateDirectory {
        /// Directory path.
        path: PathBuf,
        /// Filesystem error.
        source: std::io::Error,
    },

    /// SQLite operation failed.
    #[error("state database operation failed: {0}")]
    Database(#[from] rusqlite::Error),

    /// Stored JSON is invalid.
    #[error("invalid stored session data: {0}")]
    Json(#[from] serde_json::Error),

    /// Requested session does not exist.
    #[error("unknown sandbox session {0}")]
    NotFound(String),

    /// Concurrent-session limit was reached.
    #[error("sandbox concurrency limit reached ({0})")]
    ConcurrencyLimit(usize),

    /// A sandbox would exceed the wrapper-wide reserved-memory cap.
    #[error(
        "sandbox memory reservation would exceed the global cap: \
         {reserved_mib} MiB reserved + {requested_mib} MiB requested > {maximum_mib} MiB"
    )]
    ReservedMemoryLimit {
        /// Currently reserved memory.
        reserved_mib: u64,
        /// New memory request.
        requested_mib: u32,
        /// Configured global maximum.
        maximum_mib: u32,
    },
}

/// A wrapper-managed sandbox lease.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    /// Sandbox identifier.
    pub id: String,
    /// Canonical host project path.
    pub project: PathBuf,
    /// Resolved root source description.
    pub root: String,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Wrapper lease expiration.
    pub expires_at: DateTime<Utc>,
    /// Host maximum lease expiration.
    pub maximum_expires_at: DateTime<Utc>,
    /// Published loopback ports.
    pub ports: Vec<(u16, u16)>,
}

/// A cross-process resource reservation for any wrapper-managed VM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationRecord {
    /// Sandbox identifier.
    pub id: String,
    /// Reserved guest memory in MiB.
    pub memory_mib: u32,
    /// Reservation backstop expiration.
    pub expires_at: DateTime<Utc>,
    /// Whether runtime creation completed.
    pub active: bool,
}

/// SQLite state store.
#[derive(Debug, Clone)]
pub struct StateStore {
    path: PathBuf,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl StateStore {
    /// Open the default state database under `ASBX_HOME` or the platform home.
    pub fn open_default() -> Result<Self> {
        let home = env::var_os("ASBX_HOME")
            .map(PathBuf::from)
            .or_else(|| dirs::home_dir().map(|home| home.join(".agent-sandbox")));
        let home = home.ok_or(StateError::MissingHome)?;
        Self::open(home.join("state.db"))
    }

    /// Open a state database at an explicit path and apply its schema.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| StateError::CreateDirectory {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let store = Self { path };
        let connection = store.connection()?;
        connection.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY NOT NULL,
                project TEXT NOT NULL,
                root TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                maximum_expires_at INTEGER NOT NULL,
                ports_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
                ON sessions(expires_at);
            CREATE TABLE IF NOT EXISTS reservations (
                id TEXT PRIMARY KEY NOT NULL,
                memory_mib INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                active INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_reservations_expires_at
                ON reservations(expires_at);
            ",
        )?;
        let has_active = {
            let mut statement = connection.prepare("PRAGMA table_info(reservations)")?;
            statement
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<std::result::Result<Vec<_>, _>>()?
                .iter()
                .any(|column| column == "active")
        };
        if !has_active {
            connection.execute(
                "ALTER TABLE reservations ADD COLUMN active INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        Ok(store)
    }

    /// Atomically reserve global VM count and memory before runtime creation.
    pub fn reserve(
        &self,
        record: &ReservationRecord,
        maximum_sandboxes: usize,
        maximum_memory_mib: u32,
    ) -> Result<()> {
        let mut connection = self.connection()?;
        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let active: i64 =
            transaction.query_row("SELECT COUNT(*) FROM reservations", [], |row| row.get(0))?;
        if usize::try_from(active).unwrap_or(usize::MAX) >= maximum_sandboxes {
            return Err(StateError::ConcurrencyLimit(maximum_sandboxes));
        }
        let reserved_mib: i64 = transaction.query_row(
            "SELECT COALESCE(SUM(memory_mib), 0) FROM reservations",
            [],
            |row| row.get(0),
        )?;
        let reserved_mib = u64::try_from(reserved_mib).unwrap_or(u64::MAX);
        if reserved_mib.saturating_add(u64::from(record.memory_mib)) > u64::from(maximum_memory_mib)
        {
            return Err(StateError::ReservedMemoryLimit {
                reserved_mib,
                requested_mib: record.memory_mib,
                maximum_mib: maximum_memory_mib,
            });
        }
        transaction.execute(
            "INSERT INTO reservations (id, memory_mib, expires_at, active)
             VALUES (?1, ?2, ?3, 0)",
            params![
                record.id,
                i64::from(record.memory_mib),
                record.expires_at.timestamp()
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Mark a reservation active after its VM has been created.
    pub fn activate(&self, id: &str) -> Result<()> {
        let changed = self
            .connection()?
            .execute("UPDATE reservations SET active = 1 WHERE id = ?1", [id])?;
        if changed == 0 {
            return Err(StateError::NotFound(id.into()));
        }
        Ok(())
    }

    /// Release a VM resource reservation.
    pub fn release(&self, id: &str) -> Result<()> {
        self.connection()?
            .execute("DELETE FROM reservations WHERE id = ?1", [id])?;
        Ok(())
    }

    /// Return expired VM reservations.
    pub fn expired_reservations(&self, now: DateTime<Utc>) -> Result<Vec<ReservationRecord>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, memory_mib, expires_at, active
             FROM reservations WHERE expires_at <= ?1 ORDER BY expires_at ASC",
        )?;
        let records = statement
            .query_map([now.timestamp()], decode_reservation)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(records)
    }

    /// Return active VM reservations for runtime reconciliation.
    pub fn active_reservations(&self) -> Result<Vec<ReservationRecord>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, memory_mib, expires_at, active
             FROM reservations WHERE active = 1 ORDER BY id ASC",
        )?;
        let records = statement
            .query_map([], decode_reservation)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(records)
    }

    /// Persist metadata for a detached session after its VM is ready.
    pub fn insert(&self, record: &SessionRecord) -> Result<()> {
        self.connection()?.execute(
            "INSERT INTO sessions (
                id, project, root, created_at, expires_at, maximum_expires_at, ports_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                record.id,
                record.project.to_string_lossy(),
                record.root,
                record.created_at.timestamp(),
                record.expires_at.timestamp(),
                record.maximum_expires_at.timestamp(),
                serde_json::to_string(&record.ports)?,
            ],
        )?;
        Ok(())
    }

    /// Return a session by identifier.
    pub fn get(&self, id: &str) -> Result<SessionRecord> {
        self.connection()?
            .query_row(
                "SELECT id, project, root, created_at, expires_at, maximum_expires_at, ports_json
                 FROM sessions WHERE id = ?1",
                [id],
                decode_record,
            )
            .optional()?
            .ok_or_else(|| StateError::NotFound(id.into()))
    }

    /// List all sessions by creation time.
    pub fn list(&self) -> Result<Vec<SessionRecord>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, project, root, created_at, expires_at, maximum_expires_at, ports_json
             FROM sessions ORDER BY created_at ASC",
        )?;
        let records = statement
            .query_map([], decode_record)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(records)
    }

    /// List expired leases.
    pub fn expired(&self, now: DateTime<Utc>) -> Result<Vec<SessionRecord>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, project, root, created_at, expires_at, maximum_expires_at, ports_json
             FROM sessions WHERE expires_at <= ?1 ORDER BY expires_at ASC",
        )?;
        let records = statement
            .query_map([now.timestamp()], decode_record)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(records)
    }

    /// Extend a lease, never beyond its host maximum.
    pub fn touch(&self, id: &str, ttl: Duration, now: DateTime<Utc>) -> Result<SessionRecord> {
        let mut record = self.get(id)?;
        let requested = now
            + chrono::Duration::from_std(ttl)
                .unwrap_or_else(|_| chrono::Duration::seconds(i64::MAX));
        record.expires_at = requested.min(record.maximum_expires_at);
        let mut connection = self.connection()?;
        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        transaction.execute(
            "UPDATE sessions SET expires_at = ?1 WHERE id = ?2",
            params![record.expires_at.timestamp(), id],
        )?;
        transaction.execute(
            "UPDATE reservations SET expires_at = ?1 WHERE id = ?2",
            params![record.expires_at.timestamp(), id],
        )?;
        transaction.commit()?;
        Ok(record)
    }

    /// Remove a session lease.
    pub fn remove(&self, id: &str) -> Result<()> {
        self.connection()?
            .execute("DELETE FROM sessions WHERE id = ?1", [id])?;
        Ok(())
    }

    /// Path to the SQLite database.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn connection(&self) -> Result<Connection> {
        let connection = Connection::open(&self.path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        Ok(connection)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn decode_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<SessionRecord> {
    let created_at: i64 = row.get(3)?;
    let expires_at: i64 = row.get(4)?;
    let maximum_expires_at: i64 = row.get(5)?;
    let ports_json: String = row.get(6)?;
    let parse_time = |value| {
        Utc.timestamp_opt(value, 0)
            .single()
            .ok_or_else(|| rusqlite::Error::IntegralValueOutOfRange(0, value))
    };
    let ports = serde_json::from_str(&ports_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(6, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(SessionRecord {
        id: row.get(0)?,
        project: PathBuf::from(row.get::<_, String>(1)?),
        root: row.get(2)?,
        created_at: parse_time(created_at)?,
        expires_at: parse_time(expires_at)?,
        maximum_expires_at: parse_time(maximum_expires_at)?,
        ports,
    })
}

fn decode_reservation(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReservationRecord> {
    let memory_mib: i64 = row.get(1)?;
    let expires_at: i64 = row.get(2)?;
    Ok(ReservationRecord {
        id: row.get(0)?,
        memory_mib: u32::try_from(memory_mib)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(1, memory_mib))?,
        expires_at: Utc
            .timestamp_opt(expires_at, 0)
            .single()
            .ok_or(rusqlite::Error::IntegralValueOutOfRange(2, expires_at))?,
        active: row.get(3)?,
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    fn record() -> SessionRecord {
        let now = Utc::now();
        SessionRecord {
            id: "sbx_test".into(),
            project: PathBuf::from("/workspace/project"),
            root: "alpine".into(),
            created_at: now,
            expires_at: now + chrono::Duration::minutes(30),
            maximum_expires_at: now + chrono::Duration::hours(8),
            ports: vec![(3000, 54321)],
        }
    }

    #[test]
    fn round_trips_and_touches_sessions() {
        let directory = tempdir().unwrap();
        let store = StateStore::open(directory.path().join("state.db")).unwrap();
        let now = Utc::now();
        store
            .reserve(
                &ReservationRecord {
                    id: "sbx_test".into(),
                    memory_mib: 512,
                    expires_at: now + chrono::Duration::minutes(30),
                    active: false,
                },
                1,
                1024,
            )
            .unwrap();
        store.insert(&record()).unwrap();
        assert!(matches!(
            store.reserve(
                &ReservationRecord {
                    id: "other".into(),
                    memory_mib: 256,
                    expires_at: now + chrono::Duration::minutes(30),
                    active: false,
                },
                1,
                1024,
            ),
            Err(StateError::ConcurrencyLimit(1))
        ));
        let touched = store
            .touch("sbx_test", Duration::from_secs(3600), Utc::now())
            .unwrap();
        assert!(touched.expires_at > touched.created_at);
        store.remove("sbx_test").unwrap();
        assert!(matches!(
            store.get("sbx_test"),
            Err(StateError::NotFound(_))
        ));
    }

    #[test]
    fn enforces_global_reserved_memory() {
        let directory = tempdir().unwrap();
        let store = StateStore::open(directory.path().join("state.db")).unwrap();
        let expires_at = Utc::now() + chrono::Duration::minutes(30);
        store
            .reserve(
                &ReservationRecord {
                    id: "first".into(),
                    memory_mib: 768,
                    expires_at,
                    active: false,
                },
                4,
                1024,
            )
            .unwrap();
        assert!(matches!(
            store.reserve(
                &ReservationRecord {
                    id: "second".into(),
                    memory_mib: 512,
                    expires_at,
                    active: false,
                },
                4,
                1024,
            ),
            Err(StateError::ReservedMemoryLimit {
                reserved_mib: 768,
                requested_mib: 512,
                maximum_mib: 1024,
            })
        ));
        store.release("first").unwrap();
        store
            .reserve(
                &ReservationRecord {
                    id: "second".into(),
                    memory_mib: 512,
                    expires_at,
                    active: false,
                },
                4,
                1024,
            )
            .unwrap();
        store.activate("second").unwrap();
        let active = store.active_reservations().unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, "second");
        assert_eq!(active[0].memory_mib, 512);
        assert_eq!(active[0].expires_at.timestamp(), expires_at.timestamp());
        assert!(active[0].active);
    }

    #[test]
    fn migrates_reservations_created_before_active_tracking() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("state.db");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE reservations (
                    id TEXT PRIMARY KEY NOT NULL,
                    memory_mib INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                );",
            )
            .unwrap();
        drop(connection);

        let store = StateStore::open(&path).unwrap();
        let expires_at = Utc::now() + chrono::Duration::minutes(30);
        store
            .reserve(
                &ReservationRecord {
                    id: "migrated".into(),
                    memory_mib: 256,
                    expires_at,
                    active: false,
                },
                1,
                512,
            )
            .unwrap();
        store.activate("migrated").unwrap();
        assert_eq!(store.active_reservations().unwrap().len(), 1);
    }
}
