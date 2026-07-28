//! Durable wrapper session leases and cross-process VM reservations backed by SQLite.

#![forbid(unsafe_code)]

use std::{
    env, fs,
    path::{Path, PathBuf},
    time::Duration,
};

use agent_sandbox_runtime::BackendId;
use chrono::{DateTime, TimeZone, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sysinfo::{Pid, ProcessesToUpdate, System};

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

    /// Requested managed environment does not exist.
    #[error("unknown managed environment {0}")]
    EnvironmentNotFound(String),

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
    /// Owning runtime backend.
    pub backend: BackendId,
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

/// A reusable, wrapper-managed environment snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentRecord {
    /// User-facing environment name.
    pub name: String,
    /// Microsandbox snapshot name.
    pub snapshot: String,
    /// Deterministic build-input digest.
    pub cache_key: String,
    /// Base OCI image reference.
    pub base: String,
    /// Content-addressed base manifest digest.
    pub base_digest: String,
    /// Guest CPU architecture used by the snapshot.
    pub arch: String,
    /// Normalized toolchain expressions.
    pub toolchains: Vec<String>,
    /// Snapshot creation time.
    pub created_at: DateTime<Utc>,
    /// Most recent successful environment use.
    pub last_used_at: DateTime<Utc>,
    /// Best-effort logical snapshot bytes.
    pub size_bytes: u64,
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
                backend TEXT NOT NULL DEFAULT 'microsandbox',
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
                active INTEGER NOT NULL DEFAULT 0,
                owner_pid INTEGER NOT NULL DEFAULT 0,
                owner_started_at INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_reservations_expires_at
                ON reservations(expires_at);
            CREATE TABLE IF NOT EXISTS environments (
                name TEXT PRIMARY KEY NOT NULL,
                snapshot TEXT NOT NULL UNIQUE,
                cache_key TEXT NOT NULL,
                base TEXT NOT NULL,
                base_digest TEXT NOT NULL,
                arch TEXT NOT NULL,
                toolchains_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                last_used_at INTEGER NOT NULL,
                size_bytes INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_environments_last_used_at
                ON environments(last_used_at);
            ",
        )?;
        let session_columns = {
            let mut statement = connection.prepare("PRAGMA table_info(sessions)")?;
            statement
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        if !session_columns.iter().any(|column| column == "backend") {
            connection.execute(
                "ALTER TABLE sessions
                 ADD COLUMN backend TEXT NOT NULL DEFAULT 'microsandbox'",
                [],
            )?;
        }
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
        let reservation_columns = {
            let mut statement = connection.prepare("PRAGMA table_info(reservations)")?;
            statement
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        if !reservation_columns
            .iter()
            .any(|column| column == "owner_pid")
        {
            connection.execute(
                "ALTER TABLE reservations
                 ADD COLUMN owner_pid INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        if !reservation_columns
            .iter()
            .any(|column| column == "owner_started_at")
        {
            connection.execute(
                "ALTER TABLE reservations
                 ADD COLUMN owner_started_at INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        let environment_columns = {
            let mut statement = connection.prepare("PRAGMA table_info(environments)")?;
            statement
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        if !environment_columns
            .iter()
            .any(|column| column == "base_digest")
        {
            connection.execute(
                "ALTER TABLE environments
                 ADD COLUMN base_digest TEXT NOT NULL DEFAULT ''",
                [],
            )?;
        }
        if !environment_columns.iter().any(|column| column == "arch") {
            connection.execute(
                "ALTER TABLE environments ADD COLUMN arch TEXT NOT NULL DEFAULT ''",
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
        let (owner_pid, owner_started_at) = current_process_identity();
        transaction.execute(
            "INSERT INTO reservations (
                id, memory_mib, expires_at, active, owner_pid, owner_started_at
             ) VALUES (?1, ?2, ?3, 0, ?4, ?5)",
            params![
                record.id,
                i64::from(record.memory_mib),
                record.expires_at.timestamp(),
                i64::from(owner_pid),
                i64::try_from(owner_started_at).unwrap_or(i64::MAX),
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

    /// Return non-session reservations whose creating wrapper process is gone.
    pub fn orphaned_reservations(&self) -> Result<Vec<ReservationRecord>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT r.id, r.memory_mib, r.expires_at, r.active,
                    r.owner_pid, r.owner_started_at
             FROM reservations r
             LEFT JOIN sessions s ON s.id = r.id
             WHERE s.id IS NULL AND r.owner_pid > 0 AND r.owner_started_at > 0
             ORDER BY r.id ASC",
        )?;
        let candidates = statement
            .query_map([], |row| {
                let record = decode_reservation(row)?;
                let owner_pid: i64 = row.get(4)?;
                let owner_started_at: i64 = row.get(5)?;
                Ok((
                    record,
                    u32::try_from(owner_pid).unwrap_or(0),
                    u64::try_from(owner_started_at).unwrap_or(0),
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if candidates.is_empty() {
            return Ok(vec![]);
        }
        let pids = candidates
            .iter()
            .map(|(_, pid, _)| Pid::from_u32(*pid))
            .collect::<Vec<_>>();
        let mut system = System::new();
        system.refresh_processes(ProcessesToUpdate::Some(&pids), true);
        Ok(candidates
            .into_iter()
            .filter(|(_, pid, started_at)| {
                system
                    .process(Pid::from_u32(*pid))
                    .is_none_or(|process| process.start_time() != *started_at)
            })
            .map(|(record, _, _)| record)
            .collect())
    }

    /// Persist metadata for a detached session after its VM is ready.
    pub fn insert(&self, record: &SessionRecord) -> Result<()> {
        self.connection()?.execute(
            "INSERT INTO sessions (
                id, backend, project, root, created_at, expires_at, maximum_expires_at, ports_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                record.id,
                record.backend.as_str(),
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
                "SELECT id, backend, project, root, created_at, expires_at, maximum_expires_at, ports_json
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
            "SELECT id, backend, project, root, created_at, expires_at, maximum_expires_at, ports_json
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
            "SELECT id, backend, project, root, created_at, expires_at, maximum_expires_at, ports_json
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

    /// Insert or replace one managed environment atomically.
    pub fn upsert_environment(&self, record: &EnvironmentRecord) -> Result<()> {
        self.connection()?.execute(
            "INSERT INTO environments (
                name, snapshot, cache_key, base, base_digest, arch, toolchains_json,
                created_at, last_used_at, size_bytes
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(name) DO UPDATE SET
                snapshot = excluded.snapshot,
                cache_key = excluded.cache_key,
                base = excluded.base,
                base_digest = excluded.base_digest,
                arch = excluded.arch,
                toolchains_json = excluded.toolchains_json,
                created_at = excluded.created_at,
                last_used_at = excluded.last_used_at,
                size_bytes = excluded.size_bytes",
            params![
                record.name,
                record.snapshot,
                record.cache_key,
                record.base,
                record.base_digest,
                record.arch,
                serde_json::to_string(&record.toolchains)?,
                record.created_at.timestamp(),
                record.last_used_at.timestamp(),
                i64::try_from(record.size_bytes).unwrap_or(i64::MAX),
            ],
        )?;
        Ok(())
    }

    /// Return a managed environment by name.
    pub fn get_environment(&self, name: &str) -> Result<EnvironmentRecord> {
        self.connection()?
            .query_row(
                "SELECT name, snapshot, cache_key, base, base_digest, arch, toolchains_json,
                        created_at, last_used_at, size_bytes
                 FROM environments WHERE name = ?1",
                [name],
                decode_environment,
            )
            .optional()?
            .ok_or_else(|| StateError::EnvironmentNotFound(name.into()))
    }

    /// List managed environments from least to most recently used.
    pub fn list_environments(&self) -> Result<Vec<EnvironmentRecord>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT name, snapshot, cache_key, base, base_digest, arch, toolchains_json,
                    created_at, last_used_at, size_bytes
             FROM environments ORDER BY last_used_at ASC, name ASC",
        )?;
        Ok(statement
            .query_map([], decode_environment)?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Record a successful use for LRU pruning.
    pub fn touch_environment(&self, name: &str, now: DateTime<Utc>) -> Result<EnvironmentRecord> {
        let changed = self.connection()?.execute(
            "UPDATE environments SET last_used_at = ?1 WHERE name = ?2",
            params![now.timestamp(), name],
        )?;
        if changed == 0 {
            return Err(StateError::EnvironmentNotFound(name.into()));
        }
        self.get_environment(name)
    }

    /// Remove a managed-environment registry entry.
    pub fn remove_environment(&self, name: &str) -> Result<()> {
        self.connection()?
            .execute("DELETE FROM environments WHERE name = ?1", [name])?;
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
    let created_at: i64 = row.get(4)?;
    let expires_at: i64 = row.get(5)?;
    let maximum_expires_at: i64 = row.get(6)?;
    let ports_json: String = row.get(7)?;
    let parse_time = |value| {
        Utc.timestamp_opt(value, 0)
            .single()
            .ok_or_else(|| rusqlite::Error::IntegralValueOutOfRange(0, value))
    };
    let ports = serde_json::from_str(&ports_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let backend_value: String = row.get(1)?;
    let backend = BackendId::new(backend_value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(SessionRecord {
        id: row.get(0)?,
        backend,
        project: PathBuf::from(row.get::<_, String>(2)?),
        root: row.get(3)?,
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

fn decode_environment(row: &rusqlite::Row<'_>) -> rusqlite::Result<EnvironmentRecord> {
    let toolchains_json: String = row.get(6)?;
    let created_at: i64 = row.get(7)?;
    let last_used_at: i64 = row.get(8)?;
    let size_bytes: i64 = row.get(9)?;
    let parse_time = |index, value| {
        Utc.timestamp_opt(value, 0)
            .single()
            .ok_or(rusqlite::Error::IntegralValueOutOfRange(index, value))
    };
    Ok(EnvironmentRecord {
        name: row.get(0)?,
        snapshot: row.get(1)?,
        cache_key: row.get(2)?,
        base: row.get(3)?,
        base_digest: row.get(4)?,
        arch: row.get(5)?,
        toolchains: serde_json::from_str(&toolchains_json).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                6,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        created_at: parse_time(7, created_at)?,
        last_used_at: parse_time(8, last_used_at)?,
        size_bytes: u64::try_from(size_bytes)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(9, size_bytes))?,
    })
}

fn current_process_identity() -> (u32, u64) {
    let pid = std::process::id();
    let system_pid = Pid::from_u32(pid);
    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::Some(&[system_pid]), true);
    let started_at = system
        .process(system_pid)
        .map(|process| process.start_time())
        .unwrap_or(0);
    (pid, started_at)
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
            backend: BackendId::microsandbox(),
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

    #[test]
    fn migrates_sessions_created_before_backend_tracking() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("state.db");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE sessions (
                    id TEXT PRIMARY KEY NOT NULL,
                    project TEXT NOT NULL,
                    root TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    maximum_expires_at INTEGER NOT NULL,
                    ports_json TEXT NOT NULL
                );",
            )
            .unwrap();
        let now = Utc::now();
        connection
            .execute(
                "INSERT INTO sessions (
                    id, project, root, created_at, expires_at, maximum_expires_at, ports_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    "legacy",
                    "/workspace/project",
                    "image:alpine",
                    now.timestamp(),
                    (now + chrono::Duration::minutes(30)).timestamp(),
                    (now + chrono::Duration::hours(8)).timestamp(),
                    "[]",
                ],
            )
            .unwrap();
        drop(connection);

        let store = StateStore::open(&path).unwrap();
        assert_eq!(
            store.get("legacy").unwrap().backend,
            BackendId::microsandbox()
        );
        store.insert(&record()).unwrap();
        assert_eq!(
            store.get("sbx_test").unwrap().backend,
            BackendId::microsandbox()
        );
    }

    #[test]
    fn round_trips_and_touches_managed_environments() {
        let directory = tempdir().unwrap();
        let store = StateStore::open(directory.path().join("state.db")).unwrap();
        let created_at = Utc::now() - chrono::Duration::hours(1);
        store
            .upsert_environment(&EnvironmentRecord {
                name: "audit".into(),
                snapshot: "asbx-env-audit-deadbeef".into(),
                cache_key: "deadbeef".into(),
                base: "ubuntu:24.04".into(),
                base_digest: format!("sha256:{}", "a".repeat(64)),
                arch: "aarch64".into(),
                toolchains: vec!["go@1.24.0".into(), "rust@1.88.0".into()],
                created_at,
                last_used_at: created_at,
                size_bytes: 42,
            })
            .unwrap();
        let record = store.get_environment("audit").unwrap();
        assert_eq!(record.toolchains.len(), 2);
        let touched = store.touch_environment("audit", Utc::now()).unwrap();
        assert!(touched.last_used_at > created_at);
        assert_eq!(store.list_environments().unwrap().len(), 1);
        store.remove_environment("audit").unwrap();
        assert!(matches!(
            store.get_environment("audit"),
            Err(StateError::EnvironmentNotFound(_))
        ));
    }

    #[test]
    fn migrates_environment_records_created_before_digest_tracking() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("state.db");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE environments (
                    name TEXT PRIMARY KEY NOT NULL,
                    snapshot TEXT NOT NULL UNIQUE,
                    cache_key TEXT NOT NULL,
                    base TEXT NOT NULL,
                    toolchains_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    last_used_at INTEGER NOT NULL,
                    size_bytes INTEGER NOT NULL
                );",
            )
            .unwrap();
        drop(connection);

        let store = StateStore::open(&path).unwrap();
        let now = Utc::now();
        store
            .upsert_environment(&EnvironmentRecord {
                name: "migrated".into(),
                snapshot: "asbx-env-migrated".into(),
                cache_key: "key".into(),
                base: "ubuntu:24.04".into(),
                base_digest: format!("sha256:{}", "b".repeat(64)),
                arch: "x86_64".into(),
                toolchains: vec!["node@22.0.0".into()],
                created_at: now,
                last_used_at: now,
                size_bytes: 1,
            })
            .unwrap();
        let migrated = store.get_environment("migrated").unwrap();
        assert!(migrated.base_digest.starts_with("sha256:"));
        assert_eq!(migrated.arch, "x86_64");
    }

    #[test]
    fn detects_dead_owners_without_reclaiming_persistent_sessions() {
        let directory = tempdir().unwrap();
        let store = StateStore::open(directory.path().join("state.db")).unwrap();
        let expires_at = Utc::now() + chrono::Duration::hours(1);
        for id in ["orphan", "persistent"] {
            store
                .reserve(
                    &ReservationRecord {
                        id: id.into(),
                        memory_mib: 128,
                        expires_at,
                        active: true,
                    },
                    4,
                    1024,
                )
                .unwrap();
            store
                .connection()
                .unwrap()
                .execute(
                    "UPDATE reservations
                     SET owner_pid = ?1, owner_started_at = 1 WHERE id = ?2",
                    params![i64::from(u32::MAX), id],
                )
                .unwrap();
        }
        let mut session = record();
        session.id = "persistent".into();
        store.insert(&session).unwrap();

        let orphaned = store.orphaned_reservations().unwrap();
        assert_eq!(orphaned.len(), 1);
        assert_eq!(orphaned[0].id, "orphan");
    }
}
