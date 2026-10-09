//! SQLite persistence. One database per node; every state change of the
//! aggregator is written in a transaction after it happened, so a restart
//! resumes from the last completed step.

use anyhow::Context as _;
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;

pub struct Store {
    conn: Connection,
    path: std::path::PathBuf,
}

impl Store {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("open {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS kv (name TEXT PRIMARY KEY, bytes BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS journal (seq INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, event TEXT NOT NULL, detail TEXT NOT NULL);",
        )?;
        Ok(Self {
            conn,
            path: path.to_path_buf(),
        })
    }

    pub fn put(&mut self, name: &str, bytes: &[u8]) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO kv(name, bytes) VALUES (?1, ?2) ON CONFLICT(name) DO UPDATE SET bytes = excluded.bytes",
            params![name, bytes],
        )?;
        Ok(())
    }

    pub fn get(&self, name: &str) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self
            .conn
            .query_row("SELECT bytes FROM kv WHERE name = ?1", params![name], |r| r.get::<_, Vec<u8>>(0))
            .optional()?)
    }

    /// Writes several entries, deletes others and adds a journal line,
    /// atomically.
    pub fn commit_step(&mut self, entries: &[(&str, Vec<u8>)], deletes: &[String], event: &str, detail: &str) -> anyhow::Result<()> {
        let tx = self.conn.transaction()?;
        for (name, bytes) in entries {
            tx.execute(
                "INSERT INTO kv(name, bytes) VALUES (?1, ?2) ON CONFLICT(name) DO UPDATE SET bytes = excluded.bytes",
                params![name, bytes],
            )?;
        }
        for name in deletes {
            tx.execute("DELETE FROM kv WHERE name = ?1", params![name])?;
        }
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        tx.execute("INSERT INTO journal(ts, event, detail) VALUES (?1, ?2, ?3)", params![ts, event, detail])?;
        tx.commit()?;
        Ok(())
    }

    /// Names of the stored entries starting with `prefix`.
    pub fn names_with_prefix(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
        let mut stmt = self.conn.prepare("SELECT name FROM kv WHERE substr(name, 1, length(?1)) = ?1 ORDER BY name")?;
        let rows = stmt.query_map(params![prefix], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Bytes on disk: the database file and its write-ahead log.
    pub fn size_bytes(&self) -> anyhow::Result<u64> {
        let mut total = std::fs::metadata(&self.path)?.len();
        let mut wal = self.path.clone().into_os_string();
        wal.push("-wal");
        if let Ok(m) = std::fs::metadata(&wal) {
            total += m.len();
        }
        Ok(total)
    }

    pub fn journal_len(&self) -> anyhow::Result<u64> {
        Ok(self.conn.query_row("SELECT COUNT(*) FROM journal", [], |r| r.get::<_, i64>(0))? as u64)
    }
}
