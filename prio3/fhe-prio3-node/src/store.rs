//! SQLite persistence. One database per node; every state change of the
//! aggregator is written in a transaction after it happened, so a restart
//! resumes from the last completed step.

use anyhow::Context as _;
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;

pub struct Store {
    conn: Connection,
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
        Ok(Self { conn })
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

    /// Writes several entries and a journal line atomically.
    pub fn commit_step(&mut self, entries: &[(&str, Vec<u8>)], event: &str, detail: &str) -> anyhow::Result<()> {
        let tx = self.conn.transaction()?;
        for (name, bytes) in entries {
            tx.execute(
                "INSERT INTO kv(name, bytes) VALUES (?1, ?2) ON CONFLICT(name) DO UPDATE SET bytes = excluded.bytes",
                params![name, bytes],
            )?;
        }
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        tx.execute("INSERT INTO journal(ts, event, detail) VALUES (?1, ?2, ?3)", params![ts, event, detail])?;
        tx.commit()?;
        Ok(())
    }

    pub fn journal_len(&self) -> anyhow::Result<u64> {
        Ok(self.conn.query_row("SELECT COUNT(*) FROM journal", [], |r| r.get::<_, i64>(0))? as u64)
    }
}
