use crate::message::Prepared;
use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use std::{
    fs::File,
    path::Path,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
pub struct Queue {
    connection: Arc<Mutex<Connection>>,
    _lock: Arc<File>,
}

#[derive(Serialize)]
pub struct Receipt {
    pub id: String,
    pub status: String,
    pub attempts: u32,
    pub expires_at: i64,
    pub error: Option<String>,
}

pub enum Enqueued {
    New(Receipt),
    Existing(Receipt),
    Conflict,
    Limited,
    Full,
}

pub struct Job {
    pub id: String,
    pub recipient: String,
    pub raw: Vec<u8>,
    pub attempts: u32,
    pub expires_at: i64,
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

impl Queue {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent().filter(|value| !value.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let lock = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path.with_extension("lock"))?;
        lock.try_lock()
            .context("Another jussend process owns this queue")?;
        let connection = Connection::open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;
            PRAGMA cache_size=-1024; PRAGMA journal_size_limit=1048576; PRAGMA max_page_count=16384;
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY, request_key TEXT NOT NULL UNIQUE, request_hash BLOB NOT NULL,
                recipient_hash BLOB NOT NULL, recipient TEXT, raw BLOB,
                status TEXT NOT NULL DEFAULT 'queued', attempts INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, next_attempt INTEGER NOT NULL,
                error TEXT
            );
            CREATE INDEX IF NOT EXISTS messages_due ON messages(status,next_attempt);
            CREATE INDEX IF NOT EXISTS messages_recipient ON messages(recipient_hash,created_at);
            CREATE INDEX IF NOT EXISTS messages_created ON messages(created_at);
            UPDATE messages SET status='queued' WHERE status='sending';")?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            _lock: Arc::new(lock),
        })
    }

    async fn access<T: Send + 'static>(
        &self,
        action: impl FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let connection = self.connection.clone();
        tokio::task::spawn_blocking(move || {
            let mut connection = connection
                .lock()
                .map_err(|_| anyhow::anyhow!("Queue lock poisoned"))?;
            action(&mut connection)
        })
        .await?
    }

    pub async fn enqueue(&self, item: Prepared) -> Result<Enqueued> {
        self.access(move |connection| {
            let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let existing: Option<(Vec<u8>, Receipt)> = tx.query_row("SELECT request_hash,id,status,attempts,expires_at,error FROM messages WHERE request_key=?1", [&item.key], |row| Ok((row.get(0)?, Receipt { id: row.get(1)?, status: row.get(2)?, attempts: row.get(3)?, expires_at: row.get(4)?, error: row.get(5)? }))).optional()?;
            if let Some((hash, receipt)) = existing { return Ok(if hash == item.hash { Enqueued::Existing(receipt) } else { Enqueued::Conflict }); }
            let now = now();
            let queued: i64 = tx.query_row("SELECT COUNT(*) FROM messages WHERE status IN ('queued','sending') AND expires_at>?1", [now], |row| row.get(0))?;
            if queued >= 1000 { return Ok(Enqueued::Full); }
            let recent: i64 = tx.query_row("SELECT COUNT(*) FROM messages WHERE created_at>?1", [now - 60], |row| row.get(0))?;
            let recipient_recent: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM messages WHERE recipient_hash=?1 AND created_at>?2)", params![item.recipient_hash, now - 60], |row| row.get(0))?;
            if recent >= 60 || recipient_recent { return Ok(Enqueued::Limited); }
            tx.execute("INSERT INTO messages(id,request_key,request_hash,recipient_hash,recipient,raw,created_at,expires_at,next_attempt) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?7)", params![item.id,item.key,item.hash,item.recipient_hash,item.recipient,item.raw,now,item.expires_at])?;
            tx.commit()?;
            Ok(Enqueued::New(Receipt { id: item.id, status: "queued".into(), attempts: 0, expires_at: item.expires_at, error: None }))
        }).await
    }

    pub async fn status(&self, id: String) -> Result<Option<Receipt>> {
        self.access(move |connection| {
            Ok(connection
                .query_row(
                    "SELECT id,status,attempts,expires_at,error FROM messages WHERE id=?1",
                    [id],
                    |row| {
                        Ok(Receipt {
                            id: row.get(0)?,
                            status: row.get(1)?,
                            attempts: row.get(2)?,
                            expires_at: row.get(3)?,
                            error: row.get(4)?,
                        })
                    },
                )
                .optional()?)
        })
        .await
    }

    pub async fn claim(&self) -> Result<Option<Job>> {
        self.access(|connection| {
            let now = now();
            let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute("UPDATE messages SET status='expired',recipient=NULL,raw=NULL,error='expired' WHERE status='queued' AND expires_at<=?1", [now])?;
            tx.execute("DELETE FROM messages WHERE status NOT IN ('queued','sending') AND created_at<?1", [now - 86400])?;
            let job = tx.query_row("SELECT id,recipient,raw,attempts,expires_at FROM messages WHERE status='queued' AND next_attempt<=?1 ORDER BY next_attempt,created_at LIMIT 1", [now], |row| Ok(Job { id: row.get(0)?, recipient: row.get(1)?, raw: row.get(2)?, attempts: row.get::<_, u32>(3)? + 1, expires_at: row.get(4)? })).optional()?;
            if let Some(job) = &job { tx.execute("UPDATE messages SET status='sending',attempts=?2 WHERE id=?1", params![job.id, job.attempts])?; }
            tx.commit()?;
            Ok(job)
        }).await
    }

    pub async fn finish(
        &self,
        job: Job,
        result: Result<(), crate::delivery::Failure>,
    ) -> Result<()> {
        self.access(move |connection| {
            let now = now();
            let (status, error, next) = match result {
                Ok(()) => ("accepted", None, now),
                Err(error) if error.permanent || job.attempts >= 8 => ("failed", Some(error.code), now),
                Err(_) if job.expires_at <= now => ("expired", Some("expired"), now),
                Err(error) => ("queued", Some(error.code), now + (30_i64 * (1_i64 << job.attempts.saturating_sub(1).min(6))).min(1800)),
            };
            connection.execute("UPDATE messages SET status=?2,error=?3,next_attempt=?4,recipient=CASE WHEN ?2='queued' THEN recipient ELSE NULL END,raw=CASE WHEN ?2='queued' THEN raw ELSE NULL END WHERE id=?1", params![job.id,status,error,next])?;
            if status != "queued" { connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?; }
            tracing::info!(id=%job.id, status, attempts=job.attempts, "mail attempt finished");
            Ok(())
        }).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn prepared(key: &str) -> Prepared {
        Prepared {
            id: uuid::Uuid::new_v4().to_string(),
            key: key.into(),
            hash: vec![1],
            recipient_hash: vec![2],
            recipient: "user@example.com".into(),
            raw: b"secret token".to_vec(),
            expires_at: now() + 900,
        }
    }
    #[tokio::test]
    async fn deduplicates_and_erases_completed_payloads() {
        let path = std::env::temp_dir().join(format!("jussend-{}.sqlite3", uuid::Uuid::new_v4()));
        let queue = Queue::open(&path).unwrap();
        assert!(matches!(
            queue.enqueue(prepared("same")).await.unwrap(),
            Enqueued::New(_)
        ));
        assert!(matches!(
            queue.enqueue(prepared("same")).await.unwrap(),
            Enqueued::Existing(_)
        ));
        let mut changed = prepared("same");
        changed.hash = vec![9];
        assert!(matches!(
            queue.enqueue(changed).await.unwrap(),
            Enqueued::Conflict
        ));
        assert!(matches!(
            queue.enqueue(prepared("different")).await.unwrap(),
            Enqueued::Limited
        ));
        let job = queue.claim().await.unwrap().unwrap();
        queue.finish(job, Ok(())).await.unwrap();
        queue
            .access(|connection| {
                let empty: bool = connection.query_row(
                    "SELECT raw IS NULL AND recipient IS NULL FROM messages",
                    [],
                    |row| row.get(0),
                )?;
                assert!(empty);
                Ok(())
            })
            .await
            .unwrap();
        drop(queue);
        for file in [
            path.clone(),
            path.with_extension("lock"),
            path.with_file_name(format!(
                "{}-wal",
                path.file_name().unwrap().to_string_lossy()
            )),
            path.with_file_name(format!(
                "{}-shm",
                path.file_name().unwrap().to_string_lossy()
            )),
        ] {
            let _ = std::fs::remove_file(file);
        }
    }
}
