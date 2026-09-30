use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rusqlite::{params, Connection};
use url::Url;

type Key = (String, i64, &'static str, String);

// ponytail: drops counts once the flush window is full; per-host caps if one host starves others
const MAX_PENDING: usize = 10_000;
const RETENTION_SECS: i64 = 90 * 24 * 3600;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS counts (
    host TEXT NOT NULL,
    hour INTEGER NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    n INTEGER NOT NULL,
    PRIMARY KEY (host, hour, kind, value)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS counts_hour ON counts (hour);
";

// Caps distinct paths and referrers at 100 per host per hour so scanners cannot grow the table.
const UPSERT: &str = "
INSERT INTO counts (host, hour, kind, value, n)
SELECT ?1, ?2, ?3, ?4, ?5
WHERE ?3 = 'status'
   OR EXISTS (SELECT 1 FROM counts WHERE host = ?1 AND hour = ?2 AND kind = ?3 AND value = ?4)
   OR (SELECT COUNT(*) FROM counts WHERE host = ?1 AND hour = ?2 AND kind = ?3) < 100
ON CONFLICT (host, hour, kind, value) DO UPDATE SET n = counts.n + excluded.n
";

#[derive(Clone)]
pub struct Stats {
    pending: Arc<Mutex<HashMap<Key, u64>>>,
    db: Arc<Mutex<Connection>>,
}

#[derive(Debug, serde::Serialize)]
pub struct Report {
    pub hits: Vec<(i64, String, i64)>,
    pub paths: Vec<(String, i64)>,
    pub referrers: Vec<(String, i64)>,
}

impl Stats {
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let db = Connection::open(path)?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.busy_timeout(Duration::from_secs(5))?;
        db.execute_batch(SCHEMA)?;
        Ok(Self {
            pending: Arc::default(),
            db: Arc::new(Mutex::new(db)),
        })
    }

    pub fn record(&self, host: &str, status: &str, path: &str, referer: Option<&str>) {
        let host = host.to_ascii_lowercase();
        let hour = hour_now();
        let mut pending = self.pending.lock().unwrap();
        if pending.len() >= MAX_PENDING {
            return;
        }
        *pending
            .entry((host.clone(), hour, "status", status.to_owned()))
            .or_default() += 1;
        *pending
            .entry((host.clone(), hour, "path", path.chars().take(256).collect()))
            .or_default() += 1;
        if let Some(referrer) = referer
            .and_then(|value| Url::parse(value).ok())
            .and_then(|url| url.host_str().map(str::to_owned))
        {
            *pending.entry((host, hour, "ref", referrer)).or_default() += 1;
        }
    }

    pub async fn flush(&self) -> rusqlite::Result<()> {
        let pending = std::mem::take(&mut *self.pending.lock().unwrap());
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let mut db = db.lock().unwrap();
            let tx = db.transaction()?;
            {
                let mut upsert = tx.prepare_cached(UPSERT)?;
                for ((host, hour, kind, value), n) in pending {
                    upsert.execute(params![host, hour, kind, value, n as i64])?;
                }
            }
            tx.execute(
                "DELETE FROM counts WHERE hour < ?1",
                [hour_now() - RETENTION_SECS],
            )?;
            tx.commit()
        })
        .await
        .expect("stats flush task panicked")
    }

    pub async fn query(&self, host: String) -> rusqlite::Result<Report> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let db = db.lock().unwrap();
            let mut hits = db.prepare_cached(
                "SELECT hour, value, n FROM counts WHERE host = ?1 AND kind = 'status' ORDER BY hour",
            )?;
            let hits = hits
                .query_map([&host], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
                .collect::<Result<_, _>>()?;
            Ok(Report {
                hits,
                paths: top(&db, &host, "path")?,
                referrers: top(&db, &host, "ref")?,
            })
        })
        .await
        .expect("stats query task panicked")
    }
}

fn top(db: &Connection, host: &str, kind: &str) -> rusqlite::Result<Vec<(String, i64)>> {
    let mut statement = db.prepare_cached(
        "SELECT value, SUM(n) AS total FROM counts WHERE host = ?1 AND kind = ?2
         GROUP BY value ORDER BY total DESC LIMIT 50",
    )?;
    let rows = statement
        .query_map(params![host, kind], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect();
    rows
}

fn hour_now() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    secs - secs % 3600
}

#[cfg(test)]
mod tests {
    use super::Stats;

    #[tokio::test]
    async fn instances_sharing_a_database_sum_their_counts() {
        let path = std::env::temp_dir().join(format!("afwd-stats-{}.db", std::process::id()));
        let path = path.to_str().unwrap();
        let first = Stats::open(path).unwrap();
        let second = Stats::open(path).unwrap();

        first.record("Example.com", "302", "/a", Some("https://ref.example/x?y=1"));
        second.record("example.com", "302", "/a", None);
        first.flush().await.unwrap();
        second.flush().await.unwrap();

        let report = first.query("example.com".to_owned()).await.unwrap();
        assert_eq!(report.hits[0].1, "302");
        assert_eq!(report.hits[0].2, 2);
        assert_eq!(report.paths, vec![("/a".to_owned(), 2)]);
        assert_eq!(report.referrers, vec![("ref.example".to_owned(), 1)]);

        drop((first, second));
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{path}{suffix}"));
        }
    }
}
