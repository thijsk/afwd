use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::http::{header::REFERER, HeaderMap, Uri};
use rusqlite::{params, Connection, Transaction, TransactionBehavior};
use url::Url;

type Key = (String, i64, &'static str, String);
/// The hour, and the names counted in it per registrable domain.
type HostsThisHour = (i64, HashMap<String, HashSet<String>>);

// ponytail: drops counts once the flush window is full; per-host caps if one host starves others
const MAX_PENDING: usize = 10_000;
const RETENTION_SECS: i64 = 90 * 24 * 3600;
/// Names counted per registrable domain per hour. A wildcard record makes every made-up
/// subdomain valid, and each would otherwise get counters of its own.
const MAX_HOSTS_PER_DOMAIN: usize = 20;
/// New names per registrable domain that may get a certificate in any week. A wildcard
/// would otherwise let anyone use up the domain's certificate rate limits.
const NEW_CERTIFICATES_PER_DOMAIN: i64 = 20;
const CERTIFICATE_WINDOW_SECS: i64 = 7 * 24 * 3600;

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
CREATE INDEX IF NOT EXISTS counts_status ON counts (host, n) WHERE kind = 'status';
CREATE TABLE IF NOT EXISTS certificate_names (
    host TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    admitted INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS certificate_names_domain ON certificate_names (domain, admitted);
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
    /// The names counted this hour, per registrable domain.
    hosts: Arc<Mutex<HostsThisHour>>,
    db: Arc<Mutex<Connection>>,
}

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub struct Summary {
    pub requests: i64,
    pub domains: usize,
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
        // edge and site open the same database at the same time. One write transaction
        // makes the schema setup and the seeding below happen exactly once and completely.
        let setup = Transaction::new_unchecked(&db, TransactionBehavior::Immediate)?;
        let fresh = setup.query_row(
            "SELECT COUNT(*) = 0 FROM sqlite_master WHERE name = 'certificate_names'",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        setup.execute_batch(SCHEMA)?;
        if fresh {
            // Names that already forward traffic got their certificates before the cap
            // existed; they do not count as new.
            let hosts = setup
                .prepare("SELECT DISTINCT host FROM counts WHERE kind = 'status'")?
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            let mut insert = setup.prepare(
                "INSERT OR IGNORE INTO certificate_names (host, domain, admitted) VALUES (?1, ?2, 0)",
            )?;
            for host in hosts {
                insert.execute(params![host, registrable_domain(&host)])?;
            }
        }
        setup.commit()?;
        Ok(Self {
            pending: Arc::default(),
            hosts: Arc::default(),
            db: Arc::new(Mutex::new(db)),
        })
    }

    /// Whether `host` may get a certificate: it had one before, or its registrable
    /// domain has had fewer than [`NEW_CERTIFICATES_PER_DOMAIN`] new names this week.
    pub async fn admit_certificate(&self, host: &str) -> rusqlite::Result<bool> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let domain = registrable_domain(&host);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let db = db.lock().unwrap();
            let known = db
                .prepare_cached("SELECT 1 FROM certificate_names WHERE host = ?1")?
                .exists([&host])?;
            if known {
                return Ok(true);
            }
            let recent: i64 = db.query_row(
                "SELECT COUNT(*) FROM certificate_names WHERE domain = ?1 AND admitted > ?2",
                params![domain, now - CERTIFICATE_WINDOW_SECS],
                |row| row.get(0),
            )?;
            if recent >= NEW_CERTIFICATES_PER_DOMAIN {
                return Ok(false);
            }
            db.execute(
                "INSERT OR IGNORE INTO certificate_names (host, domain, admitted) VALUES (?1, ?2, ?3)",
                params![host, domain, now],
            )?;
            Ok(true)
        })
        .await
        .expect("certificate admission task panicked")
    }

    pub fn record(&self, host: &str, status: &str, path: &str, referer: Option<&str>) {
        let host = host.to_ascii_lowercase();
        let hour = hour_now();
        if !self.counts_host(&host, hour) {
            return;
        }
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

    /// Whether `host` may be counted this hour: it already is, or its registrable domain
    /// has fewer than [`MAX_HOSTS_PER_DOMAIN`] names counted.
    fn counts_host(&self, host: &str, hour: i64) -> bool {
        let mut hosts = self.hosts.lock().unwrap();
        if hosts.0 != hour {
            *hosts = (hour, HashMap::new());
        }
        let names = hosts.1.entry(registrable_domain(host)).or_default();
        if names.contains(host) {
            return true;
        }
        if names.len() >= MAX_HOSTS_PER_DOMAIN {
            return false;
        }
        names.insert(host.to_owned());
        true
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

    pub async fn top_domains(&self, excluded_host: &str) -> rusqlite::Result<Vec<(String, i64)>> {
        let mut rows = self.ranked_domains(excluded_host).await?;
        rows.truncate(100);
        Ok(rows)
    }

    /// Total requests and number of registrable domains over the retention period.
    pub async fn summary(&self, excluded_host: &str) -> rusqlite::Result<Summary> {
        let rows = self.ranked_domains(excluded_host).await?;
        Ok(Summary {
            requests: rows.iter().map(|(_, total)| total).sum(),
            domains: rows.len(),
        })
    }

    /// Request totals per registrable domain, busiest first.
    async fn ranked_domains(&self, excluded_host: &str) -> rusqlite::Result<Vec<(String, i64)>> {
        let excluded_host = excluded_host.to_ascii_lowercase();
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let db = db.lock().unwrap();
            let mut statement = db.prepare_cached(
                "SELECT host, SUM(n) AS total FROM counts
                 WHERE kind = 'status' AND host != ?1 GROUP BY host",
            )?;
            let rows = statement
                .query_map([excluded_host], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            let mut counts = HashMap::new();
            for (host, total) in rows {
                let domain = registrable_domain(&host);
                *counts.entry(domain).or_insert(0) += total;
            }
            let mut rows = counts.into_iter().collect::<Vec<_>>();
            rows.sort_by(|(left, left_total), (right, right_total)| {
                right_total.cmp(left_total).then_with(|| left.cmp(right))
            });
            Ok(rows)
        })
        .await
        .expect("stats query task panicked")
    }
}

/// Counts a request for `host`, when statistics are enabled.
pub fn record_request(
    stats: Option<&Stats>,
    host: &str,
    status: &str,
    uri: &Uri,
    headers: &HeaderMap,
) {
    if let Some(stats) = stats {
        let referer = headers.get(REFERER).and_then(|value| value.to_str().ok());
        stats.record(host, status, uri.path(), referer);
    }
}

/// Groups a host under its registrable domain using the Public Suffix List.
/// A host the list cannot place (a bare suffix, an IP address) is kept as it is.
fn registrable_domain(host: &str) -> String {
    let host = host.trim().trim_matches('.').to_ascii_lowercase();
    match psl::domain_str(&host) {
        Some(domain) => domain.to_owned(),
        None => host,
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
    use super::{Stats, MAX_HOSTS_PER_DOMAIN, NEW_CERTIFICATES_PER_DOMAIN};

    #[tokio::test]
    async fn names_counted_per_domain_are_capped() {
        let stats = Stats::open(":memory:").unwrap();
        for index in 0..MAX_HOSTS_PER_DOMAIN + 5 {
            stats.record(&format!("x{index}.example.com"), "302", "/", None);
        }
        // Names that are already counted keep counting.
        stats.record("x0.example.com", "302", "/", None);
        stats.record("other.example", "302", "/", None);
        stats.flush().await.unwrap();

        let counted = |host: &str| {
            let stats = stats.clone();
            let host = host.to_owned();
            async move { !stats.query(host).await.unwrap().hits.is_empty() }
        };
        assert!(counted("x0.example.com").await);
        assert!(counted(&format!("x{}.example.com", MAX_HOSTS_PER_DOMAIN - 1)).await);
        assert!(!counted(&format!("x{}.example.com", MAX_HOSTS_PER_DOMAIN)).await);
        assert!(counted("other.example").await);
        let report = stats.query("x0.example.com".to_owned()).await.unwrap();
        assert_eq!(report.hits[0].2, 2);
    }

    #[tokio::test]
    async fn new_certificate_names_per_domain_are_capped() {
        let stats = Stats::open(":memory:").unwrap();
        for index in 0..NEW_CERTIFICATES_PER_DOMAIN {
            assert!(stats
                .admit_certificate(&format!("x{index}.example.com"))
                .await
                .unwrap());
        }
        assert!(!stats
            .admit_certificate("one-too-many.example.com")
            .await
            .unwrap());
        // A name that was admitted before stays admitted, and other domains are separate.
        assert!(stats.admit_certificate("X0.example.com.").await.unwrap());
        assert!(stats.admit_certificate("www.example.net").await.unwrap());
    }

    #[tokio::test]
    async fn names_that_already_forward_traffic_are_not_new() {
        let path = std::env::temp_dir().join(format!("afwd-cert-seed-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            // A database from before the certificate cap: counts, but no admissions.
            let db = rusqlite::Connection::open(&path).unwrap();
            db.execute_batch(
                "CREATE TABLE counts (host TEXT NOT NULL, hour INTEGER NOT NULL, kind TEXT NOT NULL,
                 value TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (host, hour, kind, value)) WITHOUT ROWID;",
            )
            .unwrap();
            for index in 0..NEW_CERTIFICATES_PER_DOMAIN + 5 {
                db.execute(
                    "INSERT INTO counts VALUES (?1, 0, 'status', '302', 1)",
                    [format!("x{index}.example.com")],
                )
                .unwrap();
            }
        }
        let stats = Stats::open(path.to_str().unwrap()).unwrap();
        assert!(stats
            .admit_certificate(&format!("x{}.example.com", NEW_CERTIFICATES_PER_DOMAIN + 4))
            .await
            .unwrap());
        assert!(stats.admit_certificate("new.example.com").await.unwrap());
        drop(stats);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn instances_sharing_a_database_sum_their_counts() {
        let path = std::env::temp_dir().join(format!("afwd-stats-{}.db", std::process::id()));
        let path = path.to_str().unwrap();
        let first = Stats::open(path).unwrap();
        let second = Stats::open(path).unwrap();

        first.record(
            "Example.com",
            "302",
            "/a",
            Some("https://ref.example/x?y=1"),
        );
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

    #[tokio::test]
    async fn top_domains_are_ranked_capped_and_exclude_the_help_domain() {
        let path = std::env::temp_dir().join(format!("afwd-domains-{}.db", std::process::id()));
        let path = path.to_str().unwrap();
        let stats = Stats::open(path).unwrap();

        stats.record("help.example", "200", "/", None);
        for index in 0..101 {
            let domain = format!("domain-{index:03}.example");
            for _ in 0..=index {
                stats.record(&domain, "302", "/", None);
            }
        }
        stats.flush().await.unwrap();

        let domains = stats.top_domains("HELP.EXAMPLE").await.unwrap();
        assert_eq!(domains.len(), 100);
        assert_eq!(domains[0], ("domain-100.example".to_owned(), 101));
        assert_eq!(domains[99], ("domain-001.example".to_owned(), 2));
        assert!(!domains.iter().any(|(domain, _)| domain == "help.example"));

        // The summary counts every domain, not only the top 100.
        let summary = stats.summary("help.example").await.unwrap();
        assert_eq!(summary.domains, 101);
        assert_eq!(summary.requests, (1..=101).sum::<i64>());

        drop(stats);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{path}{suffix}"));
        }
    }

    #[tokio::test]
    async fn top_domains_groups_subdomains_together_by_registrable_domain() {
        let stats = Stats::open(":memory:").unwrap();
        stats.record("a.example.com", "302", "/", None);
        stats.record("b.example.com", "302", "/", None);
        stats.record("c.example.net", "302", "/", None);
        stats.record("d.example.co.uk", "302", "/", None);
        stats.record("e.example.co.uk", "302", "/", None);
        stats.record("help.example.com", "200", "/", None);
        stats.flush().await.unwrap();

        let domains = stats.top_domains("help.example.com").await.unwrap();
        assert_eq!(
            domains,
            vec![
                ("example.co.uk".to_owned(), 2),
                ("example.com".to_owned(), 2),
                ("example.net".to_owned(), 1),
            ]
        );
    }

    #[test]
    fn registrable_domain_follows_the_public_suffix_list() {
        for (host, expected) in [
            ("example.com", "example.com"),
            ("Www.Example.com.", "example.com"),
            ("shop.example.com.au", "example.com.au"),
            ("other.com.au", "other.com.au"),
            ("a.charity.org.uk", "charity.org.uk"),
            ("www.ah.nl", "ah.nl"),
            ("www.hp.com", "hp.com"),
            ("alice.github.io", "alice.github.io"),
            ("deep.alice.github.io", "alice.github.io"),
            ("com.au", "com.au"),
            ("localhost", "localhost"),
        ] {
            assert_eq!(super::registrable_domain(host), expected, "{host}");
        }
    }
}
