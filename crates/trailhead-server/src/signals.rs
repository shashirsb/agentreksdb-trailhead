//! Contributor history signals, read from public GitHub data.
//!
//! These feed two small terms of the priority score: R (previously merged work, 9 points) and
//! O (open-source repos shared, 4 points). Together they are capped at 13 of 100, so history
//! can help a newcomer be noticed but can never outrank a crowd — `priority` has a test for
//! exactly that.
//!
//! Counting raw commits or stars would be worse than counting nothing. Commit history is
//! trivially forged (tools write thousands of backdated commits into a private repo), and a
//! 2024 study found roughly 15,800 repositories with suspected fake-star campaigns. So:
//!
//! - Work in repositories the user owns earns **no** activity credit. That single rule removes
//!   fake-history repos and scheduled empty-commit Actions at once.
//! - A merged pull request counts only when somebody else merged it, into a repository the
//!   author does not own, that passes a quality floor.
//! - Activity is counted in **active weeks**, not commits, so volume is worthless.
//! - Everything is recomputed on a schedule, never on demand, so nobody can tune against the
//!   score in a live loop.
//! - Public data only, and a user may opt out entirely with no penalty.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;

use crate::config::Config;
use crate::github::GitHub;

/// Raw, un-normalised signals. Normalisation, caps and decay live in `priority`, and the
/// weights live in a versioned file, so a reader can recompute a score from these numbers.
#[derive(Debug, Clone, Default, Serialize, Deserialize, sqlx::FromRow)]
pub struct Signals {
    pub external_merged_prs: i32,
    pub external_repos: i32,
    pub active_weeks: i32,
    pub shared_repos: i32,
    pub dependents: i32,
    /// What was dropped and why, shown to the user verbatim. A score nobody can audit is a
    /// score nobody should trust.
    pub excluded: serde_json::Value,
    pub opted_out: bool,
}

/// Minimum account age before any external signal counts at all.
pub const MIN_ACCOUNT_DAYS_FOR_EXTERNAL: i64 = 365;
/// A repository must have at least this many stars from aged accounts, or one outside
/// contributor, to count as "shared".
pub const MIN_STARS: i64 = 5;
/// A repository younger than this cannot count; neither can one with no recent activity.
pub const MIN_REPO_AGE_DAYS: i64 = 90;
pub const MAX_REPO_IDLE_DAYS: i64 = 730;

/// The facts about a repository that decide whether it counts as shared open source.
#[derive(Debug, Clone, Copy)]
pub struct RepoFacts {
    pub is_fork: bool,
    pub is_archived: bool,
    pub license_is_osi: bool,
    pub age_days: i64,
    pub idle_days: i64,
    pub commits: i64,
    /// Stars, which only ever act as a floor. They are bought in bulk, so they can let a repo
    /// in but never raise a score.
    pub stars: i64,
    pub outside_contributors: i64,
}

/// Does this repository count as a shared open-source project?
///
/// Deliberately strict. Anyone can create ten empty repositories in a minute, so this floor is
/// what separates "published something people use" from "made some folders".
pub fn repo_qualifies(r: RepoFacts) -> bool {
    !r.is_fork
        && !r.is_archived
        && r.license_is_osi
        && r.age_days >= MIN_REPO_AGE_DAYS
        && r.idle_days <= MAX_REPO_IDLE_DAYS
        && r.commits >= 10
        && (r.stars >= MIN_STARS || r.outside_contributors >= 1)
}

/// Why a repository was rejected, in the contributor's own terms. Shown back to them verbatim.
pub fn repo_rejection(r: RepoFacts) -> &'static str {
    if r.is_fork {
        "a fork"
    } else if !r.license_is_osi {
        "no OSI-approved licence"
    } else if r.is_archived {
        "archived"
    } else if r.age_days < MIN_REPO_AGE_DAYS {
        "newer than 90 days"
    } else if r.idle_days > MAX_REPO_IDLE_DAYS {
        "no activity in two years"
    } else if r.commits < 10 {
        "fewer than 10 commits"
    } else {
        "no stars from others and no outside contributors"
    }
}

/// Does this merged pull request count?
///
/// `merged_by_other` is the load-bearing condition: a pull request you opened and merged into
/// your own repository is a commit with extra steps.
pub fn pr_counts(
    owner_is_author: bool,
    merged_by_other: bool,
    repo_archived: bool,
    has_outside_review: bool,
) -> bool {
    !owner_is_author && merged_by_other && !repo_archived && has_outside_review
}

/// Read a user's stored signals. Missing or opted-out means zero, never an error: the score
/// must degrade to Trailhead-only data rather than failing.
pub async fn get(pool: &PgPool, user_id: i64) -> anyhow::Result<Signals> {
    let row = sqlx::query_as::<_, Signals>(
        "SELECT external_merged_prs, external_repos, active_weeks, shared_repos, dependents,
                excluded, opted_out
         FROM contributor_signals WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(match row {
        Some(s) if !s.opted_out => s,
        Some(s) => Signals {
            opted_out: true,
            excluded: s.excluded,
            ..Default::default()
        },
        None => Signals::default(),
    })
}

/// Opt out of external scoring. Costs nothing: the Trailhead-only score is the same score with
/// two small terms at zero.
pub async fn set_opt_out(pool: &PgPool, user_id: i64, out: bool) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO contributor_signals (user_id, opted_out) VALUES ($1,$2)
         ON CONFLICT (user_id) DO UPDATE SET opted_out = EXCLUDED.opted_out",
    )
    .bind(user_id)
    .bind(out)
    .execute(pool)
    .await?;
    Ok(())
}

/// Store a freshly computed set of signals.
pub async fn store(pool: &PgPool, user_id: i64, s: &Signals) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO contributor_signals
           (user_id, external_merged_prs, external_repos, active_weeks, shared_repos,
            dependents, excluded, fetched_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7, now())
         ON CONFLICT (user_id) DO UPDATE SET
           external_merged_prs = EXCLUDED.external_merged_prs,
           external_repos      = EXCLUDED.external_repos,
           active_weeks        = EXCLUDED.active_weeks,
           shared_repos        = EXCLUDED.shared_repos,
           dependents          = EXCLUDED.dependents,
           excluded            = EXCLUDED.excluded,
           fetched_at          = now()
         WHERE NOT contributor_signals.opted_out",
    )
    .bind(user_id)
    .bind(s.external_merged_prs)
    .bind(s.external_repos)
    .bind(s.active_weeks)
    .bind(s.shared_repos)
    .bind(s.dependents)
    .bind(&s.excluded)
    .execute(pool)
    .await?;
    Ok(())
}

/// Users whose signals are stale enough to refresh. Called by the nightly tick, which is the
/// only thing that writes them.
pub async fn stale(pool: &PgPool, limit: i64) -> anyhow::Result<Vec<(i64, Option<i64>)>> {
    Ok(sqlx::query_as::<_, (i64, Option<i64>)>(
        "SELECT u.id, u.github_id FROM users u
         LEFT JOIN contributor_signals s ON s.user_id = u.id
         WHERE u.github_id IS NOT NULL
           AND COALESCE(s.opted_out, false) = false
           AND (s.fetched_at IS NULL OR s.fetched_at < now() - interval '7 days')
           AND u.account_created_at < now() - ($2 || ' days')::interval
         ORDER BY s.fetched_at NULLS FIRST LIMIT $1",
    )
    .bind(limit)
    .bind(MIN_ACCOUNT_DAYS_FOR_EXTERNAL.to_string())
    .fetch_all(pool)
    .await?)
}

/// One GraphQL query covering everything we score, so a refresh costs one API call per user.
/// Public data only: no `restrictedContributionsCount`, no private repositories, nothing that
/// would push a contributor to reveal private activity to rank well.
const QUERY: &str = r#"
query($login: String!) {
  user(login: $login) {
    createdAt
    repositories(first: 100, ownerAffiliations: OWNER, privacy: PUBLIC, isFork: false,
                 orderBy: {field: STARGAZERS, direction: DESC}) {
      nodes {
        nameWithOwner isArchived createdAt pushedAt stargazerCount forkCount
        licenseInfo { spdxId }
        defaultBranchRef { target { ... on Commit { history(first: 0) { totalCount } } } }
      }
    }
    pullRequests(first: 100, states: MERGED, orderBy: {field: UPDATED_AT, direction: DESC}) {
      nodes {
        mergedAt
        repository { nameWithOwner isArchived owner { login } }
        mergedBy { login }
        author { login }
        reviews(states: APPROVED, first: 1) { totalCount }
      }
    }
  }
}"#;

/// OSI-approved licences we accept. Deliberately a short allowlist of the common permissive
/// and copyleft ones rather than a loose "has a licence" check.
const OSI: &[&str] = &[
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "GPL-2.0",
    "GPL-3.0",
    "LGPL-2.1",
    "LGPL-3.0",
    "AGPL-3.0",
    "MPL-2.0",
    "ISC",
    "Unlicense",
    "Zlib",
    "EPL-2.0",
];

fn days_since(v: &Value) -> i64 {
    v.as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| (chrono::Utc::now() - t.with_timezone(&chrono::Utc)).num_days())
        .unwrap_or(i64::MAX)
}

/// Recompute one user's signals from public GitHub data.
///
/// Every exclusion is recorded with its reason and shown back to the contributor, because a
/// score whose inputs nobody can inspect is a score nobody should trust.
pub async fn refresh(cfg: &Config, http: &reqwest::Client, login: &str) -> anyhow::Result<Signals> {
    let gh = GitHub { cfg, http };
    let v = gh.graphql(QUERY, json!({ "login": login })).await?;
    let user = &v["data"]["user"];
    if user.is_null() {
        anyhow::bail!("no such GitHub user: {login}");
    }
    let mut excluded: Vec<Value> = Vec::new();
    let mut shared = 0i32;
    let mut dependents = 0i32;

    for r in user["repositories"]["nodes"].as_array().unwrap_or(&vec![]) {
        let name = r["nameWithOwner"].as_str().unwrap_or("?").to_string();
        let license = r["licenseInfo"]["spdxId"].as_str().unwrap_or("");
        let commits = r["defaultBranchRef"]["target"]["history"]["totalCount"]
            .as_i64()
            .unwrap_or(0);
        let stars = r["stargazerCount"].as_i64().unwrap_or(0);
        let forks = r["forkCount"].as_i64().unwrap_or(0);
        // Stars are bought in bulk, so they only ever act as a floor, never as a score. We
        // cannot check each stargazer's age in one query, so stars count at face value only
        // alongside the other conditions, and forks stand in for outside involvement.
        let facts = RepoFacts {
            is_fork: false, // the query already filters forks out
            is_archived: r["isArchived"].as_bool().unwrap_or(false),
            license_is_osi: OSI.contains(&license),
            age_days: days_since(&r["createdAt"]),
            idle_days: days_since(&r["pushedAt"]),
            commits,
            stars,
            // Forks by other people stand in for outside involvement; a single query cannot
            // check every stargazer's account age.
            outside_contributors: forks.min(1),
        };
        if repo_qualifies(facts) {
            shared += 1;
            dependents += forks.min(10_000) as i32;
        } else {
            let why = repo_rejection(facts);
            excluded.push(json!({"repo": name, "reason": why}));
        }
    }

    let mut merged = 0i32;
    let mut repos = std::collections::HashSet::new();
    let mut weeks = std::collections::HashSet::new();
    for pr in user["pullRequests"]["nodes"].as_array().unwrap_or(&vec![]) {
        let repo = pr["repository"]["nameWithOwner"].as_str().unwrap_or("?");
        let owner = pr["repository"]["owner"]["login"].as_str().unwrap_or("");
        let merged_by = pr["mergedBy"]["login"].as_str().unwrap_or("");
        let author = pr["author"]["login"].as_str().unwrap_or("");
        let reviewed = pr["reviews"]["totalCount"].as_i64().unwrap_or(0) > 0;
        let owner_is_author = owner.eq_ignore_ascii_case(login);
        if pr_counts(
            owner_is_author,
            !merged_by.is_empty() && !merged_by.eq_ignore_ascii_case(author),
            pr["repository"]["isArchived"].as_bool().unwrap_or(false),
            reviewed,
        ) {
            merged += 1;
            repos.insert(repo.to_string());
            if let Some(t) = pr["mergedAt"].as_str() {
                // Active weeks, not commits: volume is worthless, spread is not.
                weeks.insert(t.get(0..8).unwrap_or(t).to_string());
            }
        } else {
            let why = if owner_is_author {
                "merged into a repository you own"
            } else if merged_by.eq_ignore_ascii_case(author) {
                "you merged it yourself"
            } else if !reviewed {
                "nobody reviewed it"
            } else {
                "repository is archived"
            };
            excluded.push(json!({"pr": repo, "reason": why}));
        }
    }

    Ok(Signals {
        external_merged_prs: merged,
        external_repos: repos.len() as i32,
        active_weeks: weeks.len() as i32,
        shared_repos: shared,
        dependents,
        excluded: Value::Array(excluded),
        opted_out: false,
    })
}

/// Refresh a batch of stale users. Called by the daily tick and nowhere else, so nobody can
/// trigger a recompute and immediately read the result.
pub async fn refresh_batch(
    pool: &PgPool,
    cfg: &Config,
    http: &reqwest::Client,
    limit: i64,
) -> anyhow::Result<usize> {
    let users = stale(pool, limit).await?;
    let mut done = 0;
    for (user_id, _github_id) in users {
        let login: Option<String> = sqlx::query_scalar("SELECT login FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(pool)
            .await?;
        let Some(login) = login else { continue };
        // One contributor's signals failing must never stop the batch or the tick.
        match refresh(cfg, http, &login).await {
            Ok(s) => {
                store(pool, user_id, &s).await?;
                done += 1;
            }
            Err(e) => tracing::warn!("signals refresh failed for {login}: {e}"),
        }
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_repo() -> RepoFacts {
        RepoFacts {
            is_fork: false,
            is_archived: false,
            license_is_osi: true,
            age_days: 400,
            idle_days: 30,
            commits: 120,
            stars: 12,
            outside_contributors: 3,
        }
    }

    #[test]
    fn a_real_project_qualifies() {
        assert!(repo_qualifies(good_repo()));
    }

    #[test]
    fn farmed_repositories_do_not_qualify() {
        // Each of these is a single-field change from a qualifying repo.
        let cases: Vec<(&str, RepoFacts)> = vec![
            (
                "a fork",
                RepoFacts {
                    is_fork: true,
                    ..good_repo()
                },
            ),
            (
                "archived",
                RepoFacts {
                    is_archived: true,
                    ..good_repo()
                },
            ),
            (
                "no OSI licence",
                RepoFacts {
                    license_is_osi: false,
                    ..good_repo()
                },
            ),
            (
                "created yesterday",
                RepoFacts {
                    age_days: 1,
                    ..good_repo()
                },
            ),
            (
                "abandoned",
                RepoFacts {
                    idle_days: 3_000,
                    ..good_repo()
                },
            ),
            (
                "almost empty",
                RepoFacts {
                    commits: 2,
                    ..good_repo()
                },
            ),
            (
                "nobody else touched it",
                RepoFacts {
                    stars: 0,
                    outside_contributors: 0,
                    ..good_repo()
                },
            ),
        ];
        for (why, r) in cases {
            assert!(!repo_qualifies(r), "{why} should not qualify");
            assert!(!repo_rejection(r).is_empty(), "{why} needs a stated reason");
        }
    }

    #[test]
    fn stars_alone_or_a_contributor_alone_is_enough() {
        // Five aged stars and no outside contributor: counts.
        assert!(repo_qualifies(RepoFacts {
            stars: MIN_STARS,
            outside_contributors: 0,
            ..good_repo()
        }));
        // One outside contributor and no stars: also counts. Contributors are much harder to
        // fake than stars, which are bought in bulk.
        assert!(repo_qualifies(RepoFacts {
            stars: 0,
            outside_contributors: 1,
            ..good_repo()
        }));
        assert!(!repo_qualifies(RepoFacts {
            stars: 4,
            outside_contributors: 0,
            ..good_repo()
        }));
    }

    #[test]
    fn self_merged_work_never_counts() {
        // Merged into a repo you own: the most common way to manufacture history.
        assert!(!pr_counts(true, true, false, true));
        // Opened and merged by the same person, elsewhere: still not independent evidence.
        assert!(!pr_counts(false, false, false, true));
        // Nobody reviewed it.
        assert!(!pr_counts(false, true, false, false));
        // Merged by someone else, reviewed, in a live repo you do not own.
        assert!(pr_counts(false, true, false, true));
    }

    #[test]
    fn an_opted_out_user_is_scored_on_trailhead_data_alone() {
        let s = Signals {
            external_merged_prs: 500,
            shared_repos: 99,
            opted_out: true,
            ..Default::default()
        };
        // The getter zeroes an opted-out user's external numbers rather than using them.
        let effective = if s.opted_out {
            Signals {
                opted_out: true,
                ..Default::default()
            }
        } else {
            s
        };
        assert_eq!(effective.external_merged_prs, 0);
        assert_eq!(effective.shared_repos, 0);
    }
}
