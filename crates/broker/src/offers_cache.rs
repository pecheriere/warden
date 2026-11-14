//! The answers of `GET /v1/offers/repository/{owner}/{name}`, kept in memory for a
//! few minutes so that repeated `warden prime` runs in one checkout do not each
//! mint a token to ask GitHub. An answer that could not be told is not kept.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use warden_broker_proto::offers::{GithubTokenStatus, ReleaseStatus, RepositoryOffer};
use warden_broker_proto::release::RepoName;

/// The most answers kept at once.
const MAX_ENTRIES: usize = 256;

/// Recent answers per repository, each with the time it was stored.
#[derive(Debug, Default)]
pub struct RepositoryOfferCache {
    entries: Mutex<HashMap<RepoName, (i64, RepositoryOffer)>>,
}

impl RepositoryOfferCache {
    /// How long an answer is kept, in seconds.
    pub const TTL_SECS: i64 = 300;

    /// An empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The cached answer if stored less than [`Self::TTL_SECS`] before `now`.
    pub fn get(&self, repo: &RepoName, now: i64) -> Option<RepositoryOffer> {
        let entries = self.lock();
        entries
            .get(repo)
            .filter(|(stored, _)| fresh(*stored, now))
            .map(|(_, offer)| offer.clone())
    }

    /// Stores `offer` unless its `github_token` or `release` is `Unavailable`.
    pub fn put(&self, offer: RepositoryOffer, now: i64) {
        if offer.github_token == GithubTokenStatus::Unavailable
            || offer.release == ReleaseStatus::Unavailable
        {
            return;
        }
        let mut entries = self.lock();
        if !entries.contains_key(&offer.repository) && entries.len() >= MAX_ENTRIES {
            entries.retain(|_, (stored, _)| fresh(*stored, now));
            if entries.len() >= MAX_ENTRIES {
                let oldest = entries
                    .iter()
                    .min_by_key(|(_, (stored, _))| *stored)
                    .map(|(repo, _)| repo.clone());
                if let Some(oldest) = oldest {
                    entries.remove(&oldest);
                }
            }
        }
        entries.insert(offer.repository.clone(), (now, offer));
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<RepoName, (i64, RepositoryOffer)>> {
        // Each step under the lock leaves the map whole, so a panic elsewhere
        // while it was held cannot have left a half-written entry behind.
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Whether an answer stored at `stored` may still be given at `now`. One stored
/// "in the future", after the clock went back, is not.
fn fresh(stored: i64, now: i64) -> bool {
    (0..RepositoryOfferCache::TTL_SECS).contains(&now.saturating_sub(stored))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn repo(name: &str) -> RepoName {
        RepoName::try_from(format!("example-org/{name}")).unwrap()
    }

    fn offer(name: &str) -> RepositoryOffer {
        RepositoryOffer {
            repository: repo(name),
            github_token: GithubTokenStatus::Covered,
            commit_signing: true,
            release: ReleaseStatus::NoKey,
        }
    }

    #[test]
    fn fresh_answer_is_returned() {
        let cache = RepositoryOfferCache::new();
        cache.put(offer("example-repo"), NOW);
        assert_eq!(
            cache.get(&repo("example-repo"), NOW + 299),
            Some(offer("example-repo"))
        );
        assert_eq!(cache.get(&repo("other-repo"), NOW), None);
    }

    #[test]
    fn answer_expires_after_ttl() {
        let cache = RepositoryOfferCache::new();
        cache.put(offer("example-repo"), NOW);
        assert_eq!(cache.get(&repo("example-repo"), NOW + 300), None);
        // Nor is one given after the clock went back.
        assert_eq!(cache.get(&repo("example-repo"), NOW - 1), None);
    }

    #[test]
    fn unavailable_is_not_cached() {
        let cache = RepositoryOfferCache::new();
        let mut github = offer("github");
        github.github_token = GithubTokenStatus::Unavailable;
        let mut release = offer("release");
        release.release = ReleaseStatus::Unavailable;
        cache.put(github, NOW);
        cache.put(release, NOW);
        assert_eq!(cache.get(&repo("github"), NOW), None);
        assert_eq!(cache.get(&repo("release"), NOW), None);
        // The other answers that are not "covered" or "ready" are kept.
        let mut not_covered = offer("not-covered");
        not_covered.github_token = GithubTokenStatus::NotCovered;
        cache.put(not_covered.clone(), NOW);
        assert_eq!(cache.get(&repo("not-covered"), NOW), Some(not_covered));
    }

    #[test]
    fn map_is_bounded() {
        let cache = RepositoryOfferCache::new();
        let full = i64::try_from(MAX_ENTRIES).unwrap();
        for i in 0..full {
            cache.put(offer(&format!("repo-{i}")), NOW + i);
        }
        // Full and nothing expired: the oldest goes.
        cache.put(offer("newest"), NOW + full);
        assert_eq!(cache.lock().len(), MAX_ENTRIES);
        assert_eq!(cache.get(&repo("repo-0"), NOW + full), None);
        assert!(cache.get(&repo("repo-1"), NOW + full).is_some());
        assert!(cache.get(&repo("newest"), NOW + full).is_some());

        // Full with expired entries: all of them go, and nothing fresh does.
        let later = NOW + RepositoryOfferCache::TTL_SECS + 10;
        cache.put(offer("after-expiry"), later);
        let left = cache.lock().len();
        assert!(left < MAX_ENTRIES, "{left}");
        assert!(cache.get(&repo("after-expiry"), later).is_some());
        assert!(cache.get(&repo("newest"), later).is_some());

        // Replacing an entry that is there drops nothing.
        let before = cache.lock().len();
        cache.put(offer("newest"), later);
        assert_eq!(cache.lock().len(), before);
    }
}
