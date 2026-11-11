//! Ordering release tags by semantic versioning, to find the tag before one.

use std::cmp::Ordering;

use warden_broker_proto::release::ReleaseTag;

/// The highest tag in `tags` that is below `tag` by semver precedence, if any.
pub(super) fn previous<'a>(tag: &ReleaseTag, tags: &'a [ReleaseTag]) -> Option<&'a ReleaseTag> {
    tags.iter()
        .filter(|other| compare(other, tag) == Ordering::Less)
        .max_by(|a, b| compare(a, b))
}

/// Semver precedence of two tags (build metadata is not part of the pattern).
fn compare(a: &ReleaseTag, b: &ReleaseTag) -> Ordering {
    let (core_a, pre_a) = split(a);
    let (core_b, pre_b) = split(b);
    core_a
        .iter()
        .zip(&core_b)
        .map(|(x, y)| numeric(x, y))
        .find(|order| order.is_ne())
        .unwrap_or_else(|| match (pre_a, pre_b) {
            (None, None) => Ordering::Equal,
            // A release is above its own pre-releases.
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(x), Some(y)) => prerelease(x, y),
        })
}

/// The three numbers of the version, and the pre-release part.
fn split(tag: &ReleaseTag) -> ([&str; 3], Option<&str>) {
    let version = tag.version();
    let (core, pre) = match version.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (version, None),
    };
    let mut numbers = core.split('.');
    let mut next = || numbers.next().unwrap_or("0");
    ([next(), next(), next()], pre)
}

/// Compare two digit strings without parsing them, so no length overflows.
fn numeric(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.trim_start_matches('0'), b.trim_start_matches('0'));
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

fn prerelease(a: &str, b: &str) -> Ordering {
    let digits = |s: &str| s.bytes().all(|c| c.is_ascii_digit());
    let mut left = a.split('.');
    let mut right = b.split('.');
    loop {
        match (left.next(), right.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) => {
                let order = match (digits(x), digits(y)) {
                    (true, true) => numeric(x, y),
                    (true, false) => Ordering::Less,
                    (false, true) => Ordering::Greater,
                    (false, false) => x.cmp(y),
                };
                if order.is_ne() {
                    return order;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::previous;
    use warden_broker_proto::release::ReleaseTag;

    fn tags(names: &[&str]) -> Vec<ReleaseTag> {
        names
            .iter()
            .map(|n| ReleaseTag::try_from((*n).to_owned()).unwrap())
            .collect()
    }

    fn before(tag: &str, others: &[&str]) -> Option<String> {
        let tag = ReleaseTag::try_from(tag.to_owned()).unwrap();
        previous(&tag, &tags(others)).map(ToString::to_string)
    }

    #[test]
    fn picks_the_highest_below() {
        assert_eq!(
            before("v1.2.3", &["v1.0.0", "v1.2.2", "v1.3.0", "v1.2.3"]),
            Some("v1.2.2".to_owned())
        );
        assert_eq!(before("v1.2.3", &["v1.3.0"]), None);
        assert_eq!(before("v1.2.3", &[]), None);
    }

    #[test]
    fn compares_numbers_not_text() {
        assert_eq!(
            before("v1.10.0", &["v1.9.0", "v1.2.0"]),
            Some("v1.9.0".to_owned())
        );
        assert_eq!(
            before("v10.0.0", &["v9.99.99", "v2.0.0"]),
            Some("v9.99.99".to_owned())
        );
    }

    #[test]
    fn a_release_is_above_its_prereleases() {
        assert_eq!(
            before("v1.0.0", &["v1.0.0-rc.1", "v0.9.0"]),
            Some("v1.0.0-rc.1".to_owned())
        );
        assert_eq!(
            before("v1.0.0-rc.2", &["v1.0.0-rc.1", "v1.0.0-beta.11", "v1.0.0"]),
            Some("v1.0.0-rc.1".to_owned())
        );
        assert_eq!(
            before("v1.0.0-rc.10", &["v1.0.0-rc.9", "v1.0.0-rc.2"]),
            Some("v1.0.0-rc.9".to_owned())
        );
    }
}
