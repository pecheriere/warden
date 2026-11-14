//! The permission set of a GitHub token request: fixed when the request is created,
//! stored with it, and checked against what the App's installation holds each time
//! the approval page is rendered or approved.

use sqlx::{Row as _, SqliteConnection};
use warden_broker_proto::Id;
use warden_broker_proto::github_permissions::{Permission, PermissionSet};
use warden_broker_proto::github_token::{INSTALLATION_LACKS, INSTALLATION_UNREADABLE};

use super::{RequestError, Requests};
use crate::github_app;
use crate::policy::GithubPermissionPolicy;

/// The permissions a GitHub token request was created with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPermissions {
    /// What the grant will hold: the owner's default when the request was created,
    /// plus its extras.
    pub full: PermissionSet,
    /// The extras the default did not cover then, in name order, never
    /// `metadata:read`.
    pub beyond_default: Vec<Permission>,
}

impl StoredPermissions {
    /// What a request stored before permission sets means: the legacy set, nothing
    /// beyond it.
    #[must_use]
    pub fn legacy() -> Self {
        Self {
            full: PermissionSet::legacy(),
            beyond_default: Vec::new(),
        }
    }

    /// What a new request asking for no extras gets: the owner's default.
    pub(super) fn of_default(policy: &GithubPermissionPolicy) -> Self {
        Self {
            full: policy.default.clone(),
            beyond_default: Vec::new(),
        }
    }
}

/// Whether the App's installation holds every permission of a request, read from
/// GitHub at each render: a precondition of approval, not part of what it binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallationCheck {
    /// It holds all of them at the level asked or higher.
    Holds,
    /// It lacks these, in name order.
    Missing(Vec<Permission>),
    /// GitHub could not say.
    Unreadable,
}

impl InstallationCheck {
    /// Why a request is not approved under this check, if it is not: a fixed text,
    /// followed for [`Self::Missing`] by the missing permissions' written form.
    #[must_use]
    pub fn refusal(&self) -> Option<String> {
        match self {
            Self::Holds => None,
            Self::Missing(missing) => Some(format!("{INSTALLATION_LACKS}{}", written(missing))),
            Self::Unreadable => Some(INSTALLATION_UNREADABLE.to_owned()),
        }
    }
}

/// `list` as `name:level` joined with `,`: the empty string when it is empty.
fn written(list: &[Permission]) -> String {
    list.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// A stored row that is not what this module writes.
fn corrupt(id: &Id, what: &str) -> RequestError {
    RequestError::Corrupt(format!("the stored permissions of request {id}: {what}"))
}

/// Read `full` and `beyond_default` as [`store`] wrote them for request `id`. Each
/// must be in its written form, and every extra must be in the full set.
fn parse_stored(id: &Id, full: &str, beyond: &str) -> Result<StoredPermissions, RequestError> {
    let set = PermissionSet::parse(full).map_err(|e| corrupt(id, &e.to_string()))?;
    if set.to_string() != full {
        return Err(corrupt(id, "the set is not in its written form"));
    }
    let beyond_default = if beyond.is_empty() {
        Vec::new()
    } else {
        beyond
            .split(',')
            .map(|entry| {
                entry
                    .parse::<Permission>()
                    .map_err(|e| corrupt(id, &e.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    let ordered = beyond_default
        .windows(2)
        .all(|pair| pair[0].name() < pair[1].name());
    if !ordered
        || written(&beyond_default) != beyond
        || beyond_default
            .iter()
            .any(|p| p.name() == "metadata" || !set.covers(p))
    {
        return Err(corrupt(id, "the extras are not in the set's written form"));
    }
    Ok(StoredPermissions {
        full: set,
        beyond_default,
    })
}

/// Store `permissions` for request `id`, in the caller's transaction.
pub(super) async fn store(
    conn: &mut SqliteConnection,
    id: &Id,
    permissions: &StoredPermissions,
) -> Result<(), RequestError> {
    sqlx::query(
        "INSERT INTO github_permissions (request_id, permissions, beyond_default) \
         VALUES (?, ?, ?)",
    )
    .bind(id.as_str())
    .bind(permissions.full.to_string())
    .bind(written(&permissions.beyond_default))
    .execute(conn)
    .await?;
    Ok(())
}

impl Requests {
    /// The permissions request `id` was created with. A request with none stored
    /// was made before permission sets, and means the legacy set.
    ///
    /// # Errors
    /// [`RequestError::Corrupt`] for a stored row that does not parse; storage
    /// failures.
    pub async fn stored_permissions(&self, id: &Id) -> Result<StoredPermissions, RequestError> {
        let Some(row) = sqlx::query(
            "SELECT permissions, beyond_default FROM github_permissions WHERE request_id = ?",
        )
        .bind(id.as_str())
        .fetch_optional(&self.pool)
        .await?
        else {
            return Ok(StoredPermissions::legacy());
        };
        let full: String = row.try_get("permissions")?;
        let beyond: String = row.try_get("beyond_default")?;
        parse_stored(id, &full, &beyond)
    }

    /// The permissions a new GitHub token request gets, read through the backend
    /// call that leaves the App's private key unread. PR A takes no extras: the
    /// owner's default.
    ///
    /// # Errors
    /// What the backend says, as [`RequestError`]: a request is refused when the
    /// App or its permission fields cannot be used.
    pub(super) async fn new_github_permissions(&self) -> Result<StoredPermissions, RequestError> {
        let policy = self.backend.github_permissions().await?;
        Ok(StoredPermissions::of_default(&policy))
    }

    /// Whether the App's installation holds every permission of `wanted`, asking
    /// GitHub now.
    ///
    /// # Errors
    /// The backend's, when the App cannot be read; GitHub's failures are
    /// [`InstallationCheck::Unreadable`].
    pub(super) async fn installation_check(
        &self,
        wanted: &PermissionSet,
    ) -> Result<InstallationCheck, RequestError> {
        let key = self.backend.github_app().await?;
        match github_app::installation_permissions(&self.github, &key, self.clock.now()).await {
            Ok(held) => {
                let missing = held.missing(wanted);
                Ok(if missing.is_empty() {
                    InstallationCheck::Holds
                } else {
                    InstallationCheck::Missing(missing)
                })
            }
            Err(e) => {
                // The text of a `MintError` is fixed: nothing GitHub said is in it.
                tracing::warn!(error = %e, "GitHub could not say what the App's installation holds");
                Ok(InstallationCheck::Unreadable)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> Id {
        Id::random()
    }

    #[test]
    fn stored_form_reads_back() {
        let stored = parse_stored(
            &id(),
            "checks:read,contents:write,metadata:read",
            "checks:read",
        )
        .unwrap();
        assert_eq!(
            stored.full.to_string(),
            "checks:read,contents:write,metadata:read"
        );
        assert_eq!(written(&stored.beyond_default), "checks:read");
        let none = parse_stored(&id(), "contents:write,metadata:read", "").unwrap();
        assert_eq!(none.beyond_default, Vec::<Permission>::new());
    }

    #[test]
    fn rows_not_in_written_form_are_corrupt() {
        for (full, beyond) in [
            ("contents:admin", ""),
            ("", ""),
            ("contents:write", ""),
            ("metadata:read,contents:write", ""),
            ("contents:write,metadata:read", "checks:read"),
            (
                "checks:read,contents:write,metadata:read",
                "contents:write,checks:read",
            ),
            ("checks:read,contents:write,metadata:read", "metadata:read"),
            ("checks:read,contents:write,metadata:read", "checks:read,"),
            ("checks:read,metadata:read", "checks:write"),
        ] {
            assert!(
                matches!(
                    parse_stored(&id(), full, beyond),
                    Err(RequestError::Corrupt(_))
                ),
                "{full:?} / {beyond:?}"
            );
        }
    }

    #[test]
    fn refusals_are_fixed_texts() {
        let missing = InstallationCheck::Missing(vec!["checks:read".parse().unwrap()]);
        assert_eq!(
            missing.refusal().unwrap(),
            format!("{INSTALLATION_LACKS}checks:read")
        );
        assert_eq!(
            InstallationCheck::Unreadable.refusal().unwrap(),
            INSTALLATION_UNREADABLE
        );
        assert_eq!(InstallationCheck::Holds.refusal(), None);
    }
}
