//! The permission set of a GitHub token request: fixed when the request is created,
//! stored with it, and checked against what the App's installation holds each time
//! the approval page is rendered or approved.

use sqlx::sqlite::SqliteRow;
use sqlx::{Row as _, SqliteConnection};
use warden_broker_proto::github_permissions::{Permission, PermissionSet};
use warden_broker_proto::github_token::{
    EXTRA_NOT_ALLOWED, INSTALLATION_LACKS, INSTALLATION_UNREADABLE,
};
use warden_broker_proto::{Access, GrantAccess, Id};

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
}

/// The extras, in name order, that the owner's allowlist does not hold at the level
/// asked or higher. `metadata:read`, which every set has, is never one.
pub(super) fn refused_extras(
    extras: &PermissionSet,
    policy: &GithubPermissionPolicy,
) -> Vec<Permission> {
    extras
        .iter()
        .filter(|p| p.name() != "metadata" && !policy.allowed_extras.covers(p))
        .collect()
}

/// The first of `extras`, in name order, that the owner's allowlist does not hold
/// at the level asked or higher (see [`refused_extras`]).
///
/// # Errors
/// The permission refused.
pub(super) fn check_extras(
    extras: &PermissionSet,
    policy: &GithubPermissionPolicy,
) -> Result<(), Permission> {
    match refused_extras(extras, policy).into_iter().next() {
        Some(refused) => Err(refused),
        None => Ok(()),
    }
}

/// The refusal of `refused`, a permission [`check_extras`] returned: a fixed text
/// and the known permission name, with the level the allowlist holds when it
/// holds the name at a lower one.
pub(super) fn not_allowed_text(refused: &Permission, policy: &GithubPermissionPolicy) -> String {
    let held = policy
        .allowed_extras
        .iter()
        .find(|p| p.name() == refused.name());
    match held {
        Some(held) => format!(
            "{EXTRA_NOT_ALLOWED}{refused} (only {} is allowed)",
            held.level()
        ),
        None => format!("{EXTRA_NOT_ALLOWED}{refused}"),
    }
}

/// The extras the GitHub token grant in `row` (its `view` column) was approved with,
/// for its renewal. They are read strictly, so a stored name this version no longer
/// knows refuses the renewal instead of dropping the extra.
///
/// # Errors
/// [`RequestError::Corrupt`] for a view that does not parse, is not a GitHub token
/// grant, or holds extras that do not parse as a permission set.
pub(super) fn grant_extras(row: &SqliteRow) -> Result<Option<PermissionSet>, RequestError> {
    let view: String = row.try_get("view")?;
    let GrantAccess::GithubToken(grant) = super::stored_view(&view)?.access else {
        return Err(RequestError::Corrupt(
            "GitHub token grant changed kind".to_owned(),
        ));
    };
    super::github_extras_of(&grant)
}

/// The part of a pending request's dedupe key that tells its extra permissions: their
/// written form, or `none`. A request and a renewal build it the same way, so each
/// agent has one pending request per repositories and extras, whatever the default.
pub(super) fn extras_slot(extras: Option<&PermissionSet>) -> String {
    extras.map_or_else(|| "none".to_owned(), ToString::to_string)
}

/// What a grant holds when the agent asked for `extras` on top of `default`: both
/// together, with the extras the default did not cover noted as beyond it.
pub(super) fn full_set(
    default: &PermissionSet,
    extras: Option<&PermissionSet>,
) -> StoredPermissions {
    let Some(extras) = extras else {
        return StoredPermissions {
            full: default.clone(),
            beyond_default: Vec::new(),
        };
    };
    let full = default.union(extras);
    let beyond_default = full.extras_beyond(default).iter().collect();
    StoredPermissions {
        full,
        beyond_default,
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
    /// call that leaves the App's private key unread: the owner's default, and the
    /// extras the agent named.
    ///
    /// # Errors
    /// What the backend says, as [`RequestError`]: a request is refused when the
    /// App or its permission fields cannot be used. [`RequestError::Rejected`], with
    /// a fixed text and the permission's name, for an extra the owner's allowlist
    /// does not hold: the owner is not asked.
    pub(super) async fn new_github_permissions(
        &self,
        extras: Option<&PermissionSet>,
    ) -> Result<StoredPermissions, RequestError> {
        let policy = self.backend.github_permissions().await?;
        if let Some(extras) = extras
            && let Err(refused) = check_extras(extras, &policy)
        {
            return Err(RequestError::Rejected(not_allowed_text(&refused, &policy)));
        }
        Ok(full_set(&policy.default, extras))
    }

    /// The permissions a renewal of a grant to `access` gets: the owner's current
    /// default and the extras `access` names, so that renewals follow the default
    /// and a narrowed default never strands a grant stored before permission sets. The
    /// extras are not checked against the allowlist, so that the approval page can
    /// say which one is no longer allowed. `None` for access that holds no GitHub
    /// token permissions.
    ///
    /// # Errors
    /// What the backend says, as [`RequestError`].
    pub(super) async fn renewal_permissions(
        &self,
        access: &Access,
    ) -> Result<Option<StoredPermissions>, RequestError> {
        match access {
            Access::GithubToken(github) => {
                // The allowlist is not asked here: a renewal whose extras it no
                // longer holds is created, and its page says which one.
                let policy = self.backend.github_permissions().await?;
                Ok(Some(full_set(
                    &policy.default,
                    github.extra_permissions.as_ref(),
                )))
            }
            _ => Ok(None),
        }
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

    fn policy(default: &str, allowed: &str) -> GithubPermissionPolicy {
        GithubPermissionPolicy {
            default: PermissionSet::parse(default).unwrap(),
            allowed_extras: PermissionSet::parse(allowed).unwrap(),
        }
    }

    fn extras(text: &str) -> PermissionSet {
        PermissionSet::parse(text).unwrap()
    }

    #[test]
    fn extras_must_be_listed_at_the_level_asked_or_higher() {
        let owner = policy("contents:write", "checks:read,actions:write");
        assert_eq!(check_extras(&extras("checks:read"), &owner), Ok(()));
        assert_eq!(check_extras(&extras("actions:read"), &owner), Ok(()));
        let refused =
            check_extras(&extras("actions:read,checks:write,issues:read"), &owner).unwrap_err();
        assert_eq!(refused.to_string(), "checks:write");
        let refused = check_extras(&extras("workflows:write"), &owner).unwrap_err();
        assert_eq!(refused.to_string(), "workflows:write");
    }

    #[test]
    fn refused_extras_lists_every_one_in_name_order() {
        let owner = policy("contents:write", "checks:read");
        let refused = refused_extras(&extras("checks:write,actions:read,issues:read"), &owner);
        let written: Vec<String> = refused.iter().map(ToString::to_string).collect();
        assert_eq!(written, ["actions:read", "checks:write", "issues:read"]);
        assert_eq!(
            refused_extras(&extras("checks:read"), &owner),
            Vec::<Permission>::new()
        );
    }

    #[test]
    fn refusal_names_the_permission_and_the_level_held() {
        let owner = policy("contents:write", "checks:read");
        assert_eq!(
            not_allowed_text(&"checks:write".parse().unwrap(), &owner),
            format!("{EXTRA_NOT_ALLOWED}checks:write (only read is allowed)")
        );
        assert_eq!(
            not_allowed_text(&"workflows:write".parse().unwrap(), &owner),
            format!("{EXTRA_NOT_ALLOWED}workflows:write")
        );
    }

    #[test]
    fn full_set_is_the_default_with_the_extras_it_lacks_marked() {
        let default = extras("contents:write,issues:read");
        let none = full_set(&default, None);
        assert_eq!(none.full, default);
        assert_eq!(none.beyond_default, Vec::<Permission>::new());
        let stored = full_set(&default, Some(&extras("checks:read,issues:read")));
        assert_eq!(
            stored.full.to_string(),
            "checks:read,contents:write,issues:read,metadata:read"
        );
        assert_eq!(written(&stored.beyond_default), "checks:read");
        let raised = full_set(&default, Some(&extras("issues:write")));
        assert_eq!(written(&raised.beyond_default), "issues:write");
        assert_eq!(
            raised.full.to_string(),
            "contents:write,issues:write,metadata:read"
        );
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
