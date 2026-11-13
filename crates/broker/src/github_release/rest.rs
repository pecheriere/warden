//! The calls a release needs, as methods of [`ReleaseClient`]: read a commit,
//! its branch, its changelog and the tag and release for a name, then create the
//! tag object and ref, upload and delete assets, and publish.
//!
//! A path is built segment by segment (see `endpoint`), so a tag or a branch
//! cannot add a segment to it. Nothing GitHub says is returned unchecked: ids,
//! digests and names are validated, and a commit's title is cut and stripped of
//! control and direction-changing characters, because it is shown to the owner.

use http::{Method, StatusCode};
use secrecy::ExposeSecret as _;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::json;
use url::Url;
use warden_broker_proto::release::{CommitId, ReleaseTag};
use zeroize::Zeroizing;

use super::tag_object::{self, GitTagResponse};
use super::{Call, GithubError, ReleaseClient, call, endpoint};
use crate::github_http::{self, Payload};

/// The longest commit title returned, in characters.
const MAX_TITLE_CHARS: usize = 200;
/// The longest part of a changelog returned, in bytes.
const MAX_CHANGELOG_BYTES: usize = 16 * 1024;
/// The largest changelog and release list read.
const MAX_LARGE_BYTES: usize = 1024 * 1024;
/// The marker after a changelog section that was cut.
const CUT: &str = "\n…(cut)";
/// How many tags `release_tags` asks for.
const TAGS_PER_PAGE: &str = "100";
/// The most releases asked for in one page; see [`ReleaseClient::release_for_tag`].
const RELEASES_PER_PAGE: &str = "20";

/// A commit's title and date, for the owner to read before approving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitInfo {
    /// The first line of the message, at most 200 characters, without control
    /// characters.
    pub title: String,
    /// When it was committed, as `YYYY-MM-DDTHH:MM:SSZ`.
    pub date: String,
}

/// A tag that already exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingTag {
    /// What the tag ref points at: a commit for a lightweight tag, a tag object
    /// for an annotated one.
    pub object_sha: String,
    /// The commit the tag ends at, when it is one.
    pub commit: Option<CommitId>,
    /// The tag object's bytes, for an annotated tag whose rebuilt bytes hash to
    /// `object_sha`; `None` for a lightweight tag and when they do not.
    pub raw: Option<Vec<u8>>,
}

/// The tag object to create: an annotated tag on a commit, with the signature
/// already at the end of the message.
#[derive(Debug, Clone)]
pub struct CreateTag {
    /// The tag's name.
    pub tag: ReleaseTag,
    /// The message, signature block included.
    pub message: String,
    /// The commit.
    pub object: CommitId,
    /// The tagger's name.
    pub tagger_name: String,
    /// The tagger's email address.
    pub tagger_email: String,
    /// When the tag was made; seconds only. It goes out in UTC, so the tag
    /// object's time zone is `+0000`.
    pub tagged_at: jiff::Timestamp,
}

/// A release, as the list of a repository's releases shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// Its id.
    pub id: u64,
    /// Whether it is a draft.
    pub draft: bool,
    /// Its assets.
    pub assets: Vec<Asset>,
}

/// A file attached to a release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    /// Its id.
    pub id: u64,
    /// Its name: `[A-Za-z0-9._+-]`, at most 255 characters.
    pub name: String,
    /// `sha256:` and 64 lowercase hexadecimal characters, when GitHub reports it.
    pub digest: Option<String>,
}

#[derive(Deserialize)]
struct CommitAnswer {
    sha: String,
    message: String,
    committer: Committer,
}

#[derive(Deserialize)]
struct Committer {
    date: String,
}

#[derive(Deserialize)]
struct RepositoryAnswer {
    default_branch: String,
}

#[derive(Deserialize)]
struct CompareAnswer {
    status: String,
}

#[derive(Deserialize)]
struct TagName {
    name: String,
}

#[derive(Deserialize)]
struct RefAnswer {
    #[serde(rename = "ref")]
    name: String,
    object: ObjectAnswer,
}

#[derive(Deserialize)]
struct ObjectAnswer {
    sha: String,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Deserialize)]
struct CreatedTagAnswer {
    sha: String,
}

#[derive(Deserialize)]
struct ReleaseAnswer {
    id: u64,
    tag_name: String,
    draft: bool,
    assets: serde_json::Value,
}

#[derive(Deserialize)]
struct AssetAnswer {
    id: u64,
    name: String,
    digest: Option<String>,
}

#[derive(Deserialize)]
struct PublishedAnswer {
    id: u64,
    draft: bool,
}

impl TryFrom<AssetAnswer> for Asset {
    type Error = GithubError;

    fn try_from(answer: AssetAnswer) -> Result<Self, GithubError> {
        let name_ok = is_asset_name(&answer.name);
        let digest_ok = answer.digest.as_ref().is_none_or(|digest| {
            digest.strip_prefix("sha256:").is_some_and(|hex| {
                hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            })
        });
        if name_ok && digest_ok {
            Ok(Self {
                id: answer.id,
                name: answer.name,
                digest: answer.digest,
            })
        } else {
            Err(GithubError::Unreadable)
        }
    }
}

/// Whether `name` is an asset name warden accepts: 1 to 255 characters from
/// letters, digits and `. _ + -`, and not `.` or `..`.
fn is_asset_name(name: &str) -> bool {
    (1..=255).contains(&name.len())
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
}

fn parse<T: DeserializeOwned>(raw: &[u8]) -> Result<T, GithubError> {
    serde_json::from_slice(raw).map_err(|_| GithubError::Unreadable)
}

/// `sha` if it is an object id GitHub could host: 40 lowercase hexadecimal
/// characters.
fn object_id(sha: String) -> Result<String, GithubError> {
    CommitId::try_from(sha)
        .map(String::from)
        .map_err(|_| GithubError::Unreadable)
}

/// Characters that hide or reorder text without showing: zero-width and
/// direction-changing ones.
const fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}'
    )
}

/// The first line of `message`, shown as one line of plain text.
fn title(message: &str) -> String {
    message
        .lines()
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control() && !is_invisible(*c))
        .take(MAX_TITLE_CHARS)
        .collect()
}

/// Whether `name` is a branch name that is safe to put in a ref path, one segment
/// per component: no control or space characters, none of git's forbidden ones,
/// no `..`, `@{` or empty component, no component starting with `.`, and not
/// ending with `/` or `.`.
fn is_plain_branch(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with(['/', '.'])
        && !name.ends_with(['/', '.'])
        && !name.contains("..")
        && !name.contains("@{")
        && !name.contains("//")
        && !name.contains("/.")
        && name
            .chars()
            .all(|c| !c.is_control() && !" ~^:?*[\\".contains(c))
}

/// A section of the changelog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangelogSection {
    /// The section's text, followed by a marker when it was cut.
    pub text: String,
    /// Whether the section was longer than 16 KiB and was cut.
    pub cut: bool,
}

/// The lines of `changelog` after the `## [<version>]` heading and before the
/// next `## ` heading, at most 16 KiB, or `None` when there is no such heading
/// or nothing under it.
fn section(changelog: &str, version: &str) -> Option<ChangelogSection> {
    let heading = format!("## [{version}]");
    let mut lines = changelog.lines();
    lines.find(|line| line.starts_with(&heading))?;
    let body: Vec<&str> = lines.take_while(|line| !line.starts_with("## ")).collect();
    let text = body.join("\n");
    let text = text.trim_matches(['\n', '\r']).trim_end();
    if text.is_empty() {
        return None;
    }
    if text.len() <= MAX_CHANGELOG_BYTES {
        return Some(ChangelogSection {
            text: text.to_owned(),
            cut: false,
        });
    }
    let mut end = MAX_CHANGELOG_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    Some(ChangelogSection {
        text: format!("{}{CUT}", &text[..end]),
        cut: true,
    })
}

impl ReleaseClient<'_> {
    /// `<base>/repos/<owner>/<name>/<rest...>`.
    fn url(&self, base: &Url, rest: &[&str]) -> Result<Url, GithubError> {
        let mut segments = vec!["repos", self.repo.owner(), self.repo.name()];
        segments.extend_from_slice(rest);
        endpoint(base, &segments)
    }

    /// `rest` under the API, with these query parameters.
    fn api_url(&self, rest: &[&str], query: &[(&str, &str)]) -> Result<Url, GithubError> {
        let mut url = self.url(self.api.base(), rest)?;
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }
        Ok(url)
    }

    async fn send(&self, request: Call) -> Result<Zeroizing<Vec<u8>>, GithubError> {
        call(self.api, self.token.token.expose_secret(), request).await
    }

    /// A good answer to a `GET` of `rest`, as JSON.
    async fn get<T: DeserializeOwned>(
        &self,
        rest: &[&str],
        query: &[(&str, &str)],
    ) -> Result<T, GithubError> {
        let url = self.api_url(rest, query)?;
        let request = Call::json(Method::GET, url, Payload::Empty, StatusCode::OK);
        parse(&self.send(request).await?)
    }

    /// A good answer to a `POST` of `body` to `rest`, as JSON.
    async fn post<T: DeserializeOwned>(
        &self,
        rest: &[&str],
        body: &serde_json::Value,
    ) -> Result<T, GithubError> {
        let url = self.api_url(rest, &[])?;
        let request = Call::json(
            Method::POST,
            url,
            Payload::Json(body.to_string()),
            StatusCode::CREATED,
        );
        parse(&self.send(request).await?)
    }

    /// The commit's title and date.
    ///
    /// # Errors
    /// [`GithubError::NotFound`] when the repository has no such commit, or
    /// another [`GithubError`].
    pub async fn commit(&self, id: &CommitId) -> Result<CommitInfo, GithubError> {
        let answer: CommitAnswer = self.get(&["git", "commits", id.as_str()], &[]).await?;
        let date = answer
            .committer
            .date
            .parse::<jiff::Timestamp>()
            .map_err(|_| GithubError::Unreadable)?;
        if answer.sha != id.as_str() {
            return Err(GithubError::Unreadable);
        }
        Ok(CommitInfo {
            title: title(&answer.message),
            date: format!("{date:.0}"),
        })
    }

    /// Whether `id` is the head of the default branch or one of its ancestors.
    ///
    /// The branch's head is read from its exact ref, `refs/heads/<branch>`, and
    /// compared by commit id: a name in a compare could stand for a tag of the same
    /// name.
    ///
    /// # Errors
    /// A [`GithubError`] from any call, or [`GithubError::Unreadable`] for a branch
    /// name, branch ref or comparison status that is not understood.
    pub async fn on_default_branch(&self, id: &CommitId) -> Result<bool, GithubError> {
        let repository: RepositoryAnswer = self.get(&[], &[]).await?;
        let branch = repository.default_branch;
        if !is_plain_branch(&branch) {
            return Err(GithubError::Unreadable);
        }
        let mut path = vec!["git", "ref", "heads"];
        path.extend(branch.split('/'));
        let head: RefAnswer = self.get(&path, &[]).await?;
        if head.name != format!("refs/heads/{branch}") || head.object.kind != "commit" {
            return Err(GithubError::Unreadable);
        }
        let head = object_id(head.object.sha)?;
        let range = format!("{id}...{head}");
        // The status and the counts are on every page, but the list of changed
        // files, with their patches, is only on page 1 whatever `per_page` is (931
        // KB for a real compare). Page 2 of one-commit pages has no files.
        let query = [("per_page", "1"), ("page", "2")];
        let compare: CompareAnswer = self.get(&["compare", &range], &query).await?;
        match compare.status.as_str() {
            "identical" | "ahead" => Ok(true),
            "behind" | "diverged" => Ok(false),
            _ => Err(GithubError::Unreadable),
        }
    }

    /// What the tag `tag` points at, or `None` when there is no such tag.
    ///
    /// `raw` is the tag object's bytes only for a tag written with a `+0000`
    /// tagger date, as the broker writes them, because GitHub's answer does not
    /// keep the offset. The release key lives only in warden, so a tag it
    /// signed was made by the broker; any other tag gets `raw: None`.
    ///
    /// # Errors
    /// A [`GithubError`] when the tag cannot be read, including a tag ref that
    /// points at something other than a commit or a tag object.
    pub async fn tag_target(&self, tag: &ReleaseTag) -> Result<Option<ExistingTag>, GithubError> {
        let answer: RefAnswer = match self.get(&["git", "ref", "tags", tag.as_str()], &[]).await {
            Ok(answer) => answer,
            Err(GithubError::NotFound) => return Ok(None),
            Err(other) => return Err(other),
        };
        if answer.name != format!("refs/tags/{tag}") {
            return Err(GithubError::Unreadable);
        }
        let sha = object_id(answer.object.sha)?;
        match answer.object.kind.as_str() {
            "commit" => Ok(Some(ExistingTag {
                commit: CommitId::try_from(sha.clone()).ok(),
                object_sha: sha,
                raw: None,
            })),
            "tag" => self.annotated(tag, sha).await.map(Some),
            _ => Err(GithubError::Unreadable),
        }
    }

    /// The release tags among the first 100 tags GitHub lists, in the order it
    /// lists them. A name that is not a [`ReleaseTag`] is left out: only names
    /// that pass their pattern are returned.
    ///
    /// # Errors
    /// A [`GithubError`] when the list cannot be read.
    pub async fn release_tags(&self) -> Result<Vec<ReleaseTag>, GithubError> {
        let names: Vec<TagName> = self.get(&["tags"], &[("per_page", TAGS_PER_PAGE)]).await?;
        Ok(names
            .into_iter()
            .filter_map(|tag| ReleaseTag::try_from(tag.name).ok())
            .collect())
    }

    /// The annotated tag object `sha`.
    async fn annotated(&self, tag: &ReleaseTag, sha: String) -> Result<ExistingTag, GithubError> {
        let object: GitTagResponse = match self.get(&["git", "tags", &sha], &[]).await {
            // The ref names an object GitHub then does not have.
            Err(GithubError::NotFound) => return Err(GithubError::Unreadable),
            other => other?,
        };
        let target = object_id(object.object.sha.clone())?;
        if object.sha != sha || object.tag != tag.as_str() {
            return Err(GithubError::Unreadable);
        }
        let raw = tag_object::rebuild(&object).filter(|raw| tag_object::object_id(raw) == sha);
        Ok(ExistingTag {
            object_sha: sha,
            commit: (object.object.kind == "commit")
                .then(|| CommitId::try_from(target).ok())
                .flatten(),
            raw,
        })
    }

    /// The part of `CHANGELOG.md` at commit `id` that is under the heading
    /// `## [<version>]`, up to 16 KiB; `None` when the file or the heading is
    /// missing, the section is empty or the file is not UTF-8.
    ///
    /// # Errors
    /// A [`GithubError`] when the file cannot be read (a file over 1 MiB is
    /// [`GithubError::Unreadable`]).
    pub async fn changelog_section(
        &self,
        id: &CommitId,
        version: &str,
    ) -> Result<Option<ChangelogSection>, GithubError> {
        let url = self.api_url(&["contents", "CHANGELOG.md"], &[("ref", id.as_str())])?;
        let request = Call {
            accept: github_http::RAW,
            limit: MAX_LARGE_BYTES,
            ..Call::json(Method::GET, url, Payload::Empty, StatusCode::OK)
        };
        match self.send(request).await {
            Ok(raw) => Ok(std::str::from_utf8(&raw)
                .ok()
                .and_then(|text| section(text, version))),
            Err(GithubError::NotFound) => Ok(None),
            Err(other) => Err(other),
        }
    }

    /// Create the annotated tag object and return the id GitHub gave it.
    ///
    /// # Errors
    /// A [`GithubError`], or [`GithubError::Unreadable`] when the id returned is
    /// not an object id.
    pub async fn create_tag(&self, tag: &CreateTag) -> Result<String, GithubError> {
        let body = json!({
            "tag": tag.tag.as_str(),
            "message": tag.message,
            "object": tag.object.as_str(),
            "type": "commit",
            "tagger": {
                "name": tag.tagger_name,
                "email": tag.tagger_email,
                "date": format!("{:.0}", tag.tagged_at),
            },
        });
        let created: CreatedTagAnswer = self.post(&["git", "tags"], &body).await?;
        object_id(created.sha)
    }

    /// Create the ref `refs/tags/<tag>` at `sha`.
    ///
    /// # Errors
    /// A [`GithubError`], or [`GithubError::Unreadable`] when the ref created is
    /// not the one asked for.
    pub async fn create_ref(&self, tag: &ReleaseTag, sha: &str) -> Result<(), GithubError> {
        if CommitId::try_from(sha.to_owned()).is_err() {
            return Err(GithubError::Unreadable);
        }
        let name = format!("refs/tags/{tag}");
        let body = json!({"ref": name, "sha": sha});
        let created: RefAnswer = self.post(&["git", "refs"], &body).await?;
        if created.name == name && created.object.sha == sha {
            Ok(())
        } else {
            Err(GithubError::Unreadable)
        }
    }

    /// The release for `tag`, a draft or not, among the 20 newest releases.
    ///
    /// Only 20 are listed because a real release answer is about 11 KB, so a
    /// page of 100 could pass the 1 MiB cap and fail every release step. The
    /// step's draft is fresh and listed first, and a duplicate tag would sit
    /// beside it. A release not found in the page is `None`, and the caller
    /// refuses; nothing is assumed from what is not seen.
    ///
    /// # Errors
    /// [`GithubError::Unreadable`] when more than one release has the tag, or
    /// the release's assets are not understood; another [`GithubError`] when the
    /// list cannot be read.
    pub async fn release_for_tag(&self, tag: &ReleaseTag) -> Result<Option<Release>, GithubError> {
        let url = self.api_url(&["releases"], &[("per_page", RELEASES_PER_PAGE)])?;
        let request = Call {
            limit: MAX_LARGE_BYTES,
            ..Call::json(Method::GET, url, Payload::Empty, StatusCode::OK)
        };
        let all: Vec<ReleaseAnswer> = parse(&self.send(request).await?)?;
        let mut found = all
            .into_iter()
            .filter(|release| release.tag_name == tag.as_str());
        let Some(release) = found.next() else {
            return Ok(None);
        };
        if found.next().is_some() {
            return Err(GithubError::Unreadable);
        }
        let assets: Vec<AssetAnswer> = parse_value(release.assets)?;
        Ok(Some(Release {
            id: release.id,
            draft: release.draft,
            assets: assets
                .into_iter()
                .map(Asset::try_from)
                .collect::<Result<_, _>>()?,
        }))
    }

    /// Upload `bytes` to `release` as an asset called `name`, through the
    /// uploads host.
    ///
    /// # Errors
    /// A [`GithubError`], or [`GithubError::Unreadable`] when `name` is not an
    /// asset name (nothing is sent then) or the asset created has another name.
    pub async fn upload_asset(
        &self,
        release: u64,
        name: &str,
        bytes: &[u8],
    ) -> Result<Asset, GithubError> {
        if !is_asset_name(name) {
            return Err(GithubError::Unreadable);
        }
        let release = release.to_string();
        let mut url = self.url(self.api.uploads(), &["releases", &release, "assets"])?;
        url.query_pairs_mut().append_pair("name", name);
        let request = Call::json(
            Method::POST,
            url,
            Payload::Octets(bytes.to_vec()),
            StatusCode::CREATED,
        );
        let asset = Asset::try_from(parse::<AssetAnswer>(&self.send(request).await?)?)?;
        if asset.name == name {
            Ok(asset)
        } else {
            Err(GithubError::Unreadable)
        }
    }

    /// Delete the asset `id`.
    ///
    /// # Errors
    /// A [`GithubError`].
    pub async fn delete_asset(&self, id: u64) -> Result<(), GithubError> {
        let id = id.to_string();
        let url = self.api_url(&["releases", "assets", &id], &[])?;
        let request = Call::json(Method::DELETE, url, Payload::Empty, StatusCode::NO_CONTENT);
        self.send(request).await.map(drop)
    }

    /// Publish the draft `release`.
    ///
    /// # Errors
    /// A [`GithubError`], or [`GithubError::Unreadable`] when the answer does
    /// not say the release is no longer a draft.
    pub async fn publish(&self, release: u64) -> Result<(), GithubError> {
        let id = release.to_string();
        let url = self.api_url(&["releases", &id], &[])?;
        let request = Call::json(
            Method::PATCH,
            url,
            Payload::Json(json!({"draft": false}).to_string()),
            StatusCode::OK,
        );
        let answer: PublishedAnswer = parse(&self.send(request).await?)?;
        if answer.id == release && !answer.draft {
            Ok(())
        } else {
            Err(GithubError::Unreadable)
        }
    }
}

fn parse_value<T: DeserializeOwned>(value: serde_json::Value) -> Result<T, GithubError> {
    serde_json::from_value(value).map_err(|_| GithubError::Unreadable)
}
