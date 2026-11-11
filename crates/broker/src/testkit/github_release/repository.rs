//! The fake GitHub's repositories: commits and their ancestry, tags, refs,
//! files and releases with their assets, and the answers GitHub gives about them.

use std::collections::{BTreeMap, HashMap};

use http::{HeaderMap, Method};
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Digest as _, Sha256};

use crate::testkit::upstream::Scripted;

#[derive(Default)]
pub(super) struct Repository {
    default_branch: String,
    head: String,
    commits: HashMap<String, Commit>,
    /// Tag objects by id.
    tags: HashMap<String, TagObject>,
    /// `refs/tags/<name>` to the id of the object it points at.
    refs: BTreeMap<String, String>,
    /// File contents by commit and path.
    files: HashMap<(String, String), Vec<u8>>,
    releases: Vec<StoredRelease>,
    next_id: u64,
}

struct Commit {
    message: String,
    date: String,
    parents: Vec<String>,
}

struct TagObject {
    raw: Vec<u8>,
    object: String,
    kind: String,
    tag: String,
    tagger: Option<(String, String, i64)>,
    message: String,
}

struct StoredRelease {
    id: u64,
    tag_name: String,
    draft: bool,
    assets: Vec<StoredAsset>,
}

struct StoredAsset {
    id: u64,
    name: String,
    bytes: Vec<u8>,
}

/// A release as the fake holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseView {
    /// Whether it is a draft.
    pub draft: bool,
    /// Its assets, by name and content.
    pub assets: Vec<(String, Vec<u8>)>,
}

/// The id Git gives an object of this kind with these bytes.
fn git_id(kind: &str, raw: &[u8]) -> String {
    hex::encode(
        Sha1::new()
            .chain_update(format!("{kind} {}\0", raw.len()).as_bytes())
            .chain_update(raw)
            .finalize(),
    )
}

fn iso(seconds: i64) -> String {
    format!(
        "{:.0}",
        jiff::Timestamp::from_second(seconds).expect("test timestamp")
    )
}

fn json_answer(status: u16, value: &Value) -> Scripted {
    Scripted::with_body(status, value.to_string()).header("content-type", "application/json")
}

fn not_found() -> Scripted {
    json_answer(404, &json!({"message": "Not Found"}))
}

fn invalid(why: &str) -> Scripted {
    json_answer(422, &json!({"message": why}))
}

impl Repository {
    pub(super) fn set_default_branch(&mut self, branch: &str, head: &str) {
        branch.clone_into(&mut self.default_branch);
        head.clone_into(&mut self.head);
    }

    pub(super) fn add_commit(&mut self, sha: &str, message: &str, date: &str, parents: &[&str]) {
        self.commits.insert(
            sha.to_owned(),
            Commit {
                message: message.to_owned(),
                date: date.to_owned(),
                parents: parents.iter().map(|p| (*p).to_owned()).collect(),
            },
        );
    }

    pub(super) fn add_file(&mut self, commit: &str, path: &str, bytes: &[u8]) {
        self.files
            .insert((commit.to_owned(), path.to_owned()), bytes.to_vec());
    }

    pub(super) fn add_lightweight_tag(&mut self, tag: &str, commit: &str) {
        self.refs
            .insert(format!("refs/tags/{tag}"), commit.to_owned());
    }

    /// Store the tag object `raw`, as `git` would, and return its id.
    pub(super) fn add_tag_object(&mut self, raw: &[u8]) -> String {
        let text = String::from_utf8(raw.to_vec()).expect("a UTF-8 tag object");
        let (headers, message) = text.split_once("\n\n").expect("a tag object has a message");
        let field = |name: &str| {
            headers
                .lines()
                .find_map(|line| line.strip_prefix(name)?.strip_prefix(' '))
                .map(str::to_owned)
        };
        let tagger = field("tagger").map(|line| {
            let (identity, rest) = line.rsplit_once("> ").expect("a tagger line");
            let (name, email) = identity.split_once(" <").expect("a tagger identity");
            let seconds = rest.split(' ').next().expect("a tagger time");
            (
                name.to_owned(),
                email.to_owned(),
                seconds.parse().expect("a tagger time"),
            )
        });
        let sha = git_id("tag", raw);
        self.tags.insert(
            sha.clone(),
            TagObject {
                raw: raw.to_vec(),
                object: field("object").expect("an object line"),
                kind: field("type").expect("a type line"),
                tag: field("tag").expect("a tag line"),
                tagger,
                message: message.to_owned(),
            },
        );
        sha
    }

    pub(super) fn add_ref(&mut self, tag: &str, sha: &str) {
        self.refs.insert(format!("refs/tags/{tag}"), sha.to_owned());
    }

    pub(super) fn add_release(&mut self, tag: &str, draft: bool) -> u64 {
        self.next_id += 1;
        self.releases.push(StoredRelease {
            id: self.next_id,
            tag_name: tag.to_owned(),
            draft,
            assets: Vec::new(),
        });
        self.next_id
    }

    pub(super) fn add_asset(&mut self, release: u64, name: &str, bytes: &[u8]) {
        self.next_id += 1;
        let id = self.next_id;
        self.releases
            .iter_mut()
            .find(|r| r.id == release)
            .expect("a release of the fake")
            .assets
            .push(StoredAsset {
                id,
                name: name.to_owned(),
                bytes: bytes.to_vec(),
            });
    }

    pub(super) fn ref_target(&self, tag: &str) -> Option<String> {
        self.refs.get(&format!("refs/tags/{tag}")).cloned()
    }

    pub(super) fn tag_object(&self, sha: &str) -> Option<Vec<u8>> {
        self.tags.get(sha).map(|tag| tag.raw.clone())
    }

    pub(super) fn release(&self, id: u64) -> Option<ReleaseView> {
        self.releases
            .iter()
            .find(|r| r.id == id)
            .map(|r| ReleaseView {
                draft: r.draft,
                assets: r
                    .assets
                    .iter()
                    .map(|a| (a.name.clone(), a.bytes.clone()))
                    .collect(),
            })
    }

    /// Whether `ancestor` is `of` or one of its ancestors.
    fn is_ancestor(&self, ancestor: &str, of: &str) -> bool {
        let mut pending = vec![of];
        let mut seen = Vec::new();
        while let Some(sha) = pending.pop() {
            if sha == ancestor {
                return true;
            }
            if seen.contains(&sha) {
                continue;
            }
            seen.push(sha);
            if let Some(commit) = self.commits.get(sha) {
                pending.extend(commit.parents.iter().map(String::as_str));
            }
        }
        false
    }

    fn release_json(release: &StoredRelease) -> Value {
        let assets: Vec<Value> = release.assets.iter().map(Self::asset_json).collect();
        json!({
            "id": release.id,
            "tag_name": release.tag_name,
            "draft": release.draft,
            "assets": assets,
        })
    }

    fn asset_json(asset: &StoredAsset) -> Value {
        json!({
            "id": asset.id,
            "name": asset.name,
            "digest": format!("sha256:{}", hex::encode(Sha256::digest(&asset.bytes))),
        })
    }

    /// The answer to a call on this repository. `rest` is the path after
    /// `repos/<owner>/<name>`, decoded; `uploads` is whether the call came to the
    /// uploads path.
    pub(super) fn answer(&mut self, call: &Call<'_>) -> Scripted {
        let rest: Vec<&str> = call.rest.iter().map(String::as_str).collect();
        let query = |name: &str| {
            call.query
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
        };
        match (call.method.as_str(), call.uploads, rest.as_slice()) {
            ("GET", false, []) => json_answer(200, &json!({"default_branch": self.default_branch})),
            ("GET", false, ["git", "commits", sha]) => {
                self.commits.get(*sha).map_or_else(not_found, |c| {
                    json_answer(
                        200,
                        &json!({
                            "sha": sha,
                            "message": c.message,
                            "author": {"date": c.date},
                            "committer": {"date": c.date},
                        }),
                    )
                })
            }
            ("GET", false, ["compare", range]) => self.compare(range, query("page")),
            ("GET", false, ["git", "ref", "tags", tag]) => self.ref_answer(tag),
            ("GET", false, ["git", "tags", sha]) => {
                self.tags.get(*sha).map_or_else(not_found, |t| {
                    let tagger = t.tagger.as_ref().map(|(name, email, seconds)| {
                    json!({"name": name, "email": email, "date": iso(*seconds)})
                });
                    json_answer(
                        200,
                        &json!({
                            "sha": sha,
                            "tag": t.tag,
                            "message": t.message,
                            "tagger": tagger,
                            "object": {"sha": t.object, "type": t.kind},
                        }),
                    )
                })
            }
            ("GET", false, ["contents", path]) => query("ref")
                .and_then(|commit| self.files.get(&(commit.to_owned(), (*path).to_owned())))
                .map_or_else(not_found, |bytes| {
                    Scripted::with_body(200, bytes.clone())
                        .header("content-type", "application/vnd.github.raw+json")
                }),
            ("POST", false, ["git", "tags"]) => self.create_tag(call.body),
            ("POST", false, ["git", "refs"]) => self.create_ref(call.body),
            ("GET", false, ["releases"]) => {
                let wanted = query("per_page").and_then(|n| n.parse().ok()).unwrap_or(30);
                let all: Vec<Value> = self
                    .releases
                    .iter()
                    .rev()
                    .take(wanted)
                    .map(Self::release_json)
                    .collect();
                json_answer(200, &Value::Array(all))
            }
            ("PATCH", false, ["releases", id]) => self.publish(id, call.body),
            ("DELETE", false, ["releases", "assets", id]) => self.delete_asset(id),
            ("POST", true, ["releases", id, "assets"]) => {
                self.upload(id, query("name"), call.headers, call.body)
            }
            _ => not_found(),
        }
    }

    /// GitHub lists the changed files, with patches, on page 1 only, whatever
    /// `per_page` is: `page` is the query's page, if any.
    fn compare(&self, range: &str, page: Option<&str>) -> Scripted {
        let Some((base, head)) = range.split_once("...") else {
            return not_found();
        };
        if head != self.default_branch || !self.commits.contains_key(base) {
            return not_found();
        }
        let status = if base == self.head {
            "identical"
        } else if self.is_ancestor(base, &self.head) {
            "ahead"
        } else if self.is_ancestor(&self.head, base) {
            "behind"
        } else {
            "diverged"
        };
        let files: Vec<Value> = if page.is_none_or(|page| page == "1") {
            (0..64)
                .map(|n| json!({"filename": format!("file-{n}"), "patch": "+".repeat(2048)}))
                .collect()
        } else {
            Vec::new()
        };
        json_answer(200, &json!({"status": status, "files": files}))
    }

    fn ref_answer(&self, tag: &str) -> Scripted {
        let name = format!("refs/tags/{tag}");
        self.refs.get(&name).map_or_else(not_found, |sha| {
            let kind = if self.tags.contains_key(sha) {
                "tag"
            } else {
                "commit"
            };
            json_answer(
                200,
                &json!({"ref": name, "object": {"sha": sha, "type": kind}}),
            )
        })
    }

    fn create_tag(&mut self, body: &[u8]) -> Scripted {
        let Ok(request) = serde_json::from_slice::<Value>(body) else {
            return invalid("not JSON");
        };
        let text = |value: &Value| value.as_str().map(str::to_owned);
        let (Some(tag), Some(message), Some(object), Some(name), Some(email), Some(date)) = (
            text(&request["tag"]),
            text(&request["message"]),
            text(&request["object"]),
            text(&request["tagger"]["name"]),
            text(&request["tagger"]["email"]),
            text(&request["tagger"]["date"]),
        ) else {
            return invalid("missing field");
        };
        let Ok(when) = date.parse::<jiff::Timestamp>() else {
            return invalid("bad date");
        };
        if request["type"] != "commit" || !self.commits.contains_key(&object) {
            return invalid("no such commit");
        }
        let raw = format!(
            "object {object}\ntype commit\ntag {tag}\ntagger {name} <{email}> {} +0000\n\n{message}",
            when.as_second()
        );
        let sha = self.add_tag_object(raw.as_bytes());
        json_answer(201, &json!({"sha": sha}))
    }

    fn create_ref(&mut self, body: &[u8]) -> Scripted {
        let Ok(request) = serde_json::from_slice::<Value>(body) else {
            return invalid("not JSON");
        };
        let (Some(name), Some(sha)) = (request["ref"].as_str(), request["sha"].as_str()) else {
            return invalid("missing field");
        };
        let known = self.commits.contains_key(sha) || self.tags.contains_key(sha);
        if !known || self.refs.contains_key(name) || !name.starts_with("refs/tags/") {
            return invalid("Reference cannot be created");
        }
        self.refs.insert(name.to_owned(), sha.to_owned());
        let kind = if self.tags.contains_key(sha) {
            "tag"
        } else {
            "commit"
        };
        json_answer(
            201,
            &json!({"ref": name, "object": {"sha": sha, "type": kind}}),
        )
    }

    fn publish(&mut self, id: &str, body: &[u8]) -> Scripted {
        let Ok(request) = serde_json::from_slice::<Value>(body) else {
            return invalid("not JSON");
        };
        let Some(release) = self.releases.iter_mut().find(|r| r.id.to_string() == id) else {
            return not_found();
        };
        if let Some(draft) = request["draft"].as_bool() {
            release.draft = draft;
        }
        json_answer(200, &Self::release_json(release))
    }

    fn delete_asset(&mut self, id: &str) -> Scripted {
        for release in &mut self.releases {
            if let Some(at) = release.assets.iter().position(|a| a.id.to_string() == id) {
                release.assets.remove(at);
                return Scripted::status(204);
            }
        }
        not_found()
    }

    fn upload(
        &mut self,
        id: &str,
        name: Option<&str>,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Scripted {
        if headers.get("content-type").and_then(|v| v.to_str().ok())
            != Some("application/octet-stream")
        {
            return json_answer(415, &json!({"message": "Unsupported Media Type"}));
        }
        let Some(name) = name else {
            return invalid("name is missing");
        };
        let Some(at) = self.releases.iter().position(|r| r.id.to_string() == id) else {
            return not_found();
        };
        if self.releases[at].assets.iter().any(|a| a.name == name) {
            return invalid("already_exists");
        }
        self.next_id += 1;
        let asset = StoredAsset {
            id: self.next_id,
            name: name.to_owned(),
            bytes: body.to_vec(),
        };
        let answer = json_answer(201, &Self::asset_json(&asset));
        self.releases[at].assets.push(asset);
        answer
    }
}

/// A call to one repository's routes.
pub(super) struct Call<'a> {
    pub(super) method: &'a Method,
    /// Whether it came to the uploads path.
    pub(super) uploads: bool,
    /// The path after `repos/<owner>/<name>`, decoded.
    pub(super) rest: Vec<String>,
    pub(super) query: Vec<(String, String)>,
    pub(super) headers: &'a HeaderMap,
    pub(super) body: &'a [u8],
}
