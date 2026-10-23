//! SFTP directory mirroring (one-way sync): planning, local/remote walkers and execution.

use super::{BackendEvent, download_sftp_file, join_remote, list_sftp_directory, upload_sftp_file};
use anyhow::Result;
use russh_sftp::client::SftpSession;
use std::collections::BTreeMap;
use std::path::Path;
use tokio::sync::mpsc::UnboundedSender;

/// Seconds of mtime difference tolerated before a file is considered modified
/// (SFTP timestamps have a 1 s resolution and some file systems 2 s).
const MTIME_TOLERANCE_SECS: i64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MirrorFile {
    pub size: u64,
    pub mtime: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MirrorAction {
    /// Copy `rel` from the source to the destination.
    Copy(String),
    /// Delete `rel` on the destination (only planned when `delete_extra`).
    Delete(String),
}

/// Result of a mirror run, reported to the UI.
#[derive(Debug, Clone, Default)]
pub struct MirrorSummary {
    pub lines: Vec<String>,
    pub copied: usize,
    pub deleted: usize,
    pub errors: usize,
}

/// One-way plan making `dest` identical to `source`. Files are keyed by their
/// `/`-separated path relative to the mirrored root.
pub fn plan_mirror(
    source: &BTreeMap<String, MirrorFile>,
    dest: &BTreeMap<String, MirrorFile>,
    delete_extra: bool,
) -> Vec<MirrorAction> {
    let mut actions = Vec::new();
    for (rel, src) in source {
        let needs_copy = match dest.get(rel) {
            None => true,
            Some(dst) => src.size != dst.size || src.mtime > dst.mtime + MTIME_TOLERANCE_SECS,
        };
        if needs_copy {
            actions.push(MirrorAction::Copy(rel.clone()));
        }
    }
    if delete_extra {
        for rel in dest.keys() {
            if !source.contains_key(rel) {
                actions.push(MirrorAction::Delete(rel.clone()));
            }
        }
    }
    actions
}

/// Recursively lists regular files under `root` (symlinks are skipped).
pub fn walk_local(root: &Path) -> std::io::Result<BTreeMap<String, MirrorFile>> {
    fn rec(
        dir: &Path,
        prefix: &str,
        out: &mut BTreeMap<String, MirrorFile>,
    ) -> std::io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            let rel = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            let ft = entry.file_type()?;
            if ft.is_dir() {
                rec(&entry.path(), &rel, out)?;
            } else if ft.is_file() {
                let meta = entry.metadata()?;
                let mtime = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or(0, |d| d.as_secs() as i64);
                out.insert(
                    rel,
                    MirrorFile {
                        size: meta.len(),
                        mtime,
                    },
                );
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    rec(root, "", &mut out)?;
    Ok(out)
}

/// Recursively lists regular files under the remote `root` (symlinks are skipped).
async fn walk_remote(sftp: &SftpSession, root: &str) -> Result<BTreeMap<String, MirrorFile>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![(root.to_string(), String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        for e in list_sftp_directory(sftp, &dir).await? {
            if e.name == "." || e.name == ".." || e.is_symlink {
                continue;
            }
            let rel = if prefix.is_empty() {
                e.name.clone()
            } else {
                format!("{prefix}/{}", e.name)
            };
            if e.is_dir {
                stack.push((e.full_path.clone(), rel));
            } else {
                out.insert(
                    rel,
                    MirrorFile {
                        size: e.size,
                        mtime: e.mtime as i64,
                    },
                );
            }
        }
    }
    Ok(out)
}

/// Creates `remote_dir` and every parent folder of `rel` below it (errors ignored:
/// the folder usually exists already, a real failure surfaces on the file transfer).
async fn ensure_remote_dirs(sftp: &SftpSession, remote_dir: &str, rel: &str) {
    let _ = sftp.create_dir(remote_dir).await;
    let mut cur = remote_dir.to_string();
    let parts: Vec<&str> = rel.split('/').collect();
    for part in &parts[..parts.len().saturating_sub(1)] {
        cur = join_remote(&cur, part);
        let _ = sftp.create_dir(cur.clone()).await;
    }
}

/// Plans (and unless `dry_run`, executes) a mirror between `local_dir` and `remote_dir`.
/// `upload` mirrors local → remote, otherwise remote → local.
pub async fn run_mirror(
    sftp: &SftpSession,
    local_dir: &Path,
    remote_dir: &str,
    upload: bool,
    delete_extra: bool,
    dry_run: bool,
    evt_tx: &UnboundedSender<BackendEvent>,
) -> Result<MirrorSummary> {
    let local_root = local_dir.to_path_buf();
    let local_map = if local_dir.is_dir() {
        tokio::task::spawn_blocking(move || walk_local(&local_root)).await??
    } else {
        BTreeMap::new()
    };
    let remote_map = if sftp
        .try_exists(remote_dir.to_string())
        .await
        .unwrap_or(false)
    {
        walk_remote(sftp, remote_dir).await?
    } else {
        BTreeMap::new()
    };
    let plan = if upload {
        plan_mirror(&local_map, &remote_map, delete_extra)
    } else {
        plan_mirror(&remote_map, &local_map, delete_extra)
    };

    let mut summary = MirrorSummary::default();
    for action in &plan {
        match action {
            MirrorAction::Copy(rel) => summary.lines.push(format!("+ {rel}")),
            MirrorAction::Delete(rel) => summary.lines.push(format!("- {rel}")),
        }
    }
    if dry_run {
        return Ok(summary);
    }

    for action in plan {
        let result: Result<()> = match &action {
            MirrorAction::Copy(rel) if upload => {
                let local = local_dir.join(rel);
                let remote = join_remote(remote_dir, rel);
                ensure_remote_dirs(sftp, remote_dir, rel).await;
                upload_sftp_file(sftp, &local, &remote, evt_tx)
                    .await
                    .map(|_| ())
            }
            MirrorAction::Copy(rel) => {
                let local = local_dir.join(rel);
                if let Some(parent) = local.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                download_sftp_file(sftp, &join_remote(remote_dir, rel), &local, evt_tx)
                    .await
                    .map(|_| ())
            }
            MirrorAction::Delete(rel) if upload => sftp
                .remove_file(join_remote(remote_dir, rel))
                .await
                .map_err(Into::into),
            MirrorAction::Delete(rel) => tokio::fs::remove_file(local_dir.join(rel))
                .await
                .map_err(Into::into),
        };
        match (&action, result) {
            (MirrorAction::Copy(_), Ok(())) => summary.copied += 1,
            (MirrorAction::Delete(_), Ok(())) => summary.deleted += 1,
            (MirrorAction::Copy(rel) | MirrorAction::Delete(rel), Err(e)) => {
                summary.errors += 1;
                summary.lines.push(format!("! {rel}: {e}"));
            }
        }
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(size: u64, mtime: i64) -> MirrorFile {
        MirrorFile { size, mtime }
    }

    #[test]
    fn plan_copies_new_and_changed_files_only() {
        let source = BTreeMap::from([
            ("same.txt".to_string(), f(10, 100)),
            ("new.txt".to_string(), f(5, 100)),
            ("resized.txt".to_string(), f(20, 100)),
            ("newer.txt".to_string(), f(10, 200)),
            ("jitter.txt".to_string(), f(10, 101)),
        ]);
        let dest = BTreeMap::from([
            ("same.txt".to_string(), f(10, 100)),
            ("resized.txt".to_string(), f(10, 100)),
            ("newer.txt".to_string(), f(10, 100)),
            ("jitter.txt".to_string(), f(10, 100)),
            ("extra.txt".to_string(), f(1, 1)),
        ]);
        let keep = plan_mirror(&source, &dest, false);
        assert_eq!(
            keep,
            vec![
                MirrorAction::Copy("new.txt".into()),
                MirrorAction::Copy("newer.txt".into()),
                MirrorAction::Copy("resized.txt".into()),
            ]
        );
        let purge = plan_mirror(&source, &dest, true);
        assert_eq!(
            purge.last(),
            Some(&MirrorAction::Delete("extra.txt".into()))
        );
        assert_eq!(purge.len(), 4);
    }

    #[test]
    fn walk_local_lists_nested_files_with_slash_paths() {
        let dir = std::env::temp_dir().join(format!("cuty_mirror_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("a/b")).unwrap();
        std::fs::write(dir.join("top.txt"), b"1").unwrap();
        std::fs::write(dir.join("a/b/deep.txt"), b"22").unwrap();
        let map = walk_local(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(map.len(), 2);
        assert_eq!(map["top.txt"].size, 1);
        assert_eq!(map["a/b/deep.txt"].size, 2);
    }

    #[test]
    fn join_remote_handles_trailing_slash() {
        assert_eq!(join_remote("/srv", "a/b"), "/srv/a/b");
        assert_eq!(join_remote("/", "a"), "/a");
    }
}
