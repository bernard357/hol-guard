//! Stable reads for workspace snapshot files.
//!
//! A file is opened without following a leaf symlink or reparse point and is
//! hashed only when the open descriptor is the file the walk saw and its
//! size, mtime and inode held still for the whole read.

use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

pub(crate) enum HashError {
    Unreadable,
    Unstable,
}

/// Hash one file opened without following a leaf symlink and reject it when
/// the open descriptor is not the file the walk saw, or when its size or
/// mtime moved during the read.
pub(crate) fn hash_stable(
    path: &Path,
    seen: &Metadata,
    max_bytes: u64,
) -> Result<(String, u64), HashError> {
    let mut file = open_no_follow(path).map_err(|_| HashError::Unreadable)?;
    let before = file.metadata().map_err(|_| HashError::Unreadable)?;
    if !before.is_file() || !same_file(seen, &before) {
        return Err(HashError::Unstable);
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut read_total: u64 = 0;
    loop {
        let count = file.read(&mut buffer).map_err(|_| HashError::Unreadable)?;
        if count == 0 {
            break;
        }
        read_total += count as u64;
        if read_total > max_bytes {
            return Err(HashError::Unstable);
        }
        hasher.update(&buffer[..count]);
    }
    let after = file.metadata().map_err(|_| HashError::Unreadable)?;
    if read_total != before.len() || !same_file(&before, &after) {
        return Err(HashError::Unstable);
    }
    Ok((hex::encode(hasher.finalize()), read_total))
}

pub(crate) fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.len() == right.len() && mtime_ns(left) == mtime_ns(right) && inode(left) == inode(right)
}

#[cfg(unix)]
pub(crate) fn open_no_follow(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(unix))]
pub(crate) fn open_no_follow(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_FLAG_OPEN_REPARSE_POINT: open a reparse point itself, never its
    // target. `same_file` then rejects anything but the regular file seen.
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(0x0020_0000)
        .open(path)
}

pub(crate) fn mtime_ns(metadata: &Metadata) -> u128 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |elapsed| elapsed.as_nanos())
}

#[cfg(unix)]
pub(crate) fn inode(metadata: &Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.ino()
}

#[cfg(not(unix))]
pub(crate) fn inode(_metadata: &Metadata) -> u64 {
    0
}
