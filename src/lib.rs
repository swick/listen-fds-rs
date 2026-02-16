// SPDX-FileCopyrightText: 2026 The listen-fds-rs authors
// SPDX-License-Identifier: MIT OR Apache-2.0

use pidfd_util::{self, PidFdExt};
use std::{
    borrow::Cow,
    env,
    num::ParseIntError,
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
};
use thiserror::Error;

/// Errors that can occur when retrieving socket-activated file descriptors.
#[derive(Error, Debug)]
pub enum ListenFdsError {
    /// The process was not socket-activated.
    ///
    /// This error occurs when the `LISTEN_FDS` environment variable is not present,
    /// indicating that systemd did not socket-activate this process.
    #[error("Not socket activated")]
    NoListenFds,

    /// The socket activation targets a different process.
    ///
    /// This error occurs when the PID or pidfd ID in the environment variables
    /// does not match the current process, indicating the file descriptors were
    /// intended for a different process.
    #[error("The socket activation targets another PID (target: {listen_pid}, self: {self_pid}")]
    PidMissmatch { listen_pid: u64, self_pid: u64 },

    /// The `LISTEN_FDS` value is out of valid range.
    #[error("LISTEN_FDS contains out of range FDs")]
    OutOfRangeListenFds,

    /// The `LISTEN_PID` environment variable contains an invalid PID.
    #[error("LISTEN_PID does not contain a valid PID")]
    BadListenPid(ParseIntError),

    /// The `LISTEN_PIDFDID` environment variable contains an invalid pidfd ID.
    #[error("LISTEN_PIDFDID does not contain a valid Pidfd ID")]
    BadListenPidfdId(ParseIntError),

    /// The `LISTEN_FDS` environment variable contains an invalid number.
    #[error("LISTEN_FDS does not contain a valid Pidfd ID")]
    BadListenFds(ParseIntError),

    /// The number of names in `LISTEN_FDNAMES` doesn't match the number of file descriptors.
    #[error("LISTEN_FDNAMES contains a wrong number of names")]
    BadListenFdNames,
}

/// Container for socket-activated file descriptors passed from systemd.
///
/// This struct provides safe access to file descriptors passed via systemd socket activation.
/// It validates that the file descriptors are intended for this process and automatically sets
/// the `FD_CLOEXEC` flag on all descriptors for security.
pub struct ListenFds {
    fds: Vec<Option<OwnedFd>>,
    names: Option<Vec<String>>,
}

impl ListenFds {
    /// Creates a new `ListenFds` instance from systemd socket activation environment variables.
    ///
    /// This function reads and validates the following environment variables:
    /// - `LISTEN_PID`: The target process ID (validated against current PID)
    /// - `LISTEN_PIDFDID`: The target pidfd ID (validated against current pidfd, more secure)
    /// - `LISTEN_FDS`: The number of file descriptors passed
    /// - `LISTEN_FDNAMES`: Optional colon-separated names for the file descriptors
    ///
    /// After reading, all these environment variables are removed from the process environment
    /// for security reasons.
    ///
    /// # Safety
    ///
    /// This function is `unsafe` because:
    /// - It modifies the process environment by removing variables
    /// - It must be called before spawning any threads (to avoid race conditions)
    /// - It must be called at most once per process
    ///
    /// Call this early in `main()`, before any thread spawning occurs.
    pub unsafe fn new() -> Result<ListenFds, ListenFdsError> {
        const LISTEN_FDS_START: usize = 3;

        let listen_pid = env::var("LISTEN_PID");
        let listen_pidfdid = env::var("LISTEN_PIDFDID");
        let listen_fds = env::var("LISTEN_FDS");
        let listen_fdnames = env::var("LISTEN_FDNAMES");

        unsafe {
            env::remove_var("LISTEN_PID");
            env::remove_var("LISTEN_PIDFDID");
            env::remove_var("LISTEN_FDS");
            env::remove_var("LISTEN_FDNAMES");
        }

        if let Ok(listen_pid) = listen_pid {
            let listen_pid: u32 = listen_pid
                .trim()
                .parse()
                .map_err(ListenFdsError::BadListenPid)?;
            let self_pid = std::process::id();
            if listen_pid != self_pid {
                return Err(ListenFdsError::PidMissmatch {
                    self_pid: self_pid.into(),
                    listen_pid: listen_pid.into(),
                });
            }
        }

        if let Ok(listen_pidfdid) = listen_pidfdid {
            let listen_pidfdid: u64 = listen_pidfdid
                .trim()
                .parse()
                .map_err(ListenFdsError::BadListenPidfdId)?;
            if let Some(self_pidfdid) = pidfd_util::PidFd::from_self()
                .and_then(|pfd| pfd.get_id())
                .ok()
                && listen_pidfdid != self_pidfdid
            {
                return Err(ListenFdsError::PidMissmatch {
                    self_pid: self_pidfdid,
                    listen_pid: listen_pidfdid,
                });
            }
        }

        let listen_fds = listen_fds.map_err(|_| ListenFdsError::NoListenFds)?;
        let listen_fds: usize = listen_fds
            .trim()
            .parse()
            .map_err(ListenFdsError::BadListenFds)?;
        if LISTEN_FDS_START + listen_fds > std::mem::size_of::<std::ffi::c_int>() {
            return Err(ListenFdsError::OutOfRangeListenFds);
        }

        let fds: Vec<Option<OwnedFd>> = (0..listen_fds)
            .map(|i| unsafe { Some(OwnedFd::from_raw_fd((LISTEN_FDS_START + i) as RawFd)) })
            .collect();
        fds.iter()
            .flatten()
            .for_each(|fd| unsafe { Self::ensure_cloexec(fd) });

        let names: Option<Vec<String>> = listen_fdnames
            .ok()
            .map(|names| names.split(':').map(|s| s.to_owned()).collect::<Vec<_>>());

        if let Some(n) = &names
            && n.len() != fds.len()
        {
            return Err(ListenFdsError::BadListenFdNames);
        }

        Ok(ListenFds { fds, names })
    }

    unsafe fn ensure_cloexec<Fd: AsFd>(fd: Fd) {
        let raw_fd = fd.as_fd().as_raw_fd();
        let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFD) };

        if flags >= 0 && (flags & libc::FD_CLOEXEC) != libc::FD_CLOEXEC {
            unsafe {
                libc::fcntl(raw_fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
            }
        }
    }

    /// Returns the number of file descriptors received from systemd.
    pub fn len(&self) -> usize {
        self.fds.len()
    }

    /// Returns `true` if no file descriptors were received from systemd.
    pub fn is_empty(&self) -> bool {
        self.fds.is_empty()
    }

    /// Takes ownership of the file descriptor at the given index.
    ///
    /// This removes the file descriptor from the internal storage and returns it along with
    /// its name. Subsequent calls with the same index will return `None`.
    ///
    /// Returns `None` if the index is out of bounds or the FD has already been taken.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use listen_fds::ListenFds;
    /// # use std::os::unix::net::UnixListener;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut fds = unsafe { ListenFds::new()? };
    ///
    /// if let Some((fd, name)) = fds.take_fd(0) {
    ///     println!("Taking FD named: {}", name);
    ///     let listener = UnixListener::from(fd);
    ///     // Use the listener...
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn take_fd(&mut self, idx: usize) -> Option<(OwnedFd, &str)> {
        let fd = self.fds.get_mut(idx)?.take()?;
        let name = self.get_name(idx);
        Some((fd, name))
    }

    /// Borrows the file descriptor at the given index without taking ownership.
    ///
    /// This returns a borrowed reference to the file descriptor along with its name.
    /// The file descriptor remains in the internal storage and can be borrowed again
    /// or taken later.
    ///
    /// Returns `None` if the index is out of bounds or the FD has been taken.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use listen_fds::ListenFds;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let fds = unsafe { ListenFds::new()? };
    ///
    /// if let Some((fd, name)) = fds.get_fd(0) {
    ///     println!("FD named: {}", name);
    ///     // Use the borrowed fd...
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_fd(&self, idx: usize) -> Option<(BorrowedFd<'_>, &str)> {
        let fd = self.fds.get(idx)?.as_ref()?.as_fd();
        let name = self.get_name(idx);
        Some((fd, name))
    }

    fn get_name(&self, idx: usize) -> &str {
        self.names
            .as_ref()
            .and_then(|v| v.get(idx))
            .map(|v| v.as_str())
            .unwrap_or("unknown")
    }

    /// Takes ownership of all file descriptors with the given name.
    ///
    /// This searches for all file descriptors that match the given name (from `LISTEN_FDNAMES`)
    /// and returns an iterator that yields owned file descriptors. The matching FDs are removed
    /// from internal storage.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use listen_fds::ListenFds;
    /// # use std::net::TcpListener;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut fds = unsafe { ListenFds::new()? };
    ///
    /// // Take all FDs named "http"
    /// for fd in fds.take("http") {
    ///     let listener = TcpListener::from(fd);
    ///     // Handle HTTP connections...
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn take(&mut self, name: impl Into<Cow<'static, str>>) -> impl Iterator<Item = OwnedFd> {
        let name = name.into();
        self.names
            .iter()
            .flatten()
            .zip(&mut self.fds)
            .filter_map(move |(s, fd)| (*s == name).then(|| fd.take()).flatten())
    }
}