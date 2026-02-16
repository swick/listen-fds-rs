// SPDX-FileCopyrightText: 2026 The listen-fds-rs authors
// SPDX-License-Identifier: MIT OR Apache-2.0

use pidfd_util::{self, PidFdExt};
use std::{borrow::Cow, env, num::ParseIntError, os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd}};
use thiserror::Error;


#[derive(Error, Debug)]
pub enum ListenFdsError {
    #[error("Not socket activated")]
    NoListenFds,
    #[error("The socket activation targets another PID (target: {listen_pid}, self: {self_pid}")]
    PidMissmatch {
        listen_pid: u64,
        self_pid: u64,
    },
    #[error("LISTEN_FDS contains out of range FDs")]
    OutOfRangeListenFds,
    #[error("LISTEN_PID does not contain a valid PID")]
    BadListenPid(ParseIntError),
    #[error("LISTEN_PIDFDID does not contain a valid Pidfd ID")]
    BadListenPidfdId(ParseIntError),
    #[error("LISTEN_FDS does not contain a valid Pidfd ID")]
    BadListenFds(ParseIntError),
    #[error("LISTEN_FDNAMES contains a wrong number of names")]
    BadListenFdNames,
}

pub struct ListenFds {
    fds: Vec<Option<OwnedFd>>,
    names: Option<Vec<String>>,
}

impl ListenFds {
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
            let listen_pid: u32 = listen_pid.trim().parse().map_err(|e| ListenFdsError::BadListenPid(e))?;
            let self_pid = std::process::id();
            if listen_pid != self_pid {
                return Err(ListenFdsError::PidMissmatch {
                    self_pid: self_pid.into(),
                    listen_pid: listen_pid.into(),
                });
            }
        }

        if let Ok(listen_pidfdid) = listen_pidfdid {
            let listen_pidfdid: u64 = listen_pidfdid.trim().parse().map_err(|e| ListenFdsError::BadListenPidfdId(e))?;
            if let Some(self_pidfdid) = pidfd_util::PidFd::from_self().map(|pfd| pfd.get_id()).flatten().ok() {
                if listen_pidfdid != self_pidfdid {
                    return Err(ListenFdsError::PidMissmatch {
                        self_pid: self_pidfdid,
                        listen_pid: listen_pidfdid,
                    });
                }
            }
        }

        let listen_fds = listen_fds.map_err(|_| ListenFdsError::NoListenFds)?;
        let listen_fds: usize = listen_fds.trim().parse().map_err(|e| ListenFdsError::BadListenFds(e))?;
        if LISTEN_FDS_START + listen_fds > std::mem::size_of::<std::ffi::c_int>() || listen_fds <= 0 {
            return Err(ListenFdsError::OutOfRangeListenFds);
        }

        let fds: Vec<Option<OwnedFd>> = (0..listen_fds).into_iter()
            .map(|i| unsafe { Some(OwnedFd::from_raw_fd((LISTEN_FDS_START + i) as RawFd)) })
            .collect();
        fds.iter().flatten().for_each(|fd| unsafe { Self::ensure_cloexec(fd) });

        let names: Option<Vec<String>> = listen_fdnames.ok().map(|names| {
            names.split(':').map(|s| s.to_owned()).collect::<Vec<_>>()
        });

        if let Some(n) = &names && n.len() != fds.len() {
            return Err(ListenFdsError::BadListenFdNames);
        }

        Ok(ListenFds {
            fds: fds,
            names: names,
        })
    }

    unsafe fn ensure_cloexec<Fd: AsFd>(fd: Fd) {
        let raw_fd = fd.as_fd().as_raw_fd();
        let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFD) };

        if flags >= 0 && (flags & libc::FD_CLOEXEC) != libc::FD_CLOEXEC {
            unsafe { libc::fcntl(raw_fd, libc::F_SETFD, flags | libc::FD_CLOEXEC); }
        }
    }

    pub fn len(&self) -> usize {
        self.fds.len()
    }

    pub fn take_fd(&mut self, idx: usize) -> Option<OwnedFd> {
        self.fds.get_mut(idx)?.take()
    }

    pub fn get_fd(&self, idx: usize) -> Option<BorrowedFd<'_>> {
        Some(self.fds.get(idx)?.as_ref()?.as_fd())
    }

    pub fn get_name(&self, idx: usize) -> Option<&str> {
        Some(self.names.as_ref()?.get(idx)?)
    }

    pub fn take(&mut self, name: impl Into<Cow<'static, str>>) -> impl Iterator<Item=OwnedFd> {
        let name = name.into();
        self.names.iter().flatten().zip(&mut self.fds).filter_map(move |(s, fd)| {
            (*s == name).then(|| fd.take()).flatten()
        })
    }
}