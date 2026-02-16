# listen-fds

A Rust library for handling [systemd socket activation](https://www.freedesktop.org/software/systemd/man/latest/sd_listen_fds.html).

## What is Socket Activation?

Socket activation is a systemd feature that allows services to:
- Start on-demand when connections arrive
- Perform zero-downtime restarts (systemd holds the socket during restart)
- Improve resource utilization (services don't run until needed)

When systemd socket-activates your service, it passes listening sockets (or other file descriptors) via environment variables. This library provides a safe, idiomatic Rust interface for receiving those file descriptors.

## Features

- Safe ownership of socket-activated file descriptors
- Automatic PID validation (supports both `LISTEN_PID` and the newer `LISTEN_PIDFDID`)
- Named file descriptor lookup via `LISTEN_FDNAMES`
- Automatic `FD_CLOEXEC` setting for security
- Zero-copy borrowing or ownership transfer of FDs
- FD retrieval methods return both the file descriptor and its name (or "unknown" if unnamed)

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
listen-fds = { git = "https://github.com/swick/listen-fds-rs.git" }
```

## Usage

### Basic Example

```rust
use listen_fds::ListenFds;
use std::os::unix::net::UnixListener;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // SAFETY: Must be called early in main(), before spawning threads
    let mut fds = unsafe { ListenFds::new()? };

    println!("Received {} file descriptors", fds.len());

    // Take ownership of the first FD
    if let Some((fd, name)) = fds.take_fd(0) {
        println!("Taking FD named: {}", name);
        let listener = UnixListener::from(fd);
        // Use the listener...
    }

    Ok(())
}
```

### Using Named File Descriptors

```rust
use listen_fds::ListenFds;
use std::os::unix::net::TcpListener;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // SAFETY: Must be called early in main(), before spawning threads
    let mut fds = unsafe { ListenFds::new()? };

    // Get all FDs named "http"
    for fd in fds.take("http") {
        let listener = TcpListener::from(fd);
        // Handle HTTP connections...
    }

    Ok(())
}
```

### Borrowing File Descriptors

```rust
use listen_fds::ListenFds;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // SAFETY: Must be called early in main(), before spawning threads
    let fds = unsafe { ListenFds::new()? };

    // Borrow an FD without taking ownership
    if let Some((fd, name)) = fds.get_fd(0) {
        println!("FD 0 name: {}", name);
        // Use borrowed fd...
    }

    Ok(())
}
```

## Systemd Configuration Example

### Socket Unit (`myservice.socket`)

```ini
[Unit]
Description=My Service Socket

[Socket]
ListenStream=/run/myservice.sock
FileDescriptorName=main

[Install]
WantedBy=sockets.target
```

### Service Unit (`myservice.service`)

```ini
[Unit]
Description=My Service
Requires=myservice.socket

[Service]
Type=simple
ExecStart=/usr/bin/myservice
```

Enable socket activation:
```bash
systemctl enable --now myservice.socket
```

## Safety

The `ListenFds::new()` function is marked `unsafe` because:
1. It modifies the process environment by removing `LISTEN_*` variables
2. It must be called before spawning any threads (to avoid race conditions with environment access)
3. It must be called at most once per process

Call it early in your `main()` function, before any thread spawning occurs.

## PID Validation

The library validates that file descriptors are intended for your process using:
- **`LISTEN_PID`**: Traditional PID-based validation
- **`LISTEN_PIDFDID`**: Modern pidfd-based validation (more secure, resistant to PID reuse attacks)

If either validation fails, `ListenFds::new()` returns an error.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSES/Apache-2.0.txt) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSES/MIT.txt) or http://opensource.org/licenses/MIT)

at your option.

## References

- [systemd.socket(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html)
- [sd_listen_fds(3)](https://www.freedesktop.org/software/systemd/man/latest/sd_listen_fds.html)
- [Socket Activation](https://0pointer.de/blog/projects/socket-activation.html) by Lennart Poettering
