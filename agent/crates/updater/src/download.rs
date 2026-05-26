//! HTTP downloads for the updater.
//!
//! Uses the blocking reqwest client. 5-minute timeout. Streams to disk so
//! we don't buffer 10MB in memory.

use anyhow::{bail, Context, Result};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

const TIMEOUT_SECS: u64 = 300;
const MIN_BINARY_SIZE: u64 = 1_000_000;
const MAX_BINARY_SIZE: u64 = 100_000_000;
const MAX_SIG_SIZE: u64 = 1_024;

fn client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .user_agent(format!("open-attest-updater/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .context("build http client")
}

/// Downloads `url` to `dest`, streaming. Enforces size bounds for binaries.
pub fn download_binary(url: &str, dest: &Path) -> Result<u64> {
    let mut resp = client()?
        .get(url)
        .send()
        .with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        bail!("GET {} returned status {}", url, resp.status());
    }

    if let Some(len) = resp.content_length() {
        if len < MIN_BINARY_SIZE {
            bail!("binary too small: {} bytes (min {})", len, MIN_BINARY_SIZE);
        }
        if len > MAX_BINARY_SIZE {
            bail!("binary too large: {} bytes (max {})", len, MAX_BINARY_SIZE);
        }
    }

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let mut file = File::create(dest).with_context(|| format!("create {}", dest.display()))?;
    let mut written: u64 = 0;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = std::io::Read::read(&mut resp, &mut buf).context("read body")?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n]).context("write body")?;
        written += n as u64;
        if written > MAX_BINARY_SIZE {
            // Drop partial; caller cleans up.
            bail!("binary exceeded {} bytes during stream", MAX_BINARY_SIZE);
        }
    }
    file.flush().ok();
    drop(file);

    if written < MIN_BINARY_SIZE {
        bail!(
            "binary too small after download: {} bytes (min {})",
            written,
            MIN_BINARY_SIZE
        );
    }

    Ok(written)
}

/// Downloads a small companion file (signature, ~128 bytes hex). No streaming.
pub fn download_small(url: &str) -> Result<String> {
    let resp = client()?
        .get(url)
        .send()
        .with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        bail!("GET {} returned status {}", url, resp.status());
    }
    if let Some(len) = resp.content_length() {
        if len > MAX_SIG_SIZE {
            bail!("signature file too large: {} bytes", len);
        }
    }
    let body = resp.text().with_context(|| format!("read body of {url}"))?;
    if body.len() as u64 > MAX_SIG_SIZE {
        bail!("signature file too large: {} bytes", body.len());
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::sync::mpsc;
    use std::thread;
    use tempfile::tempdir;
    use tiny_http::{Header, Response, Server};

    /// Tiny http server that serves a fixed body once. Returns (port, join_handle).
    fn serve_once(body: Vec<u8>) -> (u16, mpsc::Receiver<()>) {
        let server = Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            if let Ok(req) = server.recv() {
                let mut resp = Response::from_data(body);
                resp.add_header(
                    Header::from_bytes(&b"Content-Type"[..], &b"application/octet-stream"[..])
                        .unwrap(),
                );
                let _ = req.respond(resp);
            }
            let _ = tx.send(());
        });
        (port, rx)
    }

    #[test]
    fn download_binary_writes_correct_bytes() {
        // Construct a 1.5MB payload (above MIN_BINARY_SIZE).
        let payload = vec![0xABu8; 1_500_000];
        let (port, _done) = serve_once(payload.clone());

        let dir = tempdir().unwrap();
        let dest = dir.path().join("downloaded");
        let url = format!("http://127.0.0.1:{port}/binary");
        let n = download_binary(&url, &dest).unwrap();
        assert_eq!(n, 1_500_000);
        let mut bytes = Vec::new();
        std::fs::File::open(&dest)
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, payload);
    }

    #[test]
    fn download_binary_rejects_too_small() {
        let payload = vec![0u8; 500];
        let (port, _done) = serve_once(payload);
        let dir = tempdir().unwrap();
        let dest = dir.path().join("small");
        let url = format!("http://127.0.0.1:{port}/binary");
        assert!(download_binary(&url, &dest).is_err());
    }

    #[test]
    fn download_small_returns_body() {
        let payload = b"abcdef1234".to_vec();
        let (port, _done) = serve_once(payload.clone());
        let url = format!("http://127.0.0.1:{port}/sig");
        let body = download_small(&url).unwrap();
        assert_eq!(body.as_bytes(), payload);
    }

    #[test]
    fn download_404_errors() {
        let server = Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        thread::spawn(move || {
            if let Ok(req) = server.recv() {
                let _ = req.respond(Response::empty(404));
            }
        });
        let url = format!("http://127.0.0.1:{port}/missing");
        assert!(download_small(&url).is_err());
    }
}
