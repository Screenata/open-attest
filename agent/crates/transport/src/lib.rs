use anyhow::{bail, Context, Result};
use open_attest_types::{
    AttestationPayload, EnrollmentRequest, EnrollmentResponse, ErrorResponse, HeartbeatPayload,
    ServerResponse,
};

/// Enroll the agent with the server.
pub fn enroll(
    server_url: &str,
    request: &EnrollmentRequest,
    _public_key_base64: &str,
) -> Result<EnrollmentResponse> {
    let url = format!("{}/v1/agents/enroll", server_url.trim_end_matches('/'));
    let client = reqwest::blocking::Client::new();

    let resp = client
        .post(&url)
        .json(request)
        .send()
        .context("Failed to send enrollment request")?;

    let status = resp.status();
    let body = resp.text().context("Failed to read enrollment response")?;

    if !status.is_success() {
        if let Ok(err) = serde_json::from_str::<ErrorResponse>(&body) {
            bail!(
                "Enrollment failed: {} - {}",
                err.error.code,
                err.error.message
            );
        }
        bail!("Enrollment failed with status {}: {}", status, body);
    }

    let enrollment: EnrollmentResponse =
        serde_json::from_str(&body).context("Failed to parse enrollment response")?;
    Ok(enrollment)
}

/// Submit an attestation payload to the server.
pub fn submit_attestation(
    server_url: &str,
    agent_id: &str,
    payload: &AttestationPayload,
    sign_fn: &dyn Fn(&[u8]) -> String,
) -> Result<ServerResponse> {
    let url = format!("{}/v1/attestations", server_url.trim_end_matches('/'));
    let body = serde_json::to_string(payload).context("Failed to serialize attestation")?;
    let signature = sign_fn(body.as_bytes());

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("X-Attestation-Signature", &signature)
        .header("X-Agent-Id", agent_id)
        .body(body)
        .send()
        .context("Failed to send attestation")?;

    let status = resp.status();
    let body = resp.text().context("Failed to read attestation response")?;

    if !status.is_success() {
        if let Ok(err) = serde_json::from_str::<ErrorResponse>(&body) {
            bail!(
                "Attestation failed: {} - {}",
                err.error.code,
                err.error.message
            );
        }
        bail!("Attestation failed with status {}: {}", status, body);
    }

    let response: ServerResponse =
        serde_json::from_str(&body).context("Failed to parse attestation response")?;
    Ok(response)
}

/// Send a heartbeat to the server.
pub fn send_heartbeat(
    server_url: &str,
    agent_id: &str,
    payload: &HeartbeatPayload,
    sign_fn: &dyn Fn(&[u8]) -> String,
) -> Result<ServerResponse> {
    let url = format!("{}/v1/heartbeat", server_url.trim_end_matches('/'));
    let body = serde_json::to_string(payload).context("Failed to serialize heartbeat")?;
    let signature = sign_fn(body.as_bytes());

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("X-Attestation-Signature", &signature)
        .header("X-Agent-Id", agent_id)
        .body(body)
        .send()
        .context("Failed to send heartbeat")?;

    let status = resp.status();
    let body = resp.text().context("Failed to read heartbeat response")?;

    if !status.is_success() {
        if let Ok(err) = serde_json::from_str::<ErrorResponse>(&body) {
            bail!(
                "Heartbeat failed: {} - {}",
                err.error.code,
                err.error.message
            );
        }
        bail!("Heartbeat failed with status {}: {}", status, body);
    }

    let response: ServerResponse =
        serde_json::from_str(&body).context("Failed to parse heartbeat response")?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use open_attest_types::*;

    #[test]
    fn enrollment_request_serialization() {
        let req = EnrollmentRequest {
            token: "tok_abc".to_string(),
            public_key: "cHViLWtleQ==".to_string(),
            hostname: "test-host".to_string(),
            platform: "macos".to_string(),
            platform_version: "14.4.1".to_string(),
            identity_anchors: IdentityAnchors {
                hardware_uuid: Some("uuid".to_string()),
                serial_hash: None,
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("tok_abc"));
        assert!(json.contains("cHViLWtleQ=="));
    }

    #[test]
    fn url_construction_strips_trailing_slash() {
        let url = format!("{}/v1/agents/enroll", "https://example.com/".trim_end_matches('/'));
        assert_eq!(url, "https://example.com/v1/agents/enroll");
    }

    #[test]
    fn url_construction_no_trailing_slash() {
        let url = format!("{}/v1/attestations", "https://example.com".trim_end_matches('/'));
        assert_eq!(url, "https://example.com/v1/attestations");
    }

    #[test]
    fn error_response_deserialization() {
        let json = r#"{"error":{"code":"TOKEN_EXPIRED","message":"Token has expired"}}"#;
        let err: ErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(err.error.code, "TOKEN_EXPIRED");
        assert_eq!(err.error.message, "Token has expired");
    }

    #[test]
    fn server_response_with_config() {
        let json = r#"{"ok":true,"config":{"heartbeat_interval_seconds":300,"snapshot_interval_seconds":3600}}"#;
        let resp: ServerResponse = serde_json::from_str(json).unwrap();
        assert!(resp.ok);
        assert_eq!(resp.config.as_ref().unwrap().heartbeat_interval_seconds, 300);
    }

    #[test]
    fn server_response_without_config() {
        let json = r#"{"ok":true}"#;
        let resp: ServerResponse = serde_json::from_str(json).unwrap();
        assert!(resp.ok);
        assert!(resp.config.is_none());
    }

    #[test]
    fn signing_header_format() {
        // Verify that our sign_fn produces a base64 string
        let sign_fn = |data: &[u8]| -> String {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(data)
        };

        let sig = sign_fn(b"test payload");
        // base64 of "test payload" should decode back
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &sig,
        )
        .unwrap();
        assert_eq!(decoded, b"test payload");
    }
}
