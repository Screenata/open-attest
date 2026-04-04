use serde::{Deserialize, Serialize};

/// Tagged union for check values matching the JSON wire format.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", content = "value")]
pub enum CheckValue {
    #[serde(rename = "bool")]
    Bool(bool),
    #[serde(rename = "int")]
    Int(i64),
    #[serde(rename = "string")]
    Str(String),
    #[serde(rename = "string_list")]
    StringList(Vec<String>),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CheckResult {
    pub key: String,
    pub value: CheckValue,
    pub observed_at: String,
    pub source: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IdentityAnchors {
    pub hardware_uuid: Option<String>,
    pub serial_hash: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DeviceInfo {
    pub device_id: String,
    pub hostname: String,
    pub platform: String,
    pub platform_version: String,
    pub identity_anchors: IdentityAnchors,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserIdentity {
    pub username: Option<String>,
    pub email: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentInfo {
    pub name: String,
    pub version: String,
    pub agent_id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AttestationPayload {
    pub schema_version: String,
    pub attestation_id: String,
    pub collected_at: String,
    pub agent: AgentInfo,
    pub device: DeviceInfo,
    pub user: Option<UserIdentity>,
    pub checks: Vec<CheckResult>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EnrollmentRequest {
    pub token: String,
    pub public_key: String,
    pub hostname: String,
    pub platform: String,
    pub platform_version: String,
    pub identity_anchors: IdentityAnchors,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CollectionConfig {
    pub heartbeat_interval_seconds: u64,
    pub snapshot_interval_seconds: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EnrollmentResponse {
    pub agent_id: String,
    pub key_id: String,
    pub org_id: String,
    pub workspace_id: Option<String>,
    pub config: CollectionConfig,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HeartbeatPayload {
    pub device_id: String,
    pub agent_id: String,
    pub timestamp: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerResponse {
    pub ok: bool,
    pub config: Option<CollectionConfig>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ErrorResponse {
    pub error: ErrorDetail,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_value_bool_roundtrip() {
        let val = CheckValue::Bool(true);
        let json = serde_json::to_string(&val).unwrap();
        let parsed: CheckValue = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, CheckValue::Bool(true));
    }

    #[test]
    fn check_value_int_roundtrip() {
        let val = CheckValue::Int(42);
        let json = serde_json::to_string(&val).unwrap();
        let parsed: CheckValue = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, CheckValue::Int(42));
    }

    #[test]
    fn check_value_str_roundtrip() {
        let val = CheckValue::Str("hello".to_string());
        let json = serde_json::to_string(&val).unwrap();
        let parsed: CheckValue = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, CheckValue::Str("hello".to_string()));
    }

    #[test]
    fn check_value_string_list_roundtrip() {
        let val = CheckValue::StringList(vec!["a".to_string(), "b".to_string()]);
        let json = serde_json::to_string(&val).unwrap();
        let parsed: CheckValue = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed,
            CheckValue::StringList(vec!["a".to_string(), "b".to_string()])
        );
    }

    #[test]
    fn check_value_bool_json_format() {
        let val = CheckValue::Bool(true);
        let json = serde_json::to_string(&val).unwrap();
        assert!(json.contains("\"type\":\"bool\""));
        assert!(json.contains("\"value\":true"));
    }

    #[test]
    fn attestation_payload_roundtrip() {
        let payload = AttestationPayload {
            schema_version: "1.0".to_string(),
            attestation_id: "test-id".to_string(),
            collected_at: "2024-01-01T00:00:00Z".to_string(),
            agent: AgentInfo {
                name: "open-attest".to_string(),
                version: "0.1.0".to_string(),
                agent_id: "agent-1".to_string(),
            },
            device: DeviceInfo {
                device_id: "device-1".to_string(),
                hostname: "test-host".to_string(),
                platform: "macos".to_string(),
                platform_version: "14.4.1".to_string(),
                identity_anchors: IdentityAnchors {
                    hardware_uuid: Some("uuid-1".to_string()),
                    serial_hash: None,
                },
            },
            user: Some(UserIdentity {
                username: Some("testuser".to_string()),
                email: None,
            }),
            checks: vec![CheckResult {
                key: "disk.encryption".to_string(),
                value: CheckValue::Bool(true),
                observed_at: "2024-01-01T00:00:00Z".to_string(),
                source: "fdesetup".to_string(),
            }],
        };

        let json = serde_json::to_string(&payload).unwrap();
        let parsed: AttestationPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.schema_version, "1.0");
        assert_eq!(parsed.checks.len(), 1);
        assert_eq!(parsed.checks[0].key, "disk.encryption");
    }

    #[test]
    fn enrollment_request_serialize() {
        let req = EnrollmentRequest {
            token: "tok_123".to_string(),
            public_key: "base64key".to_string(),
            hostname: "myhost".to_string(),
            platform: "macos".to_string(),
            platform_version: "14.4.1".to_string(),
            identity_anchors: IdentityAnchors {
                hardware_uuid: Some("hw-uuid".to_string()),
                serial_hash: Some("serial-hash".to_string()),
            },
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("tok_123"));
        assert!(json.contains("base64key"));
        assert!(json.contains("hw-uuid"));
    }
}
