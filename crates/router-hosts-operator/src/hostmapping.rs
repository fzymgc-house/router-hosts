//! HostMapping CRD for explicit host-to-IP mappings

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// HostMapping spec - defines a single hostname mapping
#[derive(CustomResource, Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "router-hosts.fzymgc.house",
    version = "v1alpha1",
    kind = "HostMapping",
    plural = "hostmappings",
    shortname = "hm",
    namespaced = true,
    status = "HostMappingStatus",
    printcolumn = r#"{"name":"Hostname", "type":"string", "jsonPath":".spec.hostname"}"#,
    printcolumn = r#"{"name":"IP", "type":"string", "jsonPath":".spec.ipAddress"}"#,
    printcolumn = r#"{"name":"Synced", "type":"string", "jsonPath":".status.synced"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct HostMappingSpec {
    /// The hostname to create in router-hosts
    pub hostname: String,
    /// Optional IP address (uses IP resolution if omitted)
    pub ip_address: Option<String>,
    /// Optional hostname aliases
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Optional additional tags
    #[serde(default)]
    pub tags: Vec<String>,
}

/// HostMapping status
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HostMappingStatus {
    /// Whether the entry is synced to router-hosts
    #[serde(default)]
    pub synced: bool,
    /// The router-hosts entry ID (if synced)
    pub router_hosts_id: Option<String>,
    /// Last successful sync time
    pub last_sync_time: Option<String>,
    /// Error message if sync failed
    pub error: Option<String>,
    /// Status conditions
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

/// Kubernetes-style condition
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    /// Type of condition (e.g., "Synced", "Ready")
    #[serde(rename = "type")]
    pub type_: String,
    /// Status: "True", "False", or "Unknown"
    pub status: String,
    /// Last time the condition transitioned
    pub last_transition_time: String,
    /// Machine-readable reason for the condition
    pub reason: String,
    /// Human-readable message
    pub message: String,
}

impl Condition {
    pub fn synced(success: bool, reason: &str, message: &str) -> Self {
        Self {
            type_: "Synced".to_string(),
            status: if success { "True" } else { "False" }.to_string(),
            last_transition_time: chrono::Utc::now().to_rfc3339(),
            reason: reason.to_string(),
            message: message.to_string(),
        }
    }

    pub fn ready(ready: bool, reason: &str, message: &str) -> Self {
        Self {
            type_: "Ready".to_string(),
            status: if ready { "True" } else { "False" }.to_string(),
            last_transition_time: chrono::Utc::now().to_rfc3339(),
            reason: reason.to_string(),
            message: message.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_hostmapping() {
        let yaml = r#"
hostname: legacy-app.example.com
ipAddress: 10.0.0.50
aliases:
  - legacy.local
tags:
  - external
"#;
        let spec: HostMappingSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.hostname, "legacy-app.example.com");
        assert_eq!(spec.ip_address, Some("10.0.0.50".to_string()));
        assert_eq!(spec.aliases, vec!["legacy.local"]);
    }

    #[test]
    fn test_minimal_hostmapping() {
        let yaml = r#"
hostname: app.example.com
"#;
        let spec: HostMappingSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.hostname, "app.example.com");
        assert!(spec.ip_address.is_none());
        assert!(spec.aliases.is_empty());
    }

    #[test]
    fn test_condition_creation() {
        let cond = Condition::synced(true, "Success", "Entry synced");
        assert_eq!(cond.type_, "Synced");
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason, "Success");
    }
}
