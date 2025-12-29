//! HostMapping CRD controller
//!
//! Watches router-hosts.fzymgc.house/v1alpha1 HostMapping resources and syncs them
//! to router-hosts entries.
//!
//! Unlike Ingress/IngressRoute controllers:
//! - No opt-in annotation required (creating a HostMapping IS the opt-in)
//! - Hostname is directly in spec.hostname (no parsing needed)
//! - Updates status subresource with sync state
//!
//! ## Deletion Handling
//!
//! This controller does not use finalizers. Deletion is handled by a separate garbage
//! collection process in the main loop that:
//! 1. Finds all entries tagged with `k8s-operator`
//! 2. Checks if the source resource (via `source:` tag) still exists
//! 3. Schedules deletion with grace period via `DeletionScheduler`
//!
//! When a HostMapping reappears (or another resource claims the same hostname),
//! the pending deletion is cancelled in the `reconcile` function.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::runtime::Controller;
use kube::Client as KubeClient;
use thiserror::Error;
use tracing::{debug, info, instrument, warn};

use crate::client::{ClientError, RouterHostsClientTrait};
use crate::config::tags;
use crate::hostmapping::{Condition, HostMapping, HostMappingStatus};
use crate::resolver::ResolverError;

use super::retry::{compute_backoff, ErrorKind};
use super::ControllerContext;

#[derive(Debug, Error)]
pub enum HostMappingError {
    #[error("IP resolution failed: {0}")]
    IpResolution(#[from] ResolverError),
    #[error("router-hosts client error: {0}")]
    Client(#[from] ClientError),
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),
    #[error("Missing required field: {0}")]
    MissingField(String),
    #[error("Invalid IP address in spec: {0}")]
    InvalidIp(String),
}

/// Validate an IP address string
fn is_valid_ip(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>().is_ok()
}

/// Build ownership tags for the HostMapping
fn build_tags(
    hostmapping: &HostMapping,
    custom_tags: &[String],
    default_tags: &[String],
    pre_existing: bool,
) -> Vec<String> {
    let mut result = vec![tags::OPERATOR.to_string()];

    // Add pre-existing marker if applicable
    if pre_existing {
        result.push(tags::PRE_EXISTING.to_string());
    }

    // Add source tracking
    if let Some(uid) = hostmapping.metadata.uid.as_ref() {
        result.push(format!("{}{}", tags::SOURCE_PREFIX, uid));
    }
    if let Some(ns) = hostmapping.metadata.namespace.as_ref() {
        result.push(format!("{}{}", tags::NAMESPACE_PREFIX, ns));
    }
    result.push(format!("{}HostMapping", tags::KIND_PREFIX));

    // Add custom tags from spec
    result.extend_from_slice(custom_tags);

    // Add default tags from config
    result.extend_from_slice(default_tags);

    result
}

/// Compare two tag lists regardless of order
fn tags_equal(a: &[String], b: &[String]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut a_sorted: Vec<_> = a.iter().collect();
    let mut b_sorted: Vec<_> = b.iter().collect();
    a_sorted.sort();
    b_sorted.sort();
    a_sorted == b_sorted
}

/// Update the status subresource of a HostMapping
async fn update_status(
    api: &Api<HostMapping>,
    name: &str,
    status: HostMappingStatus,
) -> Result<(), HostMappingError> {
    let patch = serde_json::json!({
        "status": status
    });

    api.patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;

    Ok(())
}

/// Reconcile a single HostMapping resource
#[instrument(
    skip(ctx, hostmapping),
    fields(
        name = %hostmapping.metadata.name.as_deref().unwrap_or("unknown"),
        namespace = %hostmapping.metadata.namespace.as_deref().unwrap_or("default")
    )
)]
async fn reconcile(
    hostmapping: Arc<HostMapping>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, HostMappingError> {
    let name = hostmapping
        .metadata
        .name
        .as_deref()
        .ok_or_else(|| HostMappingError::MissingField("metadata.name".to_string()))?;
    let namespace = hostmapping
        .metadata
        .namespace
        .as_deref()
        .ok_or_else(|| HostMappingError::MissingField("metadata.namespace".to_string()))?;

    let hostname = &hostmapping.spec.hostname;

    info!(
        name = %name,
        namespace = %namespace,
        hostname = %hostname,
        "Reconciling HostMapping"
    );

    // Create API client for status updates using shared client from context
    let api: Api<HostMapping> = Api::namespaced(ctx.kube_client.clone(), namespace);

    // Resolve IP address
    let ip = match &hostmapping.spec.ip_address {
        Some(ip) => {
            // Validate the IP address format
            if !is_valid_ip(ip) {
                let error_msg = format!("Invalid IP address: {}", ip);
                warn!(hostname = %hostname, ip = %ip, "Invalid IP address in spec");
                let status = HostMappingStatus {
                    synced: false,
                    router_hosts_id: None,
                    last_sync_time: None,
                    error: Some(error_msg.clone()),
                    conditions: vec![Condition::synced(false, "InvalidIP", &error_msg)],
                };
                update_status(&api, name, status).await?;
                return Err(HostMappingError::InvalidIp(ip.clone()));
            }
            debug!(hostname = %hostname, ip = %ip, "Using explicit IP from spec");
            ip.clone()
        }
        None => {
            // Use resolver with empty annotations (no custom IP override)
            let annotations = std::collections::BTreeMap::new();
            match ctx.resolver.resolve(&annotations).await {
                Ok(ip) => {
                    debug!(hostname = %hostname, ip = %ip, "Resolved IP via resolver");
                    ip
                }
                Err(e) => {
                    warn!(hostname = %hostname, error = %e, "Failed to resolve IP");
                    // Update status with error
                    let status = HostMappingStatus {
                        synced: false,
                        router_hosts_id: None,
                        last_sync_time: None,
                        error: Some(format!("IP resolution failed: {}", e)),
                        conditions: vec![Condition::synced(
                            false,
                            "ResolutionFailed",
                            &format!("Failed to resolve IP: {}", e),
                        )],
                    };
                    update_status(&api, name, status).await?;
                    return Err(e.into());
                }
            }
        }
    };

    let aliases = hostmapping.spec.aliases.clone();
    let custom_tags = hostmapping.spec.tags.clone();

    // Check if entry already exists
    match ctx.client.find_by_hostname(hostname).await {
        Ok(Some(existing)) => {
            // Cancel any pending deletion - regardless of ownership
            if ctx.deletion.is_pending(&existing.id).await {
                ctx.deletion.cancel(&existing.id).await;
                info!(
                    entry_id = %existing.id,
                    hostname = %hostname,
                    "Cancelled pending deletion"
                );
            }

            let source_tag = hostmapping
                .metadata
                .uid
                .as_ref()
                .map(|uid| format!("{}{}", tags::SOURCE_PREFIX, uid));

            let is_ours = source_tag
                .as_ref()
                .map(|t| existing.tags.contains(t))
                .unwrap_or(false);
            let has_operator_tag = existing.tags.contains(&tags::OPERATOR.to_string());

            if is_ours {
                // Update if needed
                let new_tags =
                    build_tags(&hostmapping, &custom_tags, &ctx.config.default_tags, false);

                // Use set comparison for tags to avoid order-dependent updates
                if existing.ip_address != ip
                    || existing.aliases != aliases
                    || !tags_equal(&existing.tags, &new_tags)
                {
                    match ctx
                        .client
                        .update_host(
                            &existing.id,
                            Some(ip.clone()),
                            Some(aliases.clone()),
                            Some(new_tags),
                            Some(existing.version.clone()),
                        )
                        .await
                    {
                        Ok(_) => {
                            info!(
                                entry_id = %existing.id,
                                hostname = %hostname,
                                ip = %ip,
                                "Updated host entry"
                            );

                            // Update status: success
                            let status = HostMappingStatus {
                                synced: true,
                                router_hosts_id: Some(existing.id.clone()),
                                last_sync_time: Some(chrono::Utc::now().to_rfc3339()),
                                error: None,
                                conditions: vec![Condition::synced(
                                    true,
                                    "Synced",
                                    "Entry updated successfully",
                                )],
                            };
                            update_status(&api, name, status).await?;
                        }
                        Err(e) => {
                            warn!(
                                entry_id = %existing.id,
                                hostname = %hostname,
                                error = %e,
                                "Failed to update host entry"
                            );

                            // Update status: failure
                            let status = HostMappingStatus {
                                synced: false,
                                router_hosts_id: Some(existing.id),
                                last_sync_time: None,
                                error: Some(format!("Update failed: {}", e)),
                                conditions: vec![Condition::synced(
                                    false,
                                    "UpdateFailed",
                                    &format!("Failed to update entry: {}", e),
                                )],
                            };
                            update_status(&api, name, status).await?;
                            return Err(e.into());
                        }
                    }
                } else {
                    debug!(hostname = %hostname, "Entry unchanged");
                }
            } else if has_operator_tag {
                debug!(hostname = %hostname, "Entry owned by different resource, skipping");

                // Update status: conflict
                let status = HostMappingStatus {
                    synced: false,
                    router_hosts_id: None,
                    last_sync_time: None,
                    error: Some("Hostname already claimed by another resource".to_string()),
                    conditions: vec![Condition::synced(
                        false,
                        "Conflict",
                        "Hostname already claimed by another Kubernetes resource",
                    )],
                };
                update_status(&api, name, status).await?;
            } else {
                // Adopt pre-existing entry
                let new_tags =
                    build_tags(&hostmapping, &custom_tags, &ctx.config.default_tags, true);

                match ctx
                    .client
                    .update_host(
                        &existing.id,
                        Some(ip.clone()),
                        Some(aliases.clone()),
                        Some(new_tags),
                        Some(existing.version.clone()),
                    )
                    .await
                {
                    Ok(_) => {
                        info!(
                            entry_id = %existing.id,
                            hostname = %hostname,
                            ip = %ip,
                            "Adopted pre-existing entry"
                        );

                        // Update status: success
                        let status = HostMappingStatus {
                            synced: true,
                            router_hosts_id: Some(existing.id.clone()),
                            last_sync_time: Some(chrono::Utc::now().to_rfc3339()),
                            error: None,
                            conditions: vec![Condition::synced(
                                true,
                                "Adopted",
                                "Adopted pre-existing entry",
                            )],
                        };
                        update_status(&api, name, status).await?;
                    }
                    Err(e) => {
                        warn!(
                            entry_id = %existing.id,
                            hostname = %hostname,
                            error = %e,
                            "Failed to adopt pre-existing entry"
                        );

                        // Update status: failure
                        let status = HostMappingStatus {
                            synced: false,
                            router_hosts_id: Some(existing.id),
                            last_sync_time: None,
                            error: Some(format!("Adoption failed: {}", e)),
                            conditions: vec![Condition::synced(
                                false,
                                "AdoptionFailed",
                                &format!("Failed to adopt entry: {}", e),
                            )],
                        };
                        update_status(&api, name, status).await?;
                        return Err(e.into());
                    }
                }
            }
        }
        Ok(None) => {
            // Create new entry
            let new_tags = build_tags(&hostmapping, &custom_tags, &ctx.config.default_tags, false);

            match ctx.client.add_host(hostname, &ip, aliases, new_tags).await {
                Ok(entry) => {
                    info!(
                        entry_id = %entry.id,
                        hostname = %hostname,
                        ip = %ip,
                        "Created host entry"
                    );

                    // Update status: success
                    let status = HostMappingStatus {
                        synced: true,
                        router_hosts_id: Some(entry.id),
                        last_sync_time: Some(chrono::Utc::now().to_rfc3339()),
                        error: None,
                        conditions: vec![Condition::synced(
                            true,
                            "Created",
                            "Entry created successfully",
                        )],
                    };
                    update_status(&api, name, status).await?;
                }
                Err(e) => {
                    warn!(
                        hostname = %hostname,
                        error = %e,
                        "Failed to create host entry"
                    );

                    // Update status: failure
                    let status = HostMappingStatus {
                        synced: false,
                        router_hosts_id: None,
                        last_sync_time: None,
                        error: Some(format!("Creation failed: {}", e)),
                        conditions: vec![Condition::synced(
                            false,
                            "CreationFailed",
                            &format!("Failed to create entry: {}", e),
                        )],
                    };
                    update_status(&api, name, status).await?;
                    return Err(e.into());
                }
            }
        }
        Err(e) => {
            warn!(
                hostname = %hostname,
                error = %e,
                "Failed to query existing entry"
            );

            // Update status: failure
            let status = HostMappingStatus {
                synced: false,
                router_hosts_id: None,
                last_sync_time: None,
                error: Some(format!("Query failed: {}", e)),
                conditions: vec![Condition::synced(
                    false,
                    "QueryFailed",
                    &format!("Failed to query existing entry: {}", e),
                )],
            };
            update_status(&api, name, status).await?;
            return Err(e.into());
        }
    }

    // Reset retry counter on success
    if let Some(uid) = hostmapping.metadata.uid.as_deref() {
        ctx.retry_tracker.reset(uid);
    }

    // Requeue for periodic resync
    Ok(Action::requeue(Duration::from_secs(300)))
}

/// Classify error type for retry behavior
fn classify_error(error: &HostMappingError) -> ErrorKind {
    match error {
        HostMappingError::IpResolution(_) => ErrorKind::Transient,
        HostMappingError::Client(_) => ErrorKind::Transient,
        HostMappingError::Kube(_) => ErrorKind::Transient,
        // Invalid config won't recover without resource change
        HostMappingError::MissingField(_) => ErrorKind::Permanent,
        HostMappingError::InvalidIp(_) => ErrorKind::Permanent,
    }
}

/// Error policy for the controller with exponential backoff
fn error_policy(
    hostmapping: Arc<HostMapping>,
    error: &HostMappingError,
    ctx: Arc<ControllerContext>,
) -> Action {
    let uid = hostmapping.metadata.uid.as_deref().unwrap_or("unknown");
    let kind = classify_error(error);

    // RetryTracker uses std::sync::Mutex so we can call this synchronously
    let attempt = ctx.retry_tracker.increment(uid);

    warn!(
        name = %hostmapping.metadata.name.as_deref().unwrap_or("unknown"),
        error = %error,
        attempt = attempt,
        error_kind = ?kind,
        "HostMapping reconciliation failed"
    );

    compute_backoff(attempt, kind)
}

/// Start the HostMapping controller
pub async fn run(client: KubeClient, ctx: Arc<ControllerContext>) {
    let hostmappings: Api<HostMapping> = Api::all(client);

    info!("Starting HostMapping controller");

    Controller::new(hostmappings, WatcherConfig::default())
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|result| async move {
            match result {
                Ok((obj, _action)) => {
                    debug!(
                        name = %obj.name,
                        "HostMapping reconciled successfully"
                    );
                }
                Err(e) => {
                    warn!(error = %e, "HostMapping controller error");
                }
            }
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    use crate::hostmapping::HostMappingSpec;

    fn test_hostmapping(hostname: &str, ip: Option<&str>, uid: &str) -> HostMapping {
        HostMapping {
            metadata: ObjectMeta {
                name: Some("test-hostmapping".to_string()),
                namespace: Some("default".to_string()),
                uid: Some(uid.to_string()),
                ..Default::default()
            },
            spec: HostMappingSpec {
                hostname: hostname.to_string(),
                ip_address: ip.map(|s| s.to_string()),
                aliases: vec![],
                tags: vec![],
            },
            status: None,
        }
    }

    #[test]
    fn test_build_tags() {
        let hm = test_hostmapping("app.example.com", Some("10.0.0.1"), "abc-123");
        let custom_tags = vec!["custom".to_string()];
        let default_tags = vec!["default".to_string()];

        let tags = build_tags(&hm, &custom_tags, &default_tags, false);

        assert!(tags.contains(&"k8s-operator".to_string()));
        assert!(tags.contains(&"source:abc-123".to_string()));
        assert!(tags.contains(&"namespace:default".to_string()));
        assert!(tags.contains(&"kind:HostMapping".to_string()));
        assert!(tags.contains(&"custom".to_string()));
        assert!(tags.contains(&"default".to_string()));
        assert!(!tags.contains(&"pre-existing:true".to_string()));
    }

    #[test]
    fn test_build_tags_pre_existing() {
        let hm = test_hostmapping("app.example.com", Some("10.0.0.1"), "abc-123");
        let tags = build_tags(&hm, &[], &[], true);

        assert!(tags.contains(&"pre-existing:true".to_string()));
    }

    #[test]
    fn test_build_tags_with_custom() {
        let mut hm = test_hostmapping("app.example.com", Some("10.0.0.1"), "abc-123");
        hm.spec.tags = vec!["env:prod".to_string(), "team:platform".to_string()];

        let tags = build_tags(&hm, &hm.spec.tags, &[], false);

        assert!(tags.contains(&"env:prod".to_string()));
        assert!(tags.contains(&"team:platform".to_string()));
    }
}
