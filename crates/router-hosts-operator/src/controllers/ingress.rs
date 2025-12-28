//! Ingress controller
//!
//! Watches networking.k8s.io/v1 Ingress resources and creates/updates/deletes
//! corresponding router-hosts entries.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use k8s_openapi::api::networking::v1::Ingress;
use kube::runtime::controller::Action;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::runtime::Controller;
use kube::{Api, Client};
use thiserror::Error;
use tracing::{debug, info, instrument, warn};

use crate::client::ClientError;
use crate::config::{annotations, tags};
use crate::resolver::ResolverError;

use super::retry::{compute_backoff, ErrorKind};
use super::ControllerContext;

#[derive(Debug, Error)]
pub enum IngressError {
    #[error("IP resolution failed: {0}")]
    IpResolution(#[from] ResolverError),
    #[error("router-hosts client error: {0}")]
    Client(#[from] ClientError),
    #[error("Missing required field: {0}")]
    MissingField(String),
}

/// Check if Ingress has opt-in annotation
fn is_enabled(annotations: &BTreeMap<String, String>) -> bool {
    annotations
        .get(annotations::ENABLED)
        .map(|v| v == "true")
        .unwrap_or(false)
}

/// Extract hosts from Ingress spec
fn extract_hosts(ingress: &Ingress) -> Vec<String> {
    let mut hosts = Vec::new();

    if let Some(spec) = &ingress.spec {
        if let Some(rules) = &spec.rules {
            for rule in rules {
                if let Some(host) = &rule.host {
                    if !host.is_empty() {
                        hosts.push(host.clone());
                    }
                }
            }
        }
    }

    hosts
}

/// Build ownership tags for the Ingress
fn build_tags(
    ingress: &Ingress,
    custom_tags: &[String],
    default_tags: &[String],
    pre_existing: bool,
) -> Vec<String> {
    let mut tags = vec![tags::OPERATOR.to_string()];

    // Add pre-existing marker if applicable
    if pre_existing {
        tags.push(tags::PRE_EXISTING.to_string());
    }

    // Add source tracking
    if let Some(uid) = ingress.metadata.uid.as_ref() {
        tags.push(format!("{}{}", tags::SOURCE_PREFIX, uid));
    }
    if let Some(namespace) = ingress.metadata.namespace.as_ref() {
        tags.push(format!("{}{}", tags::NAMESPACE_PREFIX, namespace));
    }
    tags.push(format!("{}Ingress", tags::KIND_PREFIX));

    // Add custom tags from annotation
    tags.extend_from_slice(custom_tags);

    // Add default tags from config
    tags.extend_from_slice(default_tags);

    tags
}

/// Parse aliases from annotation
fn parse_aliases(annotations: &BTreeMap<String, String>) -> Vec<String> {
    annotations
        .get(annotations::ALIASES)
        .map(|s| {
            s.split(',')
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Parse custom tags from annotation
fn parse_custom_tags(annotations: &BTreeMap<String, String>) -> Vec<String> {
    annotations
        .get(annotations::TAGS)
        .map(|s| {
            s.split(',')
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Reconcile a single Ingress resource
#[instrument(skip(ctx, ingress), fields(
    namespace = %ingress.metadata.namespace.as_deref().unwrap_or("default"),
    name = %ingress.metadata.name.as_deref().unwrap_or("unknown"),
))]
async fn reconcile(
    ingress: Arc<Ingress>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, IngressError> {
    let annotations = ingress.metadata.annotations.as_ref();

    // Skip if not enabled
    if let Some(annots) = annotations {
        if !is_enabled(annots) {
            debug!("Ingress not enabled, skipping");
            return Ok(Action::await_change());
        }
    } else {
        debug!("No annotations, skipping");
        return Ok(Action::await_change());
    }

    let annotations = annotations.ok_or(IngressError::MissingField("annotations".to_string()))?;

    // Extract hosts from spec
    let hosts = extract_hosts(&ingress);
    if hosts.is_empty() {
        debug!("No hosts found in Ingress spec");
        return Ok(Action::requeue(Duration::from_secs(60)));
    }

    // Resolve IP address
    let ip = ctx.resolver.resolve(annotations).await?;
    debug!(ip = %ip, "Resolved IP address");

    // Parse additional configuration
    let aliases = parse_aliases(annotations);
    let custom_tags = parse_custom_tags(annotations);

    // Process each host
    for hostname in hosts {
        // Check if entry already exists
        match ctx.client.find_by_hostname(&hostname).await? {
            Some(existing) => {
                // Check if this entry is owned by us
                let source_tag = format!(
                    "{}{}",
                    tags::SOURCE_PREFIX,
                    ingress.metadata.uid.as_deref().unwrap_or("")
                );
                let owned_by_us = existing.tags.contains(&source_tag);
                let pre_existing =
                    !owned_by_us && !existing.tags.contains(&tags::OPERATOR.to_string());

                // Cancel any pending deletion
                if ctx.deletion.is_pending(&existing.id).await {
                    ctx.deletion.cancel(&existing.id).await;
                    info!(
                        entry_id = %existing.id,
                        hostname = %hostname,
                        "Cancelled pending deletion"
                    );
                }

                // Build tags, marking as pre-existing if we're adopting it
                let new_tags = build_tags(
                    &ingress,
                    &custom_tags,
                    &ctx.config.default_tags,
                    pre_existing,
                );

                // Update entry if needed
                if existing.ip_address != ip
                    || existing.aliases != aliases
                    || existing.tags != new_tags
                {
                    ctx.client
                        .update_host(
                            &existing.id,
                            Some(&ip),
                            Some(aliases.clone()),
                            Some(new_tags),
                            Some(&existing.version),
                        )
                        .await?;

                    info!(
                        entry_id = %existing.id,
                        hostname = %hostname,
                        ip = %ip,
                        pre_existing = pre_existing,
                        "Updated host entry"
                    );
                } else {
                    debug!(hostname = %hostname, "Entry unchanged");
                }
            }
            None => {
                // Create new entry
                let new_tags = build_tags(&ingress, &custom_tags, &ctx.config.default_tags, false);
                let entry = ctx
                    .client
                    .add_host(&hostname, &ip, aliases.clone(), new_tags)
                    .await?;

                info!(
                    entry_id = %entry.id,
                    hostname = %hostname,
                    ip = %ip,
                    "Created host entry"
                );
            }
        }
    }

    // Reset retry counter on success
    if let Some(uid) = ingress.metadata.uid.as_deref() {
        ctx.retry_tracker.reset(uid).await;
    }

    // Requeue for periodic resync
    Ok(Action::requeue(Duration::from_secs(300)))
}

/// Classify error type for retry behavior
fn classify_error(error: &IngressError) -> ErrorKind {
    match error {
        // Network and client errors are transient
        IngressError::IpResolution(_) => ErrorKind::Transient,
        IngressError::Client(_) => ErrorKind::Transient,
        // Missing fields are permanent - won't resolve without resource change
        IngressError::MissingField(_) => ErrorKind::Permanent,
    }
}

/// Error policy for the controller with exponential backoff
fn error_policy(
    ingress: Arc<Ingress>,
    error: &IngressError,
    ctx: Arc<ControllerContext>,
) -> Action {
    let uid = ingress.metadata.uid.as_deref().unwrap_or("unknown");
    let kind = classify_error(error);

    // Get current attempt count and increment synchronously
    let attempt = futures::executor::block_on(ctx.retry_tracker.increment(uid));

    warn!(
        error = %error,
        attempt = attempt,
        error_kind = ?kind,
        "Reconciliation error"
    );

    compute_backoff(attempt, kind)
}

/// Run the Ingress controller
pub async fn run(client: Client, ctx: Arc<ControllerContext>) {
    let ingresses: Api<Ingress> = Api::all(client.clone());

    info!("Starting Ingress controller");

    Controller::new(ingresses, WatcherConfig::default())
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .filter_map(|x| async move { std::result::Result::ok(x) })
        .for_each(|_| futures::future::ready(()))
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn test_ingress(annotations: BTreeMap<String, String>, uid: &str) -> Ingress {
        Ingress {
            metadata: ObjectMeta {
                name: Some("test-ingress".to_string()),
                namespace: Some("default".to_string()),
                uid: Some(uid.to_string()),
                annotations: Some(annotations),
                ..Default::default()
            },
            spec: Some(k8s_openapi::api::networking::v1::IngressSpec {
                rules: Some(vec![k8s_openapi::api::networking::v1::IngressRule {
                    host: Some("test.example.com".to_string()),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            status: None,
        }
    }

    #[test]
    fn test_is_enabled() {
        let mut annotations = BTreeMap::new();
        assert!(!is_enabled(&annotations));

        annotations.insert(annotations::ENABLED.to_string(), "false".to_string());
        assert!(!is_enabled(&annotations));

        annotations.insert(annotations::ENABLED.to_string(), "true".to_string());
        assert!(is_enabled(&annotations));
    }

    #[test]
    fn test_extract_hosts() {
        let ingress = test_ingress(BTreeMap::new(), "test-uid");
        let hosts = extract_hosts(&ingress);
        assert_eq!(hosts, vec!["test.example.com"]);

        // Test with no spec
        let ingress_no_spec = Ingress {
            metadata: ObjectMeta::default(),
            spec: None,
            status: None,
        };
        let hosts = extract_hosts(&ingress_no_spec);
        assert!(hosts.is_empty());
    }

    #[test]
    fn test_build_tags() {
        let ingress = test_ingress(BTreeMap::new(), "abc-123");
        let custom_tags = vec!["custom".to_string()];
        let default_tags = vec!["default".to_string()];

        let tags = build_tags(&ingress, &custom_tags, &default_tags, false);

        assert!(tags.contains(&"k8s-operator".to_string()));
        assert!(tags.contains(&"source:abc-123".to_string()));
        assert!(tags.contains(&"namespace:default".to_string()));
        assert!(tags.contains(&"kind:Ingress".to_string()));
        assert!(tags.contains(&"custom".to_string()));
        assert!(tags.contains(&"default".to_string()));
        assert!(!tags.contains(&"pre-existing:true".to_string()));
    }

    #[test]
    fn test_build_tags_pre_existing() {
        let ingress = test_ingress(BTreeMap::new(), "abc-123");
        let tags = build_tags(&ingress, &[], &[], true);

        assert!(tags.contains(&"pre-existing:true".to_string()));
    }
}
