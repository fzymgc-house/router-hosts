//! Traefik IngressRoute controller
//!
//! Watches traefik.io/v1alpha1 IngressRoute resources and syncs hostnames to router-hosts.
//!
//! ## Deletion Handling
//!
//! This controller does not use finalizers. Deletion is handled by a separate garbage
//! collection process in the main loop that:
//! 1. Finds all entries tagged with `k8s-operator`
//! 2. Checks if the source resource (via `source:` tag) still exists
//! 3. Schedules deletion with grace period via `DeletionScheduler`
//!
//! When an IngressRoute reappears (or another resource claims the same hostname),
//! the pending deletion is cancelled in the `reconcile` function.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::runtime::Controller;
use kube::{Client, CustomResource};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, instrument, warn};

use crate::client::{ClientError, RouterHostsClientTrait};
use crate::config::{annotations, tags};
use crate::matcher;
use crate::resolver::ResolverError;

use super::retry::{compute_backoff, ErrorKind};
use super::ControllerContext;

/// IngressRoute route definition
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct IngressRouteRoute {
    /// Match expression (e.g., "Host(`example.com`) && PathPrefix(`/api`)")
    #[serde(rename = "match")]
    pub match_expr: String,
    /// Route kind (Rule, etc.)
    #[serde(default)]
    pub kind: String,
}

/// IngressRoute spec
#[derive(CustomResource, Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "traefik.io",
    version = "v1alpha1",
    kind = "IngressRoute",
    plural = "ingressroutes",
    namespaced
)]
pub struct IngressRouteSpec {
    /// Entry points (e.g., ["web", "websecure"])
    #[serde(default)]
    pub entry_points: Vec<String>,
    /// Routes with match expressions
    pub routes: Vec<IngressRouteRoute>,
}

#[derive(Debug, Error)]
pub enum IngressRouteError {
    #[error("IP resolution failed: {0}")]
    IpResolution(#[from] ResolverError),
    #[error("router-hosts client error: {0}")]
    Client(#[from] ClientError),
    #[error("Missing required field: {0}")]
    MissingField(String),
}

/// Check if IngressRoute has opt-in annotation
fn is_enabled(annotations: &BTreeMap<String, String>) -> bool {
    annotations
        .get(annotations::ENABLED)
        .map(|v| v == "true")
        .unwrap_or(false)
}

/// Extract hosts from IngressRoute spec using match expressions
fn extract_hosts(ingressroute: &IngressRoute) -> Vec<String> {
    let mut hosts = Vec::new();

    for route in &ingressroute.spec.routes {
        hosts.extend(matcher::extract_hosts(&route.match_expr));
    }

    // Deduplicate
    hosts.sort();
    hosts.dedup();
    hosts
}

/// Build ownership tags (matches Ingress controller pattern)
fn build_tags(
    ingressroute: &IngressRoute,
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
    if let Some(uid) = ingressroute.metadata.uid.as_ref() {
        result.push(format!("{}{}", tags::SOURCE_PREFIX, uid));
    }
    if let Some(ns) = ingressroute.metadata.namespace.as_ref() {
        result.push(format!("{}{}", tags::NAMESPACE_PREFIX, ns));
    }
    result.push(format!("{}IngressRoute", tags::KIND_PREFIX));

    // Add custom tags from annotation
    result.extend_from_slice(custom_tags);

    // Add default tags from config
    result.extend_from_slice(default_tags);

    result
}

/// Parse custom tags from annotation
fn parse_custom_tags(annotations: &BTreeMap<String, String>) -> Vec<String> {
    annotations
        .get(annotations::TAGS)
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Parse aliases from annotation
fn parse_aliases(annotations: &BTreeMap<String, String>) -> Vec<String> {
    annotations
        .get(annotations::ALIASES)
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

#[instrument(
    skip(ctx, ingressroute),
    fields(
        name = %ingressroute.metadata.name.as_deref().unwrap_or("unknown"),
        namespace = %ingressroute.metadata.namespace.as_deref().unwrap_or("default")
    )
)]
async fn reconcile(
    ingressroute: Arc<IngressRoute>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, IngressRouteError> {
    let name = ingressroute.metadata.name.as_deref().unwrap_or("unknown");
    let annotations = ingressroute
        .metadata
        .annotations
        .clone()
        .unwrap_or_default();

    if !is_enabled(&annotations) {
        debug!(name = %name, "IngressRoute not enabled, skipping");
        return Ok(Action::await_change());
    }

    let hosts = extract_hosts(&ingressroute);
    if hosts.is_empty() {
        debug!(name = %name, "No hosts in IngressRoute, skipping");
        return Ok(Action::await_change());
    }

    info!(name = %name, hosts = ?hosts, "Reconciling IngressRoute");

    let ip = ctx.resolver.resolve(&annotations).await?;
    let aliases = parse_aliases(&annotations);
    let custom_tags = parse_custom_tags(&annotations);

    for hostname in &hosts {
        let existing = ctx.client.find_by_hostname(hostname).await?;

        match existing {
            Some(entry) => {
                // Cancel any pending deletion - regardless of ownership
                // If any resource claims this hostname, don't delete the entry
                if ctx.deletion.is_pending(&entry.id).await {
                    ctx.deletion.cancel(&entry.id).await;
                    info!(
                        entry_id = %entry.id,
                        hostname = %hostname,
                        "Cancelled pending deletion"
                    );
                }

                let source_tag = ingressroute
                    .metadata
                    .uid
                    .as_ref()
                    .map(|uid| format!("{}{}", tags::SOURCE_PREFIX, uid));

                let is_ours = source_tag
                    .as_ref()
                    .map(|t| entry.tags.contains(t))
                    .unwrap_or(false);
                let has_operator_tag = entry.tags.contains(&tags::OPERATOR.to_string());

                if is_ours {
                    if entry.ip_address != ip || entry.aliases != aliases {
                        let new_tags = build_tags(
                            &ingressroute,
                            &custom_tags,
                            &ctx.config.default_tags,
                            false,
                        );
                        ctx.client
                            .update_host(
                                &entry.id,
                                Some(ip.clone()),
                                Some(aliases.clone()),
                                Some(new_tags),
                                Some(entry.version.clone()),
                            )
                            .await?;
                        info!(hostname = %hostname, "Updated host entry");
                    }
                } else if has_operator_tag {
                    debug!(hostname = %hostname, "Entry owned by different resource, skipping");
                } else {
                    // Adopt pre-existing entry
                    let new_tags =
                        build_tags(&ingressroute, &custom_tags, &ctx.config.default_tags, true);
                    ctx.client
                        .update_host(
                            &entry.id,
                            Some(ip.clone()),
                            Some(aliases.clone()),
                            Some(new_tags),
                            Some(entry.version.clone()),
                        )
                        .await?;
                    info!(hostname = %hostname, "Adopted pre-existing entry");
                }
            }
            None => {
                // Create new entry
                let new_tags =
                    build_tags(&ingressroute, &custom_tags, &ctx.config.default_tags, false);
                ctx.client
                    .add_host(hostname, &ip, aliases.clone(), new_tags)
                    .await?;
                info!(hostname = %hostname, ip = %ip, "Created host entry");
            }
        }
    }

    // Reset retry counter on success
    if let Some(uid) = ingressroute.metadata.uid.as_deref() {
        ctx.retry_tracker.reset(uid).await;
    }

    Ok(Action::requeue(Duration::from_secs(300)))
}

/// Classify error type for retry behavior
fn classify_error(error: &IngressRouteError) -> ErrorKind {
    match error {
        IngressRouteError::IpResolution(_) => ErrorKind::Transient,
        IngressRouteError::Client(_) => ErrorKind::Transient,
        IngressRouteError::MissingField(_) => ErrorKind::Permanent,
    }
}

fn error_policy(
    ingressroute: Arc<IngressRoute>,
    error: &IngressRouteError,
    ctx: Arc<ControllerContext>,
) -> Action {
    let uid = ingressroute.metadata.uid.as_deref().unwrap_or("unknown");
    let kind = classify_error(error);

    let attempt = futures::executor::block_on(ctx.retry_tracker.increment(uid));

    warn!(
        name = %ingressroute.metadata.name.as_deref().unwrap_or("unknown"),
        error = %error,
        attempt = attempt,
        error_kind = ?kind,
        "IngressRoute reconciliation failed"
    );

    compute_backoff(attempt, kind)
}

/// Start the IngressRoute controller
pub async fn run(client: Client, ctx: Arc<ControllerContext>) {
    let ingressroutes: Api<IngressRoute> = Api::all(client);

    Controller::new(ingressroutes, WatcherConfig::default())
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|result| async move {
            match result {
                Ok((obj, _action)) => {
                    debug!(
                        name = %obj.name,
                        "IngressRoute reconciled successfully"
                    );
                }
                Err(e) => {
                    warn!(error = %e, "IngressRoute controller error");
                }
            }
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ingressroute(name: &str, matches: Vec<&str>, enabled: bool) -> IngressRoute {
        let mut ir = IngressRoute::new(
            name,
            IngressRouteSpec {
                entry_points: vec!["web".to_string()],
                routes: matches
                    .into_iter()
                    .map(|m| IngressRouteRoute {
                        match_expr: m.to_string(),
                        kind: "Rule".to_string(),
                    })
                    .collect(),
            },
        );
        ir.metadata.namespace = Some("default".to_string());
        ir.metadata.uid = Some("test-uid-123".to_string());

        if enabled {
            ir.metadata
                .annotations
                .get_or_insert_with(BTreeMap::new)
                .insert(annotations::ENABLED.to_string(), "true".to_string());
        }

        ir
    }

    #[test]
    fn test_is_enabled() {
        let enabled = make_ingressroute("test", vec!["Host(`app.com`)"], true);
        assert!(is_enabled(
            enabled
                .metadata
                .annotations
                .as_ref()
                .expect("test fixture should have annotations")
        ));

        let disabled = make_ingressroute("test", vec!["Host(`app.com`)"], false);
        assert!(!is_enabled(
            &disabled.metadata.annotations.unwrap_or_default()
        ));
    }

    #[test]
    fn test_extract_hosts() {
        let ir = make_ingressroute(
            "test",
            vec!["Host(`a.com`) || Host(`b.com`)", "Host(`c.com`)"],
            true,
        );
        let hosts = extract_hosts(&ir);
        assert_eq!(hosts, vec!["a.com", "b.com", "c.com"]);
    }

    #[test]
    fn test_build_tags() {
        let ir = make_ingressroute("test", vec!["Host(`app.com`)"], true);
        let custom = vec!["custom:tag".to_string()];
        let default = vec!["cluster:test".to_string()];
        let tags = build_tags(&ir, &custom, &default, false);

        assert!(tags.contains(&"k8s-operator".to_string()));
        assert!(tags.contains(&"custom:tag".to_string()));
        assert!(tags.contains(&"cluster:test".to_string()));
        assert!(tags.contains(&"kind:IngressRoute".to_string()));
        assert!(tags.iter().any(|t| t.starts_with("source:")));
        assert!(!tags.contains(&"pre-existing:true".to_string()));
    }

    #[test]
    fn test_build_tags_pre_existing() {
        let ir = make_ingressroute("test", vec!["Host(`app.com`)"], true);
        let tags = build_tags(&ir, &[], &[], true);

        assert!(tags.contains(&"pre-existing:true".to_string()));
    }
}
