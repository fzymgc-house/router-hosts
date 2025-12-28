use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use k8s_openapi::api::core::v1::Secret;
use kube::api::ListParams;
use kube::{Api, Client};
use tokio::select;
use tokio::signal::unix::{signal, SignalKind};
use tokio::time::{interval, sleep};
use tracing::{debug, error, info, warn};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use router_hosts_operator::client::RouterHostsClient;
use router_hosts_operator::config::{tags, RouterHostsConfig};
use router_hosts_operator::controllers::retry::RetryTracker;
use router_hosts_operator::controllers::ControllerContext;
use router_hosts_operator::deletion::DeletionScheduler;
use router_hosts_operator::resolver::IpResolver;

const GC_INTERVAL_SECS: u64 = 60;
const SHUTDOWN_GRACE_SECS: u64 = 30;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing with JSON formatting for production
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
                .with_current_span(false),
        )
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("router-hosts-operator starting");

    // Create Kubernetes client
    let kube_client = Client::try_default()
        .await
        .context("Failed to create Kubernetes client")?;

    info!("Connected to Kubernetes cluster");

    // Load RouterHostsConfig (singleton cluster-scoped CRD)
    let config = load_config(&kube_client)
        .await
        .context("Failed to load RouterHostsConfig")?;

    info!(
        endpoint = %config.server.endpoint,
        strategies = config.ip_resolution.len(),
        grace_period = config.deletion.grace_period_seconds,
        "Loaded configuration"
    );

    // Load mTLS secrets
    let (ca_cert, client_cert, client_key) = load_mtls_secrets(&kube_client, &config)
        .await
        .context("Failed to load mTLS certificates")?;

    info!(
        secret_name = %config.server.tls_secret_ref.name,
        secret_namespace = %config.server.tls_secret_ref.namespace,
        "Loaded mTLS certificates"
    );

    // Create RouterHostsClient
    let router_client =
        RouterHostsClient::new(&config.server.endpoint, &ca_cert, &client_cert, &client_key)
            .await
            .context("Failed to create router-hosts client")?;

    info!(endpoint = %config.server.endpoint, "Connected to router-hosts server");

    // Create IpResolver with strategies from config
    let resolver = IpResolver::new(kube_client.clone(), config.ip_resolution.clone());

    // Create DeletionScheduler with grace period from config
    let deletion_scheduler = DeletionScheduler::new(Duration::from_secs(
        config.deletion.grace_period_seconds as u64,
    ));

    // Create ControllerContext shared across all controllers
    let ctx = Arc::new(ControllerContext {
        client: Arc::new(router_client),
        resolver: Arc::new(resolver),
        deletion: Arc::new(deletion_scheduler),
        config: Arc::new(config),
        kube_client: kube_client.clone(),
        retry_tracker: Arc::new(RetryTracker::new()),
    });

    info!("Starting controllers");

    // Setup signal handlers
    let mut sigterm = signal(SignalKind::terminate()).context("Failed to setup SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("Failed to setup SIGINT handler")?;

    // Start controllers and GC loop concurrently
    select! {
        result = run_controllers(kube_client.clone(), ctx.clone()) => {
            // Controller failure should trigger pod restart
            return result.context("Controller failure");
        }
        _ = run_garbage_collection(ctx.clone()) => {
            // GC loop should never exit
            bail!("Garbage collection loop exited unexpectedly");
        }
        _ = sigterm.recv() => {
            info!("Received SIGTERM, shutting down gracefully");
        }
        _ = sigint.recv() => {
            info!("Received SIGINT, shutting down gracefully");
        }
    }

    // Graceful shutdown
    info!(
        grace_seconds = SHUTDOWN_GRACE_SECS,
        "Starting graceful shutdown"
    );
    sleep(Duration::from_secs(SHUTDOWN_GRACE_SECS)).await;
    info!("Shutdown complete");

    Ok(())
}

/// Load singleton RouterHostsConfig from cluster
async fn load_config(
    client: &Client,
) -> Result<router_hosts_operator::config::RouterHostsConfigSpec> {
    let api: Api<RouterHostsConfig> = Api::all(client.clone());
    let configs = api.list(&ListParams::default()).await?;

    if configs.items.is_empty() {
        bail!("No RouterHostsConfig found in cluster - please create one");
    }

    if configs.items.len() > 1 {
        warn!(
            count = configs.items.len(),
            "Multiple RouterHostsConfig resources found, using first one"
        );
    }

    let config = &configs.items[0];
    Ok(config.spec.clone())
}

/// Load mTLS certificates from referenced Secret
async fn load_mtls_secrets(
    client: &Client,
    config: &router_hosts_operator::config::RouterHostsConfigSpec,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let secret_ref = &config.server.tls_secret_ref;
    let secrets: Api<Secret> = Api::namespaced(client.clone(), &secret_ref.namespace);

    let secret = secrets.get(&secret_ref.name).await.with_context(|| {
        format!(
            "Secret {}/{} not found",
            secret_ref.namespace, secret_ref.name
        )
    })?;

    let data = secret.data.as_ref().context("Secret has no data field")?;

    let ca_cert = data
        .get("ca.crt")
        .context("Secret missing ca.crt")?
        .0
        .clone();

    let client_cert = data
        .get("tls.crt")
        .context("Secret missing tls.crt")?
        .0
        .clone();

    let client_key = data
        .get("tls.key")
        .context("Secret missing tls.key")?
        .0
        .clone();

    Ok((ca_cert, client_cert, client_key))
}

/// Run all controllers concurrently
///
/// Returns an error if any controller exits unexpectedly, which should trigger
/// a pod restart by Kubernetes.
async fn run_controllers(client: Client, ctx: Arc<ControllerContext>) -> Result<()> {
    info!("Starting Ingress controller");
    let ingress = tokio::spawn(router_hosts_operator::controllers::ingress::run(
        client.clone(),
        ctx.clone(),
    ));

    info!("Starting IngressRoute controller");
    let ingressroute = tokio::spawn(router_hosts_operator::controllers::ingressroute::run(
        client.clone(),
        ctx.clone(),
    ));

    info!("Starting IngressRouteTCP controller");
    let ingressroutetcp = tokio::spawn(router_hosts_operator::controllers::ingressroutetcp::run(
        client.clone(),
        ctx.clone(),
    ));

    info!("Starting HostMapping controller");
    let hostmapping = tokio::spawn(router_hosts_operator::controllers::hostmapping::run(
        client.clone(),
        ctx.clone(),
    ));

    info!("All controllers spawned");

    // Wait for any controller to exit (they shouldn't under normal operation)
    select! {
        result = ingress => {
            handle_controller_exit("Ingress", result)
        }
        result = ingressroute => {
            handle_controller_exit("IngressRoute", result)
        }
        result = ingressroutetcp => {
            handle_controller_exit("IngressRouteTCP", result)
        }
        result = hostmapping => {
            handle_controller_exit("HostMapping", result)
        }
    }
}

/// Handle a controller task exit, returning an error to trigger pod restart
fn handle_controller_exit(
    name: &str,
    result: std::result::Result<(), tokio::task::JoinError>,
) -> Result<()> {
    match result {
        Ok(()) => {
            error!(controller = name, "Controller exited unexpectedly");
            bail!("{} controller exited unexpectedly", name)
        }
        Err(e) if e.is_panic() => {
            error!(controller = name, "Controller panicked");
            bail!("{} controller panicked: {:?}", name, e.into_panic())
        }
        Err(e) if e.is_cancelled() => {
            warn!(controller = name, "Controller was cancelled");
            bail!("{} controller was cancelled", name)
        }
        Err(e) => {
            error!(controller = name, error = ?e, "Controller task failed");
            bail!("{} controller task failed: {}", name, e)
        }
    }
}

/// Run garbage collection loop
async fn run_garbage_collection(ctx: Arc<ControllerContext>) {
    let mut gc_interval = interval(Duration::from_secs(GC_INTERVAL_SECS));
    gc_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    info!(
        interval_secs = GC_INTERVAL_SECS,
        "Starting garbage collection loop"
    );

    loop {
        gc_interval.tick().await;

        if let Err(e) = run_gc_cycle(&ctx).await {
            error!(error = %e, "Garbage collection cycle failed");
        }
    }
}

/// Run a single garbage collection cycle
async fn run_gc_cycle(ctx: &ControllerContext) -> Result<()> {
    // Process expired deletions first
    let process_result = ctx
        .deletion
        .process_expired(&ctx.client)
        .await
        .context("Failed to process expired deletions")?;

    if process_result.deleted > 0 || process_result.tags_removed > 0 || process_result.errors > 0 {
        info!(
            deleted = process_result.deleted,
            tags_removed = process_result.tags_removed,
            errors = process_result.errors,
            "Processed expired deletions"
        );
    }

    // Find all operator-managed entries
    let entries = ctx
        .client
        .find_by_tag(tags::OPERATOR)
        .await
        .context("Failed to query operator-managed entries")?;

    if entries.is_empty() {
        return Ok(());
    }

    info!(
        count = entries.len(),
        "Checking operator-managed entries for orphans"
    );

    // Build UID caches once per GC cycle - O(n) instead of O(n*m)
    let uid_cache = build_uid_cache(&ctx.kube_client).await?;

    let mut orphaned = 0;
    let mut verified = 0;

    for entry in entries {
        // Extract source UID from tags
        let source_uid = entry
            .tags
            .iter()
            .find(|t| t.starts_with(tags::SOURCE_PREFIX))
            .and_then(|t| t.strip_prefix(tags::SOURCE_PREFIX));

        let Some(source_uid) = source_uid else {
            warn!(
                entry_id = %entry.id,
                hostname = %entry.hostname,
                "Entry missing source: tag, skipping"
            );
            continue;
        };

        // Extract kind from tags
        let kind = entry
            .tags
            .iter()
            .find(|t| t.starts_with(tags::KIND_PREFIX))
            .and_then(|t| t.strip_prefix(tags::KIND_PREFIX));

        // Check if source resource still exists using cached UIDs
        let exists = uid_cache.contains(kind, source_uid);

        if !exists {
            // Check if already pending deletion (has pending-deletion: tag)
            let already_pending = entry
                .tags
                .iter()
                .any(|t| t.starts_with(tags::PENDING_DELETION));

            if !already_pending {
                // Check if pre-existing
                let pre_existing = entry.tags.contains(&tags::PRE_EXISTING.to_string());

                info!(
                    entry_id = %entry.id,
                    hostname = %entry.hostname,
                    source_uid = %source_uid,
                    pre_existing = pre_existing,
                    "Found orphaned entry, scheduling deletion"
                );

                ctx.deletion
                    .schedule(entry.id, entry.hostname, pre_existing, None)
                    .await;

                orphaned += 1;
            }
        } else {
            verified += 1;
        }
    }

    if orphaned > 0 || verified > 0 {
        info!(
            orphaned = orphaned,
            verified = verified,
            "Garbage collection cycle complete"
        );
    }

    Ok(())
}

/// Cache of resource UIDs for efficient orphan detection
///
/// Built once per GC cycle to avoid repeated API calls.
/// This reduces GC complexity from O(n*m) to O(n+m).
struct UidCache {
    ingresses: HashSet<String>,
    ingressroutes: HashSet<String>,
    ingressroutetcps: HashSet<String>,
    hostmappings: HashSet<String>,
}

impl UidCache {
    /// Check if a resource UID exists for the given kind
    fn contains(&self, kind: Option<&str>, uid: &str) -> bool {
        match kind {
            Some("Ingress") => self.ingresses.contains(uid),
            Some("IngressRoute") => self.ingressroutes.contains(uid),
            Some("IngressRouteTCP") => self.ingressroutetcps.contains(uid),
            Some("HostMapping") => self.hostmappings.contains(uid),
            Some(k) => {
                warn!(kind = k, "Unknown resource kind, assuming exists");
                true
            }
            None => false,
        }
    }
}

/// Build UID cache for all watched resource types
///
/// Lists each resource type once and extracts UIDs into HashSets
/// for O(1) lookup during orphan checking.
async fn build_uid_cache(client: &Client) -> Result<UidCache> {
    use k8s_openapi::api::networking::v1::Ingress;
    use router_hosts_operator::controllers::ingressroute::IngressRoute;
    use router_hosts_operator::controllers::ingressroutetcp::IngressRouteTCP;
    use router_hosts_operator::HostMapping;

    // Create API clients - must be bound to variables for lifetime reasons
    let ingress_api: Api<Ingress> = Api::all(client.clone());
    let ingressroute_api: Api<IngressRoute> = Api::all(client.clone());
    let ingressroutetcp_api: Api<IngressRouteTCP> = Api::all(client.clone());
    let hostmapping_api: Api<HostMapping> = Api::all(client.clone());

    let params = ListParams::default();

    // List all resources in parallel for efficiency
    let (ingresses, ingressroutes, ingressroutetcps, hostmappings) = tokio::try_join!(
        ingress_api.list(&params),
        ingressroute_api.list(&params),
        ingressroutetcp_api.list(&params),
        hostmapping_api.list(&params),
    )?;

    // Extract UIDs into HashSets for O(1) lookup
    let ingresses: HashSet<String> = ingresses
        .items
        .into_iter()
        .filter_map(|i| i.metadata.uid)
        .collect();

    let ingressroutes: HashSet<String> = ingressroutes
        .items
        .into_iter()
        .filter_map(|r| r.metadata.uid)
        .collect();

    let ingressroutetcps: HashSet<String> = ingressroutetcps
        .items
        .into_iter()
        .filter_map(|r| r.metadata.uid)
        .collect();

    let hostmappings: HashSet<String> = hostmappings
        .items
        .into_iter()
        .filter_map(|m| m.metadata.uid)
        .collect();

    debug!(
        ingresses = ingresses.len(),
        ingressroutes = ingressroutes.len(),
        ingressroutetcps = ingressroutetcps.len(),
        hostmappings = hostmappings.len(),
        "Built UID cache for GC"
    );

    Ok(UidCache {
        ingresses,
        ingressroutes,
        ingressroutetcps,
        hostmappings,
    })
}
