//! Service controller
//!
//! Watches v1/Service resources and creates/updates/deletes
//! corresponding router-hosts entries for LoadBalancer and NodePort types.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use k8s_openapi::api::core::v1::Service;
use kube::runtime::controller::Action;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::runtime::Controller;
use kube::{Api, Client};
use thiserror::Error;
use tracing::{debug, error, info, instrument, warn};

use crate::client::{ClientError, RouterHostsClientTrait};
use crate::config::{annotations, tags};

use super::retry::{compute_backoff, ErrorKind};
use super::ControllerContext;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("router-hosts client error: {0}")]
    Client(#[from] ClientError),
    #[error("Missing required annotation: {0}")]
    MissingAnnotation(String),
    #[error("Invalid service type: {0}")]
    InvalidServiceType(String),
    #[error("Pending LoadBalancer IP")]
    PendingLoadBalancerIp,
}
