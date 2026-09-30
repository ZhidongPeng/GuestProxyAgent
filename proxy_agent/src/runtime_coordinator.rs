// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! Coordinates the proxy server and redirector lifecycles based on SoftAudit mode.
//!
//! In normal mode, the coordinator starts the proxy server before the redirector.
//! In SoftAudit mode, a degraded pair is stopped in the reverse order so traffic is
//! no longer redirected before the proxy listener is shut down.

use crate::common::{constants, logger};
use crate::proxy::proxy_server::ProxyServer;
use crate::redirector::{self, Redirector};
use crate::shared_state::agent_status_wrapper::{AgentStatusModule, RuntimeStatusSnapshot};
use crate::shared_state::SharedState;
use proxy_agent_shared::proxy_agent_aggregate_status::ModuleState;
use std::thread::JoinHandle as ThreadJoinHandle;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

const RECONCILE_INTERVAL: Duration = Duration::from_secs(5);

/// A lifecycle operation selected during reconciliation.
///
/// The enum order is not significant; [`reconcile_plan`] determines execution order.
#[derive(Clone, Copy, Debug, PartialEq)]
enum ReconcileAction {
    StopRedirector,
    StopProxyServer,
    StartProxyServer,
    StartRedirector,
}

/// Produces the ordered lifecycle operations needed for the current runtime status.
///
/// Owned components include components that are starting, running, or waiting to be
/// stopped. Ownership prevents duplicate starts while status updates are in flight.
fn reconcile_plan(
    status: &RuntimeStatusSnapshot,
    proxy_server_owned: bool,
    redirector_owned: bool,
) -> Vec<ReconcileAction> {
    if status.soft_audit_enabled
        && (status.proxy_server_state != ModuleState::RUNNING
            || status.redirector_state != ModuleState::RUNNING)
    {
        let mut actions = Vec::new();
        if redirector_owned || status.redirector_state == ModuleState::RUNNING {
            actions.push(ReconcileAction::StopRedirector);
        }
        if proxy_server_owned || status.proxy_server_state == ModuleState::RUNNING {
            actions.push(ReconcileAction::StopProxyServer);
        }
        return actions;
    }

    if status.soft_audit_enabled {
        return Vec::new();
    }

    if status.proxy_server_state != ModuleState::RUNNING {
        return if proxy_server_owned {
            Vec::new()
        } else {
            vec![ReconcileAction::StartProxyServer]
        };
    }

    if status.redirector_state != ModuleState::RUNNING && !redirector_owned {
        return vec![ReconcileAction::StartRedirector];
    }

    Vec::new()
}

/// Owns the cancellation token and dedicated thread for one proxy-server generation.
struct ProxyServerRuntime {
    /// Stops only this proxy-server generation, not the GPA service.
    cancellation_token: CancellationToken,
    /// Runs the proxy server's isolated Tokio runtime.
    thread: ThreadJoinHandle<()>,
}

/// Owns the cancellation token and startup task for one redirector generation.
struct RedirectorRuntime {
    /// Stops alert processing and marks this redirector generation as cancelled.
    cancellation_token: CancellationToken,
    /// Tracks startup until the eBPF object is installed or startup fails.
    start_task: Option<JoinHandle<()>>,
}

/// Serializes proxy-server and redirector lifecycle changes.
///
/// Component state and SoftAudit mode remain authoritative in
/// `AgentStatusSharedState`; this type owns only runtime handles and retry timing.
pub struct RuntimeCoordinator {
    /// Shared GPA services used to construct and observe managed components.
    shared_state: SharedState,
    /// Currently owned proxy-server generation, if any.
    proxy_server_runtime: Option<ProxyServerRuntime>,
    /// Currently owned redirector generation, if any.
    redirector_runtime: Option<RedirectorRuntime>,
    /// Earliest time at which a failed proxy server may be restarted.
    proxy_server_retry_after: Option<Instant>,
    /// Earliest time at which a failed redirector may be restarted.
    redirector_retry_after: Option<Instant>,
}

impl RuntimeCoordinator {
    /// Starts the coordinator task and returns its Tokio task handle.
    ///
    /// The task runs until the global service cancellation token is cancelled or the
    /// runtime-status publisher closes.
    pub fn start(shared_state: SharedState) -> JoinHandle<()> {
        tokio::spawn(async move {
            Self {
                shared_state,
                proxy_server_runtime: None,
                redirector_runtime: None,
                proxy_server_retry_after: None,
                redirector_retry_after: None,
            }
            .run()
            .await;
        })
    }

    /// Watches runtime status, reconciles desired state, and performs ordered shutdown.
    async fn run(&mut self) {
        let service_cancellation_token = self.shared_state.get_cancellation_token();
        let mut runtime_status_rx = self
            .shared_state
            .get_agent_status_shared_state()
            .subscribe_runtime_status();

        loop {
            let mut status = runtime_status_rx.borrow_and_update().clone();
            self.cleanup_finished_components(&mut status).await;
            self.reconcile(&status).await;

            tokio::select! {
                _ = service_cancellation_token.cancelled() => break,
                result = runtime_status_rx.changed() => {
                    if result.is_err() {
                        logger::write_warning(
                            "Runtime status publisher stopped; shutting down runtime coordinator."
                                .to_string(),
                        );
                        break;
                    }
                }
                _ = tokio::time::sleep(RECONCILE_INTERVAL) => {}
            }
        }

        self.stop_redirector().await;
        self.stop_proxy_server().await;
    }

    /// Reaps completed startup/runtime handles and publishes stopped component states.
    ///
    /// Retry deadlines are set here so failed components cannot enter a tight restart
    /// loop when their status notification immediately wakes the coordinator.
    async fn cleanup_finished_components(&mut self, status: &mut RuntimeStatusSnapshot) {
        let proxy_server_finished = self
            .proxy_server_runtime
            .as_ref()
            .is_some_and(|runtime| runtime.thread.is_finished());
        if proxy_server_finished {
            if let Some(runtime) = self.proxy_server_runtime.take() {
                match tokio::task::spawn_blocking(move || runtime.thread.join()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => {
                        logger::write_warning("Proxy server runtime thread panicked.".to_string());
                    }
                    Err(e) => {
                        logger::write_warning(format!(
                            "Failed to join the proxy server runtime thread: {e}"
                        ));
                    }
                }
            }
            status.proxy_server_state = ModuleState::STOPPED;
            self.proxy_server_retry_after = Some(Instant::now() + RECONCILE_INTERVAL);
            let _ = self
                .shared_state
                .get_agent_status_shared_state()
                .set_module_state(ModuleState::STOPPED, AgentStatusModule::ProxyServer)
                .await;
        }

        let redirector_start_finished = self
            .redirector_runtime
            .as_ref()
            .and_then(|runtime| runtime.start_task.as_ref())
            .is_some_and(JoinHandle::is_finished);
        if redirector_start_finished {
            let mut start_failed = false;
            if let Some(runtime) = self.redirector_runtime.as_mut() {
                if let Some(start_task) = runtime.start_task.take() {
                    if let Err(e) = start_task.await {
                        logger::write_warning(format!(
                            "Redirector start task failed to complete: {e}"
                        ));
                        start_failed = true;
                    }
                }
            }
            if start_failed || status.redirector_state == ModuleState::STOPPED {
                self.redirector_runtime = None;
                self.redirector_retry_after = Some(Instant::now() + RECONCILE_INTERVAL);
                status.redirector_state = ModuleState::STOPPED;
                let _ = self
                    .shared_state
                    .get_agent_status_shared_state()
                    .set_module_state(ModuleState::STOPPED, AgentStatusModule::Redirector)
                    .await;
            }
        }
        if status.redirector_state == ModuleState::STOPPED
            && self
                .redirector_runtime
                .as_ref()
                .is_some_and(|runtime| runtime.start_task.is_none())
        {
            if let Some(runtime) = self.redirector_runtime.take() {
                runtime.cancellation_token.cancel();
            }
            self.redirector_retry_after = Some(Instant::now() + RECONCILE_INTERVAL);
        }
    }

    /// Applies the lifecycle plan for a runtime-status snapshot.
    ///
    /// Successful `RUNNING` states clear prior retry deadlines.
    async fn reconcile(&mut self, status: &RuntimeStatusSnapshot) {
        if status.proxy_server_state == ModuleState::RUNNING {
            self.proxy_server_retry_after = None;
        }
        if status.redirector_state == ModuleState::RUNNING {
            self.redirector_retry_after = None;
        }

        let actions = reconcile_plan(
            status,
            self.proxy_server_runtime.is_some(),
            self.redirector_runtime.is_some(),
        );

        for action in actions {
            match action {
                ReconcileAction::StopRedirector => self.stop_redirector().await,
                ReconcileAction::StopProxyServer => self.stop_proxy_server().await,
                ReconcileAction::StartProxyServer => self.start_proxy_server().await,
                ReconcileAction::StartRedirector => self.start_redirector(),
            }
        }
    }

    /// Starts a proxy-server generation unless its retry deadline is still active.
    async fn start_proxy_server(&mut self) {
        if self
            .proxy_server_retry_after
            .is_some_and(|retry_after| Instant::now() < retry_after)
        {
            return;
        }
        let cancellation_token = self.shared_state.get_cancellation_token().child_token();
        let proxy_server = ProxyServer::new_with_listener_cancellation_token(
            constants::PROXY_AGENT_PORT,
            &self.shared_state,
            cancellation_token.clone(),
        );
        match proxy_server.start_on_dedicated_runtime() {
            Ok(thread) => {
                self.proxy_server_runtime = Some(ProxyServerRuntime {
                    cancellation_token,
                    thread,
                });
            }
            Err(e) => {
                logger::write_error(format!(
                    "Failed to start the proxy server runtime thread: {e}"
                ));
                self.proxy_server_retry_after = Some(Instant::now() + RECONCILE_INTERVAL);
                let _ = self
                    .shared_state
                    .get_agent_status_shared_state()
                    .set_module_state(ModuleState::STOPPED, AgentStatusModule::ProxyServer)
                    .await;
            }
        }
    }

    /// Starts a redirector generation unless its retry deadline is still active.
    fn start_redirector(&mut self) {
        if self
            .redirector_retry_after
            .is_some_and(|retry_after| Instant::now() < retry_after)
        {
            return;
        }
        let cancellation_token = self.shared_state.get_cancellation_token().child_token();
        let redirector = Redirector::new_with_cancellation_token(
            constants::PROXY_AGENT_PORT,
            &self.shared_state,
            cancellation_token.clone(),
        );
        let start_task = tokio::spawn(async move {
            redirector.start().await;
        });
        self.redirector_runtime = Some(RedirectorRuntime {
            cancellation_token,
            start_task: Some(start_task),
        });
    }

    /// Cancels redirector startup and alert processing, then closes the eBPF object.
    async fn stop_redirector(&mut self) {
        if let Some(mut runtime) = self.redirector_runtime.take() {
            runtime.cancellation_token.cancel();
            if let Some(start_task) = runtime.start_task.take() {
                if let Err(e) = start_task.await {
                    logger::write_warning(format!(
                        "Redirector start task failed while stopping: {e}"
                    ));
                }
            }
        }
        redirector::close(
            self.shared_state.get_redirector_shared_state(),
            self.shared_state.get_agent_status_shared_state(),
        )
        .await;
    }

    /// Cancels the proxy listener and waits for its dedicated runtime thread to exit.
    async fn stop_proxy_server(&mut self) {
        if let Some(runtime) = self.proxy_server_runtime.take() {
            runtime.cancellation_token.cancel();
            match tokio::task::spawn_blocking(move || runtime.thread.join()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    logger::write_warning("Proxy server runtime thread panicked.".to_string());
                }
                Err(e) => {
                    logger::write_warning(format!(
                        "Failed to join the proxy server runtime thread: {e}"
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{reconcile_plan, ReconcileAction};
    use crate::shared_state::agent_status_wrapper::RuntimeStatusSnapshot;
    use proxy_agent_shared::proxy_agent_aggregate_status::ModuleState;

    /// Creates a runtime-status snapshot for reconciliation tests.
    fn status(
        soft_audit_enabled: bool,
        proxy_server_state: ModuleState,
        redirector_state: ModuleState,
    ) -> RuntimeStatusSnapshot {
        RuntimeStatusSnapshot {
            soft_audit_enabled,
            proxy_server_state,
            redirector_state,
        }
    }

    /// Verifies that a healthy pair remains active in SoftAudit mode.
    #[test]
    fn soft_audit_keeps_running_pair() {
        assert!(reconcile_plan(
            &status(true, ModuleState::RUNNING, ModuleState::RUNNING),
            true,
            true,
        )
        .is_empty());
    }

    /// Verifies fail-closed shutdown ordering when either SoftAudit component is degraded.
    #[test]
    fn soft_audit_stops_redirector_before_proxy_when_pair_is_degraded() {
        assert_eq!(
            vec![
                ReconcileAction::StopRedirector,
                ReconcileAction::StopProxyServer,
            ],
            reconcile_plan(
                &status(true, ModuleState::STOPPED, ModuleState::RUNNING),
                true,
                true,
            )
        );
    }

    /// Verifies dependency ordering when normal mode starts a stopped pair.
    #[test]
    fn normal_mode_starts_proxy_before_redirector() {
        assert_eq!(
            vec![ReconcileAction::StartProxyServer],
            reconcile_plan(
                &status(false, ModuleState::STOPPED, ModuleState::STOPPED),
                false,
                false,
            )
        );
        assert_eq!(
            vec![ReconcileAction::StartRedirector],
            reconcile_plan(
                &status(false, ModuleState::RUNNING, ModuleState::STOPPED),
                true,
                false,
            )
        );
    }

    /// Verifies that owned startup operations are not launched more than once.
    #[test]
    fn normal_mode_does_not_duplicate_in_progress_starts() {
        assert!(reconcile_plan(
            &status(false, ModuleState::UNKNOWN, ModuleState::UNKNOWN),
            true,
            false,
        )
        .is_empty());
        assert!(reconcile_plan(
            &status(false, ModuleState::RUNNING, ModuleState::UNKNOWN),
            true,
            true,
        )
        .is_empty());
    }
}
