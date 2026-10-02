// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! Manages the proxy server and redirector as one runtime pair.

use crate::common::{constants, logger};
use crate::proxy::proxy_server::ProxyServer;
use crate::redirector::{self, Redirector};
use crate::shared_state::agent_status_wrapper::{AgentStatusModule, RuntimeStatusSnapshot};
use crate::shared_state::SharedState;
use proxy_agent_shared::proxy_agent_aggregate_status::ModuleState;
use std::thread::JoinHandle as ThreadJoinHandle;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const RECONCILE_INTERVAL: Duration = Duration::from_secs(1);

/// Policy for managing the runtime pair based on soft audit status changes.
#[derive(Clone, Copy, Debug, PartialEq)]
enum PairAction {
    /// No action is required for the pair.
    None,
    /// Start both modules in the pair.
    StartPair,
    /// Stop both modules in the pair.
    StopPair,
}

fn evaluate_status(status: &RuntimeStatusSnapshot) -> PairAction {
    if status.both_running() {
        // If both modules are running, we don't need to take any action.
        return PairAction::None;
    }

    if status.soft_audit_enabled {
        // If soft audit is enabled and either module is stopped, we should stop the pair.
        PairAction::StopPair
    } else {
        // If soft audit is not enabled, we should start the pair immediately.
        PairAction::StartPair
    }
}

struct ProxyServerRuntime {
    cancellation_token: CancellationToken,
    thread: ThreadJoinHandle<()>,
}

struct RedirectorRuntime {
    cancellation_token: CancellationToken,
    start_task: JoinHandle<()>,
}

pub struct RuntimeCoordinator {
    shared_state: SharedState,
    proxy_server_runtime: Option<ProxyServerRuntime>,
    redirector_runtime: Option<RedirectorRuntime>,
}

impl RuntimeCoordinator {
    pub fn start(shared_state: SharedState) -> JoinHandle<()> {
        tokio::spawn(async move {
            Self {
                shared_state,
                proxy_server_runtime: None,
                redirector_runtime: None,
            }
            .run()
            .await;
        })
    }

    async fn run(&mut self) {
        let service_cancellation_token = self.shared_state.get_cancellation_token();
        let mut runtime_status_rx = self
            .shared_state
            .get_agent_status_shared_state()
            .subscribe_runtime_status();

        if !service_cancellation_token.is_cancelled() {
            // Start both the proxy server and redirector initially.
            self.start_proxy_server().await;
            self.start_redirector().await;
        }

        loop {
            tokio::select! {
                _ = service_cancellation_token.cancelled() => break,
                result = runtime_status_rx.changed() => {
                    if result.is_err() {
                        logger::write_warning(
                            "Runtime status publisher stopped; stopping managed modules."
                                .to_string(),
                        );
                        break;
                    }
                }
                _ = tokio::time::sleep(RECONCILE_INTERVAL) => {}
            }

            if service_cancellation_token.is_cancelled() {
                break;
            }

            let status = runtime_status_rx.borrow_and_update().clone();

            // Only reconcile the runtime pair if both modules are at their ultimate state.
            // This ensures that we only take actions when both the proxy server and redirector have reached a stable state,
            // it prevents premature actions based on transient states.
            if status.both_at_ultimate_state() {
                match evaluate_status(&status) {
                    PairAction::None => {}
                    PairAction::StartPair => {
                        self.start_pair(&status).await;
                    }
                    PairAction::StopPair => {
                        self.stop_pair(&status).await;
                    }
                }
            }
        }

        // Stop the runtime pair before exiting the run.
        self.stop_redirector().await;
        self.stop_proxy_server().await;
    }

    /// Starts the runtime pair, including the proxy server and redirector, if they are not already running.
    async fn start_pair(&mut self, status: &RuntimeStatusSnapshot) {
        if status.proxy_server_state != ModuleState::RUNNING {
            self.start_proxy_server().await;
        }
        if status.redirector_state != ModuleState::RUNNING {
            self.start_redirector().await;
        }
    }

    /// Starts the proxy server if it is not already running.
    async fn start_proxy_server(&mut self) {
        let agent_status = self.shared_state.get_agent_status_shared_state();
        if let Err(e) = agent_status
            .set_module_state(ModuleState::STARTING, AgentStatusModule::ProxyServer)
            .await
        {
            logger::write_warning(format!(
                "Failed to mark ProxyServer as starting before runtime pair startup: {e}"
            ));
        }

        let proxy_cancellation_token = self.shared_state.get_cancellation_token().child_token();
        let proxy_server = ProxyServer::new_with_listener_cancellation_token(
            constants::PROXY_AGENT_PORT,
            &self.shared_state,
            proxy_cancellation_token.clone(),
        );
        let proxy_thread = match proxy_server.start_on_dedicated_runtime() {
            Ok(thread) => thread,
            Err(e) => {
                logger::write_error(format!(
                    "Failed to start the proxy server runtime thread: {e}"
                ));
                let _ = self
                    .shared_state
                    .get_agent_status_shared_state()
                    .set_module_state(ModuleState::STOPPED, AgentStatusModule::ProxyServer)
                    .await;
                return;
            }
        };
        self.proxy_server_runtime = Some(ProxyServerRuntime {
            cancellation_token: proxy_cancellation_token,
            thread: proxy_thread,
        });
    }

    /// Starts the redirector if it is not already running.
    async fn start_redirector(&mut self) {
        let agent_status = self.shared_state.get_agent_status_shared_state();
        if let Err(e) = agent_status
            .set_module_state(ModuleState::STARTING, AgentStatusModule::Redirector)
            .await
        {
            logger::write_warning(format!(
                "Failed to mark Redirector as starting before runtime pair startup: {e}"
            ));
        }

        let redirector_cancellation_token =
            self.shared_state.get_cancellation_token().child_token();
        let redirector = Redirector::new_with_cancellation_token(
            constants::PROXY_AGENT_PORT,
            &self.shared_state,
            redirector_cancellation_token.clone(),
        );
        let redirector_task = tokio::spawn(async move {
            redirector.start().await;
        });
        self.redirector_runtime = Some(RedirectorRuntime {
            cancellation_token: redirector_cancellation_token,
            start_task: redirector_task,
        });
    }

    /// Stops both the redirector and the proxy server if they are running.
    /// It ensures that both components are properly stopped before returning.
    async fn stop_pair(&mut self, status: &RuntimeStatusSnapshot) {
        if status.redirector_state == ModuleState::RUNNING {
            self.stop_redirector().await;
        }

        if status.proxy_server_state == ModuleState::RUNNING {
            self.stop_proxy_server().await;
        }
    }

    /// It ensures that the redirector is properly stopped before returning.
    /// It also sets the appropriate status message in the agent status shared state.
    async fn stop_redirector(&mut self) {
        if let Some(runtime) = self.redirector_runtime.take() {
            runtime.cancellation_token.cancel();
            if let Err(e) = runtime.start_task.await {
                logger::write_warning(format!("Redirector start task failed while stopping: {e}"));
            }
        }
        redirector::close(
            self.shared_state.get_redirector_shared_state(),
            self.shared_state.get_agent_status_shared_state(),
        )
        .await;

        if let Err(e) = self
            .shared_state
            .get_agent_status_shared_state()
            .set_module_status_message(
                "RuntimeCoordinator stopped Redirector".to_string(),
                AgentStatusModule::Redirector,
            )
            .await
        {
            logger::write_warning(format!(
                "Failed to set Redirector module status message: {e}"
            ));
        }
    }

    /// It ensures that the proxy server is properly stopped before returning.
    /// It also sets the appropriate status message in the agent status shared state.
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

            if let Err(e) = self
                .shared_state
                .get_agent_status_shared_state()
                .set_module_status_message(
                    "RuntimeCoordinator stopped ProxyServer".to_string(),
                    AgentStatusModule::ProxyServer,
                )
                .await
            {
                logger::write_warning(format!(
                    "Failed to set ProxyServer module status message: {e}"
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{evaluate_status, PairAction};
    use crate::shared_state::agent_status_wrapper::RuntimeStatusSnapshot;
    use proxy_agent_shared::proxy_agent_aggregate_status::ModuleState;

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

    #[test]
    fn running_pair_requires_no_action() {
        assert_eq!(
            PairAction::None,
            evaluate_status(&status(false, ModuleState::RUNNING, ModuleState::RUNNING,))
        );
        assert_eq!(
            PairAction::None,
            evaluate_status(&status(true, ModuleState::RUNNING, ModuleState::RUNNING,))
        );
    }

    #[test]
    fn soft_audit_stops_a_non_running_pair() {
        assert_eq!(
            PairAction::StopPair,
            evaluate_status(&status(true, ModuleState::RUNNING, ModuleState::STOPPED,))
        );
        assert_eq!(
            PairAction::StopPair,
            evaluate_status(&status(true, ModuleState::STOPPED, ModuleState::STOPPED,))
        );
    }

    #[test]
    fn normal_mode_starts_a_non_running_pair() {
        assert_eq!(
            PairAction::StartPair,
            evaluate_status(&status(false, ModuleState::STOPPED, ModuleState::RUNNING,))
        );
        assert_eq!(
            PairAction::StartPair,
            evaluate_status(&status(false, ModuleState::RUNNING, ModuleState::STARTING,))
        );
    }

    #[test]
    fn ultimate_state_requires_both_modules_to_be_running_or_stopped() {
        assert!(
            !status(false, ModuleState::STARTING, ModuleState::RUNNING).both_at_ultimate_state()
        );
        assert!(!status(false, ModuleState::RUNNING, ModuleState::UNKNOWN).both_at_ultimate_state());
        assert!(status(false, ModuleState::RUNNING, ModuleState::STOPPED).both_at_ultimate_state());
        assert!(status(false, ModuleState::STOPPED, ModuleState::STOPPED).both_at_ultimate_state());
    }
}
