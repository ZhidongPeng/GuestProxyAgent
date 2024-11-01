// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#[cfg(windows)]
pub mod windows;

use crate::common::{config, constants, helpers, logger};
use crate::key_keeper::KeyKeeper;
use crate::proxy::proxy_server::{self, ProxyServer};
use crate::shared_state::SharedStateSenders;
use proxy_agent_shared::logger_manager;
use proxy_agent_shared::telemetry::event_logger;

#[cfg(not(windows))]
use std::time::Duration;

/// Start the service with the shared state.
/// Example:
/// ```rust
/// use proxy_agent::service;
/// use proxy_agent::shared_state::SharedState;
/// use std::sync::{Arc, Mutex};
///
/// let shared_state = SharedState::new();
/// service::start_service(shared_state);
/// ```
pub fn start_service(shared_state_senders: SharedStateSenders) {
    logger_manager::init_logger(
        logger::AGENT_LOGGER_KEY.to_string(),
        config::get_logs_dir(),
        "ProxyAgent.log".to_string(),
        constants::MAX_LOG_FILE_SIZE,
        constants::MAX_LOG_FILE_COUNT as u16,
    );
    logger::write_information(format!(
        "============== GuestProxyAgent ({}) is starting on {}, elapsed: {}",
        proxy_agent_shared::misc_helpers::get_current_version(),
        helpers::get_long_os_version(),
        helpers::get_elapsed_time_in_millisec()
    ));

    tokio::spawn({
        let key_keeper = KeyKeeper::new(
            (format!("http://{}/", constants::WIRE_SERVER_IP))
                .parse()
                .unwrap(),
            config::get_keys_dir(),
            config::get_logs_dir(),
            config::get_poll_key_status_duration(),
            config::get_start_redirector(),
            shared_state_senders.get_cancellation_token(),
            shared_state_senders.get_key_keeper_state(),
            shared_state_senders.get_telemetry_state(),
            shared_state_senders.get_shared_state(),
        );
        async move {
            key_keeper.poll_secure_channel_status().await;
        }
    });

    tokio::spawn({
        let proxy_server = ProxyServer::new(
            constants::PROXY_AGENT_PORT,
            shared_state_senders.get_cancellation_token(),
            shared_state_senders.get_key_keeper_state(),
            shared_state_senders.get_telemetry_state(),
            shared_state_senders.get_shared_state(),
        );
        async move {
            proxy_server.start().await;
        }
    });
}

/// Start the service and wait until the service is stopped.
/// Example:
/// ```rust
/// use proxy_agent::service;
/// service::start_service_wait();
/// ```
#[cfg(not(windows))]
pub async fn start_service_wait() {
    let shared_state_senders = SharedStateSenders::start_all();
    start_service(shared_state_senders);

    loop {
        // continue to sleep until the service is stopped
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Stop the service with the shared state.
/// Example:
/// ```rust
/// use proxy_agent::service;
/// use proxy_agent::shared_state::SharedState;
/// use std::sync::{Arc, Mutex};
///
/// let shared_state = SharedState::new();
/// service::stop_service(shared_state);
/// ```
pub fn stop_service(shared_state_senders: SharedStateSenders) {
    let shared_state = shared_state_senders.get_shared_state();
    logger::write_information(format!(
        "============== GuestProxyAgent is stopping, elapsed: {}",
        helpers::get_elapsed_time_in_millisec()
    ));
    shared_state_senders.cancel_cancellation_token();

    crate::redirector::close(shared_state.clone());
    proxy_server::stop(shared_state.clone());
    event_logger::stop();
}
