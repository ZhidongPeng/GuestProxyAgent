// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module provides the provision functions for the GPA service and GPA --status command line.
//! It is used to track the provision state for each module and write the provision state to provisioned.tag and status.tag files.
//! It also provides the http handler to query the provision status for GPA service.
//! It is used to query the provision status from GPA service http listener.
//! Example for GPA service:
//! ```rust
//! use proxy_agent::provision;
//! use std::sync::{Arc, Mutex};
//! use std::time::Duration;
//!
//! let shared_state = Arc::new(Mutex::new(SharedState::new()));
//! let provision_state = provision::get_provision_state(shared_state.clone());
//! assert_eq!(false, provision_state.finished);
//! assert_eq!(0, provision_state.errorMessage.len());
//!
//! // update provision state when each provision finished
//! provision::redirector_ready(shared_state.clone());
//! provision::key_latched(shared_state.clone());
//! provision::listener_started(shared_state.clone());
//!
//! let provision_state = provision::get_provision_state(shared_state.clone());
//! assert_eq!(true, provision_state.finished);
//! assert_eq!(0, provision_state.errorMessage.len());
//! ```
//!
//! Example for GPA command line option --status [--wait seconds]:
//! ```rust
//! use proxy_agent::provision;
//! use std::time::Duration;
//!
//! let provision_not_finished_state = provision::get_provision_status_wait(8092, None).await;
//! assert_eq!(false, provision_state.0);
//! assert_eq!(0, provision_state.1.len());
//!
//! let provision_finished_state = provision::get_provision_status_wait(8092, Some(Duration::from_millis(5))).await;
//! assert_eq!(true, provision_state.0);
//! assert_eq!(0, provision_state.1.len());
//! ```

use crate::common::{
    config, constants, error::Error, helpers, hyper_client, logger, result::Result,
};
use crate::proxy::proxy_server;
use crate::shared_state::key_keeper_wrapper::KeyKeeperState;
use crate::shared_state::telemetry_wrapper::TelemetryState;
use crate::shared_state::{provision_wrapper, SharedState};
use crate::telemetry::event_reader::EventReader;
use crate::{proxy_agent_status, redirector};
use proxy_agent_shared::misc_helpers;
use proxy_agent_shared::telemetry::event_logger;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const STATUS_TAG_TMP_FILE_NAME: &str = "status.tag.tmp";
const STATUS_TAG_FILE_NAME: &str = "status.tag";

bitflags::bitflags! {
    /// Provision flags
    /// NONE - no provision finished
    /// REDIRECTOR_READY - redirector provision finished
    /// KEY_LATCH_READY - key latch provision finished
    /// LISTENER_READY - listener provision finished
    /// ALL_READY - all provision finished
    /// It is used to track each module provision state
    /// Example:
    /// ```rust
    /// use proxy_agent::provision::ProvisionFlags;
    ///
    /// let flags = ProvisionFlags::REDIRECTOR_READY | ProvisionFlags::KEY_LATCH_READY;
    /// assert_eq!(3, flags.bits());
    /// assert_eq!(true, flags.contains(ProvisionFlags::REDIRECTOR_READY));
    /// assert_eq!(true, flags.contains(ProvisionFlags::KEY_LATCH_READY));
    /// assert_eq!(false, flags.contains(ProvisionFlags::LISTENER_READY));
    ///
    /// let flags = ProvisionFlags::REDIRECTOR_READY | ProvisionFlags::KEY_LATCH_READY | ProvisionFlags::LISTENER_READY;
    /// assert_eq!(7, flags.bits());
    /// assert_eq!(true, flags.contains(ProvisionFlags::REDIRECTOR_READY));
    /// assert_eq!(true, flags.contains(ProvisionFlags::KEY_LATCH_READY));
    /// assert_eq!(true, flags.contains(ProvisionFlags::LISTENER_READY));
    /// ```
    #[derive(Clone)]
    pub struct ProvisionFlags: u8 {
        const NONE = 0;
        const REDIRECTOR_READY = 1;
        const KEY_LATCH_READY = 2;
        const LISTENER_READY = 4;
        const ALL_READY = 7;
    }
}

/// Provision status
/// finished - provision finished or timedout
///            true means provision finished or timedout, false means provision still in progress
/// errorMessage - provision error message
#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct ProvisionState {
    finished: bool,
    errorMessage: String,
}

/// Provision URL path, it is used to query the provision status from GPA service http listener
pub const PROVISION_URL_PATH: &str = "/provision";

/// Update provision state when redirector provision finished
/// It could  be called by redirector module
pub async fn redirector_ready(
    cancellation_token: CancellationToken,
    key_keeper_state: KeyKeeperState,
    telemetry_state: TelemetryState,
    shared_state: Arc<Mutex<SharedState>>,
) {
    update_provision_state(
        ProvisionFlags::REDIRECTOR_READY,
        None,
        cancellation_token,
        key_keeper_state,
        telemetry_state,
        shared_state,
    )
    .await;
}

/// Update provision state when key latch provision finished
/// It could  be called by key latch module
pub async fn key_latched(
    cancellation_token: CancellationToken,
    key_keeper_state: KeyKeeperState,
    telemetry_state: TelemetryState,
    shared_state: Arc<Mutex<SharedState>>,
) {
    update_provision_state(
        ProvisionFlags::KEY_LATCH_READY,
        None,
        cancellation_token,
        key_keeper_state,
        telemetry_state,
        shared_state,
    )
    .await;
}

/// Update provision state when listener provision finished
/// It could  be called by listener module
pub async fn listener_started(
    cancellation_token: CancellationToken,
    key_keeper_state: KeyKeeperState,
    telemetry_state: TelemetryState,
    shared_state: Arc<Mutex<SharedState>>,
) {
    update_provision_state(
        ProvisionFlags::LISTENER_READY,
        None,
        cancellation_token,
        key_keeper_state,
        telemetry_state,
        shared_state,
    )
    .await;
}

/// Update provision state for each module to shared_state
async fn update_provision_state(
    state: ProvisionFlags,
    provision_dir: Option<PathBuf>,
    cancellation_token: CancellationToken,
    key_keeper_state: KeyKeeperState,
    telemetry_state: TelemetryState,
    shared_state: Arc<Mutex<SharedState>>,
) {
    let provision_state = provision_wrapper::update_state(shared_state.clone(), state);
    if provision_state.contains(ProvisionFlags::ALL_READY) {
        provision_wrapper::set_provision_finished(shared_state.clone(), true);

        // write provision success state here
        write_provision_state(
            provision_dir,
            key_keeper_state.clone(),
            shared_state.clone(),
        )
        .await;

        // start event threads right after provision successfully
        start_event_threads(
            cancellation_token,
            key_keeper_state,
            telemetry_state,
            shared_state.clone(),
        )
        .await;
    }
}

pub fn key_latch_ready_state_reset(shared_state: Arc<Mutex<SharedState>>) {
    reset_provision_state(ProvisionFlags::KEY_LATCH_READY, shared_state);
}

fn reset_provision_state(state_to_reset: ProvisionFlags, shared_state: Arc<Mutex<SharedState>>) {
    let provision_state = provision_wrapper::reset_state(shared_state.clone(), state_to_reset);
    provision_wrapper::set_provision_finished(
        shared_state.clone(),
        provision_state.contains(ProvisionFlags::ALL_READY),
    );
}

/// Update provision state when provision timedout
/// It will be called if key latch provision timedout
/// Example:
/// ```rust
/// use proxy_agent::provision;
/// use std::sync::{Arc, Mutex};
///
/// let shared_state = Arc::new(Mutex::new(SharedState::new()));
/// provision::provision_timeup(None, shared_state.clone());
/// ```
pub async fn provision_timeup(
    provision_dir: Option<PathBuf>,
    key_keeper_state: KeyKeeperState,
    shared_state: Arc<Mutex<SharedState>>,
) {
    let provision_state = provision_wrapper::get_state(shared_state.clone());
    if !provision_state.contains(ProvisionFlags::ALL_READY) {
        provision_wrapper::set_provision_finished(shared_state.clone(), true);

        // write provision state
        write_provision_state(provision_dir, key_keeper_state, shared_state).await;
    }
}

/// Start event logger & reader tasks and status reporting task
/// It will be called when provision finished or timedout,
/// it is designed to delay start those tasks to give more cpu time to provision tasks
pub async fn start_event_threads(
    cancellation_token: CancellationToken,
    key_keeper_state: KeyKeeperState,
    telemetry_state: TelemetryState,
    shared_state: Arc<Mutex<SharedState>>,
) {
    let logger_threads_initialized =
        provision_wrapper::get_event_log_threads_initialized(shared_state.clone());
    if logger_threads_initialized {
        return;
    }

    let cloned_telemetry_state = telemetry_state.clone();
    event_logger::start_async(
        config::get_events_dir(),
        Duration::default(),
        config::get_max_event_file_count(),
        logger::AGENT_LOGGER_KEY,
        move |status: String| {
            let cloned_telemetry_state = cloned_telemetry_state.clone();
            async move {
                cloned_telemetry_state
                    .set_logger_status_message(status)
                    .await;
            }
        },
    );
    tokio::spawn({
        let event_reader = EventReader::new(
            config::get_events_dir(),
            true,
            cancellation_token.clone(),
            key_keeper_state.clone(),
            telemetry_state.clone(),
            shared_state.clone(),
        );
        async move {
            event_reader
                .start(Some(Duration::from_secs(300)), None, None)
                .await;
        }
    });
    provision_wrapper::set_event_log_threads_initialized(shared_state.clone(), true);

    tokio::spawn({
        let agent_status_task = proxy_agent_status::ProxyAgentStatusTask::new(
            Duration::from_secs(60),
            config::get_logs_dir(),
            cancellation_token.clone(),
            key_keeper_state.clone(),
            telemetry_state.clone(),
            shared_state.clone(),
        );
        async move {
            agent_status_task.start().await;
        }
    });
}

/// Write provision state to provisioned.tag file and status.tag file under provision_dir
/// provisioned.tag is backcompat file, it is used to indicate the provision finished for pilot WinPA
/// status.tag is used to store the provision error message for current WinPA service to query the provision status
///  if status.tag file exists, it means provision finished
///  if status.tag file does not exist, it means provision still in progress
///  the content of the status.tag file is the provision error message,
///  empty means provision success, otherwise provision failed with error message
async fn write_provision_state(
    provision_dir: Option<PathBuf>,
    key_keeper_state: KeyKeeperState,
    shared_state: Arc<Mutex<SharedState>>,
) {
    let provision_dir = provision_dir.unwrap_or_else(config::get_keys_dir);

    let provisioned_file: PathBuf = provision_dir.join("provisioned.tag");
    if let Err(e) = misc_helpers::try_create_folder(&provision_dir) {
        logger::write_error(format!("Failed to create provision folder with error: {e}"));
        return;
    }

    if let Err(e) = std::fs::write(
        provisioned_file,
        misc_helpers::get_date_time_string_with_milliseconds(),
    ) {
        logger::write_error(format!("Failed to write provisioned file with error: {e}"));
    }

    let failed_state_message =
        get_provision_failed_state_message(key_keeper_state, shared_state.clone()).await;
    let status_file: PathBuf = provision_dir.join(STATUS_TAG_TMP_FILE_NAME);
    match std::fs::write(status_file, failed_state_message.as_bytes()) {
        Ok(_) => {
            match std::fs::rename(
                provision_dir.join(STATUS_TAG_TMP_FILE_NAME),
                provision_dir.join(STATUS_TAG_FILE_NAME),
            ) {
                Ok(_) => {}
                Err(e) => {
                    logger::write_error(format!("Failed to rename status file with error: {e}"));
                }
            }
        }
        Err(e) => {
            logger::write_error(format!("Failed to write temp status file with error: {e}"));
        }
    }
}

/// Get provision failed state message
async fn get_provision_failed_state_message(
    key_keeper_state: KeyKeeperState,
    shared_state: Arc<Mutex<SharedState>>,
) -> String {
    let provision_state = provision_wrapper::get_state(shared_state.clone());

    let mut state = String::new(); //provision success, write 0 byte to file
    if !provision_state.contains(ProvisionFlags::REDIRECTOR_READY) {
        state.push_str(&format!(
            "ebpfProgramStatus - {}\r\n",
            redirector::get_status(shared_state.clone()).message
        ));
    }

    if !provision_state.contains(ProvisionFlags::KEY_LATCH_READY) {
        state.push_str(&format!(
            "keyLatchStatus - {}\r\n",
            key_keeper_state.get_status().await.message
        ));
    }

    if !provision_state.contains(ProvisionFlags::LISTENER_READY) {
        state.push_str(&format!(
            "proxyListenerStatus - {}\r\n",
            proxy_server::get_status(shared_state.clone()).message
        ));
    }

    state
}

/// Get provision state
/// It returns the current GPA serice provision state (from shared_state) for GPA service
/// This function is designed and invoked in GPA service
pub async fn get_provision_state(
    key_keeper_state: KeyKeeperState,
    shared_state: Arc<Mutex<SharedState>>,
) -> ProvisionState {
    ProvisionState {
        finished: provision_wrapper::get_provision_finished(shared_state.clone()),
        errorMessage: get_provision_failed_state_message(key_keeper_state, shared_state).await,
    }
}

pub struct ProvisionQuery {
    port: u16,
    duration: Option<Duration>,
}

impl ProvisionQuery {
    pub fn new(port: u16, duration: Option<Duration>) -> ProvisionQuery {
        ProvisionQuery { port, duration }
    }

    /// Get current GPA service provision status and wait until the GPA service provision finished or timeout
    /// This function is designed for GPA command line, serves for --status [--wait seconds] option
    pub async fn get_provision_status_wait(&self) -> (bool, String) {
        loop {
            let (finished, message) = match self.get_current_provision_status().await {
                Ok(state) => (state.finished, state.errorMessage),
                Err(e) => {
                    println!(
                        "Failed to query the current provision state with error: {}.",
                        e
                    );
                    (false, String::new())
                }
            };
            if finished {
                return (finished, message);
            }

            if let Some(d) = self.duration {
                if d.as_millis() >= helpers::get_elapsed_time_in_millisec() {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            }

            // wait timedout return as 'not finished'
            return (false, String::new());
        }
    }

    // Get current provision status from GPA service via http request
    // return value
    //  bool - true provision finished; false provision not finished
    //  String - provision error message, empty means provision success or provision failed.
    async fn get_current_provision_status(&self) -> Result<ProvisionState> {
        let provision_url: String = format!(
            "http://{}:{}{}",
            Ipv4Addr::LOCALHOST,
            self.port,
            PROVISION_URL_PATH
        );

        let provision_url: hyper::Uri = provision_url
            .parse::<hyper::Uri>()
            .map_err(|e| Error::ParseUrl(provision_url, e.to_string()))?;

        let mut headers = HashMap::new();
        headers.insert(constants::METADATA_HEADER.to_string(), "true".to_string());
        hyper_client::get(&provision_url, &headers, None, None, logger::write_warning).await
    }
}

#[cfg(test)]
mod tests {
    use crate::common::logger;
    use crate::provision::ProvisionFlags;
    use crate::proxy::proxy_connection::Connection;
    use crate::proxy::proxy_server;
    use crate::shared_state::key_keeper_wrapper::KeyKeeperState;
    use crate::shared_state::provision_wrapper;
    use crate::shared_state::telemetry_wrapper::TelemetryState;
    use crate::shared_state::SharedState;
    use proxy_agent_shared::logger_manager;
    use std::env;
    use std::fs;
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn provision_state_test() {
        let mut temp_test_path = env::temp_dir();
        let logger_key = "provision_state_test";
        temp_test_path.push(logger_key);

        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);

        logger_manager::init_logger(
            logger::AGENT_LOGGER_KEY.to_string(), // production code uses 'Agent_Log' to write.
            temp_test_path.clone(),
            logger_key.to_string(),
            10 * 1024 * 1024,
            20,
        );
        Connection::init_logger(temp_test_path.to_path_buf());

        // start listener, the port must different from the one used in production code
        let shared_state = SharedState::new();
        let cancellation_token = CancellationToken::new();
        let key_keeper_state = KeyKeeperState::start_new();
        let telemetry_state = TelemetryState::start_new();
        let port: u16 = 8092;
        let proxy_server = proxy_server::ProxyServer::new(
            port,
            cancellation_token.clone(),
            key_keeper_state.clone(),
            telemetry_state.clone(),
            shared_state.clone(),
        );

        tokio::spawn({
            let proxy_server = proxy_server.clone();
            async move {
                proxy_server.start().await;
            }
        });

        // give some time to let the listener started
        let sleep_duration = Duration::from_millis(100);
        tokio::time::sleep(sleep_duration).await;

        let provision_query = super::ProvisionQuery::new(port, None);
        let provision_status = provision_query.get_provision_status_wait().await;
        assert!(!provision_status.0, "provision_status.0 must be false");
        assert_eq!(
            0,
            provision_status.1.len(),
            "provision_status.1 must be empty"
        );

        let dir1 = temp_test_path.to_path_buf();
        let dir2 = temp_test_path.to_path_buf();
        let dir3 = temp_test_path.to_path_buf();
        let s1 = shared_state.clone();
        let s2 = shared_state.clone();
        let s3 = shared_state.clone();
        let handles = vec![
            tokio::spawn(super::update_provision_state(
                ProvisionFlags::REDIRECTOR_READY,
                Some(dir1),
                cancellation_token.clone(),
                key_keeper_state.clone(),
                telemetry_state.clone(),
                s1,
            )),
            tokio::spawn(super::update_provision_state(
                ProvisionFlags::KEY_LATCH_READY,
                Some(dir2),
                cancellation_token.clone(),
                key_keeper_state.clone(),
                telemetry_state.clone(),
                s2,
            )),
            tokio::spawn(super::update_provision_state(
                ProvisionFlags::LISTENER_READY,
                Some(dir3),
                cancellation_token.clone(),
                key_keeper_state.clone(),
                telemetry_state.clone(),
                s3,
            )),
        ];
        for handle in handles {
            handle.await.unwrap();
        }

        let provisioned_file = temp_test_path.join("provisioned.tag");
        assert!(provisioned_file.exists());

        let status_file = temp_test_path.join(super::STATUS_TAG_FILE_NAME);
        assert!(status_file.exists());
        assert_eq!(
            0,
            status_file.metadata().unwrap().len(),
            "success status.tag file must be empty"
        );

        let provision_query = super::ProvisionQuery::new(port, Some(Duration::from_millis(5)));
        let provision_status = provision_query.get_provision_status_wait().await;
        assert!(provision_status.0, "provision_status.0 must be true");
        assert_eq!(
            0,
            provision_status.1.len(),
            "provision_status.1 must be empty"
        );

        let event_threads_initialized =
            provision_wrapper::get_event_log_threads_initialized(shared_state.clone());
        assert!(event_threads_initialized);

        // test reset key latch provision state
        super::key_latch_ready_state_reset(shared_state.clone());
        let provision_state = provision_wrapper::get_state(shared_state.clone());
        assert!(!provision_state.contains(ProvisionFlags::KEY_LATCH_READY));
        let provision_status = provision_query.get_provision_status_wait().await;
        assert!(!provision_status.0, "provision_status.0 must be false");
        assert_eq!(
            0,
            provision_status.1.len(),
            "provision_status.1 must be empty"
        );

        // test key_latched ready again
        super::key_latched(
            cancellation_token.clone(),
            key_keeper_state.clone(),
            telemetry_state.clone(),
            shared_state.clone(),
        );
        let provision_state = provision_wrapper::get_state(shared_state.clone());
        assert!(
            provision_state.contains(ProvisionFlags::ALL_READY),
            "ALL_READY must be true after key_latched again"
        );
        let provision_status = provision_query.get_provision_status_wait().await;
        assert!(provision_status.0, "provision_status.0 must be true");
        assert_eq!(
            0,
            provision_status.1.len(),
            "provision_status.1 must be empty"
        );

        // stop listener
        cancellation_token.cancel();
        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
    }
}
