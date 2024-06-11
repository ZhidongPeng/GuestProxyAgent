// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common::{config, helpers, logger};
use crate::proxy::proxy_server;
use crate::shared_state::{provision_wrapper, telemetry_wrapper, SharedState};
use crate::telemetry::event_reader;
use crate::{key_keeper, proxy_agent_status, redirector};
use proxy_agent_shared::misc_helpers;
use proxy_agent_shared::telemetry::event_logger;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const STATUS_TAG_TMP_FILE_NAME: &str = "status.tag.tmp";
const STATUS_TAG_FILE_NAME: &str = "status.tag";

const REDIRECTOR_READY: u8 = 1;
const KEY_LATCH_READY: u8 = 2;
const LISTENER_READY: u8 = 4;

pub const PROVISION_URL_PATH: &str = "/provision";

pub fn redirector_ready(shared_state: Arc<Mutex<SharedState>>) {
    update_provision_state(REDIRECTOR_READY, None, shared_state);
}

pub fn key_latched(shared_state: Arc<Mutex<SharedState>>) {
    update_provision_state(KEY_LATCH_READY, None, shared_state);
}

pub fn listener_started(shared_state: Arc<Mutex<SharedState>>) {
    update_provision_state(LISTENER_READY, None, shared_state);
}

fn update_provision_state(
    state: u8,
    provision_dir: Option<PathBuf>,
    shared_state: Arc<Mutex<SharedState>>,
) {
    let provision_state = provision_wrapper::update_state(shared_state.clone(), state);
    if provision_state == 7 {
        provision_wrapper::set_provision_finished(shared_state.clone());

        // write provision state
        write_provision_state(provision_dir, shared_state.clone());

        // start event threads right after provision successfully
        start_event_threads(shared_state.clone());
    }
}

pub fn provision_timeup(provision_dir: Option<PathBuf>, shared_state: Arc<Mutex<SharedState>>) {
    let provision_state = provision_wrapper::get_state(shared_state.clone());
    if provision_state != 7 {
        provision_wrapper::set_provision_finished(shared_state.clone());

        // write provision state
        write_provision_state(provision_dir, shared_state.clone());
    }
}

pub fn start_event_threads(shared_state: Arc<Mutex<SharedState>>) {
    let logger_threads_initialized =
        provision_wrapper::get_event_log_threads_initialized(shared_state.clone());
    if logger_threads_initialized {
        return;
    }

    let cloned_state = shared_state.clone();
    event_logger::start_async(
        config::get_events_dir(),
        Duration::default(),
        config::get_max_event_file_count(),
        logger::AGENT_LOGGER_KEY,
        move |status: String| {
            telemetry_wrapper::set_logger_status_message(cloned_state.clone(), status);
        },
    );
    event_reader::start_async(
        config::get_events_dir(),
        Duration::from_secs(300),
        true,
        shared_state.clone(),
        None,
    );
    provision_wrapper::set_event_log_threads_initialized(shared_state.clone(), true);
    proxy_agent_status::start_async(Duration::default(), shared_state.clone());
}

fn write_provision_state(provision_dir: Option<PathBuf>, shared_state: Arc<Mutex<SharedState>>) {
    let provision_dir = provision_dir.unwrap_or_else(config::get_keys_dir);

    let provisioned_file: PathBuf = provision_dir.join("provisioned.tag");
    _ = misc_helpers::try_create_folder(provision_dir.to_path_buf());
    _ = std::fs::write(
        provisioned_file,
        misc_helpers::get_date_time_string_with_milliseconds(),
    );

    let status = get_provision_state_message(shared_state.clone());
    let status_file: PathBuf = provision_dir.join(STATUS_TAG_TMP_FILE_NAME);
    match std::fs::write(status_file, status.as_bytes()) {
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

pub fn get_provision_state(shared_state: Arc<Mutex<SharedState>>) -> ProivsionState {
    ProivsionState {
        finished: provision_wrapper::get_provision_finished(shared_state.clone()),
        errorMessage: get_provision_state_message(shared_state),
    }
}

fn get_provision_state_message(shared_state: Arc<Mutex<SharedState>>) -> String {
    let provision_state = provision_wrapper::get_state(shared_state.clone());

    let mut state = String::new(); //provision success, write 0 byte to file
    if provision_state & REDIRECTOR_READY != REDIRECTOR_READY {
        state.push_str(&format!(
            "ebpfProgramStatus - {}\r\n",
            redirector::get_status(shared_state.clone()).message
        ));
    }

    if provision_state & KEY_LATCH_READY != KEY_LATCH_READY {
        state.push_str(&format!(
            "keyLatchStatus - {}\r\n",
            key_keeper::get_status(shared_state.clone()).message
        ));
    }

    if provision_state & LISTENER_READY != LISTENER_READY {
        state.push_str(&format!(
            "proxyListenerStatus - {}\r\n",
            proxy_server::get_status(shared_state.clone()).message
        ));
    }

    state
}

pub fn get_provision_status_wait(port: u16, duration: Option<Duration>) -> (bool, String) {
    // Create a new Tokio runtime
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    // Use the runtime to block on the async task
    rt.block_on(async move { get_provision_status_wait_async(port, duration).await })
}

async fn get_provision_status_wait_async(port: u16, duration: Option<Duration>) -> (bool, String) {
    loop {
        let provision_state = get_current_provision_status(port).await;
        let (finished, message) = match provision_state {
            Ok(state) => (state.finished, state.errorMessage),
            Err(e) => {
                logger::write_warning(format!(
                    "Failed to query the current provision state with error:{}.",
                    e
                ));
                (false, String::new())
            }
        };

        if finished {
            return (finished, message);
        }

        if let Some(d) = duration {
            if d.as_millis() >= helpers::get_elapsed_time_in_millisec() {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
        }

        return (false, String::new());
    }
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct ProivsionState {
    finished: bool,
    errorMessage: String,
}

// Get provision status
// return value
//  bool - true provision finished; false provision not finished
//  String - provision error message, empty means provision success or provision failed.
async fn get_current_provision_status(port: u16) -> std::io::Result<ProivsionState> {
    let provision_url = format!("http://127.0.0.1:{}{}", port, PROVISION_URL_PATH);
    let headers = HashMap::new();
    crate::common::http::get(&provision_url, &headers, None, None, logger::write_warning).await
}

#[cfg(test)]
mod tests {
    use proxy_agent_shared::logger_manager;

    use crate::common::logger;
    use crate::proxy::proxy_connection::Connection;
    use crate::proxy::proxy_server;
    use crate::shared_state::provision_wrapper;
    use crate::shared_state::SharedState;
    use std::env;
    use std::fs;
    use std::thread;
    use std::time::Duration;

    // this test is to test the direct request to the proxy server
    // it requires more threads to run server and client
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn provision_state_test() {
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push("update_provision_state_test");

        let logger_key = "direct_request_test";
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push(logger_key);
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
        let s = shared_state.clone();
        let port: u16 = 8092;
        proxy_server::start_async(port, s.clone()).await;

        // give some time to let the listener started
        let sleep_duration = Duration::from_millis(100);
        thread::sleep(sleep_duration);

        let provision_status = super::get_provision_status_wait_async(port, None).await;
        assert!(!provision_status.0, "provision_status.0 must be false");
        println!("provision_status - {}", provision_status.1);
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
            thread::spawn(move || super::update_provision_state(1, Some(dir1), s1)),
            thread::spawn(move || super::update_provision_state(2, Some(dir2), s2)),
            thread::spawn(move || super::update_provision_state(4, Some(dir3), s3)),
        ];

        for handle in handles {
            handle.join().unwrap();
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

        let provision_status =
            super::get_provision_status_wait_async(port, Some(Duration::from_millis(5))).await;
        assert!(provision_status.0, "provision_status.0 must be true");
        assert_eq!(
            0,
            provision_status.1.len(),
            "provision_status.1 must be empty"
        );

        let event_threads_initialized =
            provision_wrapper::get_event_log_threads_initialized(shared_state.clone());
        assert!(event_threads_initialized);

        // stop listener
        proxy_server::stop(port, shared_state);

        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
    }
}
