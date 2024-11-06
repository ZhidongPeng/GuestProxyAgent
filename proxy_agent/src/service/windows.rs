// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to start the GPA service as a Windows service and hook up stop service control handler.
//! The GPA service is implemented as a Windows service using the windows_service crate.
//! It is started, stopped, and controlled by the Windows service manager.

use crate::common::{constants, logger, result::Result};
use crate::{service, shared_state::SharedState};
use std::time::Duration;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

pub async fn run_service() -> Result<()> {
    let shared_state = SharedState::start_all();
    let cloned_shared_state = shared_state.clone();
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                // Pass the tokio runtime handle here for the windows service stop event.
                let handle = crate::ASYNC_RUNTIME_HANDLE.get().expect(
                    "You must provide the Tokio runtime handle before this function is called",
                );
                handle.block_on(async {
                    service::stop_service(cloned_shared_state.clone()).await;
                    if let Ok(Some(status_handle)) = cloned_shared_state
                        .get_windows_service_shared_state()
                        .get_service_status_handle()
                        .await
                    {
                        let stop_state = ServiceStatus {
                            service_type: ServiceType::OWN_PROCESS,
                            current_state: ServiceState::Stopped,
                            controls_accepted: ServiceControlAccept::STOP,
                            exit_code: ServiceExitCode::Win32(0),
                            checkpoint: 0,
                            wait_hint: Duration::default(),
                            process_id: None,
                        };
                        if let Err(e) = status_handle.set_service_status(stop_state) {
                            logger::write_error(format!(
                                "Failed to set service status to Stopped: {}",
                                e
                            ));
                        }
                    } else {
                        // workaround to stop the service by exiting the process
                        logger::write_warning(
                            "Force exit the process to stop the service.".to_string(),
                        );
                        std::process::exit(0);
                    }
                });
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    // start service
    service::start_service(shared_state.clone());

    // set the service state to Running
    let status_handle =
        service_control_handler::register(constants::PROXY_AGENT_SERVICE_NAME, event_handler)?;
    let running_state = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    status_handle.set_service_status(running_state)?;

    shared_state
        .get_windows_service_shared_state()
        .set_service_status_handle(status_handle)
        .await?;

    Ok(())
}
