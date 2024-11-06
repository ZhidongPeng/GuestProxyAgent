// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use crate::common::result::Result;
use crate::common::{error::Error, logger};
use tokio::sync::{mpsc, oneshot};
use windows_service::service_control_handler::ServiceStatusHandle;

enum ServiceAction {
    GetServiceStatusHandle {
        response: oneshot::Sender<Option<ServiceStatusHandle>>,
    },
    SetServiceStatusHandle {
        service_status_handle: Option<ServiceStatusHandle>,
        response: oneshot::Sender<()>,
    },
}

#[derive(Clone)]
pub struct WindowsServiceSharedState(mpsc::Sender<ServiceAction>);

impl WindowsServiceSharedState {
    pub fn start_new() -> Self {
        let (tx, mut rx) = mpsc::channel(100);
        tokio::spawn(async move {
            let mut service_status_handle: Option<ServiceStatusHandle> = None;
            while let Some(action) = rx.recv().await {
                match action {
                    ServiceAction::GetServiceStatusHandle { response } => {
                        if response.send(service_status_handle.clone()).is_err() {
                            logger::write_warning(
                                "Failed to send response to GetServiceStatusHandle".to_string(),
                            );
                        }
                    }
                    ServiceAction::SetServiceStatusHandle {
                        service_status_handle: new_service_status_handle,
                        response,
                    } => {
                        service_status_handle = new_service_status_handle;
                        if response.send(()).is_err() {
                            logger::write_warning(
                                "Failed to send response to SetServiceStatusHandle".to_string(),
                            );
                        }
                    }
                }
            }
        });

        WindowsServiceSharedState(tx)
    }

    pub async fn get_service_status_handle(&self) -> Result<Option<ServiceStatusHandle>> {
        let (response_tx, response_rx) = oneshot::channel();
        self.0
            .send(ServiceAction::GetServiceStatusHandle {
                response: response_tx,
            })
            .await
            .map_err(|e| {
                Error::SendError(
                    "ServiceAction::GetServiceStatusHandle".to_string(),
                    e.to_string(),
                )
            })?;
        response_rx
            .await
            .map_err(|e| Error::RecvError("ServiceAction::GetServiceStatusHandle".to_string(), e))
    }

    pub async fn set_service_status_handle(
        &self,
        service_status_handle: ServiceStatusHandle,
    ) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();
        self.0
            .send(ServiceAction::SetServiceStatusHandle {
                service_status_handle: Some(service_status_handle),
                response: response_tx,
            })
            .await
            .map_err(|e| {
                Error::SendError(
                    "ServiceAction::SetServiceStatusHandle".to_string(),
                    e.to_string(),
                )
            })?;
        response_rx
            .await
            .map_err(|e| Error::RecvError("ServiceAction::SetServiceStatusHandle".to_string(), e))
    }
}
