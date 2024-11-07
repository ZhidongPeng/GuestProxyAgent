// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use crate::common::result::Result;
use crate::common::{error::Error, logger};
use crate::telemetry::event_reader::VmMetaData;
use proxy_agent_shared::proxy_agent_aggregate_status::{ModuleState, ProxyAgentDetailStatus};
use tokio::sync::{mpsc, oneshot};

enum TelemetryAction {
    SetVmMetaData {
        vm_meta_data: Option<VmMetaData>,
        response: oneshot::Sender<()>,
    },
    GetVmMetaData {
        response: oneshot::Sender<Option<VmMetaData>>,
    },
}

#[derive(Clone, Debug)]
pub struct TelemetrySharedState(mpsc::Sender<TelemetryAction>);

impl TelemetrySharedState {
    pub fn start_new() -> Self {
        let (sender, mut receiver) = mpsc::channel(100);
        tokio::spawn(async move {
            let mut vm_meta_data: Option<VmMetaData> = None;
            loop {
                match receiver.recv().await {
                    Some(TelemetryAction::SetVmMetaData {
                        vm_meta_data: meta_data,
                        response,
                    }) => {
                        vm_meta_data = meta_data.clone();
                        if response.send(()).is_err() {
                            logger::write_warning(format!(
                                "Failed to send response to TelemetryAction::SetVmMetaData '{:?}'",
                                meta_data,
                            ));
                        }
                    }
                    Some(TelemetryAction::GetVmMetaData { response }) => {
                        if let Err(meta_data) = response.send(vm_meta_data.clone()) {
                            logger::write_warning(format!(
                                "Failed to send response to TelemetryAction::GetVmMetaData '{:?}'",
                                meta_data,
                            ));
                        }
                    }
                    None => {
                        break;
                    }
                }
            }
        });

        Self(sender)
    }

    pub async fn set_vm_meta_data(&self, vm_meta_data: Option<VmMetaData>) -> Result<()> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(TelemetryAction::SetVmMetaData {
                vm_meta_data,
                response,
            })
            .await
            .map_err(|e| {
                Error::SendError("TelemetryAction::SetVmMetaData".to_string(), e.to_string())
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("TelemetryAction::SetVmMetaData".to_string(), e))
    }

    pub async fn get_vm_meta_data(&self) -> Result<Option<VmMetaData>> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(TelemetryAction::GetVmMetaData { response })
            .await
            .map_err(|e| {
                Error::SendError("TelemetryAction::GetVmMetaData".to_string(), e.to_string())
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("TelemetryAction::GetVmMetaData".to_string(), e))
    }

}
