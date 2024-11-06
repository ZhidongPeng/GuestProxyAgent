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
    SetReaderState {
        reader_state: ModuleState,
        response: oneshot::Sender<()>,
    },
    GetReaderState {
        response: oneshot::Sender<ModuleState>,
    },
    SetLoggerState{
        logger_state: ModuleState,
        response: oneshot::Sender<()>,
    },
    GetLoggerState{
        response: oneshot::Sender<ModuleState>,
    },
    SetReaderStatusMessage{
        reader_status_message: String,
        response: oneshot::Sender<()>,
    },
    GetReaderStatusMessage{
        response: oneshot::Sender<String>,
    },
    SetLoggerStatusMessage{
        logger_status_message: String,
        response: oneshot::Sender<()>,
    },
    GetLoggerStatusMessage{
        response: oneshot::Sender<String>,
    },
}

#[derive(Clone, Debug)]
pub struct TelemetrySharedState(mpsc::Sender<TelemetryAction>);

impl TelemetrySharedState {
    pub fn start_new() -> Self {
        let (sender, mut receiver) = mpsc::channel(100);
        tokio::spawn(async move {
            let mut vm_meta_data: Option<VmMetaData> = None;
            let mut reader_state = ModuleState::UNKNOWN;
            let mut logger_state = ModuleState::UNKNOWN;
            let mut reader_status_message = super::UNKNOWN_STATUS_MESSAGE.to_string();
            let mut logger_status_message = super::UNKNOWN_STATUS_MESSAGE.to_string();
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
                    Some(TelemetryAction::SetReaderState {
                        reader_state: state,
                        response,
                    }) => {
                        reader_state = state.clone();
                        if response.send(()).is_err() {
                            logger::write_warning(format!(
                                "Failed to send response to TelemetryAction::SetReaderState '{:?}'",
                                state,
                            ));
                        }
                    }
                    Some(TelemetryAction::GetReaderState { response }) => {
                        if let Err(state) = response.send(reader_state.clone()) {
                            logger::write_warning(format!(
                                "Failed to send response to TelemetryAction::GetReaderState '{:?}'",
                                state,
                            ));
                        }
                    }
                    Some(TelemetryAction::SetLoggerState {
                        logger_state: state,
                        response,
                    }) => {
                        logger_state = state.clone();
                        if response.send(()).is_err() {
                            logger::write_warning(format!(
                                "Failed to send response to TelemetryAction::SetLoggerState '{:?}'",
                                state,
                            ));
                        }
                    }
                    Some(TelemetryAction::GetLoggerState { response }) => {
                        if let Err(state) = response.send(logger_state.clone()) {
                            logger::write_warning(format!(
                                "Failed to send response to TelemetryAction::GetLoggerState '{:?}'",
                                state,
                            ));
                        }
                    }
                    Some(TelemetryAction::SetReaderStatusMessage {
                        reader_status_message: message,
                        response,
                    }) => {
                        reader_status_message = message.clone();
                        if response.send(()).is_err() {
                            logger::write_warning(format!(
                                "Failed to send response to TelemetryAction::SetReaderStatusMessage '{:?}'",
                                message,
                            ));
                        }
                    }
                    Some(TelemetryAction::GetReaderStatusMessage { response }) => {
                        if let Err(message) = response.send(reader_status_message.clone()) {
                            logger::write_warning(format!(
                                "Failed to send response to TelemetryAction::GetReaderStatusMessage '{:?}'",
                                message,
                            ));
                        }
                    }
                    Some(TelemetryAction::SetLoggerStatusMessage {
                        logger_status_message: message,
                        response,
                    }) => {
                        logger_status_message = message.clone();
                        if response.send(()).is_err() {
                            logger::write_warning(format!(
                                "Failed to send response to TelemetryAction::SetLoggerStatusMessage '{:?}'",
                                message,
                            ));
                        }
                    }
                    Some(TelemetryAction::GetLoggerStatusMessage { response }) => {
                        if let Err(message) = response.send(logger_status_message.clone()) {
                            logger::write_warning(format!(
                                "Failed to send response to TelemetryAction::GetLoggerStatusMessage '{:?}'",
                                message,
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

    pub async fn set_reader_state(&self, reader_state: ModuleState) -> Result<()> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(TelemetryAction::SetReaderState {
                reader_state,
                response,
            })
            .await
            .map_err(|e| {
                Error::SendError("TelemetryAction::SetReaderState".to_string(), e.to_string())
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("TelemetryAction::SetReaderState".to_string(), e))
    }

    pub async fn get_reader_state(&self) -> Result<ModuleState> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(TelemetryAction::GetReaderState { response })
            .await
            .map_err(|e| {
                Error::SendError("TelemetryAction::GetReaderState".to_string(), e.to_string())
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("TelemetryAction::GetReaderState".to_string(), e))
    }

    pub async fn set_logger_state(&self, logger_state: ModuleState) -> Result<()> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(TelemetryAction::SetLoggerState {
                logger_state,
                response,
            })
            .await
            .map_err(|e| {
                Error::SendError("TelemetryAction::SetLoggerState".to_string(), e.to_string())
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("TelemetryAction::SetLoggerState".to_string(), e))
    }

    pub async fn get_logger_state(&self) -> Result<ModuleState> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(TelemetryAction::GetLoggerState { response })
            .await
            .map_err(|e| {
                Error::SendError("TelemetryAction::GetLoggerState".to_string(), e.to_string())
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("TelemetryAction::GetLoggerState".to_string(), e))
    }

    pub async fn set_reader_status_message(&self, reader_status_message: String) -> Result<()> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(TelemetryAction::SetReaderStatusMessage {
                reader_status_message,
                response,
            })
            .await
            .map_err(|e| {
                Error::SendError("TelemetryAction::SetReaderStatusMessage".to_string(), e.to_string())
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("TelemetryAction::SetReaderStatusMessage".to_string(), e))
    }

    pub async fn get_reader_status_message(&self) -> Result<String> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(TelemetryAction::GetReaderStatusMessage { response })
            .await
            .map_err(|e| {
                Error::SendError("TelemetryAction::GetReaderStatusMessage".to_string(), e.to_string())
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("TelemetryAction::GetReaderStatusMessage".to_string(), e))
    }

    pub async fn set_logger_status_message(&self, logger_status_message: String) -> Result<()> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(TelemetryAction::SetLoggerStatusMessage {
                logger_status_message,
                response,
            })
            .await
            .map_err(|e| {
                Error::SendError("TelemetryAction::SetLoggerStatusMessage".to_string(), e.to_string())
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("TelemetryAction::SetLoggerStatusMessage".to_string(), e))
    }

    pub async fn get_logger_status_message(&self) -> Result<String> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(TelemetryAction::GetLoggerStatusMessage { response })
            .await
            .map_err(|e| {
                Error::SendError("TelemetryAction::GetLoggerStatusMessage".to_string(), e.to_string())
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("TelemetryAction::GetLoggerStatusMessage".to_string(), e))
    }

    pub async fn get_telemetry_logger_status(&self) -> ProxyAgentDetailStatus {
        ProxyAgentDetailStatus {
            status:self.get_logger_state().await.unwrap_or(ModuleState::UNKNOWN),
            message: self.get_logger_status_message().await.unwrap_or(super::UNKNOWN_STATUS_MESSAGE.to_string()),
            states: None,
        }
    }

    pub async fn get_telemetry_reader_status(&self) -> ProxyAgentDetailStatus {
        ProxyAgentDetailStatus {
            status:self.get_reader_state().await.unwrap_or(ModuleState::UNKNOWN),
            message: self.get_reader_status_message().await.unwrap_or(super::UNKNOWN_STATUS_MESSAGE.to_string()),
            states: None,
        }
    }
}
