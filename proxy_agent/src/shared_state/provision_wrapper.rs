// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use crate::common::error::Error;
use crate::common::logger;
use crate::common::result::Result;
use crate::provision::ProvisionFlags;
use tokio::sync::{mpsc, oneshot};

enum ProvisionAction {
    UpdateState {
        state: ProvisionFlags,
        response: oneshot::Sender<ProvisionFlags>,
    },
    GetState {
        response: oneshot::Sender<ProvisionFlags>,
    },
    SetEventLogThreadsInitialized {
        response: oneshot::Sender<()>,
    },
    GetEventLogsThreadsInitialized {
        response: oneshot::Sender<bool>,
    },
    SetProvisionFinished {
        finished: bool,
        response: oneshot::Sender<bool>,
    },
    GetProvisionFinished {
        response: oneshot::Sender<bool>,
    },
}

#[derive(Clone, Debug)]
pub struct ProvisionSharedState(mpsc::Sender<ProvisionAction>);

impl ProvisionSharedState {
    pub fn start_new() -> Self {
        let (tx, mut rx) = mpsc::channel(100);
        tokio::spawn(async move {
            // The provision state, it is a bitflag field
            let mut provision_state: ProvisionFlags = ProvisionFlags::NONE;
            // The flag to indicate if the event log threads are initialized
            let mut provision_event_log_threads_initialized: bool = false;
            // The flag to indicate if the GPA service provision is finished
            let mut provision_finished: bool = false;
            while let Some(action) = rx.recv().await {
                match action {
                    ProvisionAction::UpdateState { state, response } => {
                        provision_state &= state;
                        if let Err(new_state) = response.send(provision_state.clone()) {
                            logger::write_warning(format!(
                                "Failed to send response to ProvisionAction::UpdateState with new state '{:?}'",
                                new_state
                            ));
                        }
                    }
                    ProvisionAction::GetState { response } => {
                        if let Err(state) = response.send(provision_state.clone()) {
                            logger::write_warning(format!(
                                "Failed to send response to ProvisionAction::GetState with state '{:?}'",
                                state
                            ));
                        }
                    }
                    ProvisionAction::SetEventLogThreadsInitialized { response } => {
                        provision_event_log_threads_initialized = true;
                        if response.send(()).is_err() {
                            logger::write_warning("Failed to send response to ProvisionAction::SetEventLogThreadsInitialized".to_string());
                        }
                    }
                    ProvisionAction::GetEventLogsThreadsInitialized { response } => {
                        if let Err(initialized) =
                            response.send(provision_event_log_threads_initialized)
                        {
                            logger::write_warning(format!(
                                "Failed to send response to ProvisionAction::GetEventLogsThreadsInitialized with initialized '{:?}'",
                                initialized
                            ));
                        }
                    }
                    ProvisionAction::SetProvisionFinished { finished, response } => {
                        provision_finished = finished;
                        if response.send(finished).is_err() {
                            logger::write_warning(
                                "Failed to send response to ProvisionAction::SetProvisionFinished"
                                    .to_string(),
                            );
                        }
                    }
                    ProvisionAction::GetProvisionFinished { response } => {
                        if let Err(finished) = response.send(provision_finished) {
                            logger::write_warning(format!(
                                "Failed to send response to ProvisionAction::GetProvisionFinished with finished '{:?}'",
                                finished
                            ));
                        }
                    }
                }
            }
        });

        ProvisionSharedState(tx)
    }

    /// Update the one of the provision state
    /// # Arguments
    /// * `state` - ProvisionFlags
    /// # Returns
    /// * `ProvisionFlags` - the updated provision state
    /// # Errors - SendError, RecvError
    /// # Remarks
    /// * The provision state is a bit field, the state is updated by OR operation
    pub async fn update_one_state(&self, state: ProvisionFlags) -> Result<ProvisionFlags> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(ProvisionAction::UpdateState {
                state,
                response: tx,
            })
            .await
            .map_err(|e| {
                Error::SendError("ProvisionAction::UpdateState".to_string(), e.to_string())
            })?;
        rx.await
            .map_err(|e| Error::RecvError("ProvisionAction::UpdateState".to_string(), e))
    }

    /// Reset the provision state
    /// # Arguments
    /// * `shared_state` - Arc<Mutex<SharedState>>
    /// * `state` - ProvisionFlags to reset/remove from the provision state
    /// # Returns
    /// * `ProvisionFlags` - the updated provision state
    /// # Errors - SendError, RecvError
    /// # Remarks
    /// * The provision state is a bit field, the state is updated by AND & NOT operation
    pub async fn reset_one_state(&self, state: ProvisionFlags) -> Result<ProvisionFlags> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(ProvisionAction::UpdateState {
                state: !state,
                response: tx,
            })
            .await
            .map_err(|e| {
                Error::SendError("ProvisionAction::UpdateState".to_string(), e.to_string())
            })?;
        rx.await
            .map_err(|e| Error::RecvError("ProvisionAction::UpdateState".to_string(), e))
    }

    pub async fn get_state(&self) -> Result<ProvisionFlags> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(ProvisionAction::GetState { response: tx })
            .await
            .map_err(|e| {
                Error::SendError("ProvisionAction::GetState".to_string(), e.to_string())
            })?;
        rx.await
            .map_err(|e| Error::RecvError("ProvisionAction::GetState".to_string(), e))
    }

    pub async fn set_event_log_threads_initialized(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(ProvisionAction::SetEventLogThreadsInitialized { response: tx })
            .await
            .map_err(|e| {
                Error::SendError(
                    "ProvisionAction::SetEventLogThreadsInitialized".to_string(),
                    e.to_string(),
                )
            })?;
        rx.await.map_err(|e| {
            Error::RecvError(
                "ProvisionAction::SetEventLogThreadsInitialized".to_string(),
                e,
            )
        })
    }

    pub async fn get_event_log_threads_initialized(&self) -> Result<bool> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(ProvisionAction::GetEventLogsThreadsInitialized { response: tx })
            .await
            .map_err(|e| {
                Error::SendError(
                    "ProvisionAction::GetEventLogsThreadsInitialized".to_string(),
                    e.to_string(),
                )
            })?;
        rx.await.map_err(|e| {
            Error::RecvError(
                "ProvisionAction::GetEventLogsThreadsInitialized".to_string(),
                e,
            )
        })
    }

    pub async fn set_provision_finished(&self, finished: bool) -> Result<bool> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(ProvisionAction::SetProvisionFinished {
                finished,
                response: tx,
            })
            .await
            .map_err(|e| {
                Error::SendError(
                    "ProvisionAction::SetProvisionFinished".to_string(),
                    e.to_string(),
                )
            })?;
        rx.await
            .map_err(|e| Error::RecvError("ProvisionAction::SetProvisionFinished".to_string(), e))
    }

    pub async fn get_provision_finished(&self) -> Result<bool> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(ProvisionAction::GetProvisionFinished { response: tx })
            .await
            .map_err(|e| {
                Error::SendError(
                    "ProvisionAction::GetProvisionFinished".to_string(),
                    e.to_string(),
                )
            })?;
        rx.await
            .map_err(|e| Error::RecvError("ProvisionAction::GetProvisionFinished".to_string(), e))
    }
}
