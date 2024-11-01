// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/// The KeyKeeperState struct is used to send actions to the KeyKeeper module related sahred state fields
/// Example:
/// ```
/// use crate::shared_state::key_keeper_wrapper::KeyKeeperState;
/// use crate::key_keeper::key::Key;
/// use crate::common::result::Result;
/// use std::sync::Arc;
/// use tokio::sync::Notify;
///
/// #[tokio::main]
/// async fn main() -> Result<()> {
///    let key_keeper_state = KeyKeeperState::start_new();
///    let key = Key {
///        key: "key".to_string(),
///        guid: "guid".to_string(),
///        incarnationId: 1,
///    };
///   // set the set when the feature is enabled
///   key_keeper_state.update_key(key).await?;
///   let key = key_keeper_state.get_current_key_value().await?;
///   let guid = key_keeper_state.get_current_key_guid().await?;
///   let incarnation = key_keeper_state.get_current_key_incarnation().await?;
///   let state = key_keeper_state.get_current_secure_channel_state().await?;
///   let rule_id = key_keeper_state.get_wireserver_rule_id().await?;
///   let rule_id = key_keeper_state.get_imds_rule_id().await?;
///   let status_message = key_keeper_state.get_status_message().await?;
///
///   // clear the key once the feature is disabled
///   key_keeper_state.clear_key().await?;
///
///   let notify = key_keeper_state.get_notify().await?;
///   key_keeper_state.notify().await?;
///   Ok(())
/// }
/// ```
use crate::common::error::Error;
use crate::common::result::Result;
use crate::key_keeper::UNKNOWN_STATE;
use crate::{common::logger, key_keeper::key::Key};
use proxy_agent_shared::proxy_agent_aggregate_status::{ModuleState, ProxyAgentDetailStatus};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Notify};

/// The KeyKeeperAction enum represents the actions that can be performed on the KeyKeeper module
enum KeyKeeperAction {
    SetKey {
        key: Option<Key>,
        response: oneshot::Sender<()>,
    },
    GetKey {
        response: oneshot::Sender<Option<Key>>,
    },
    SetSecureChannelState {
        state: String,
        response: oneshot::Sender<()>,
    },
    GetSecureChannelState {
        response: oneshot::Sender<String>,
    },
    SetWireServerRuleId {
        rule_id: String,
        response: oneshot::Sender<()>,
    },
    GetWireServerRuleId {
        response: oneshot::Sender<String>,
    },
    SetImdsRuleId {
        rule_id: String,
        response: oneshot::Sender<()>,
    },
    GetImdsRuleId {
        response: oneshot::Sender<String>,
    },
    GetState {
        response: oneshot::Sender<ModuleState>,
    },
    SetState {
        state: ModuleState,
        response: oneshot::Sender<()>,
    },
    SetKeyKeeperStatusMessage {
        message: String,
        response: oneshot::Sender<()>,
    },
    GetKeyKeeperStatusMessage {
        response: oneshot::Sender<String>,
    },
    GetNotify {
        response: oneshot::Sender<Arc<Notify>>,
    },
}

#[derive(Clone, Debug)]
pub struct KeyKeeperState(mpsc::Sender<KeyKeeperAction>);

impl KeyKeeperState {
    pub fn start_new() -> Self {
        let (sender, mut receiver) = mpsc::channel(100);

        tokio::spawn(async move {
            // The key is used to compute signature for the data between the agent and the host endpoints
            let mut key = None;
            // The current secure channel state
            let mut current_secure_channel_state: String =
                crate::key_keeper::UNKNOWN_STATE.to_string();
            // The rule ID for the WireServer endpoints
            let mut wireserver_rule_id: String = String::new();
            // The rule ID for the IMDS endpoints
            let mut imds_rule_id: String = String::new();
            // The state for key keeper module
            let mut key_keeper_state: ModuleState = ModuleState::UNKNOWN;
            // The status message for the key keeper module
            let mut key_keeper_status_message: String = super::UNKNOWN_STATUS_MESSAGE.to_string();
            let notify = Arc::new(Notify::new());
            loop {
                match receiver.recv().await {
                    Some(KeyKeeperAction::SetKey {
                        key: new_key,
                        response,
                    }) => {
                        key = new_key.clone();
                        if response.send(()).is_err() {
                            logger::write_warning(format!(
                                "Failed to send response to KeyKeeperAction::SetKey with guid '{:?}'",
                                new_key.map(|k| k.guid),
                            ));
                        }
                    }
                    Some(KeyKeeperAction::GetKey { response }) => {
                        if let Err(key) = response.send(key.clone()) {
                            logger::write_warning(format!(
                                "Failed to send response to KeyKeeperAction::GetKey with guid '{:?}'",
                                key.map(|e| e.guid)
                            ));
                        }
                    }
                    Some(KeyKeeperAction::SetSecureChannelState { state, response }) => {
                        current_secure_channel_state = state.to_string();
                        if response.send(()).is_err() {
                            logger::write_warning(format!(
                                "Failed to send response to KeyKeeperAction::SetSecureChannelState '{}' ",
                                state
                            ));
                        }
                    }
                    Some(KeyKeeperAction::GetSecureChannelState { response }) => {
                        if let Err(state) = response.send(current_secure_channel_state.clone()) {
                            logger::write_warning(format!(
                                "Failed to send response to KeyKeeperAction::GetSecureChannelState '{}'",
                                state
                            ));
                        }
                    }
                    Some(KeyKeeperAction::SetWireServerRuleId { rule_id, response }) => {
                        wireserver_rule_id = rule_id.to_string();
                        if response.send(()).is_err() {
                            logger::write_warning(format!(
                                "Failed to send response to KeyKeeperAction::SetWireServerRuleId '{}'",
                                rule_id
                            ));
                        }
                    }
                    Some(KeyKeeperAction::GetWireServerRuleId { response }) => {
                        if let Err(rule_id) = response.send(wireserver_rule_id.clone()) {
                            logger::write_warning(format!(
                                "Failed to send response to KeyKeeperAction::GetWireServerRuleId '{}'",
                                rule_id
                            ));
                        }
                    }
                    Some(KeyKeeperAction::SetImdsRuleId { rule_id, response }) => {
                        imds_rule_id = rule_id.to_string();
                        if response.send(()).is_err() {
                            logger::write_warning(format!(
                                "Failed to send response to KeyKeeperAction::SetImdsRuleId '{}'",
                                rule_id
                            ));
                        }
                    }
                    Some(KeyKeeperAction::GetImdsRuleId { response }) => {
                        if let Err(rule_id) = response.send(imds_rule_id.clone()) {
                            logger::write_warning(format!(
                                "Failed to send response to KeyKeeperAction::GetImdsRuleId '{}'",
                                rule_id
                            ));
                        }
                    }
                    Some(KeyKeeperAction::GetState { response }) => {
                        if let Err(state) = response.send(key_keeper_state.clone()) {
                            logger::write_warning(format!(
                                "Failed to send response to KeyKeeperAction::GetState '{:?}'",
                                state
                            ));
                        }
                    }
                    Some(KeyKeeperAction::SetState { state, response }) => {
                        key_keeper_state = state.clone();
                        if response.send(()).is_err() {
                            logger::write_warning(format!(
                                "Failed to send response to KeyKeeperAction::SetState '{:?}'",
                                state
                            ));
                        }
                    }
                    Some(KeyKeeperAction::SetKeyKeeperStatusMessage { message, response }) => {
                        key_keeper_status_message = message.to_string();
                        if response.send(()).is_err() {
                            logger::write_warning(format!(
                                "Failed to send response to KeyKeeperAction::SetKeyKeeperStatusMessage '{}'",
                                message
                            ));
                        }
                    }
                    Some(KeyKeeperAction::GetKeyKeeperStatusMessage { response }) => {
                        if let Err(message) = response.send(key_keeper_status_message.clone()) {
                            logger::write_warning(format!(
                                "Failed to send response to KeyKeeperAction::GetKeyKeeperStatusMessage '{}'",
                                message
                            ));
                        }
                    }
                    Some(KeyKeeperAction::GetNotify { response }) => {
                        if response.send(notify.clone()).is_err() {
                            logger::write_warning(
                                "Failed to send response to KeyKeeperAction::GetNotify".to_string(),
                            );
                        }
                    }
                    None => break,
                }
            }
        });

        Self(sender)
    }

    async fn set_key(&self, key: Option<Key>) -> Result<()> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(KeyKeeperAction::SetKey { key, response })
            .await
            .map_err(|e| Error::SendError("KeyKeeperAction::SetKey".to_string(), e.to_string()))?;
        receiver
            .await
            .map_err(|e| Error::RecvError("KeyKeeperAction::SetKey".to_string(), e))
    }

    async fn get_key(&self) -> Result<Option<Key>> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(KeyKeeperAction::GetKey { response })
            .await
            .map_err(|e| Error::SendError("KeyKeeperAction::GetKey".to_string(), e.to_string()))?;
        receiver
            .await
            .map_err(|e| Error::RecvError("KeyKeeperAction::GetKey".to_string(), e))
    }

    pub async fn update_key(&self, key: Key) -> Result<()> {
        self.set_key(Some(key)).await
    }

    pub async fn clear_key(&self) -> Result<()> {
        self.set_key(None).await
    }

    pub async fn get_current_key_value(&self) -> Result<Option<String>> {
        match self.get_key().await {
            Ok(Some(k)) => Ok(Some(k.key)),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn get_current_key_guid(&self) -> Result<Option<String>> {
        match self.get_key().await {
            Ok(Some(k)) => Ok(Some(k.guid)),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn get_current_key_incarnation(&self) -> Result<Option<u32>> {
        match self.get_key().await {
            Ok(Some(k)) => Ok(k.incarnationId),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Update the current secure channel state
    /// # Arguments
    /// * `shared_state` - Arc<Mutex<SharedState>>
    /// * `state` - String
    /// # Returns
    /// * `bool` - true if the state is update successfully
    /// *        - false if state is the same as the current state
    /// * `Error` - Error if the state is not read or updated successfully
    pub async fn update_current_secure_channel_state(&self, state: String) -> Result<bool> {
        let current_state = self.get_current_secure_channel_state().await?;
        if current_state == state {
            Ok(false)
        } else {
            self.set_secure_channel_state(state).await?;
            Ok(true)
        }
    }

    async fn set_secure_channel_state(&self, state: String) -> Result<()> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(KeyKeeperAction::SetSecureChannelState { state, response })
            .await
            .map_err(|e| {
                Error::SendError(
                    "KeyKeeperAction::SetSecureChannelState".to_string(),
                    e.to_string(),
                )
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("KeyKeeperAction::SetSecureChannelState".to_string(), e))
    }

    pub async fn get_current_secure_channel_state(&self) -> Result<String> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(KeyKeeperAction::GetSecureChannelState { response })
            .await
            .map_err(|e| {
                Error::SendError(
                    "KeyKeeperAction::GetSecureChannelState".to_string(),
                    e.to_string(),
                )
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("KeyKeeperAction::GetSecureChannelState".to_string(), e))
    }

    /// Update the WireServer rule ID
    /// # Arguments
    /// * `shared_state` - Arc<Mutex<SharedState>>
    /// * `rule_id` - String
    /// # Returns
    /// * `bool` - true if the rule ID is update successfully
    /// *        - false if rule ID is the same as the current state  
    /// * `String` - the rule Id before the update operation
    /// * `Error` - Error if the rule ID is not read or updated successfully
    pub async fn update_wireserver_rule_id(&self, rule_id: String) -> Result<(bool, String)> {
        let old_rule_id = self.get_wireserver_rule_id().await?;
        if old_rule_id == rule_id {
            Ok((false, old_rule_id))
        } else {
            self.set_wireserver_rule_id(rule_id).await?;
            Ok((true, old_rule_id))
        }
    }

    async fn set_wireserver_rule_id(&self, rule_id: String) -> Result<()> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(KeyKeeperAction::SetWireServerRuleId { rule_id, response })
            .await
            .map_err(|e| {
                Error::SendError(
                    "KeyKeeperAction::SetWireServerRuleId".to_string(),
                    e.to_string(),
                )
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("KeyKeeperAction::SetWireServerRuleId".to_string(), e))
    }

    pub async fn get_wireserver_rule_id(&self) -> Result<String> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(KeyKeeperAction::GetWireServerRuleId { response })
            .await
            .map_err(|e| {
                Error::SendError(
                    "KeyKeeperAction::GetWireServerRuleId".to_string(),
                    e.to_string(),
                )
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("KeyKeeperAction::GetWireServerRuleId".to_string(), e))
    }

    pub async fn get_imds_rule_id(&self) -> Result<String> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(KeyKeeperAction::GetImdsRuleId { response })
            .await
            .map_err(|e| {
                Error::SendError("KeyKeeperAction::GetImdsRuleId".to_string(), e.to_string())
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("KeyKeeperAction::GetImdsRuleId".to_string(), e))
    }

    async fn set_imds_rule_id(&self, rule_id: String) -> Result<()> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(KeyKeeperAction::SetImdsRuleId { rule_id, response })
            .await
            .map_err(|e| {
                Error::SendError("KeyKeeperAction::SetImdsRuleId".to_string(), e.to_string())
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("KeyKeeperAction::SetImdsRuleId".to_string(), e))
    }

    /// Update the IMDS rule ID
    /// # Arguments
    /// * `shared_state` - Arc<Mutex<SharedState>>
    /// * `rule_id` - String
    /// # Returns
    /// * `bool` - true if the rule ID is update successfully
    /// * `String` - the rule Id before the update operation
    /// * `Error` - Error if the rule ID is not read or updated successfully
    pub async fn update_imds_rule_id(&self, rule_id: String) -> Result<(bool, String)> {
        let old_rule_id = self.get_imds_rule_id().await?;
        if old_rule_id == rule_id {
            Ok((false, old_rule_id))
        } else {
            self.set_imds_rule_id(rule_id).await?;
            Ok((true, old_rule_id))
        }
    }

    pub async fn get_status_message(&self) -> Result<String> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(KeyKeeperAction::GetKeyKeeperStatusMessage { response })
            .await
            .map_err(|e| {
                Error::SendError(
                    "KeyKeeperAction::GetKeyKeeperStatusMessage".to_string(),
                    e.to_string(),
                )
            })?;
        receiver.await.map_err(|e| {
            Error::RecvError("KeyKeeperAction::GetKeyKeeperStatusMessage".to_string(), e)
        })
    }

    pub async fn set_status_message(&self, message: String) -> Result<()> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(KeyKeeperAction::SetKeyKeeperStatusMessage { message, response })
            .await
            .map_err(|e| {
                Error::SendError(
                    "KeyKeeperAction::SetKeyKeeperStatusMessage".to_string(),
                    e.to_string(),
                )
            })?;
        receiver.await.map_err(|e| {
            Error::RecvError("KeyKeeperAction::SetKeyKeeperStatusMessage".to_string(), e)
        })
    }

    pub async fn get_current_state(&self) -> Result<ModuleState> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(KeyKeeperAction::GetState { response })
            .await
            .map_err(|e| {
                Error::SendError("KeyKeeperAction::GetState".to_string(), e.to_string())
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("KeyKeeperAction::GetState".to_string(), e))
    }

    pub async fn set_state(&self, state: ModuleState) -> Result<()> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(KeyKeeperAction::SetState { state, response })
            .await
            .map_err(|e| {
                Error::SendError("KeyKeeperAction::SetState".to_string(), e.to_string())
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("KeyKeeperAction::SetState".to_string(), e))
    }

    pub async fn get_notify(&self) -> Result<Arc<Notify>> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(KeyKeeperAction::GetNotify { response })
            .await
            .map_err(|e| {
                Error::SendError("KeyKeeperAction::GetNotify".to_string(), e.to_string())
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("KeyKeeperAction::GetNotify".to_string(), e))
    }

    pub async fn notify(&self) -> Result<()> {
        let notify = self.get_notify().await?;
        notify.notify_one();
        Ok(())
    }

    pub async fn get_status(&self) -> ProxyAgentDetailStatus {
        let mut states = HashMap::new();
        states.insert(
            "secureChannelState".to_string(),
            self
                .get_current_secure_channel_state()
                .await
                .unwrap_or(UNKNOWN_STATE.to_string()),
        );
        if let Ok(Some(key_guid)) = self.get_current_key_guid().await {
            states.insert("keyGuid".to_string(), key_guid);
        }
        states.insert(
            "wireServerRuleId".to_string(),
            self
                .get_wireserver_rule_id()
                .await
                .unwrap_or(UNKNOWN_STATE.to_string()),
        );
        states.insert(
            "imdsRuleId".to_string(),
            self
                .get_imds_rule_id()
                .await
                .unwrap_or(UNKNOWN_STATE.to_string()),
        );
        if let Ok(Some(incarnation)) = self.get_current_key_incarnation().await {
            states.insert("keyIncarnationId".to_string(), incarnation.to_string());
        }

        ProxyAgentDetailStatus {
            status: self
                .get_current_state()
                .await
                .unwrap_or(ModuleState::UNKNOWN),
            message: self
                .get_status_message()
                .await
                .unwrap_or(super::UNKNOWN_STATUS_MESSAGE.to_string()),
            states: Some(states),
        }
    }
}
