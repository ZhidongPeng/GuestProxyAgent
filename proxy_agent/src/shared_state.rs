// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use crate::key_keeper::{self, key::Key};
use std::sync::{Arc, Mutex};

const UNKNOWN_STATUS_MESSAGE: &str = "Status unknown.";

#[derive(Clone)]
pub struct SharedState {
    // key_keeper
    pub key: Option<Key>,
    pub current_secure_channel_state: String,
    pub wireserver_rule_id: String,
    pub imds_rule_id: String,
    pub key_keeper_shutdown: bool,
    pub key_keeper_status_message: String,
    // proxy_listener
    pub proxy_listner_shutdown: bool,
    pub connection_count: u128,
    pub proxy_listner_status_message: String,
}

pub fn new_shared_state() -> Arc<Mutex<SharedState>> {
    let shared_state = SharedState::default();
    Arc::new(Mutex::new(shared_state))
}

impl Default for SharedState {
    fn default() -> Self {
        SharedState {
            // key_keeper
            key: None,
            current_secure_channel_state: key_keeper::UNKNOWN_STATE.to_string(),
            wireserver_rule_id: String::new(),
            imds_rule_id: String::new(),
            key_keeper_shutdown: false,
            key_keeper_status_message: UNKNOWN_STATUS_MESSAGE.to_string(),
            // proxy_listener
            proxy_listner_shutdown: false,
            connection_count: 0,
            proxy_listner_status_message: UNKNOWN_STATUS_MESSAGE.to_string(),
        }
    }
}

/// KeyKeeper implementation
impl SharedState {
    pub fn set_key(&mut self, key: Key) {
        self.key = Some(key);
    }

    pub fn get_current_key_value(&self) -> Option<String> {
        self.key.as_ref().map(|k| k.key.clone())
    }

    pub fn get_current_key_guid(&self) -> Option<String> {
        self.key.as_ref().map(|k| k.guid.clone())
    }

    pub fn get_current_key_incarnation(&self) -> Option<u32> {
        self.key.as_ref().map(|k| k.incarnationId)?
    }
}
