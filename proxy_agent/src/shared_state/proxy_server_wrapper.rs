// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use crate::common::error::Error;
use crate::common::logger;
use crate::common::result::Result;
use crate::proxy::User;
use std::collections::HashMap;
use tokio::sync::{mpsc, oneshot};

enum ProxyServerAction {
    AddUser {
        user: User,
        response: oneshot::Sender<()>,
    },
    GetUser {
        user_id: u64,
        response: oneshot::Sender<Option<User>>,
    },
    GetUsersCount {
        response: oneshot::Sender<usize>,
    },
    ClearUsers {
        response: oneshot::Sender<()>,
    },
}

#[derive(Clone, Debug)]
pub struct ProxyServerSharedState(mpsc::Sender<ProxyServerAction>);

impl ProxyServerSharedState {
    pub fn start_new() -> Self {
        let (tx, mut rx) = mpsc::channel(100);
        tokio::spawn(async move {
            let mut users: HashMap<u64, User> = HashMap::new();
            while let Some(action) = rx.recv().await {
                match action {
                    ProxyServerAction::AddUser { user, response } => {
                        let id = user.logon_id;
                        users.insert(id, user);
                        if response.send(()).is_err() {
                            logger::write_warning(format!("Failed to send response to ProxyServerAction::AddUser with id '{}'", id));
                        }
                    }
                    ProxyServerAction::GetUser { user_id, response } => {
                        let user = users.get(&user_id).cloned();
                        if response.send(user).is_err() {
                            logger::write_warning(format!("Failed to send response to ProxyServerAction::GetUser with id '{}'", user_id));
                        }
                    }
                    ProxyServerAction::GetUsersCount { response } => {
                        if response.send(users.len()).is_err() {
                            logger::write_warning(
                                "Failed to send response to ProxyServerAction::GetUsersCount"
                                    .to_string(),
                            );
                        }
                    }
                    ProxyServerAction::ClearUsers { response } => {
                        users.clear();
                        if response.send(()).is_err() {
                            logger::write_warning(
                                "Failed to send response to ProxyServerAction::ClearUsers"
                                    .to_string(),
                            );
                        }
                    }
                }
            }
        });
        ProxyServerSharedState(tx)
    }

    pub async fn add_user(&self, user: User) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(ProxyServerAction::AddUser { user, response: tx })
            .await
            .map_err(|e| {
                Error::SendError("ProxyServerAction::AddUser".to_string(), e.to_string())
            })?;
        rx.await
            .map_err(|e| Error::RecvError("ProxyServerAction::AddUser".to_string(), e))
    }

    pub async fn get_user(&self, user_id: u64) -> Result<Option<User>> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(ProxyServerAction::GetUser { user_id, response: tx })
            .await
            .map_err(|e| {
                Error::SendError("ProxyServerAction::GetUser".to_string(), e.to_string())
            })?;
        rx.await
            .map_err(|e| Error::RecvError("ProxyServerAction::GetUser".to_string(), e))
    }

    #[cfg(test)]
    pub async fn get_users_count(&self) -> Result<usize> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(ProxyServerAction::GetUsersCount { response: tx })
            .await
            .map_err(|e| {
                Error::SendError("ProxyServerAction::GetUsersCount".to_string(), e.to_string())
            })?;
        rx.await
            .map_err(|e| Error::RecvError("ProxyServerAction::GetUsersCount".to_string(), e))
    }

    // TODO:: need caller to refresh the users info regularly
    pub async fn clear_users(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(ProxyServerAction::ClearUsers { response: tx })
            .await
            .map_err(|e| {
                Error::SendError("ProxyServerAction::ClearUsers".to_string(), e.to_string())
            })?;
        rx.await
            .map_err(|e| Error::RecvError("ProxyServerAction::ClearUsers".to_string(), e))
    }
}
