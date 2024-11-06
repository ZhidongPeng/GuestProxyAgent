// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to authorize the connection based on the claims.
//! The claims are used to determine if the process is allowed to connect to the remote server.
//!
//! Example
//! ```rust
//! use proxy_agent::proxy_authorizer;
//! use proxy_agent::proxy::Claims;
//! use proxy_agent::shared_state::SharedState;
//! use std::sync::{Arc, Mutex};
//!
//! let shared_state = SharedState::new();
//!
//! let authorize = proxy_authorizer::get_authorizer(constants::WIRE_SERVER_IP, constants::WIRE_SERVER_PORT, claims);
//! let url = hyper::Uri::from_str("http://localhost/test?").unwrap();
//! authorize.authorize(1, url, shared_state.clone());
//!  

use super::authorization_rules::{AuthorizationMode, ComputedAuthorizationItem};
use super::proxy_connection::Connection;
use super::proxy_summary::ProxySummary;
use crate::key_keeper::key::AuthorizationItem;
use crate::shared_state::agent_status_wrapper::AgentStatusSharedState;
use crate::shared_state::key_keeper_wrapper::KeyKeeperSharedState;
use crate::{common::config, common::constants, common::result::Result, proxy::Claims};
use async_trait::async_trait;
use http::StatusCode;

#[cfg(windows)]
mod default {
    use crate::proxy::Claims;
    use proxy_agent_shared::misc_helpers;
    use std::path::PathBuf;

    const VM_APPLICATION_MANAGER_FILE_NAME: &str = "vm-application-manager";
    const WINDOWS_AZURE_GUEST_AGENT_FILE_NAME: &str = "windowsazureguestagent.exe";
    const WAAPPAGENT_FILE_NAME: &str = "waappagent.exe";
    const COLLECT_GUEST_LOG_FILE_NAME: &str = "collectguestlogs.exe";
    const SEC_AGENT_FILE_NAME: &str = "wasecagentprov.exe";
    const IMMEDIATE_RUNCOMMAND_SERVICE_FILE_NAME: &str = "immediateruncommandservice.exe";

    pub fn is_platform_process(claims: &Claims) -> bool {
        let process_name =
            misc_helpers::get_file_name(&PathBuf::from(&claims.processName)).to_lowercase();
        if process_name == VM_APPLICATION_MANAGER_FILE_NAME
            || process_name == WINDOWS_AZURE_GUEST_AGENT_FILE_NAME
            || process_name == WAAPPAGENT_FILE_NAME
            || process_name == COLLECT_GUEST_LOG_FILE_NAME
            || process_name == SEC_AGENT_FILE_NAME
            || process_name == IMMEDIATE_RUNCOMMAND_SERVICE_FILE_NAME
        {
            return true;
        }

        false
    }
}

#[cfg(not(windows))]
mod default {
    use crate::proxy::Claims;
    use once_cell::sync::Lazy;
    use proxy_agent_shared::misc_helpers;
    use regex::Regex;
    use std::path::PathBuf;

    const VM_APPLICATION_MANAGER_FILE_NAME: &str = "vm-application-manager";
    const IMMEDIATE_RUNCOMMAND_SERVICE_FILE_NAME: &str = "immediate-run-command-handler";
    static LINUX_VM_AGENT_REGEX: Lazy<Regex> =
        Lazy::new(|| Regex::new(r".*python.*walinuxagent").unwrap());

    pub fn is_platform_process(claims: &Claims) -> bool {
        let process_name =
            misc_helpers::get_file_name(&PathBuf::from(&claims.processName)).to_lowercase();
        if process_name == VM_APPLICATION_MANAGER_FILE_NAME
            || process_name == IMMEDIATE_RUNCOMMAND_SERVICE_FILE_NAME
        {
            return true;
        }

        let process_cmd_line = claims.processCmdLine.to_string().to_lowercase();
        if LINUX_VM_AGENT_REGEX.is_match(&process_cmd_line) {
            return true;
        }

        false
    }
}

#[async_trait]
pub trait Authorizer {
    // authorize the connection
    async fn authorize(
        &self,
        connection_id: u128,
        request_url: hyper::Uri,
        key_keeper_shared_state: KeyKeeperSharedState,
        agent_status_shred_state: AgentStatusSharedState,
    ) -> Result<bool>;
    fn to_string(&self) -> String;
}

struct WireServer {
    claims: Claims,
}
#[async_trait]
impl Authorizer for WireServer {
    async fn authorize(
        &self,
        connection_id: u128,
        request_url: hyper::Uri,
        key_keeper_shared_state: KeyKeeperSharedState,
        agent_status_shred_state: AgentStatusSharedState,
    ) -> Result<bool> {
        if !self.claims.runAsElevated {
            return Ok(false);
        }

        if config::get_wire_server_support() == 2 {
            let wireserver_rules = key_keeper_shared_state.get_wireserver_rules().await?;
            if let Some(rules) = wireserver_rules {
                let allowed =
                    rules.is_allowed(connection_id, request_url.clone(), self.claims.clone());
                if !allowed {
                    let summary = ProxySummary {
                        id: connection_id,
                        userId: self.claims.userId,
                        userName: self.claims.userName.to_string(),
                        userGroups: self.claims.userGroups.clone(),
                        clientIp: self.claims.clientIp.to_string(),
                        processFullPath: self.claims.processFullPath.to_string(),
                        processCmdLine: self.claims.processCmdLine.to_string(),
                        runAsElevated: self.claims.runAsElevated,
                        method: String::new(),
                        url: request_url.to_string(),
                        ip: constants::WIRE_SERVER_IP.to_string(),
                        port: constants::WIRE_SERVER_PORT,
                        responseStatus: StatusCode::FORBIDDEN.to_string(),
                        elapsedTime: 0,
                    };
                    agent_status_shred_state
                        .add_one_failed_connection_summary(summary)
                        .await;

                    if rules.mode == AuthorizationMode::Audit {
                        Connection::write_information(connection_id, format!("WireServer request {} denied in audit mode, continue forward the request", request_url));
                        return Ok(true);
                    }
                }
                return Ok(allowed);
            }
        }

        Ok(true)
    }

    fn to_string(&self) -> String {
        format!(
            "WireServer {{ runAsElevated: {}, processName: {} }}",
            self.claims.runAsElevated, self.claims.processName
        )
    }
}

struct Imds {
    #[allow(dead_code)]
    claims: Claims,
}
#[async_trait]
impl Authorizer for Imds {
    async fn authorize(
        &self,
        connection_id: u128,
        request_url: hyper::Uri,
        key_keeper_shared_state: KeyKeeperSharedState,
        agent_status_shred_state: AgentStatusSharedState,
    ) -> Result<bool> {
        if config::get_imds_support() == 2 {
            let imds_rules = key_keeper_shared_state.get_imds_rules().await?;
            if let Some(rules) = imds_rules {
                let allowed =
                    rules.is_allowed(connection_id, request_url.clone(), self.claims.clone());

                if !allowed {
                    let summary = ProxySummary {
                        id: connection_id,
                        userId: self.claims.userId,
                        userName: self.claims.userName.to_string(),
                        userGroups: self.claims.userGroups.clone(),
                        clientIp: self.claims.clientIp.to_string(),
                        processFullPath: self.claims.processFullPath.to_string(),
                        processCmdLine: self.claims.processCmdLine.to_string(),
                        runAsElevated: self.claims.runAsElevated,
                        method: String::new(),
                        url: request_url.to_string(),
                        ip: constants::IMDS_IP.to_string(),
                        port: constants::IMDS_PORT,
                        responseStatus: StatusCode::FORBIDDEN.to_string(),
                        elapsedTime: 0,
                    };
                    agent_status_shred_state
                        .add_one_failed_connection_summary(summary)
                        .await;

                    if rules.mode == AuthorizationMode::Audit {
                        Connection::write_information(connection_id, format!("IMDS request {} denied in audit mode, continue forward the request", request_url));
                        return Ok(true);
                    }
                }
                return Ok(allowed);
            }
        }

        Ok(true)
    }

    fn to_string(&self) -> String {
        "IMDS".to_string()
    }
}

struct GAPlugin {
    claims: Claims,
}

#[async_trait]
impl Authorizer for GAPlugin {
    async fn authorize(
        &self,
        _connection_id: u128,
        _request_url: hyper::Uri,
        _key_keeper_shared_state: KeyKeeperSharedState,
        _agent_status_shred_state: AgentStatusSharedState,
    ) -> Result<bool> {
        if !self.claims.runAsElevated {
            return Ok(false);
        }
        if config::get_host_gaplugin_support() == 2 {
            // only allow VMAgent and VMApp extension talks to GAPlugin
            return Ok(default::is_platform_process(&self.claims));
        }

        Ok(true)
    }

    fn to_string(&self) -> String {
        format!(
            "GAPlugin {{ runAsElevated: {}, processName: {} }}",
            self.claims.runAsElevated, self.claims.processName
        )
    }
}

struct ProxyAgent {}
#[async_trait]
impl Authorizer for ProxyAgent {
    async fn authorize(
        &self,
        _connection_id: u128,
        _request_url: hyper::Uri,
        _key_keeper_shared_state: KeyKeeperSharedState,
        _agent_status_shred_state: AgentStatusSharedState,
    ) -> Result<bool> {
        // Forbid the request send to this listener directly
        Ok(false)
    }

    fn to_string(&self) -> String {
        "ProxyAgent".to_string()
    }
}

struct Default {}
#[async_trait]
impl Authorizer for Default {
    async fn authorize(
        &self,
        _connection_id: u128,
        _request_url: hyper::Uri,
        _key_keeper_shared_state: KeyKeeperSharedState,
        _agent_status_shred_state: AgentStatusSharedState,
    ) -> Result<bool> {
        Ok(true)
    }

    fn to_string(&self) -> String {
        "Default".to_string()
    }
}

pub fn get_authorizer(ip: String, port: u16, claims: Claims) -> Box<dyn Authorizer> {
    if ip == constants::WIRE_SERVER_IP && port == constants::WIRE_SERVER_PORT {
        Box::new(WireServer { claims })
    } else if ip == constants::GA_PLUGIN_IP && port == constants::GA_PLUGIN_PORT {
        return Box::new(GAPlugin { claims });
    } else if ip == constants::IMDS_IP && port == constants::IMDS_PORT {
        return Box::new(Imds { claims });
    } else if ip == constants::PROXY_AGENT_IP && port == constants::PROXY_AGENT_PORT {
        return Box::new(ProxyAgent {});
    } else {
        Box::new(Default {})
    }
}

pub async fn authorize(
    ip: String,
    port: u16,
    connection_id: u128,
    request_uri: hyper::Uri,
    claims: Claims,
    key_keeper_shared_state: KeyKeeperSharedState,
    agent_status_shred_state: AgentStatusSharedState,
) -> Result<bool> {
    let auth = get_authorizer(ip, port, claims);
    Connection::write(connection_id, format!("Got auth: {}", auth.to_string()));
    auth.authorize(
        connection_id,
        request_uri,
        key_keeper_shared_state,
        agent_status_shred_state,
    )
    .await
}

#[cfg(test)]
mod tests {
    use crate::{
        key_keeper::key::{self, AuthorizationItem},
        shared_state::{
            self, agent_status_wrapper::AgentStatusSharedState,
            key_keeper_wrapper::KeyKeeperSharedState,
        },
    };
    use std::str::FromStr;

    #[tokio::test]
    async fn get_authenticate_test() {
        let claims = crate::proxy::Claims {
            userId: 0,
            userName: "test".to_string(),
            userGroups: vec!["test".to_string()],
            processId: std::process::id(),
            processName: "test".to_string(),
            processFullPath: "test".to_string(),
            processCmdLine: "test".to_string(),
            runAsElevated: true,
            clientIp: "127.0.0.1".to_string(),
        };
        let key_keeper_shared_state = KeyKeeperSharedState::start_new();
        let agent_status_shared_state = AgentStatusSharedState::start_new();
        let auth: Box<dyn super::Authorizer> = super::get_authorizer(
            crate::common::constants::WIRE_SERVER_IP.to_string(),
            crate::common::constants::WIRE_SERVER_PORT,
            claims.clone(),
        );
        let test_uri = hyper::Uri::from_str("test").unwrap();
        assert_eq!(
            auth.to_string(),
            "WireServer { runAsElevated: true, processName: test }"
        );
        assert!(
            auth.authorize(
                1,
                test_uri.clone(),
                key_keeper_shared_state.clone(),
                agent_status_shared_state.clone()
            )
            .await
            .unwrap(),
            "WireServer authentication must be true"
        );

        let auth = super::get_authorizer(
            crate::common::constants::GA_PLUGIN_IP.to_string(),
            crate::common::constants::GA_PLUGIN_PORT,
            claims.clone(),
        );
        assert_eq!(
            auth.to_string(),
            "GAPlugin { runAsElevated: true, processName: test }"
        );
        assert!(
            auth.authorize(
                1,
                test_uri.clone(),
                key_keeper_shared_state.clone(),
                agent_status_shared_state.clone()
            )
            .await
            .unwrap(),            "GAPlugin authentication must be true since it has not enabled for builtin processes in the config yet"
        );

        let auth = super::get_authorizer(
            crate::common::constants::IMDS_IP.to_string(),
            crate::common::constants::IMDS_PORT,
            claims.clone(),
        );
        assert_eq!(auth.to_string(), "IMDS");
        assert!(
            auth.authorize(
                1,
                test_uri.clone(),
                key_keeper_shared_state.clone(),
                agent_status_shared_state.clone()
            )
            .await
            .unwrap(),
            "IMDS authentication must be true"
        );

        let auth = super::get_authorizer(
            crate::common::constants::PROXY_AGENT_IP.to_string(),
            crate::common::constants::PROXY_AGENT_PORT,
            claims.clone(),
        );
        assert_eq!(auth.to_string(), "ProxyAgent");
        assert!(
            !auth
                .authorize(
                    1,
                    test_uri.clone(),
                    key_keeper_shared_state.clone(),
                    agent_status_shared_state.clone()
                )
                .await
                .unwrap(),
            "ProxyAgent authentication must be false"
        );

        let auth = super::get_authorizer(
            crate::common::constants::PROXY_AGENT_IP.to_string(),
            crate::common::constants::PROXY_AGENT_PORT + 1,
            claims.clone(),
        );
        assert_eq!(auth.to_string(), "Default");
    }

    #[tokio::test]
    async fn wireserver_authenticate_test() {
        let claims = crate::proxy::Claims {
            userId: 0,
            userName: "test".to_string(),
            userGroups: vec!["test".to_string()],
            processId: std::process::id(),
            processName: "test".to_string(),
            processFullPath: "test".to_string(),
            processCmdLine: "test".to_string(),
            runAsElevated: true,
            clientIp: "127.0.0.1".to_string(),
        };
        let auth = super::get_authorizer(
            crate::common::constants::WIRE_SERVER_IP.to_string(),
            crate::common::constants::WIRE_SERVER_PORT,
            claims.clone(),
        );
        let url = hyper::Uri::from_str("http://localhost/test?").unwrap();
        let key_keeper_shared_state = KeyKeeperSharedState::start_new();
        let agent_status_shared_state = AgentStatusSharedState::start_new();

        // validate disabled rules
        let disabled_rules = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "disabled".to_string(),
            id: "id".to_string(),
            rules: None,
        };
        key_keeper_shared_state
            .set_wireserver_rules(Some(disabled_rules))
            .await
            .unwrap();
        assert!(
            auth.authorize(
                1,
                url.clone(),
                key_keeper_shared_state.clone(),
                agent_status_shared_state.clone()
            )
            .await
            .unwrap(),
            "WireServer authentication must be true with disabled rules"
        );

        // validate audit rules
        let audit_deny_rules = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "audit".to_string(),
            id: "id".to_string(),
            rules: None,
        };
        let audit_allow_rules = AuthorizationItem {
            defaultAccess: "allow".to_string(),
            mode: "audit".to_string(),
            id: "id".to_string(),
            rules: None,
        };
        key_keeper_shared_state
            .set_wireserver_rules(Some(audit_allow_rules))
            .await
            .unwrap();
        assert!(
            auth.authorize(
                1,
                url.clone(),
                key_keeper_shared_state.clone(),
                agent_status_shared_state.clone()
            )
            .await
            .unwrap(),
            "WireServer authentication must be true with audit allow rules"
        );
        key_keeper_shared_state
            .set_wireserver_rules(Some(audit_deny_rules))
            .await
            .unwrap();
        assert!(
            auth.authorize(
                1,
                url.clone(),
                key_keeper_shared_state.clone(),
                agent_status_shared_state.clone()
            )
            .await
            .unwrap(),
            "WireServer authentication must be true with audit deny rules"
        );

        // validate enforce rules
        let enforce_allow_rules = AuthorizationItem {
            defaultAccess: "allow".to_string(),
            mode: "enforce".to_string(),
            id: "id".to_string(),
            rules: None,
        };
        let enforce_deny_rules = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "enforce".to_string(),
            id: "id".to_string(),
            rules: None,
        };
        key_keeper_shared_state
            .set_wireserver_rules(Some(enforce_allow_rules))
            .await
            .unwrap();
        assert!(
            auth.authorize(
                1,
                url.clone(),
                key_keeper_shared_state.clone(),
                agent_status_shared_state.clone()
            )
            .await
            .unwrap(),
            "WireServer authentication must be true with enforce allow rules"
        );
        key_keeper_shared_state
            .set_wireserver_rules(Some(enforce_deny_rules))
            .await
            .unwrap();
        assert!(
            !auth
                .authorize(
                    1,
                    url.clone(),
                    key_keeper_shared_state.clone(),
                    agent_status_shared_state.clone()
                )
                .await
                .unwrap(),
            "WireServer authentication must be false with enforce deny rules"
        );
    }

    #[tokio::test]
    async fn imds_authenticate_test() {
        let claims = crate::proxy::Claims {
            userId: 0,
            userName: "test".to_string(),
            userGroups: vec!["test".to_string()],
            processId: std::process::id(),
            processName: "test".to_string(),
            processFullPath: "test".to_string(),
            processCmdLine: "test".to_string(),
            runAsElevated: true,
            clientIp: "127.0.0.1".to_string(),
        };
        let auth = super::get_authorizer(
            crate::common::constants::IMDS_IP.to_string(),
            crate::common::constants::IMDS_PORT,
            claims.clone(),
        );
        let url = hyper::Uri::from_str("http://localhost/test?").unwrap();
        let key_keeper_shared_state = KeyKeeperSharedState::start_new();
        let agent_status_shared_state = AgentStatusSharedState::start_new();

        // validate disabled rules
        let disabled_rules = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "disabled".to_string(),
            id: "id".to_string(),
            rules: None,
        };
        key_keeper_shared_state
            .set_imds_rules(Some(disabled_rules))
            .await
            .unwrap();
        assert!(
            !auth
                .authorize(
                    1,
                    url.clone(),
                    key_keeper_shared_state.clone(),
                    agent_status_shared_state.clone()
                )
                .await
                .unwrap(),
            "IMDS authentication must be true with disabled rules"
        );

        // validate audit rules
        let audit_deny_rules = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "audit".to_string(),
            id: "id".to_string(),
            rules: None,
        };
        let audit_allow_rules = AuthorizationItem {
            defaultAccess: "allow".to_string(),
            mode: "audit".to_string(),
            id: "id".to_string(),
            rules: None,
        };
        super::set_imds_rules(shared_state.clone(), Some(audit_allow_rules));
        assert!(
            auth.authorize(1, url.clone(), shared_state.clone()),
            "IMDS authentication must be true with audit allow rules"
        );
        super::set_imds_rules(shared_state.clone(), Some(audit_deny_rules));
        assert!(
            auth.authorize(1, url.clone(), shared_state.clone()),
            "IMDS authentication must be true with audit deny rules"
        );

        // validate enforce rules
        let enforce_allow_rules = AuthorizationItem {
            defaultAccess: "allow".to_string(),
            mode: "enforce".to_string(),
            id: "id".to_string(),
            rules: None,
        };
        let enforce_deny_rules = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "enforce".to_string(),
            id: "id".to_string(),
            rules: None,
        };
        super::set_imds_rules(shared_state.clone(), Some(enforce_allow_rules));
        assert!(
            auth.authorize(1, url.clone(), shared_state.clone()),
            "IMDS authentication must be true with enforce allow rules"
        );
        super::set_imds_rules(shared_state.clone(), Some(enforce_deny_rules));
        assert!(
            !auth.authorize(1, url.clone(), shared_state.clone()),
            "IMDS authentication must be false with enforce deny rules"
        );
    }

    #[test]
    fn is_platform_process_test() {
        let mut claims = crate::proxy::Claims {
            userId: 0,
            userName: "test".to_string(),
            userGroups: vec!["test".to_string()],
            processId: std::process::id(),
            processName: "test".to_string(),
            processFullPath: "test".to_string(),
            processCmdLine: "test".to_string(),
            runAsElevated: true,
            clientIp: "127.0.0.1".to_string(),
        };

        #[cfg(windows)]
        {
            let windows_process_names = [
                "vm-application-manager",
                "windowsazureguestagent.exe",
                "waappagent.exe",
                "immediateruncommandservice.exe",
            ];
            for process in windows_process_names.iter() {
                claims.processName = process.to_string();
                assert!(
                    super::default::is_platform_process(&claims),
                    "{process} should be built-in process"
                );
            }
        }

        #[cfg(not(windows))]
        {
            let linux_process_names = ["vm-application-manager", "immediate-run-command-handler"];
            for process in linux_process_names.iter() {
                claims.processName = process.to_string();
                assert!(
                    super::default::is_platform_process(&claims),
                    "{process} should be built-in process"
                );
            }

            let linux_process_cmds =
                ["python3 -u bin/WALinuxAgent-2.9.1.1-py3.8.egg -run-exthandlers"];
            for process_cmd in linux_process_cmds.iter() {
                claims.processCmdLine = process_cmd.to_string();
                assert!(
                    super::default::is_platform_process(&claims),
                    "{process_cmd} should be built-in process"
                );
            }
        }
    }
}
