// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::key_keeper::key::{AuthorizationItem, Identity, Privilege};
use proxy_agent_shared::misc_helpers;
use serde_derive::{Deserialize, Serialize};

use super::{proxy_connection::Connection, Claims};

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Rule {
    pub roleName: String,
    pub privileges: Vec<Privilege>,
    pub identities: Vec<Identity>,
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct AuthorizationRules {
    // The default access: allow -> true, deny-> false
    pub defaultAllowed: bool,
    // disabled, audit, enforce
    pub mode: String,
    pub rules: Option<Vec<Rule>>,
}

#[allow(dead_code)]
impl AuthorizationRules {
    pub fn new() -> AuthorizationRules {
        AuthorizationRules {
            defaultAllowed: false,
            mode: "disabled".to_string(),
            rules: None,
        }
    }

    pub fn from_authorization_item(authorization_item: AuthorizationItem) -> AuthorizationRules {
        let rules = match authorization_item.rules {
            Some(access_control_rules) => match access_control_rules.roleAssignments {
                Some(role_assignments) => {
                    let mut rules = Vec::new();
                    for role_assignment in role_assignments {
                        let role_name = role_assignment.role.to_string();

                        let mut privileges = Vec::new();
                        match &access_control_rules.privileges {
                            Some(input_privileges) => match &access_control_rules.roles {
                                Some(roles) => {
                                    for role in roles {
                                        if role.name == role_name {
                                            for privilege_name in &role.privileges {
                                                for privilege in input_privileges {
                                                    if privilege.name == privilege_name.to_string()
                                                    {
                                                        privileges.push(privilege.clone());
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                None => {}
                            },
                            None => {}
                        }

                        let mut identities = Vec::new();
                        match &access_control_rules.identities {
                            Some(input_identities) => {
                                for identity_name in role_assignment.identities {
                                    for identity in input_identities {
                                        if identity.name == identity_name {
                                            identities.push(identity.clone());
                                        }
                                    }
                                }
                            }
                            None => {}
                        }

                        rules.push(Rule {
                            roleName: role_name,
                            privileges: privileges,
                            identities: identities,
                        });
                    }
                    Some(rules)
                }
                None => None,
            },
            None => None,
        };

        AuthorizationRules {
            defaultAllowed: authorization_item.defaultAccess.to_lowercase() == "allow",
            mode: authorization_item.mode.to_string(),
            rules: rules,
        }
    }

    pub fn clone(&self) -> AuthorizationRules {
        match misc_helpers::json_clone(self) {
            Ok(rules) => rules,
            Err(_) => AuthorizationRules::new(),
        }
    }

    pub fn is_allowed(&self, connection_id: u128, request_url: String, claims: Claims) -> bool {
        if self.mode.to_lowercase() == "disabled" {
            return true;
        }

        let url = request_url.to_lowercase();
        let url = match url::Url::parse(&url) {
            Ok(u) => u,
            Err(_) => {
                Connection::write_error(
                    connection_id,
                    format!("Failed to parse the request url: {}", request_url),
                );
                return false;
            }
        };

        if self.mode.to_lowercase() == "enforce" {
            if let Some(rules) = &self.rules {
                let mut role_privilege_matched = false;
                for rule in rules {
                    // is privilege match
                    for privilege in &rule.privileges {
                        if privilege.is_match(connection_id, url.clone()) {
                            role_privilege_matched = true;
                            for identity in &rule.identities {
                                if identity.is_match(connection_id, claims.clone()) {
                                    return true;
                                }
                            }
                        }
                    }
                }

                if role_privilege_matched {
                    // all the privilege matched, but no identity matched, block the request
                    return false;
                }
            }
        }

        if self.mode.to_lowercase() == "audit" {
            return true;
        }
        // no privilege matched, fall back to default access
        self.defaultAllowed
    }
}

#[cfg(test)]
mod tests {
    use crate::key_keeper::key::{
        AccessControlRules, AuthorizationItem, Identity, Privilege, Role, RoleAssignment,
    };
    use crate::proxy::authorization_rules::AuthorizationRules;
    use crate::proxy::{proxy_connection::Connection, Claims};

    #[test]
    fn test_authorization_rules() {
        let logger_key = "test_authorization_rules";
        let mut temp_test_path = std::env::temp_dir();
        temp_test_path.push(logger_key);
        Connection::init_logger(temp_test_path.to_path_buf());

        // Test Enforce Mode
        let access_control_rules = AccessControlRules {
            roles: Some(vec![Role {
                name: "test".to_string(),
                privileges: vec!["test".to_string(), "test1".to_string()],
            }]),
            privileges: Some(vec![Privilege {
                name: "test".to_string(),
                path: "/test".to_string(),
                queryParameters: None,
            }]),
            identities: Some(vec![Identity {
                name: "test".to_string(),
                exePath: Some("test".to_string()),
                groupName: Some("test".to_string()),
                processName: Some("test".to_string()),
                userName: Some("test".to_string()),
            }]),
            roleAssignments: Some(vec![RoleAssignment {
                role: "test".to_string(),
                identities: vec!["test".to_string()],
            }]),
        };
        let authorization_item: AuthorizationItem = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "enforce".to_string(),
            rules: Some(access_control_rules),
            id: "0".to_string(),
        };
        let rules = AuthorizationRules::from_authorization_item(authorization_item);
        let _clone_rules = rules.clone();
        assert_eq!(rules.defaultAllowed, false);
        assert_eq!(rules.mode, "enforce");
        assert_eq!(rules.rules.is_some(), true);

        let mut claims = Claims {
            userId: 0,
            userName: "test".to_string(),
            userGroups: vec!["test".to_string()],
            processId: 0,
            processFullPath: "test".to_string(),
            clientIp: "0".to_string(),
            processName: "test".to_string(),
            processCmdLine: "test".to_string(),
            runAsElevated: true,
        };
        // assert the claim is allowed given the rules above
        let url = url::Url::parse("http://localhost/test?").unwrap();
        assert_eq!(rules.is_allowed(0, url.to_string(), claims.clone()), true);
        claims.userName = "test1".to_string();
        assert_eq!(rules.is_allowed(0, url.to_string(), claims.clone()), false);

        // Test Audit Mode
        let access_control_rules = AccessControlRules {
            roles: Some(vec![Role {
                name: "test".to_string(),
                privileges: vec!["test".to_string(), "test1".to_string()],
            }]),
            privileges: Some(vec![Privilege {
                name: "test".to_string(),
                path: "/test".to_string(),
                queryParameters: None,
            }]),
            identities: Some(vec![Identity {
                name: "test".to_string(),
                exePath: Some("test".to_string()),
                groupName: Some("test".to_string()),
                processName: Some("test".to_string()),
                userName: Some("test".to_string()),
            }]),
            roleAssignments: Some(vec![RoleAssignment {
                role: "test".to_string(),
                identities: vec!["test".to_string()],
            }]),
        };
        let authorization_item: AuthorizationItem = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "audit".to_string(),
            rules: Some(access_control_rules),
            id: "0".to_string(),
        };
        let rules = AuthorizationRules::from_authorization_item(authorization_item);
        assert_eq!(rules.defaultAllowed, false);
        assert_eq!(rules.mode, "audit");
        assert_eq!(rules.rules.is_some(), true);

        let url = url::Url::parse("http://localhost/test?").unwrap();
        assert_eq!(rules.is_allowed(0, url.to_string(), claims.clone()), true);
        claims.userName = "test1".to_string();
        assert_eq!(rules.is_allowed(0, url.to_string(), claims.clone()), true);

        // Test Disabled Mode
        let access_control_rules = AccessControlRules {
            roles: Some(vec![Role {
                name: "test".to_string(),
                privileges: vec!["test".to_string(), "test1".to_string()],
            }]),
            privileges: Some(vec![Privilege {
                name: "test".to_string(),
                path: "/test".to_string(),
                queryParameters: None,
            }]),
            identities: Some(vec![Identity {
                name: "test".to_string(),
                exePath: Some("test".to_string()),
                groupName: Some("test".to_string()),
                processName: Some("test".to_string()),
                userName: Some("test".to_string()),
            }]),
            roleAssignments: Some(vec![RoleAssignment {
                role: "test".to_string(),
                identities: vec!["test".to_string()],
            }]),
        };
        let authorization_item: AuthorizationItem = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "disabled".to_string(),
            rules: Some(access_control_rules),
            id: "0".to_string(),
        };
        let rules = AuthorizationRules::from_authorization_item(authorization_item);
        assert_eq!(rules.defaultAllowed, false);
        assert_eq!(rules.mode, "disabled");
        assert_eq!(rules.rules.is_some(), true);

        let url = url::Url::parse("http://localhost/test?").unwrap();
        assert_eq!(rules.is_allowed(0, url.to_string(), claims.clone()), true);

        // Test enforce mode, identity not match
        let access_control_rules = AccessControlRules {
            roles: Some(vec![Role {
                name: "test".to_string(),
                privileges: vec!["test".to_string(), "test1".to_string()],
            }]),
            privileges: Some(vec![Privilege {
                name: "test".to_string(),
                path: "/test".to_string(),
                queryParameters: None,
            }]),
            identities: Some(vec![Identity {
                name: "test1".to_string(),
                exePath: Some("test".to_string()),
                groupName: Some("test".to_string()),
                processName: Some("test".to_string()),
                userName: Some("test".to_string()),
            }]),
            roleAssignments: Some(vec![RoleAssignment {
                role: "test".to_string(),
                identities: vec!["test1".to_string()],
            }]),
        };
        let authorization_item: AuthorizationItem = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "enforce".to_string(),
            rules: Some(access_control_rules),
            id: "0".to_string(),
        };
        let rules = AuthorizationRules::from_authorization_item(authorization_item);
        assert_eq!(rules.defaultAllowed, false);
        assert_eq!(rules.mode, "enforce");
        assert_eq!(rules.rules.is_some(), true);

        let url = url::Url::parse("http://localhost/test?").unwrap();
        assert_eq!(rules.is_allowed(0, url.to_string(), claims.clone()), false);
    }
}