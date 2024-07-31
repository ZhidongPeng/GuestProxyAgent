// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use super::{constants, helpers};
use http::{HeaderName, HeaderValue};
use proxy_agent_shared::misc_helpers;
use serde::de::DeserializeOwned;
use std::collections::HashMap;

pub fn htons(u: u16) -> u16 {
    u.to_be()
}

pub fn ntohs(u: u16) -> u16 {
    u16::from_be(u)
}

pub async fn get<T>(
    url: &str,
    headers: &HashMap<String, String>,
    key_guid: Option<String>,
    key: Option<String>,
) -> std::io::Result<T>
where
    T: DeserializeOwned,
{
    let request = get_request("GET", url, headers, key_guid, key)?;
    let response = match request.send().await {
        Ok(r) => r,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to send request to {}: {}", url, e),
            ))
        }
    };
    let status = response.status();
    if !status.is_success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "Failed to get response from {}, status code: {}",
                url, status
            ),
        ));
    }
    let body = match response.text().await {
        Ok(b) => b,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to get response body from {}: {}", url, e),
            ))
        }
    };

    match serde_json::from_str(&body) {
        Ok(obj) => Ok(obj),
        Err(e) => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to deserialize the response: {}", e),
        )),
    }
}

pub fn get_request(
    method: &str,
    uri: &str,
    headers: &HashMap<String, String>,
    key_guid: Option<String>,
    key: Option<String>,
) -> std::io::Result<reqwest::RequestBuilder> {
    let uri = match url::Url::parse(uri) {
        Ok(u) => u,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to parse uri {}: {}", uri, e),
            ))
        }
    };
    let mut request = reqwest::Client::new().request(
        match reqwest::Method::from_bytes(method.as_bytes()) {
            Ok(m) => m,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to create method {}: {}", method, e),
                ))
            }
        },
        uri,
    );

    for (key, value) in headers {
        request = request.header(
            match HeaderName::from_bytes(key.as_bytes()) {
                Ok(h) => h,
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to create header name {}: {}", key, e),
                    ))
                }
            },
            match HeaderValue::from_str(value) {
                Ok(v) => v,
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to parse header value {}: {}", value, e),
                    ))
                }
            },
        );
    }

    request = request.header(
        constants::DATE_HEADER.to_string(),
        misc_helpers::get_date_time_rfc1123_string(),
    );
    request = request.header(
        constants::CLAIMS_HEADER.to_string(),
        format!("{{ \"{}\": \"{}\"}}", constants::CLAIMS_IS_ROOT, true,),
    );

    if let (Some(key), Some(key_guid)) = (key, key_guid) {
        //todo: input to sign
        let mut input_to_sign = key.to_string();
        input_to_sign.push_str(key_guid.as_str());
        let input_to_sign = input_to_sign.as_bytes();
        //TODO:

        let authorization_value = format!(
            "{} {} {}",
            constants::AUTHORIZATION_SCHEME,
            key_guid,
            helpers::compute_signature(key.to_string(), input_to_sign)?
        );
        request = request.header(
            constants::AUTHORIZATION_HEADER.to_string(),
            authorization_value.to_string(),
        );
    }

    Ok(request)
}
