// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use super::{constants, helpers};
use crate::common::constants;
use http::request::Parts;
use http::{HeaderName, HeaderValue};
use hyper::body::Bytes;
use itertools::Itertools;
use proxy_agent_shared::misc_helpers;
use reqwest::Request;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::{clone, collections::HashMap};
use url::Url;

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
    let request = get_request("GET", url, headers, None, key_guid, key)?;
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
    body: Option<Vec<u8>>,
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
        uri.clone(),
    );

    let content_length = match body {
        Some(b) => {
            let content_length = b.len();
            request = request.body(b);
            content_length
        }
        None => 0,
    };

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
    request = request.header(
        "Host",
        match uri.host_str() {
            Some(h) => h,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to get host from uri {}", uri),
                ))
            }
        },
    );
    request = request.header("Content-Length", content_length.to_string());

    if let (Some(key), Some(key_guid)) = (key, key_guid) {
        let cloned_request = match request.try_clone() {
            Some(r) => r.build(),
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to clone request",
                ))
            }
        };
        let cloned_request = match cloned_request {
            Ok(r) => r,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to build cloned request: {}", e),
                ))
            }
        };

        let input_to_sign = request_to_sign_input(cloned_request);
        let authorization_value = format!(
            "{} {} {}",
            constants::AUTHORIZATION_SCHEME,
            key_guid,
            helpers::compute_signature(key.to_string(), input_to_sign.as_slice())?
        );
        request = request.header(
            constants::AUTHORIZATION_HEADER.to_string(),
            authorization_value.to_string(),
        );
    }

    Ok(request)
}

/*
    StringToSign = Method + "\n" +
           HexEncoded(Body) + "\n" +
           CanonicalizedHeaders + "\n"
           UrlEncodedPath + "\n"
           CanonicalizedParameters;
*/
pub fn as_sig_input(head: Parts, body: Bytes) -> Vec<u8> {
    let mut data: Vec<u8> = head.method.to_string().as_bytes().to_vec();
    data.extend(constants::LF.as_bytes());
    data.extend(body);
    data.extend(constants::LF.as_bytes());

    data.extend(headers_to_canonicalized_string(&head.headers).as_bytes());
    let path_para = get_path_and_canonicalized_parameters(&head.uri);
    data.extend(path_para.0.as_bytes());
    data.extend(constants::LF.as_bytes());
    data.extend(path_para.1.as_bytes());

    data
}

pub fn request_to_sign_input(request: Request) -> Vec<u8> {
    let mut data: Vec<u8> = request.method().as_str().as_bytes().to_vec();
    data.extend(constants::LF.as_bytes());
    match request.body() {
        Some(body) => {
            let body = match body.as_bytes() {
                Some(b) => b,
                None => {
                    return Vec::new();
                }
            };
            data.extend(body);
        }
        None => {}
    }
    data.extend(constants::LF.as_bytes());

    data.extend(headers_to_canonicalized_string(request.headers()).as_bytes());
    let path_para = get_path_and_canonicalized_parameters(request.uri());
    data.extend(path_para.0.as_bytes());
    data.extend(constants::LF.as_bytes());
    data.extend(path_para.1.as_bytes());

    data
}

fn headers_to_canonicalized_string(headers: &hyper::HeaderMap) -> String {
    let mut canonicalized_headers = String::new();
    let separator = String::from(constants::LF);
    let mut map: HashMap<String, (String, String)> = HashMap::new();

    for (key, value) in headers.iter() {
        let key = key.to_string();
        let value = value.to_str().unwrap().to_string();
        let key_lower_case = key.to_lowercase();
        map.insert(key_lower_case, (key, value));
    }

    for key in map.keys().sorted() {
        // skip the expect header
        if key.eq_ignore_ascii_case(constants::AUTHORIZATION_HEADER) {
            continue;
        }
        let h = format!("{}:{}{}", key, map[key].1.trim(), separator);
        canonicalized_headers.push_str(&h);
    }

    canonicalized_headers
}

fn get_path_and_canonicalized_parameters(uri: &hyper::Uri) -> (String, String) {
    let path = uri.path().to_string();

    let path_query = uri.path_and_query().unwrap().as_str();
    // Url crate does not support parsing relative paths, so we need to add a dummy base url
    let mut url = Url::parse("http://127.0.0.1").unwrap();
    match url.join(path_query) {
        Ok(u) => url = u,
        Err(_) => return (path, "".to_string()),
    }

    let parameters = url.query_pairs();
    let mut pairs: HashMap<String, String> = HashMap::new();
    let mut canonicalized_parameters = String::new();
    if parameters.count() > 0 {
        for p in parameters {
            // Convert the parameter name to lowercase
            pairs.insert(p.0.to_lowercase(), p.1.to_string());
        }

        // Sort the parameters lexicographically by parameter name, in ascending order.
        let mut first = true;
        for key in pairs.keys().sorted() {
            if !first {
                canonicalized_parameters.push('&');
            }
            first = false;
            // Join each parameter key value pair with '='
            let p = format!("{}={}", key, pairs[key]);
            canonicalized_parameters.push_str(&p);
        }
    }

    (path, canonicalized_parameters)
}
