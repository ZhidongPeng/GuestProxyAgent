// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common::constants;
use http::request::Parts;
use hyper::body::Bytes;
use itertools::Itertools;
use std::collections::HashMap;
use url::Url;

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
