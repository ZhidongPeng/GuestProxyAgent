// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common::constants;
use http::request::Parts;
use hyper::body::Bytes;
use itertools::Itertools;
use reqwest::Request;
use std::collections::HashMap;
use url::Url;
