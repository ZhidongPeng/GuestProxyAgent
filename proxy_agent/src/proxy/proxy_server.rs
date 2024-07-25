// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common::{config, constants, helpers, http, logger};
use crate::proxy::proxy_connection::{Connection, ConnectionContext};
use crate::proxy::{proxy_authentication, proxy_extensions, proxy_summary::ProxySummary, Claims};
use crate::shared_state::{
    agent_status_wrapper, key_keeper_wrapper, proxy_listener_wrapper, SharedState,
};
use crate::{provision, redirector};
use http_body_util::Full;
use http_body_util::{combinators::BoxBody, BodyExt, Empty};
use hyper::body::{Bytes, Frame};
use hyper::header::{HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::StatusCode;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use proxy_agent_shared::misc_helpers;
use proxy_agent_shared::telemetry::event_logger;
use std::os::windows::io::AsRawSocket;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::net::TcpStream;

pub fn start_async(port: u16, shared_state: Arc<Mutex<SharedState>>) {
    _ = std::thread::Builder::new()
        .name("proxy_listener".to_string())
        .spawn(move || {
            let _ = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move { tokio::spawn(start(port, shared_state)).await });
        });
}

pub fn stop(port: u16, shared_state: Arc<Mutex<SharedState>>) {
    proxy_listener_wrapper::set_shutdown(shared_state.clone(), true);
    let _ = std::net::TcpStream::connect(format!("127.0.0.1:{}", port));
    logger::write_warning("Sending stop signal.".to_string());

    // TODO: set cancellationtoken to the listener
    // TODO: wait for the listener async tasks to stop
}

async fn start(
    port: u16,
    shared_state: Arc<Mutex<SharedState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    Connection::init_logger(config::get_logs_dir());

    let addr = format!("{}:{}", std::net::Ipv4Addr::LOCALHOST, port);
    logger::write(format!("Start proxy listener at '{}'.", &addr));

    let listener = match TcpListener::bind(&addr).await {
        Ok(listener) => listener,
        Err(e) => {
            let message = format!("Failed to bind TcpListener '{}' with error {}.", addr, e);
            proxy_listener_wrapper::set_status_message(shared_state.clone(), message.to_string());
            logger::write_error(message);
            return Err(Box::new(e));
        }
    };

    let message = helpers::write_startup_event(
        "Started proxy listener, ready to accept request",
        "start",
        "proxy_listener",
        logger::AGENT_LOGGER_KEY,
    );
    proxy_listener_wrapper::set_status_message(shared_state.clone(), message.to_string());
    provision::listener_started(shared_state.clone());

    // TODO: Create cancellation token

    // We start a loop to continuously accept incoming connections
    loop {
        let (stream, client_addr) = match listener.accept().await {
            Ok((stream, client_addr)) => (stream, client_addr),
            Err(e) => {
                logger::write_warning(format!("ProxyListener accept error {}", e));
                continue;
            }
        };

        if proxy_listener_wrapper::get_shutdown(shared_state.clone()) {
            let message = "Stop signal received, stop the listener.";
            proxy_listener_wrapper::set_status_message(shared_state.clone(), message.to_string());
            logger::write_warning(message.to_string());
            return Ok(());
        }

        // Increase the connection count
        let connection_id = proxy_listener_wrapper::increase_connection_count(shared_state.clone());
        Connection::write(connection_id, "Accepted new connection.".to_string());
        let shared_state = shared_state.clone();
        tokio::spawn(async move {
            // Convert the stream to a std stream
            let std_stream = match stream.into_std() {
                Ok(std_stream) => std_stream,
                Err(e) => {
                    Connection::write_warning(
                        connection_id,
                        format!("ProxyListener stream error {}", e),
                    );
                    return;
                }
            };
            // Set the read timeout
            _ = std_stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));

            // Clone the stream for the service_fn
            let cloned_std_stream = match std_stream.try_clone() {
                Ok(cloned_stream) => cloned_stream,
                Err(e) => {
                    Connection::write_warning(
                        connection_id,
                        format!("ProxyListener stream clone error {}", e),
                    );
                    return;
                }
            };

            // Convert the std stream back to a tokio stream
            let stream = match TcpStream::from_std(std_stream) {
                Ok(stream) => stream,
                Err(e) => {
                    Connection::write_warning(
                        connection_id,
                        format!("ProxyListener: TcpStream::from_std error {}", e),
                    );
                    return;
                }
            };

            let cloned_std_stream = Arc::new(Mutex::new(cloned_std_stream));
            // move client addr, cloned std stream and shared_state to the service_fn
            let service = service_fn(move |req| {
                let shared_state = shared_state.clone();
                let connection = ConnectionContext {
                    stream: cloned_std_stream.clone(),
                    client_addr,
                    id: connection_id,
                    now: std::time::Instant::now(),
                    method: String::new(),
                    url: String::new(),
                    ip: String::new(),
                    port: 0,
                    claims: None,
                };

                // TODO: pass cancellation token
                handle_request(req, connection, shared_state)
            });

            // Use an adapter to access something implementing `tokio::io` traits as if they implement
            let io = TokioIo::new(stream);
            // We use the `hyper::server::conn::Http` to serve the connection
            let http = hyper::server::conn::http1::Builder::new();
            if let Err(e) = http.serve_connection(io, service).await {
                Connection::write_warning(
                    connection_id,
                    format!("ProxyListener serve_connection error: {}", e),
                );
            }
        });
    }
}

async fn handle_request(
    request: Request<hyper::body::Incoming>,
    mut connection: ConnectionContext,
    shared_state: Arc<Mutex<SharedState>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let connection_id = connection.id;
    connection.method = request.method().to_string();
    connection.url = request.uri().to_string();
    Connection::write_warning(
        connection_id,
        format!(
            "Got request from {} for {} {}",
            connection.client_addr, &connection.method, &connection.url
        ),
    );

    let client_source_ip = connection.client_addr.ip();
    let client_source_port = connection.client_addr.port();

    let entry;
    match redirector::lookup_audit(client_source_port, shared_state.clone()) {
        Ok(data) => entry = data,
        Err(e) => {
            let err = format!("Failed to get lookup_audit: {}", e);
            event_logger::write_event(
                event_logger::WARN_LEVEL,
                err,
                "handle_request",
                "proxy_listener",
                Connection::CONNECTION_LOGGER_KEY,
            );
            Connection::write_information(
                connection_id,
                "Try to get audit entry from socket stream".to_string(),
            );
            match redirector::get_audit_from_stream_socket(
                connection.stream.lock().unwrap().as_raw_socket() as usize,
            ) {
                Ok(data) => entry = data,
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::Unsupported {
                        let err = format!("Failed to get lookup_audit_from_stream: {}", e);
                        event_logger::write_event(
                            event_logger::WARN_LEVEL,
                            err,
                            "handle_request",
                            "proxy_listener",
                            Connection::CONNECTION_LOGGER_KEY,
                        );
                    }
                    log_connection_summary(
                        &connection,
                        StatusCode::MISDIRECTED_REQUEST,
                        shared_state.clone(),
                    );
                    return Ok(empty_response(StatusCode::MISDIRECTED_REQUEST));
                }
            }
        }
    }
    let claims = Claims::from_audit_entry(&entry, client_source_ip, shared_state.clone());

    let claim_details: String = match serde_json::to_string(&claims) {
        Ok(json) => json,
        Err(e) => {
            Connection::write_warning(
                connection_id,
                format!("Failed to get claim json string: {}", e),
            );
            log_connection_summary(
                &connection,
                StatusCode::MISDIRECTED_REQUEST,
                shared_state.clone(),
            );
            return Ok(empty_response(StatusCode::MISDIRECTED_REQUEST));
        }
    };
    Connection::write(connection_id, claim_details.to_string());
    connection.claims = Some(claims.clone());

    // Get the dst ip and port to remote server
    let (ip, port);
    ip = redirector::ip_to_string(entry.destination_ipv4);
    port = http::ntohs(entry.destination_port);
    Connection::write(connection_id, format!("Use lookup value:{ip}:{port}."));
    connection.ip = ip.to_string();
    connection.port = port;

    // authenticate the connection
    if !proxy_authentication::authenticate(
        ip.to_string(),
        port,
        connection_id,
        request.uri().to_string(),
        claims.clone(),
        shared_state.clone(),
    ) {
        Connection::write_warning(
            connection_id,
            format!("Denied unauthorize request: {}", claim_details),
        );
        log_connection_summary(&connection, StatusCode::FORBIDDEN, shared_state.clone());
        return Ok(empty_response(StatusCode::FORBIDDEN));
    }

    // forward the request to the target server
    let mut proxy_request = request;

    // Add required headers
    let host_claims = format!(
        "{{ \"{}\": \"{}\"}}",
        constants::CLAIMS_IS_ROOT,
        claims.runAsElevated
    );
    proxy_request.headers_mut().insert(
        HeaderName::from_static(constants::CLAIMS_HEADER),
        HeaderValue::from_str(&host_claims).unwrap(),
    );
    proxy_request.headers_mut().insert(
        HeaderName::from_static(constants::DATE_HEADER),
        HeaderValue::from_str(&misc_helpers::get_date_time_rfc1123_string()).unwrap(),
    );

    if connection.need_skip_sig() {
        Connection::write(
            connection_id,
            format!(
                "Skip compute signature for the request for {} {}",
                &connection.method, &connection.url
            ),
        );
    } else {
        return handle_request_with_signature(connection, proxy_request, shared_state).await;
    }

    // start new request to the Host endpoint
    let server_addr = format!("{}:{}", ip, port);
    let proxy_stream = TcpStream::connect(server_addr).await.unwrap();
    let io = TokioIo::new(proxy_stream);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok((sender, conn)) => (sender, conn),
        Err(e) => {
            Connection::write_warning(connection_id, format!("Failed to connect to host: {}", e));
            log_connection_summary(
                &connection,
                StatusCode::MISDIRECTED_REQUEST,
                shared_state.clone(),
            );
            return Ok(empty_response(StatusCode::MISDIRECTED_REQUEST));
        }
    };
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            Connection::write(
                connection_id,
                format!("Connection to host failed: {:?}", err),
            );
        }
    });

    //  send to remote server
    let proxy_response = sender.send_request(proxy_request).await.unwrap();
    let frame_stream = proxy_response.into_body().map_frame(|frame| {
        let frame = if let Ok(data) = frame.into_data() {
            // streaming the data
            data.iter().map(|byte| byte.to_be()).collect::<Bytes>()
        } else {
            Bytes::new()
        };

        Frame::data(frame)
    });

    let mut response = Response::new(frame_stream.boxed());
    // insert default x-ms-azure-host-authorization header to let the client know it is through proxy agent
    response.headers_mut().insert(
        HeaderName::from_static(constants::AUTHORIZATION_HEADER),
        HeaderValue::from_static("value"),
    );

    log_connection_summary(&connection, response.status(), shared_state.clone());
    Ok(response)
}

fn log_connection_summary(
    connection: &ConnectionContext,
    response_status: StatusCode,
    shared_state: Arc<Mutex<SharedState>>,
) {
    let elapsed_time = connection.now.elapsed();
    let claims = match &connection.claims {
        Some(c) => c.clone(),
        None => Claims::empty(),
    };

    let summary = ProxySummary {
        id: connection.id,
        userId: claims.userId,
        userName: claims.userName.to_string(),
        userGroups: claims.userGroups.clone(),
        clientIp: claims.clientIp.to_string(),
        processFullPath: claims.processFullPath.to_string(),
        processCmdLine: claims.processCmdLine.to_string(),
        runAsElevated: claims.runAsElevated,
        method: connection.method.to_string(),
        url: connection.url.to_string(),
        ip: connection.ip.to_string(),
        port: connection.port,
        responseStatus: response_status.to_string(),
        elapsedTime: elapsed_time.as_millis(),
    };
    if let Ok(json) = serde_json::to_string(&summary) {
        event_logger::write_event(
            event_logger::INFO_LEVEL,
            json,
            "log_connection_summary",
            "proxy_listener",
            Connection::CONNECTION_LOGGER_KEY,
        );
    };
    agent_status_wrapper::add_one_connection_summary(shared_state, summary, false);
}

// We create some utility functions to make Empty and Full bodies
// fit our broadened Response body type.
fn empty_response(status_code: StatusCode) -> Response<BoxBody<Bytes, hyper::Error>> {
    let empty = Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed();

    let mut response = Response::new(empty);
    *response.status_mut() = status_code;

    response
}

async fn handle_request_with_signature(
    connection: ConnectionContext,
    request: Request<hyper::body::Incoming>,
    shared_state: Arc<Mutex<SharedState>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    // start new request to the Host endpoint
    let server_addr = format!("{}:{}", connection.ip, connection.port);
    let proxy_stream = TcpStream::connect(server_addr).await.unwrap();
    let io = TokioIo::new(proxy_stream);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok((sender, conn)) => (sender, conn),
        Err(e) => {
            Connection::write_warning(connection.id, format!("Failed to connect to host: {}", e));
            log_connection_summary(
                &connection,
                StatusCode::MISDIRECTED_REQUEST,
                shared_state.clone(),
            );
            return Ok(empty_response(StatusCode::MISDIRECTED_REQUEST));
        }
    };
    let connection_id = connection.id;
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            Connection::write(
                connection_id,
                format!("Connection to host failed: {:?}", err),
            );
        }
    });

    let (head, body) = request.into_parts();
    let whole_body = match body.collect().await {
        Ok(data) => data.to_bytes(),
        Err(e) => {
            Connection::write_error(
                connection_id,
                format!("Failed to receive the request body: {}", e),
            );
            return Ok(empty_response(StatusCode::BAD_REQUEST));
        }
    };

    Connection::write(
        connection_id,
        format!(
            "Received the client request body (len={}) for {} {}",
            whole_body.len(),
            &connection.method,
            &connection.url,
        ),
    );

    // create a new request to the Host endpoint
    let mut proxy_request = Request::from_parts(head.clone(), Full::new(whole_body.clone()));

    // sign the request
    // Add header x-ms-azure-host-authorization
    if let (Some(key), Some(key_guid)) = (
        key_keeper_wrapper::get_current_key_value(shared_state.clone()),
        key_keeper_wrapper::get_current_key_guid(shared_state.clone()),
    ) {
        let input_to_sign = proxy_extensions::as_sig_input(head, whole_body);
        match helpers::compute_signature(key.to_string(), input_to_sign.as_slice()) {
            Ok(sig) => {
                match String::from_utf8(input_to_sign) {
                    Ok(data) => Connection::write(
                        connection.id,
                        format!("Computed the signature with input: {}", data),
                    ),
                    Err(e) => {
                        Connection::write_warning(
                            connection.id,
                            format!("Failed convert the input_to_sign to string, error {}", e),
                        );
                    }
                }

                let authorization_value =
                    format!("{} {} {}", constants::AUTHORIZATION_SCHEME, key_guid, sig);
                proxy_request.headers_mut().insert(
                    HeaderName::from_static(constants::AUTHORIZATION_HEADER),
                    HeaderValue::from_str(&authorization_value).unwrap(),
                );

                Connection::write(
                    connection.id,
                    format!("Added authorization header {}", authorization_value),
                )
            }
            Err(e) => {
                Connection::write_error(
                    connection.id,
                    format!("compute_signature failed with error: {}", e),
                );
            }
        }
    } else {
        Connection::write(
            connection.id,
            "current key is empty, skip compute signature for testing.".to_string(),
        );
    }

    //  send to remote server
    let proxy_response = sender.send_request(proxy_request).await.unwrap();
    let frame_stream = proxy_response.into_body().map_frame(|frame| {
        let frame = if let Ok(data) = frame.into_data() {
            // streaming the data
            data.iter().map(|byte| byte.to_be()).collect::<Bytes>()
        } else {
            Bytes::new()
        };

        Frame::data(frame)
    });

    let mut response = Response::new(frame_stream.boxed());
    // insert default x-ms-azure-host-authorization header to let the client know it is through proxy agent
    response.headers_mut().insert(
        HeaderName::from_static(constants::AUTHORIZATION_HEADER),
        HeaderValue::from_static("value"),
    );

    log_connection_summary(&connection, response.status(), shared_state.clone());
    Ok(response)
}
