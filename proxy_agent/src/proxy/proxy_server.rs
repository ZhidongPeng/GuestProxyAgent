use crate::common::{config, constants, helpers, http, logger};
use crate::proxy::proxy_connection::{Connection, ConnectionContext};
use crate::proxy::{proxy_authentication, Claims};
use crate::shared_state::{key_keeper_wrapper, proxy_listener_wrapper, SharedState};
use crate::{provision, redirector};
use http_body_util::{combinators::BoxBody, BodyExt, Empty};
use hyper::body::{Bytes, Frame};
use hyper::header::{HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::StatusCode;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use itertools::Itertools;
use proxy_agent_shared::misc_helpers;
use proxy_agent_shared::telemetry::event_logger;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::windows::io::AsRawSocket;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use url::Url;

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
}

async fn start(
    port: u16,
    shared_state: Arc<Mutex<SharedState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    Connection::init_logger(config::get_logs_dir());

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = match TcpListener::bind(addr).await {
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

        let shared_state = shared_state.clone();
        tokio::spawn(async move {
            let connection_id =
                proxy_listener_wrapper::increase_connection_count(shared_state.clone());
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

            let cloned_stream = match std_stream.try_clone() {
                Ok(cloned_stream) => cloned_stream,
                Err(e) => {
                    Connection::write_warning(
                        connection_id,
                        format!("ProxyListener stream clone error {}", e),
                    );
                    return;
                }
            };

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

            let cloned_stream = Arc::new(Mutex::new(cloned_stream));
            // add client addr and shared_state to the service_fn
            let service = service_fn(move |req| {
                let shared_state = shared_state.clone();
                let connection = ConnectionContext {
                    stream: cloned_stream.clone(),
                    client_addr,
                    id: connection_id,
                    now: std::time::Instant::now(),
                    ip: String::new(),
                    port: 0,
                    claims: None,
                };
                handle_request(req, connection, shared_state)
            });
            // Use an adapter to access something implementing `tokio::io` traits as if they implement
            let io = TokioIo::new(stream);

            // We use the `hyper::server::conn::Http` to serve the connection
            let http = hyper::server::conn::http1::Builder::new();

            if let Err(e) = http.serve_connection(io, service).await {
                logger::write_warning(format!("ProxyListener connection error {}", e));
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
    Connection::write_warning(
        connection_id,
        format!(
            "Got request from {} for {}",
            connection.client_addr,
            request.uri()
        ),
    );

    let client_source_ip = connection.client_addr.ip();
    let client_source_port = connection.client_addr.port();

    let entry;
    match redirector::lookup_audit(client_source_port) {
        Ok(data) => entry = data,
        Err(e) => {
            let err = format!("Failed to get lookup_audit: {}", e);
            event_logger::write_event(
                event_logger::WARN_LEVEL,
                err,
                "handle_connection",
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
                            "handle_connection",
                            "proxy_listener",
                            Connection::CONNECTION_LOGGER_KEY,
                        );
                    }
                    //log_connection_summary(connection, &request, Response::MISDIRECTED.to_string());
                    return Ok(empty_response(StatusCode::MISDIRECTED_REQUEST));
                }
            }
        }
    }
    let claims = Claims::from_audit_entry(&entry, client_source_ip);

    let claim_details: String = match serde_json::to_string(&claims) {
        Ok(json) => json,
        Err(e) => {
            Connection::write_warning(
                connection_id,
                format!("Failed to get claim json string: {}", e),
            );
            // log_connection_summary(connection, &request, Response::MISDIRECTED.to_string());
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

    // authenticate the connection
    if !proxy_authentication::authenticate(
        ip.to_string(),
        port,
        connection_id,
        request.uri().to_string(),
        claims.clone(),
    ) {
        Connection::write_warning(
            connection_id,
            format!("Denied unauthorize request: {}", claim_details),
        );
        //log_connection_summary(connection, &request, Response::FORBIDDEN.to_string());
        return Ok(empty_response(StatusCode::FORBIDDEN));
    }

    let server_addr = format!("{}:{}", ip, port); // imds server
    let proxy_stream = TcpStream::connect(server_addr).await.unwrap();
    let io = TokioIo::new(proxy_stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            Connection::write(
                connection_id,
                format!("Connection to host failed: {:?}", err),
            );
        }
    });

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

    // sign the request
    // Add header x-ms-azure-host-authorization
    if let Some(key) = key_keeper_wrapper::get_current_key_value(shared_state.clone()) {
        if let Some(key_guid) = key_keeper_wrapper::get_current_key_guid(shared_state.clone()) {
            let input_to_sign = as_sig_input(&proxy_request).await;
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
                        HeaderName::from_static(constants::AUTHORIZATION_SCHEME),
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
        }
    } else {
        Connection::write(
            connection.id,
            "current key is empty, skip compute signature for testing.".to_string(),
        );
    }

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
    response.headers_mut().insert(
        HeaderName::from_static(constants::AUTHORIZATION_HEADER),
        HeaderValue::from_static("value"),
    );

    Ok(response)
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

/*
    StringToSign = Method + "\n" +
           HexEncoded(Body) + "\n" +
           CanonicalizedHeaders + "\n"
           UrlEncodedPath + "\n"
           CanonicalizedParameters;
*/
async fn as_sig_input(request: &Request<hyper::body::Incoming>) -> Vec<u8> {
    let mut data: Vec<u8> = request.method().to_string().as_bytes().to_vec();
    data.extend(constants::LF.as_bytes());
    //data.extend(request.clone().collect().await.unwrap().to_bytes());
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
