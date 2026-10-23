use std::{
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde_json::json;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    aws::{AwsBroker, AwsLoginStatus, AwsSettings, is_session_expired_error},
    controller::{
        AwsRequestOutcome, AwsRequestResolution, Controller, RequestOutcome, RequestResolution,
    },
    paths::ensure_parent,
    process::{inspect_process_tree, verify_connection_owner},
};

use super::protocol::{ClientRequest, EndpointFile};

const MAX_REQUEST_BYTES: u64 = 16 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const AWS_REQUEST_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const MAX_CONNECTIONS: usize = 64;

pub struct RequestServer {
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    runtime_path: PathBuf,
}

impl RequestServer {
    pub fn start(
        controller: Arc<Mutex<Controller>>,
        runtime_path: PathBuf,
        notify: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<Self, String> {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .map_err(|error| format!("Could not start request server: {error}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| error.to_string())?;
        let port = listener
            .local_addr()
            .map_err(|error| error.to_string())?
            .port();
        let mut token_bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(token_bytes.as_mut()).map_err(|error| error.to_string())?;
        let token = BASE64.encode(token_bytes.as_slice());
        write_endpoint(
            &runtime_path,
            &EndpointFile {
                version: 1,
                host: "127.0.0.1".into(),
                port,
                token: token.clone(),
            },
        )?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicUsize::new(0));
        let thread_shutdown = Arc::clone(&shutdown);
        let thread = thread::Builder::new()
            .name("secretd-request-server".into())
            .spawn(move || {
                while !thread_shutdown.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((connection, _)) => {
                            if active.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
                                active.fetch_sub(1, Ordering::AcqRel);
                                let _ = write_response(
                                    connection,
                                    json!({"ok": false, "error": "Too many pending requests"}),
                                );
                                continue;
                            }
                            let controller = Arc::clone(&controller);
                            let token = token.clone();
                            let notify = Arc::clone(&notify);
                            let active = Arc::clone(&active);
                            let _ = thread::Builder::new().name("secretd-request".into()).spawn(
                                move || {
                                    let _guard = ActiveConnection(active);
                                    handle_connection(connection, &token, &controller, &notify);
                                },
                            );
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(20));
                        }
                        Err(error) => {
                            eprintln!("secretd request listener: {error}");
                            break;
                        }
                    }
                }
            })
            .map_err(|error| error.to_string())?;
        Ok(Self {
            shutdown,
            thread: Some(thread),
            runtime_path,
        })
    }

    pub fn close(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = fs::remove_file(&self.runtime_path);
    }
}

impl Drop for RequestServer {
    fn drop(&mut self) {
        self.close();
    }
}

struct ActiveConnection(Arc<AtomicUsize>);

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn handle_connection(
    mut connection: TcpStream,
    token: &str,
    controller: &Arc<Mutex<Controller>>,
    notify: &Arc<dyn Fn() + Send + Sync>,
) {
    let result = (|| -> Result<Zeroizing<String>, String> {
        connection
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| error.to_string())?;
        let request = read_request(&mut connection)?;
        if !constant_time_equal(&request.token, token) {
            return Err("Authentication failed".into());
        }
        if request.version != 1 || request.pid == 0 {
            return Err("Invalid request".into());
        }
        match request.action.as_str() {
            "get" => {
                let secret = request
                    .secret
                    .as_deref()
                    .filter(|secret| !secret.is_empty())
                    .ok_or_else(|| "Invalid request".to_string())?;
                handle_secret_request(secret, request.pid, &connection, controller, notify)
            }
            "aws-credentials" => {
                let profile = request
                    .profile
                    .as_deref()
                    .filter(|profile| !profile.is_empty())
                    .ok_or_else(|| "Invalid request".to_string())?;
                handle_aws_request(profile, request.pid, &connection, controller, notify)
            }
            "aws-login" => {
                begin_aws_login(Arc::clone(controller), Arc::clone(notify))?;
                Ok(Zeroizing::new(
                    "AWS SSO refresh started in secretd; your browser will open if sign-in is needed".into(),
                ))
            }
            _ => Err("Invalid request".into()),
        }
    })();

    match result {
        Ok(value) => {
            let _ = write_response(connection, json!({"ok": true, "value": &*value}));
        }
        Err(error) => {
            let _ = write_response(connection, json!({"ok": false, "error": error}));
        }
    }
}

fn request_process(
    pid: u32,
    connection: &TcpStream,
) -> Result<(bool, Vec<crate::process::ProcessIdentity>), String> {
    let verified = verify_connection_owner(pid, connection);
    let tree = inspect_process_tree(pid, 12)?;
    if tree.is_empty() {
        return Err("Unable to inspect the requesting process".into());
    }
    Ok((verified, tree))
}

fn handle_secret_request(
    secret: &str,
    pid: u32,
    connection: &TcpStream,
    controller: &Arc<Mutex<Controller>>,
    notify: &Arc<dyn Fn() + Send + Sync>,
) -> Result<Zeroizing<String>, String> {
    let (verified, tree) = request_process(pid, connection)?;
    let outcome = controller
        .lock()
        .map_err(|_| "secretd state is unavailable".to_string())?
        .begin_request(secret, tree, verified)
        .map_err(|error| error.to_string())?;
    match outcome {
        RequestOutcome::Immediate(value) => Ok(value),
        RequestOutcome::Pending { id, receiver } => {
            notify();
            match receiver.recv_timeout(REQUEST_TIMEOUT) {
                Ok(RequestResolution::Approved) => {
                    let value = controller
                        .lock()
                        .map_err(|_| "secretd state is unavailable".to_string())?
                        .release_after_approval(secret)
                        .map_err(|error| error.to_string());
                    notify();
                    value
                }
                Ok(RequestResolution::Denied) => {
                    notify();
                    Err("Request denied or timed out".into())
                }
                Ok(RequestResolution::Failed(error)) => {
                    notify();
                    Err(error)
                }
                Err(_) => {
                    if let Ok(mut controller) = controller.lock() {
                        controller.timeout_request(&id);
                    }
                    notify();
                    Err("Request denied or timed out".into())
                }
            }
        }
    }
}

fn handle_aws_request(
    profile: &str,
    pid: u32,
    connection: &TcpStream,
    controller: &Arc<Mutex<Controller>>,
    notify: &Arc<dyn Fn() + Send + Sync>,
) -> Result<Zeroizing<String>, String> {
    let (verified, tree) = request_process(pid, connection)?;
    let outcome = controller
        .lock()
        .map_err(|_| "secretd state is unavailable".to_string())?
        .begin_aws_request(profile, tree, verified)
        .map_err(|error| error.to_string())?;
    let level = match outcome {
        AwsRequestOutcome::Immediate(level) => level,
        AwsRequestOutcome::Denied => {
            return Err("AWS credential request denied".into());
        }
        AwsRequestOutcome::Pending { id, receiver } => {
            notify();
            match receiver.recv_timeout(AWS_REQUEST_TIMEOUT) {
                Ok(AwsRequestResolution::Approved(level)) => level,
                Ok(AwsRequestResolution::Denied) => {
                    notify();
                    return Err("AWS credential request denied or timed out".into());
                }
                Err(_) => {
                    if let Ok(mut controller) = controller.lock() {
                        controller.timeout_aws_request(&id);
                    }
                    notify();
                    return Err("AWS credential request denied or timed out".into());
                }
            }
        }
    };
    let (broker, _) = controller
        .lock()
        .map_err(|_| "secretd state is unavailable".to_string())?
        .aws_credential_context()
        .map_err(|error| error.to_string())?;
    let _operation = broker.operation()?;
    // Reload the settings after acquiring the operation lock. Another concurrent
    // credential helper may have completed the shared login while this one waited.
    let (_, mut settings) = controller
        .lock()
        .map_err(|_| "secretd state is unavailable".to_string())?
        .aws_credential_context()
        .map_err(|error| error.to_string())?;
    let first_attempt = broker.credentials(&mut settings, profile, level);
    controller
        .lock()
        .map_err(|_| "secretd state is unavailable".to_string())?
        .persist_aws_settings(&settings)
        .map_err(|error| error.to_string())?;
    let credentials = match first_attempt {
        Ok(credentials) => credentials,
        Err(error) if is_session_expired_error(&error) => {
            let (_, login_settings) = controller
                .lock()
                .map_err(|_| "secretd state is unavailable".to_string())?
                .prepare_aws_login()
                .map_err(|error| error.to_string())?;
            notify();
            run_aws_login(
                &broker,
                login_settings,
                Arc::clone(controller),
                Arc::clone(notify),
            )?;
            let (_, mut refreshed_settings) = controller
                .lock()
                .map_err(|_| "secretd state is unavailable".to_string())?
                .aws_credential_context()
                .map_err(|error| error.to_string())?;
            let credentials = broker.credentials(&mut refreshed_settings, profile, level);
            controller
                .lock()
                .map_err(|_| "secretd state is unavailable".to_string())?
                .persist_aws_settings(&refreshed_settings)
                .map_err(|error| error.to_string())?;
            credentials?
        }
        Err(error) => return Err(error),
    };
    notify();
    serde_json::to_string(&credentials)
        .map(Zeroizing::new)
        .map_err(|_| "Could not encode AWS credentials".into())
}

pub fn begin_aws_login(
    controller: Arc<Mutex<Controller>>,
    notify: Arc<dyn Fn() + Send + Sync>,
) -> Result<(), String> {
    let (broker, _) = controller
        .lock()
        .map_err(|_| "secretd state is unavailable".to_string())?
        .preview_aws_login()
        .map_err(|error| error.to_string())?;
    let login_controller = Arc::clone(&controller);
    let login_notify = Arc::clone(&notify);
    let spawn_result = thread::Builder::new()
        .name("secretd-aws-login".into())
        .spawn(move || {
            let result = broker.operation().and_then(|_operation| {
                let (_, settings) = login_controller
                    .lock()
                    .map_err(|_| "secretd state is unavailable".to_string())?
                    .prepare_aws_login()
                    .map_err(|error| error.to_string())?;
                login_notify();
                run_aws_login(
                    &broker,
                    settings,
                    Arc::clone(&login_controller),
                    Arc::clone(&login_notify),
                )
            });
            if let Err(error) = result {
                if let Ok(mut controller) = login_controller.lock() {
                    controller.complete_aws_login(Err(error.clone()));
                }
                login_notify();
                eprintln!("secretd AWS login: {error}");
            }
        });
    match spawn_result {
        Ok(_) => Ok(()),
        Err(error) => {
            let message = format!("Could not start AWS SSO login: {error}");
            if let Ok(mut controller) = controller.lock() {
                controller.set_aws_login_status(AwsLoginStatus::Failed(message.clone()));
            }
            notify();
            Err(message)
        }
    }
}

fn run_aws_login(
    broker: &AwsBroker,
    settings: AwsSettings,
    controller: Arc<Mutex<Controller>>,
    notify: Arc<dyn Fn() + Send + Sync>,
) -> Result<(), String> {
    // Discovery renews expired access tokens before using them. Only a rejected or
    // missing session needs browser authorization; network/service errors remain errors.
    let mut settings = settings;
    let discovery = broker.discover_accounts(&mut settings);
    let discovery = if discovery
        .as_ref()
        .is_err_and(|error| is_session_expired_error(error))
    {
        let browser_controller = Arc::clone(&controller);
        let browser_notify = Arc::clone(&notify);
        settings = match broker.login(settings, move |authorization| {
            if let Ok(mut controller) = browser_controller.lock() {
                controller.set_aws_login_status(AwsLoginStatus::AwaitingUser(authorization));
            }
            browser_notify();
        }) {
            Ok(settings) => settings,
            Err(error) => {
                if let Ok(mut controller) = controller.lock() {
                    controller.complete_aws_login(Err(error.clone()));
                }
                notify();
                return Err(error);
            }
        };
        controller
            .lock()
            .map_err(|_| "secretd state is unavailable".to_string())?
            .set_aws_login_status(AwsLoginStatus::Discovering);
        notify();
        broker.discover_accounts(&mut settings)
    } else {
        discovery
    };
    let mut controller = controller
        .lock()
        .map_err(|_| "secretd state is unavailable".to_string())?;
    match discovery {
        Ok(()) => controller.complete_aws_login(Ok(settings)),
        Err(error) => controller.complete_aws_discovery_failure(&settings, error),
    }
    drop(controller);
    notify();
    Ok(())
}

fn read_request(connection: &mut TcpStream) -> Result<ClientRequest, String> {
    let mut bytes = Zeroizing::new(Vec::new());
    BufReader::new(connection)
        .take(MAX_REQUEST_BYTES + 1)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| "Invalid request".to_string())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("Request is too large".into());
    }
    serde_json::from_slice(&bytes).map_err(|_| "Invalid request".into())
}

fn write_response(mut connection: TcpStream, value: serde_json::Value) -> Result<(), String> {
    let mut bytes = Zeroizing::new(serde_json::to_vec(&value).map_err(|error| error.to_string())?);
    bytes.push(b'\n');
    connection
        .write_all(&bytes)
        .map_err(|error| error.to_string())
}

fn constant_time_equal(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let mut difference = left.len() ^ right.len();
    let length = left.len().max(right.len());
    for index in 0..length {
        difference |= usize::from(left.get(index).copied().unwrap_or(0))
            ^ usize::from(right.get(index).copied().unwrap_or(0));
    }
    difference == 0
}

fn write_endpoint(path: &Path, endpoint: &EndpointFile) -> Result<(), String> {
    let directory = ensure_parent(path)?;
    create_private_directory(directory).map_err(|error| error.to_string())?;
    let temporary = directory.join(format!(".secretd-runtime-{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|error| error.to_string())?;
        let mut bytes = serde_json::to_vec(endpoint).map_err(|error| error.to_string())?;
        bytes.push(b'\n');
        file.write_all(&bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        fs::rename(&temporary, path).map_err(|error| error.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700).create(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_comparison_checks_length_and_contents() {
        assert!(constant_time_equal("abc", "abc"));
        assert!(!constant_time_equal("abc", "abd"));
        assert!(!constant_time_equal("abc", "abcx"));
    }
}
