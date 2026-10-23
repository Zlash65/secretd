use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use url::Url;
use zeroize::Zeroizing;

pub(super) const REDIRECT_URI: &str = "http://127.0.0.1/oauth/callback";
pub(super) const LOGIN_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const MAX_CALLBACK_BYTES: u64 = 16 * 1024;

pub(super) struct BrowserLogin {
    listener: TcpListener,
    pub redirect_uri: String,
    pub verifier: Zeroizing<String>,
    state: String,
}

impl BrowserLogin {
    pub async fn new() -> Result<Self, String> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|error| format!("Could not listen for AWS sign-in: {error}"))?;
        let address = listener.local_addr().map_err(|error| error.to_string())?;
        Ok(Self {
            listener,
            redirect_uri: format!("http://{address}/oauth/callback"),
            verifier: Zeroizing::new(random_url_token()?),
            state: random_url_token()?,
        })
    }

    pub fn authorization_url(&self, endpoint: &str, client_id: &str) -> Result<String, String> {
        let mut url = Url::parse(endpoint)
            .map_err(|_| "AWS returned an invalid authorization URL".to_string())?;
        if url.scheme() != "https" || url.host_str().is_none() {
            return Err("AWS returned an invalid authorization URL".into());
        }
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("state", &self.state)
            .append_pair("code_challenge_method", "S256")
            .append_pair("code_challenge", &code_challenge(&self.verifier))
            .append_pair("scopes", super::SSO_SCOPE);
        Ok(url.into())
    }

    pub async fn wait_for_code(&self, wait: Duration) -> Result<Zeroizing<String>, String> {
        timeout(wait, async {
            loop {
                let (mut stream, _) = self.listener.accept().await.map_err(|error| {
                    format!("Could not receive the AWS sign-in callback: {error}")
                })?;
                // An unrelated or incomplete local request must not consume the login attempt.
                let result = timeout(Duration::from_secs(2), self.read_callback(&mut stream)).await;
                if let Ok(Ok(Some(code))) = result {
                    return code;
                }
            }
        })
        .await
        .map_err(|_| "AWS sign-in timed out; try again".to_string())?
    }

    async fn read_callback(
        &self,
        stream: &mut TcpStream,
    ) -> Result<Option<Result<Zeroizing<String>, String>>, std::io::Error> {
        let mut reader = BufReader::new((&mut *stream).take(MAX_CALLBACK_BYTES));
        let mut line = Zeroizing::new(String::new());
        reader.read_line(&mut line).await?;
        let result = parse_callback(&line, &self.redirect_uri, &self.state);
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header).await? == 0 {
                return Ok(None);
            }
            if header == "\r\n" {
                break;
            }
        }
        let (status, message) = match &result {
            Some(Ok(_)) => (
                "200 OK",
                "AWS sign-in received. You can return to secretd and close this tab.",
            ),
            Some(Err(_)) => (
                "200 OK",
                "AWS sign-in was not completed. Return to secretd to try again.",
            ),
            None => (
                "400 Bad Request",
                "This callback does not match the current sign-in attempt.",
            ),
        };
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n{message}",
            message.len()
        );
        // Browser disconnects do not invalidate a callback that we already verified.
        let _ = stream.write_all(response.as_bytes()).await;
        Ok(result)
    }
}

fn random_url_token() -> Result<String, String> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|error| error.to_string())?;
    Ok(URL_SAFE_NO_PAD.encode(bytes.as_slice()))
}

fn code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn parse_callback(
    request: &str,
    redirect_uri: &str,
    expected_state: &str,
) -> Option<Result<Zeroizing<String>, String>> {
    let mut parts = request.split_whitespace();
    if parts.next()? != "GET" {
        return None;
    }
    let target = parts.next()?;
    if !target.starts_with("/oauth/callback?") {
        return None;
    }
    let url = Url::parse(redirect_uri).ok()?.join(target).ok()?;
    if url.path() != "/oauth/callback" {
        return None;
    }
    let mut state = None;
    let mut code = None;
    let mut error = None;
    for (key, value) in url.query_pairs() {
        let slot = match key.as_ref() {
            "state" => &mut state,
            "code" => &mut code,
            "error" => &mut error,
            _ => continue,
        };
        if slot.replace(Zeroizing::new(value.into_owned())).is_some() {
            return None;
        }
    }
    if state.as_deref().map(|value| value.as_str()) != Some(expected_state) {
        return None;
    }
    if error.is_some() {
        return Some(Err(
            "AWS sign-in was declined or could not be completed; try again".into(),
        ));
    }
    code.filter(|code| !code.is_empty()).map(Ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn pkce_challenge_matches_the_rfc_7636_vector() {
        assert_eq!(
            code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn browser_authorization_uses_unique_state_and_a_challenge_without_the_verifier() {
        runtime().block_on(async {
            let login = BrowserLogin::new().await.unwrap();
            let other = BrowserLogin::new().await.unwrap();
            assert_ne!(login.state, other.state);
            assert_ne!(*login.verifier, *other.verifier);
            let url = login
                .authorization_url(
                    "https://oidc.ca-central-1.amazonaws.com/authorize",
                    "client+id",
                )
                .unwrap();
            let url = Url::parse(&url).unwrap();
            let query: std::collections::HashMap<_, _> = url.query_pairs().collect();
            assert_eq!(query["client_id"], "client+id");
            assert_eq!(query["redirect_uri"], login.redirect_uri);
            assert_eq!(query["state"], login.state);
            assert_eq!(query["response_type"], "code");
            assert_eq!(query["scopes"], "sso:account:access");
            assert_eq!(query["code_challenge_method"], "S256");
            assert_eq!(query["code_challenge"], code_challenge(&login.verifier));
            assert!(!url.as_str().contains(login.verifier.as_str()));
            assert!(
                login
                    .authorization_url("http://example.com/authorize", "id")
                    .is_err()
            );
        });
    }

    #[test]
    fn callback_rejects_wrong_state_paths_methods_duplicates_and_empty_codes() {
        for request in [
            "GET /oauth/callback?code=code&state=other HTTP/1.1",
            "GET /oauth/callback?code=code HTTP/1.1",
            "GET /favicon.ico?code=code&state=expected HTTP/1.1",
            "POST /oauth/callback?code=code&state=expected HTTP/1.1",
            "GET /oauth/callback?code=code&state=expected&state=other HTTP/1.1",
            "GET /oauth/callback?code=code&code=other&state=expected HTTP/1.1",
            "GET /oauth/callback?code=&state=expected HTTP/1.1",
            "GET //example.com/oauth/callback?code=code&state=expected HTTP/1.1",
            "GET /oauth/callback?error=access_denied&state=other HTTP/1.1",
        ] {
            assert!(
                parse_callback(request, REDIRECT_URI, "expected").is_none(),
                "{request}"
            );
        }
        assert_eq!(
            *parse_callback(
                "GET /oauth/callback?code=a%2Bb&state=expected HTTP/1.1",
                REDIRECT_URI,
                "expected"
            )
            .unwrap()
            .unwrap(),
            "a+b"
        );
        assert!(
            parse_callback(
                "GET /oauth/callback?error=access_denied&state=expected HTTP/1.1",
                REDIRECT_URI,
                "expected"
            )
            .unwrap()
            .is_err()
        );
    }

    async fn callback_request(address: std::net::SocketAddr, target: &str) -> String {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(format!("GET {target} HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    #[test]
    fn loopback_callback_ignores_unrelated_requests_then_completes_and_closes() {
        runtime().block_on(async {
            let login = BrowserLogin::new().await.unwrap();
            let address = login.listener.local_addr().unwrap();
            assert!(address.ip().is_loopback());
            let target = format!("/oauth/callback?code=browser-code&state={}", login.state);
            let send = tokio::spawn(async move {
                assert!(
                    callback_request(address, "/favicon.ico")
                        .await
                        .starts_with("HTTP/1.1 400")
                );
                assert!(
                    callback_request(address, "/oauth/callback?code=bad&state=wrong")
                        .await
                        .starts_with("HTTP/1.1 400")
                );
                let response = callback_request(address, &target).await;
                assert!(response.starts_with("HTTP/1.1 200"));
                assert!(response.contains("Cache-Control: no-store"));
                assert!(!response.contains("browser-code"));
            });
            let code = login.wait_for_code(Duration::from_secs(2)).await;
            send.await.unwrap();
            assert_eq!(*code.unwrap(), "browser-code");
            drop(login);
            assert!(TcpStream::connect(address).await.is_err());
        });
    }

    #[test]
    fn browser_wait_times_out_and_accepts_a_verified_denial() {
        runtime().block_on(async {
            let login = BrowserLogin::new().await.unwrap();
            assert!(
                login
                    .wait_for_code(Duration::from_millis(10))
                    .await
                    .unwrap_err()
                    .contains("timed out")
            );
            let address = login.listener.local_addr().unwrap();
            let target = format!("/oauth/callback?error=access_denied&state={}", login.state);
            let send = tokio::spawn(async move { callback_request(address, &target).await });
            let result = login.wait_for_code(Duration::from_secs(2)).await;
            send.await.unwrap();
            assert!(result.unwrap_err().contains("declined"));
        });
    }
}
