use crate::params::build_query_string;
use crate::wasco_dev::open_id_connect::types::{ApiError, ServerErrorBody};
use wstd::http::{Body, Client, Request};
use wstd::runtime::block_on;
use wstd::time::Duration;

/// Deserialization target for RFC 6749 §5.2 error responses.
#[derive(serde::Deserialize)]
struct OAuthError {
    #[serde(default = "default_server_error")]
    error: String,
    error_description: Option<String>,
    error_uri: Option<String>,
}

fn default_server_error() -> String {
    "server_error".to_string()
}

async fn send<T: for<'de> serde::Deserialize<'de>>(request: Request<Body>) -> Result<T, ApiError> {
    let mut client = Client::new();
    client.set_connect_timeout(Duration::from_secs(30));
    client.set_between_bytes_timeout(Duration::from_secs(30));
    client.set_first_byte_timeout(Duration::from_secs(30));
    let response = client
        .send(request)
        .await
        .map_err(|error| ApiError::HttpError(error.to_string()))?;

    let status = response.status();
    let mut body = response.into_body();

    if status.is_success() {
        body.json::<T>()
            .await
            .map_err(|error| ApiError::ParseError(error.to_string()))
    } else if let Ok(oauth_error) = body.json::<OAuthError>().await {
        Err(ApiError::ServerError(ServerErrorBody {
            error: oauth_error.error,
            error_description: oauth_error.error_description,
            error_uri: oauth_error.error_uri,
        }))
    } else {
        Err(ApiError::HttpError(format!(
            "HTTP {status}: {}",
            body.str_contents()
                .await
                .unwrap_or("Could not read response body")
        )))
    }
}

fn build_form_request(url: &str, params: &[(&str, &str)]) -> Result<Request<Body>, ApiError> {
    let body_string = build_query_string(params);
    let content_length = body_string.len().to_string();
    Request::post(url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Content-Length", &content_length)
        .body(Body::from(body_string))
        .map_err(|error| ApiError::InvalidUrl(error.to_string()))
}

pub fn post_form<T: for<'de> serde::Deserialize<'de>>(
    url: &str,
    params: &[(&str, &str)],
) -> Result<T, ApiError> {
    let request = build_form_request(url, params)?;
    block_on(send(request))
}

pub fn post_form_empty(url: &str, params: &[(&str, &str)]) -> Result<(), ApiError> {
    let request = build_form_request(url, params)?;
    block_on(send::<serde_json::Value>(request))?;
    Ok(())
}

pub fn get_json<T: for<'de> serde::Deserialize<'de>>(
    url: &str,
    bearer: Option<&str>,
) -> Result<T, ApiError> {
    let mut builder = Request::get(url);
    if let Some(token) = bearer {
        builder = builder.header("Authorization", &format!("Bearer {token}"));
    }
    let request = builder
        .body(Body::empty())
        .map_err(|error| ApiError::InvalidUrl(error.to_string()))?;
    block_on(send(request))
}
