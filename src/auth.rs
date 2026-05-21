use crate::client::{get_json, post_form, post_form_empty};
use crate::convert::{
    DeviceAuthResponseDe, DiscoveryDocumentDe, JwksDe, TokenResponseDe, UserInfoDe,
};
use crate::params::{create_base_params, push_param};
use crate::wasco_dev::open_id_connect::types::{
    ApiError, CodeChallengeMethod, DeviceAuthResponse, DiscoveryDocument, Jwks, TokenResponse,
    UserInfo,
};

pub struct AuthorizationUrlOptions {
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub response_mode: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<CodeChallengeMethod>,
    pub login_hint: Option<String>,
    pub prompt: Option<String>,
}

fn normalize_scope(scope: &str) -> String {
    scope
        .split(',')
        .map(str::trim)
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn build_authorization_url(
    authorization_endpoint: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    response_type: String,
    options: AuthorizationUrlOptions,
) -> String {
    let scope_str = normalize_scope(&scope);

    let mut params = create_base_params(&client_id, &redirect_uri, &scope_str, &response_type);

    push_authorization_options_to_params(options, &mut params);

    authorization_endpoint + "?" + &params
}

fn push_authorization_options_to_params(options: AuthorizationUrlOptions, params: &mut String) {
    options
        .state
        .inspect(|state| push_param(params, "state", state));
    options
        .nonce
        .inspect(|nonce| push_param(params, "nonce", nonce));
    options
        .response_mode
        .inspect(|response_mode| push_param(params, "response_mode", response_mode));
    options
        .code_challenge
        .inspect(|code_challenge| push_param(params, "code_challenge", code_challenge));
    options.code_challenge_method.inspect(|method| {
        push_param(
            params,
            "code_challenge_method",
            code_challenge_method_as_str(method),
        )
    });
    options
        .login_hint
        .inspect(|login_hint| push_param(params, "login_hint", login_hint));
    options
        .prompt
        .inspect(|prompt| push_param(params, "prompt", prompt));
}

fn code_challenge_method_as_str(method: &CodeChallengeMethod) -> &'static str {
    match method {
        CodeChallengeMethod::Plain => "plain",
        CodeChallengeMethod::S256 => "S256",
    }
}

pub fn exchange_code(
    token_endpoint: String,
    client_id: String,
    client_secret: String,
    code: String,
    redirect_uri: String,
    code_verifier: Option<String>,
) -> Result<TokenResponse, ApiError> {
    let mut params = vec![
        ("grant_type", "authorization_code"),
        ("client_id", &client_id),
        ("client_secret", &client_secret),
        ("code", &code),
        ("redirect_uri", &redirect_uri),
    ];
    if let Some(ref verifier) = code_verifier {
        params.push(("code_verifier", verifier));
    }
    Ok(post_form::<TokenResponseDe>(&token_endpoint, &params)?.into())
}

pub fn refresh_access_token(
    token_endpoint: String,
    client_id: String,
    client_secret: String,
    refresh_token: String,
) -> Result<TokenResponse, ApiError> {
    Ok(post_form::<TokenResponseDe>(
        &token_endpoint,
        &[
            ("grant_type", "refresh_token"),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
            ("refresh_token", &refresh_token),
        ],
    )?
    .into())
}

pub fn exchange_jwt_bearer(
    token_endpoint: String,
    assertion: String,
) -> Result<TokenResponse, ApiError> {
    Ok(post_form::<TokenResponseDe>(
        &token_endpoint,
        &[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &assertion),
        ],
    )?
    .into())
}

pub fn initiate_device_auth(
    device_authorization_endpoint: String,
    client_id: String,
    scope: String,
) -> Result<DeviceAuthResponse, ApiError> {
    let scope_str = normalize_scope(&scope);
    Ok(post_form::<DeviceAuthResponseDe>(
        &device_authorization_endpoint,
        &[("client_id", &client_id), ("scope", &scope_str)],
    )?
    .into())
}

pub fn poll_device_token(
    token_endpoint: String,
    client_id: String,
    client_secret: Option<String>,
    device_code: String,
) -> Result<TokenResponse, ApiError> {
    let mut params = vec![
        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ("client_id", &client_id),
        ("device_code", &device_code),
    ];
    if let Some(ref secret) = client_secret {
        params.push(("client_secret", secret));
    }
    Ok(post_form::<TokenResponseDe>(&token_endpoint, &params)?.into())
}

pub fn get_userinfo(userinfo_endpoint: String, access_token: String) -> Result<UserInfo, ApiError> {
    Ok(get_json::<UserInfoDe>(&userinfo_endpoint, Some(&access_token))?.into())
}

pub fn revoke_token(revocation_endpoint: String, token: String) -> Result<(), ApiError> {
    post_form_empty(&revocation_endpoint, &[("token", &token)])
}

pub fn get_jwks(jwks_uri: String) -> Result<Jwks, ApiError> {
    Ok(get_json::<JwksDe>(&jwks_uri, None)?.into())
}

pub fn get_discovery(url: String) -> Result<DiscoveryDocument, ApiError> {
    Ok(get_json::<DiscoveryDocumentDe>(&url, None)?.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_options() -> AuthorizationUrlOptions {
        AuthorizationUrlOptions {
            state: None,
            nonce: None,
            response_mode: None,
            code_challenge: None,
            code_challenge_method: None,
            login_hint: None,
            prompt: None,
        }
    }

    fn build_url(
        endpoint: &str,
        client_id: &str,
        redirect_uri: &str,
        scope: &str,
        response_type: &str,
    ) -> String {
        build_authorization_url(
            endpoint.into(),
            client_id.into(),
            redirect_uri.into(),
            scope.into(),
            response_type.into(),
            no_options(),
        )
    }

    #[test]
    fn build_authorization_url_contains_base_endpoint() {
        let url = build_url(
            "https://example.com/auth",
            "client1",
            "https://app/cb",
            "openid",
            "code",
        );
        assert!(url.starts_with("https://example.com/auth?"));
    }

    #[test]
    fn build_authorization_url_includes_client_id() {
        let url = build_url(
            "https://example.com/auth",
            "my-client",
            "https://app/cb",
            "openid",
            "code",
        );
        assert!(url.contains("client_id=my-client"), "url: {url}");
    }

    #[test]
    fn build_authorization_url_includes_redirect_uri() {
        let url = build_url(
            "https://example.com/auth",
            "c",
            "https://app/callback",
            "openid",
            "code",
        );
        assert!(
            url.contains("redirect_uri=https%3A%2F%2Fapp%2Fcallback"),
            "url: {url}"
        );
    }

    #[test]
    fn build_authorization_url_includes_response_type() {
        let url = build_url(
            "https://example.com/auth",
            "c",
            "https://app/cb",
            "openid",
            "code",
        );
        assert!(url.contains("response_type=code"), "url: {url}");
    }

    #[test]
    fn build_authorization_url_converts_comma_scope_to_space_separated() {
        let url = build_url(
            "https://example.com/auth",
            "c",
            "https://app/cb",
            "openid,email,profile",
            "code",
        );
        assert!(url.contains("scope=openid%20email%20profile"), "url: {url}");
    }

    #[test]
    fn build_authorization_url_trims_scope_whitespace() {
        let url = build_url(
            "https://example.com/auth",
            "c",
            "https://app/cb",
            "openid, email",
            "code",
        );
        assert!(url.contains("scope=openid%20email"), "url: {url}");
    }

    #[test]
    fn build_authorization_url_omits_state_when_none() {
        let url = build_url(
            "https://example.com/auth",
            "c",
            "https://app/cb",
            "openid",
            "code",
        );
        assert!(!url.contains("state="), "url: {url}");
    }

    #[test]
    fn build_authorization_url_includes_state_when_some() {
        let url = build_authorization_url(
            "https://example.com/auth".into(),
            "c".into(),
            "https://app/cb".into(),
            "openid".into(),
            "code".into(),
            AuthorizationUrlOptions {
                state: Some("xyz123".into()),
                ..no_options()
            },
        );
        assert!(url.contains("state=xyz123"), "url: {url}");
    }

    #[test]
    fn build_authorization_url_maps_s256_code_challenge_method() {
        let url = build_authorization_url(
            "https://example.com/auth".into(),
            "c".into(),
            "https://app/cb".into(),
            "openid".into(),
            "code".into(),
            AuthorizationUrlOptions {
                code_challenge: Some("challenge_value".into()),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                ..no_options()
            },
        );
        assert!(url.contains("code_challenge_method=S256"), "url: {url}");
    }

    #[test]
    fn build_authorization_url_maps_plain_code_challenge_method() {
        let url = build_authorization_url(
            "https://example.com/auth".into(),
            "c".into(),
            "https://app/cb".into(),
            "openid".into(),
            "code".into(),
            AuthorizationUrlOptions {
                code_challenge: Some("challenge_value".into()),
                code_challenge_method: Some(CodeChallengeMethod::Plain),
                ..no_options()
            },
        );
        assert!(url.contains("code_challenge_method=plain"), "url: {url}");
    }

    #[test]
    fn exchange_code_returns_invalid_url_error_for_malformed_url() {
        let result = exchange_code(
            "not a valid url".into(),
            "client_id".into(),
            "client_secret".into(),
            "code".into(),
            "https://app/cb".into(),
            None,
        );
        assert!(matches!(result, Err(ApiError::InvalidUrl(_))));
    }

    #[test]
    fn get_discovery_returns_invalid_url_error_for_malformed_url() {
        let result = get_discovery("not a valid url".into());
        assert!(matches!(result, Err(ApiError::InvalidUrl(_))));
    }
}
