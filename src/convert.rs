use serde::Deserialize;

use crate::wasco_dev::open_id_connect::types::{
    DeviceAuthResponse, DiscoveryDocument, Jwk, Jwks, TokenResponse, UserInfo,
};

fn default_bearer() -> String {
    "Bearer".to_string()
}

#[derive(Deserialize)]
pub struct TokenResponseDe {
    pub access_token: String,
    #[serde(default = "default_bearer")]
    pub token_type: String,
    pub expires_in: Option<u32>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub id_token: Option<String>,
}

impl From<TokenResponseDe> for TokenResponse {
    fn from(deserialized: TokenResponseDe) -> Self {
        TokenResponse {
            access_token: deserialized.access_token,
            token_type: deserialized.token_type,
            expires_in: deserialized.expires_in,
            refresh_token: deserialized.refresh_token,
            scope: deserialized.scope,
            id_token: deserialized.id_token,
        }
    }
}

#[derive(Deserialize)]
pub struct DeviceAuthResponseDe {
    pub device_code: String,
    pub user_code: String,
    /// Accepts either the RFC 8628 name (`verification_uri`) or the older
    /// Google-style alias (`verification_url`).
    #[serde(alias = "verification_url")]
    pub verification_uri: String,
    #[serde(alias = "verification_url_complete")]
    pub verification_uri_complete: Option<String>,
    pub expires_in: u32,
    #[serde(default)]
    pub interval: u32,
}

impl From<DeviceAuthResponseDe> for DeviceAuthResponse {
    fn from(deserialized: DeviceAuthResponseDe) -> Self {
        DeviceAuthResponse {
            device_code: deserialized.device_code,
            user_code: deserialized.user_code,
            verification_uri: deserialized.verification_uri,
            verification_uri_complete: deserialized.verification_uri_complete,
            expires_in: deserialized.expires_in,
            interval: deserialized.interval,
        }
    }
}

#[derive(Deserialize)]
pub struct UserInfoDe {
    pub sub: String,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub locale: Option<String>,
}

impl From<UserInfoDe> for UserInfo {
    fn from(deserialized: UserInfoDe) -> Self {
        UserInfo {
            sub: deserialized.sub,
            name: deserialized.name,
            given_name: deserialized.given_name,
            family_name: deserialized.family_name,
            picture: deserialized.picture,
            email: deserialized.email,
            email_verified: deserialized.email_verified,
            locale: deserialized.locale,
        }
    }
}

#[derive(Deserialize)]
pub struct JwkDe {
    pub kty: String,
    #[serde(rename = "use")]
    pub key_use: Option<String>,
    pub n: Option<String>,
    pub e: Option<String>,
    pub alg: Option<String>,
    pub kid: Option<String>,
    pub x5t: Option<String>,
    #[serde(default)]
    pub x5c: Vec<String>,
}

impl From<JwkDe> for Jwk {
    fn from(deserialized: JwkDe) -> Self {
        Jwk {
            kty: deserialized.kty,
            key_use: deserialized.key_use,
            n: deserialized.n,
            e: deserialized.e,
            alg: deserialized.alg,
            kid: deserialized.kid,
            x5t: deserialized.x5t,
            x5c: deserialized.x5c,
        }
    }
}

#[derive(Deserialize)]
pub struct JwksDe {
    pub keys: Vec<JwkDe>,
}

impl From<JwksDe> for Jwks {
    fn from(deserialized: JwksDe) -> Self {
        Jwks {
            keys: deserialized.keys.into_iter().map(Jwk::from).collect(),
        }
    }
}

#[derive(Deserialize)]
pub struct DiscoveryDocumentDe {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub device_authorization_endpoint: Option<String>,
    pub token_endpoint: String,
    pub userinfo_endpoint: Option<String>,
    pub revocation_endpoint: Option<String>,
    pub jwks_uri: String,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    #[serde(default)]
    pub response_types_supported: Vec<String>,
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    #[serde(default)]
    pub claims_supported: Vec<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
}

impl From<DiscoveryDocumentDe> for DiscoveryDocument {
    fn from(deserialized: DiscoveryDocumentDe) -> Self {
        DiscoveryDocument {
            issuer: deserialized.issuer,
            authorization_endpoint: deserialized.authorization_endpoint,
            device_authorization_endpoint: deserialized.device_authorization_endpoint,
            token_endpoint: deserialized.token_endpoint,
            userinfo_endpoint: deserialized.userinfo_endpoint,
            revocation_endpoint: deserialized.revocation_endpoint,
            jwks_uri: deserialized.jwks_uri,
            scopes_supported: deserialized.scopes_supported,
            response_types_supported: deserialized.response_types_supported,
            grant_types_supported: deserialized.grant_types_supported,
            claims_supported: deserialized.claims_supported,
            code_challenge_methods_supported: deserialized.code_challenge_methods_supported,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse_token(value: serde_json::Value) -> TokenResponseDe {
        serde_json::from_value(value).unwrap()
    }

    fn parse_device(value: serde_json::Value) -> DeviceAuthResponseDe {
        serde_json::from_value(value).unwrap()
    }

    fn parse_discovery(value: serde_json::Value) -> DiscoveryDocumentDe {
        serde_json::from_value(value).unwrap()
    }

    fn parse_jwks(value: serde_json::Value) -> JwksDe {
        serde_json::from_value(value).unwrap()
    }

    fn parse_user_info(value: serde_json::Value) -> UserInfoDe {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn token_response_parses_access_token() {
        let json_value = json!({ "access_token": "abc123", "token_type": "Bearer" });
        assert_eq!(parse_token(json_value).access_token, "abc123");
    }

    #[test]
    fn token_response_parses_token_type() {
        let json_value = json!({ "access_token": "", "token_type": "MAC" });
        assert_eq!(parse_token(json_value).token_type, "MAC");
    }

    #[test]
    fn token_response_defaults_token_type_to_bearer_when_absent() {
        let json_value = json!({ "access_token": "x" });
        assert_eq!(parse_token(json_value).token_type, "Bearer");
    }

    #[test]
    fn token_response_parses_expires_in() {
        let json_value = json!({ "access_token": "", "token_type": "Bearer", "expires_in": 3600 });
        assert_eq!(parse_token(json_value).expires_in, Some(3600));
    }

    #[test]
    fn token_response_expires_in_absent_is_none() {
        let json_value = json!({ "access_token": "", "token_type": "Bearer" });
        assert!(parse_token(json_value).expires_in.is_none());
    }

    #[test]
    fn token_response_refresh_token_present() {
        let json_value =
            json!({ "access_token": "", "token_type": "Bearer", "refresh_token": "rt123" });
        assert_eq!(
            parse_token(json_value).refresh_token.as_deref(),
            Some("rt123")
        );
    }

    #[test]
    fn token_response_refresh_token_absent_is_none() {
        let json_value = json!({ "access_token": "", "token_type": "Bearer" });
        assert!(parse_token(json_value).refresh_token.is_none());
    }

    #[test]
    fn token_response_parses_id_token() {
        let json_value =
            json!({ "access_token": "", "token_type": "Bearer", "id_token": "eyJ.payload.sig" });
        assert_eq!(
            parse_token(json_value).id_token.as_deref(),
            Some("eyJ.payload.sig")
        );
    }

    #[test]
    fn device_auth_response_parses_required_fields() {
        let json_value = json!({
            "device_code": "dc123",
            "user_code": "ABCD-1234",
            "verification_uri": "https://example.com/activate",
            "expires_in": 1800,
            "interval": 5
        });
        let response = parse_device(json_value);
        assert_eq!(response.device_code, "dc123");
        assert_eq!(response.user_code, "ABCD-1234");
        assert_eq!(response.verification_uri, "https://example.com/activate");
        assert_eq!(response.expires_in, 1800);
        assert_eq!(response.interval, 5);
    }

    #[test]
    fn device_auth_response_falls_back_to_verification_url() {
        let json_value = json!({
            "device_code": "", "user_code": "",
            "verification_url": "https://example.com/activate",
            "expires_in": 0, "interval": 0
        });
        assert_eq!(
            parse_device(json_value).verification_uri,
            "https://example.com/activate"
        );
    }

    #[test]
    fn discovery_parses_required_fields() {
        let json_value = json!({
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/auth",
            "token_endpoint": "https://example.com/token",
            "jwks_uri": "https://example.com/jwks"
        });
        let discovery = parse_discovery(json_value);
        assert_eq!(discovery.issuer, "https://example.com");
        assert_eq!(discovery.authorization_endpoint, "https://example.com/auth");
        assert_eq!(discovery.token_endpoint, "https://example.com/token");
        assert_eq!(discovery.jwks_uri, "https://example.com/jwks");
    }

    #[test]
    fn discovery_optional_fields_absent_when_missing() {
        let json_value = json!({
            "issuer": "", "authorization_endpoint": "",
            "token_endpoint": "", "jwks_uri": ""
        });
        let discovery = parse_discovery(json_value);
        assert!(discovery.device_authorization_endpoint.is_none());
        assert!(discovery.userinfo_endpoint.is_none());
        assert!(discovery.revocation_endpoint.is_none());
    }

    #[test]
    fn discovery_parses_scopes_supported() {
        let json_value = json!({
            "issuer": "", "authorization_endpoint": "", "token_endpoint": "", "jwks_uri": "",
            "scopes_supported": ["openid", "email", "profile"]
        });
        assert_eq!(
            parse_discovery(json_value).scopes_supported,
            vec!["openid", "email", "profile"]
        );
    }

    #[test]
    fn discovery_parses_grant_types_supported() {
        let json_value = json!({
            "issuer": "", "authorization_endpoint": "", "token_endpoint": "", "jwks_uri": "",
            "grant_types_supported": ["authorization_code", "refresh_token"]
        });
        let discovery = parse_discovery(json_value);
        assert!(
            discovery
                .grant_types_supported
                .contains(&"authorization_code".to_string())
        );
        assert!(
            discovery
                .grant_types_supported
                .contains(&"refresh_token".to_string())
        );
    }

    #[test]
    fn discovery_parses_code_challenge_methods() {
        let json_value = json!({
            "issuer": "", "authorization_endpoint": "", "token_endpoint": "", "jwks_uri": "",
            "code_challenge_methods_supported": ["S256", "plain"]
        });
        let discovery = parse_discovery(json_value);
        assert!(
            discovery
                .code_challenge_methods_supported
                .contains(&"S256".to_string())
        );
        assert!(
            discovery
                .code_challenge_methods_supported
                .contains(&"plain".to_string())
        );
    }

    #[test]
    fn jwks_parses_single_key() {
        let json_value =
            json!({ "keys": [{ "kty": "RSA", "n": "abc", "e": "AQAB", "kid": "key1" }] });
        let jwks = parse_jwks(json_value);
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kty, "RSA");
        assert_eq!(jwks.keys[0].kid.as_deref(), Some("key1"));
    }

    #[test]
    fn jwks_empty_keys_array() {
        let json_value = json!({ "keys": [] });
        assert_eq!(parse_jwks(json_value).keys.len(), 0);
    }

    #[test]
    fn user_info_parses_sub() {
        let json_value = json!({ "sub": "user123" });
        assert_eq!(parse_user_info(json_value).sub, "user123");
    }

    #[test]
    fn user_info_optional_fields_absent_when_missing() {
        let json_value = json!({ "sub": "user123" });
        let user_info = parse_user_info(json_value);
        assert!(user_info.name.is_none());
        assert!(user_info.email.is_none());
        assert!(user_info.email_verified.is_none());
    }

    #[test]
    fn user_info_parses_email_and_verified() {
        let json_value = json!({ "sub": "x", "email": "test@example.com", "email_verified": true });
        let user_info = parse_user_info(json_value);
        assert_eq!(user_info.email.as_deref(), Some("test@example.com"));
        assert_eq!(user_info.email_verified, Some(true));
    }

    #[test]
    fn user_info_parses_name_fields() {
        let json_value = json!({
            "sub": "x",
            "name": "Jane Doe",
            "given_name": "Jane",
            "family_name": "Doe"
        });
        let user_info = parse_user_info(json_value);
        assert_eq!(user_info.name.as_deref(), Some("Jane Doe"));
        assert_eq!(user_info.given_name.as_deref(), Some("Jane"));
        assert_eq!(user_info.family_name.as_deref(), Some("Doe"));
    }
}
