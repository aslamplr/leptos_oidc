/*
* The MIT License (MIT)
*
* Copyright (c) 2023 Daniél Kerkmann <daniel@kerkmann.dev>
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

#![allow(clippy::module_name_repetitions)]

use std::sync::Arc;

use chrono::Local;
use codee::string::JsonSerdeCodec as JsonCodec;
use jsonwebtoken::{decode, jwk::Jwk, DecodingKey};
use leptos::{
    create_effect, create_local_resource, expect_context, provide_context, spawn_local, Resource,
    SignalGet, SignalGetUntracked, SignalUpdate,
};
use leptos_router::{use_navigate, use_query, NavigateOptions};
use leptos_use::{
    storage::{use_local_storage, use_session_storage},
    use_timeout_fn, UseTimeoutFnReturn,
};
use oauth2::{PkceCodeChallenge, PkceCodeVerifier};
use response::{CallbackResponse, SuccessCallbackResponse, TokenResponse};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use storage::{TokenStorage, CODE_VERIFIER_KEY, LOCAL_STORAGE_KEY};
use utils::ParamBuilder;

pub mod components;
pub mod error;
pub mod response;
pub mod storage;
pub mod utils;

pub use components::*;
pub use error::AuthError;

pub type Algorithm = jsonwebtoken::Algorithm;
pub type TokenData<T> = jsonwebtoken::TokenData<T>;
pub type Validation = jsonwebtoken::Validation;
pub type IssuerResource = Resource<AuthParameters, (Configuration, Keys)>;
pub type AuthResource = Resource<
    (Option<(Configuration, Keys)>, Option<TokenStorage>),
    Result<Option<TokenStorage>, AuthError>,
>;

const REFRESH_TOKEN_SECONDS_BEFORE: usize = 30;

/// Represents authentication parameters required for initializing the `Auth`
/// structure. These parameters include authentication and token endpoints,
/// client ID, and other related data.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct AuthParameters {
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub post_logout_redirect_uri: String,
    pub challenge: Challenge,
    pub scope: Option<String>,
    pub audience: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum Challenge {
    #[default]
    S256,
    Plain,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct Configuration {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub end_session_endpoint: String,
    pub jwks_uri: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct Keys {
    keys: Vec<Jwk>,
}

/// Authentication handler responsible for handling user authentication and
/// token management.
#[derive(Debug, Clone)]
pub struct Auth {
    parameters: AuthParameters,
    issuer: IssuerResource,
    resource: AuthResource,
}

impl PartialEq for Auth {
    fn eq(&self, other: &Self) -> bool {
        self.parameters == other.parameters
            && self.issuer.get() == other.issuer.get()
            && self.resource.get().and_then(Result::ok) == other.resource.get().and_then(Result::ok)
    }
}

impl Eq for Auth {}

impl Auth {
    /// Initializes a new `Auth` instance with the provided authentication
    /// parameters. This function creates and returns an `Auth` struct
    /// configured for authentication.
    #[allow(clippy::must_use_candidate)]
    pub fn init(parameters: AuthParameters) -> Self {
        let issuer = init_issuer_resource(parameters.clone());
        let resource = init_auth_resource(parameters.clone(), issuer);

        create_handle_refresh_effect(parameters.clone(), issuer, resource);

        let auth = Self {
            parameters,
            issuer,
            resource,
        };

        provide_context(auth);

        expect_context::<Auth>()
    }

    /// Generates and returns the URL for initiating the authentication process.
    /// This URL is used to redirect the user to the authentication provider's
    /// login page.
    #[must_use]
    pub fn login_url(&self) -> Option<String> {
        let issuer = self.issuer.get()?;

        let mut params = issuer
            .0
            .authorization_endpoint
            .clone()
            .push_param_query("response_type", "code")
            .push_param_query("client_id", &self.parameters.client_id)
            .push_param_query("redirect_uri", &self.parameters.redirect_uri)
            .push_param_query(
                "scope",
                self.parameters
                    .scope
                    .clone()
                    .unwrap_or("openid".to_string()),
            );

        if let Some(audience) = &self.parameters.audience {
            params = params.push_param_query("audience", audience);
        }

        let (code_verifier, set_code_verifier, remove_code_verifier) =
            use_session_storage::<Option<String>, JsonCodec>(CODE_VERIFIER_KEY);

        match &self.parameters.challenge {
            Challenge::S256 | Challenge::Plain => {
                let code_challenge = if let Some(code_verifier_secret) = code_verifier.get() {
                    let verifier = PkceCodeVerifier::new(code_verifier_secret);
                    if self.parameters.challenge == Challenge::S256 {
                        PkceCodeChallenge::from_code_verifier_sha256(&verifier)
                    } else {
                        PkceCodeChallenge::from_code_verifier_plain(&verifier)
                    }
                } else {
                    let (code, verifier) = if self.parameters.challenge == Challenge::S256 {
                        PkceCodeChallenge::new_random_sha256()
                    } else {
                        PkceCodeChallenge::new_random_plain()
                    };
                    set_code_verifier.update(|u| *u = Some(verifier.secret().to_owned()));
                    code
                };
                params = params.push_param_query("code_challenge", code_challenge.as_str());
                params = params
                    .push_param_query("code_challenge_method", code_challenge.method().as_str());
            }
            Challenge::None => {
                remove_code_verifier();
            }
        }

        Some(params)
    }

    /// Generates and returns the URL for initiating the logout process. This
    /// URL is used to redirect the user to the authentication provider's logout
    /// page.
    #[must_use]
    pub fn logout_url(&self) -> Option<String> {
        let issuer = self.issuer.get()?;

        let url = issuer.0.end_session_endpoint.clone().push_param_query(
            "post_logout_redirect_uri",
            self.parameters
                .post_logout_redirect_uri
                .clone()
                .push_param_query("destroy_session", "true"),
        );

        if let Some(token) = self.resource.get().and_then(Result::ok).flatten() {
            return Some(url.push_param_query("id_token_hint", token.id_token));
        }

        Some(url)
    }

    /// Checks if the authentication process is currently loading.
    #[must_use]
    pub fn loading(&self) -> bool {
        self.resource.loading().get()
    }

    /// Checks if the user is authenticated.
    #[must_use]
    pub fn authenticated(&self) -> bool {
        self.resource.get().and_then(Result::ok).flatten().is_some()
    }

    /// Returns the ID token, if available, from the authentication response.
    #[must_use]
    pub fn id_token(&self) -> Option<String> {
        self.resource
            .get()
            .and_then(Result::ok)
            .flatten()
            .map(|response| response.id_token)
    }

    /// Returns the decoded access token, if available, from the authentication response.
    #[must_use]
    pub fn decoded_id_token<T: DeserializeOwned>(
        &self,
        algorithm: Algorithm,
        audience: &[&str],
    ) -> Option<Option<TokenData<T>>> {
        let issuer = self.issuer.get()?;

        let mut validation = Validation::new(algorithm);
        validation.set_audience(audience);

        self.resource
            .get()
            .and_then(Result::ok)
            .flatten()
            .map(|response| {
                for key in issuer.1.keys {
                    let Ok(decoding_key) = DecodingKey::from_jwk(&key) else {
                        continue;
                    };

                    match decode::<T>(&response.id_token, &decoding_key, &validation) {
                        Ok(data) => return Some(data),
                        Err(_) => continue,
                    }
                }

                None
            })
    }

    /// Returns the access token, if available, from the authentication response.
    #[must_use]
    pub fn access_token(&self) -> Option<String> {
        self.resource
            .get()
            .and_then(Result::ok)
            .flatten()
            .map(|response| response.access_token)
    }

    /// Returns the decoded access token, if available, from the authentication response.
    #[must_use]
    pub fn decoded_access_token<T: DeserializeOwned>(
        &self,
        algorithm: Algorithm,
        audience: &[&str],
    ) -> Option<Option<TokenData<T>>> {
        let issuer = self.issuer.get()?;

        let mut validation = Validation::new(algorithm);
        validation.set_audience(audience);

        self.resource
            .get()
            .and_then(Result::ok)
            .flatten()
            .map(|response| {
                for key in issuer.1.keys {
                    let Ok(decoding_key) = DecodingKey::from_jwk(&key) else {
                        continue;
                    };

                    match decode::<T>(&response.id_token, &decoding_key, &validation) {
                        Ok(data) => return Some(data),
                        Err(_) => continue,
                    }
                }

                None
            })
    }

    /// Returns the authentication state, which may contain token storage information.
    pub fn ok(&self) -> Option<Option<TokenStorage>> {
        self.resource.get().and_then(Result::ok)
    }

    /// Returns any authentication error that occurred during the process.
    pub fn err(&self) -> Option<AuthError> {
        self.resource.get().and_then(Result::err)
    }

    /// This can be used to set the `redirect_uri` dynamically. It's helpful if
    /// you would like to be redirected to the current page.
    pub fn set_redirect_uri(&mut self, uri: String) {
        self.parameters.redirect_uri = uri;
    }
}

/// Initialize the issuer resource, which will fetch the JWKS and endpoints.
///
/// # Panics
///
/// The init function can panic when the issuer and jwks could ne be fetched successfully.
fn init_issuer_resource(parameters: AuthParameters) -> IssuerResource {
    create_local_resource(move || parameters.clone(), {
        move |parameters: AuthParameters| async move {
            let configuration = reqwest::Client::new()
                .get(format!(
                    "{}/.well-known/openid-configuration",
                    parameters.issuer
                ))
                .send()
                .await
                .unwrap()
                .json::<Configuration>()
                .await
                .unwrap();

            let keys = reqwest::Client::new()
                .get(configuration.jwks_uri.clone())
                .send()
                .await
                .unwrap()
                .json::<Keys>()
                .await
                .unwrap();

            (configuration, keys)
        }
    })
}

/// Initialize the auth resource, which will handle the entire state of the authentication.
fn init_auth_resource(parameters: AuthParameters, issuer: IssuerResource) -> AuthResource {
    create_local_resource(
        move || {
            (
                issuer.get(),
                use_local_storage::<Option<TokenStorage>, JsonCodec>(LOCAL_STORAGE_KEY)
                    .0
                    .get(),
            )
        },
        {
            move |(issuer, local_storage): (Option<(Configuration, Keys)>, Option<TokenStorage>)| {
                let parameters = parameters.clone();
                async move {
                    let Some(issuer) = issuer else {
                        return Ok(None);
                    };

                    let (_, set_local_storage, remove_local_storage) =
                        use_local_storage::<Option<TokenStorage>, JsonCodec>(LOCAL_STORAGE_KEY);

                    let auth_response = use_query::<CallbackResponse>();
                    match auth_response.get_untracked() {
                        Ok(CallbackResponse::SuccessLogin(response)) => {
                            use_navigate()(
                                &parameters.redirect_uri,
                                NavigateOptions {
                                    resolve: false,
                                    replace: true,
                                    scroll: true,
                                    state: leptos_router::State(None),
                                },
                            );

                            if let Some(token_storage) = local_storage {
                                if token_storage.expires_in >= Local::now().naive_utc() {
                                    return Ok(Some(token_storage));
                                }
                            }

                            let token_storage =
                                fetch_token(&parameters, &issuer.0, response).await?;

                            set_local_storage.update(|u| *u = Some(token_storage.clone()));

                            Ok(Some(token_storage))
                        }
                        Ok(CallbackResponse::SuccessLogout(response)) => {
                            use_navigate()(
                                &parameters.post_logout_redirect_uri,
                                NavigateOptions {
                                    resolve: false,
                                    replace: true,
                                    scroll: true,
                                    state: leptos_router::State(None),
                                },
                            );

                            if response.destroy_session {
                                remove_local_storage();
                            }

                            Ok(None)
                        }
                        Ok(CallbackResponse::Error(error)) => Err(AuthError::Provider(error)),
                        Err(_) => {
                            if let Some(token_storage) = local_storage {
                                if token_storage.expires_in >= Local::now().naive_utc() {
                                    return Ok(Some(token_storage));
                                }

                                remove_local_storage();
                            }

                            Ok(None)
                        }
                    }
                }
            }
        },
    )
}

/// This will handle the refresh, if there is an refresh token.
fn create_handle_refresh_effect(
    parameters: AuthParameters,
    issuer: IssuerResource,
    resource: AuthResource,
) {
    create_effect(move |_| {
        let Some(issuer) = issuer.get() else {
            return;
        };
        let Some(Ok(Some(token_storage))) = resource.get() else {
            return;
        };

        let expires_in = token_storage.expires_in - Local::now().naive_utc();
        #[allow(clippy::cast_precision_loss)]
        let wait = (expires_in.num_seconds() as f64 - REFRESH_TOKEN_SECONDS_BEFORE as f64).max(0.0)
            * 1000.0;

        let UseTimeoutFnReturn { start, .. } = use_timeout_fn(
            move |(parameters, configuration, resource, token): (
                AuthParameters,
                Configuration,
                AuthResource,
                String,
            )| {
                spawn_local(async move {
                    match refresh_token(&parameters, &configuration, token)
                        .await
                        .map(Option::Some)
                    {
                        Ok(token_storage) => {
                            use_local_storage::<Option<TokenStorage>, JsonCodec>(LOCAL_STORAGE_KEY)
                                .1
                                .update(|u| *u = token_storage);
                        }
                        Err(error) => {
                            resource.update(|u| *u = Some(Err(error)));
                        }
                    }
                });
            },
            wait,
        );

        start((
            parameters.clone(),
            issuer.0,
            resource,
            token_storage.refresh_token.clone(),
        ));
    });
}

/// Asynchronous function for fetching an authentication token.
/// This function is used to exchange an authorization code for an access token.
async fn fetch_token(
    parameters: &AuthParameters,
    configuration: &Configuration,
    auth_response: SuccessCallbackResponse,
) -> Result<TokenStorage, AuthError> {
    let mut body = "&grant_type=authorization_code"
        .to_string()
        .push_param_body("client_id", &parameters.client_id)
        .push_param_body("redirect_uri", &parameters.redirect_uri)
        .push_param_body("code", &auth_response.code);

    if let Some(state) = &auth_response.session_state {
        body = body.push_param_body("state", state);
    }

    let (code_verifier, _, remove_code_verifier) =
        use_session_storage::<Option<String>, JsonCodec>(CODE_VERIFIER_KEY);

    if let Some(code_verifier) = code_verifier.get_untracked() {
        body = body.push_param_body("code_verifier", code_verifier);

        remove_code_verifier();
    }

    let response = reqwest::Client::new()
        .post(configuration.token_endpoint.clone())
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .map_err(Arc::new)?
        .json::<TokenResponse>()
        .await
        .map_err(Arc::new)?;

    match response {
        TokenResponse::Success(success) => Ok(success.into()),
        TokenResponse::Error(error) => Err(AuthError::Provider(error)),
    }
}

/// Asynchronous function for refetching an authentication token.
/// This function is used to exchange a new access token and refresh token.
async fn refresh_token(
    parameters: &AuthParameters,
    configuration: &Configuration,
    refresh_token: String,
) -> Result<TokenStorage, AuthError> {
    let response = reqwest::Client::new()
        .post(configuration.token_endpoint.clone())
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(
            "&grant_type=refresh_token"
                .to_string()
                .push_param_body("client_id", &parameters.client_id)
                .push_param_body("refresh_token", refresh_token),
        )
        .send()
        .await
        .map_err(Arc::new)?
        .json::<TokenResponse>()
        .await
        .map_err(Arc::new)?;

    match response {
        TokenResponse::Success(success) => Ok(success.into()),
        TokenResponse::Error(error) => Err(AuthError::Provider(error)),
    }
}
