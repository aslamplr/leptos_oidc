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

use chrono::Utc;
use leptos::{
    create_effect, create_local_resource, expect_context, provide_context, spawn_local, Resource,
    SignalGet, SignalGetUntracked, SignalSet,
};
use leptos_router::use_query;
use response::{CallbackResponse, SuccessCallbackResponse, TokenResponse};
use serde::Deserialize;
use storage::{read_token_storage, remove_token_storage, write_to_token_storage, TokenStorage};
use utils::ParamBuilder;

pub mod components;
pub mod error;
pub mod response;
pub mod storage;
pub mod utils;

pub use components::*;
pub use error::AuthError;

/// Represents authentication parameters required for initializing the `Auth`
/// structure. These parameters include authentication and token endpoints,
/// client ID, and other related data.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthParameters {
    pub auth_endpoint: String,
    pub token_endpoint: String,
    pub logout_endpoint: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub post_logout_redirect_uri: String,
    pub scope: Option<String>,
}

/// Authentication handler responsible for handling user authentication and
/// token management.
#[derive(Debug, Clone)]
pub struct Auth {
    parameters: AuthParameters,
    resource: Resource<(), Result<Option<TokenStorage>, AuthError>>,
}

impl Auth {
    /// Initializes a new `Auth` instance with the provided authentication
    /// parameters. This function creates and returns an `Auth` struct
    /// configured for authentication.
    #[allow(clippy::must_use_candidate)]
    pub fn init(parameters: AuthParameters) -> Self {
        let resource = create_local_resource(move || (), {
            let parameters = parameters.clone();
            move |()| {
                let parameters = parameters.clone();
                async move {
                    let auth_response = use_query::<CallbackResponse>();
                    match auth_response.get_untracked() {
                        Ok(CallbackResponse::SuccessLogin(response)) => {
                            fetch_token(&parameters, response).await.map(Option::Some)
                        }
                        Ok(CallbackResponse::SuccessLogout(response)) => {
                            if response.destroy_session {
                                create_effect(move |_| {
                                    if let Err(error) = remove_token_storage() {
                                        leptos::logging::error!(
                                            "Unable to delete token: {error:#?}"
                                        );
                                    }
                                });
                            }

                            Ok(None)
                        }
                        Ok(CallbackResponse::Error(error)) => Err(AuthError::Provider(error)),
                        Err(_) => {
                            create_effect(move |_| {
                                let auth = expect_context::<Auth>();
                                match read_token_storage() {
                                    Err(error) => {
                                        remove_token_storage().ok();
                                        auth.resource.set(Err(error));
                                    }
                                    Ok(Some(state)) => {
                                        if state.refresh_expires_in < Utc::now().naive_utc() {
                                            remove_token_storage().ok();
                                            auth.resource.set(Ok(None));
                                        } else {
                                            auth.resource.set(Ok(Some(state)));
                                        }
                                    }
                                    Ok(None) => {
                                        auth.resource.set(Ok(None));
                                    }
                                }
                            });

                            Ok(None)
                        }
                    }
                }
            }
        });

        let auth = Self {
            parameters,
            resource,
        };

        provide_context(auth);

        expect_context::<Auth>()
    }

    /// Generates and returns the URL for initiating the authentication process.
    /// This URL is used to redirect the user to the authentication provider's
    /// login page.
    #[must_use]
    pub fn login_url(&self) -> String {
        self.parameters
            .auth_endpoint
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
            )
    }

    /// Generates and returns the URL for initiating the logout process. This
    /// URL is used to redirect the user to the authentication provider's logout
    /// page.
    #[must_use]
    pub fn logout_url(&self) -> String {
        let url = self.parameters.logout_endpoint.clone().push_param_query(
            "post_logout_redirect_uri",
            self.parameters
                .post_logout_redirect_uri
                .clone()
                .push_param_query("destroy_session", "true"),
        );
        if let Some(token) = self.resource.get().and_then(Result::ok).flatten() {
            return url.push_param_query("id_token_hint", token.id_token);
        }

        url
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

    /// Returns the access token, if available, from the authentication response.
    #[must_use]
    pub fn access_token(&self) -> Option<String> {
        self.resource
            .get()
            .and_then(Result::ok)
            .flatten()
            .map(|response| response.access_token)
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

    /// Refresh the current access token with the current refresh token
    pub fn refresh_token(&self) {
        let token = self
            .resource
            .get()
            .and_then(Result::ok)
            .flatten()
            .map(|storage| storage.refresh_token);
        let parameters = self.parameters.clone();
        spawn_local(async move {
            if let Some(token) = token {
                let response = refresh_token(&parameters, token).await.map(Option::Some);
                if response.is_err() {
                    remove_token_storage().ok();
                }
                expect_context::<Auth>().resource.set(response);
            }
        });
    }
}

/// Asynchronous function for fetching an authentication token.
/// This function is used to exchange an authorization code for an access token.
async fn fetch_token(
    parameters: &AuthParameters,
    auth_response: SuccessCallbackResponse,
) -> Result<TokenStorage, AuthError> {
    let response = reqwest::Client::new()
        .post(parameters.token_endpoint.clone())
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(
            "&grant_type=authorization_code"
                .to_string()
                .push_param_body("client_id", &parameters.client_id)
                .push_param_body("redirect_uri", &parameters.redirect_uri)
                .push_param_body("code", &auth_response.code)
                .push_param_body("state", &auth_response.session_state),
        )
        .send()
        .await
        .map_err(Arc::new)?
        .json::<TokenResponse>()
        .await
        .map_err(Arc::new)?;

    let token_storage = match response {
        TokenResponse::Success(success) => Ok(success.into()),
        TokenResponse::Error(error) => Err(AuthError::Provider(error)),
    }?;

    let token_storage_json = serde_json::to_string(&token_storage).map_err(Arc::new)?;
    write_to_token_storage(token_storage_json.as_str())?;

    Ok(token_storage)
}

/// Asynchronous function for refetching an authentication token.
/// This function is used to exchange a new access token and refresh token.
async fn refresh_token(
    parameters: &AuthParameters,
    refresh_token: String,
) -> Result<TokenStorage, AuthError> {
    let response = reqwest::Client::new()
        .post(parameters.token_endpoint.clone())
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

    let token_storage = match response {
        TokenResponse::Success(success) => Ok(success.into()),
        TokenResponse::Error(error) => Err(AuthError::Provider(error)),
    }?;

    let token_storage_json = serde_json::to_string(&token_storage).map_err(Arc::new)?;
    write_to_token_storage(token_storage_json.as_str())?;

    Ok(token_storage)
}
