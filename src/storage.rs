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

use std::sync::Arc;

use chrono::{NaiveDateTime, TimeDelta, Utc};
use leptos::window;
use serde::{Deserialize, Serialize};
use web_sys::Storage;

use crate::{error::AuthError, response::SuccessTokenResponse};

/// The key used for storing authentication token data in local storage.
const LOCAL_STORAGE_KEY: &str = "auth";

/// A structure representing the storage of authentication tokens.
#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
pub struct TokenStorage {
    pub id_token: String,
    pub access_token: String,
    pub expires_in: NaiveDateTime,
    pub refresh_token: String,
    pub refresh_expires_in: Option<NaiveDateTime>,
}

/// Converts a `SuccessTokenResponse` into a `TokenStorage` structure.
impl From<SuccessTokenResponse> for TokenStorage {
    fn from(value: SuccessTokenResponse) -> Self {
        Self {
            id_token: value.id_token,
            access_token: value.access_token,
            expires_in: Utc::now().naive_utc()
                + TimeDelta::try_seconds(value.expires_in).unwrap_or_default(),
            refresh_token: value.refresh_token,
            refresh_expires_in: value.refresh_expires_in.map(|refresh_expires_in| {
                Utc::now().naive_utc()
                    + TimeDelta::try_seconds(refresh_expires_in).unwrap_or_default()
            }),
        }
    }
}

/// Retrieves the local storage for the application.
fn get_storage() -> Result<Storage, AuthError> {
    window()
        .local_storage()
        .map_err(|_| AuthError::Storage)?
        .ok_or(AuthError::Storage)
}

/// Reads the token storage from local storage and deserializes it into a
/// `TokenStorage` structure.
pub(crate) fn read_token_storage() -> Result<Option<TokenStorage>, AuthError> {
    let storage = get_storage()?;
    let item = storage
        .get(LOCAL_STORAGE_KEY)
        .map_err(|_| AuthError::Storage)?;
    if let Some(item) = item {
        let token_storage = serde_json::from_str(item.as_str())
            .map_err(|error| AuthError::Serde(Arc::new(error)))?;
        return Ok(Some(token_storage));
    }

    Ok(None)
}

/// Removes the token storage from local storage.
pub(crate) fn remove_token_storage() -> Result<(), AuthError> {
    let storage = get_storage()?;
    storage
        .delete(LOCAL_STORAGE_KEY)
        .map_err(|_| AuthError::Storage)
}

/// Writes a JSON representation of the token storage to local storage.
pub(crate) fn write_to_token_storage(token_storage_json: &str) -> Result<(), AuthError> {
    let storage = get_storage()?;
    storage
        .set(LOCAL_STORAGE_KEY, token_storage_json)
        .map_err(|_| AuthError::Storage)
}
