# Leptos OIDC Authentication

**leptos_oidc** is a utility library for handling OpenID Connect (OIDC)
authentication within the Leptos framework. It simplifies the integration of
OIDC authentication flows with Leptos-based applications, making it easier to
manage user authentication and tokens.

## Table of Contents

- [Leptos compatibility](leptos-compatibility)
- [Features](#features)
- [Missing Features](#missing-features)
- [Tested Backends with Example](#tested-backends-with-example)
- [Usage](#usage)
  - [Initialization](#initialization)
  - [Generating Login and Logout URLs](#generating-login-and-logout-urls)
  - [Conditional Rendering Components](#conditional-rendering-components)
  - [Refreshing Access Tokens](#refreshing-access-tokens)
- [License](#license)

## Leptos compatibility

| Crate version | Compatible Leptos version |
|---------------|---------------------------|
| <= 0.3        | 0.5                       |
| 0.4           | 0.6                       |

## Features

**leptos_oidc** offers the following features:

- Initialization of the OIDC authentication process.
- Generation of login and logout URLs for redirecting users to OIDC providers (e.g., Keycloak).
- Conditional rendering of components based on the authentication state.
- Refreshing access tokens and storing them in local storage.
- Working with client and server side rendering

### Missing Features

- Refetch access token periodically/automatically in the background
- Some minor code refactoring/cleanup

### Tested Backends with Example

**leptos_oidc** was tested with various backends. This doesn't mean that other
backends are not supported. Every backend which is support `oidc` should work.
But feel free to ask for advice or give feedback!

Tested backends:
- [KeyCloak](https://github.com/keycloak/keycloak)
- [rauthy](https://github.com/sebadob/rauthy/)

You can find a setup guide for the backends under [docs/backends](docs/backends/README.md).

#### Keycloak

#### Rauthy

## Installation

To use **leptos_oidc** in your Leptos-based application, add it as a dependency
in your `Cargo.toml` file:

```toml
[dependencies]
leptos_oidc = "0.2"
```

Note: This needs at least `leptos v0.5`.

## Usage

### Initialization and Example

To get started with OIDC authentication, initialize the library with the
required authentication parameters. You can use the `AuthParameters` struct
to specify the OIDC endpoints, client ID, redirect URIs, and other relevant
information.

```rust
use leptos::*;
use leptos_oidc::{Auth, AuthParameters};

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();

    view! {
        <Stylesheet id="leptos" href="/pkg/main.css"/>

        <Link rel="shortcut icon" type_="image/ico" href="/favicon.ico"/>

        <Router>
            <AppWithRouter/>
        </Router>
    }
}

#[component]
pub fn AppWithRouter() -> impl IntoView {
    // Specify OIDC authentication parameters here.
    // Note: This is an example for keycloak, please change it to your needs
    let auth_parameters = AuthParameters {
        auth_endpoint: "https://ENDPOINT/auth/realms/REALM/protocol/openid-connect/auth".to_string(),
        token_endpoint: "https://ENDPOINT/auth/realms/REALM/protocol/openid-connect/token".to_string(),
        logout_endpoint: "https://ENDPOINT/auth/realms/REALM/protocol/openid-connect/logout".to_string(),
        client_id: "CLIENT_ID".to_string(),
        redirect_uri: "http://localhost:3000/profile".to_string(),
        post_logout_redirect_uri: "http://localhost:3000/bye".to_string(),
        scope: Some("openid"),
    };
    let auth = Auth::init(auth_parameters);

    provide_context(NavbarSignal::new());

    view! {
        // This is an example for a navbar where you have a login and logout
        // button, based on the state.
        <div>
            <Authenticated unauthenticated=move || {
                view! {
                    <LoginLink class="text-login">Sign in</LoginLink>
                }
            }>
                <LogoutLink class="text-logut">Sign Out</LogoutLink>
            </Authenticated>
        </div>

        <Routes>
            <Route path="/" view=move || view! { <Home/> }/>

            // This is an example route for your profile, it will render
            // loading if it's still loading, render unauthenticated if it's
            // unauthenticated and it will render the children, if it's
            // authenticated
            <Route
                path="/profile"
                view=move || {
                    view! {
                        <Authenticated
                            loading=move || view! { <Loading/> }
                            unauthenticated=move || view! { <Unauthenticated/> }
                        >
                            <Profile/>
                        </Authenticated>
                    }
                }
            />
        </Routes>
    }
}

#[component]
pub fn Home() -> impl IntoView {
    let auth = expect_context::<Auth>();

    view! {
        <Title text="Home"/>
        <h1>Home</h1>

        // Your Pome Page without authentication
    }
}

/// This will be rendered, if the authentication library is still loading
#[component]
pub fn Loading() -> impl IntoView {
    view! {
        <Title text="Loading"/>
        <h1>Loading</h1>

        // Your Loading Page/Animation
    }
}

/// This will be rendered, if the user is unauthenticated
#[component]
pub fn Unauthenticated() -> impl IntoView {
    view! {
        <Title text="Unauthenticated"/>
        <h1>Unauthenticated</h1>

        // Your Unauthenticated Page
    }
}

/// This will be rendered, if the user is authentication
#[component]
pub fn Profile() -> impl IntoView {
    view! {
        <Title text="Profile"/>
        <h1>Profile</h1>

        // Your Profile Page
    }
}
```

Note: Please keep in mind that the `Auth::init` needs to be `inside a Router`.
The internal state is using `use_query`, which is only available inside a
`Router`.

### Generating Login and Logout URLs

**leptos_oidc** provides functions to generate login and logout URLs for your
application. These URLs are used to redirect users to the OIDC provider for
authentication and logout.

```rust
use leptos::*;
use leptos_oidc::Auth;

#[component]
fn MyComponent() {
    let auth = expect_context::<Auth>();

    // Generate the login URL to initiate the authentication process.
    let login_url = move || auth.login_url();

    // Generate the logout URL for logging out the user.
    let logout_url = move || auth.logout_url();
}
```

### Conditional Rendering Components

The library includes transparent components to conditionally render content
based on the authentication state. These components simplify the user interface
when dealing with authenticated and unauthenticated users.

```rust
use leptos::*;
use leptos_oidc::Auth;

#[component]
fn MyComponent() {

    view! {
        // Generate Sign In link
        <LoginLink class="optional-class-attributes">Sign in</LoginLink>

        // Generate Sign Out link
        <LogoutLink class="optional-class-attributes">Sign Out</LogoutLink>

        <AuthLoaded>"This will be rendered only when the auth library is not loading anymore"</AuthLoaded>

        <AuthLoading>"This will be rendered only when the auth library is still loading"</AuthLoading>

        <Authenticated>"This will only be rendered if the user is authenticated"</Authenticated>

        // A more complex example with optional fallbacks for the loading and unauthenticated state
        <Authenticated
            unauthenticated=move || view! { "this will only be renderd if the user is unauthenticated" }
            loading=move || view! { "this will only be renderd if the library is still loading" }
            >
                "This will only be rendered if the user is authenticated"
        </Authenticated>
    }
}
```

### Refreshing Access Tokens

**leptos_oidc** offers the ability to refresh access tokens. This functionality
is essential for ensuring that authenticated users maintain their access rights.
Refreshed tokens are stored in local storage.

```rust
use leptos::*;
use leptos_oidc::Auth;

#[component]
fn main() {
    let auth = expect_context::<Auth>();

    view! {
        // Refresh the access token and get the new token.
        <button on:click=move |_| auth.refresh_token() class="text-black dark:text-white">
            Refresh Token
        </button>
    }
}
```

## License

**leptos_oidc** is distributed under the [MIT License](https://opensource.org/licenses/MIT).
For more information, see the [LICENSE](https://gitlab.com/kerkmann/leptos_oidc/blob/main/LICENSE) file.
