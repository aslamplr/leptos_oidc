# Changelog

This is containing every changes, there are and there will be some bugs. But
tackling them down and documenting them will hopefully help you out. :)

## v0.3.0

- Add capability to decode the access token inside this crate 

## v0.2.2

- Fix `when reloading page and refresh_expires_in is null token is removed` #2

## v0.2.1

- Fix `crash when converting from SucessTokenResponse to TokenStorage` #1

## v0.2.0

- Add rauthy support
- Set fields like `refresh_expires_in` as optional
- Set clippy to pedantic in pipeline
- Add KeyCloak and rauthy backend example in the README.md
- Add CHANGELOG.md

## v0.1.1

- Add missing `use import` in the README.md example
- Fix endpoints in the example in the README.md

## v0.1.0

This is the initial release of a working POC, it's not perfect, but working. :)
