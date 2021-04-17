## v0.13.0 - 2021-04-17

### Changed
- Switch from `isomorphic-fetch` to `cross-fetch` library (fixes weird 
  downstream error during `discover()`).

## v0.12.0-v0.12.4 - 2021-01-13

### Added
- Implement PKCE.

### Changed
- Switch webpack excludes from webpack.config to package.json.
- Use universal-base64 lib.

## v0.11.0 - 2019-11-14

### Changed
- Major refactor to use es7 async/await.

## v0.10.0 - 2019-11-08

### Changed
- (BREAKING) Moved package.json `main:` to `src/` instead of `lib/` (no longer
  transpiling to ES5).
- Remove dependency on `json-document`.
- Update `@solid/jose` dependency to `v0.5.0`.
- Updated various other dependencies to latest.

## v0.8.0-v0.9.0 - 2018-10-25

### Added
- Send credentials on logout.
- Misc fixes.

## v0.7.1 - 2018-08-28

- Forked into the Solid github org.
