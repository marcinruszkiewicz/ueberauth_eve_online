# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2024-12-27

### Fixed
- **CRITICAL BUG FIX**: OAuth state parameter validation now works around upstream Ueberauth library bug
  - Added fallback mechanism to read state parameter from cookies when `conn.private[:ueberauth_state_param]` is `nil`
  - Prevents false "Invalid state parameter. Possible CSRF attack." errors during OAuth callback
  - Maintains full CSRF protection while fixing authentication failures
  - This resolves an issue where all EVE SSO OAuth flows would fail despite correct state parameters

### Added
- Comprehensive test coverage for state parameter validation scenarios:
  - Tests for correct state parameter validation
  - Tests for cookie fallback mechanism when private state param is nil
  - Tests for preferring private state param over cookie when both are present
  - Tests for failure cases with mismatched state parameters
  - Tests for edge cases with no state sources available

### Technical Details
- The fix works around a bug in Ueberauth core library's `get_state_cookie/1` function
- When `conn.private[:ueberauth_state_param]` is `nil`, the strategy now reads directly from `conn.req_cookies["ueberauth.state_param"]`
- This preserves the original OAuth2 security model while providing a robust workaround
- No breaking changes to existing API or configuration

### Security
- Maintains CSRF protection integrity
- Does not weaken security model - only provides alternative state validation path
- Fallback mechanism only activates when primary method fails due to upstream bug

## [1.0.0] - 2024-01-01

### Added
- Initial release of Ueberauth EVE Online strategy
- Support for EVE SSO v2 authentication
- Configurable UID fields (owner_hash, character_id, name)
- Configurable OAuth2 scopes
- Comprehensive error handling for OAuth2 flows
- Support for token refresh
- Network error handling with user-friendly messages
- Full test coverage
- Complete documentation
