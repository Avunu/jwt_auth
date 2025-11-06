# JWT Auth Testing Suite

This directory contains comprehensive tests for the JWT Auth Frappe app, covering all doctypes, functions, and API interactions.

## Test Structure

### 1. Doctype Tests
- `jwt_auth/jwt_auth/doctype/jwt_auth_settings/test_jwt_auth_settings.py`
  - Unit tests for JWT Auth Settings doctype
  - Integration tests for settings persistence and validation
  - Tests for mandatory field validation and default values

### 2. Core Functionality Tests
- `tests/test_auth.py`
  - Unit tests for `JWTAuth` class methods
  - Unit tests for `SessionJWTAuth` class
  - Unit tests for utility functions (jwt_logout, on_logout, web_logout, etc.)
  - Integration tests for complete authentication flow

### 3. Provider Tests
- `tests/test_providers.py`
  - Unit tests for `BaseProvider` class
  - Unit tests for `CloudflareAccessProvider` class
  - Integration tests for provider functionality with real settings
  - Tests for URL generation and public key retrieval

### 4. Hooks Tests
- `tests/test_hooks.py`
  - Unit tests for contact hooks (`on_update` function)
  - Unit tests for error page hooks (`JWTAuthErrorPage` class)
  - Integration tests for hooks with real Frappe documents

### 5. Cloudflare Access Simulation Tests
- `tests/test_cloudflare_simulation.py`
  - Comprehensive simulation of Cloudflare Access API interactions
  - Mock JWT token validation with various scenarios
  - Complete authentication flow testing without external calls
  - Error handling and edge case testing

### 6. Test Utilities
- `tests/test_utils.py`
  - Mock classes for common objects (MockCloudflareAccess, MockJWTAuthSettings, etc.)
  - Helper functions for creating test data
  - Common assertions for Cloudflare URL validation
  - Test data constants

## Test Coverage

### Functions Tested
- **auth.py**: All functions and class methods
  - `JWTAuth.__init__()`, `auth()`, `validate_auth()`, `can_auth()`, `update()`
  - `get_login_url()`, `get_logout_url()`, `get_public_keys()`, `get_token()`, `is_valid_token()`, `register_user()`
  - `SessionJWTAuth.__init__()`, `__getattr__()`
  - `handle_redirects()`, `jwt_logout()`, `on_logout()`, `web_logout()`, `validate_auth()`

- **providers.py**: All provider classes and methods
  - `BaseProvider.__init__()`, properties, `get_public_keys()`
  - `CloudflareAccessProvider.__init__()`, properties, `get_jwks_url()`, `get_login_url()`, `get_logout_url()`

- **hooks/contact.py**: Contact update hooks
  - `on_update()` function with all scenarios

- **hooks/error_page.py**: Error page handling
  - `JWTAuthErrorPage.__init__()`, `can_render()`, `init_context()`

### Doctypes Tested
- **JWT Auth Settings**: Creation, validation, persistence, password fields

### API Testing
- **Cloudflare Access Integration**: Complete simulation without external calls
  - JWKS endpoint responses
  - JWT token validation (valid, expired, invalid audience)
  - Login/logout URL generation
  - User registration flow
  - Error handling

## Running Tests

### Using Frappe Test Runner
```bash
# Run all tests
bench --site [site-name] run-tests --app jwt_auth

# Run specific test file
bench --site [site-name] run-tests jwt_auth.jwt_auth.doctype.jwt_auth_settings.test_jwt_auth_settings

# Run specific test class
bench --site [site-name] run-tests jwt_auth.tests.test_auth.TestJWTAuthUnit

# Run with verbose output
bench --site [site-name] run-tests --app jwt_auth --verbose
```

### Using pytest (if available)
```bash
# Run all tests
pytest jwt_auth/tests/

# Run specific test file
pytest jwt_auth/tests/test_auth.py

# Run with coverage
pytest jwt_auth/tests/ --cov=jwt_auth
```

## Test Design Principles

### 1. Frappe Conventions
- Uses `frappe.tests.UnitTestCase` for unit tests
- Uses `frappe.tests.IntegrationTestCase` for integration tests
- Follows Frappe naming conventions and patterns
- Properly handles test record dependencies

### 2. No External Dependencies
- All external API calls are mocked
- Cloudflare Access interactions are simulated
- No actual network requests are made during testing
- JWT token validation uses mock keys and payloads

### 3. Comprehensive Coverage
- Tests all public methods and functions
- Tests both success and failure scenarios
- Tests edge cases and error conditions
- Tests integration between components

### 4. Isolation and Cleanup
- Each test is isolated and doesn't affect others
- Proper setup and teardown methods
- Test data is cleaned up after each test
- Mock objects are reset between tests

## Mock Strategy

### External APIs
- **Cloudflare JWKS endpoint**: Mocked with realistic response structure
- **JWT token validation**: Mocked with various token scenarios
- **Network requests**: All `requests.get()` calls are mocked

### Frappe Framework
- **frappe.local**: Mocked for request/session simulation
- **frappe.db**: Mocked for database operations
- **frappe.cache**: Mocked for caching operations
- **Document operations**: Mocked for create/read/update/delete

### JWT Library
- **jwt.decode()**: Mocked to return various claim scenarios
- **jwt.algorithms.RSAAlgorithm**: Mocked for key handling
- **JWT exceptions**: Simulated for error testing

## Test Data

### Valid JWT Claims
```python
{
    "aud": ["test-secret"],
    "email": "test@example.com",
    "exp": <future_timestamp>,
    "iat": <current_timestamp>,
    "iss": "https://test-team.cloudflareaccess.com",
    "sub": "1234567890",
    "common_name": "test@example.com"
}
```

### Cloudflare JWKS Response
```python
{
    "keys": [
        {
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "kid": "cloudflare-key-1",
            "n": "example_n_parameter",
            "e": "AQAB"
        }
    ]
}
```

## Test Scenarios Covered

### Authentication Flow
1. Valid JWT token authentication
2. Expired JWT token handling
3. Invalid audience token handling
4. Missing token scenarios
5. User registration with/without existing contacts
6. Login/logout redirects

### Provider Integration
1. Cloudflare URL generation
2. JWKS key retrieval
3. Multiple key handling
4. Network error handling
5. URL encoding edge cases

### Settings Validation
1. Mandatory field validation
2. Conditional field requirements
3. Password field handling
4. Default value verification

### Hooks Functionality
1. Contact field synchronization
2. Contact renaming logic
3. User profile updates
4. Error page rendering

## Contributing

When adding new functionality to JWT Auth:

1. **Add corresponding tests** for new functions/methods
2. **Update existing tests** if changing behavior
3. **Add mock scenarios** for new external dependencies
4. **Test both success and failure paths**
5. **Follow existing naming conventions**
6. **Add docstrings** explaining test purpose
7. **Update this README** if adding new test categories

## Common Test Patterns

### Mocking External Calls
```python
@patch('jwt_auth.auth.requests.get')
def test_external_api(self, mock_requests):
    mock_requests.return_value.json.return_value = {...}
    # Test implementation
```

### Testing JWT Validation
```python
@patch('jwt_auth.auth.jwt.decode')
def test_jwt_validation(self, mock_jwt_decode):
    mock_jwt_decode.return_value = {'email': 'test@example.com'}
    # Test implementation
```

### Testing Frappe Documents
```python
def test_document_operation(self):
    doc = frappe.get_doc('DocType', 'name')
    # Modify doc
    doc.save()
    # Assert changes
```