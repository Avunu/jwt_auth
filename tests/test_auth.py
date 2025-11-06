# Copyright (c) 2024, Avunu LLC and Contributors
# See license.txt

import json
import jwt
from unittest.mock import Mock, patch, MagicMock
from urllib.parse import quote

import frappe
from frappe.tests import IntegrationTestCase, UnitTestCase

from jwt_auth.auth import JWTAuth, SessionJWTAuth, handle_redirects, jwt_logout, on_logout, web_logout, validate_auth


class TestJWTAuthUnit(UnitTestCase):
	"""Unit tests for JWTAuth class methods."""

	def setUp(self):
		"""Set up test environment."""
		# Mock settings
		self.mock_settings = Mock()
		self.mock_settings.enabled = True
		self.mock_settings.enable_user_reg = True
		self.mock_settings.enable_login = True
		self.mock_settings.jwt_header = 'Cf-Access-Token'
		self.mock_settings.jwks_url = 'https://test.cloudflareaccess.com/cdn-cgi/access/certs'
		self.mock_settings.login_url = 'https://test.cloudflareaccess.com/cdn-cgi/access/login/test'
		self.mock_settings.logout_url = 'https://test.cloudflareaccess.com/cdn-cgi/access/logout'
		self.mock_settings.redirect_param = 'redirect_url'
		self.mock_settings.get_password.return_value = 'test-secret'

	@patch('jwt_auth.auth.frappe.get_cached_doc')
	def test_jwt_auth_initialization(self, mock_get_cached_doc):
		"""Test JWTAuth initialization."""
		mock_get_cached_doc.return_value = self.mock_settings
		
		auth = JWTAuth('/test/path', 200)
		
		self.assertEqual(auth.path, '/test/path')
		self.assertEqual(auth.http_status_code, 200)
		self.assertEqual(auth.settings, self.mock_settings)
		self.assertIsNone(auth.claims)
		self.assertIsNone(auth.user_email)
		self.assertIsNone(auth.token)
		self.assertIsNone(auth.redirect_to)

	@patch('jwt_auth.auth.frappe.get_cached_doc')
	def test_update_method(self, mock_get_cached_doc):
		"""Test the update method."""
		mock_get_cached_doc.return_value = self.mock_settings
		
		auth = JWTAuth()
		auth.update('/new/path', 404)
		
		self.assertEqual(auth.path, '/new/path')
		self.assertEqual(auth.http_status_code, 404)

	@patch('jwt_auth.auth.frappe.get_cached_doc')
	def test_get_login_url_without_redirect(self, mock_get_cached_doc):
		"""Test get_login_url without redirect parameter."""
		mock_get_cached_doc.return_value = self.mock_settings
		
		auth = JWTAuth()
		login_url = auth.get_login_url()
		
		expected_url = 'https://test.cloudflareaccess.com/cdn-cgi/access/login/test'
		self.assertEqual(login_url, expected_url)

	@patch('jwt_auth.auth.frappe.get_cached_doc')
	def test_get_login_url_with_redirect(self, mock_get_cached_doc):
		"""Test get_login_url with redirect parameter."""
		mock_get_cached_doc.return_value = self.mock_settings
		
		auth = JWTAuth('/test/path')
		login_url = auth.get_login_url('/dashboard')
		
		expected_path = '%2F' + quote('/dashboard', safe='')
		expected_url = f'https://test.cloudflareaccess.com/cdn-cgi/access/login/test?redirect_url={expected_path}'
		self.assertEqual(login_url, expected_url)

	@patch('jwt_auth.auth.frappe.get_cached_doc')
	@patch('jwt_auth.auth.frappe.local')
	def test_get_logout_url(self, mock_local, mock_get_cached_doc):
		"""Test get_logout_url method."""
		mock_get_cached_doc.return_value = self.mock_settings
		mock_local.request.url = 'https://example.com/dashboard'
		
		auth = JWTAuth()
		logout_url = auth.get_logout_url()
		
		expected_url = 'https://test.cloudflareaccess.com/cdn-cgi/access/logout?redirect_url=https://example.com/dashboard'
		self.assertEqual(logout_url, expected_url)

	@patch('jwt_auth.auth.frappe.get_cached_doc')
	@patch('jwt_auth.auth.requests.get')
	def test_get_public_keys(self, mock_requests_get, mock_get_cached_doc):
		"""Test get_public_keys method."""
		mock_get_cached_doc.return_value = self.mock_settings
		
		# Mock JWKS response
		mock_jwks_response = {
			"keys": [
				{
					"kty": "RSA",
					"kid": "test-key-id",
					"use": "sig",
					"alg": "RS256",
					"n": "test-n-value",
					"e": "AQAB"
				}
			]
		}
		mock_requests_get.return_value.json.return_value = mock_jwks_response
		
		with patch('jwt_auth.auth.jwt.algorithms.RSAAlgorithm.from_jwk') as mock_from_jwk:
			mock_public_key = Mock()
			mock_from_jwk.return_value = mock_public_key
			
			auth = JWTAuth()
			public_keys = auth.get_public_keys()
			
			self.assertEqual(len(public_keys), 1)
			self.assertEqual(public_keys[0], mock_public_key)
			mock_requests_get.assert_called_once_with(self.mock_settings.jwks_url)

	@patch('jwt_auth.auth.frappe.get_cached_doc')
	def test_get_token_from_cookie(self, mock_get_cached_doc):
		"""Test get_token method with token in cookie."""
		mock_get_cached_doc.return_value = self.mock_settings
		
		mock_request = Mock()
		mock_request.cookies.get.return_value = 'test-jwt-token'
		mock_request.headers.get.return_value = None
		
		auth = JWTAuth()
		token = auth.get_token(mock_request)
		
		self.assertEqual(token, 'test-jwt-token')
		mock_request.cookies.get.assert_called_once_with('Cf-Access-Token')

	@patch('jwt_auth.auth.frappe.get_cached_doc')
	def test_get_token_from_header(self, mock_get_cached_doc):
		"""Test get_token method with token in header."""
		mock_get_cached_doc.return_value = self.mock_settings
		
		mock_request = Mock()
		mock_request.cookies.get.return_value = None
		mock_request.headers.get.return_value = 'test-jwt-token'
		
		auth = JWTAuth()
		token = auth.get_token(mock_request)
		
		self.assertEqual(token, 'test-jwt-token')
		mock_request.headers.get.assert_called_once_with('Cf-Access-Token')

	@patch('jwt_auth.auth.frappe.get_cached_doc')
	def test_get_token_not_found(self, mock_get_cached_doc):
		"""Test get_token method when token is not found."""
		mock_get_cached_doc.return_value = self.mock_settings
		
		mock_request = Mock()
		mock_request.cookies.get.return_value = None
		mock_request.headers.get.return_value = None
		
		auth = JWTAuth()
		token = auth.get_token(mock_request)
		
		self.assertIsNone(token)

	@patch('jwt_auth.auth.frappe.get_cached_doc')
	def test_is_valid_token_success(self, mock_get_cached_doc):
		"""Test is_valid_token method with valid token."""
		mock_get_cached_doc.return_value = self.mock_settings
		
		# Mock JWT decode success
		mock_claims = {'email': 'test@example.com', 'sub': '12345'}
		mock_public_key = Mock()
		
		with patch.object(JWTAuth, 'get_public_keys', return_value=[mock_public_key]):
			with patch('jwt_auth.auth.jwt.decode', return_value=mock_claims):
				auth = JWTAuth()
				result = auth.is_valid_token('test-token')
				
				self.assertTrue(result)
				self.assertEqual(auth.claims, mock_claims)

	@patch('jwt_auth.auth.frappe.get_cached_doc')
	def test_is_valid_token_failure(self, mock_get_cached_doc):
		"""Test is_valid_token method with invalid token."""
		mock_get_cached_doc.return_value = self.mock_settings
		
		mock_public_key = Mock()
		
		with patch.object(JWTAuth, 'get_public_keys', return_value=[mock_public_key]):
			with patch('jwt_auth.auth.jwt.decode', side_effect=jwt.InvalidTokenError):
				auth = JWTAuth()
				result = auth.is_valid_token('invalid-token')
				
				self.assertFalse(result)

	@patch('jwt_auth.auth.frappe.get_cached_doc')
	def test_can_auth_conditions(self, mock_get_cached_doc):
		"""Test can_auth method various conditions."""
		mock_get_cached_doc.return_value = self.mock_settings
		
		with patch('jwt_auth.auth.frappe.local') as mock_local:
			mock_local.session.user = 'Guest'
			mock_local.request = Mock()
			
			auth = JWTAuth()
			
			# Test redirect_to condition
			auth.redirect_to = '/somewhere'
			self.assertFalse(auth.can_auth())
			
			# Test authenticated user condition
			auth.redirect_to = None
			mock_local.session.user = 'test@example.com'
			self.assertFalse(auth.can_auth())
			
			# Test disabled settings condition
			mock_local.session.user = 'Guest'
			self.mock_settings.enabled = False
			self.assertFalse(auth.can_auth())
			
			# Test jwt_logout_redirect flag
			self.mock_settings.enabled = True
			with patch('jwt_auth.auth.frappe.flags.get', return_value=True):
				self.assertFalse(auth.can_auth())

	@patch('jwt_auth.auth.frappe.get_cached_doc')
	@patch('jwt_auth.auth.frappe.db')
	@patch('jwt_auth.auth.frappe.get_doc')
	def test_register_user_with_contact(self, mock_get_doc, mock_db, mock_get_cached_doc):
		"""Test register_user method when contact exists."""
		mock_get_cached_doc.return_value = self.mock_settings
		
		# Mock contact exists
		mock_db.get_value.return_value = 'Contact-001'
		
		# Mock contact document
		mock_contact = Mock()
		mock_contact.first_name = 'John'
		mock_contact.last_name = 'Doe'
		mock_contact.full_name = 'John Doe'
		mock_contact.phone = '123-456-7890'
		mock_contact.mobile_no = '987-654-3210'
		mock_contact.gender = 'Male'
		mock_contact.company_name = 'Test Company'
		mock_contact.middle_name = None
		
		# Mock user document
		mock_user = Mock()
		
		mock_get_doc.side_effect = [mock_contact, mock_user]
		
		with patch('jwt_auth.auth.frappe.db.commit'):
			auth = JWTAuth()
			auth.register_user('test@example.com')
			
			# Verify user document creation
			user_doc_args = mock_get_doc.call_args_list[1][0][0]
			self.assertEqual(user_doc_args['doctype'], 'User')
			self.assertEqual(user_doc_args['email'], 'test@example.com')
			self.assertEqual(user_doc_args['first_name'], 'John')
			self.assertEqual(user_doc_args['last_name'], 'Doe')
			
			# Verify contact is linked to user
			mock_contact.save.assert_called_once_with(ignore_permissions=True)
			mock_user.insert.assert_called_once_with(ignore_permissions=True)

	@patch('jwt_auth.auth.frappe.get_cached_doc')
	@patch('jwt_auth.auth.frappe.db')
	@patch('jwt_auth.auth.frappe.get_doc')
	def test_register_user_without_contact(self, mock_get_doc, mock_db, mock_get_cached_doc):
		"""Test register_user method when contact doesn't exist."""
		mock_get_cached_doc.return_value = self.mock_settings
		
		# Mock no contact exists
		mock_db.get_value.return_value = None
		
		# Mock user document
		mock_user = Mock()
		mock_get_doc.return_value = mock_user
		
		with patch('jwt_auth.auth.frappe.db.commit'):
			auth = JWTAuth()
			auth.register_user('test@example.com')
			
			# Verify user document creation
			user_doc_args = mock_get_doc.call_args[0][0]
			self.assertEqual(user_doc_args['doctype'], 'User')
			self.assertEqual(user_doc_args['email'], 'test@example.com')
			self.assertEqual(user_doc_args['first_name'], '[Change Me]')
			
			# Verify redirect is set for profile update
			self.assertEqual(auth.redirect_to, '/update-profile/test@example.com/edit')
			
			mock_user.insert.assert_called_once_with(ignore_permissions=True)


class TestSessionJWTAuthUnit(UnitTestCase):
	"""Unit tests for SessionJWTAuth class."""

	@patch('jwt_auth.auth.frappe.local')
	def test_session_jwt_auth_initialization(self, mock_local):
		"""Test SessionJWTAuth initialization."""
		mock_local.jwt_auth = None
		
		with patch('jwt_auth.auth.JWTAuth') as mock_jwt_auth:
			mock_jwt_auth_instance = Mock()
			mock_jwt_auth.return_value = mock_jwt_auth_instance
			
			session_auth = SessionJWTAuth('/test', 200)
			
			mock_jwt_auth.assert_called_once_with('/test', 200)
			self.assertEqual(mock_local.jwt_auth, mock_jwt_auth_instance)

	@patch('jwt_auth.auth.frappe.local')
	def test_session_jwt_auth_reuse_existing(self, mock_local):
		"""Test SessionJWTAuth reuses existing instance."""
		mock_existing_auth = Mock()
		mock_local.jwt_auth = mock_existing_auth
		
		session_auth = SessionJWTAuth('/new', 404)
		
		mock_existing_auth.update.assert_called_once_with('/new', 404)

	@patch('jwt_auth.auth.frappe.local')
	def test_session_jwt_auth_getattr(self, mock_local):
		"""Test SessionJWTAuth __getattr__ delegation."""
		mock_jwt_auth = Mock()
		mock_jwt_auth.test_method.return_value = 'test_result'
		mock_local.jwt_auth = mock_jwt_auth
		
		session_auth = SessionJWTAuth()
		result = session_auth.test_method()
		
		self.assertEqual(result, 'test_result')
		mock_jwt_auth.test_method.assert_called_once()


class TestUtilityFunctionsUnit(UnitTestCase):
	"""Unit tests for utility functions."""

	@patch('jwt_auth.auth.SessionJWTAuth')
	@patch('jwt_auth.auth.frappe.local')
	def test_jwt_logout(self, mock_local, mock_session_jwt_auth):
		"""Test jwt_logout function."""
		mock_auth = Mock()
		mock_auth.settings.enabled = True
		mock_auth.get_logout_url.return_value = 'https://logout.url'
		mock_session_jwt_auth.return_value = mock_auth
		
		mock_login_manager = Mock()
		mock_local.login_manager = mock_login_manager
		
		result = jwt_logout()
		
		mock_login_manager.logout.assert_called_once()
		self.assertEqual(result, {'redirect_url': 'https://logout.url'})

	@patch('jwt_auth.auth.SessionJWTAuth')
	@patch('jwt_auth.auth.frappe.local')
	def test_jwt_logout_disabled(self, mock_local, mock_session_jwt_auth):
		"""Test jwt_logout function when JWT auth is disabled."""
		mock_auth = Mock()
		mock_auth.settings.enabled = False
		mock_session_jwt_auth.return_value = mock_auth
		
		mock_login_manager = Mock()
		mock_local.login_manager = mock_login_manager
		
		result = jwt_logout()
		
		mock_login_manager.logout.assert_called_once()
		self.assertEqual(result, {'redirect_url': '/login'})

	@patch('jwt_auth.auth.SessionJWTAuth')
	@patch('jwt_auth.auth.frappe.flags')
	def test_on_logout(self, mock_flags, mock_session_jwt_auth):
		"""Test on_logout function."""
		mock_auth = Mock()
		mock_auth.get_logout_url.return_value = 'https://logout.url'
		mock_session_jwt_auth.return_value = mock_auth
		
		on_logout()
		
		mock_flags.__setitem__.assert_called_once_with('jwt_logout_redirect', 'https://logout.url')

	@patch('jwt_auth.auth.SessionJWTAuth')
	@patch('jwt_auth.auth.frappe.local')
	def test_web_logout(self, mock_local, mock_session_jwt_auth):
		"""Test web_logout function."""
		mock_auth = Mock()
		mock_auth.settings.enabled = True
		mock_auth.get_logout_url.return_value = 'https://logout.url'
		mock_session_jwt_auth.return_value = mock_auth
		
		mock_login_manager = Mock()
		mock_local.login_manager = mock_login_manager
		mock_local.response = {}
		
		web_logout()
		
		mock_login_manager.logout.assert_called_once()
		self.assertEqual(mock_local.response['type'], 'redirect')
		self.assertEqual(mock_local.response['location'], 'https://logout.url')

	@patch('jwt_auth.auth.SessionJWTAuth')
	def test_validate_auth(self, mock_session_jwt_auth):
		"""Test validate_auth function."""
		mock_auth = Mock()
		mock_session_jwt_auth.return_value = mock_auth
		
		validate_auth()
		
		mock_auth.validate_auth.assert_called_once()

	@patch('jwt_auth.auth.frappe.session')
	@patch('jwt_auth.auth.frappe.flags')
	def test_handle_redirects_logout_redirect(self, mock_flags, mock_session):
		"""Test handle_redirects with logout redirect."""
		mock_response = Mock()
		mock_request = Mock()
		
		mock_session.get.return_value = 'Guest'
		mock_flags.get.return_value = 'https://logout.url'
		mock_flags.pop.return_value = 'https://logout.url'
		
		handle_redirects(mock_response, mock_request)
		
		self.assertEqual(mock_response.status_code, 302)
		self.assertEqual(mock_response.headers['Location'], 'https://logout.url')

	@patch('jwt_auth.auth.frappe.session')
	@patch('jwt_auth.auth.frappe.cache')
	def test_handle_redirects_auth_redirect(self, mock_cache, mock_session):
		"""Test handle_redirects with auth redirect."""
		mock_response = Mock()
		mock_request = Mock()
		mock_request.path = '/dashboard'
		
		mock_session.get.return_value = 'test@example.com'
		mock_session.data = {'jwt_auth_redirect': '/dashboard'}
		
		with patch('jwt_auth.auth.frappe.flags.get', return_value=False):
			handle_redirects(mock_response, mock_request)
			
			self.assertEqual(mock_response.status_code, 302)
			self.assertEqual(mock_response.headers['Location'], '/dashboard')

	@patch('jwt_auth.auth.frappe.session')
	@patch('jwt_auth.auth.frappe.cache')
	def test_handle_redirects_cache_redirect(self, mock_cache, mock_session):
		"""Test handle_redirects with cache-based redirect."""
		mock_response = Mock()
		mock_request = Mock()
		mock_request.path = '/me'
		
		mock_session.get.return_value = 'test@example.com'
		mock_session.user = 'test@example.com'
		mock_session.data = {}
		
		mock_cache_instance = Mock()
		mock_cache_instance.get_value.return_value = '/original/location'
		mock_cache.return_value = mock_cache_instance
		
		with patch('jwt_auth.auth.frappe.flags.get', return_value=False):
			handle_redirects(mock_response, mock_request)
			
			self.assertEqual(mock_response.status_code, 302)
			self.assertEqual(mock_response.headers['Location'], '/original/location')
			mock_cache_instance.delete_value.assert_called_once()


class TestJWTAuthIntegration(IntegrationTestCase):
	"""Integration tests for JWT authentication flow."""

	def setUp(self):
		"""Set up test environment."""
		# Create test JWT Auth Settings
		try:
			self.settings = frappe.get_doc("JWT Auth Settings")
		except frappe.DoesNotExistError:
			self.settings = frappe.new_doc("JWT Auth Settings")
		
		self.settings.update({
			'enabled': 1,
			'enable_user_reg': 1,
			'enable_login': 1,
			'jwt_header': 'Cf-Access-Token',
			'jwks_url': 'https://test.cloudflareaccess.com/cdn-cgi/access/certs',
			'jwt_private_secret': 'test-secret',
			'login_url': 'https://test.cloudflareaccess.com/cdn-cgi/access/login/test',
			'logout_url': 'https://test.cloudflareaccess.com/cdn-cgi/access/logout',
			'redirect_param': 'redirect_url'
		})
		self.settings.save()

	def test_full_authentication_flow(self):
		"""Test complete authentication flow."""
		# Mock external dependencies
		with patch('jwt_auth.auth.requests.get') as mock_requests:
			with patch('jwt_auth.auth.jwt.decode') as mock_jwt_decode:
				with patch('jwt_auth.auth.frappe.local') as mock_local:
					# Setup mocks
					mock_requests.return_value.json.return_value = {
						"keys": [{"kty": "RSA", "kid": "test", "use": "sig", "alg": "RS256", "n": "test", "e": "AQAB"}]
					}
					mock_jwt_decode.return_value = {'email': 'test@example.com'}
					
					mock_local.session.user = 'Guest'
					mock_local.request = Mock()
					mock_local.request.cookies.get.return_value = 'test-jwt-token'
					mock_local.request.headers.get.return_value = None
					
					# Test authentication
					auth = JWTAuth()
					
					with patch.object(auth, 'get_public_keys', return_value=[Mock()]):
						can_auth = auth.can_auth()
						self.assertTrue(can_auth)
						self.assertEqual(auth.token, 'test-jwt-token')

	def tearDown(self):
		"""Clean up after tests."""
		# Reset settings
		self.settings.enabled = 0
		self.settings.enable_user_reg = 0
		self.settings.enable_login = 0
		self.settings.save()