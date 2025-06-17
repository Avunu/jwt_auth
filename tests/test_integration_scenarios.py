# Copyright (c) 2024, Avunu LLC and Contributors
# See license.txt

"""
Integration test demonstrating the complete JWT Auth testing approach.
This file shows how all components work together in a realistic scenario.
"""

import json
import jwt
import time
from unittest.mock import Mock, patch, MagicMock

import frappe
from frappe.tests import IntegrationTestCase

from jwt_auth.auth import JWTAuth, SessionJWTAuth
from jwt_auth.providers import CloudflareAccessProvider
from jwt_auth.tests.test_utils import MockCloudflareAccess, MockJWTAuthSettings, create_mock_request


class TestJWTAuthFullIntegration(IntegrationTestCase):
	"""Full integration test demonstrating complete JWT Auth workflow."""

	def setUp(self):
		"""Set up a complete test environment."""
		# Create test settings
		try:
			self.settings = frappe.get_doc("JWT Auth Settings")
		except frappe.DoesNotExistError:
			self.settings = frappe.new_doc("JWT Auth Settings")
		
		# Configure settings for Cloudflare Access
		self.team_name = 'integration-test-team'
		self.aud_tag = 'integration-test-aud'
		self.secret = 'integration-test-secret'
		
		self.settings.update({
			'enabled': 1,
			'enable_user_reg': 1,
			'enable_login': 1,
			'jwt_header': 'Cf-Access-Token',
			'jwks_url': f'https://{self.team_name}.cloudflareaccess.com/cdn-cgi/access/certs',
			'jwt_private_secret': self.secret,
			'login_url': f'https://{self.team_name}.cloudflareaccess.com/cdn-cgi/access/login/{self.aud_tag}',
			'logout_url': f'https://{self.team_name}.cloudflareaccess.com/cdn-cgi/access/logout',
			'redirect_param': 'redirect_url',
			'team_name': self.team_name,
			'aud_tag': self.aud_tag
		})
		self.settings.save()
		
		# Create mock Cloudflare Access helper
		self.cf_mock = MockCloudflareAccess(self.team_name, self.aud_tag, self.secret)
		
		# Test user email
		self.test_email = 'integration-test@example.com'

	def test_complete_authentication_workflow(self):
		"""Test the complete authentication workflow from start to finish."""
		# Step 1: User visits protected page without authentication
		with patch('jwt_auth.auth.frappe.local') as mock_local:
			mock_local.session.user = 'Guest'
			mock_local.request = create_mock_request(path='/protected-page')
			
			auth = JWTAuth('/protected-page')
			
			# Should not be able to authenticate without token
			self.assertFalse(auth.can_auth())

		# Step 2: User gets redirected to Cloudflare Access login
		provider = CloudflareAccessProvider(self.settings)
		login_url = provider.get_login_url('/protected-page')
		
		expected_login_url = self.cf_mock.get_login_url('/protected-page')
		self.assertEqual(login_url, expected_login_url)

		# Step 3: User authenticates with Cloudflare and returns with JWT token
		jwt_token = 'mock.jwt.token.from.cloudflare'
		jwt_claims = self.cf_mock.get_valid_jwt_payload(self.test_email)
		
		with patch('jwt_auth.auth.frappe.local') as mock_local:
			with patch('jwt_auth.auth.frappe.qb') as mock_qb:
				# Setup mock request with JWT token
				mock_local.session.user = 'Guest'
				mock_local.request = create_mock_request(
					token=jwt_token,
					token_in='cookie',
					path='/protected-page'
				)
				mock_local.login_manager = Mock()
				
				# Mock user lookup - no existing user
				mock_contact = Mock()
				mock_contact_email = Mock()
				mock_qb.DocType.side_effect = [mock_contact, mock_contact_email]
				mock_qb.from_.return_value.select.return_value.join.return_value.on.return_value.where.return_value.run.return_value = []
				
				auth = JWTAuth('/protected-page')
				
				# Mock JWT validation
				with patch.object(auth, 'get_public_keys', return_value=[Mock()]):
					with patch('jwt_auth.auth.jwt.decode', return_value=jwt_claims):
						# Should be able to authenticate with valid token
						self.assertTrue(auth.can_auth())
						self.assertEqual(auth.token, jwt_token)
						self.assertEqual(auth.claims, jwt_claims)
						
						# Step 4: User registration (since enable_user_reg is True)
						with patch('jwt_auth.auth.frappe.db') as mock_db:
							with patch('jwt_auth.auth.frappe.get_doc') as mock_get_doc:
								with patch('jwt_auth.auth.frappe.db.commit'):
									# Mock no existing contact
									mock_db.get_value.return_value = None
									
									# Mock user document creation
									mock_user = Mock()
									mock_get_doc.return_value = mock_user
									
									# Trigger authentication
									auth.auth()
									
									# Verify user registration was attempted
									user_doc_args = mock_get_doc.call_args[0][0]
									self.assertEqual(user_doc_args['doctype'], 'User')
									self.assertEqual(user_doc_args['email'], self.test_email)
									
									# Verify login was attempted
									mock_local.login_manager.login_as.assert_called_once_with(self.test_email)

	def test_existing_user_authentication_workflow(self):
		"""Test authentication workflow for existing user."""
		jwt_token = 'existing.user.jwt.token'
		jwt_claims = self.cf_mock.get_valid_jwt_payload(self.test_email)
		
		with patch('jwt_auth.auth.frappe.local') as mock_local:
			with patch('jwt_auth.auth.frappe.qb') as mock_qb:
				# Setup mock request
				mock_local.session.user = 'Guest'
				mock_local.request = create_mock_request(
					token=jwt_token,
					token_in='header',
					path='/dashboard'
				)
				mock_local.login_manager = Mock()
				
				# Mock existing user lookup
				mock_contact = Mock()
				mock_contact_email = Mock()
				mock_qb.DocType.side_effect = [mock_contact, mock_contact_email]
				mock_qb.from_.return_value.select.return_value.join.return_value.on.return_value.where.return_value.run.return_value = [
					{'user': self.test_email}
				]
				
				auth = JWTAuth('/dashboard')
				
				# Mock JWT validation
				with patch.object(auth, 'get_public_keys', return_value=[Mock()]):
					with patch('jwt_auth.auth.jwt.decode', return_value=jwt_claims):
						# Authenticate existing user
						self.assertTrue(auth.can_auth())
						
						# Trigger authentication
						auth.auth()
						
						# Verify existing user was logged in directly
						mock_local.login_manager.login_as.assert_called_once_with(self.test_email)

	def test_logout_workflow(self):
		"""Test the logout workflow."""
		# Test programmatic logout
		with patch('jwt_auth.auth.SessionJWTAuth') as mock_session_auth:
			with patch('jwt_auth.auth.frappe.local') as mock_local:
				mock_auth = Mock()
				mock_auth.settings.enabled = True
				mock_auth.get_logout_url.return_value = self.cf_mock.get_logout_url()
				mock_session_auth.return_value = mock_auth
				
				mock_local.login_manager = Mock()
				
				from jwt_auth.auth import jwt_logout
				result = jwt_logout()
				
				# Verify logout and redirect
				mock_local.login_manager.logout.assert_called_once()
				expected_logout_url = self.cf_mock.get_logout_url()
				self.assertEqual(result['redirect_url'], expected_logout_url)

	def test_error_scenarios(self):
		"""Test various error scenarios."""
		# Test expired token
		expired_claims = self.cf_mock.get_expired_jwt_payload(self.test_email)
		
		with patch('jwt_auth.auth.frappe.local') as mock_local:
			mock_local.session.user = 'Guest'
			mock_local.request = create_mock_request(token='expired.token')
			
			auth = JWTAuth()
			
			with patch.object(auth, 'get_public_keys', return_value=[Mock()]):
				with patch('jwt_auth.auth.jwt.decode', side_effect=jwt.ExpiredSignatureError):
					# Should not be able to authenticate with expired token
					self.assertFalse(auth.can_auth())

		# Test invalid audience
		with patch('jwt_auth.auth.frappe.local') as mock_local:
			mock_local.session.user = 'Guest'
			mock_local.request = create_mock_request(token='invalid.aud.token')
			
			auth = JWTAuth()
			
			with patch.object(auth, 'get_public_keys', return_value=[Mock()]):
				with patch('jwt_auth.auth.jwt.decode', side_effect=jwt.InvalidAudienceError):
					# Should not be able to authenticate with invalid audience
					self.assertFalse(auth.can_auth())

	def test_provider_integration(self):
		"""Test provider integration with settings."""
		provider = CloudflareAccessProvider(self.settings)
		
		# Test all URL generation methods
		self.assertEqual(provider.get_jwks_url(), self.cf_mock.get_jwks_url())
		self.assertEqual(provider.get_login_url(), self.cf_mock.get_login_url())
		
		# Test with redirect
		login_with_redirect = provider.get_login_url('/app/dashboard')
		expected_with_redirect = self.cf_mock.get_login_url('/app/dashboard')
		self.assertEqual(login_with_redirect, expected_with_redirect)
		
		# Test public key retrieval
		with patch('jwt_auth.providers.requests.get') as mock_requests:
			mock_response = Mock()
			mock_response.json.return_value = self.cf_mock.get_jwks_response()
			mock_requests.return_value = mock_response
			
			with patch('jwt_auth.providers.jwt.algorithms.RSAAlgorithm.from_jwk') as mock_from_jwk:
				mock_public_key = Mock()
				mock_from_jwk.return_value = mock_public_key
				
				public_keys = provider.get_public_keys()
				
				self.assertEqual(len(public_keys), 1)
				self.assertEqual(public_keys[0], mock_public_key)
				
				# Verify correct Cloudflare URL was called
				mock_requests.assert_called_once_with(self.cf_mock.get_jwks_url())

	def test_session_jwt_auth_wrapper(self):
		"""Test SessionJWTAuth wrapper functionality."""
		with patch('jwt_auth.auth.frappe.local') as mock_local:
			# Test first initialization
			mock_local.jwt_auth = None
			
			with patch('jwt_auth.auth.JWTAuth') as mock_jwt_auth:
				mock_jwt_auth_instance = Mock()
				mock_jwt_auth.return_value = mock_jwt_auth_instance
				
				session_auth = SessionJWTAuth('/test', 200)
				
				# Verify JWTAuth was created
				mock_jwt_auth.assert_called_once_with('/test', 200)
				self.assertEqual(mock_local.jwt_auth, mock_jwt_auth_instance)
				
				# Test attribute delegation
				mock_jwt_auth_instance.test_method.return_value = 'test_result'
				result = session_auth.test_method()
				self.assertEqual(result, 'test_result')

	def tearDown(self):
		"""Clean up after tests."""
		# Reset settings
		self.settings.enabled = 0
		self.settings.enable_user_reg = 0
		self.settings.enable_login = 0
		self.settings.save()
		
		# Clean up any test users/contacts
		if frappe.db.exists('User', self.test_email):
			frappe.delete_doc('User', self.test_email, ignore_permissions=True)


class TestRealisticCloudflareScenarios(IntegrationTestCase):
	"""Test realistic Cloudflare Access scenarios."""

	def setUp(self):
		"""Set up for realistic scenarios."""
		self.cf_mock = MockCloudflareAccess('mycompany', 'production-app', 'my-app-audience-secret')

	def test_production_like_jwt_validation(self):
		"""Test JWT validation with production-like claims."""
		# Realistic Cloudflare Access JWT claims
		realistic_claims = {
			"aud": ["my-app-audience-secret"],
			"email": "john.doe@mycompany.com",
			"exp": int(time.time()) + 3600,
			"iat": int(time.time()),
			"iss": "https://mycompany.cloudflareaccess.com",
			"sub": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
			"custom": {
				"name": "John Doe",
				"department": "Engineering",
				"groups": ["Employees", "Developers", "Admin"]
			},
			"identity_nonce": "12345abcdef",
			"common_name": "john.doe@mycompany.com",
			"country": "US",
			"ip": "192.168.1.100"
		}
		
		# Mock settings for production-like environment
		mock_settings = MockJWTAuthSettings(
			team_name='mycompany',
			aud_tag='production-app',
			jwt_private_secret='my-app-audience-secret',
			jwks_url='https://mycompany.cloudflareaccess.com/cdn-cgi/access/certs'
		)
		
		with patch('jwt_auth.auth.frappe.get_cached_doc', return_value=mock_settings):
			auth = JWTAuth()
			
			# Mock successful JWT decode with realistic claims
			with patch.object(auth, 'get_public_keys', return_value=[Mock()]):
				with patch('jwt_auth.auth.jwt.decode', return_value=realistic_claims):
					result = auth.is_valid_token('realistic.production.token')
					
					self.assertTrue(result)
					self.assertEqual(auth.claims, realistic_claims)
					self.assertEqual(auth.claims['email'], 'john.doe@mycompany.com')
					self.assertEqual(auth.claims['custom']['department'], 'Engineering')

	def test_multiple_keys_rotation_scenario(self):
		"""Test key rotation scenario with multiple JWKS keys."""
		# Realistic JWKS response with multiple keys (key rotation)
		jwks_with_rotation = {
			"keys": [
				{
					"alg": "RS256",
					"kty": "RSA",
					"use": "sig",
					"x5c": ["MIIC...old_cert"],
					"n": "old_key_n_parameter",
					"e": "AQAB",
					"kid": "mycompany-2023-key",
					"x5t": "old_thumbprint"
				},
				{
					"alg": "RS256",
					"kty": "RSA", 
					"use": "sig",
					"x5c": ["MIIC...new_cert"],
					"n": "new_key_n_parameter",
					"e": "AQAB",
					"kid": "mycompany-2024-key",
					"x5t": "new_thumbprint"
				}
			]
		}
		
		provider = CloudflareAccessProvider(
			MockJWTAuthSettings(team_name='mycompany', aud_tag='production-app')
		)
		
		with patch('jwt_auth.providers.requests.get') as mock_requests:
			mock_response = Mock()
			mock_response.json.return_value = jwks_with_rotation
			mock_requests.return_value = mock_response
			
			with patch('jwt_auth.providers.jwt.algorithms.RSAAlgorithm.from_jwk') as mock_from_jwk:
				mock_old_key = Mock()
				mock_new_key = Mock()
				mock_from_jwk.side_effect = [mock_old_key, mock_new_key]
				
				public_keys = provider.get_public_keys()
				
				# Should have both keys available for validation
				self.assertEqual(len(public_keys), 2)
				self.assertEqual(public_keys[0], mock_old_key)
				self.assertEqual(public_keys[1], mock_new_key)

	def tearDown(self):
		"""Clean up."""
		pass