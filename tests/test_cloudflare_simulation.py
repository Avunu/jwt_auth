# Copyright (c) 2024, Avunu LLC and Contributors
# See license.txt

import json
import jwt
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

import frappe
from frappe.tests import IntegrationTestCase, UnitTestCase

from jwt_auth.auth import JWTAuth, SessionJWTAuth
from jwt_auth.providers import CloudflareAccessProvider


class TestCloudflareAccessSimulation(UnitTestCase):
	"""Unit tests simulating Cloudflare Access API interactions without external calls."""

	def setUp(self):
		"""Set up test environment with mock Cloudflare responses."""
		self.team_name = 'test-team'
		self.aud_tag = 'test-aud-tag'
		self.secret = 'test-audience-secret'
		
		# Mock JWT Auth Settings
		self.mock_settings = Mock()
		self.mock_settings.enabled = True
		self.mock_settings.enable_user_reg = True
		self.mock_settings.enable_login = True
		self.mock_settings.jwt_header = 'Cf-Access-Token'
		self.mock_settings.team_name = self.team_name
		self.mock_settings.aud_tag = self.aud_tag
		self.mock_settings.get_password.return_value = self.secret

		# Mock Cloudflare JWKS response
		self.mock_jwks_response = {
			"keys": [
				{
					"alg": "RS256",
					"kty": "RSA",
					"use": "sig",
					"x5c": [
						"MIIC+DCCAeCgAwIBAgIJAKZ7...example_certificate_data"
					],
					"n": "example_n_parameter_base64url_encoded",
					"e": "AQAB",
					"kid": "cloudflare-access-key-1",
					"x5t": "example_x5t_thumbprint"
				}
			]
		}

		# Mock valid JWT token payload from Cloudflare Access
		self.mock_valid_jwt_payload = {
			"aud": [self.secret],
			"email": "user@example.com",
			"exp": int(time.time()) + 3600,  # Expires in 1 hour
			"iat": int(time.time()),
			"iss": f"https://{self.team_name}.cloudflareaccess.com",
			"sub": "1234567890abcdef",
			"custom": {
				"name": "John Doe",
				"groups": ["Developers", "Users"]
			},
			"identity_nonce": "example_nonce",
			"common_name": "user@example.com",
			"country": "US"
		}

		# Mock expired JWT token payload
		self.mock_expired_jwt_payload = {
			**self.mock_valid_jwt_payload,
			"exp": int(time.time()) - 3600,  # Expired 1 hour ago
			"iat": int(time.time()) - 7200   # Issued 2 hours ago
		}

		# Mock invalid audience JWT token payload
		self.mock_invalid_aud_jwt_payload = {
			**self.mock_valid_jwt_payload,
			"aud": ["wrong-audience"]
		}

	def test_cloudflare_jwks_endpoint_simulation(self):
		"""Test simulation of Cloudflare JWKS endpoint call."""
		provider = CloudflareAccessProvider(self.mock_settings)
		
		with patch('jwt_auth.providers.requests.get') as mock_requests:
			mock_response = Mock()
			mock_response.json.return_value = self.mock_jwks_response
			mock_requests.return_value = mock_response
			
			with patch('jwt_auth.providers.jwt.algorithms.RSAAlgorithm.from_jwk') as mock_from_jwk:
				mock_public_key = Mock()
				mock_from_jwk.return_value = mock_public_key
				
				public_keys = provider.get_public_keys()
				
				# Verify correct Cloudflare JWKS URL was called
				expected_url = f'https://{self.team_name}.cloudflareaccess.com/cdn-cgi/access/certs'
				mock_requests.assert_called_once_with(expected_url)
				
				# Verify public key was extracted
				self.assertEqual(len(public_keys), 1)
				self.assertEqual(public_keys[0], mock_public_key)

	def test_cloudflare_login_redirect_simulation(self):
		"""Test simulation of Cloudflare Access login redirect."""
		provider = CloudflareAccessProvider(self.mock_settings)
		
		# Test login URL without redirect
		login_url = provider.get_login_url()
		expected_base_url = f'https://{self.team_name}.cloudflareaccess.com/cdn-cgi/access/login/{self.aud_tag}'
		self.assertEqual(login_url, expected_base_url)
		
		# Test login URL with redirect
		redirect_to = '/app/dashboard'
		login_url_with_redirect = provider.get_login_url(redirect_to)
		self.assertIn('redirect_url=', login_url_with_redirect)
		self.assertIn('%2Fapp%2Fdashboard', login_url_with_redirect)

	def test_cloudflare_logout_redirect_simulation(self):
		"""Test simulation of Cloudflare Access logout redirect."""
		provider = CloudflareAccessProvider(self.mock_settings)
		
		with patch('jwt_auth.providers.frappe.utils.get_url') as mock_get_url:
			mock_get_url.return_value = 'https://myapp.example.com'
			
			logout_url = provider.get_logout_url()
			
			# Verify logout URL structure
			expected_base = f'https://{self.team_name}.cloudflareaccess.com/cdn-cgi/access/logout'
			self.assertIn(expected_base, logout_url)
			self.assertIn('redirect_url=', logout_url)
			self.assertIn('https%3A//myapp.example.com', logout_url)

	def test_valid_cloudflare_jwt_token_simulation(self):
		"""Test simulation of valid Cloudflare Access JWT token validation."""
		with patch('jwt_auth.auth.frappe.get_cached_doc') as mock_get_cached_doc:
			mock_get_cached_doc.return_value = self.mock_settings
			
			auth = JWTAuth()
			
			with patch.object(auth, 'get_public_keys') as mock_get_keys:
				mock_public_key = Mock()
				mock_get_keys.return_value = [mock_public_key]
				
				with patch('jwt_auth.auth.jwt.decode') as mock_jwt_decode:
					mock_jwt_decode.return_value = self.mock_valid_jwt_payload
					
					# Test token validation
					result = auth.is_valid_token('mock.jwt.token')
					
					self.assertTrue(result)
					self.assertEqual(auth.claims, self.mock_valid_jwt_payload)
					
					# Verify JWT decode was called with correct parameters
					mock_jwt_decode.assert_called_once_with(
						'mock.jwt.token',
						key=mock_public_key,
						audience=self.secret,
						algorithms=['RS256']
					)

	def test_expired_cloudflare_jwt_token_simulation(self):
		"""Test simulation of expired Cloudflare Access JWT token."""
		with patch('jwt_auth.auth.frappe.get_cached_doc') as mock_get_cached_doc:
			mock_get_cached_doc.return_value = self.mock_settings
			
			auth = JWTAuth()
			
			with patch.object(auth, 'get_public_keys') as mock_get_keys:
				mock_public_key = Mock()
				mock_get_keys.return_value = [mock_public_key]
				
				with patch('jwt_auth.auth.jwt.decode') as mock_jwt_decode:
					# Simulate expired token error
					mock_jwt_decode.side_effect = jwt.ExpiredSignatureError('Token expired')
					
					result = auth.is_valid_token('expired.jwt.token')
					
					self.assertFalse(result)

	def test_invalid_audience_cloudflare_jwt_token_simulation(self):
		"""Test simulation of Cloudflare Access JWT token with invalid audience."""
		with patch('jwt_auth.auth.frappe.get_cached_doc') as mock_get_cached_doc:
			mock_get_cached_doc.return_value = self.mock_settings
			
			auth = JWTAuth()
			
			with patch.object(auth, 'get_public_keys') as mock_get_keys:
				mock_public_key = Mock()
				mock_get_keys.return_value = [mock_public_key]
				
				with patch('jwt_auth.auth.jwt.decode') as mock_jwt_decode:
					# Simulate invalid audience error
					mock_jwt_decode.side_effect = jwt.InvalidAudienceError('Invalid audience')
					
					result = auth.is_valid_token('invalid.aud.token')
					
					self.assertFalse(result)

	def test_cloudflare_token_extraction_simulation(self):
		"""Test simulation of extracting Cloudflare Access token from request."""
		with patch('jwt_auth.auth.frappe.get_cached_doc') as mock_get_cached_doc:
			mock_get_cached_doc.return_value = self.mock_settings
			
			auth = JWTAuth()
			
			# Test token in Cf-Access-Token cookie (Cloudflare's preferred method)
			mock_request_cookie = Mock()
			mock_request_cookie.cookies.get.return_value = 'cookie.jwt.token'
			mock_request_cookie.headers.get.return_value = None
			
			token = auth.get_token(mock_request_cookie)
			self.assertEqual(token, 'cookie.jwt.token')
			mock_request_cookie.cookies.get.assert_called_once_with('Cf-Access-Token')
			
			# Test token in Cf-Access-Token header (fallback method)
			mock_request_header = Mock()
			mock_request_header.cookies.get.return_value = None
			mock_request_header.headers.get.return_value = 'header.jwt.token'
			
			token = auth.get_token(mock_request_header)
			self.assertEqual(token, 'header.jwt.token')
			mock_request_header.headers.get.assert_called_once_with('Cf-Access-Token')

	def test_cloudflare_user_registration_simulation(self):
		"""Test simulation of user registration with Cloudflare Access data."""
		with patch('jwt_auth.auth.frappe.get_cached_doc') as mock_get_cached_doc:
			mock_get_cached_doc.return_value = self.mock_settings
			
			auth = JWTAuth()
			auth.claims = self.mock_valid_jwt_payload
			
			# Mock database and document operations
			with patch('jwt_auth.auth.frappe.db') as mock_db:
				with patch('jwt_auth.auth.frappe.get_doc') as mock_get_doc:
					with patch('jwt_auth.auth.frappe.db.commit'):
						# Simulate no existing contact
						mock_db.get_value.return_value = None
						
						# Mock user document creation
						mock_user = Mock()
						mock_get_doc.return_value = mock_user
						
						auth.register_user('user@example.com')
						
						# Verify user document was created with correct data
						user_doc_args = mock_get_doc.call_args[0][0]
						self.assertEqual(user_doc_args['doctype'], 'User')
						self.assertEqual(user_doc_args['email'], 'user@example.com')
						self.assertEqual(user_doc_args['first_name'], '[Change Me]')
						
						# Verify redirect is set for profile completion
						self.assertEqual(auth.redirect_to, '/update-profile/user@example.com/edit')
						
						mock_user.insert.assert_called_once_with(ignore_permissions=True)

	def test_full_cloudflare_authentication_flow_simulation(self):
		"""Test simulation of complete Cloudflare Access authentication flow."""
		with patch('jwt_auth.auth.frappe.get_cached_doc') as mock_get_cached_doc:
			mock_get_cached_doc.return_value = self.mock_settings
			
			with patch('jwt_auth.auth.frappe.local') as mock_local:
				with patch('jwt_auth.auth.frappe.qb') as mock_qb:
					# Setup mock request with Cloudflare token
					mock_local.session.user = 'Guest'
					mock_local.request = Mock()
					mock_local.request.cookies.get.return_value = 'cloudflare.jwt.token'
					mock_local.request.headers.get.return_value = None
					
					# Setup mock login manager
					mock_login_manager = Mock()
					mock_local.login_manager = mock_login_manager
					
					# Mock existing user lookup
					mock_contact = Mock()
					mock_contact_email = Mock()
					mock_qb.DocType.side_effect = [mock_contact, mock_contact_email]
					mock_qb.from_.return_value.select.return_value.join.return_value.on.return_value.where.return_value.run.return_value = [
						{'user': 'user@example.com'}
					]
					
					auth = JWTAuth()
					
					# Mock token validation
					with patch.object(auth, 'get_public_keys') as mock_get_keys:
						with patch('jwt_auth.auth.jwt.decode') as mock_jwt_decode:
							mock_get_keys.return_value = [Mock()]
							mock_jwt_decode.return_value = self.mock_valid_jwt_payload
							
							# Test can_auth
							can_authenticate = auth.can_auth()
							self.assertTrue(can_authenticate)
							self.assertEqual(auth.token, 'cloudflare.jwt.token')
							self.assertEqual(auth.claims, self.mock_valid_jwt_payload)
							
							# Test auth
							auth.auth()
							
							# Verify user was logged in
							mock_login_manager.login_as.assert_called_once_with('user@example.com')


class TestCloudflareAccessIntegration(IntegrationTestCase):
	"""Integration tests for Cloudflare Access simulation with real Frappe environment."""

	def setUp(self):
		"""Set up test environment with Cloudflare settings."""
		# Create JWT Auth Settings with Cloudflare configuration
		try:
			self.settings = frappe.get_doc("JWT Auth Settings")
		except frappe.DoesNotExistError:
			self.settings = frappe.new_doc("JWT Auth Settings")
		
		# Configure for Cloudflare Access
		self.team_name = 'test-integration-team'
		self.aud_tag = 'test-integration-aud'
		
		self.settings.update({
			'enabled': 1,
			'enable_user_reg': 1,
			'enable_login': 1,
			'jwt_header': 'Cf-Access-Token',
			'jwks_url': f'https://{self.team_name}.cloudflareaccess.com/cdn-cgi/access/certs',
			'jwt_private_secret': 'integration-test-secret',
			'login_url': f'https://{self.team_name}.cloudflareaccess.com/cdn-cgi/access/login/{self.aud_tag}',
			'logout_url': f'https://{self.team_name}.cloudflareaccess.com/cdn-cgi/access/logout',
			'redirect_param': 'redirect_url'
		})
		
		# Add Cloudflare-specific fields
		if not hasattr(self.settings, 'team_name'):
			setattr(self.settings, 'team_name', self.team_name)
		if not hasattr(self.settings, 'aud_tag'):
			setattr(self.settings, 'aud_tag', self.aud_tag)
		
		self.settings.save()

	def test_cloudflare_provider_integration_with_settings(self):
		"""Test CloudflareAccessProvider integration with real JWT Auth Settings."""
		provider = CloudflareAccessProvider(self.settings)
		
		# Test that provider uses settings correctly
		self.assertEqual(provider.team_name, self.team_name)
		self.assertEqual(provider.aud_tag, self.aud_tag)
		self.assertEqual(provider.jwt_header, 'Cf-Access-Token')
		
		# Test URL generation
		login_url = provider.get_login_url('/dashboard')
		expected_login = f'https://{self.team_name}.cloudflareaccess.com/cdn-cgi/access/login/{self.aud_tag}?redirect_url=%2F%2Fdashboard'
		self.assertEqual(login_url, expected_login)
		
		jwks_url = provider.get_jwks_url()
		expected_jwks = f'https://{self.team_name}.cloudflareaccess.com/cdn-cgi/access/certs'
		self.assertEqual(jwks_url, expected_jwks)

	def test_cloudflare_error_handling_simulation(self):
		"""Test error handling in Cloudflare Access simulation."""
		provider = CloudflareAccessProvider(self.settings)
		
		# Test JWKS endpoint error
		with patch('jwt_auth.providers.requests.get') as mock_requests:
			mock_requests.side_effect = Exception('Network error')
			
			with self.assertRaises(Exception):
				provider.get_public_keys()

	def test_cloudflare_jwt_signature_verification_simulation(self):
		"""Test JWT signature verification simulation with multiple keys."""
		provider = CloudflareAccessProvider(self.settings)
		
		# Mock JWKS response with multiple keys (common in production)
		mock_jwks_response = {
			"keys": [
				{
					"alg": "RS256",
					"kty": "RSA",
					"use": "sig",
					"kid": "old-cloudflare-key",
					"n": "old_key_n_value",
					"e": "AQAB"
				},
				{
					"alg": "RS256", 
					"kty": "RSA",
					"use": "sig",
					"kid": "current-cloudflare-key",
					"n": "current_key_n_value",
					"e": "AQAB"
				}
			]
		}
		
		with patch('jwt_auth.providers.requests.get') as mock_requests:
			mock_response = Mock()
			mock_response.json.return_value = mock_jwks_response
			mock_requests.return_value = mock_response
			
			with patch('jwt_auth.providers.jwt.algorithms.RSAAlgorithm.from_jwk') as mock_from_jwk:
				mock_key_1 = Mock()
				mock_key_2 = Mock()
				mock_from_jwk.side_effect = [mock_key_1, mock_key_2]
				
				public_keys = provider.get_public_keys()
				
				# Verify both keys were processed
				self.assertEqual(len(public_keys), 2)
				self.assertEqual(public_keys[0], mock_key_1)
				self.assertEqual(public_keys[1], mock_key_2)
				
				# Verify correct number of from_jwk calls
				self.assertEqual(mock_from_jwk.call_count, 2)

	def tearDown(self):
		"""Clean up after tests."""
		# Reset settings
		self.settings.enabled = 0
		self.settings.enable_user_reg = 0
		self.settings.enable_login = 0
		self.settings.save()