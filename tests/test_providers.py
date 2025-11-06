# Copyright (c) 2024, Avunu LLC and Contributors
# See license.txt

import json
import jwt
from unittest.mock import Mock, patch, MagicMock
from urllib.parse import quote

import frappe
from frappe.tests import IntegrationTestCase, UnitTestCase

from jwt_auth.providers import BaseProvider, CloudflareAccessProvider


class TestBaseProviderUnit(UnitTestCase):
	"""Unit tests for BaseProvider class."""

	def setUp(self):
		"""Set up test environment."""
		self.mock_settings = Mock()
		self.mock_settings.enabled = True
		self.mock_settings.enable_login = True
		self.mock_settings.enable_user_reg = True
		self.mock_settings.get_password.return_value = 'test-secret'

	def test_base_provider_initialization(self):
		"""Test BaseProvider initialization."""
		provider = BaseProvider(self.mock_settings)
		
		self.assertEqual(provider.settings, self.mock_settings)

	def test_base_provider_properties(self):
		"""Test BaseProvider properties."""
		provider = BaseProvider(self.mock_settings)
		
		self.assertTrue(provider.enabled)
		self.assertTrue(provider.enable_login)
		self.assertTrue(provider.enable_user_reg)
		self.assertEqual(provider.jwt_private_secret, 'test-secret')
		self.assertEqual(provider.jwt_header, 'Cf-Access-Token')

	def test_base_provider_abstract_methods(self):
		"""Test that abstract methods raise NotImplementedError."""
		provider = BaseProvider(self.mock_settings)
		
		with self.assertRaises(NotImplementedError):
			provider.get_login_url()
		
		with self.assertRaises(NotImplementedError):
			provider.get_logout_url()
		
		with self.assertRaises(NotImplementedError):
			provider.get_jwks_url()

	@patch('jwt_auth.providers.requests.get')
	def test_get_public_keys(self, mock_requests_get):
		"""Test get_public_keys method."""
		provider = BaseProvider(self.mock_settings)
		
		# Mock JWKS response
		mock_jwks_response = {
			"keys": [
				{
					"kty": "RSA",
					"kid": "test-key-1",
					"use": "sig",
					"alg": "RS256",
					"n": "test-n-value-1",
					"e": "AQAB"
				},
				{
					"kty": "RSA",
					"kid": "test-key-2",
					"use": "sig", 
					"alg": "RS256",
					"n": "test-n-value-2",
					"e": "AQAB"
				}
			]
		}
		mock_requests_get.return_value.json.return_value = mock_jwks_response
		
		# Mock RSA algorithm
		mock_public_key_1 = Mock()
		mock_public_key_2 = Mock()
		
		with patch('jwt_auth.providers.jwt.algorithms.RSAAlgorithm.from_jwk') as mock_from_jwk:
			mock_from_jwk.side_effect = [mock_public_key_1, mock_public_key_2]
			
			with patch.object(provider, 'get_jwks_url', return_value='https://test.jwks.url'):
				public_keys = provider.get_public_keys()
				
				self.assertEqual(len(public_keys), 2)
				self.assertEqual(public_keys[0], mock_public_key_1)
				self.assertEqual(public_keys[1], mock_public_key_2)
				
				# Verify calls
				mock_requests_get.assert_called_once_with('https://test.jwks.url')
				self.assertEqual(mock_from_jwk.call_count, 2)


class TestCloudflareAccessProviderUnit(UnitTestCase):
	"""Unit tests for CloudflareAccessProvider class."""

	def setUp(self):
		"""Set up test environment."""
		self.mock_settings = Mock()
		self.mock_settings.enabled = True
		self.mock_settings.enable_login = True
		self.mock_settings.enable_user_reg = True
		self.mock_settings.team_name = 'test-team'
		self.mock_settings.aud_tag = 'test-aud-tag'
		self.mock_settings.get_password.return_value = 'test-secret'

	def test_cloudflare_provider_initialization(self):
		"""Test CloudflareAccessProvider initialization."""
		provider = CloudflareAccessProvider(self.mock_settings)
		
		self.assertEqual(provider.settings, self.mock_settings)
		self.assertTrue(isinstance(provider, BaseProvider))

	def test_cloudflare_provider_properties(self):
		"""Test CloudflareAccessProvider properties."""
		provider = CloudflareAccessProvider(self.mock_settings)
		
		self.assertEqual(provider.team_name, 'test-team')
		self.assertEqual(provider.aud_tag, 'test-aud-tag')
		self.assertEqual(provider.jwt_header, 'Cf-Access-Token')

	def test_get_jwks_url(self):
		"""Test get_jwks_url method."""
		provider = CloudflareAccessProvider(self.mock_settings)
		
		jwks_url = provider.get_jwks_url()
		expected_url = 'https://test-team.cloudflareaccess.com/cdn-cgi/access/certs'
		
		self.assertEqual(jwks_url, expected_url)

	def test_get_login_url_without_redirect(self):
		"""Test get_login_url without redirect parameter."""
		provider = CloudflareAccessProvider(self.mock_settings)
		
		login_url = provider.get_login_url()
		expected_url = 'https://test-team.cloudflareaccess.com/cdn-cgi/access/login/test-aud-tag'
		
		self.assertEqual(login_url, expected_url)

	def test_get_login_url_with_redirect(self):
		"""Test get_login_url with redirect parameter."""
		provider = CloudflareAccessProvider(self.mock_settings)
		
		redirect_to = '/dashboard/reports'
		login_url = provider.get_login_url(redirect_to)
		
		expected_path = '%2F' + quote(redirect_to, safe='')
		expected_url = f'https://test-team.cloudflareaccess.com/cdn-cgi/access/login/test-aud-tag?redirect_url={expected_path}'
		
		self.assertEqual(login_url, expected_url)

	@patch('jwt_auth.providers.frappe.utils.get_url')
	def test_get_logout_url(self, mock_get_url):
		"""Test get_logout_url method."""
		mock_get_url.return_value = 'https://mysite.example.com'
		
		provider = CloudflareAccessProvider(self.mock_settings)
		logout_url = provider.get_logout_url()
		
		expected_site_url = quote('https://mysite.example.com', safe='')
		expected_url = f'https://test-team.cloudflareaccess.com/cdn-cgi/access/logout?redirect_url={expected_site_url}'
		
		self.assertEqual(logout_url, expected_url)
		mock_get_url.assert_called_once()

	@patch('jwt_auth.providers.requests.get')
	def test_inherited_get_public_keys(self, mock_requests_get):
		"""Test that CloudflareAccessProvider inherits get_public_keys correctly."""
		provider = CloudflareAccessProvider(self.mock_settings)
		
		# Mock JWKS response that would come from Cloudflare
		mock_jwks_response = {
			"keys": [
				{
					"kty": "RSA",
					"kid": "cloudflare-key-1",
					"use": "sig",
					"alg": "RS256",
					"n": "cloudflare-n-value",
					"e": "AQAB"
				}
			]
		}
		mock_requests_get.return_value.json.return_value = mock_jwks_response
		
		mock_public_key = Mock()
		
		with patch('jwt_auth.providers.jwt.algorithms.RSAAlgorithm.from_jwk', return_value=mock_public_key):
			public_keys = provider.get_public_keys()
			
			self.assertEqual(len(public_keys), 1)
			self.assertEqual(public_keys[0], mock_public_key)
			
			# Verify it called the correct Cloudflare URL
			expected_jwks_url = 'https://test-team.cloudflareaccess.com/cdn-cgi/access/certs'
			mock_requests_get.assert_called_once_with(expected_jwks_url)


class TestProvidersIntegration(IntegrationTestCase):
	"""Integration tests for provider classes."""

	def setUp(self):
		"""Set up test environment."""
		# Create test settings
		try:
			self.settings = frappe.get_doc("JWT Auth Settings")
		except frappe.DoesNotExistError:
			self.settings = frappe.new_doc("JWT Auth Settings")
		
		# Add Cloudflare-specific fields if they don't exist
		if not hasattr(self.settings, 'team_name'):
			setattr(self.settings, 'team_name', 'test-team')
		if not hasattr(self.settings, 'aud_tag'):
			setattr(self.settings, 'aud_tag', 'test-aud-tag')
		
		self.settings.update({
			'enabled': 1,
			'enable_user_reg': 1,
			'enable_login': 1,
			'jwt_header': 'Cf-Access-Token',
			'jwks_url': 'https://test-team.cloudflareaccess.com/cdn-cgi/access/certs',
			'jwt_private_secret': 'test-secret',
			'login_url': 'https://test-team.cloudflareaccess.com/cdn-cgi/access/login/test-aud-tag',
			'logout_url': 'https://test-team.cloudflareaccess.com/cdn-cgi/access/logout',
			'redirect_param': 'redirect_url',
			'team_name': 'test-team',
			'aud_tag': 'test-aud-tag'
		})

	def test_cloudflare_provider_with_real_settings(self):
		"""Test CloudflareAccessProvider with real settings document."""
		provider = CloudflareAccessProvider(self.settings)
		
		# Test URL generation
		login_url = provider.get_login_url('/dashboard')
		self.assertIn('test-team.cloudflareaccess.com', login_url)
		self.assertIn('test-aud-tag', login_url)
		self.assertIn('redirect_url=', login_url)
		
		# Test JWKS URL
		jwks_url = provider.get_jwks_url()
		expected_jwks = 'https://test-team.cloudflareaccess.com/cdn-cgi/access/certs'
		self.assertEqual(jwks_url, expected_jwks)

	def test_provider_integration_with_mocked_cloudflare_api(self):
		"""Test provider integration with mocked Cloudflare API responses."""
		provider = CloudflareAccessProvider(self.settings)
		
		# Mock Cloudflare JWKS endpoint response
		mock_cloudflare_jwks = {
			"keys": [
				{
					"alg": "RS256",
					"kty": "RSA",
					"use": "sig",
					"x5c": ["MIIC..."],
					"n": "example-n-value",
					"e": "AQAB",
					"kid": "cloudflare-access-kid",
					"x5t": "example-thumbprint"
				}
			]
		}
		
		with patch('jwt_auth.providers.requests.get') as mock_requests:
			mock_response = Mock()
			mock_response.json.return_value = mock_cloudflare_jwks
			mock_requests.return_value = mock_response
			
			with patch('jwt_auth.providers.jwt.algorithms.RSAAlgorithm.from_jwk') as mock_from_jwk:
				mock_public_key = Mock()
				mock_from_jwk.return_value = mock_public_key
				
				public_keys = provider.get_public_keys()
				
				# Verify the integration worked
				self.assertEqual(len(public_keys), 1)
				self.assertEqual(public_keys[0], mock_public_key)
				
				# Verify correct Cloudflare URL was called
				mock_requests.assert_called_once_with(
					'https://test-team.cloudflareaccess.com/cdn-cgi/access/certs'
				)

	def test_provider_url_encoding(self):
		"""Test that provider handles URL encoding correctly."""
		provider = CloudflareAccessProvider(self.settings)
		
		# Test complex redirect path with special characters
		complex_path = '/app/form/User/test@example.com?tab=details&section=profile'
		login_url = provider.get_login_url(complex_path)
		
		# Should contain properly encoded redirect URL
		self.assertIn('redirect_url=', login_url)
		self.assertIn('%2F', login_url)  # Forward slash should be encoded
		
		# Test logout URL encoding
		with patch('jwt_auth.providers.frappe.utils.get_url') as mock_get_url:
			mock_get_url.return_value = 'https://my-site.example.com:8000/app'
			
			logout_url = provider.get_logout_url()
			
			# Should contain properly encoded site URL
			self.assertIn('redirect_url=', logout_url)
			self.assertIn('https%3A//my-site.example.com', logout_url)

	def tearDown(self):
		"""Clean up after tests."""
		# Reset settings
		if hasattr(self, 'settings'):
			self.settings.enabled = 0
			self.settings.enable_user_reg = 0
			self.settings.enable_login = 0