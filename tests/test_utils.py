# Copyright (c) 2024, Avunu LLC and Contributors
# See license.txt

"""
Test utilities for JWT Auth testing suite.
Provides common mock objects and helper functions for testing.
"""

import json
import jwt
import time
from unittest.mock import Mock, MagicMock
from datetime import datetime, timedelta


class MockCloudflareAccess:
	"""Mock Cloudflare Access API responses and behaviors."""
	
	def __init__(self, team_name='test-team', aud_tag='test-aud', secret='test-secret'):
		self.team_name = team_name
		self.aud_tag = aud_tag
		self.secret = secret
	
	def get_jwks_response(self, num_keys=1):
		"""Generate mock JWKS response."""
		keys = []
		for i in range(num_keys):
			key = {
				"alg": "RS256",
				"kty": "RSA",
				"use": "sig",
				"x5c": [f"MIIC+DCCAeCgAwIBAgIJAKZ7...example_cert_data_{i}"],
				"n": f"example_n_parameter_base64url_encoded_{i}",
				"e": "AQAB",
				"kid": f"cloudflare-access-key-{i}",
				"x5t": f"example_x5t_thumbprint_{i}"
			}
			keys.append(key)
		
		return {"keys": keys}
	
	def get_valid_jwt_payload(self, email='user@example.com', extra_claims=None):
		"""Generate valid JWT payload."""
		payload = {
			"aud": [self.secret],
			"email": email,
			"exp": int(time.time()) + 3600,  # Expires in 1 hour
			"iat": int(time.time()),
			"iss": f"https://{self.team_name}.cloudflareaccess.com",
			"sub": "1234567890abcdef",
			"custom": {
				"name": "John Doe",
				"groups": ["Developers", "Users"]
			},
			"identity_nonce": "example_nonce",
			"common_name": email,
			"country": "US"
		}
		
		if extra_claims:
			payload.update(extra_claims)
		
		return payload
	
	def get_expired_jwt_payload(self, email='user@example.com'):
		"""Generate expired JWT payload."""
		payload = self.get_valid_jwt_payload(email)
		payload.update({
			"exp": int(time.time()) - 3600,  # Expired 1 hour ago
			"iat": int(time.time()) - 7200   # Issued 2 hours ago
		})
		return payload
	
	def get_invalid_audience_jwt_payload(self, email='user@example.com'):
		"""Generate JWT payload with invalid audience."""
		payload = self.get_valid_jwt_payload(email)
		payload["aud"] = ["wrong-audience"]
		return payload
	
	def get_login_url(self, redirect_to=None):
		"""Generate expected Cloudflare login URL."""
		base_url = f"https://{self.team_name}.cloudflareaccess.com/cdn-cgi/access/login/{self.aud_tag}"
		if redirect_to:
			from urllib.parse import quote
			path = '%2F' + quote(redirect_to, safe='')
			base_url += f"?redirect_url={path}"
		return base_url
	
	def get_logout_url(self, site_url='https://example.com'):
		"""Generate expected Cloudflare logout URL."""
		from urllib.parse import quote
		encoded_site = quote(site_url, safe='')
		return f"https://{self.team_name}.cloudflareaccess.com/cdn-cgi/access/logout?redirect_url={encoded_site}"
	
	def get_jwks_url(self):
		"""Generate expected Cloudflare JWKS URL."""
		return f"https://{self.team_name}.cloudflareaccess.com/cdn-cgi/access/certs"


class MockJWTAuthSettings:
	"""Mock JWT Auth Settings with reasonable defaults."""
	
	def __init__(self, **kwargs):
		# Default settings
		defaults = {
			'enabled': True,
			'enable_user_reg': True,
			'enable_login': True,
			'jwt_header': 'Cf-Access-Token',
			'jwks_url': 'https://test-team.cloudflareaccess.com/cdn-cgi/access/certs',
			'jwt_private_secret': 'test-secret',
			'login_url': 'https://test-team.cloudflareaccess.com/cdn-cgi/access/login/test-aud',
			'logout_url': 'https://test-team.cloudflareaccess.com/cdn-cgi/access/logout',
			'redirect_param': 'redirect_url',
			'team_name': 'test-team',
			'aud_tag': 'test-aud'
		}
		
		# Override with provided kwargs
		defaults.update(kwargs)
		
		# Set attributes
		for key, value in defaults.items():
			setattr(self, key, value)
		
		# Mock the get_password method
		self.get_password = Mock(return_value=self.jwt_private_secret)


class MockFrappeLocal:
	"""Mock frappe.local object."""
	
	def __init__(self):
		self.session = Mock()
		self.session.user = 'Guest'
		self.session.data = {}
		
		self.request = Mock()
		self.request.cookies = Mock()
		self.request.headers = Mock()
		self.request.path = '/'
		self.request.url = 'https://example.com/'
		
		self.login_manager = Mock()
		self.response = {}


class MockFrappeDoc:
	"""Mock Frappe document."""
	
	def __init__(self, doctype, name=None, **kwargs):
		self.doctype = doctype
		self.name = name or f"{doctype}-001"
		
		# Set provided fields
		for key, value in kwargs.items():
			setattr(self, key, value)
		
		# Mock methods
		self.get = Mock(side_effect=lambda field, default=None: getattr(self, field, default))
		self.has_value_changed = Mock(return_value=False)
		self.save = Mock()
		self.insert = Mock()
		self.delete = Mock()
		self.update = Mock()


class MockContact(MockFrappeDoc):
	"""Mock Contact document with JWT Auth specific behavior."""
	
	def __init__(self, **kwargs):
		defaults = {
			'first_name': 'John',
			'last_name': 'Doe',
			'full_name': 'John Doe',
			'email_id': 'john.doe@example.com',
			'phone': '123-456-7890',
			'mobile_no': '987-654-3210',
			'gender': 'Male',
			'company_name': 'Test Company',
			'user': None
		}
		defaults.update(kwargs)
		super().__init__('Contact', **defaults)


class MockUser(MockFrappeDoc):
	"""Mock User document."""
	
	def __init__(self, **kwargs):
		defaults = {
			'email': 'user@example.com',
			'username': 'user@example.com',
			'first_name': 'Test',
			'last_name': 'User',
			'full_name': 'Test User',
			'enabled': 1,
			'send_welcome_email': 0
		}
		defaults.update(kwargs)
		super().__init__('User', **defaults)


def create_mock_request(token=None, token_in='cookie', path='/', headers=None):
	"""Create a mock request object with JWT token."""
	mock_request = Mock()
	mock_request.path = path
	mock_request.url = f'https://example.com{path}'
	
	# Setup cookies
	mock_request.cookies = Mock()
	if token_in == 'cookie' and token:
		mock_request.cookies.get = Mock(side_effect=lambda key: token if key == 'Cf-Access-Token' else None)
	else:
		mock_request.cookies.get = Mock(return_value=None)
	
	# Setup headers
	mock_request.headers = Mock()
	if token_in == 'header' and token:
		mock_request.headers.get = Mock(side_effect=lambda key: token if key == 'Cf-Access-Token' else None)
	else:
		mock_request.headers.get = Mock(return_value=None)
	
	# Add any extra headers
	if headers:
		for key, value in headers.items():
			mock_request.headers.get = Mock(side_effect=lambda k: headers.get(k))
	
	return mock_request


def create_mock_response():
	"""Create a mock HTTP response object."""
	mock_response = Mock()
	mock_response.status_code = 200
	mock_response.headers = {}
	return mock_response


def setup_mock_frappe_environment():
	"""Set up common mock frappe environment."""
	mocks = {
		'local': MockFrappeLocal(),
		'session': Mock(),
		'flags': Mock(),
		'cache': Mock(),
		'db': Mock(),
		'utils': Mock()
	}
	
	# Setup common return values
	mocks['session'].get = Mock(return_value='Guest')
	mocks['flags'].get = Mock(return_value=False)
	mocks['cache'].return_value = Mock()
	mocks['db'].get_value = Mock(return_value=None)
	mocks['db'].exists = Mock(return_value=False)
	mocks['db'].commit = Mock()
	mocks['utils'].get_url = Mock(return_value='https://example.com')
	
	return mocks


def assert_cloudflare_urls(test_case, provider, team_name, aud_tag):
	"""Assert that provider generates correct Cloudflare URLs."""
	import unittest.mock
	
	# Test JWKS URL
	jwks_url = provider.get_jwks_url()
	expected_jwks = f'https://{team_name}.cloudflareaccess.com/cdn-cgi/access/certs'
	test_case.assertEqual(jwks_url, expected_jwks)
	
	# Test login URL without redirect
	login_url = provider.get_login_url()
	expected_login = f'https://{team_name}.cloudflareaccess.com/cdn-cgi/access/login/{aud_tag}'
	test_case.assertEqual(login_url, expected_login)
	
	# Test login URL with redirect
	login_url_with_redirect = provider.get_login_url('/dashboard')
	test_case.assertIn('redirect_url=', login_url_with_redirect)
	test_case.assertIn('%2F', login_url_with_redirect)
	
	# Test logout URL
	with unittest.mock.patch('jwt_auth.providers.frappe.utils.get_url', return_value='https://example.com'):
		logout_url = provider.get_logout_url()
		expected_logout_base = f'https://{team_name}.cloudflareaccess.com/cdn-cgi/access/logout'
		test_case.assertIn(expected_logout_base, logout_url)
		test_case.assertIn('redirect_url=', logout_url)


def create_test_jwt_settings(docname="JWT Auth Settings", **overrides):
	"""Create test JWT Auth Settings document."""
	import frappe
	
	try:
		settings = frappe.get_doc(docname)
	except frappe.DoesNotExistError:
		settings = frappe.new_doc(docname)
	
	default_values = {
		'enabled': 1,
		'enable_user_reg': 1,
		'enable_login': 1,
		'jwt_header': 'Cf-Access-Token',
		'jwks_url': 'https://test-team.cloudflareaccess.com/cdn-cgi/access/certs',
		'jwt_private_secret': 'test-secret',
		'login_url': 'https://test-team.cloudflareaccess.com/cdn-cgi/access/login/test-aud',
		'logout_url': 'https://test-team.cloudflareaccess.com/cdn-cgi/access/logout',
		'redirect_param': 'redirect_url'
	}
	
	# Apply overrides
	default_values.update(overrides)
	
	# Set values
	for key, value in default_values.items():
		setattr(settings, key, value)
	
	return settings


# Common test data
VALID_JWT_CLAIMS = {
	"aud": ["test-secret"],
	"email": "test@example.com",
	"exp": int(time.time()) + 3600,
	"iat": int(time.time()),
	"iss": "https://test-team.cloudflareaccess.com",
	"sub": "1234567890",
	"common_name": "test@example.com"
}

EXPIRED_JWT_CLAIMS = {
	**VALID_JWT_CLAIMS,
	"exp": int(time.time()) - 3600,
	"iat": int(time.time()) - 7200
}

INVALID_AUD_JWT_CLAIMS = {
	**VALID_JWT_CLAIMS,
	"aud": ["wrong-audience"]
}

CLOUDFLARE_JWKS_RESPONSE = {
	"keys": [
		{
			"alg": "RS256",
			"kty": "RSA",
			"use": "sig",
			"x5c": ["MIIC+DCCAeCgAwIBAgIJAKZ7..."],
			"n": "example_n_parameter",
			"e": "AQAB",
			"kid": "cloudflare-key-1",
			"x5t": "example_thumbprint"
		}
	]
}