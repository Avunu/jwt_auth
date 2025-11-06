# Copyright (c) 2024, Avunu LLC and Contributors
# See license.txt

import frappe
from frappe.tests import IntegrationTestCase, UnitTestCase
from jwt_auth.jwt_auth.doctype.jwt_auth_settings.jwt_auth_settings import JWTAuthSettings


# On IntegrationTestCase, the doctype test records and all
# link-field test record depdendencies are recursively loaded
# Use these module variables to add/remove to/from that list
EXTRA_TEST_RECORD_DEPENDENCIES = []  # eg. ["User"]
IGNORE_TEST_RECORD_DEPENDENCIES = []  # eg. ["User"]


class TestJWTAuthSettingsUnit(UnitTestCase):
	"""
	Unit tests for JWTAuthSettings.
	Use this class for testing individual functions and methods.
	"""

	def test_doctype_creation(self):
		"""Test that JWT Auth Settings doctype can be created."""
		settings = frappe.get_doc("JWT Auth Settings")
		self.assertIsInstance(settings, JWTAuthSettings)

	def test_default_values(self):
		"""Test default values are set correctly."""
		settings = frappe.get_doc("JWT Auth Settings")
		# Test default values match the DocType definition
		self.assertEqual(settings.enabled, 1)
		self.assertEqual(settings.enable_user_reg, 1)
		self.assertEqual(settings.enable_login, 1)

	def test_mandatory_fields_validation(self):
		"""Test that mandatory fields are validated when enabled."""
		settings = frappe.get_doc("JWT Auth Settings")
		settings.enabled = 1
		
		# These fields should be mandatory when enabled=1
		mandatory_fields = ['jwt_header', 'jwks_url', 'jwt_private_secret']
		
		for field in mandatory_fields:
			with self.subTest(field=field):
				# Clear the field and expect validation error
				setattr(settings, field, None)
				with self.assertRaises(frappe.ValidationError):
					settings.validate()

	def test_enable_login_dependencies(self):
		"""Test that login URL and redirect param are mandatory when enable_login is set."""
		settings = frappe.get_doc("JWT Auth Settings")
		settings.enable_login = 1
		
		# These fields should be mandatory when enable_login=1
		mandatory_fields = ['login_url', 'redirect_param']
		
		for field in mandatory_fields:
			with self.subTest(field=field):
				setattr(settings, field, None)
				with self.assertRaises(frappe.ValidationError):
					settings.validate()


class TestJWTAuthSettingsIntegration(IntegrationTestCase):
	"""
	Integration tests for JWTAuthSettings.
	Use this class for testing interactions between multiple components.
	"""

	def setUp(self):
		"""Set up test environment."""
		# Create test settings
		self.test_settings = {
			'enabled': 1,
			'enable_user_reg': 1,
			'enable_login': 1,
			'jwt_header': 'Cf-Access-Token',
			'jwks_url': 'https://test.cloudflareaccess.com/cdn-cgi/access/certs',
			'jwt_private_secret': 'test-secret',
			'login_url': 'https://test.cloudflareaccess.com/cdn-cgi/access/login/test',
			'logout_url': 'https://test.cloudflareaccess.com/cdn-cgi/access/logout',
			'redirect_param': 'redirect_url'
		}

	def test_settings_persistence(self):
		"""Test that settings can be saved and retrieved."""
		# Get or create the single doctype
		try:
			settings = frappe.get_doc("JWT Auth Settings")
		except frappe.DoesNotExistError:
			settings = frappe.new_doc("JWT Auth Settings")
		
		# Update with test values
		settings.update(self.test_settings)
		settings.save()
		
		# Retrieve and verify
		saved_settings = frappe.get_doc("JWT Auth Settings")
		for key, value in self.test_settings.items():
			if key != 'jwt_private_secret':  # Password field handled differently
				self.assertEqual(getattr(saved_settings, key), value)

	def test_password_field_handling(self):
		"""Test that password fields are handled correctly."""
		try:
			settings = frappe.get_doc("JWT Auth Settings")
		except frappe.DoesNotExistError:
			settings = frappe.new_doc("JWT Auth Settings")
		
		settings.update(self.test_settings)
		settings.save()
		
		# Test password retrieval
		password = settings.get_password('jwt_private_secret')
		self.assertEqual(password, 'test-secret')

	def tearDown(self):
		"""Clean up after tests."""
		# Reset settings to defaults
		try:
			settings = frappe.get_doc("JWT Auth Settings")
			settings.enabled = 0
			settings.enable_user_reg = 0
			settings.enable_login = 0
			settings.jwt_header = None
			settings.jwks_url = None
			settings.jwt_private_secret = None
			settings.login_url = None
			settings.logout_url = None
			settings.redirect_param = None
			settings.save()
		except frappe.DoesNotExistError:
			pass
